// Derived from
// https://github.com/smackers/smack/blob/master/tools/smack/smack.cpp
//
// Copyright (c) 2013 Pantazis Deligiannis (p.deligiannis@imperial.ac.uk)
// This file is distributed under the MIT License. See LICENSE for details.
//

///
// SeaPP-- LLVM bitcode Pre-Processor for Verification
///

#include "llvm_seahorn/InitializePasses.h"
#include "llvm_seahorn/Transforms/IPO.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Bitcode/BitcodeWriterPass.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include "llvm/IR/Verifier.h"

#include "seahorn/InitializePasses.hh"
#include "seahorn/Passes.hh"

#include "seadsa/InitializePasses.hh"
#include "seadsa/support/RemovePtrToInt.hh"

#ifdef HAVE_LLVM_SEAHORN
#include "llvm_seahorn/Transforms/Scalar.h"
#endif

#include "seadsa/InitializePasses.hh"

#include "seahorn/Expr/Smt/EZ3.hh"
#include "seahorn/Support/SeaLog.hh"
#include "seahorn/Support/Stats.hh"
#include "seahorn/Transforms/Utils/NameValues.hh"

#include "seahorn/config.h"

void print_seapp_version(llvm::raw_ostream &OS) {
  OS << "SeaHorn (http://seahorn.github.io/):\n"
     << "  SeaPP version " << SEAHORN_VERSION_INFO << "\n";
}

static llvm::cl::opt<std::string>
    InputFilename(llvm::cl::Positional,
                  llvm::cl::desc("<input LLVM bitcode file>"),
                  llvm::cl::Required, llvm::cl::value_desc("filename"));

static llvm::cl::opt<std::string>
    OutputFilename("o", llvm::cl::desc("Override output filename"),
                   llvm::cl::init(""), llvm::cl::value_desc("filename"));

static llvm::cl::opt<bool>
    OutputAssembly("S", llvm::cl::desc("Write output as LLVM assembly"));

static llvm::cl::opt<std::string> DefaultDataLayout(
    "default-data-layout",
    llvm::cl::desc("data layout string to use if not specified by module"),
    llvm::cl::init(""), llvm::cl::value_desc("layout-string"));

static llvm::cl::opt<bool> InlineAll("horn-inline-all",
                                     llvm::cl::desc("Inline all functions"),
                                     llvm::cl::init(false));

static llvm::cl::opt<bool> InlineAllocFn(
    "horn-inline-allocators",
    llvm::cl::desc("Inline functions that allocate or deallocate memory"),
    llvm::cl::init(false));

static llvm::cl::opt<bool>
    InlineConstructFn("horn-inline-constructors",
                      llvm::cl::desc("Inline C++ constructors and destructors"),
                      llvm::cl::init(false));

static llvm::cl::opt<bool> CutLoops("horn-cut-loops",
                                    llvm::cl::desc("Cut all natural loops"),
                                    llvm::cl::init(false));
static llvm::cl::opt<unsigned>
    PeelLoops("horn-peel-loops", llvm::cl::desc("Number of iterations to peel"),
              llvm::cl::init(0));

static llvm::cl::opt<bool> SymbolizeLoops(
    "horn-symbolize-loops",
    llvm::cl::desc("Convert constant loop bounds into symbolic bounds"),
    llvm::cl::init(false));

static llvm::cl::opt<bool>
    KeepArithOverflow("horn-keep-arith-overflow",
                      llvm::cl::desc("Keep arithmetic overflow intrinsics."),
                      llvm::cl::init(false));

static llvm::cl::opt<bool> SimplifyPointerLoops(
    "simplify-pointer-loops",
    llvm::cl::desc("Simplify loops that iterate over pointers"),
    llvm::cl::init(false));

static llvm::cl::opt<bool> UnfoldLoopsForDsa(
    "unfold-loops-for-dsa",
    llvm::cl::desc(
        "Unfold the first loop iteration if useful for DSA analysis"),
    llvm::cl::init(false));

static llvm::cl::opt<bool>
    NullChecks("null-check", llvm::cl::desc("Insert null-dereference checks"),
               llvm::cl::init(false));

static llvm::cl::opt<bool>
    SimpleMemoryChecks("smc", llvm::cl::desc("Insert simple memory checks"),
                       llvm::cl::init(false));

static llvm::cl::opt<bool> EnumVerifierCalls(
    "enum-verifier-calls",
    llvm::cl::desc("Assign a unique identifier to each call to verifier.error"),
    llvm::cl::init(false));

static llvm::cl::opt<bool>
    MixedSem("horn-mixed-sem", llvm::cl::desc("Mixed-Semantics Transformation"),
             llvm::cl::init(false));

static llvm::cl::opt<bool> KillVaArg("kill-vaarg",
                                     llvm::cl::desc("Delete vaarg functions"),
                                     llvm::cl::init(false));

static llvm::cl::opt<bool>
    StripExtern("strip-extern",
                llvm::cl::desc("Replace external functions by nondet"),
                llvm::cl::init(false));

static llvm::cl::opt<bool> OnlyStripExtern(
    "only-strip-extern",
    llvm::cl::desc(
        "Replace external functions by nondet and perform no other changes"),
    llvm::cl::init(false));

static llvm::cl::opt<bool>
    LowerInvoke("lower-invoke", llvm::cl::desc("Lower all invoke instructions"),
                llvm::cl::init(true));

static llvm::cl::opt<bool>
    LowerGlobalInitializers("lower-gv-init",
                            llvm::cl::desc("Lower some global initializers"),
                            llvm::cl::init(true));

static llvm::cl::opt<bool> DevirtualizeFuncs(
    "devirt-functions",
    llvm::cl::desc("Devirtualize indirect calls "
                   "(disabled by default). "
                   "If enabled then use "
                   "--devirt-functions-method=types|sea-dsa to choose method."),
    llvm::cl::init(false));

static llvm::cl::opt<bool> ExternalizeAddrTakenFuncs(
    "externalize-addr-taken-funcs",
    llvm::cl::desc("Externalize uses of address-taken functions"),
    llvm::cl::init(false));

static llvm::cl::opt<bool>
    LowerAssert("lower-assert",
                llvm::cl::desc("Replace assertions with assumptions"),
                llvm::cl::init(false));

static llvm::cl::opt<bool>
    PromoteAssumptions("promote-assumptions",
                       llvm::cl::desc("Promote verifier.assume to llvm.assume"),
                       llvm::cl::init(false));

static llvm::cl::opt<bool> ReplaceLoopsWithNDFuncs(
    "horn-replace-loops-with-nd-funcs",
    llvm::cl::desc(
        "Replace all loops with functions that return nondet values"),
    llvm::cl::init(false));

// static llvm::cl::opt<int>
//     SROA_Threshold("sroa-threshold",
//                    llvm::cl::desc("Threshold for ScalarReplAggregates pass"),
//                    llvm::cl::init(INT_MAX));
// static llvm::cl::opt<int> SROA_StructMemThreshold(
//     "sroa-struct",
//     llvm::cl::desc("Structure threshold for ScalarReplAggregates"),
//     llvm::cl::init(INT_MAX));

// static llvm::cl::opt<int> SROA_ArrayElementThreshold(
//     "sroa-array", llvm::cl::desc("Array threshold for ScalarReplAggregates"),
//     llvm::cl::init(INT_MAX));
// static llvm::cl::opt<int> SROA_ScalarLoadThreshold(
//     "sroa-scalar-load",
//     llvm::cl::desc("Scalar load threshold for ScalarReplAggregates"),
//     llvm::cl::init(-1));

static llvm::cl::opt<bool>
    KleeInternalize("klee-internalize",
                    llvm::cl::desc("Internalizes definitions for Klee"),
                    llvm::cl::init(false));
static llvm::cl::opt<bool>
    WrapMem("wrap-mem",
            llvm::cl::desc("Wrap memory accesses with special functions"),
            llvm::cl::init(false));

static llvm::cl::opt<bool> FatBoundsCheck(
    "fat-bnd-check",
    llvm::cl::desc(
        "Instrument buffer bounds check  using extended pointer bits"),
    llvm::cl::init(false));

static llvm::cl::opt<bool>
    ExternalizeFns("externalize-fns",
                   llvm::cl::desc("Run externalize functions pass"),
                   llvm::cl::init(false));

static llvm::cl::opt<bool>
    LowerIsDeref("lower-is-deref",
                 llvm::cl::desc("Lower sea_is_dereferenceable() calls"),
                 llvm::cl::init(false));

static llvm::cl::opt<bool>
    StripShadowMem("strip-shadow-mem",
                   llvm::cl::desc("Strip shadow memory functions"),
                   llvm::cl::init(false));

static llvm::cl::opt<bool> RenameNondet(
    "rename-nondet",
    llvm::cl::desc("Assign a unique name to each non-determinism per call."),
    llvm::cl::init(false));

static llvm::cl::opt<bool>
    AbstractMemory("abstract-memory",
                   llvm::cl::desc("Abstract memory instructions"),
                   llvm::cl::init(false));

static llvm::cl::opt<bool> NameValues(
    "name-values",
    llvm::cl::desc(
        "Run the seahorn::NameValues pass (WARNING -- can be extremely slow)"),
    llvm::cl::init(false));

static llvm::cl::opt<bool>
    InstNamer("instnamer", llvm::cl::desc("Run the llvm's instnamer pass"),
              llvm::cl::init(false));

static llvm::cl::opt<bool>
    LowerSwitch("lower-switch",
                llvm::cl::desc("Lower SwitchInstructions to branches"),
                llvm::cl::init(true));

static llvm::cl::opt<bool>
    PromoteBoolLoads("promote-bool-loads",
                     llvm::cl::desc("Promote bool loads to sgt"),
                     llvm::cl::init(true));

static llvm::cl::opt<bool>
    NondetInit("promote-nondet-undef",
               llvm::cl::desc("Replace all undef with non-determinism"),
               llvm::cl::init(true));

static llvm::cl::opt<bool> StripDebug("strip-debug",
                                      llvm::cl::desc("Strip debug info"),
                                      llvm::cl::init(false));

static llvm::cl::opt<bool> VerifyAfterAll(
    "verify-after-all",
    llvm::cl::desc("Run the verification pass after each transformation"),
    llvm::cl::init(false));

static llvm::cl::opt<bool> AddBranchSentinelOpt(
    "add-branch-sentinel",
    llvm::cl::desc(
        "Add a branch sentinel instruction before every branch instruction"),
    llvm::cl::init(false));

static llvm::cl::opt<bool> CrabLowerIsDeref(
    "crab-lower-is-deref",
    llvm::cl::desc("Lower sea_is_dereferenceable() calls by Running Crab"),
    llvm::cl::init(false));

static llvm::cl::opt<bool> PrintStats("seapp-stats",
                                      llvm::cl::desc("Print statistics"),
                                      llvm::cl::init(false));

static llvm::cl::opt<bool> Kernel("kernel",
                                  llvm::cl::desc("Target the Linux kernel"),
                                  llvm::cl::init(false));

static llvm::cl::opt<bool>
    KernelExec("kernel-exec", llvm::cl::desc("Run the kernel verification"),
               llvm::cl::init(false));

static llvm::cl::opt<std::string>
    AcpiDriver("acpi-driver", llvm::cl::desc("Target ACPI drivers"),
               llvm::cl::init(""));

static llvm::cl::opt<std::string>
    PlatformDriver("platform-driver", llvm::cl::desc("Target Platform driver"),
                   llvm::cl::init(""));

static llvm::cl::opt<std::string>
    FileOperation("file-operations", llvm::cl::desc("Target File Operations"),
                  llvm::cl::init(""));

static llvm::cl::opt<std::string>
    DsaSwitchOps("dsa-switch-ops", llvm::cl::desc("Target DSA Switch Ops"),
                 llvm::cl::init(""));

static llvm::cl::opt<std::string> I2CDriver("i2c-driver",
                                            llvm::cl::desc("Target I2C driver"),
                                            llvm::cl::init(""));

static llvm::cl::opt<std::string>
    SpecificFunction("specific-function",
                     llvm::cl::desc("Specific function name"),
                     llvm::cl::init(""));

static llvm::cl::list<std::string>
    ListOps("list-ops", llvm::cl::desc("List device driver operations"),
            llvm::cl::ZeroOrMore, llvm::cl::CommaSeparated);

static llvm::cl::opt<std::string>
    KernelOutLL("kernel-out-ll",
                llvm::cl::desc("Output file for the kernel LLVM IR"),
                llvm::cl::init(""));

static llvm::cl::opt<std::string> DriverList("driver-list",
                                             llvm::cl::desc("List of drivers"),
                                             llvm::cl::init(""));

namespace {
enum class DriverType {
  SpecificFunction,
  FileOperations,
  PlatformDriver,
  I2CDriver,
  DsaSwitchOps,
  None
};

llvm::SmallVector<std::pair<DriverType, std::string>>
parseDriverList(llvm::StringRef path) {
  llvm::SmallVector<std::pair<DriverType, std::string>> drivers;
  std::ifstream file(path.str());
  if (!file.is_open()) {
    llvm::errs() << "Unable to open driver list file\n";
    std::exit(1);
  }
  std::string line;
  while (std::getline(file, line)) {
    std::istringstream iss(line);
    std::string driver;
    std::string name;
    if (!(iss >> driver >> name)) {
      llvm::errs() << "Invalid driver list file\n";
      std::exit(1);
    }
    if (driver == "file_operations")
      drivers.push_back({DriverType::FileOperations, name});
    else if (driver == "platform_driver")
      drivers.push_back({DriverType::PlatformDriver, name});
    else if (driver == "i2c_driver")
      drivers.push_back({DriverType::I2CDriver, name});
    else if (driver == "dsa_switch_ops")
      drivers.push_back({DriverType::DsaSwitchOps, name});
  }
  file.close();
  return drivers;
}

/// Simple wrapper around llvm::legacy::PassManager for easier debugging.
class SeaPassManagerWrapper {
  llvm::legacy::PassManager m_PM;
  int m_verifierInstanceID = 0;

public:
  void add(llvm::Pass *pass) {
    m_PM.add(pass);

    if (VerifyAfterAll)
      m_PM.add(seahorn::createDebugVerifierPass(++m_verifierInstanceID,
                                                pass->getPassName()));
  }

  void run(llvm::Module &m) { m_PM.run(m); }

  llvm::legacy::PassManager &getPassManager() { return m_PM; }

  SeaPassManagerWrapper(llvm::PassRegistry &Registry,
                        std::unique_ptr<llvm::ToolOutputFile> &output,
                        DriverType driverType, llvm::StringRef name,
                        bool onlyKernelPP, llvm::StringRef kernelOut) {
    if (VerifyAfterAll)
      m_PM.add(seahorn::createDebugVerifierPass(++m_verifierInstanceID,
                                                "Initial Verifier Pass"));
    add(llvm_seahorn::createSeaAnnotation2MetadataLegacyPass());
    add(seahorn::createSeaBuiltinsWrapperPass());
    if (ReplaceLoopsWithNDFuncs) {
      add(llvm_seahorn::createSeaLoopExtractorPass());
    }

    if (Kernel) {
      if (!ListOps.empty()) {
        add(seahorn::createListOpsPass(ListOps));
        return;
      }

      add(seahorn::createKernelSetupPass());
      add(llvm::createVerifierPass(true));
      add(seahorn::createHandleDevicesPass());
      add(llvm::createVerifierPass(true));
      // TODO: merge these passes into one.
      switch (driverType) {
      case DriverType::SpecificFunction:
        add(seahorn::createSpecificFunctionPass(name));
        break;
      case DriverType::FileOperations:
        add(seahorn::createFileOperationsSetupPass(name));
        break;
      case DriverType::PlatformDriver:
        add(seahorn::createPlatformDriverPass(name));
        break;
      case DriverType::I2CDriver:
        add(seahorn::createI2CDriverPass(name));
        break;
      case DriverType::DsaSwitchOps:
        add(seahorn::createDsaSwitchOpsPass(name));
        break;
      case DriverType::None:
        llvm::errs() << "Unknown driver target\n";
        std::exit(1);
      }
      add(seahorn::createPromoteVerifierCallsPass());
      add(seahorn::createSlimDownPass());
      add(seahorn::createHandleDevmPass());
      add(seahorn::createHandleInlineAsmPass());
      add(seahorn::createInitGlobalKrefsPass());
      add(seahorn::createAssertKrefsPass());
      add(llvm::createVerifierPass(true));
      add(seahorn::createAssumeNonNullPass());
      /*add(seahorn::createIntoBinaryPass());*/
      add(seahorn::createHandleNondetMallocPass());
      add(llvm::createCFGSimplificationPass());
      add(llvm::createVerifierPass(true));
      add(seahorn::createKernelDebugPass(kernelOut));
      if (onlyKernelPP)
        return;
    }

    if (RenameNondet)
      // -- ren-nondet utility pass
      add(seahorn::createRenameNondetPass());
    else if (StripShadowMem)
      // -- strips shadows. Useful for debugging
      add(seahorn::createStripShadowMemPass());
    else if (KleeInternalize)
      // -- internalize external definitions to make klee happy
      // -- useful for preparing seahorn bitcode to be used with KLEE
      add(seahorn::createKleeInternalizePass());
    else if (WrapMem)
      // -- wraps memory instructions with a custom function
      // -- not actively used. part of cex replaying
      add(seahorn::createWrapMemPass());
    else if (OnlyStripExtern) {
      // -- remove useless declarations
      add(seahorn::createDevirtualizeFunctionsPass());
      add(seahorn::createStripUselessDeclarationsPass());
    } else if (MixedSem) {
      // -- apply mixed semantics
      assert(LowerSwitch && "Lower switch must be enabled");
      add(llvm::createLowerSwitchPass());
      add(seahorn::createPromoteVerifierCallsPass());
      add(seahorn::createCanFailPass());
      add(seahorn::createMixedSemanticsPass());
      add(seahorn::createRemoveUnreachableBlocksPass());
      add(seahorn::createPromoteMallocPass());
    } else if (CutLoops || PeelLoops > 0) {
      // -- cut loops to turn a program into loop-free program
      assert(LowerSwitch && "Lower switch must be enabled");
      add(llvm::createLowerSwitchPass());
      add(llvm::createLoopSimplifyPass());
      add(llvm::createLoopSimplifyCFGPass());
      add(llvm_seahorn::createLoopRotatePass(/*1023*/));
      add(llvm::createLCSSAPass());
      if (PeelLoops > 0)
        add(seahorn::createLoopPeelerPass(PeelLoops));
      if (CutLoops) {
        add(seahorn::createBackEdgeCutterPass());
        // -- disabled. back-edge-cutter should be more robust
        // add(seahorn::createCutLoopsPass());
      }
      // add (new seahorn::RemoveUnreachableBlocksPass ());
    }
    // checking for simple instances of memory safety. WIP
    else if (SimpleMemoryChecks) {
      add(llvm::createPromoteMemoryToRegisterPass());
      add(seahorn::createSimpleMemoryCheckPass());
    }
    // null deref check. WIP. Not used.
    else if (NullChecks) {
      add(seahorn::createLowerCstExprPass());
      add(seahorn::createNullCheckPass());
    } else if (FatBoundsCheck) {
      initializeFatBufferBoundsCheckPass(Registry);
      add(seahorn::createFatBufferBoundsCheckPass());
    } else if (LowerIsDeref) {
      add(seahorn::createLowerIsDerefPass());
    } else if (AddBranchSentinelOpt) {
      initializeAddBranchSentinelPassPass(Registry);
      add(seahorn::createAddBranchSentinelPassPass());
    } else if (ExternalizeFns) {
      // -- Externalize some user-selected functions
      add(seahorn::createExternalizeFunctionsPass());
    } else if (CrabLowerIsDeref) {
      // -- prerequisite 1 : Lower constant expressions to instructions
      add(seahorn::createLowerCstExprPass());
      add(llvm::createDeadCodeEliminationPass());
      // -- prerequisite 2 : Run Name Values Pass
      add(seahorn::createNameValuesPass());
      // -- attempt to lower any left sea.is_dereferenceable()
      // First pass is attempted by using LLVM Memory Builtins to compute
      // the requested size of access <= object size.
      add(seahorn::createLowerIsDerefPass());
      // Second pass is using Crab Analysis to compute size and offset
      // invariants for each pointer.
      // Note that, another prerequisite: Sea-DSA analysis is run inside
      // the below LLVM pass.
      add(seahorn::createCrabLowerIsDerefPass());
    }
    // default pre-processing pipeline
    else {
      // -- Externalize some user-selected functions
      add(seahorn::createExternalizeFunctionsPass());

      // -- Replace main function by entry point.
      add(seahorn::createDummyMainFunctionPass());

      // -- promote verifier specific functions to special names
      add(seahorn::createPromoteVerifierCallsPass());

      // -- promote top-level mallocs to alloca
      add(seahorn::createPromoteMallocPass());

      // -- turn loads from _Bool from truc to sgt
      if (PromoteBoolLoads)
        add(seahorn::createPromoteBoolLoadsPass());

      if (KillVaArg)
        add(seahorn::createKillVarArgFnPass());

      if (StripExtern)
        add(seahorn::createStripUselessDeclarationsPass());

      // -- mark entry points of all functions
      add(seahorn::createMarkFnEntryPass());

      // turn all functions internal so that we can inline them if requested
      auto PreserveMain = [=](const llvm::GlobalValue &GV) {
        return GV.getName() == "main" || GV.getName() == "bcmp";
      };
      add(llvm::createInternalizePass(PreserveMain));

      if (LowerInvoke) {
        // -- lower invoke's
        add(llvm::createLowerInvokePass());
        // cleanup after lowering invoke's
        add(llvm::createCFGSimplificationPass());
      }

      // -- resolve indirect calls
      if (DevirtualizeFuncs) {
        add(seadsa::createRemovePtrToIntPass());
        add(llvm::createWholeProgramDevirtPass(nullptr, nullptr));
        add(seahorn::createDevirtualizeFunctionsPass());
      }

      // -- externalize uses of address-taken functions
      if (ExternalizeAddrTakenFuncs)
        add(seahorn::createExternalizeAddressTakenFunctionsPass());

      // kill internal unused code
      add(llvm::createGlobalDCEPass()); // kill unused internal global

      // -- global optimizations
      add(llvm::createGlobalOptimizerPass());

      // -- explicitly initialize globals in the beginning of main()
      if (LowerGlobalInitializers)
        add(seahorn::createLowerGvInitializersPass());

      // -- SSA
      add(llvm::createPromoteMemoryToRegisterPass());

      if (NondetInit)
        // -- Turn undef into nondet
        add(seahorn::createNondetInitPass());

      // -- Promote memcpy to loads-and-stores for easier alias analysis.
      add(seahorn::createPromoteMemcpyPass());

      // -- cleanup after SSA
      add(seahorn::createInstCombine());
      add(llvm::createCFGSimplificationPass());

      // -- break aggregates
      // XXX: createScalarReplAggregatesPass is not defined in llvm 5.0
      // add(llvm::createScalarReplAggregatesPass(
      //     SROA_Threshold, true, SROA_StructMemThreshold,
      //     SROA_ArrayElementThreshold, SROA_ScalarLoadThreshold));
      add(llvm::createSROAPass());
      if (NondetInit)
        // -- Turn undef into nondet (undef are created by SROA when it calls
        //     mem2reg)
        add(seahorn::createNondetInitPass());

      // -- cleanup after break aggregates
      add(seahorn::createInstCombine());
      add(llvm::createCFGSimplificationPass());

      // eliminate unused calls to verifier.nondet() functions
      add(seahorn::createDeadNondetElimPass());

      if (LowerSwitch)
        add(llvm::createLowerSwitchPass());

      add(llvm::createDeadCodeEliminationPass());
      // Superseded by DCE in LLVM12
      // add(llvm::createDeadInstEliminationPass());
      add(seahorn::createRemoveUnreachableBlocksPass());

      if (!KeepArithOverflow)
        // lower arithmetic with overflow intrinsics
        add(seahorn::createLowerArithWithOverflowIntrinsicsPass());
      // lower libc++abi functions
      add(seahorn::createLowerLibCxxAbiFunctionsPass());

      // cleanup after lowering
      add(seahorn::createInstCombine());
      add(llvm::createCFGSimplificationPass());

      if (UnfoldLoopsForDsa) {
        // --- help DSA to be more precise
#ifdef HAVE_LLVM_SEAHORN
        add(llvm_seahorn::createFakeLatchExitPass());
#endif
        add(seahorn::createUnfoldLoopForDsaPass());
      }

      if (SimplifyPointerLoops) {
        // --- simplify loops that iterate over pointers
        add(seahorn::createSimplifyPointerLoopsPass());
      }

      // XXX: AG: Should not be part of standard pipeline
      if (AbstractMemory) {
        // -- abstract memory load/stores pointer operands with
        // -- non-deterministic values
        add(seahorn::createAbstractMemoryPass());
        // -- abstract memory pass generates a lot of dead load/store
        // -- instructions
        add(llvm::createDeadCodeEliminationPass());
        // Superseded by DCE in LLVM12
        // add(llvm::createDeadInstEliminationPass());
      }

      // AG: Used for inconsistency analysis
      // XXX Should be moved out of standard pp pipeline
      if (LowerAssert) {
        add(seahorn::createLowerAssertPass());
        // LowerAssert might generate some dead code
        add(llvm::createDeadCodeEliminationPass());
        // Superseded by DCE in LLVM12
        // add(llvm::createDeadInstEliminationPass());
      }
      add(seahorn::createRemoveUnreachableBlocksPass());

      // -- request seaopt to inline all functions
      if (InlineAll || Kernel || KernelExec) {
        add(llvm_seahorn::createSeaAnnotation2MetadataLegacyPass());
        add(seahorn::createMarkInternalInlinePass());
      } else {
        // mark memory allocator/deallocators to be inlined
        if (InlineAllocFn)
          add(seahorn::createMarkInternalAllocOrDeallocInlinePass());
        // mark constructors to be inlined
        if (InlineConstructFn)
          add(seahorn::createMarkInternalConstructOrDestructInlinePass());
      }

      // run inliner pass
      if (InlineAll || InlineAllocFn || InlineConstructFn || Kernel ||
          KernelExec) {
        add(llvm::createAlwaysInlinerLegacyPass());
        add(llvm::createGlobalDCEPass()); // kill unused internal global
        add(seahorn::createPromoteMallocPass());
        add(seahorn::createRemoveUnreachableBlocksPass());

        // -- Promote memcpy to loads-and-stores for easier alias analysis.
        // -- inline can help with alignment which will help this pass
        add(seahorn::createPromoteMemcpyPass());
      }

      // -- EVERYTHING IS MORE EXPENSIVE AFTER INLINING
      // -- BEFORE SCHEDULING PASSES HERE, THINK WHETHER THEY BELONG BEFORE
      // INLINE!
      add(llvm::createDeadCodeEliminationPass());
      // Superseded by DCE in LLVM12
      // add(llvm::createDeadInstEliminationPass());
      add(llvm::createGlobalDCEPass()); // kill unused internal global
      add(llvm::createUnifyFunctionExitNodesPass());

      // -- moves loop initialization up
      // AG: After inline because cheap and loop initialization is moved higher
      // up
      if (SymbolizeLoops)
        add(seahorn::createSymbolizeConstantLoopBoundsPass());

      // AG: Maybe should be moved before inline. Not used as far as I know.
      if (EnumVerifierCalls)
        add(seahorn::createEnumVerifierCallsPass());

      add(seahorn::createRemoveUnreachableBlocksPass());
      add(seahorn::createPromoteMallocPass());
      add(llvm::createGlobalDCEPass()); // kill unused internal global

      // -- Enable function slicing
      // AG: NOT USED. Not part of std pipeline
      add(seahorn::createSliceFunctionsPass());

      // AG: Dangerous. Promotes verifier.assume() to llvm.assume()
      if (PromoteAssumptions)
        add(seahorn::createPromoteSeahornAssumePass());
    }

    if (NameValues)
      add(seahorn::createNameValuesPass());

    if (InstNamer)
      add(llvm::createInstructionNamerPass());

    if (StripDebug)
      add(llvm::createStripDeadDebugInfoPass());

    // --- verify if an undefined value can be read
    add(seahorn::createCanReadUndefPass());
    // --- verify if bitcode is well-formed
    add(llvm::createVerifierPass());

    if (!OutputFilename.empty()) {
      if (OutputAssembly)
        add(createPrintModulePass(output->os()));
      else
        add(createBitcodeWriterPass(output->os()));
    }
  }
};
} // namespace

int main(int argc, char **argv) {
  llvm::llvm_shutdown_obj shutdown; // calls llvm_shutdown() on exit
  llvm::cl::AddExtraVersionPrinter(print_seapp_version);
  llvm::cl::ParseCommandLineOptions(
      argc, argv, "SeaPP-- LLVM bitcode Pre-Processor for Verification\n");

  llvm::sys::PrintStackTraceOnErrorSignal(argv[0]);
  llvm::PrettyStackTraceProgram PSTP(argc, argv);
  llvm::EnableDebugBuffering = true;

  std::error_code error_code;
  llvm::SMDiagnostic err;
  static llvm::LLVMContext context;
  std::unique_ptr<llvm::Module> module;
  std::unique_ptr<llvm::ToolOutputFile> output;

  module = llvm::parseIRFile(InputFilename, err, context);
  if (!module) {
    if (llvm::errs().has_colors())
      llvm::errs().changeColor(llvm::raw_ostream::RED);
    llvm::errs() << "error: "
                 << "Bitcode was not properly read; " << err.getMessage()
                 << "\n";
    if (llvm::errs().has_colors())
      llvm::errs().resetColor();
    return 3;
  }

  if (llvm::verifyModule(*module, &(llvm::errs()))) {
    ERR << "BROKEN INPUT IR\n";
    return 4;
  }
  llvm::errs() << "parsed the module\n";

  if (!OutputFilename.empty())
    output = std::make_unique<llvm::ToolOutputFile>(
        OutputFilename.c_str(), error_code, llvm::sys::fs::OF_None);

  if (error_code) {
    if (llvm::errs().has_colors())
      llvm::errs().changeColor(llvm::raw_ostream::RED);
    llvm::errs() << "error: Could not open " << OutputFilename << ": "
                 << error_code.message() << "\n";
    if (llvm::errs().has_colors())
      llvm::errs().resetColor();
    return 3;
  }

  ///////////////////////////////
  // initialise and run passes //
  ///////////////////////////////

  llvm::PassRegistry &Registry = *llvm::PassRegistry::getPassRegistry();
  llvm::initializeCore(Registry);
  llvm::initializeTransformUtils(Registry);
  llvm::initializeAnalysis(Registry);

  /// call graph and other IPA passes
  // llvm::initializeIPA (Registry);
  // XXX: porting to 3.8
  llvm::initializeCallGraphWrapperPassPass(Registry);
  // XXX: commented while porting to 5.0
  // llvm::initializeCallGraphPrinterPass(Registry);
  llvm::initializeCallGraphViewerPass(Registry);
  // XXX: not sure if needed anymore
  llvm::initializeGlobalsAAWrapperPassPass(Registry);
  llvm::initializeAllocWrapInfoPass(Registry);
  llvm::initializeDsaLibFuncInfoPass(Registry);

  llvm::initializeCompleteCallGraphPass(Registry);
  llvm::initializeSeaAnnotation2MetadataLegacyPass(Registry);

  llvm::initializeRemovePtrToIntPass(Registry);
  seahorn::initializeShadowMemPassPass(Registry);

  // add an appropriate DataLayout instance for the module
  const llvm::DataLayout *dl = &module->getDataLayout();
  if (!dl && !DefaultDataLayout.empty()) {
    module->setDataLayout(DefaultDataLayout);
    dl = &module->getDataLayout();
  }

  assert(dl && "Could not find Data Layout for the module");

  if (!DriverList.empty()) {
    llvm::SmallVector<std::pair<DriverType, std::string>> drivers =
        parseDriverList(DriverList);
    const llvm::Module &m = *module.get();
    for (std::pair<DriverType, std::string> driver : drivers) {
      std::string out = "gen-" + driver.second + ".ll";
      SeaPassManagerWrapper pm_wrapper(Registry, output, driver.first,
                                       driver.second, true, out);
      llvm::errs() << "Running driver for " << driver.second << "\n";
      std::unique_ptr<llvm::Module> clonedModule = llvm::CloneModule(m);
      llvm::errs() << "cloned\n";
      pm_wrapper.run(*clonedModule.get());
    }
  } else {
    DriverType driverType = DriverType::None;
    llvm::StringRef name = "";
    if (Kernel) {
      if (!SpecificFunction.empty()) {
        driverType = DriverType::SpecificFunction;
        name = SpecificFunction;
      } else if (!FileOperation.empty()) {
        driverType = DriverType::FileOperations;
        name = FileOperation;
      } else if (!PlatformDriver.empty()) {
        driverType = DriverType::PlatformDriver;
        name = PlatformDriver;
      } else if (!I2CDriver.empty()) {
        driverType = DriverType::I2CDriver;
        name = I2CDriver;
      } else if (!DsaSwitchOps.empty()) {
        driverType = DriverType::DsaSwitchOps;
        name = DsaSwitchOps;
      }
    }
    SeaPassManagerWrapper pm_wrapper(Registry, output, driverType, name, false,
                                     KernelOutLL);
    pm_wrapper.run(*module.get());
  }

  if (PrintStats)
    seahorn::Stats::PrintBrunch(llvm::outs());

  if (!OutputFilename.empty())
    output->keep();
  return 0;
}
