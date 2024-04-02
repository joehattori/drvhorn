/**
SeaHorn Verification Framework
Copyright (c) 2020 Arie Gurfinkel
All Rights Reserved.

THIS SOFTWARE IS PROVIDED "AS IS," WITH NO WARRANTIES
WHATSOEVER. UNIVERSITY OF WATERLOO EXPRESSLY DISCLAIMS TO THE
FULLEST EXTENT PERMITTEDBY LAW ALL EXPRESS, IMPLIED, AND STATUTORY
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
NON-INFRINGEMENT OF PROPRIETARY RIGHTS.

Released under a modified BSD license, please see license.txt for full
terms.
*/

#pragma once

#include "seahorn/config.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"

namespace llvm {
class LoopPass;
}
namespace seahorn {
llvm::Pass *createMarkInternalInlinePass();
llvm::Pass *createMarkInternalAllocOrDeallocInlinePass();
llvm::Pass *createMarkInternalConstructOrDestructInlinePass();
llvm::Pass *createNondetInitPass();
llvm::Pass *createDeadNondetElimPass();
llvm::Pass *createDummyExitBlockPass();
llvm::Pass *createDummyMainFunctionPass(std::string entry);
llvm::Pass *createOneAssumePerBlockPass();
llvm::Pass *createExternalizeAddressTakenFunctionsPass();
llvm::Pass *createExternalizeFunctionsPass();
llvm::Pass *createSliceFunctionsPass();
llvm::Pass *createDevirtualizeFunctionsPass();
llvm::Pass *createAbstractMemoryPass();
llvm::Pass *createPromoteMemoryToRegisterPass();
llvm::Pass *createLoadCrabPass();

llvm::Pass *createCutLoopsPass();
llvm::Pass *createMarkFnEntryPass();
llvm::Pass *createPromoteVerifierCallsPass();
llvm::Pass *createPromoteMallocPass();
llvm::Pass *createKillVarArgFnPass();
llvm::Pass *createLowerArithWithOverflowIntrinsicsPass();
llvm::Pass *createLowerLibCxxAbiFunctionsPass();
llvm::Pass *createSimplifyPointerLoopsPass();
llvm::Pass *createSymbolizeConstantLoopBoundsPass();
llvm::Pass *createLowerAssertPass();
llvm::Pass *createUnfoldLoopForDsaPass();
llvm::Pass *createStripLifetimePass();
llvm::Pass *createStripUselessDeclarationsPass();

llvm::Pass *createPromoteBoolLoadsPass();

llvm::Pass *createEnumVerifierCallsPass();

llvm::Pass *createCanReadUndefPass();

llvm::Pass *createBmcPass(llvm::raw_ostream *out, bool solve);
llvm::Pass *createPathBmcPass(llvm::raw_ostream *out, bool solve);

llvm::Pass *createProfilerPass();
llvm::Pass *createCFGPrinterPass();
llvm::Pass *createCFGOnlyPrinterPass();
llvm::Pass *createCFGViewerPass();
llvm::Pass *createCFGOnlyViewerPass();
llvm::Pass *createDsaPrinterPass();
llvm::Pass *createDsaViewerPass();

llvm::Pass *createPromoteSeahornAssumePass();
llvm::Pass *createKleeInternalizePass();
llvm::Pass *createWrapMemPass();
llvm::Pass *createRenameNondetPass();

llvm::Pass *createMixedSemanticsPass();
llvm::Pass *createRemoveUnreachableBlocksPass();

llvm::Pass *createLowerGvInitializersPass();
llvm::Pass *createLowerCstExprPass();

llvm::Pass *createNullCheckPass();

llvm::Pass *createGlobalBufferBoundsCheck();
llvm::Pass *createLocalBufferBoundsCheck();
llvm::Pass *createGlobalCBufferBoundsCheckPass();

llvm::Pass *createFatBufferBoundsCheckPass();

llvm::Pass *createAddBranchSentinelPassPass();

llvm::Pass *createEvalBranchSentinelPassPass();

llvm::Pass *createSimpleMemoryCheckPass();

llvm::Pass *createCanFailPass();

llvm::FunctionPass *createPromoteMemcpyPass();

llvm::Pass *createBoogieWriterPass(llvm::raw_ostream *out, bool use_crab);

llvm::ModulePass *createControlDependenceAnalysisPass();
llvm::ModulePass *createGateAnalysisPass();
llvm::Pass *createGeneratePartialFnPass();
llvm::Pass *createCHAPass();
llvm::ModulePass *createDebugVerifierPass(int instanceID, llvm::StringRef name);
llvm::Pass *createUnifyAssumesPass();
llvm::Pass *createCrabLowerIsDerefPass();

llvm::Pass *createAcpiSetupPass(std::string entry);
llvm::Pass *createKernelSetupPass();
} // namespace seahorn

#ifdef HAVE_LLVM_SEAHORN
llvm::FunctionPass *
createSeaInstructionCombiningPass();

namespace seahorn {
inline llvm::FunctionPass *createInstCombine() {
  return createSeaInstructionCombiningPass();
}
} // namespace seahorn
#else
namespace seahorn {
inline llvm::FunctionPass *createInstCombine() {
  return llvm::createInstructionCombiningPass();
}
} // namespace seahorn
#endif

#include "seadsa/ShadowMem.hh"
namespace seahorn {
inline llvm::Pass *createSeaDsaShadowMemPass() {
  return seadsa::createShadowMemPass();
}

inline llvm::Pass *createStripShadowMemPass() {
  return seadsa::createStripShadowMemPass();
}

llvm::ImmutablePass *createSeaBuiltinsWrapperPass();
llvm::Pass* createLoopPeelerPass(unsigned Num = 1);
llvm::Pass* createBackEdgeCutterPass();
llvm::Pass* createLowerIsDerefPass();
} // namespace seahorn
