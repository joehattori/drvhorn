#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/MemoryDependenceAnalysis.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"

#include "seahorn/Analysis/SeaBuiltinsInfo.hh"
#include "seahorn/Transforms/Kernel/Util.hh"

#include <queue>

#define COMPILER_USED_NAME "llvm.compiler.used"
#define DEVICE_GETTER_PREFIX "__DRVHORN_embedded_device.getter."

using namespace llvm;

namespace seahorn {
struct Filter {
  Filter(const Module &m) {
    buildNonArgStartingPoint(m);
    buildCoreTargets(m);
    DenseSet<const Value *> memo;
    for (const CallInst *call : coreTargets) {
      buildRelevantArgs(call, 0, memo);
    }
    buildTargets(m);
  }

  bool isTarget(const Instruction *inst) const { return targets.count(inst); }

private:
  DenseSet<const Instruction *> targets;
  DenseSet<const CallInst *> coreTargets;
  DenseSet<const CallInst *> startingPoints;
  DenseSet<const Argument *> relevantArgs;

  void buildNonArgStartingPoint(const Module &m) { recordDeviceNodeGetter(m); }

  void recordCallers(const Function *f) {
    DenseSet<const Function *> visited;
    std::queue<const Function *> worklist;
    worklist.push(f);
    while (!worklist.empty()) {
      const Function *f = worklist.front();
      worklist.pop();
      if (!visited.insert(f).second)
        continue;
      for (const CallInst *call : getCalls(f)) {
        startingPoints.insert(call);
        worklist.push(call->getFunction());
      }
    }
  }

  void recordDeviceNodeGetter(const Module &m) {
    StringRef names[] = {
        "__DRVHORN_get_device_node",
        "__DRVHORN_create_device_node",
    };
    for (StringRef name : names) {
      if (const Function *getDevNode = m.getFunction(name)) {
        recordCallers(getDevNode);
      }
    }
    for (const Function &f : m) {
      if (f.getName().startswith(DEVICE_GETTER_PREFIX)) {
        recordCallers(&f);
      }
    }
  }

  void buildCoreTargets(const Module &m) {
    StringRef fnNames[] = {
        "kobject_init",
        "kobject_get",
        "kobject_put",
    };
    for (StringRef name : fnNames) {
      if (const Function *f = m.getFunction(name)) {
        for (const CallInst *call : getCalls(f)) {
          coreTargets.insert(call);
        }
      }
    }
  }

  void buildRelevantArgs(const CallInst *call, unsigned argIdx,
                         DenseSet<const Value *> &memo) {
    if (!memo.insert(call).second)
      return;
    const Value *v = call->getArgOperand(argIdx);
    DenseMap<const Value *, const Value *> baseMemo;
    if (const Value *base = baseOfValue(v, baseMemo)) {
      if (const Argument *arg = dyn_cast<Argument>(base)) {
        relevantArgs.insert(arg);
        for (const CallInst *call : getCalls(arg->getParent())) {
          buildRelevantArgs(call, arg->getArgNo(), memo);
        }
      }
    }
  }

  // returns either an llvm::Argument*, an llvm::CallInst*, or nullptr.
  const Value *baseOfValue(const Value *v,
                           DenseMap<const Value *, const Value *> &memo) const {
    if (const Argument *arg = dyn_cast<Argument>(v)) {
      return arg;
    }
    if (isa<Constant, MetadataAsValue, InlineAsm>(v)) {
      return nullptr;
    }
    if (memo.count(v))
      return memo[v];
    memo[v] = nullptr;
    if (const Instruction *inst = dyn_cast<Instruction>(v)) {
      return memo[v] = baseOfInst(inst, memo);
    }
    if (const Operator *op = dyn_cast<Operator>(v)) {
      for (const Value *v : op->operands()) {
        if (const Value *base = baseOfValue(v, memo)) {
          return memo[op] = base;
        }
      }
      return nullptr;
    }
    errs() << "TODO: baseOfValue " << *v << '\n';
    std::exit(1);
  }

  const Value *baseOfInst(const Instruction *inst,
                          DenseMap<const Value *, const Value *> &memo) const {
    if (const PHINode *phi = dyn_cast<PHINode>(inst)) {
      for (const Value *v : phi->incoming_values()) {
        if (const Value *base = baseOfValue(v, memo)) {
          return base;
        }
      }
      return nullptr;
    } else if (const CallInst *call = dyn_cast<CallInst>(inst)) {
      if (startingPoints.count(call) || coreTargets.count(call)) {
        return call;
      }
      return nullptr;
    } else {
      for (const Value *v : inst->operands()) {
        if (const Value *base = baseOfValue(v, memo)) {
          return base;
        }
      }
      return nullptr;
    }
  }

  void buildTargets(const Module &m) {
    DenseMap<const Value *, bool> memo;
    for (const Function &f : m) {
      for (const Instruction &inst : instructions(f)) {
        if (isa<BranchInst, SwitchInst, ReturnInst, PHINode, UnreachableInst>(
                inst)) {
          targets.insert(&inst);
        } else {
          isValueTarget(&inst, memo);
        }
      }
    }
    errs() << "target counts " << targets.size() << "\n";
  }

  bool isValueTarget(const Value *v, DenseMap<const Value *, bool> &memo) {
    if (isa<Argument>(v))
      return true;
    if (isa<Constant, MetadataAsValue, InlineAsm>(v))
      return false;
    if (memo.count(v))
      return memo[v];
    memo[v] = false;
    if (const Instruction *inst = dyn_cast<Instruction>(v)) {
      return memo[v] = isInstTarget(inst, memo);
    } else if (const Operator *op = dyn_cast<Operator>(v)) {
      for (const Value *v : op->operands()) {
        if (isValueTarget(v, memo)) {
          return memo[op] = true;
        }
      }
      return false;
    } else {
      errs() << "TODO: isValueTarget " << *v << '\n';
      std::exit(1);
    }
  }

  bool isInstTarget(const Instruction *inst,
                    DenseMap<const Value *, bool> &memo) {
    if (const PHINode *phi = dyn_cast<PHINode>(inst)) {
      return isPHITarget(phi, memo);
    } else if (const CallInst *call = dyn_cast<CallInst>(inst)) {
      return isCallTarget(call, memo);
    } else if (const LoadInst *load = dyn_cast<LoadInst>(inst)) {
      return isLoadTarget(load, memo);
    } else if (isa<StoreInst>(inst)) {
      return false;
    } else {
      for (const Value *v : inst->operands()) {
        if (isValueTarget(v, memo)) {
          targets.insert(inst);
          return true;
        }
      }
      return false;
    }
  }

  bool isPHITarget(const PHINode *phi, DenseMap<const Value *, bool> &memo) {
    for (const Value *v : phi->incoming_values()) {
      if (isValueTarget(v, memo)) {
        targets.insert(phi);
        return true;
      }
    }
    return false;
  }

  bool isCallTarget(const CallInst *call, DenseMap<const Value *, bool> &memo) {
    if (startingPoints.count(call) || coreTargets.count(call)) {
      targets.insert(call);
      return true;
    }
    for (unsigned i = 0; i < call->arg_size(); i++) {
      const Value *argVal = call->getArgOperand(i);
      if (isValueTarget(argVal, memo)) {
        if (const Function *f = extractCalledFunction(call)) {
          if (relevantArgs.count(f->getArg(i))) {
            targets.insert(call);
            return true;
          }
        }
      }
    }
    return false;
  }

  bool isLoadTarget(const LoadInst *load, DenseMap<const Value *, bool> &memo) {
    for (const StoreInst *store : getStores(load)) {
      if (isValueTarget(store->getValueOperand(), memo)) {
        targets.insert(store);
        targets.insert(load);
        return true;
      }
    }
    if (isValueTarget(load->getPointerOperand(), memo)) {
      targets.insert(load);
      return true;
    }
    return false;
  }

  SmallVector<const StoreInst *> getStores(const LoadInst *load) {
    SmallVector<const StoreInst *> stores;
    DenseSet<const Value *> visited;
    for (const User *user : load->getPointerOperand()->users()) {
      collectStores(user, stores, visited);
    }
    return stores;
  }

  void collectStores(const Value *val, SmallVector<const StoreInst *> &stores,
                     DenseSet<const Value *> &visited) {
    if (!visited.insert(val).second)
      return;
    if (const StoreInst *store = dyn_cast<StoreInst>(val)) {
      stores.push_back(store);
    } else if (const Operator *op = dyn_cast<Operator>(val)) {
      for (const Value *v : op->operands())
        collectStores(v, stores, visited);
    } else if (const SelectInst *select = dyn_cast<SelectInst>(val)) {
      collectStores(select->getTrueValue(), stores, visited);
      collectStores(select->getFalseValue(), stores, visited);
    } else if (const PHINode *phi = dyn_cast<PHINode>(val)) {
      for (const Value *v : phi->incoming_values()) {
        collectStores(v, stores, visited);
      }
    }
  }
};

class SlimDown : public ModulePass {
public:
  static char ID;

  SlimDown() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    updateLinkage(m);
    runDCEPasses(m);
    removeCompilerUsed(m);
    runDCEPasses(m);

    Filter filter(m);
    slimDownOnlyReachables(m, filter);
    runDCEPasses(m, true);
    return true;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<seahorn::SeaBuiltinsInfoWrapperPass>();
    AU.setPreservesAll();
  }

  virtual StringRef getPassName() const override { return "SlimDown"; }

private:
  DenseMap<const Value *, DenseSet<const Value *>> graph;

  void removeCompilerUsed(Module &M) {
    if (GlobalVariable *compilerUsed = M.getNamedGlobal(COMPILER_USED_NAME)) {
      Type *ty = compilerUsed->getType();
      compilerUsed->eraseFromParent();
      // llvm.compiler.used seems to be required, so insert an empty value
      M.getOrInsertGlobal(COMPILER_USED_NAME, ty->getPointerElementType());
    }
  }

  void updateLinkage(Module &m) {
    for (Function &f : m) {
      if (f.isDeclaration())
        continue;
      if (f.getName().equals("main") || f.getName().startswith("__VERIFIER_") ||
          f.getName().equals("__DRVHORN_malloc"))
        continue;
      f.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    }
    for (GlobalVariable &v : m.globals()) {
      if (v.isDeclaration())
        continue;
      v.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    }
    for (GlobalAlias &alias : m.aliases()) {
      if (alias.isDeclaration())
        continue;
      alias.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    }
  }

  void handleRetainedInst(Instruction *inst,
                          DenseMap<const Type *, Function *> &ndvalfn,
                          DenseSet<Instruction *> &toRemoveInstructions) {
    if (StoreInst *store = dyn_cast<StoreInst>(inst)) {
      if (Instruction *dst =
              dyn_cast<Instruction>(store->getPointerOperand())) {
        if (toRemoveInstructions.count(dst)) {
          AllocaInst *alloc =
              new AllocaInst(store->getValueOperand()->getType(), 0, "", dst);
          dst->replaceAllUsesWith(alloc);
        }
      }
      return;
    }
    for (unsigned i = 0; i < inst->getNumOperands(); i++) {
      if (Instruction *opInst = dyn_cast<Instruction>(inst->getOperand(i))) {
        if (toRemoveInstructions.count(opInst)) {
          Instruction *insertPoint = getRepalcementInsertPoint(opInst);
          Value *replace = nondetValue(opInst->getType(), insertPoint, ndvalfn);
          opInst->replaceAllUsesWith(replace);
        }
      }
    }
  }

  Instruction *getRepalcementInsertPoint(Instruction *inst) {
    return isa<PHINode>(inst) ? inst->getParent()->getFirstNonPHI() : inst;
  }

  Value *nondetValue(Type *type, Instruction *before,
                     DenseMap<const Type *, Function *> &ndvalfn) {
    IRBuilder<> b(before);
    if (!type->isPointerTy()) {
      Function *nondetFn = getNondetValueFn(type, before->getModule(), ndvalfn);
      Value *call = b.CreateCall(nondetFn);
      if (StructType *s = dyn_cast<StructType>(type)) {
        for (unsigned i = 0; i < s->getNumElements(); i++) {
          Value *elem = nondetValue(s->getElementType(i), before, ndvalfn);
          call = b.CreateInsertValue(call, elem, i);
        }
      }
      return call;
    }

    Module *m = before->getModule();
    Type *elemType = type->getPointerElementType();
    if (FunctionType *ft = dyn_cast<FunctionType>(elemType)) {
      return makeNewValFn(m, ft, ndvalfn.size());
    }
    /*Function *malloc = nondetMalloc(m);*/
    /*FunctionType *ft =*/
    /*    FunctionType::get(type, malloc->getArg(0)->getType(), false);*/
    /*Constant *casted = ConstantExpr::getBitCast(malloc, ft->getPointerTo());*/
    /*size_t size = m->getDataLayout().getTypeAllocSize(elemType);*/
    /*Type *i64Type = Type::getInt64Ty(m->getContext());*/
    /*Value *call = b.CreateCall(ft, casted, ConstantInt::get(i64Type, size));*/
    Value *call = b.CreateAlloca(elemType);
    if (elemType->isPointerTy()) {
      Value *value = nondetValue(elemType, before, ndvalfn);
      b.CreateStore(value, call);
    }
    return call;
  }

  Function *nondetMalloc(Module *m) {
    if (Function *f = m->getFunction("nondet.malloc"))
      return f;
    FunctionType *nondetMallocType =
        FunctionType::get(Type::getInt8PtrTy(m->getContext()),
                          Type::getInt64Ty(m->getContext()), false);
    return Function::Create(nondetMallocType,
                            GlobalValue::LinkageTypes::ExternalLinkage,
                            "nondet.malloc", m);
  }

  void slimDownOnlyReachables(Module &m, const Filter &filter) {
    DenseSet<Instruction *> toRemoveInstructions;
    DenseMap<const Type *, Function *> ndvalfn;
    for (Function &f : m) {
      // we keep these functions still.
      if (f.getName().equals("main") || f.getName().equals("kobject_get") ||
          f.getName().equals("kobject_put") ||
          f.getName().equals("kobject_init") ||
          f.getName().startswith("__DRVHORN_") || f.isDeclaration())
        continue;
      SmallVector<Instruction *> retained;
      for (BasicBlock &bb : f) {
        for (Instruction &inst : bb) {
          if (filter.isTarget(&inst)) {
            retained.push_back(&inst);
          } else {
            toRemoveInstructions.insert(&inst);
          }
        }
      }
      for (Instruction *inst : retained) {
        handleRetainedInst(inst, ndvalfn, toRemoveInstructions);
      }
    }
    for (Instruction *inst : toRemoveInstructions) {
      inst->eraseFromParent();
    }
  }

  void runDCEPasses(Module &m, bool removeArg = false) {
    legacy::PassManager pm;
    pm.add(createVerifierPass(false));
    pm.add(createAggressiveDCEPass());
    pm.add(createGlobalDCEPass());
    if (removeArg)
      pm.add(createDeadArgEliminationPass());
    pm.add(createCFGSimplificationPass());
    int counter = 0;
    while (counter++ < 10) {
      removeUnusedNondetCalls(m);
      if (!pm.run(m))
        break;
    }
  }

  void removeUnusedNondetCalls(Module &m) {
    // nondet function calls are not removed by DCE passes.
    std::vector<Instruction *> toRemove;
    for (Function &f : m) {
      for (Instruction &inst : instructions(f)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (Function *f = extractCalledFunction(call)) {
            if (f->getName().equals("verifier.error") ||
                f->getName().equals("verifier.assume"))
              continue;
            if (f->isDeclaration() && call->user_empty())
              toRemove.push_back(call);
          }
        }
      }
    }
    for (Instruction *inst : toRemove) {
      inst->eraseFromParent();
    }
  }

  Function *getNondetValueFn(Type *retType, Module *m,
                             DenseMap<const Type *, Function *> &ndvalfn) {
    auto it = ndvalfn.find(retType);
    if (it != ndvalfn.end()) {
      return it->second;
    }
    Function *res =
        makeNewValFn(m, retType, ndvalfn.size(), "verifier.nondetvalue.");
    ndvalfn[retType] = res;
    return res;
  }

  Function *makeNewValFn(Module *m, Type *type, unsigned startFrom,
                         std::string prefix) {
    std::string name;
    unsigned c = startFrom;
    do {
      name = prefix + std::to_string(c++);
    } while (m->getNamedValue(name));
    return Function::Create(FunctionType::get(type, false),
                            GlobalValue::LinkageTypes::ExternalLinkage, name,
                            m);
  }

  Function *makeNewValFn(Module *m, FunctionType *type, unsigned startFrom) {
    std::string name;
    unsigned c = startFrom;
    do {
      name = "verifier.nondetvaluefn." + std::to_string(c++);
    } while (m->getNamedValue(name));
    return Function::Create(type, GlobalValue::LinkageTypes::ExternalLinkage,
                            name, m);
  }
};

char SlimDown::ID = 0;
Pass *createSlimDownPass() { return new SlimDown(); }
} // namespace seahorn
