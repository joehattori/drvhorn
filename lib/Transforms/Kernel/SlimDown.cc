#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstVisitor.h"
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

#define COMPILER_USED_NAME "llvm.compiler.used"

using namespace llvm;

namespace seahorn {

struct Filter : public InstVisitor<Filter, bool> {
public:
  Filter(Module &m) {
    buildStartingPoint(m);
    buildTargetArgs(m);

    for (Function &f : m) {
      // First, track return insts.
      for (BasicBlock &blk : f) {
        if (ReturnInst *ret = dyn_cast<ReturnInst>(blk.getTerminator())) {
          visitReturnInst(*ret);
          recordUnderlyingObjectOfRetVal(ret);
        }
      }
      // store and some calls cannot be tracked from ret.
      for (Instruction &inst : instructions(f)) {
        if (StoreInst *store = dyn_cast<StoreInst>(&inst)) {
          visitStoreInst(*store);
        } else if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          visitCallInst(*call);
        }
      }
    }
  }

  bool isTarget(const Instruction *inst) {
    if (inst->isTerminator())
      return true;
    return targets.count(inst);
  }

  bool visitReturnInst(ReturnInst &ret) {
    acceptInst(&ret);
    if (Value *retVal = ret.getReturnValue()) {
      visitValue(retVal);
    }
    return true;
  }

  bool visitLoadInst(LoadInst &load) {
    Value *ptr = load.getPointerOperand();
    bool isTarget = visitValue(ptr);
    if (isTarget) {
      acceptInst(&load);
      underlyingLoadedPtrs.insert(getUnderlyingObject(ptr));
    }
    return isTarget;
  }

  bool visitStoreInst(StoreInst &store) {
    bool isTarget = isStoreTarget(&store);
    if (isTarget) {
      acceptInst(&store);
      visitValue(store.getValueOperand());
      visitValue(store.getPointerOperand());
    }
    return isTarget;
  }

  // ignore ptrtoint
  bool visitPtrToIntInst(PtrToIntInst &ptrToInt) { return false; }

  bool visitCallInst(CallInst &call) {
    bool isTarget = startingPoints.count(&call);
    if (Function *f = extractCalledFunction(call)) {
      for (Argument &arg : f->args()) {
        isTarget |= targetArgs.count(&arg);
      }
    }
    if (isTarget) {
      acceptInst(&call);
      for (Value *v : call.operands()) {
        visitValue(v);
      }
    }
    return isTarget;
  }

  bool visitBranchInst(BranchInst &br) {
    if (br.isConditional()) {
      visitValue(br.getCondition());
    }
    acceptInst(&br);
    return true;
  }

  bool visitPHINode(PHINode &phi) {
    for (Value *v : phi.incoming_values()) {
      visitValue(v);
    }
    acceptInst(&phi);
    return true;
  }

  bool visitInstruction(Instruction &inst) {
    bool isTarget =
        all_of(inst.operands(), [this](Value *v) { return visitValue(v); });
    if (isTarget) {
      acceptInst(&inst);
    }
    return isTarget;
  }

private:
  DenseSet<const CallInst *> startingPoints;
  DenseSet<const Argument *> targetArgs;
  DenseSet<const Instruction *> targets;
  DenseSet<const Value *> underlyingLoadedPtrs;
  DenseSet<const Value *> underlyingRetPtrs;
  DenseSet<const Value *> underlyingTargetArgsPtrs;
  DenseMap<const Value *, bool> cache;

  bool visitValue(Value *val) {
    if (cache.count(val))
      return cache[val];
    cache[val] = false;
    bool isTarget = false;
    if (Instruction *inst = dyn_cast<Instruction>(val)) {
      isTarget = visit(*inst);
    } else if (BasicBlock *blk = dyn_cast<BasicBlock>(val)) {
      isTarget = visit(*blk->getTerminator());
    } else if (Operator *op = dyn_cast<Operator>(val)) {
      isTarget = visitOperator(op);
    } else if (Constant *c = dyn_cast<Constant>(val)) {
      isTarget = visitConstant(c);
    } else if (isa<Argument>(val)) {
      isTarget = true;
    }
    cache[val] = isTarget;
    return isTarget;
  }

  bool visitConstant(Constant *c) {
    if (ConstantExpr *ce = dyn_cast<ConstantExpr>(c)) {
      return visitValue(ce->getAsInstruction());
    }
    return true;
  }

  bool visitOperator(Operator *op) {
    if (isa<BitCastOperator, GEPOperator>(op))
      return visitValue(op->getOperand(0));
    return false;
  }

  void acceptInst(Instruction *inst) {
    targets.insert(inst);
    for (BasicBlock *blk : predecessors(inst->getParent())) {
      visitValue(blk->getTerminator());
    }
  }

  bool isStoreTarget(const StoreInst *store) {
    const Value *v = getUnderlyingObject(store->getPointerOperand());
    if (const Argument *arg = dyn_cast<Argument>(v)) {
      return targetArgs.count(arg);
    }
    return underlyingLoadedPtrs.count(v) || underlyingRetPtrs.count(v) ||
           underlyingTargetArgsPtrs.count(v);
  }

  void recordUnderlyingObjectOfRetVal(ReturnInst *ret) {
    Value *retVal = ret->getReturnValue();
    if (retVal->getType()->isPointerTy()) {
      SmallVector<const Value *> objects;
      getUnderlyingObjects(retVal, objects, nullptr, 0);
      for (const Value *v : objects) {
        underlyingRetPtrs.insert(v);
      }
    }
  }

  void recordCallers(const Function *f) {
    DenseSet<const Function *> visited;
    SmallVector<const Function *> workList;
    workList.push_back(f);
    while (!workList.empty()) {
      const Function *f = workList.back();
      workList.pop_back();
      if (!visited.insert(f).second)
        continue;
      for (const CallInst *call : getCalls(f)) {
        startingPoints.insert(call);
        workList.push_back(call->getFunction());
      }
    }
  }

  void buildStartingPoint(const Module &m) {
    if (const Function *f = m.getFunction("drvhorn.update_index")) {
      recordCallers(f);
    }
  }

  void buildTargetArgs(Module &m) {
    buildKrefTargetArgs(m);
    for (const Argument *arg : targetArgs) {
      const Function *f = arg->getParent();
      for (const CallInst *call : getCalls(f)) {
        if (const Value *v = call->getArgOperand(arg->getArgNo())) {
          SmallVector<const Value *> objs;
          getUnderlyingObjects(v, objs, nullptr, 0);
          for (const Value *obj : objs) {
            underlyingTargetArgsPtrs.insert(obj);
          }
        }
      }
    }
  }

  void buildKrefTargetArgs(Module &m) {
    SmallVector<const Argument *> workList;
    DenseSet<const Argument *> visited;
    StringRef fnNames[] = {
        "drvhorn.kref_init",
        "drvhorn.kref_get",
        "drvhorn.kref_put",
    };
    for (StringRef name : fnNames) {
      if (const Function *f = m.getFunction(name)) {
        const Argument *arg = f->getArg(0);
        workList.push_back(arg);
        visited.insert(arg);
      }
    }

    while (!workList.empty()) {
      const Argument *arg = workList.pop_back_val();
      targetArgs.insert(arg);
      for (const CallInst *call : getCalls(arg->getParent())) {
        const Value *v = call->getArgOperand(arg->getArgNo());
        for (const Argument *arg : underlyingArgs(v)) {
          if (visited.insert(arg).second) {
            workList.push_back(arg);
          }
        }
      }
    }
  }

  SmallVector<const Argument *> underlyingArgs(const Value *v) {
    SmallVector<const Value *> objects;
    getUnderlyingObjects(v, objects, nullptr, 0);

    SmallVector<const Argument *> ret;
    for (const Value *v : objects) {
      if (const Argument *arg = dyn_cast<Argument>(v))
        ret.push_back(arg);
    }
    return ret;
  }
};

class SlimDown : public ModulePass {
public:
  static char ID;

  SlimDown() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    m.setModuleInlineAsm("");
    ignoreSomeFunctions(m);
    updateLinkage(m);
    removeCompilerUsed(m);
    runDCEPasses(m);

    sliceModule(m);
    runDCEPasses(m, 10);
    removeNotCalledFunctions(m);
    runDCEPasses(m, 20);
    return true;
  }

  void getAnalysisUsage(AnalysisUsage &au) const override {
    au.addRequired<seahorn::SeaBuiltinsInfoWrapperPass>();
    au.setPreservesAll();
  }

  virtual StringRef getPassName() const override { return "SlimDown"; }

private:
  void removeCompilerUsed(Module &m) {
    if (GlobalVariable *compilerUsed = m.getNamedGlobal(COMPILER_USED_NAME)) {
      Type *ty = compilerUsed->getType();
      compilerUsed->eraseFromParent();
      // llvm.compiler.used seems to be required, so insert an empty value
      m.getOrInsertGlobal(COMPILER_USED_NAME, ty->getPointerElementType());
    }
  }

  void updateLinkage(Module &m) {
    for (Function &f : m) {
      if (f.isDeclaration() || f.getName().equals("main") ||
          f.getName().startswith("__VERIFIER_") ||
          // might be used later
          f.getName().equals("drvhorn.assert_kref") ||
          f.getName().equals("drvhorn.kref_init") ||
          f.getName().equals("drvhorn.malloc"))
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
                          const DenseSet<Instruction *> &toRemoveInstructions,
                          DenseSet<Instruction *> &removedInstructions) {
    for (Value *op : inst->operands()) {
      if (Instruction *opInst = dyn_cast<Instruction>(op)) {
        if (toRemoveInstructions.count(opInst)) {
          if (!removedInstructions.insert(opInst).second)
            continue;
          if (CallInst *call = dyn_cast<CallInst>(opInst))
            handleRetainedCallInst(call, toRemoveInstructions, ndvalfn);
          Value *replace = getReplacement(opInst, ndvalfn);
          opInst->replaceAllUsesWith(replace);
        }
      }
    }
  }

  void
  handleRetainedCallInst(CallInst *call,
                         const DenseSet<Instruction *> &toRemoveInstructions,
                         DenseMap<const Type *, Function *> &ndvalfn) {
    Function *f = extractCalledFunction(call);
    if (!f)
      return;
    for (Argument &arg : f->args()) {
      if (arg.hasAttribute(Attribute::WriteOnly)) {
        Value *argVal =
            call->getArgOperand(arg.getArgNo())->stripPointerCasts();
        if (Instruction *inst = dyn_cast<Instruction>(argVal)) {
          if (toRemoveInstructions.count(inst))
            continue;
        }
        Value *ndVal = nondetValue(argVal->getType()->getPointerElementType(),
                                   call, ndvalfn);
        ndVal->setName("writeonly_filler." + call->getName().str());
        IRBuilder<> b(call);
        b.CreateStore(ndVal, argVal);
      }
    }
  }

  bool isPointerToOpaqueType(Type *type) {
    if (type->isPointerTy())
      return isPointerToOpaqueType(type->getPointerElementType());
    if (StructType *structType = dyn_cast<StructType>(type)) {
      return structType->isOpaque();
    }
    return false;
  }

  Value *getReplacement(Instruction *inst,
                        DenseMap<const Type *, Function *> &ndvalfn) {
    Instruction *insertPoint =
        isa<PHINode>(inst) ? inst->getParent()->getFirstNonPHI() : inst;
    return nondetValue(inst->getType(), insertPoint, ndvalfn);
  }

  void ignoreSomeFunctions(Module &m) {
    StringRef names[] = {
        "slob_free",
        "refcount_warn_saturate",
        "__kobject_del",
        "kobject_uevent_env",
        "__mdiobus_register",
        "mdiobus_unregister",
        "device_add",
        "device_del",
        "device_register",
        "device_unregister",
        "__of_mdiobus_register",
        "of_property_notify",
        "fwnode_mdiobus_register_phy",
        "fwnode_mdiobus_phy_device_register",
    };
    for (StringRef name : names) {
      if (Function *f = m.getFunction(name))
        f->deleteBody();
    }
  }

  void sliceModule(Module &m) {
    Filter filter(m);
    DenseMap<const Type *, Function *> ndvalfn;
    for (Function &f : m) {
      // we keep these functions still.
      if (f.getName().equals("main") || f.getName().startswith("drvhorn.") ||
          f.isDeclaration())
        continue;
      DenseSet<Instruction *> toRemoveInstructions;
      DenseSet<Instruction *> removedInstructions;
      SmallVector<Instruction *> retained;
      for (Instruction &inst : instructions(f)) {
        if (filter.isTarget(&inst)) {
          retained.push_back(&inst);
        } else {
          toRemoveInstructions.insert(&inst);
        }
      }
      for (Instruction *inst : retained) {
        handleRetainedInst(inst, ndvalfn, toRemoveInstructions,
                           removedInstructions);
      }
      for (Instruction *inst : toRemoveInstructions) {
        inst->eraseFromParent();
      }
    }
  }

  void runDCEPasses(Module &m, unsigned limit = 1) {
    legacy::PassManager pm;
    pm.add(createVerifierPass(false));
    pm.add(createGlobalDCEPass());
    pm.add(createAggressiveDCEPass());
    pm.add(createDeadArgEliminationPass());
    pm.add(createCFGSimplificationPass());
    unsigned counter = 0;
    while (counter++ < limit) {
      removeUnusedNondetCalls(m);
      if (!pm.run(m))
        break;
    }
  }

  void removeNotCalledFunctions(Module &m) {
    for (Function &f : m) {
      if (getCalls(&f).empty() && !f.getName().equals("main") &&
          // functions below might be used later.
          !f.getName().equals("drvhorn.fail") &&
          !f.getName().equals("drvhorn.kref_init") &&
          !f.getName().equals("drvhorn.assert_kref"))
        f.deleteBody();
    }
  }

  void removeUnusedNondetCalls(Module &m) {
    // nondet function calls are not removed by DCE passes.
    SmallVector<Instruction *, 16> toRemove;
    SeaBuiltinsInfo &sbi = getAnalysis<SeaBuiltinsInfoWrapperPass>().getSBI();
    for (Function &f : m) {
      for (Instruction &inst : instructions(f)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (sbi.isSeaBuiltin(*call)) {
            continue;
          }
          if (Function *f = extractCalledFunction(call)) {
            if (f->isDeclaration() && call->user_empty() &&
                !f->getName().equals("drvhorn.fail"))
              toRemove.push_back(call);
          }
        }
      }
    }
    for (Instruction *inst : toRemove) {
      inst->eraseFromParent();
    }
  }

  Value *nondetValue(Type *type, Instruction *before,
                     DenseMap<const Type *, Function *> &ndvalfn) {
    IRBuilder<> b(before);
    Module *m = before->getModule();
    if (!type->isPointerTy()) {
      Function *nondetFn = getNondetValueFn(type, m, ndvalfn);
      Value *call = b.CreateCall(nondetFn);
      if (StructType *s = dyn_cast<StructType>(type)) {
        for (unsigned i = 0; i < s->getNumElements(); i++) {
          Value *elem = nondetValue(s->getElementType(i), before, ndvalfn);
          call = b.CreateInsertValue(call, elem, i);
        }
      }
      return call;
    }

    Type *elemType = type->getPointerElementType();
    if (FunctionType *ft = dyn_cast<FunctionType>(elemType)) {
      return makeNewValFn(m, ft, ndvalfn.size());
    }
    if (StructType *st = dyn_cast<StructType>(elemType)) {
      if (st->isOpaque()) {
        Function *f = getNondetValueFn(type, m, ndvalfn);
        return b.CreateCall(f);
      }
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
