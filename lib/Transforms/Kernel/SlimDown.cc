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

#include <queue>

#define COMPILER_USED_NAME "llvm.compiler.used"
#define DEVICE_GETTER_PREFIX "__DRVHORN_embedded_device.getter."

using namespace llvm;

namespace seahorn {

struct Visitor : public InstVisitor<Visitor, bool> {
public:
  bool isTarget(const Instruction *inst) const { return targets.count(inst); }

  void visitModule(Module &m) {
    DenseSet<const CallInst *> kobjCalls = getKobjCalls(m);
    DenseSet<const Value *> memo;
    buildStartingPoint(m);
    for (const CallInst *call : kobjCalls) {
      const Function *f = extractCalledFunction(call);
      targetArgs.insert(f->getArg(0));
      buildTargetArgs(call->getArgOperand(0), memo, kobjCalls);
    }
  }

  bool visitCallInst(CallInst &call) {
    Function *f = extractCalledFunction(call);
    if (!f) {
      cache[&call] = false;
      return false;
    }
    bool isTarget = false;
    if (startingPoints.count(&call)) {
      isTarget = true;
    }
    for (Argument &arg : f->args()) {
      if (targetArgs.count(&arg)) {
        isTarget = true;
      }
    }
    if (isTarget) {
      targets.insert(&call);
    }
    cache[&call] = isTarget;
    return isTarget;
  }

  bool visitLoadInst(LoadInst &load) {
    bool isTarget = false;
    if (visitValue(load.getPointerOperand())) {
      isTarget = true;
      targets.insert(&load);
    }
    cache[&load] = isTarget;
    return isTarget;
  }

  bool visitStoreInst(StoreInst &store) {
    Value *v = getUnderlyingObject(store.getPointerOperand());
    DenseSet<Value *> visited;
    SmallVector<Value *> workList;
    workList.push_back(v);
    visited.insert(v);

    bool isTarget = false;
    while (!workList.empty()) {
      Value *v = workList.back();
      workList.pop_back();
      if (visitValue(v)) {
        isTarget = true;
        break;
      }
      if (LoadInst *load = dyn_cast<LoadInst>(v)) {
        Value *nxt = getUnderlyingObject(load->getPointerOperand());
        if (visited.insert(nxt).second) {
          workList.push_back(nxt);
        }
      }
    }

    if (isTarget)
      targets.insert(&store);
    cache[&store] = isTarget;
    return isTarget;
  }

  bool visitPHINode(PHINode &phi) {
    cache[&phi] = true;
    for (Value *v : phi.incoming_values()) {
      visitValue(v);
    }
    targets.insert(&phi);
    return true;
  }

  bool visitTerminator(Instruction &inst) {
    cache[&inst] = true;
    for (Value *v : inst.operands()) {
      visitValue(v);
    }
    targets.insert(&inst);
    return true;
  }

  bool visitInstruction(Instruction &inst) {
    bool isTarget = false;
    for (Value *v : inst.operands()) {
      if (visitValue(v))
        isTarget = true;
    }
    if (isTarget) {
      targets.insert(&inst);
    }
    cache[&inst] = isTarget;
    return isTarget;
  }

private:
  DenseMap<const Value *, bool> cache;
  DenseSet<const CallInst *> startingPoints;
  DenseSet<const Argument *> targetArgs;
  DenseSet<const Instruction *> targets;

  bool visitValue(Value *v) {
    if (Argument *arg = dyn_cast<Argument>(v))
      return targetArgs.count(arg);
    if (isa<Constant>(v))
      return true;
    if (isa<BasicBlock, MetadataAsValue, InlineAsm>(v))
      return false;
    if (cache.count(v))
      return cache[v];

    cache[v] = false;
    if (Instruction *inst = dyn_cast<Instruction>(v)) {
      return cache[v] = visit(*inst);
    } else if (Operator *op = dyn_cast<Operator>(v)) {
      for (Value *v : op->operands()) {
        if (visitValue(v)) {
          return cache[op] = true;
        }
      }
      return false;
    } else {
      errs() << "TODO: isValueTarget " << *v << '\n';
      std::exit(1);
    }
  }

  void recordCallers(const Function *f) {
    DenseSet<const Function *> visited;
    std::queue<const Function *> workList;
    workList.push(f);
    while (!workList.empty()) {
      const Function *f = workList.front();
      workList.pop();
      if (!visited.insert(f).second)
        continue;
      for (const CallInst *call : getCalls(f)) {
        startingPoints.insert(call);
        workList.push(call->getFunction());
      }
    }
  }

  void buildStartingPoint(const Module &m) {
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

  DenseSet<const CallInst *> getKobjCalls(const Module &m) {
    StringRef fnNames[] = {
        "drvhorn.kref_init",
        "drvhorn.kref_get",
        "drvhorn.kref_put",
    };
    DenseSet<const CallInst *> calls;
    for (StringRef name : fnNames) {
      if (const Function *f = m.getFunction(name)) {
        for (const CallInst *call : getCalls(f)) {
          calls.insert(call);
        }
      }
    }
    return calls;
  }

  void buildTargetArgs(const Value *argVal, DenseSet<const Value *> &memo,
                       const DenseSet<const CallInst *> &kobjCalls) {
    if (!memo.insert(argVal).second)
      return;
    DenseMap<const Value *, const Value *> baseMemo;
    if (const Argument *arg = dyn_cast_or_null<Argument>(
            baseOfValue(argVal, baseMemo, kobjCalls))) {
      targetArgs.insert(arg);
      for (const CallInst *call : getCalls(arg->getParent())) {
        const Value *v = call->getArgOperand(arg->getArgNo());
        buildTargetArgs(v, memo, kobjCalls);
      }
    }
  }

  // returns either an llvm::Argument*, an llvm::CallInst*, or nullptr.
  // TODO: use getUnderlyingObject instead.
  const Value *baseOfValue(const Value *v,
                           DenseMap<const Value *, const Value *> &memo,
                           const DenseSet<const CallInst *> &kobjCalls) const {
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
      return memo[v] = baseOfInst(inst, memo, kobjCalls);
    }
    if (const Operator *op = dyn_cast<Operator>(v)) {
      for (const Value *v : op->operands()) {
        if (const Value *base = baseOfValue(v, memo, kobjCalls)) {
          return memo[op] = base;
        }
      }
      return nullptr;
    }
    errs() << "TODO: baseOfValue " << *v << '\n';
    std::exit(1);
  }

  const Value *baseOfInst(const Instruction *inst,
                          DenseMap<const Value *, const Value *> &memo,
                          const DenseSet<const CallInst *> &kobjCalls) const {
    if (const PHINode *phi = dyn_cast<PHINode>(inst)) {
      for (const Value *v : phi->incoming_values()) {
        if (const Value *base = baseOfValue(v, memo, kobjCalls)) {
          return base;
        }
      }
      return nullptr;
    } else if (const CallInst *call = dyn_cast<CallInst>(inst)) {
      if (kobjCalls.count(call)) {
        return baseOfValue(call->getArgOperand(0), memo, kobjCalls);
      }
      if (startingPoints.count(call)) {
        return call;
      }
      return nullptr;
    } else {
      for (const Value *v : inst->operands()) {
        if (const Value *base = baseOfValue(v, memo, kobjCalls)) {
          return base;
        }
      }
      return nullptr;
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
    removeObviousGetPutPairs(m);
    runDCEPasses(m);

    slimDownOnlyReachables(m);
    runDCEPasses(m, true);
    removeNotCalledFunctions(m);
    runDCEPasses(m, true);
    return true;
  }

  void getAnalysisUsage(AnalysisUsage &au) const override {
    au.addRequired<seahorn::SeaBuiltinsInfoWrapperPass>();
    au.setPreservesAll();
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

  void removeObviousGetPutPairs(Module &m) {
    // remove obvious get/put pairs.
    // If a pair resides in the same basic block, we can remove them.
    std::pair<StringRef, StringRef> pairs[] = {
        {"kobject_get", "kobject_put"},
        {"get_device", "put_device"},
        {"of_node_get", "of_node_put"},
    };
    for (std::pair<StringRef, StringRef> &p : pairs) {
      for (Function &f : m) {
        for (BasicBlock &blk : f) {
          CallInst *getter = nullptr;
          CallInst *putter = nullptr;
          Value *op = nullptr;
          for (Instruction &inst : blk) {
            if (CallInst *call = dyn_cast<CallInst>(&inst)) {
              Function *callee = extractCalledFunction(call);
              if (!getter) {
                if (callee && callee->getName().equals(p.first)) {
                  getter = call;
                  op = call->getArgOperand(0);
                }
              } else {
                if (callee && callee->getName().equals(p.second) &&
                    call->getArgOperand(0) == op)
                  putter = call;
              }
            }
          }
          if (putter) {
            getter->replaceAllUsesWith(op);
            putter->replaceAllUsesWith(op);
            getter->eraseFromParent();
            putter->eraseFromParent();
          }
        }
      }
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
                          const DenseSet<Instruction *> &toRemoveInstructions) {
    for (Value *op : inst->operands()) {
      if (Instruction *opInst = dyn_cast<Instruction>(op)) {
        if (toRemoveInstructions.count(opInst)) {
          Value *replace = getReplacement(opInst, ndvalfn);
          opInst->replaceAllUsesWith(replace);
        }
      }
    }
  }

  Value *getReplacement(Instruction *inst,
                        DenseMap<const Type *, Function *> &ndvalfn) {
    Instruction *insertPoint =
        isa<PHINode>(inst) ? inst->getParent()->getFirstNonPHI() : inst;
    return nondetValue(inst->getType(), insertPoint, ndvalfn);
  }

  void slimDownOnlyReachables(Module &m) {
    Visitor visitor;
    visitor.visit(m);
    DenseSet<Instruction *> toRemoveInstructions;
    DenseMap<const Type *, Function *> ndvalfn;
    for (Function &f : m) {
      // we keep these functions still.
      if (f.getName().equals("main") || f.getName().startswith("drvhorn.") ||
          f.getName().startswith("__DRVHORN_") || f.isDeclaration())
        continue;
      SmallVector<Instruction *> retained;
      for (Instruction &inst : instructions(f)) {
        if (visitor.isTarget(&inst)) {
          retained.push_back(&inst);
        } else {
          toRemoveInstructions.insert(&inst);
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

  void removeNotCalledFunctions(Module &m) {
    for (Function &f : m) {
      if (!f.getName().equals("main") && getCalls(&f).empty())
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
