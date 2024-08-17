#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/AliasAnalysis.h"
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
      buildTargetArgs(call, 0, memo, kobjCalls);
    }
  }

  bool visitCallInst(CallInst &call) {
    const Function *f = extractCalledFunction(call);
    if (!f) {
      cache[&call] = false;
      return false;
    }
    bool isTarget = false;
    if (startingPoints.count(&call)) {
      isTarget = true;
    }
    for (const Argument &arg : f->args()) {
      if (targetArgs.count(&arg)) {
        const Value *argVal = call.getArgOperand(arg.getArgNo());
        acceptValue(argVal);
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
    bool isTarget = visitValue(load.getPointerOperand());
    for (StoreInst *store : getStores(load)) {
      if (visitValue(store->getValueOperand())) {
        targets.insert(store);
        isTarget = true;
      }
    }
    if (isTarget)
      targets.insert(&load);
    cache[&load] = isTarget;
    return isTarget;
  }

  bool visitStore(StoreInst &store) {
    bool isTarget = false;
    if (const Argument *arg = dyn_cast<Argument>(
            getUnderlyingObject(store.getPointerOperand()))) {
      isTarget = targetArgs.count(arg);
    }
    if (isTarget) {
      targets.insert(&store);
      acceptValue(store.getValueOperand());
      acceptValue(store.getPointerOperand());
    }
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

  SmallVector<StoreInst *> getStores(LoadInst &load) {
    SmallVector<StoreInst *> stores;
    DenseSet<Value *> visited;
    for (User *user : load.getPointerOperand()->stripPointerCasts()->users()) {
      collectStores(user, stores, visited);
    }
    return stores;
  }

  void collectStores(Value *val, SmallVector<StoreInst *> &stores,
                     DenseSet<Value *> &visited) {
    if (!visited.insert(val).second)
      return;
    if (StoreInst *store = dyn_cast<StoreInst>(val)) {
      stores.push_back(store);
    } else if (Operator *op = dyn_cast<Operator>(val)) {
      for (Value *v : op->operands())
        collectStores(v, stores, visited);
    } else if (SelectInst *select = dyn_cast<SelectInst>(val)) {
      collectStores(select->getTrueValue(), stores, visited);
      collectStores(select->getFalseValue(), stores, visited);
    } else if (PHINode *phi = dyn_cast<PHINode>(val)) {
      for (Value *v : phi->incoming_values()) {
        collectStores(v, stores, visited);
      }
    }
  }

  void acceptValue(const Value *v) {
    DenseSet<const Value *> visited;
    acceptValue(v, visited);
  }

  void acceptValue(const Value *v, DenseSet<const Value *> &visited) {
    if (!visited.insert(v).second)
      return;
    cache[v] = true;
    if (const Instruction *inst = dyn_cast<Instruction>(v)) {
      if (!isa<CallInst>(inst)) {
        targets.insert(inst);
        for (const Value *v : inst->operands()) {
          acceptValue(v, visited);
        }
      }
    } else if (const Operator *op = dyn_cast<Operator>(v)) {
      for (const Value *v : op->operands()) {
        acceptValue(v, visited);
      }
    }
  }

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
        "kobject_init",
        "kobject_get",
        "kobject_put",
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

  void buildTargetArgs(const CallInst *call, unsigned argIdx,
                       DenseSet<const Value *> &memo,
                       const DenseSet<const CallInst *> &kobjCalls) {
    if (!memo.insert(call).second)
      return;
    const Value *v = call->getArgOperand(argIdx);
    DenseMap<const Value *, const Value *> baseMemo;
    if (const Value *base = baseOfValue(v, baseMemo, kobjCalls)) {
      if (const Argument *arg = dyn_cast<Argument>(base)) {
        targetArgs.insert(arg);
        for (const CallInst *call : getCalls(arg->getParent())) {
          unsigned argNo = arg->getArgNo();
          buildTargetArgs(call, argNo, memo, kobjCalls);
        }
      }
    }
  }

  // returns either an llvm::Argument*, an llvm::CallInst*, or nullptr.
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
                          DenseSet<Instruction *> &toRemoveInstructions) {
    if (isa<BinaryOperator, CmpInst, GetElementPtrInst>(inst)) {
      bool isOperandRemoved =
          any_of(inst->operands(), [&toRemoveInstructions](Value *op) -> bool {
            if (Instruction *opInst = dyn_cast<Instruction>(op)) {
              return toRemoveInstructions.count(opInst);
            }
            return false;
          });
      if (isOperandRemoved) {
        Value *replace = nondetValue(inst->getType(), inst, ndvalfn);
        inst->replaceAllUsesWith(replace);
        toRemoveInstructions.insert(inst);
      }
    } else {
      for (Value *op : inst->operands()) {
        if (Instruction *opInst = dyn_cast<Instruction>(op)) {
          if (toRemoveInstructions.count(opInst)) {
            Instruction *insertPoint = getRepalcementInsertPoint(opInst);
            Value *replace =
                nondetValue(opInst->getType(), insertPoint, ndvalfn);
            opInst->replaceAllUsesWith(replace);
          }
        }
      }
    }
  }

  Instruction *getRepalcementInsertPoint(Instruction *inst) {
    return isa<PHINode>(inst) ? inst->getParent()->getFirstNonPHI() : inst;
  }

  void slimDownOnlyReachables(Module &m) {
    Visitor visitor;
    visitor.visit(m);
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
