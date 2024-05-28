#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"

#define COMPILER_USED_NAME "llvm.compiler.used"

using namespace llvm;

namespace seahorn {
struct TargetCollector {
public:
  DenseSet<const Instruction *> &build(Module &M, User *user) {
    visitUser(user, user);
    visitVerifierFns(M);
    return targets;
  }

private:
  DenseSet<const User *> visited;
  DenseSet<const Instruction *> targets;

  bool isUpdatableType(const Type *type) {
    return type->isPointerTy() &&
           !type->getPointerElementType()->isFunctionTy();
  }

  void visitVerifierFns(const Module &M) {
    const Function *err = M.getFunction("__VERIFIER_error");
    for (const User *user : err->users()) {
      if (const CallInst *call = dyn_cast<CallInst>(user)) {
        targets.insert(call);
      } else {
        errs() << "unexpected user of __VERIFIER_error: " << *user << "\n";
      }
    }
  }

  void visitUser(User *user, const Value *from) {
    if (!visited.insert(user).second)
      return;
    if (Instruction *inst = dyn_cast<Instruction>(user)) {
      visitInst(inst, from);
    }
    for (User *u : user->users()) {
      visitUser(u, from);
    }
  }

  void visitInst(Instruction *inst, const Value *target) {
    if (StoreInst *store = dyn_cast<StoreInst>(inst)) {
      targets.insert(store);
      Value *src = store->getValueOperand();
      if (src->getType()->isPointerTy()) {
        Value *newTarget = extractTarget(src);
        for (User *user : newTarget->users())
          visitUser(user, newTarget);
      }
    } else if (CallInst *call = dyn_cast<CallInst>(inst)) {
      if (const Function *f = call->getCalledFunction()) {
        // visit arguments
        if (!f->isVarArg()) {
          for (unsigned index = 0; index < call->arg_size(); index++) {
            Value *argVal = call->getArgOperand(index);
            if (!isUpdatableType(argVal->getType())) {
              continue;
            }
            Argument *arg = f->getArg(index);
            for (User *user : arg->users()) {
              visitUser(user, arg);
            }
          }
        }
      }
    }
    for (User *user : inst->users()) {
      visitUser(user, target);
    }
  }

  Value *extractTarget(Value *value) {
    if (isa<Instruction>(value))
      return value;
    if (isa<Operator>(value)) {
      if (GEPOperator *gepOp = dyn_cast<GEPOperator>(value)) {
        return extractTarget(gepOp->getPointerOperand());
      } else if (BitCastOperator *bcOp = dyn_cast<BitCastOperator>(value)) {
        return extractTarget(bcOp->getOperand(0));
      } else {
        errs() << "TODO: extractTarget" << *value << "\n";
        return nullptr;
      }
    }
    if (isa<Constant>(value))
      return value;
    if (isa<Argument>(value))
      return value;
    errs() << "TODO: extractTarget" << *value << "\n";
    return nullptr;
  }
};

static Function *makeNewValFn(Module &M, Type *type, unsigned startFrom,
                              std::string prefix) {
  std::string name;
  unsigned c = startFrom;
  do {
    name = prefix + std::to_string(c++);
  } while (M.getNamedValue(name));
  return Function::Create(FunctionType::get(type, false),
                          GlobalValue::LinkageTypes::ExternalLinkage, name, &M);
}

static Function *getNondetValueFn(Type *retType, Module &M,
                                  DenseMap<const Type *, Function *> &ndvalfn) {
  auto it = ndvalfn.find(retType);
  if (it != ndvalfn.end()) {
    return it->second;
  }

  Function *res =
      makeNewValFn(M, retType, ndvalfn.size(), "verifier.nondetvalue.");
  ndvalfn[retType] = res;
  return res;
}

static Function *makeNewFn(Module &M, FunctionType *type, unsigned startFrom,
                           std::string prefix) {
  std::string name;
  unsigned c = startFrom;
  do {
    name = prefix + std::to_string(c++);
  } while (M.getNamedValue(name));
  return Function::Create(type, GlobalValue::LinkageTypes::ExternalLinkage,
                          name, &M);
}

static bool isConditionNondet(const Value *cond,
                              const DenseSet<const Value *> &retain) {
  if (const User *user = dyn_cast<User>(cond)) {
    return !retain.count(user);
  } else if (isa<Constant>(cond)) {
    return false;
  } else if (isa<Argument>(cond)) {
    return false;
  } else {
    return true;
  }
}

static void
handleNonRetainedInst(Module &M, const DenseSet<const Value *> &retain,
                      Instruction *inst,
                      DenseMap<const Type *, Function *> &ndvalfn,
                      std::set<Instruction *> &toRemoveInstructions) {
  if (BranchInst *branch = dyn_cast<BranchInst>(inst)) {
    if (branch->isConditional()) {
      Value *cond = branch->getCondition();
      if (isConditionNondet(cond, retain)) {
        Function *nondetFn = getNondetValueFn(cond->getType(), M, ndvalfn);
        CallInst *newCall = CallInst::Create(nondetFn, "", inst);
        branch->setCondition(newCall);
      }
    }
  } else if (SwitchInst *switchInst = dyn_cast<SwitchInst>(inst)) {
    Value *cond = switchInst->getCondition();
    if (isConditionNondet(cond, retain)) {
      Function *nondetFn = getNondetValueFn(cond->getType(), M, ndvalfn);
      CallInst *newCall = CallInst::Create(nondetFn, "", inst);
      switchInst->setCondition(newCall);
    }
  } else if (ReturnInst *ret = dyn_cast<ReturnInst>(inst)) {
    Value *retVal = ret->getReturnValue();
    if (retVal) {
      if (isConditionNondet(retVal, retain)) {
        Function *nondetFn = getNondetValueFn(retVal->getType(), M, ndvalfn);
        IRBuilder<> B(ret);
        CallInst *call = B.CreateCall(nondetFn);
        ReturnInst *newRet = B.CreateRet(call);
        ret->replaceAllUsesWith(newRet);
        toRemoveInstructions.insert(inst);
      }
    }
  } else if (isa<UnreachableInst>(inst)) {
    FunctionCallee err = M.getFunction("__VERIFIER_error");
    CallInst *call = CallInst::Create(err, "", inst);
    inst->replaceAllUsesWith(call);
  } else if (isa<CallBrInst>(inst)) {
  } else {
    toRemoveInstructions.insert(inst);
  }
}

static void handleRetainedInst(Module &M, const DenseSet<const Value *> &retain,
                               Instruction *inst,
                               DenseMap<const Type *, Function *> &ndvalfn,
                               std::set<Instruction *> &toRemoveInstructions) {
  if (CallInst *call = dyn_cast<CallInst>(inst)) {
    bool nondet = true;
    if (Function *f = call->getCalledFunction()) {
      if (retain.count(f))
        nondet = false;
    }
    if (nondet) {
      Function *nondet = getNondetValueFn(inst->getType(), M, ndvalfn);
      CallInst *newCall = CallInst::Create(nondet, "", inst);
      inst->replaceAllUsesWith(newCall);
      toRemoveInstructions.insert(inst);
    }
  }
}

static void collectOperands(const Value *value, DenseSet<const Value *> &retain,
                            DenseSet<const Value *> &visited) {
  if (!visited.insert(value).second)
    return;
  if (const User *user = dyn_cast<User>(value)) {
    retain.insert(user);
    if (const Instruction *inst = dyn_cast<Instruction>(user)) {
      if (const CallInst *call = dyn_cast<CallInst>(inst)) {
        const Function *f = call->getCalledFunction();
        if (!call->user_empty() && f) {
          for (const BasicBlock &block : *f) {
            if (const ReturnInst *ret =
                    dyn_cast<ReturnInst>(block.getTerminator()))
              collectOperands(ret, retain, visited);
          }
        }
        for (const Use &u : call->args())
          collectOperands(u.get(), retain, visited);
      }
      retain.insert(inst->getFunction());
      for (const User *user : inst->getFunction()->users()) {
        if (isa<CallInst>(user)) {
          collectOperands(user, retain, visited);
        }
      }
      collectOperands(inst->getParent(), retain, visited);
    }
    for (const Use &use : user->operands()) {
      collectOperands(use.get(), retain, visited);
    }
  } else if (const BasicBlock *block = dyn_cast<BasicBlock>(value)) {
    for (const User *user : block->users()) {
      collectOperands(user, retain, visited);
    }
  } else if (const Argument *arg = dyn_cast<Argument>(value)) {
    for (const User *user : arg->users()) {
      collectOperands(user, retain, visited);
    }
  } else if (isa<InlineAsm>(value)) {
    errs() << "TODO: InlineAsm " << *value << "\n";
  } else {
    errs() << "TODO: collectOperands " << *value << "\n";
  }
}

static void updateLinkage(Module &M) {
  for (Function &f : M) {
    if (f.isDeclaration())
      continue;
    if (f.getName().equals("main") || f.getName().startswith("__VERIFIER_"))
      continue;
    f.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
  }
  for (GlobalVariable &v : M.globals()) {
    if (v.isDeclaration())
      continue;
    v.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
  }
  for (GlobalAlias &alias : M.aliases()) {
    if (alias.isDeclaration())
      continue;
    alias.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
  }
}

static void replacePanic(Module &M) {
  Function *panic = M.getFunction("panic");
  Function *newPanic =
      makeNewFn(M, panic->getFunctionType(), 0, "verifier.panic.");
  BasicBlock *entry = BasicBlock::Create(M.getContext(), "entry", newPanic);
  IRBuilder<> B(entry);
  B.CreateUnreachable();
  panic->replaceAllUsesWith(newPanic);
  panic->eraseFromParent();
}

static void slimDownOnlyReachables(Module &M, User *root) {
  TargetCollector collector;
  DenseSet<const Instruction *> &targets = collector.build(M, root);
  DenseSet<const Value *> retain;
  DenseSet<const Value *> visited;
  for (const Value *v : targets) {
    collectOperands(v, retain, visited);
  }
  std::set<Instruction *> toRemoveInstructions;
  DenseMap<const Type *, Function *> ndvalfn;
  for (Function &f : M) {
    for (Instruction &inst : instructions(f)) {
      if (retain.count(&inst)) {
        handleRetainedInst(M, retain, &inst, ndvalfn, toRemoveInstructions);
      } else {
        handleNonRetainedInst(M, retain, &inst, ndvalfn, toRemoveInstructions);
      }
    }
  }
  for (Instruction *inst : toRemoveInstructions) {
    inst->eraseFromParent();
  }
  SmallVector<GlobalVariable *> toRemoveGlobalVars;
  for (GlobalVariable &gv : M.globals()) {
    if (!retain.count(&gv))
      toRemoveGlobalVars.push_back(&gv);
  }
  for (GlobalVariable *gv : toRemoveGlobalVars) {
    gv->dropAllReferences();
    gv->eraseFromParent();
  }
  SmallVector<Function *> toRemoveFns;
  for (Function &f : M) {
    // nondet functions should not be removed.
    if (f.isDeclaration())
      continue;
    if (!retain.count(&f))
      toRemoveFns.push_back(&f);
  }
  for (Function *f : toRemoveFns) {
    f->dropAllReferences();
    f->eraseFromParent();
  }
}

static void runDCE(Module &M, bool removeArg = false) {
  legacy::PassManager pm;
  pm.add(createAggressiveDCEPass());
  pm.add(createGlobalDCEPass());
  if (removeArg)
    pm.add(createDeadArgEliminationPass());
  int c = 0;
  while (pm.run(M) && c++ < 10) {
  }
}

void slimDown(Module &M, User *root) {
  updateLinkage(M);
  runDCE(M);

  if (GlobalVariable *compilerUsed = M.getNamedGlobal(COMPILER_USED_NAME)) {
    Type *ty = compilerUsed->getType();
    compilerUsed->eraseFromParent();
    // llvm.compiler.used seems to be required, so insert an empty value
    M.getOrInsertGlobal(COMPILER_USED_NAME, ty->getPointerElementType());
  }
  runDCE(M);

  replacePanic(M);
  slimDownOnlyReachables(M, root);
  runDCE(M, true);
}
} // namespace seahorn
