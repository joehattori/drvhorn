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

using namespace llvm;

namespace seahorn {
// Track from llvm::Argument. If an llvm::Instruction is not reachable from
// llvm::Argument, remove it or replace it with a nondet value.
struct Graph {
  Graph(Module &m, const Function *verifierError) {
    for (const Function &f : m) {
      for (const Argument &arg : f.args()) {
        visitArg(&arg);
      }
    }
    buildNonArgStartingPoint(m);
    errs() << "core target num " << coreTargets.size() << '\n';
    collectCallPath(m);
    errs() << "target num " << targets.size() << '\n';
    collectReturnPath(m);
    errs() << "target num " << targets.size() << '\n';
  }

  bool isTarget(const Instruction *inst) const { return targets.count(inst); }

  void collectCallPath(const Module &m) {
    DenseMap<const Value *, bool> visiting;
    for (const Function &f : m) {
      for (const Argument &arg : f.args()) {
        collectCallPath(&arg, visiting);
      }
    }
    for (const Instruction *st : startingPoints) {
      collectCallPath(st, visiting);
    }
  }

  bool collectCallPath(const Value *v,
                       DenseMap<const Value *, bool> &visiting) {
    if (visiting.count(v))
      return visiting[v];
    visiting[v] = false;
    if (const Instruction *inst = dyn_cast<Instruction>(v)) {
      if (coreTargets.count(inst)) {
        targets.insert(inst);
        visiting[v] = true;
      }
    }
    if (const CallInst *call = dyn_cast<CallInst>(v)) {
      if (const Function *f = extractCalledFunction(call)) {
        for (const Argument &arg : f->args()) {
          if (collectCallPath(&arg, visiting)) {
            targets.insert(call);
            visiting[v] = true;
            break;
          }
        }
      }
    }
    for (const Instruction *d : edges[v]) {
      if (collectCallPath(d, visiting)) {
        if (isa<Instruction>(v) && !isa<CallInst>(v))
          targets.insert(cast<Instruction>(v));
        visiting[v] = true;
      }
    }
    return visiting[v];
  }

  void collectReturnPath(const Module &m) {
    DenseMap<const Value *, bool> visiting;
    for (const Function &f : m) {
      for (const Argument &arg : f.args()) {
        collectRetPath(&arg, visiting);
      }
    }
    for (const Instruction *st : startingPoints) {
      collectRetPath(st, visiting);
    }
  }

  bool collectRetPath(const Value *v, DenseMap<const Value *, bool> &visiting) {
    if (visiting.count(v))
      return visiting[v];
    visiting[v] = false;
    if (isa<ReturnInst>(v)) {
      targets.insert(cast<Instruction>(v));
      visiting[v] = true;
    }
    for (const Instruction *inst : edges[v]) {
      if (collectRetPath(inst, visiting)) {
        if (isa<Instruction>(v) && !isa<CallInst>(v))
          targets.insert(cast<Instruction>(v));
        visiting[v] = true;
      }
    }
    return visiting[v];
  }
  bool debug{false};

private:
  DenseMap<const Value *, DenseSet<const Instruction *>> edges;
  DenseSet<const Instruction *> coreTargets;
  DenseSet<const Instruction *> targets;
  DenseSet<const Instruction *> startingPoints;
  std::set<std::tuple<const User *, const Value *>> visited;
  DenseMap<const Instruction *, bool> isTargetMemo;

  void buildNonArgStartingPoint(const Module &m) {
    DenseSet<const Function *> visited;
    std::queue<const Function *> worklist;
    const Function *getDevNode = m.getFunction("__DRVHORN_get_device_node");
    if (!getDevNode)
      return;
    worklist.push(getDevNode);
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

  void visitArg(const Argument *arg) {
    for (const User *user : arg->users()) {
      visitUser(user, arg);
    }
  }

  void visitUser(const User *user, const Value *orig) {
    if (!visited.insert({user, orig}).second)
      return;
    if (const Instruction *inst = dyn_cast<Instruction>(user)) {
      visitInst(inst, orig);
    } else {
      for (const User *u : user->users()) {
        visitUser(u, user);
      }
    }
  }

  void visitInst(const Instruction *inst, const Value *orig) {
    edges[orig].insert(inst);
    if (const CallInst *call = dyn_cast<CallInst>(inst)) {
      visitCall(call, orig);
    } else if (const BranchInst *br = dyn_cast<BranchInst>(inst)) {
      visitBranch(br);
    } else if (const StoreInst *store = dyn_cast<StoreInst>(inst)) {
      visitStore(store);
    } else {
      for (const User *user : inst->users()) {
        visitUser(user, inst);
      }
    }
  }

  void visitCall(const CallInst *call, const Value *orig) {
    const Function *f = extractCalledFunction(call);
    if (!f || f->isVarArg())
      return;
    if (f->getName().equals("kobject_get") ||
        f->getName().equals("kobject_put") ||
        f->getName().equals("kobject_init")) {
      coreTargets.insert(call);
    }
    for (const User *user : call->users()) {
      visitUser(user, call);
    }
  }

  void visitBranch(const BranchInst *br) {
    for (const BasicBlock *succ : br->successors()) {
      SmallVector<const Instruction *, 8> children;
      for (const PHINode &phi : succ->phis()) {
        children.push_back(&phi);
      }
      children.push_back(succ->getFirstNonPHI());
      for (const Instruction *child : children) {
        edges[br].insert(child);
        for (const User *user : child->users()) {
          visitUser(user, child);
        }
      }
    }
  }

  void visitStore(const StoreInst *store) {
    for (const User *user : store->getPointerOperand()->users()) {
      visitUser(user, store);
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

    SeaBuiltinsInfo &sbi =
        getAnalysis<seahorn::SeaBuiltinsInfoWrapperPass>().getSBI();
    Function *verifierError = sbi.mkSeaBuiltinFn(SeaBuiltinsOp::ERROR, m);
    Graph g(m, verifierError);
    slimDownOnlyReachables(m, g);
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

  void updateLinkage(Module &M) {
    for (Function &f : M) {
      if (f.isDeclaration())
        continue;
      if (f.getName().equals("main") || f.getName().startswith("__VERIFIER_") ||
          f.getName().equals("__DRVHORN_malloc"))
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

  bool isNondet(const Value *v, Graph &graph) {
    if (isa<Argument>(v))
      return false;
    if (isa<BasicBlock>(v))
      return false;
    if (isa<Constant>(v))
      return false;
    return !graph.isTarget(cast<Instruction>(v));
  }

  void handleNonRetainedInst(Graph &graph, Instruction *inst,
                             DenseMap<const Type *, Function *> &ndvalfn,
                             std::set<Instruction *> &toRemoveInstructions) {
    if (BranchInst *branch = dyn_cast<BranchInst>(inst)) {
      if (branch->isConditional()) {
        Value *cond = branch->getCondition();
        if (isNondet(cond, graph)) {
          Value *replace = nondetValue(cond->getType(), inst, ndvalfn);
          branch->setCondition(replace);
        }
      }
    } else if (SwitchInst *switchInst = dyn_cast<SwitchInst>(inst)) {
      Value *cond = switchInst->getCondition();
      if (isNondet(cond, graph)) {
        Value *replace = nondetValue(cond->getType(), inst, ndvalfn);
        switchInst->setCondition(replace);
      }
    } else if (ReturnInst *ret = dyn_cast<ReturnInst>(inst)) {
      Value *retVal = ret->getReturnValue();
      if (retVal) {
        if (isNondet(retVal, graph)) {
          Value *v = nondetValue(retVal->getType(), ret, ndvalfn);
          ReturnInst *newRet = ReturnInst::Create(inst->getContext(), v, ret);
          ret->replaceAllUsesWith(newRet);
          toRemoveInstructions.insert(inst);
        }
      }
    } else if (isa<UnreachableInst>(inst)) {
    } else if (isa<CallBrInst>(inst)) {
      errs() << "unhandled CallBr in " << inst->getFunction()->getName()
             << *inst << '\n';
      std::exit(1);
    } else {
      if (!inst->user_empty()) {
        Instruction *insertPoint = getRepalcementInsertPoint(inst);
        Value *replace = nondetValue(inst->getType(), insertPoint, ndvalfn);
        inst->replaceAllUsesWith(replace);
      }
      toRemoveInstructions.insert(inst);
    }
  }

  Instruction *getRepalcementInsertPoint(Instruction *inst) {
    PHINode *phi = dyn_cast<PHINode>(inst);
    if (!phi)
      return inst;
    for (Instruction &inst : *phi->getParent()) {
      if (!isa<PHINode>(&inst))
        return &inst;
    }
    errs() << "All instructions are PHINode.\n";
    return nullptr;
  }

  Value *nondetValue(Type *type, Instruction *before,
                     DenseMap<const Type *, Function *> &ndvalfn) {
    if (!type->isPointerTy()) {
      Function *nondetFn = getNondetValueFn(type, before->getModule(), ndvalfn);
      return CallInst::Create(nondetFn, "", before);
    }

    Module *m = before->getModule();
    IRBuilder<> builder(before);
    return populateType(cast<PointerType>(type), m, builder, ndvalfn);
  }

  Value *populateType(PointerType *type, Module *m, IRBuilder<> &b,
                      DenseMap<const Type *, Function *> &ndvalfn) {
    Type *elemType = type->getPointerElementType();
    if (FunctionType *ft = dyn_cast<FunctionType>(elemType)) {
      return makeNewValFn(m, ft, ndvalfn.size());
    }
    Function *malloc = nondetMalloc(m);
    FunctionType *ft =
        FunctionType::get(type, malloc->getArg(0)->getType(), false);
    Constant *casted = ConstantExpr::getBitCast(malloc, ft->getPointerTo());
    size_t size = m->getDataLayout().getTypeAllocSize(elemType);
    Type *i64Type = Type::getInt64Ty(m->getContext());
    return b.CreateCall(ft, casted, ConstantInt::get(i64Type, size));
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

  void slimDownOnlyReachables(Module &m, Graph &g) {
    std::set<Instruction *> toRemoveInstructions;
    DenseMap<const Type *, Function *> ndvalfn;
    for (Function &f : m) {
      // we keep these functions still.
      if (f.getName().equals("main") || f.getName().equals("kobject_get") ||
          f.getName().equals("kobject_put") ||
          f.getName().equals("kobject_init") ||
          f.getName().startswith("__DRVHORN_") || f.isDeclaration())
        continue;
      for (Instruction &inst : instructions(f)) {
        if (!g.isTarget(&inst)) {
          handleNonRetainedInst(g, &inst, ndvalfn, toRemoveInstructions);
        }
      }
    }
    for (Instruction *inst : toRemoveInstructions) {
      inst->dropAllReferences();
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
    pm.run(m);
    removeUnusedNondetCalls(m);
    pm.run(m);
    removeUnusedNondetCalls(m);
    pm.run(m);
    removeUnusedNondetCalls(m);
    pm.run(m);
  }

  void removeUnusedNondetCalls(Module &m) {
    // nondet function calls are not removed by DCE passes.
    std::vector<Instruction *> toRemove;
    for (Function &f : m) {
      for (Instruction &inst : instructions(f)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (Function *f = extractCalledFunction(call)) {
            if (f->getName().equals("verifier.error"))
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
