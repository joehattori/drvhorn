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

#include <map>
#include <optional>
#include <queue>

#define COMPILER_USED_NAME "llvm.compiler.used"

using namespace llvm;

namespace seahorn {
static uint64_t kobjIndices[] = {6, 0, 0, 0};

// Track from llvm::Argument. If an llvm::Instruction is not reachable from
// llvm::Argument, remove it or replace it with a nondet value.
struct Graph {
  Graph(Module &m) {
    kobjectType = StructType::getTypeByName(m.getContext(), "struct.kobject");
  }

  void build(const Function *main, const Function *verifierError) {
    for (const Instruction &inst : instructions(*main)) {
      if (const CallInst *call = dyn_cast<CallInst>(&inst)) {
        DenseMap<const Instruction *, bool> visited;
        const Function *f = extractCalledFunction(call);
        for (const Argument &arg : f->args()) {
          visitArg(&arg, None);
        }
        connectRetToCall(*f, call);
      }
      coreTargets.insert(&inst);
    }
  }

  bool isTarget(const Value *value) {
    DenseSet<const Value *> visited;
    return isTarget(value, visited);
  }

  bool isTarget(const Value *value, DenseSet<const Value *> &visited) {
    if (!value)
      return false;
    if (!visited.insert(value).second)
      return false;
    if (coreTargets.count(dyn_cast<Instruction>(value))) {
      return true;
    }
    for (const Value *v : edges[value]) {
      if (isTarget(v, visited)) {
        return true;
      }
    }
    return false;
  }

private:
  const StructType *kobjectType;
  DenseMap<const Value *, DenseSet<const Value *>> edges;
  DenseSet<const Instruction *> coreTargets;
  std::set<std::tuple<const User *, const Value *, Optional<size_t>>> visited;

  void visitArg(const Argument *arg, Optional<size_t> currentGEPIndex) {
    for (const User *user : arg->users()) {
      visitUser(user, arg, currentGEPIndex);
    }
  }

  void visitUser(const User *user, const Value *orig,
                 Optional<size_t> currentGEPIndex) {
    edges[orig].insert(user);
    if (!visited.insert({user, orig, currentGEPIndex}).second)
      return;
    if (const Instruction *inst = dyn_cast<Instruction>(user)) {
      visitInst(inst, orig, currentGEPIndex);
    } else {
      for (const User *u : user->users()) {
        visitUser(u, user, None);
      }
    }
  }

  void visitInst(const Instruction *inst, const Value *orig,
                 Optional<size_t> currentGEPIndex) {
    edges[inst->getParent()].insert(inst);
    if (const CallInst *call = dyn_cast<CallInst>(inst)) {
      visitCall(call, orig, currentGEPIndex);
    } else if (const BranchInst *br = dyn_cast<BranchInst>(inst)) {
      visitBranch(br, currentGEPIndex);
    } else if (const GetElementPtrInst *gep =
                   dyn_cast<GetElementPtrInst>(inst)) {
      visitGEP(gep, orig, currentGEPIndex);
    } else if (const StoreInst *store = dyn_cast<StoreInst>(inst)) {
      visitStore(store, currentGEPIndex);
    } else {
      for (const User *user : inst->users()) {
        visitUser(user, inst, None);
      }
    }
  }

  bool isTargetFunc(const Instruction *inst, StringRef name) {
    return inst->getFunction()->getName().equals(name);
  }

  void visitCall(const CallInst *call, const Value *orig,
                 Optional<size_t> currentGEPIndex) {
    for (const User *u : call->users()) {
      visitUser(u, call, None);
    }
    const Function *f = extractCalledFunction(call);
    if (!f || f->isVarArg())
      return;
    for (size_t i = 0; i < call->arg_size(); i++) {
      Optional<size_t> nextIndex =
          call->getArgOperand(i) == orig ? currentGEPIndex : None;
      const Argument *arg = f->getArg(i);
      edges[call].insert(arg);
      visitArg(arg, nextIndex);
    }
    connectRetToCall(*f, call);
  }

  void connectRetToCall(const Function &f, const CallInst *call) {
    if (call->user_empty())
      return;
    for (const BasicBlock &block : f) {
      const Instruction *inst = block.getTerminator();
      if (isa<ReturnInst>(inst)) {
        edges[inst].insert(call);
      }
    }
  }

  void visitBranch(const BranchInst *br, Optional<size_t> currentGEPIndex) {
    for (const BasicBlock *succ : br->successors()) {
      edges[br].insert(succ);
    }
  }

  void visitStore(const StoreInst *store, Optional<size_t> currentGEPIndex) {
    if (currentGEPIndex.hasValue()) {
      coreTargets.insert(store);
    }
  }

  void visitGEP(const GetElementPtrInst *gep, const Value *orig,
                Optional<size_t> currentGEPIndex) {
    Optional<size_t> nextIndex = nextKobjectIndex(gep, currentGEPIndex);
    if (gep->getFunction()->getName().equals("kobject_uevent_net_broadcast")) {
      errs() << "visiting GEP " << currentGEPIndex << ' ' << nextIndex << ' '
             << *gep << '\n';
    }
    for (const User *user : gep->users()) {
      visitUser(user, gep, nextIndex);
    }
  }

  Optional<size_t> nextKobjectIndex(const GetElementPtrInst *gep,
                                    Optional<size_t> currentIndex) {
    if (currentIndex.hasValue()) {
      // already in kobject.
      size_t cur = currentIndex.getValue();
      // skip the first index.
      for (size_t i = 1; i < gep->getNumIndices(); i++) {
        const Value *index = gep->getOperand(i + 1);
        if (getValueInteger(index) != kobjIndices[cur + i - 1])
          return None;
      }
      return cur + gep->getNumIndices() - 1;
    } else {
      // find the GEP index that points to `struct kobject`.
      const Optional<size_t> kobjIndex = lookForKobjectGEPIndex(gep);
      if (!kobjIndex.hasValue())
        return None;
      size_t nextGEPIndex = kobjIndex.getValue() + 1;
      size_t remainingGEPIndices = gep->getNumIndices() - nextGEPIndex;
      for (size_t i = 0; i < remainingGEPIndices; i++) {
        const Value *index = gep->getOperand(i + 1 + nextGEPIndex);
        const Optional<uint64_t> indexInt = getValueInteger(index);
        if (!indexInt.hasValue())
          return None;
        if (indexInt.getValue() != kobjIndices[i])
          return None;
      }
      return remainingGEPIndices;
    }
  }

  Optional<size_t> lookForKobjectGEPIndex(const GetElementPtrInst *gep) {
    const StructType *indexedStructType =
        dyn_cast<StructType>(gep->getSourceElementType());
    if (!indexedStructType)
      return None;
    if (equivTypes(indexedStructType, kobjectType))
      return 0;
    // skip the first index.
    for (size_t i = 1; i < gep->getNumIndices(); i++) {
      const Value *index = gep->getOperand(i + 1);
      indexedStructType =
          dyn_cast<StructType>(indexedStructType->getTypeAtIndex(index));
      if (!indexedStructType)
        return None;
      if (equivTypes(indexedStructType, kobjectType))
        return i;
    }
    return None;
  }

  Optional<uint64_t> getValueInteger(const Value *v) {
    if (const ConstantInt *ci = dyn_cast<ConstantInt>(v))
      return ci->getZExtValue();
    return None;
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
    Graph g(m);
    g.build(m.getFunction("main"), verifierError);
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

  Instruction *getInstruction(User *user) {
    if (Instruction *inst = dyn_cast<Instruction>(user)) {
      return inst;
    } else if (Operator *op = dyn_cast<Operator>(user)) {
      for (User *user : op->users()) {
        if (Instruction *inst = getInstruction(user)) {
          return inst;
        }
      }
    }
    return nullptr;
  }

  const Instruction *getInstruction(const User *user) {
    if (const Instruction *inst = dyn_cast<Instruction>(user)) {
      return inst;
    } else if (const Operator *op = dyn_cast<Operator>(user)) {
      for (const User *user : op->users()) {
        if (const Instruction *inst = getInstruction(user)) {
          return inst;
        }
      }
    }
    return nullptr;
  }

  void updateLinkage(Module &M) {
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

  bool isNondet(const Value *v, Graph &graph) {
    if (isa<Argument>(v))
      return false;
    if (isa<BasicBlock>(v))
      return false;
    if (isa<Constant>(v))
      return false;
    return !graph.isTarget(v);
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
          Value *def = Constant::getNullValue(retVal->getType());
          ReturnInst *newRet = ReturnInst::Create(inst->getContext(), def, ret);
          ret->replaceAllUsesWith(newRet);
          toRemoveInstructions.insert(inst);
        }
      }
    } else if (isa<UnreachableInst>(inst)) {
    } else if (isa<CallBrInst>(inst)) {
      errs() << "unhandled CallBr " << *inst << '\n';
      std::exit(1);
    } else {
      if (!inst->user_empty()) {
        Value *replace = nondetValue(inst->getType(), inst, ndvalfn);
        inst->replaceAllUsesWith(replace);
      }
      toRemoveInstructions.insert(inst);
    }
  }

  Value *nondetValue(Type *type, Instruction *before,
                     DenseMap<const Type *, Function *> &ndvalfn) {
    if (type->isPointerTy()) {
      Type *elemType = type->getPointerElementType();
      if (FunctionType *ft = dyn_cast<FunctionType>(elemType)) {
        return makeNewValFn(before->getModule(), ft, ndvalfn.size());
      } else {
        return new AllocaInst(elemType, 0, "", before);
      }
    } else {
      Function *nondetFn = getNondetValueFn(type, before->getModule(), ndvalfn);
      return CallInst::Create(nondetFn, "", before);
    }
  }

  void slimDownOnlyReachables(Module &m, Graph &g) {
    std::set<Instruction *> toRemoveInstructions;
    std::vector<Function *> toRemoveFns;
    DenseMap<const Type *, Function *> ndvalfn;
    for (Function &f : m) {
      if (f.getName().equals("main") || f.getName().startswith("__DRVHORN_") ||
          f.isDeclaration())
        continue;
      bool removeFn = true;
      for (Instruction &inst : instructions(f)) {
        if (g.isTarget(&inst)) {
          removeFn = false;
        } else {
          handleNonRetainedInst(g, &inst, ndvalfn, toRemoveInstructions);
        }
      }
      if (removeFn) {
        toRemoveFns.push_back(&f);
      }
    }
    for (Instruction *inst : toRemoveInstructions) {
      inst->dropAllReferences();
      inst->eraseFromParent();
    }
    for (Function *f : toRemoveFns) {
      std::vector<CallInst *> calls;
      for (User *user : f->users()) {
        if (CallInst *call = dyn_cast<CallInst>(getInstruction(user))) {
          calls.push_back(call);
        }
      }
      for (CallInst *call : calls) {
        Value *replace = nondetValue(call->getType(), call, ndvalfn);
        call->replaceAllUsesWith(replace);
        call->dropAllReferences();
        call->eraseFromParent();
      }
      f->dropAllReferences();
      f->eraseFromParent();
    }
  }

  void runDCEPasses(Module &m, bool removeArg = false) {
    legacy::PassManager pm;
    pm.add(createAggressiveDCEPass());
    pm.add(createGlobalDCEPass());
    pm.add(createCFGSimplificationPass());
    if (removeArg)
      pm.add(createDeadArgEliminationPass());
    int c = 0;
    while (pm.run(m) && c++ < 10) {
    }

    // nondet function calls are not removed by DCE passes.
    std::vector<Instruction *> toRemove;
    for (Function &f : m) {
      for (Instruction &inst : instructions(f)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (Function *f = extractCalledFunction(call)) {
            if (f->getName().startswith("verifier.nondet") &&
                call->user_empty())
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
