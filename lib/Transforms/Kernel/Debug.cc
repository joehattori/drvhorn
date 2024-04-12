#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"

#include <set>
#include <vector>

using namespace llvm;

namespace seahorn {

class Debug : public ModulePass {
public:
  static char ID;

  Debug() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    unsigned int counter = 0;
    std::map<StringRef, std::set<StringRef>> callers = getCallers(M);
    for (const auto &caller : callers["x86_idle"]) {
      errs() << "Caller: " << caller.str() << "\n";
    }
    for (const auto &caller : callers["select_idle_routine"]) {
      errs() << "Caller: " << caller.str() << "\n";
    }
    for (Function &F : M) {
      if (F.isDeclaration() || !F.hasName())
        continue;
      if (F.getName().equals("x86_idle")) {
        errs() << "called 0\n";
      }
      if (F.getName().equals("select_idle_routine")) {
        errs() << "called 1\n";
      }
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (InlineAsm *inlineAsm =
                  dyn_cast<InlineAsm>(call->getCalledOperand())) {
            if (counter < 10) {
              StringRef name = F.getName();
              errs() << "In func " << name.str() << "\n";
              errs() << "asm: " << inlineAsm->getAsmString() << "\n";
              errs() << "constraints " << inlineAsm->getConstraintString()
                     << "\n";
            }
            counter++;
          }
        }
      }
    }
    if (counter) {
      errs() << "Total number of inline asm instructions: " << counter << "\n";
    }
    return false;
  }

  virtual StringRef getPassName() const override { return "KernelDebug"; }

private:
  std::map<StringRef, std::set<StringRef>> getCallers(Module &M) {
    std::map<StringRef, std::set<StringRef>> callers;
    CallGraph cg = CallGraph(M);
    for (const auto &it : cg) {
      const Function *caller = it.first;
      const std::unique_ptr<CallGraphNode> &node = it.second;
      for (const auto &call : *node) {
        const Function *callee = call.second->getFunction();
        if (callee && caller) {
          StringRef callerName = caller->getName();
          StringRef calleeName = callee->getName();
          callers[calleeName].insert(callerName);
        }
      }
    }
    return callers;
  }
};

char Debug::ID = 0;

Pass *createKernelDebugPass() { return new Debug(); };
} // namespace seahorn
