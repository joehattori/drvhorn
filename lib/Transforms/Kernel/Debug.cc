#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"

using namespace llvm;

namespace seahorn {

class Debug : public ModulePass {
public:
  static char ID;

  Debug() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    for (Function &F : M) {
      if (F.isDeclaration() || !F.hasName())
        continue;
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (InlineAsm *inlineAsm =
                  dyn_cast<InlineAsm>(call->getCalledOperand())) {
            static int c = 0;
            if (c++ < 10) {
              StringRef name = F.getName();
              errs() << "In func " << name.str() << "\n";
              errs() << "asm: " << inlineAsm->getAsmString() << "\n";
              errs() << "constraints " << inlineAsm->getConstraintString()
                     << "\n";
            }
          }
        }
      }
    }
    return false;
  }

  virtual StringRef getPassName() const override { return "KernelDebug"; }
};

char Debug::ID = 0;

Pass *createKernelDebugPass() { return new Debug(); };
} // namespace seahorn
