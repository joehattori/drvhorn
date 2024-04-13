#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"

#define COMPILER_USED_NAME "llvm.compiler.used"

using namespace llvm;

namespace seahorn {
class RemoveUnnecessaryFunctions : public ModulePass {
public:
  static char ID;

  RemoveUnnecessaryFunctions() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    verify(M);

    StringRef globalVarNames[] = {
        "sys_call_table",
    };
    for (StringRef name : globalVarNames) {
      GlobalVariable *v = M.getNamedGlobal(name);
      v->eraseFromParent();
    }

    GlobalVariable *compilerUsed = M.getNamedGlobal(COMPILER_USED_NAME);
    Type *ty = compilerUsed->getType();
    compilerUsed->eraseFromParent();
    // llvm.compiler.used seems to be required, so insert an empty value
    M.getOrInsertGlobal(COMPILER_USED_NAME, ty->getPointerElementType());

    verify(M);
    return true;
  }

  virtual StringRef getPassName() const override {
    return "RemoveUnnecessaryFunctions";
  }

private:
  void verify(Module &M) {
    if (verifyModule(M, &errs())) {
      errs() << "Module verification failed\n";
    } else {
      errs() << "Module verification Ok\n";
    }
  }
};

char RemoveUnnecessaryFunctions::ID = 0;

Pass *createRemoveUnnecessaryFunctionsPass() {
  return new RemoveUnnecessaryFunctions();
}
} // namespace seahorn
