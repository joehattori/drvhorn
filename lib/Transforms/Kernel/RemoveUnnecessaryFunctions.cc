#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"

#define COMPILER_USED_NAME "llvm.compiler.used"

using namespace llvm;

namespace seahorn {
class RemoveUnnecessaryFunctions : public ModulePass {
public:
  static char ID;

  RemoveUnnecessaryFunctions() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    verify(M);
    updateLinkage(M);

    GlobalVariable *compilerUsed = M.getNamedGlobal(COMPILER_USED_NAME);
    Type *ty = compilerUsed->getType();
    compilerUsed->eraseFromParent();
    // llvm.compiler.used seems to be required, so insert an empty value
    M.getOrInsertGlobal(COMPILER_USED_NAME, ty->getPointerElementType());

    legacy::PassManager pm;
    pm.add(createAggressiveDCEPass());
    pm.add(createGlobalDCEPass());

    while (pm.run(M))
      ;

    verify(M);
    return true;
  }

  virtual StringRef getPassName() const override {
    return "RemoveUnnecessaryFunctions";
  }

private:
  void debug(Module &M, StringRef name) {
    GlobalValue *f = M.getGlobalVariable(name);
    // GlobalValue *f = M.getFunction(name);
    if (f)
      errs() << name << " found: " << f->isDiscardableIfUnused() << "\n";
    else
      errs() << name << " not found\n";
  }

  void updateLinkage(Module &M) {
    for (Function &f : M) {
      if (f.isDeclaration())
        continue;
      if (!f.getName().equals("main"))
        f.setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
    }
    for (GlobalVariable &v : M.globals()) {
      if (v.isDeclaration())
        continue;
      v.setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
    }
  }

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
