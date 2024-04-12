#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/User.h"
#include "llvm/Pass.h"

using namespace llvm;

namespace seahorn {
class RemoveUnnecessaryFunctions : public ModulePass {
public:
  static char ID;

  RemoveUnnecessaryFunctions() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    StringRef functions[] = {
        "default_idle",
    };
    for (StringRef name : functions) {
      Function *fn = M.getFunction(name);
      fn->dropAllReferences();
      fn->eraseFromParent();
    }

    StringRef globalVarNames[] = {
        "sys_call_table",
    };
    for (StringRef name : globalVarNames) {
      GlobalValue *v = M.getNamedValue(name);
      v->eraseFromParent();
    }
    return true;
  }

  virtual StringRef getPassName() const override {
    return "RemoveUnnecessaryFunctions";
  }
};

char RemoveUnnecessaryFunctions::ID = 0;

Pass *createRemoveUnnecessaryFunctionsPass() {
  return new RemoveUnnecessaryFunctions();
}
} // namespace seahorn
