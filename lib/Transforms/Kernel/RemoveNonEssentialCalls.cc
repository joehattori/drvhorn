#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Pass.h"

#include <algorithm>
#include <iostream>

using namespace llvm;

namespace seahorn {

class RemoveNonEssentialCalls : public ModulePass {
public:
  static char ID;

  RemoveNonEssentialCalls() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    std::vector<CallInst *> callsToRemove;
    std::set<StringRef> fnNamesToRemove;
    for (Function &fn : M) {
      for (Instruction &inst : instructions(fn)) {
        CallInst *call = dyn_cast<CallInst>(&inst);
        if (!call)
          continue;
        Function *fn = call->getCalledFunction();
        if (!fn)
          continue;
        StringRef name = fn->getName();
        if (shouldRemove(name)) {
          callsToRemove.push_back(call);
          fnNamesToRemove.insert(name);
        }
      }
    }

    for (CallInst *call : callsToRemove)
      call->eraseFromParent();

    for (StringRef name : fnNamesToRemove) {
      Function *fn = M.getFunction(name);
      fn->eraseFromParent();
    }

    return !callsToRemove.empty();
  }

  virtual StringRef getPassName() const override {
    return "Remove non-essential function calls";
  }

private:
  std::vector<StringRef> functions_to_remove = {
      "acpi_os_wait_semaphore",
  };

  std::vector<StringRef> target_prefixes = {
      "mutex_",
      "__mutex_",
  };

  bool shouldRemove(StringRef fn_name) {
    bool full_match = std::any_of(
        functions_to_remove.begin(), functions_to_remove.end(),
        [&fn_name](StringRef name) { return fn_name.equals(name); });
    bool partial_match = std::any_of(
        target_prefixes.begin(), target_prefixes.end(),
        [&fn_name](StringRef prefix) { return fn_name.startswith(prefix); });
    return full_match || partial_match;
  }
};

char RemoveNonEssentialCalls::ID = 0;

Pass *createRemoveNonEssentialCalls() { return new RemoveNonEssentialCalls(); }

} // namespace seahorn
