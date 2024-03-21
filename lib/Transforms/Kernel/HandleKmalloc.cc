#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"

#include "boost/range.hpp"

#include <iostream>
#include <algorithm>

using namespace llvm;

namespace seahorn {

class HandleKmalloc : public ModulePass {
public:
  static char ID;

  HandleKmalloc() : ModulePass(ID) {}
  
  bool runOnModule(Module &M) override {
    FunctionCallee stub = createKmallocStub(M);

    std::vector<CallInst *> calls;
    for (Function &fn : M) {
      for (Instruction &inst : llvm::make_range(inst_begin(fn), inst_end(fn))) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isKmallocCall(call))
            calls.push_back(call);
        }
      }
    }

    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      std::vector<Value *> args(call->arg_begin(), call->arg_end());
      // malloc_stub takes two arguments.
      args.resize(2);
      CallInst *new_call = B.CreateCall(stub, args);
      call->replaceAllUsesWith(new_call);
      call->eraseFromParent();
    }
    return !calls.empty();
  }

  virtual StringRef getPassName() const override { return "HandleKmalloc"; }

private:
  bool isKmallocCall(const CallInst *call) {
    const Function *fn = call->getCalledFunction();
    if (!fn)
      return false;
    StringRef fn_name = fn->getName();
    return std::any_of(std::begin(kmalloc_names), std::end(kmalloc_names),
                       [&fn_name](StringRef name) { return fn_name.equals(name); });
  }

  FunctionCallee createKmallocStub(Module &M) {
    LLVMContext &ctx = M.getContext();
    // void pointer type.
    Type *retType = Type::getInt8PtrTy(ctx);
    std::vector<Type *> argTypes = { Type::getInt32Ty(ctx), Type::getInt32Ty(ctx) };
    FunctionType *funcType = FunctionType::get(retType, argTypes, false);
    return M.getOrInsertFunction("malloc_stub", funcType);
  }
  
  StringRef kmalloc_names[4] = {"__kmalloc", "kmalloc_large", "__kmalloc_node", "kmalloc_large_node"};
};

char HandleKmalloc::ID = 0;

Pass *createHandleKmallocPass() { return new HandleKmalloc(); }
}
