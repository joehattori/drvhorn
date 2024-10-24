#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

class SpecificFunction : public ModulePass {
public:
  static char ID;

  SpecificFunction(StringRef fnName) : ModulePass(ID), fnName(fnName) {}

  bool runOnModule(Module &m) override {
    LLVMContext &ctx = m.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    Function *main = Function::Create(
        FunctionType::get(i32Ty, false),
        GlobalValue::LinkageTypes::ExternalLinkage, "main", &m);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", main);
    BasicBlock *fail = BasicBlock::Create(ctx, "fail", main);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", main);
    Function *target = m.getFunction(fnName);
    if (!target) {
      errs() << "function not found: " << fnName << "\n";
      std::exit(1);
    }
    // if target is fastcc, main gets omitted somehow.
    target->setCallingConv(CallingConv::C);

    buildEntryBlock(m, target, entry, fail, ret);
    buildFailBlock(m, fail, ret);
    buildRetBlock(m, ret);
    return true;
  }

  virtual StringRef getPassName() const override { return "SpecificFunction"; }

private:
  StringRef fnName;
  DenseMap<const Type *, Function *> ndfn;

  void buildEntryBlock(Module &m, Function *target, BasicBlock *entry,
                       BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(entry);
    IntegerType *retTy = dyn_cast<IntegerType>(target->getReturnType());
    if (!retTy) {
      errs() << "specify a function that returns an integer\n";
      std::exit(1);
    }
    SmallVector<Value *, 8> args;
    for (Argument &arg : target->args()) {
      args.push_back(setupCallArg(b, arg.getType(), m));
    }
    CallInst *call = b.CreateCall(target, args);
    Value *zero = b.CreateICmpEQ(call, ConstantInt::get(retTy, 0));
    b.CreateCondBr(zero, ret, fail);
  }

  Value *setupCallArg(IRBuilder<> &b, Type *type, Module &m) {
    if (!type->isPointerTy()) {
      Function *nondet = getNondetFn(type, m);
      CallInst *val = b.CreateCall(nondet);
      return val;
    }
    Type *elemType = type->getPointerElementType();
    Value *content = setupCallArg(b, elemType, m);
    Value *ptr = b.CreateAlloca(elemType);
    b.CreateStore(content, ptr);
    return ptr;
  }

  void buildFailBlock(Module &m, BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(fail);
    LLVMContext &ctx = m.getContext();
    Function *failFn = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), false),
        GlobalValue::LinkageTypes::ExternalLinkage, "drvhorn.fail", &m);
    b.CreateCall(failFn);
    b.CreateBr(ret);
  }

  void buildRetBlock(Module &m, BasicBlock *ret) {
    IRBuilder<> b(ret);
    Type *i32Ty = Type::getInt32Ty(m.getContext());
    b.CreateRet(ConstantInt::get(i32Ty, 0));
  }

  Function *getNondetFn(Type *type, Module &m) {
    auto it = ndfn.find(type);
    if (it != ndfn.end()) {
      return it->second;
    }
    Function *res =
        createNewNondetFn(m, *type, ndfn.size(), "verifier.nondet.");
    ndfn[type] = res;
    return res;
  }

  Function *createNewNondetFn(Module &m, Type &type, unsigned num,
                              std::string prefix) {
    std::string name;
    unsigned c = num;
    do {
      name = prefix + std::to_string(c++);
    } while (m.getNamedValue(name));
    return dyn_cast<Function>(m.getOrInsertFunction(name, &type).getCallee());
  }
};

char SpecificFunction::ID = 0;

Pass *createSpecificFunctionPass(StringRef fnName) {
  return new SpecificFunction(fnName);
}
} // namespace seahorn
