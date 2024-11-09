#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

class AssertKrefs : public ModulePass {
public:
  static char ID;

  AssertKrefs() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    Function *devresRelease = m.getFunction("drvhorn.devres_release");
    buildDevresRelease(m, devresRelease);
    buildFail(m, devresRelease);
    removeNotCalledFunctions(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "AssertKrefs"; }

private:
  Function *genAssertFunction(Module &m, GlobalVariable &storage,
                              GlobalVariable *targetIndex, StringRef suffix) {
    Function *checker = m.getFunction("drvhorn.assert_kref");
    LLVMContext &ctx = m.getContext();
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    Function *f =
        Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                         GlobalValue::ExternalLinkage,
                         "drvhorn.check_storage." + suffix.str(), &m);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", f);
    BasicBlock *check = BasicBlock::Create(ctx, "check", f);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", f);
    IRBuilder<> b(entry);

    Value *target = b.CreateLoad(i64Ty, targetIndex);
    Value *cond = b.CreateICmpNE(target, ConstantInt::get(i64Ty, -1));
    b.CreateCondBr(cond, check, ret);

    b.SetInsertPoint(check);
    StructType *krefType = cast<StructType>(
        checker->getArg(0)->getType()->getPointerElementType());
    ArrayType *storageType = cast<ArrayType>(storage.getValueType());
    Value *elem = b.CreateInBoundsGEP(storageType, &storage,
                                      {ConstantInt::get(i64Ty, 0), target});
    StructType *elemType;
    if (storageType->getElementType()->isPointerTy()) {
      elemType = cast<StructType>(
          storageType->getElementType()->getPointerElementType());
      elem = b.CreateLoad(storageType->getElementType(), elem);
    } else {
      elemType = cast<StructType>(storageType->getElementType());
    }
    Value *krefPtr = b.CreateInBoundsGEP(
        elemType, elem, gepIndicesToStruct(elemType, krefType).getValue());
    b.CreateCall(checker, krefPtr);
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    b.CreateRetVoid();
    return f;
  }

  void buildDevresRelease(Module &m, Function *release) {
    std::string deversPrefix = "drvhorn.devres.";
    LLVMContext &ctx = m.getContext();
    BasicBlock *blk = BasicBlock::Create(ctx, "blk", release);
    IRBuilder<> b(blk);
    for (GlobalVariable &gv : m.globals()) {
      if (gv.getName().startswith(deversPrefix)) {
        StringRef fnName = gv.getName().substr(deversPrefix.size());
        size_t p = fnName.find('.');
        if (p != StringRef::npos)
          fnName = fnName.substr(0, p);
        Function *f = getAssertDevresFunction(m, gv, fnName);
        b.CreateCall(f);
      }
    }
    b.CreateRetVoid();
  }

  Function *getAssertDevresFunction(Module &m, GlobalVariable &gv,
                                    StringRef fnName) {
    LLVMContext &ctx = m.getContext();
    Function *f =
        Function::Create(FunctionType::get(Type::getVoidTy(ctx), false),
                         GlobalValue::ExternalLinkage,
                         "drvhorn.devres_release." + fnName.str(), &m);
    Function *release = m.getFunction(fnName);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", f);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);

    IRBuilder<> b(entry);
    Value *devresPtr = b.CreateInBoundsGEP(
        gv.getValueType(), &gv,
        {ConstantInt::get(i64Ty, 0), ConstantInt::get(i64Ty, 0)});
    if (devresPtr->getType() != release->getArg(1)->getType()) {
      devresPtr = b.CreateBitCast(devresPtr, release->getArg(1)->getType());
    }
    b.CreateCall(
        release,
        {Constant::getNullValue(release->getArg(0)->getType()), devresPtr});
    b.CreateRetVoid();
    return f;
  }

  void buildFail(Module &m, Function *devresRelease) {
    Function *fail = m.getFunction("drvhorn.fail");
    Function *checker = m.getFunction("drvhorn.assert_kref");
    Type *krefType = checker->getArg(0)->getType()->getPointerElementType();
    LLVMContext &ctx = m.getContext();
    BasicBlock *blk = BasicBlock::Create(ctx, "entry", fail);
    IRBuilder<> b(blk);
    b.CreateCall(devresRelease);

    std::string storagePrefix = "drvhorn.storage.";
    for (GlobalVariable &gv : m.globals()) {
      if (gv.getName().startswith(storagePrefix)) {
        StringRef suffix = gv.getName().substr(storagePrefix.size());
        GlobalVariable *targetIndex =
            m.getGlobalVariable("drvhorn.target_index." + suffix.str(), true);
        Function *f = genAssertFunction(m, gv, targetIndex, suffix);
        b.CreateCall(f);
      } else if (gv.getName().startswith("drvhorn.kref.")) {
        Type *type = gv.getValueType();
        Value *krefPtr;
        if (equivTypes(type, krefType->getPointerTo())) {
          krefPtr = b.CreateLoad(type, &gv);
        } else {
          krefPtr = b.CreateInBoundsGEP(
              type, &gv,
              gepIndicesToStruct(cast<StructType>(type), krefType).getValue());
        }
        b.CreateCall(checker, krefPtr);
      }
    }

    b.CreateRetVoid();
  }

  void removeNotCalledFunctions(Module &m) {
    for (Function &f : m) {
      if (getCalls(&f).empty() && f.hasFnAttribute("devres_release"))
        f.deleteBody();
    }
  }
};

char AssertKrefs::ID = 0;

Pass *createAssertKrefsPass() { return new AssertKrefs(); }
} // namespace seahorn
