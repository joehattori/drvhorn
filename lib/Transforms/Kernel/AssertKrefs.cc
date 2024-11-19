#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Analysis/SeaBuiltinsInfo.hh"
#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

class AssertKrefs : public ModulePass {
public:
  static char ID;

  AssertKrefs() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    buildFail(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "AssertKrefs"; }

  void getAnalysisUsage(AnalysisUsage &au) const override {
    au.addRequired<SeaBuiltinsInfoWrapperPass>();
    au.setPreservesAll();
  }

private:
  void buildFail(Module &m) {
    Function *fail = m.getFunction("drvhorn.fail");
    Function *checker = m.getFunction("drvhorn.assert_kref");
    Type *krefType = checker->getArg(0)->getType()->getPointerElementType();
    LLVMContext &ctx = m.getContext();
    BasicBlock *blk = BasicBlock::Create(ctx, "entry", fail);
    IRBuilder<> b(blk);

    static const std::string storagePrefix = "drvhorn.storage.";
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

  Function *genAssertFunction(Module &m, GlobalVariable &storage,
                              GlobalVariable *targetIndex, StringRef suffix) {
    Function *checker = m.getFunction("drvhorn.assert_kref");
    LLVMContext &ctx = m.getContext();
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    StructType *deviceType = StructType::getTypeByName(ctx, "struct.device");
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
    if (equivTypes(elemType, deviceType)) {
      Function *devChecker = deviceChecker(m, elemType);
      b.CreateCall(devChecker, elem);
    }
    Value *krefPtr = b.CreateInBoundsGEP(
        elemType, elem, gepIndicesToStruct(elemType, krefType).getValue());
    b.CreateCall(checker, krefPtr);
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    b.CreateRetVoid();
    return f;
  }

  Function *deviceChecker(Module &m, StructType *devType) {
    std::string name =
        "drvhorn.assert_dev_is_deleted." + devType->getName().str();
    if (Function *f = m.getFunction(name))
      return f;
    LLVMContext &ctx = m.getContext();
    Function *f = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), devType->getPointerTo(), false),
        GlobalValue::ExternalLinkage, name, &m);
    IntegerType *i8Ty = Type::getInt8Ty(ctx);
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    Argument *dev = f->getArg(0);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", f);
    BasicBlock *err = BasicBlock::Create(ctx, "err", f);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", f);

    IRBuilder<> b(entry);
    Value *isAddedGEP = b.CreateInBoundsGEP(devType, dev,
                                            {ConstantInt::get(i64Ty, 0),
                                             ConstantInt::get(i32Ty, 0),
                                             ConstantInt::get(i32Ty, 7)});
    Value *isAdded = b.CreateLoad(i8Ty, isAddedGEP);
    Value *isZero = b.CreateICmpEQ(isAdded, ConstantInt::get(i8Ty, 0));
    b.CreateCondBr(isZero, ret, err);

    b.SetInsertPoint(err);
    SeaBuiltinsInfo &sbi = getAnalysis<SeaBuiltinsInfoWrapperPass>().getSBI();
    Function *error = sbi.mkSeaBuiltinFn(SeaBuiltinsOp::ERROR, m);
    b.CreateCall(error);
    b.CreateUnreachable();

    b.SetInsertPoint(ret);
    b.CreateRetVoid();
    return f;
  }
};

char AssertKrefs::ID = 0;

Pass *createAssertKrefsPass() { return new AssertKrefs(); }
} // namespace seahorn
