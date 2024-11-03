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
    Function *fail = m.getFunction("drvhorn.fail");
    Function *checker = m.getFunction("drvhorn.assert_kref");
    Type *krefType = checker->getArg(0)->getType()->getPointerElementType();
    LLVMContext &ctx = m.getContext();
    BasicBlock *blk = BasicBlock::Create(ctx, "entry", fail);
    IRBuilder<> b(blk);
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
                         GlobalValue::LinkageTypes::ExternalLinkage,
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
    StructType *elemType = cast<StructType>(storageType->getElementType());
    SmallVector<Value *> devIndices(
        gepIndicesToStruct(elemType, krefType).getValue());
    auto pos = devIndices.begin();
    pos++;
    devIndices.insert(pos, target);
    Value *krefPtr =
        b.CreateInBoundsGEP(storage.getValueType(), &storage, devIndices);
    b.CreateCall(checker, krefPtr);
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    b.CreateRetVoid();
    return f;
  }
};

char AssertKrefs::ID = 0;

Pass *createAssertKrefsPass() { return new AssertKrefs(); }
} // namespace seahorn
