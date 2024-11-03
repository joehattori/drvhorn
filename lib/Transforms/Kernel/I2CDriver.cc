#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

static unsigned i2cDriverProbeIndex = 1;

class I2CDriver : public ModulePass {
public:
  static char ID;

  I2CDriver(StringRef i2cDriverName)
      : ModulePass(ID), i2cDriverName(i2cDriverName) {}

  bool runOnModule(Module &m) override {
    LLVMContext &ctx = m.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    Function *main = Function::Create(
        FunctionType::get(i32Ty, false),
        GlobalValue::LinkageTypes::ExternalLinkage, "main", &m);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", main);
    BasicBlock *fail = BasicBlock::Create(ctx, "fail", main);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", main);

    Function *probe = getProbeFn(m);
    buildEntryBlock(m, probe, entry, fail, ret);
    buildFailBlock(m, fail, ret);
    buildRetBlock(m, ret);

    return true;
  }

  virtual StringRef getPassName() const override { return "I2CDriver"; }

private:
  StringRef i2cDriverName;

  Function *getProbeFn(Module &m) {
    GlobalVariable *drv = m.getGlobalVariable(i2cDriverName, true);
    Constant *probe =
        drv->getInitializer()->getAggregateElement(i2cDriverProbeIndex);
    return dyn_cast_or_null<Function>(probe);
  }

  void buildEntryBlock(Module &m, Function *probe, BasicBlock *entry,
                       BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(entry);
    StructType *i2cClientType =
        cast<StructType>(probe->getArg(0)->getType()->getPointerElementType());
    Value *i2cClient = setupI2CClient(m, b, i2cClientType);
    CallInst *call = b.CreateCall(probe, i2cClient);
    Value *isZero = b.CreateICmpEQ(call, ConstantInt::get(call->getType(), 0));
    b.CreateCondBr(isZero, ret, fail);
  }

  Value *setupI2CClient(Module &m, IRBuilder<> &b, StructType *i2cClientType) {
    LLVMContext &ctx = m.getContext();
    StructType *deviceType = StructType::getTypeByName(ctx, "struct.device");
    Function *krefInit = m.getFunction("drvhorn.kref_init");
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    PointerType *krefPtrType =
        cast<PointerType>(krefInit->getArg(0)->getType());
    GlobalVariable *globalKref = new GlobalVariable(
        m, krefPtrType, false, GlobalValue::LinkageTypes::PrivateLinkage,
        ConstantPointerNull::get(krefPtrType),
        "drvhorn.kref.struct.i2c_client");
    SmallVector<Value *> gepIndices(
        gepIndicesToStruct(i2cClientType, deviceType).getValue());
    AllocaInst *i2cClient = b.CreateAlloca(i2cClientType);
    gepIndices.push_back(ConstantInt::get(i32Ty, 0));
    gepIndices.push_back(ConstantInt::get(i32Ty, 6));
    Value *krefPtr = b.CreateInBoundsGEP(i2cClientType, i2cClient, gepIndices);
    b.CreateCall(krefInit, krefPtr);
    b.CreateStore(krefPtr, globalKref);
    return i2cClient;
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
};

char I2CDriver::ID = 0;

Pass *createI2CDriverPass(StringRef i2cDriverName) {
  return new I2CDriver(i2cDriverName);
}

} // namespace seahorn
