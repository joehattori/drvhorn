#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Analysis/SeaBuiltinsInfo.hh"
#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

static unsigned platformDriverProbeIndex = 0;
static unsigned pDevDeviceGEPIndex = 3;
static unsigned deviceDriverDataIndex = 8;

class PlatformDriver : public ModulePass {
public:
  static char ID;

  PlatformDriver(StringRef platformDriverName)
      : ModulePass(ID), platformDriverName(platformDriverName) {}

  bool runOnModule(Module &m) override {
    LLVMContext &ctx = m.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    Function *main = Function::Create(FunctionType::get(i32Ty, false),
                                      GlobalValue::ExternalLinkage, "main", &m);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", main);
    BasicBlock *fail = BasicBlock::Create(ctx, "fail", main);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", main);

    Function *probe = getProbeFn(m);
    buildEntryBlock(m, probe, entry, fail, ret);
    buildFailBlock(m, fail, ret);
    buildRetBlock(m, ret);

    return true;
  }

  virtual StringRef getPassName() const override { return "PlatformDriver"; }

private:
  StringRef platformDriverName;
  DenseMap<const Type *, Function *> ndfn;

  Function *getProbeFn(Module &m) {
    GlobalVariable *drv = m.getGlobalVariable(platformDriverName, true);
    Constant *probe =
        drv->getInitializer()->getAggregateElement(platformDriverProbeIndex);
    return dyn_cast_or_null<Function>(probe);
  }

  void buildEntryBlock(Module &m, Function *probe, BasicBlock *entry,
                       BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(entry);
    Type *pdevType = probe->getArg(0)->getType()->getPointerElementType();
    Value *pdev = allocType(m, b, pdevType);
    setupPDev(m, b, pdev);
    CallInst *call = b.CreateCall(probe, pdev);
    Value *zero = b.CreateICmpEQ(call, ConstantInt::get(call->getType(), 0));
    b.CreateCondBr(zero, ret, fail);
  }

  void setupPDev(Module &m, IRBuilder<> &b, Value *pdev) {
    Function *krefInit = m.getFunction("drvhorn.kref_init");
    Type *pdevType = pdev->getType()->getPointerElementType();
    LLVMContext &ctx = m.getContext();
    Type *krefType = krefInit->getArg(0)->getType()->getPointerElementType();
    PointerType *krefPtrType = krefType->getPointerTo();
    StringRef kobjName = "drvhorn.kref.struct.platform_device";
    Value *globalKref = m.getGlobalVariable(kobjName, true);
    if (!globalKref) {
      globalKref =
          new GlobalVariable(m, krefPtrType, false, GlobalValue::PrivateLinkage,
                             ConstantPointerNull::get(krefPtrType), kobjName);
    }
    Type *i8Ty = Type::getInt8Ty(ctx);
    Type *i32Ty = Type::getInt32Ty(ctx);
    Type *i64Ty = Type::getInt64Ty(ctx);
    Value *devPtr =
        b.CreateInBoundsGEP(pdevType, pdev,
                            {
                                ConstantInt::get(i64Ty, 0),
                                ConstantInt::get(i32Ty, pDevDeviceGEPIndex),
                            },
                            "device");
    StructType *devType =
        cast<StructType>(devPtr->getType()->getPointerElementType());
    Value *krefPtr = b.CreateInBoundsGEP(devType, devPtr,
                                         {
                                             ConstantInt::get(i64Ty, 0),
                                             ConstantInt::get(i32Ty, 0),
                                             ConstantInt::get(i32Ty, 6),
                                         },
                                         "kref");
    b.CreateCall(krefInit, krefPtr);
    b.CreateStore(krefPtr, globalKref);

    // setup driver_data
    Value *driverDataPtr =
        b.CreateInBoundsGEP(devType, devPtr,
                            {
                                ConstantInt::get(i64Ty, 0),
                                ConstantInt::get(i32Ty, deviceDriverDataIndex),
                            },
                            "driver_data");
    Constant *driverDataSize = ConstantInt::get(i64Ty, 0x1000);
    AllocaInst *driverData = b.CreateAlloca(i8Ty, driverDataSize);
    b.CreateStore(driverData, driverDataPtr);

    // setup of_node
    const SmallVector<Value *> &devNodeIndices =
        gepIndicesToStruct(devType,
                           StructType::getTypeByName(ctx, "struct.device_node")
                               ->getPointerTo())
            .getValue();
    Value *ofNodeGEP =
        b.CreateInBoundsGEP(devType, devPtr, devNodeIndices, "of_node");
    Function *devNodeGetter = m.getFunction("drvhorn.gen_device_node");
    Value *ofNode = b.CreateCall(devNodeGetter);
    if (ofNode->getType() != ofNodeGEP->getType()->getPointerElementType())
      ofNode = b.CreateBitCast(ofNode,
                               ofNodeGEP->getType()->getPointerElementType());
    b.CreateStore(ofNode, ofNodeGEP);
  }

  Value *allocType(Module &m, IRBuilder<> &b, Type *type) {
    AllocaInst *alloc = b.CreateAlloca(type);
    Function *nondet = getNondetFn(type, m);
    CallInst *val = b.CreateCall(nondet);
    // Fill the allocated memory with a nondet value.
    b.CreateStore(val, alloc);
    return alloc;
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

char PlatformDriver::ID = 0;

Pass *createPlatformDriverPass(StringRef name) {
  return new PlatformDriver(name);
}
}; // namespace seahorn
