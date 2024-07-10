#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Analysis/SeaBuiltinsInfo.hh"

using namespace llvm;

namespace seahorn {

static unsigned platformDriverProbeIndex = 0;
static unsigned pDevDeviceGEPIndex = 3;
static unsigned deviceKobjGEPIndex = 0;

class PlatformDriver : public ModulePass {
public:
  static char ID;

  PlatformDriver(StringRef platformDriverName)
      : ModulePass(ID), platformDriverName(platformDriverName) {}

  bool runOnModule(Module &m) override {
    seahorn::SeaBuiltinsInfo &sbi =
        getAnalysis<SeaBuiltinsInfoWrapperPass>().getSBI();
    Function *verifierError = sbi.mkSeaBuiltinFn(SeaBuiltinsOp::ERROR, m);
    constructMain(m, verifierError);
    return true;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<seahorn::SeaBuiltinsInfoWrapperPass>();
    AU.setPreservesAll();
  }

  virtual StringRef getPassName() const override { return "PlatformDriver"; }

private:
  StringRef platformDriverName;
  DenseMap<const Type *, Function *> ndfn;

  void constructMain(Module &m, Function *verifierError) {
    Type *i32Ty = Type::getInt32Ty(m.getContext());
    Function *main = Function::Create(
        FunctionType::get(i32Ty, false),
        GlobalValue::LinkageTypes::ExternalLinkage, "main", &m);
    BasicBlock *entry = BasicBlock::Create(m.getContext(), "entry", main);
    BasicBlock *fail = BasicBlock::Create(m.getContext(), "fail", main);
    BasicBlock *err = BasicBlock::Create(m.getContext(), "error", main);
    BasicBlock *ret = BasicBlock::Create(m.getContext(), "ret", main);

    Function *probe = getProbeFn(m);
    Value *devPtr = buildEntryBlock(m, probe, entry, fail, ret);
    buildFailBlock(m, fail, err, ret, devPtr);
    buildErrBlock(err, ret, verifierError);
    buildRetBlock(m, ret);
  }

  Function *getProbeFn(Module &m) {
    GlobalVariable *drv = m.getGlobalVariable(platformDriverName);
    Constant *probe =
        drv->getInitializer()->getAggregateElement(platformDriverProbeIndex);
    return dyn_cast_or_null<Function>(probe);
  }

  Value *buildEntryBlock(Module &m, Function *probe, BasicBlock *entry,
                         BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(entry);
    Function *setupOfRoot = m.getFunction("__DRVHORN_setup_of_root");
    b.CreateCall(setupOfRoot);
    StructType *pdevType =
        StructType::getTypeByName(m.getContext(), "struct.platform_device");
    Value *pdev = allocType(m, b, pdevType);
    Value *devPtr = setupPDev(m, b, pdev);
    if (pdev->getType() != probe->getArg(0)->getType())
      pdev = b.CreateBitCast(pdev, probe->getArg(0)->getType());
    CallInst *call = b.CreateCall(probe, {pdev});
    Value *zero = b.CreateICmpEQ(call, ConstantInt::get(call->getType(), 0));
    b.CreateCondBr(zero, ret, fail);
    return devPtr;
  }

  Value *setupPDev(Module &m, IRBuilder<> &b, Value *pdev) {
    Function *setupDevice = m.getFunction("__DRVHORN_setup_device");
    Type *pdevType = pdev->getType()->getPointerElementType();
    Type *i32Type = Type::getInt32Ty(m.getContext());
    Type *i64Type = Type::getInt64Ty(m.getContext());
    Constant *zero = ConstantInt::get(i64Type, 0);
    Constant *idx = ConstantInt::get(i32Type, pDevDeviceGEPIndex);
    Value *devPtr = b.CreateGEP(pdevType, pdev, {zero, idx});
    if (devPtr->getType() != setupDevice->getArg(0)->getType())
      devPtr = b.CreateBitCast(devPtr, setupDevice->getArg(0)->getType());
    b.CreateCall(setupDevice, {devPtr});
    return devPtr;
  }

  void buildFailBlock(Module &m, BasicBlock *fail, BasicBlock *err,
                      BasicBlock *ret, Value *devPtr) {
    Function *counterFn = m.getFunction("__DRVHORN_util_get_kobject_count");
    Type *i32Ty = Type::getInt32Ty(m.getContext());
    Type *i64Type = Type::getInt64Ty(m.getContext());
    Constant *zero = ConstantInt::get(i64Type, 0);

    IRBuilder<> b(fail);
    b.CreateCall(m.getFunction("__DRVHORN_check_device_node_refcounts"));
    b.CreateCall(m.getFunction("__DRVHORN_check_device_refcounts"));
    Value *devKobjPtr =
        b.CreateGEP(devPtr->getType()->getPointerElementType(), devPtr,
                    {zero, ConstantInt::get(i32Ty, deviceKobjGEPIndex)});

    if (counterFn->getArg(0)->getType() != devKobjPtr->getType())
      devKobjPtr = b.CreateBitCast(devKobjPtr, counterFn->getArg(0)->getType());
    CallInst *counter = b.CreateCall(counterFn, {devKobjPtr});
    Value *isOne = b.CreateICmpEQ(counter, ConstantInt::get(i32Ty, 1));
    b.CreateCondBr(isOne, ret, err);
  }

  void buildErrBlock(BasicBlock *err, BasicBlock *ret,
                     Function *verifierError) {
    IRBuilder<> b(err);
    b.CreateCall(verifierError);
    b.CreateBr(ret);
  }

  void buildRetBlock(Module &m, BasicBlock *ret) {
    IRBuilder<> b(ret);
    Type *i32Ty = Type::getInt32Ty(m.getContext());
    b.CreateRet(ConstantInt::get(i32Ty, 0));
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
