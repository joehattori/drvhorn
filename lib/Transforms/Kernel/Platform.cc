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

class PlatformDriver : public ModulePass {
public:
  static char ID;

  PlatformDriver(StringRef platformDriverName)
      : ModulePass(ID), platformDriverName(platformDriverName) {}

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
    StructType *pdevType =
        StructType::getTypeByName(m.getContext(), "struct.platform_device");
    Value *pdev = allocType(m, b, pdevType);
    setupPDev(m, b, pdev);
    if (pdev->getType() != probe->getArg(0)->getType())
      pdev = b.CreateBitCast(pdev, probe->getArg(0)->getType());
    CallInst *call = b.CreateCall(probe, {pdev});
    Value *zero = b.CreateICmpEQ(call, ConstantInt::get(call->getType(), 0));
    b.CreateCondBr(zero, ret, fail);
  }

  void setupPDev(Module &m, IRBuilder<> &b, Value *pdev) {
    Function *setupKref = m.getFunction("drvhorn.setup_kref");
    Type *pdevType = pdev->getType()->getPointerElementType();
    LLVMContext &ctx = m.getContext();
    PointerType *krefPtrType =
        cast<PointerType>(setupKref->getArg(0)->getType());
    StringRef kobjName = "drvhorn.kref.struct.platform_device";
    Value *globalKref = m.getGlobalVariable(kobjName, true);
    if (!globalKref) {
      globalKref = new GlobalVariable(
          m, krefPtrType, false, GlobalValue::LinkageTypes::PrivateLinkage,
          ConstantPointerNull::get(krefPtrType), kobjName);
    }
    Type *i32Ty = Type::getInt32Ty(ctx);
    Type *i64Ty = Type::getInt64Ty(ctx);
    Value *krefPtr =
        b.CreateGEP(pdevType, pdev,
                    {
                        ConstantInt::get(i64Ty, 0),
                        ConstantInt::get(i32Ty, pDevDeviceGEPIndex),
                        ConstantInt::get(i32Ty, 0),
                        ConstantInt::get(i32Ty, 6),
                    });
    if (krefPtr->getType() != setupKref->getArg(0)->getType())
      krefPtr = b.CreateBitCast(krefPtr, setupKref->getArg(0)->getType());
    if (globalKref->getType() != setupKref->getArg(1)->getType())
      globalKref = b.CreateBitCast(globalKref, setupKref->getArg(1)->getType());
    b.CreateCall(setupKref, {krefPtr, globalKref});
  }

  void buildFailBlock(Module &m, BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(fail);
    Function *checker = m.getFunction("drvhorn.assert_kref");
    for (GlobalVariable *g : getKrefs(m)) {
      Value *v = b.CreateLoad(g->getValueType(), g);
      if (v->getType() != checker->getArg(0)->getType())
        v = b.CreateBitCast(v, checker->getArg(0)->getType());
      b.CreateCall(checker, v);
    }
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
