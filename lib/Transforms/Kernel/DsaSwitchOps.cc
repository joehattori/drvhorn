#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

static unsigned dsaSwitchOpsSetupIndex = 4;

class DsaSwitchOps : public ModulePass {
public:
  static char ID;

  DsaSwitchOps(StringRef dsaSwitchOpsName)
      : ModulePass(ID), dsaSwitchOpsName(dsaSwitchOpsName) {}

  bool runOnModule(Module &m) override {
    LLVMContext &ctx = m.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    Function *main = Function::Create(
        FunctionType::get(i32Ty, false),
        GlobalValue::LinkageTypes::ExternalLinkage, "main", &m);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", main);
    BasicBlock *fail = BasicBlock::Create(ctx, "fail", main);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", main);

    Function *setup = getSetupFn(m);
    buildEntryBlock(m, setup, entry, fail, ret);
    buildFailBlock(m, fail, ret);
    buildRetBlock(m, ret);

    return true;
  }

  virtual StringRef getPassName() const override { return "DsaSwitchOps"; }

private:
  StringRef dsaSwitchOpsName;
  DenseMap<const Type *, Function *> ndfn;

  Function *getSetupFn(Module &m) {
    GlobalVariable *drv = m.getGlobalVariable(dsaSwitchOpsName, true);
    Constant *setup =
        drv->getInitializer()->getAggregateElement(dsaSwitchOpsSetupIndex);
    return dyn_cast_or_null<Function>(setup);
  }

  void buildEntryBlock(Module &m, Function *setup, BasicBlock *entry,
                       BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(entry);
    Type *dsaSwitchType = setup->getArg(0)->getType()->getPointerElementType();
    Value *dsaSwitch = allocType(m, b, dsaSwitchType);
    setupDsaSwitch(m, b, dsaSwitch);
    CallInst *call = b.CreateCall(setup, {dsaSwitch});
    Value *zero = b.CreateICmpEQ(call, ConstantInt::get(call->getType(), 0));
    b.CreateCondBr(zero, ret, fail);
  }

  void setupDsaSwitch(Module &m, IRBuilder<> &b, Value *dsaSwitch) {
    Function *setupDevice = m.getFunction("__DRVHORN_setup_device");
    LLVMContext &ctx = m.getContext();
    Type *deviceType =
        setupDevice->getArg(0)->getType()->getPointerElementType();
    Value *devPtr = b.CreateAlloca(deviceType);
    PointerType *kobjPtrType = cast<PointerType>(
        setupDevice->getArg(1)->getType()->getPointerElementType());
    GlobalVariable *kobj = new GlobalVariable(
        m, kobjPtrType, false, GlobalValue::LinkageTypes::PrivateLinkage,
        ConstantPointerNull::get(kobjPtrType),
        "drvhorn.kref.struct.dsa_switch");
    b.CreateCall(setupDevice, {devPtr, kobj});
    Type *i32Type = Type::getInt32Ty(ctx);
    Type *i64Type = Type::getInt64Ty(ctx);
    Value *gep = b.CreateGEP(
        dsaSwitch->getType()->getPointerElementType(), dsaSwitch,
        {ConstantInt::get(i64Type, 0), ConstantInt::get(i32Type, 0)});
    if (devPtr->getType() != gep->getType()->getPointerElementType())
      devPtr = b.CreateBitCast(devPtr, gep->getType()->getPointerElementType());
    b.CreateStore(devPtr, gep);
  }

  void buildFailBlock(Module &m, BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(fail);
    Function *checker = m.getFunction("__DRVHORN_assert_kref");
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

char DsaSwitchOps::ID = 0;

Pass *createDsaSwitchOpsPass(StringRef name) { return new DsaSwitchOps(name); }

} // namespace seahorn
