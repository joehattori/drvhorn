#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

class HandleDevm : public ModulePass {
public:
  static char ID;

  HandleDevm() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    handleDevmAddActionCalls(m);
    handleDevresAllocCalls(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "Devm"; }

private:
  void handleDevmAddActionCalls(Module &m) {
    Function *devmAddAction = m.getFunction("drvhorn.__devm_add_action");
    if (!devmAddAction)
      return;
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    LLVMContext &ctx = m.getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    ConstantInt *zero = ConstantInt::get(i32Ty, 0);
    ConstantInt *enomem = ConstantInt::get(i32Ty, -12);
    for (CallInst *call : getCalls(devmAddAction)) {
      Function *action =
          dyn_cast<Function>(call->getArgOperand(1)->stripPointerCasts());
      if (!action) {
        errs() << "TODO: 1st argument of __devm_add_action in "
               << call->getFunction()->getName() << " is not Function " << *call
               << "\n";
        continue;
      }
      std::string name = action->getName().str();
      GlobalVariable *switchGV = getOrCreateDevmSwitch(m, name);
      Value *data = call->getArgOperand(2);
      GlobalVariable *dataGV =
          getOrCreateDevmActionData(m, name, data->getType());

      IRBuilder<> b(call);
      Value *isOk = b.CreateCall(ndBool);
      Value *ret = b.CreateSelect(isOk, zero, enomem);
      b.CreateStore(isOk, switchGV);
      b.CreateStore(data, dataGV);
      call->replaceAllUsesWith(ret);
      call->eraseFromParent();
    }
  }

  GlobalVariable *getOrCreateDevmSwitch(Module &m, std::string fnName) {
    std::string gvName = "drvhorn.devm_switch." + fnName;
    if (GlobalVariable *gv = m.getGlobalVariable(gvName, true))
      return gv;
    LLVMContext &ctx = m.getContext();
    return new GlobalVariable(m, Type::getInt1Ty(ctx), false,
                              GlobalValue::ExternalLinkage,
                              ConstantInt::getFalse(ctx), gvName);
  }

  GlobalVariable *getOrCreateDevmActionData(Module &m, std::string fnName,
                                            Type *dataType) {
    std::string gvName = "drvhorn.devm_action_data." + fnName;
    if (GlobalVariable *gv = m.getGlobalVariable(gvName, true))
      return gv;
    return new GlobalVariable(m, dataType, false, GlobalValue::ExternalLinkage,
                              Constant::getNullValue(dataType), gvName);
  }

  void handleDevresAllocCalls(Module &m) {
    Function *f = m.getFunction("drvhorn.__devres_alloc_node");
    if (!f)
      return;
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    LLVMContext &ctx = m.getContext();
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    PointerType *i8PtrTy = Type::getInt8PtrTy(ctx);
    for (CallInst *call : getCalls(f)) {
      Function *release =
          dyn_cast<Function>(call->getArgOperand(0)->stripPointerCasts());
      ConstantInt *size = dyn_cast<ConstantInt>(call->getArgOperand(1));
      if (!release || !size)
        continue;
      std::string name = release->getName().str();
      GlobalVariable *devres =
          getOrCreateDevresGV(m, name, size->getZExtValue());
      GlobalVariable *switchGV = getOrCreateDevmSwitch(m, name);

      IRBuilder<> b(call);
      Value *isOk = b.CreateCall(ndBool);
      b.CreateStore(isOk, switchGV);
      Constant *devresPtr = ConstantExpr::getInBoundsGetElementPtr(
          devres->getValueType(), devres,
          ArrayRef<Constant *>{ConstantInt::get(i64Ty, 0),
                               ConstantInt::get(i64Ty, 0)});
      Value *replace =
          b.CreateSelect(isOk, devresPtr, Constant::getNullValue(i8PtrTy));
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  GlobalVariable *getOrCreateDevresGV(Module &m, std::string name,
                                      uint64_t size) {
    std::string gvName = "drvhorn.devres_alloc." + name;
    if (GlobalVariable *gv = m.getGlobalVariable(gvName, true))
      return gv;
    LLVMContext &ctx = m.getContext();
    ArrayType *type = ArrayType::get(Type::getInt8Ty(ctx), size);
    return new GlobalVariable(m, type, false, GlobalValue::ExternalLinkage,
                              Constant::getNullValue(type), gvName);
  }
};

char HandleDevm::ID = 0;

Pass *createHandleDevmPass() { return new HandleDevm(); }
} // namespace seahorn
