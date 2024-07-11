#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

#include <map>

using namespace llvm;

namespace seahorn {
struct DevClassRel {
  StructType *surroundingDevType; // struct that embeds a `struct device`.
  SmallVector<Value *, 8> devIdx;
  GlobalVariable *cls;

  bool isValid() const { return surroundingDevType && cls; }
};

class HandleDeviceTree : public ModulePass {
public:
  static char ID;

  HandleDeviceTree() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    handleFindDeviceNode(m);
    handleClassFindDevice(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "HandleDeviceTree"; }

private:
  void handleFindDeviceNode(Module &m) {
    LLVMContext &ctx = m.getContext();
    std::pair<StringRef, Optional<size_t>> namesAndDeviceNodeIndices[] = {
        {"of_find_node_opts_by_path", None}, {"of_find_node_by_name", 0},
        {"of_find_node_by_type", 0},         {"of_find_compatible_node", 0},
        {"of_find_node_with_property", 0},
    };
    Function *getter = m.getFunction("__DRVHORN_get_device_node");
    for (const std::pair<StringRef, Optional<size_t>> &nameAndIndex :
         namesAndDeviceNodeIndices) {
      Function *f = m.getFunction(nameAndIndex.first);
      if (!f)
        continue;
      std::string wrapperName = nameAndIndex.first.str() + "_wrapper";
      Function *wrapper = Function::Create(
          f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
          wrapperName, &m);
      BasicBlock *block = BasicBlock::Create(ctx, "", wrapper);
      IRBuilder<> b(block);
      Value *from;
      PointerType *devNodeArgType =
          cast<PointerType>(getter->getArg(0)->getType());
      if (nameAndIndex.second == None) {
        from = ConstantPointerNull::get(devNodeArgType);
      } else {
        from = wrapper->getArg(0);
        if (from->getType() != devNodeArgType)
          from = b.CreateBitCast(from, devNodeArgType);
      }
      Value *call = b.CreateCall(getter, from);
      if (call->getType() != f->getReturnType())
        call = b.CreateBitCast(call, f->getReturnType());
      b.CreateRet(call);
      f->replaceAllUsesWith(wrapper);
      f->eraseFromParent();
    }
  }

  void handleClassFindDevice(Module &m) {
    std::map<CallInst *, Value *> toReplace;
    Function *clsFindDev = m.getFunction("class_find_device");
    for (CallInst *call : getCalls(clsFindDev)) {
      Value *clsArg = call->getArgOperand(0);
      StructType *surroundingDevType = nullptr;
      if (GlobalVariable *cls = dyn_cast<GlobalVariable>(clsArg)) {
        if (StructType *t = getSurroundingDeviceType(cls))
          surroundingDevType = t;
      } else if (LoadInst *load = dyn_cast<LoadInst>(clsArg)) {
        GlobalVariable *cls =
            dyn_cast<GlobalVariable>(load->getPointerOperand());
        for (User *u : cls->users()) {
          if (isa<LoadInst>(u)) {
            if (StructType *t = getSurroundingDeviceType(u))
              surroundingDevType = t;
          }
        }
      } else if (Argument *arg = dyn_cast<Argument>(clsArg)) {
        if (arg->getParent()->getName().equals("device_destroy"))
          continue;
        errs() << "TODO: handleClassFindDevice\n";
        std::exit(1);
      } else {
        errs() << "TODO: handleClassFindDevice\n";
        std::exit(1);
      }
      Value *devPtr = buildNewClassFindDevice(m, surroundingDevType, call);
      toReplace[call] = devPtr;
    }
    for (std::pair<CallInst *, Value *> p : toReplace) {
      p.first->replaceAllUsesWith(p.second);
      p.first->dropAllReferences();
      p.first->eraseFromParent();
    }
  }

  // @cls: a `struct.class**` variable.
  StructType *getSurroundingDeviceType(Value *cls) {
    Value *devicePtr = nullptr;
    for (User *user : cls->users()) {
      if (StoreInst *store = dyn_cast<StoreInst>(user)) {
        devicePtr = store->getPointerOperand();
        break;
      }
    }
    if (!devicePtr)
      return nullptr;
    if (GEPOperator *gep = dyn_cast<GEPOperator>(devicePtr)) {
      return dyn_cast<StructType>(gep->getSourceElementType());
    } else if (BitCastOperator *bitcast =
                   dyn_cast<BitCastOperator>(devicePtr)) {
      Value *src = bitcast->getOperand(0);
      if (GEPOperator *gep = dyn_cast<GEPOperator>(src)) {
        src = gep->getPointerOperand();
        if (src->getType() == Type::getInt8PtrTy(cls->getContext())) {
          for (User *user : src->users()) {
            if (BitCastOperator *bc = dyn_cast<BitCastOperator>(user))
              return dyn_cast<StructType>(
                  bc->getType()->getPointerElementType());
          }
        }
      }
    }
    errs() << "TODO: getSurroundingDeviceType\n";
    std::exit(1);
  }

  Value *buildNewClassFindDevice(Module &m, StructType *surroundingDevType,
                                 CallInst *origCall) {
    Function *malloc = m.getFunction("malloc");
    FunctionType *mallocType =
        FunctionType::get(surroundingDevType->getPointerTo(),
                          malloc->getArg(0)->getType(), false);
    Constant *castedMalloc =
        ConstantExpr::getBitCast(malloc, mallocType->getPointerTo());
    size_t size = m.getDataLayout().getTypeAllocSize(surroundingDevType);
    Type *i64Type = Type::getInt64Ty(m.getContext());
    Type *i32Type = Type::getInt32Ty(m.getContext());
    IRBuilder<> b(origCall);
    CallInst *call = b.CreateCall(mallocType, castedMalloc,
                                  {ConstantInt::get(i64Type, size)});
    Optional<size_t> idx = getEmbeddedDeviceIndex(surroundingDevType);
    if (idx == None) {
      errs() << "surroundingDevType " << *surroundingDevType
             << " does not embed a device\n";
      std::exit(1);
    }
    Value *devPtr = b.CreateGEP(
        surroundingDevType, call,
        {ConstantInt::get(i64Type, 0), ConstantInt::get(i32Type, *idx)});

    Function *ndBool = m.getFunction("nd_bool");
    CallInst *ndVal = b.CreateCall(ndBool->getFunctionType(), ndBool);
    devPtr = b.CreateSelect(
        ndVal, devPtr,
        ConstantPointerNull::get(cast<PointerType>(devPtr->getType())));

    Function *setupDevice = m.getFunction("__DRVHORN_setup_device");
    Value *setupDevArg = devPtr;
    if (setupDevArg->getType() != setupDevice->getArg(0)->getType())
      setupDevArg =
          b.CreateBitCast(setupDevArg, setupDevice->getArg(0)->getType());
    b.CreateCall(setupDevice, {setupDevArg});

    Function *recordDevice = m.getFunction("__DRVHORN_record_device");
    Value *recordDevArg = devPtr;
    if (call->getType() != recordDevice->getArg(0)->getType())
      recordDevArg =
          b.CreateBitCast(recordDevArg, recordDevice->getArg(0)->getType());
    devPtr = b.CreateCall(recordDevice, {recordDevArg});

    Function *getDevice = m.getFunction("get_device");
    Value *getDeviceArg = devPtr;
    if (getDeviceArg->getType() != getDevice->getArg(0)->getType())
      getDeviceArg =
          b.CreateBitCast(getDeviceArg, getDevice->getArg(0)->getType());
    b.CreateCall(getDevice, {getDeviceArg});

    if (devPtr->getType() != origCall->getType())
      devPtr = b.CreateBitCast(devPtr, origCall->getType());
    return devPtr;
  }

  Optional<size_t> getEmbeddedDeviceIndex(StructType *surroundingDevType) {
    for (size_t i = 0; i < surroundingDevType->getNumElements(); i++) {
      if (surroundingDevType->getElementType(i)->getStructName().startswith(
              "struct.device"))
        return i;
    }
    return None;
  }

  CallInst *getCallInst(User *user) {
    if (isa<Instruction>(user)) {
      return dyn_cast<CallInst>(user);
    } else {
      for (User *u : user->users()) {
        if (CallInst *call = getCallInst(u))
          return call;
      }
      return nullptr;
    }
  }
};

char HandleDeviceTree::ID = 0;

Pass *createHandleDeviceTreePass() { return new HandleDeviceTree(); }
}; // namespace seahorn
