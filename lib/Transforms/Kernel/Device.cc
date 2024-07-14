#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

#include <map>

using namespace llvm;

namespace seahorn {
class HandleDevices : public ModulePass {
public:
  static char ID;

  HandleDevices() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    handleDeviceNodeFinders(m);
    handleDeviceFinders(m);
    handleDeviceNodeIsCompatible(m);
    handleDeviceAdd(m);
    killDeviceNodeNotify(m);
    killDeviceDel(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "HandleDeviceTree"; }

private:
  void handleDeviceNodeFinders(Module &m) {
    LLVMContext &ctx = m.getContext();
    std::pair<StringRef, Optional<size_t>> namesAndDeviceNodeIndices[] = {
        {"of_find_node_opts_by_path", None},
        {"of_find_node_by_name", 0},
        {"of_find_node_by_type", 0},
        {"of_find_compatible_node", 0},
        {"of_find_node_by_phandle", None},
        {"of_find_matching_node_and_match", 0},
        {"of_find_node_with_property", 0},
    };
    Function *getter = m.getFunction("__DRVHORN_get_device_node");
    for (const std::pair<StringRef, Optional<size_t>> &nameAndIndex :
         namesAndDeviceNodeIndices) {
      Function *f = m.getFunction(nameAndIndex.first);
      if (!f)
        continue;
      std::string stubName = "__DRVHORN_" + nameAndIndex.first.str();
      Function *stub = Function::Create(
          f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
          stubName, &m);
      BasicBlock *block = BasicBlock::Create(ctx, "", stub);
      IRBuilder<> b(block);
      Value *from;
      PointerType *devNodeArgType =
          cast<PointerType>(getter->getArg(0)->getType());
      if (nameAndIndex.second.hasValue()) {
        from = stub->getArg(*nameAndIndex.second);
        if (from->getType() != devNodeArgType)
          from = b.CreateBitCast(from, devNodeArgType);
      } else {
        from = ConstantPointerNull::get(devNodeArgType);
      }
      Value *call = b.CreateCall(getter, from);
      if (call->getType() != f->getReturnType())
        call = b.CreateBitCast(call, f->getReturnType());
      b.CreateRet(call);
      f->replaceAllUsesWith(stub);
      f->eraseFromParent();
    }
  }

  void handleDeviceFinders(Module &m) {
    std::map<CallInst *, Value *> toReplace;
    StringRef deviceFinderNames[] = {"class_find_device", "bus_find_device"};
    for (StringRef name : deviceFinderNames) {
      Function *finder = m.getFunction(name);
      for (CallInst *call : getCalls(finder)) {
        if (Value *replacement = buildDeviceFindCallReplacer(m, call))
          toReplace[call] = replacement;
      }
    }
    for (std::pair<CallInst *, Value *> p : toReplace) {
      p.first->replaceAllUsesWith(p.second);
      p.first->eraseFromParent();
    }
  }

  Value *buildDeviceFindCallReplacer(Module &m, CallInst *call) {
    Value *arg = call->getArgOperand(0);
    for (Value *clsOrBusPtr : getClassOrBusPtrs(arg->stripPointerCasts())) {
      if (StructType *t = getSurroundingDeviceType(clsOrBusPtr)) {
        return buildNewEmbeddedDevice(m, t, call);
      }
    }
    return nullptr;
  }

  // get struct.class* or struct.bus_type*.
  SmallVector<Value *, 16> getClassOrBusPtrs(Value *v) {
    if (GlobalVariable *gv = dyn_cast<GlobalVariable>(v)) {
      return {gv};
    } else if (LoadInst *load = dyn_cast<LoadInst>(v)) {
      SmallVector<Value *, 16> clsOrBusPtrs;
      Value *gv = load->getPointerOperand();
      for (User *u : gv->users()) {
        if (isa<LoadInst>(u))
          clsOrBusPtrs.push_back(u);
      }
      return clsOrBusPtrs;
    }
    return {};
  }

  // @cls: a `struct.class*` variable.
  StructType *getSurroundingDeviceType(Value *clsOrBusPtr) {
    auto findSurroundingDeviceType = [this](Value *dest) -> StructType * {
      GEPOperator *gep = dyn_cast<GEPOperator>(dest);
      if (!gep)
        return nullptr;
      Type *i8Type = Type::getInt8Ty(dest->getContext());
      if (gep->getSourceElementType() != i8Type) {
        StructType *t = dyn_cast<StructType>(gep->getSourceElementType());
        return t && getEmbeddedDeviceIndex(t).hasValue() ? t : nullptr;
      }
      // kmalloc'ed type
      CallInst *call = dyn_cast<CallInst>(gep->getPointerOperand());
      if (!call ||
          !call->getCalledFunction()->getName().equals("__DRVHORN___kmalloc"))
        return nullptr;
      for (User *user : call->users()) {
        if (BitCastOperator *bitcast = dyn_cast<BitCastOperator>(user)) {
          StructType *casted = dyn_cast<StructType>(
              bitcast->getDestTy()->getPointerElementType());
          if (casted && getEmbeddedDeviceIndex(casted).hasValue())
            return casted;
        }
      }
      return nullptr;
    };

    // struct.class is stored in the class field of struct.device.
    for (StoreInst *store : getStores(clsOrBusPtr)) {
      Value *dest = store->getPointerOperand()->stripPointerCasts();
      if (StructType *ret = findSurroundingDeviceType(dest))
        return ret;
    }
    return nullptr;
  }

  SmallVector<StoreInst *> getStores(Value *ptr) {
    SmallVector<StoreInst *, 8> stores;
    for (User *user : ptr->users()) {
      if (isa<BitCastOperator>(user))
        stores.append(getStores(user));
      if (StoreInst *store = dyn_cast<StoreInst>(user))
        stores.push_back(store);
    }
    return stores;
  }

  Value *buildNewEmbeddedDevice(Module &m, StructType *surroundingDevType,
                                CallInst *origCall) {
    Function *malloc = m.getFunction("__DRVHORN_malloc");
    FunctionType *mallocType =
        FunctionType::get(surroundingDevType->getPointerTo(),
                          malloc->getArg(0)->getType(), false);
    Constant *castedMalloc =
        ConstantExpr::getBitCast(malloc, mallocType->getPointerTo());
    size_t size = m.getDataLayout().getTypeAllocSize(surroundingDevType);
    Type *i64Type = Type::getInt64Ty(m.getContext());
    Type *i32Type = Type::getInt32Ty(m.getContext());
    IRBuilder<> b(origCall);
    CallInst *call =
        b.CreateCall(mallocType, castedMalloc,
                     {ConstantInt::get(i64Type, size)}, "surrounding.dev");
    Optional<size_t> idx = getEmbeddedDeviceIndex(surroundingDevType);
    if (!idx.hasValue()) {
      errs() << "surroundingDevType " << *surroundingDevType
             << " does not embed a device\n";
      std::exit(1);
    }
    Value *devPtr = b.CreateGEP(
        surroundingDevType, call,
        {ConstantInt::get(i64Type, 0), ConstantInt::get(i32Type, *idx)});

    Value *cond = b.CreateICmpNE(
        call, ConstantPointerNull::get(cast<PointerType>(call->getType())));
    devPtr = b.CreateSelect(
        cond, devPtr,
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

  Optional<size_t> getEmbeddedDeviceIndex(StructType *s) {
    StructType *deviceType =
        StructType::getTypeByName(s->getContext(), "struct.device");
    for (size_t i = 0; i < s->getNumElements(); i++) {
      if (equivTypes(s->getElementType(i), deviceType))
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

  void handleDeviceNodeIsCompatible(Module &m) {
    Function *ndBool = m.getFunction("nd_bool");
    Type *i32Type = Type::getInt32Ty(m.getContext());
    for (CallInst *call :
         getCalls(m.getFunction("__of_device_is_compatible"))) {
      CallInst *ndVal = CallInst::Create(ndBool, "", call);
      ZExtInst *replace = new ZExtInst(ndVal, i32Type, "", call);
      call->replaceAllUsesWith(replace);
      call->dropAllReferences();
      call->eraseFromParent();
    }
  }

  void handleDeviceAdd(Module &m) {
    Function *orig = m.getFunction("device_add");
    Function *replace = m.getFunction("__DRVHORN_device_add");
    for (CallInst *call : getCalls(orig)) {
      Value *devPtr = call->getArgOperand(0);
      if (devPtr->getType() != replace->getArg(0)->getType())
        devPtr =
            new BitCastInst(devPtr, replace->getArg(0)->getType(), "", call);
      CallInst *newCall = CallInst::Create(replace, devPtr, "", call);
      call->replaceAllUsesWith(newCall);
      call->dropAllReferences();
      call->eraseFromParent();
    }
  }

  void killDeviceNodeNotify(Module &m) {
    for (CallInst *call : getCalls(m.getFunction("of_property_notify"))) {
      Value *zero = ConstantInt::get(call->getType(), 0);
      call->replaceAllUsesWith(zero);
      call->eraseFromParent();
    }
  }

  void killDeviceDel(Module &m) {
    for (CallInst *call : getCalls(m.getFunction("device_del"))) {
      call->dropAllReferences();
      call->eraseFromParent();
    }
  }
};

char HandleDevices::ID = 0;

Pass *createHandleDevicesPass() { return new HandleDevices(); }
}; // namespace seahorn
