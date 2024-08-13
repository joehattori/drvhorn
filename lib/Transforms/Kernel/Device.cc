#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {
class HandleDevices : public ModulePass {
public:
  static char ID;

  HandleDevices() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    handleDeviceNodeFinders(m);
    handleDeviceFinders(m);
    stubSomeOfFunctions(m);
    handleDeviceAdd(m);
    killDeviceNodeNotify(m);
    killDeviceDel(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "HandleDevices"; }

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
    DenseMap<CallInst *, Value *> toReplace;
    StringRef deviceFinderNames[] = {"class_find_device", "bus_find_device"};
    DenseMap<StructType *, Function *> structTypeReplacer;
    for (StringRef name : deviceFinderNames) {
      Function *finder = m.getFunction(name);
      for (CallInst *call : getCalls(finder)) {
        if (Function *getter = deviceGetter(m, call, structTypeReplacer)) {
          Value *newCall = CallInst::Create(getter, "", call);
          if (newCall->getType() != call->getType())
            newCall = new BitCastInst(newCall, call->getType(), "", call);
          toReplace[call] = newCall;
        }
      }
    }
    for (std::pair<CallInst *, Value *> p : toReplace) {
      p.first->replaceAllUsesWith(p.second);
      p.first->eraseFromParent();
    }
  }

  Function *
  deviceGetter(Module &m, CallInst *call,
               DenseMap<StructType *, Function *> &structTypeReplacer) {
    Value *arg = call->getArgOperand(0);
    for (Value *clsOrBusPtr : getClassOrBusPtrs(arg->stripPointerCasts())) {
      if (StructType *t = getSurroundingDeviceType(clsOrBusPtr)) {
        if (structTypeReplacer.count(t))
          return structTypeReplacer[t];
        Optional<size_t> devIndex = getEmbeddedDeviceIndex(t);
        if (!devIndex.hasValue()) {
          errs() << "surroundingDevType " << *t << " does not embed a device\n";
          std::exit(1);
        }
        Function *f = embeddedDeviceGetter(m, t, *devIndex);
        structTypeReplacer[t] = f;
        return f;
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

  StructType *getSurroundingDeviceType(Value *clsOrBusPtr) {
    auto findSurroundingDeviceType = [](Value *dest) -> StructType * {
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

  Function *embeddedDeviceGetter(Module &m, StructType *surroundingDevType,
                                 size_t devIndex) {
    LLVMContext &ctx = m.getContext();
    IntegerType *i32Type = Type::getInt32Ty(ctx);
    IntegerType *i64Type = Type::getInt64Ty(ctx);
    PointerType *devPtrType =
        surroundingDevType->getElementType(devIndex)->getPointerTo();

    std::string funcName = "__DRVHORN_embedded_device.getter." +
                           surroundingDevType->getName().str();
    static uint64_t STORAGE_LIMIT = 0x10000;
    ArrayType *storageType = ArrayType::get(surroundingDevType, STORAGE_LIMIT);
    GlobalVariable *storage = new GlobalVariable(
        m, storageType, false, GlobalValue::LinkageTypes::ExternalLinkage,
        nullptr, funcName + ".storage");
    GlobalVariable *counter = new GlobalVariable(
        m, i64Type, false, GlobalValue::LinkageTypes::ExternalLinkage, nullptr,
        funcName + ".counter");
    Function *getter = Function::Create(
        FunctionType::get(devPtrType, false),
        GlobalValue::LinkageTypes::ExternalLinkage, funcName, &m);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", getter);
    BasicBlock *body = BasicBlock::Create(ctx, "body", getter);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", getter);

    IRBuilder<> b(entry);
    Value *ndCond = b.CreateCall(m.getFunction("nd_bool"));
    Value *curCount = b.CreateLoad(i64Type, counter);
    Value *limit =
        b.CreateICmpSGE(curCount, ConstantInt::get(i64Type, STORAGE_LIMIT));
    Value *cond = b.CreateOr(ndCond, limit);
    b.CreateCondBr(cond, body, ret);

    b.SetInsertPoint(body);
    Value *newCount = b.CreateAdd(curCount, ConstantInt::get(i64Type, 1));
    Value *surroundingDevPtr = b.CreateGEP(
        storageType, storage, {ConstantInt::get(i64Type, 0), newCount});
    b.CreateStore(newCount, counter);
    Value *devPtr = b.CreateGEP(
        surroundingDevType, surroundingDevPtr,
        {ConstantInt::get(i64Type, 0), ConstantInt::get(i32Type, devIndex)});
    callWithNecessaryBitCast(m.getFunction("__DRVHORN_setup_device"), devPtr,
                             b);
    callWithNecessaryBitCast(m.getFunction("get_device"), devPtr, b);
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    PHINode *phi = b.CreatePHI(devPtrType, 2);
    phi->addIncoming(ConstantPointerNull::get(devPtrType), entry);
    phi->addIncoming(devPtr, body);
    b.CreateRet(phi);

    return getter;
  }

  Value *callWithNecessaryBitCast(Function *f, Value *arg, IRBuilder<> &b) {
    if (arg->getType() != f->getArg(0)->getType()) {
      arg = b.CreateBitCast(arg, f->getArg(0)->getType());
    }
    return b.CreateCall(f, arg);
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

  void stubSomeOfFunctions(Module &m) {
    StringRef names[] = {
        "of_phandle_iterator_next",
    };
    for (StringRef name : names) {
      Function *origFn = m.getFunction(name);
      if (!origFn)
        continue;
      Constant *newFn = m.getFunction("__DRVHORN_" + name.str());
      if (origFn->getType() != newFn->getType())
        newFn = ConstantExpr::getBitCast(newFn, origFn->getType());
      origFn->replaceAllUsesWith(newFn);
      origFn->eraseFromParent();
    }
  }

  void handleDeviceAdd(Module &m) {
    Function *orig = m.getFunction("device_add");
    Function *replace = m.getFunction("__DRVHORN_device_add");
    for (CallInst *call : getCalls(orig)) {
      IRBuilder<> b(call);
      Value *devPtr = call->getArgOperand(0);
      Value *newCall = callWithNecessaryBitCast(replace, devPtr, b);
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
