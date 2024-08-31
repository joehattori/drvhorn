#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

#define STORAGE_LIMIT 0x10000

using namespace llvm;

namespace seahorn {
class HandleDevices : public ModulePass {
public:
  static char ID;

  HandleDevices() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    handleDeviceNodeFinders(m);
    handleDeviceFinders(m);
    handleChildNodeFinders(m);
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

  void handleChildNodeFinders(Module &m) {
    StringRef names[] = {"of_get_next_child", "of_get_next_available_child"};
    Function *stub = m.getFunction("__DRVHORN_of_get_next_child");
    for (StringRef name : names) {
      Function *f = m.getFunction(name);
      if (!f)
        continue;
      Value *replacement = stub;
      if (f->getFunctionType() != stub->getFunctionType())
        replacement = ConstantExpr::getBitCast(stub, f->getType());
      f->replaceAllUsesWith(replacement);
      f->eraseFromParent();
    }
  }

  Function *
  deviceGetter(Module &m, CallInst *call,
               DenseMap<StructType *, Function *> &structTypeReplacer) {
    Value *arg = call->getArgOperand(0);
    LLVMContext &ctx = m.getContext();
    for (Value *clsOrBusPtr : getClassOrBusPtrs(arg->stripPointerCasts())) {
      GlobalVariable *gv = nullptr;
      if (LoadInst *load = dyn_cast<LoadInst>(clsOrBusPtr)) {
        gv = dyn_cast<GlobalVariable>(load->getPointerOperand());
      } else {
        gv = dyn_cast<GlobalVariable>(clsOrBusPtr);
      }
      if (!gv) {
        errs() << "unhandled class or bus pointer: " << *clsOrBusPtr << '\n';
        std::exit(1);
      }
      StructType *t = nullptr;
      if (gv->getName().equals("mdio_bus_class")) {
        t = StructType::getTypeByName(ctx, "struct.mii_bus");
      } else if (gv->getName().equals("power_supply_class")) {
        t = StructType::getTypeByName(ctx, "struct.power_supply");
      } else if (gv->getName().equals("net_class")) {
        t = StructType::getTypeByName(ctx, "struct.net_device");
      } else if (gv->getName().equals("mdio_bus_type")) {
        t = StructType::getTypeByName(ctx, "struct.phy_device");
      } else if (gv->getName().equals("platform_bus_type")) {
        t = StructType::getTypeByName(ctx, "struct.platform_device");
      } else if (gv->getName().equals("acpi_bus_type")) {
        t = StructType::getTypeByName(ctx, "struct.acpi_device");
      } else {
        errs() << "unknown class or bus " << *gv << '\n';
        std::exit(1);
      }
      if (structTypeReplacer.count(t))
        return structTypeReplacer[t];
      Optional<SmallVector<size_t>> devIndices = getEmbeddedDeviceIndices(t);
      if (!devIndices.hasValue()) {
        errs() << "surroundingDevType " << *t << " does not embed a device\n";
        std::exit(1);
      }
      Function *f = embeddedDeviceGetter(m, t, *devIndices);
      structTypeReplacer[t] = f;
      return f;
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

  Function *embeddedDeviceGetter(Module &m, StructType *surroundingDevType,
                                 SmallVector<size_t> devIndices) {
    LLVMContext &ctx = m.getContext();
    IntegerType *i32Type = Type::getInt32Ty(ctx);
    IntegerType *i64Type = Type::getInt64Ty(ctx);
    PointerType *kobjPtrType =
        StructType::getTypeByName(ctx, "struct.kobject")->getPointerTo();

    std::string suffix = surroundingDevType->getName().str();
    std::string funcName = "__DRVHORN_embedded_device.getter." + suffix;

    ArrayType *storageType = ArrayType::get(surroundingDevType, STORAGE_LIMIT);
    Constant *storageContent[STORAGE_LIMIT];
    for (size_t i = 0; i < STORAGE_LIMIT; i++) {
      storageContent[i] = Constant::getNullValue(surroundingDevType);
    }
    GlobalVariable *storage = new GlobalVariable(
        m, storageType, false, GlobalValue::LinkageTypes::PrivateLinkage,
        ConstantArray::get(storageType, storageContent), funcName + ".storage");

    GlobalVariable *counter = new GlobalVariable(
        m, i64Type, false, GlobalValue::LinkageTypes::PrivateLinkage,
        ConstantInt::get(i64Type, 0), funcName + ".counter");
    GlobalVariable *kobj = new GlobalVariable(
        m, kobjPtrType, false, GlobalValue::LinkageTypes::PrivateLinkage,
        ConstantPointerNull::get(kobjPtrType), "drvhorn.kobject." + suffix);

    StructType *curType = surroundingDevType;
    for (size_t i : devIndices) {
      curType = cast<StructType>(curType->getElementType(i));
    }
    PointerType *devPtrType = curType->getPointerTo();

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

    SmallVector<Value *> gepIndices(devIndices.size() + 1);
    gepIndices[0] = ConstantInt::get(i64Type, 0);
    for (size_t i = 0; i < devIndices.size(); i++) {
      gepIndices[i + 1] = ConstantInt::get(i32Type, devIndices[i]);
    }
    Value *devPtr =
        b.CreateGEP(surroundingDevType, surroundingDevPtr, gepIndices);
    callWithNecessaryBitCast(m.getFunction("__DRVHORN_setup_device"),
                             {devPtr, kobj}, b);
    callWithNecessaryBitCast(m.getFunction("get_device"), {devPtr}, b);
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    PHINode *phi = b.CreatePHI(devPtrType, 2);
    phi->addIncoming(ConstantPointerNull::get(devPtrType), entry);
    phi->addIncoming(devPtr, body);
    b.CreateRet(phi);

    return getter;
  }

  Value *callWithNecessaryBitCast(Function *f, SmallVector<Value *> args,
                                  IRBuilder<> &b) {
    for (size_t i = 0; i < args.size(); i++) {
      if (args[i]->getType() != f->getArg(i)->getType()) {
        args[i] = b.CreateBitCast(args[i], f->getArg(i)->getType());
      }
    }
    return b.CreateCall(f, args);
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
      Value *newCall = callWithNecessaryBitCast(replace, {devPtr}, b);
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

  Optional<SmallVector<size_t>> getEmbeddedDeviceIndices(const StructType *s) {
    Optional<SmallVector<size_t>> indices = getEmbeddedDeviceReversedIndices(s);
    if (!indices.hasValue())
      return None;
    std::reverse(indices->begin(), indices->end());
    return indices;
  }

  Optional<SmallVector<size_t>>
  getEmbeddedDeviceReversedIndices(const StructType *s) {
    const StructType *deviceType =
        StructType::getTypeByName(s->getContext(), "struct.device");
    for (size_t i = 0; i < s->getNumElements(); i++) {
      const Type *elemType = s->getElementType(i);
      if (equivTypes(elemType, deviceType))
        return SmallVector<size_t>{i};
      if (const StructType *sTy = dyn_cast<StructType>(elemType)) {
        Optional<SmallVector<size_t>> indices =
            getEmbeddedDeviceReversedIndices(sTy);
        if (indices.hasValue()) {
          indices->push_back(i);
          return indices;
        }
      }
    }
    return None;
  }
};

char HandleDevices::ID = 0;

Pass *createHandleDevicesPass() { return new HandleDevices(); }
}; // namespace seahorn
