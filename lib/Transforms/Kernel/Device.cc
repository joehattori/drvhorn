#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
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
    handleChildNodeFinders(m);
    stubOfFunctions(m);
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
        {"of_get_compatible_child", 0},
        {"of_get_child_by_name", 0},
    };
    Function *getter = m.getFunction("drvhorn.get_device_node");
    for (const std::pair<StringRef, Optional<size_t>> &nameAndIndex :
         namesAndDeviceNodeIndices) {
      Function *f = m.getFunction(nameAndIndex.first);
      if (!f)
        continue;
      std::string stubName = "drvhorn." + nameAndIndex.first.str();
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
    StringRef deviceFinderNames[] = {"class_find_device", "bus_find_device"};
    DenseMap<StructType *, Function *> structTypeReplacer;
    DenseMap<const GlobalVariable *, StructType *> clsOrBusToDevType =
        clsOrBusToDeviceMap(m);
    for (StringRef name : deviceFinderNames) {
      Function *finder = m.getFunction(name);
      if (!finder)
        continue;
      for (CallInst *call : getCalls(finder)) {
        if (Function *getter =
                deviceGetter(m, call, structTypeReplacer, clsOrBusToDevType)) {
          Value *newCall = CallInst::Create(getter, "", call);
          if (newCall->getType() != call->getType())
            newCall = new BitCastInst(newCall, call->getType(), "", call);
          call->replaceAllUsesWith(newCall);
          call->eraseFromParent();
        }
      }
    }
  }

  void handleChildNodeFinders(Module &m) {
    StringRef names[] = {"of_get_next_child", "of_get_next_available_child"};
    Function *stub = m.getFunction("drvhorn.of_get_next_child");
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

  bool isEmbeddedStruct(StructType *embedded, StructType *base) {
    SmallVector<StructType *> elements;
    DenseSet<StructType *> visited;
    for (Type *elem : base->elements()) {
      if (StructType *s = dyn_cast<StructType>(elem)) {
        elements.push_back(s);
        visited.insert(s);
      }
    }
    while (!elements.empty()) {
      StructType *elem = elements.pop_back_val();
      if (equivTypes(elem, embedded))
        return true;
      for (Type *e : elem->elements()) {
        if (StructType *s = dyn_cast<StructType>(e)) {
          if (visited.insert(s).second)
            elements.push_back(s);
        }
      }
    }
    return false;
  }

  bool isClsOrBusPtr(Type *type) {
    if (PointerType *ptr = dyn_cast<PointerType>(type)) {
      if (StructType *s = dyn_cast<StructType>(ptr->getElementType()))
        return s->getName().startswith("struct.class.") ||
               s->getName().startswith("struct.bus_type.") ||
               s->getName().equals("struct.class") ||
               s->getName().equals("struct.bus_type");
    }
    return false;
  }

  SmallVector<StructType *> getBaseType(const Value *v) {
    SmallVector<StructType *> res;
    auto recordTypeIfEmbedsDevice = [this, &res](Type *type) {
      if (StructType *s = dyn_cast<StructType>(type)) {
        if (embedsDevice(s))
          res.push_back(s);
      }
    };

    const Value *base = getUnderlyingObject(v);
    if (const CallInst *call = dyn_cast<CallInst>(base)) {
      const Function *f = extractCalledFunction(call);
      if (f->getName().equals("drvhorn.__kmalloc") ||
          f->getName().equals("drvhorn.__kmalloc_node") ||
          f->getName().equals("drvhorn.__kmalloc_node_track_caller") ||
          f->getName().equals("drvhorn.kmalloc_large") ||
          f->getName().equals("drvhorn.kmalloc_trace") ||
          f->getName().equals("drvhorn.kmalloc_large_node") ||
          f->getName().equals("drvhorn.__vmalloc_node_range") ||
          f->getName().equals("drvhorn.slob_alloc") ||
          f->getName().equals("drvhorn.pcpu_alloc")) {
        // guess the actual type for a kmalloc-ish call.
        SmallVector<const User *> workList(call->user_begin(),
                                           call->user_end());

        DenseSet<const User *> visited;
        while (!workList.empty()) {
          const User *user = workList.pop_back_val();
          if (const BitCastOperator *bitcast =
                  dyn_cast<BitCastOperator>(user)) {
            for (const User *u : user->users()) {
              if (visited.insert(u).second)
                workList.push_back(u);
            }
            recordTypeIfEmbedsDevice(
                bitcast->getDestTy()->getPointerElementType());
          } else if (const ReturnInst *ret = dyn_cast<ReturnInst>(user)) {
            Type *retValType =
                ret->getReturnValue()->getType()->getPointerElementType();
            recordTypeIfEmbedsDevice(retValType);
          } else if (const PHINode *phi = dyn_cast<PHINode>(user)) {
            for (const User *u : phi->users()) {
              if (visited.insert(u).second)
                workList.push_back(u);
            }
          } else if (const StoreInst *store = dyn_cast<StoreInst>(user)) {
            Type *valType = store->getValueOperand()->getType();
            if (valType->isPointerTy() &&
                valType->getPointerElementType()->isIntegerTy(8)) {
              const Value *ptr = store->getPointerOperand();
              // %a = bitcast %struct.some_dev** to i8*
              // store i8*, i8** %a
              Type *strippedType = ptr->stripPointerCasts()->getType();
              if (strippedType->isPointerTy() &&
                  strippedType->getPointerElementType()->isPointerTy()) {
                recordTypeIfEmbedsDevice(strippedType->getPointerElementType()
                                             ->getPointerElementType());
              }
            }
          }
        }
      }
    }
    recordTypeIfEmbedsDevice(base->getType()->getPointerElementType());
    return res;
  }

  StructType *getDeviceTypeForClsOrBus(const GlobalVariable *gv, bool isPtr) {
    SmallVector<const User *> clsOrBus;
    if (!isPtr) {
      clsOrBus.push_back(gv);
    } else {
      SmallVector<const User *> workList(gv->users());
      DenseSet<const User *> visitedUsers(gv->user_begin(), gv->user_end());
      while (!workList.empty()) {
        const User *user = workList.pop_back_val();
        if (isa<BitCastOperator>(user)) {
          for (const User *u : user->users()) {
            if (visitedUsers.insert(u).second)
              workList.push_back(u);
          }
        } else if (isa<LoadInst>(user)) {
          clsOrBus.push_back(user);
        }
      }
    }
    DenseSet<const User *> visited;
    SmallVector<const User *> users;
    for (const User *p : clsOrBus) {
      for (const User *u : p->users()) {
        if (visited.insert(u).second)
          users.push_back(u);
      }
    }
    SmallVector<StructType *> baseTypes;
    while (!users.empty()) {
      const User *user = users.pop_back_val();
      if (isa<BitCastOperator>(user)) {
        for (const User *u : user->users()) {
          if (visited.insert(u).second)
            users.push_back(u);
        }
      } else if (const StoreInst *store = dyn_cast<StoreInst>(user)) {
        if (isClsOrBusPtr(store->getValueOperand()->getType())) {
          SmallVector<StructType *> baseType =
              getBaseType(store->getPointerOperand());
          baseTypes.append(baseType.begin(), baseType.end());
        }
      }
    }
    if (baseTypes.empty()) {
      return nullptr;
    }
    StructType *cur = baseTypes[0];
    for (size_t i = 1; i < baseTypes.size(); i++) {
      if (isEmbeddedStruct(cur, baseTypes[i]))
        cur = baseTypes[i];
    }
    return cur;
  }

  DenseMap<const GlobalVariable *, StructType *>
  clsOrBusToDeviceMap(const Module &m) {
    DenseMap<const GlobalVariable *, StructType *> map;
    LLVMContext &ctx = m.getContext();
    StructType *clsType = StructType::getTypeByName(ctx, "struct.class");
    StructType *busType = StructType::getTypeByName(ctx, "struct.bus_type");
    for (const GlobalVariable &gv : m.globals()) {
      Type *type = gv.getValueType();
      bool isPtr = false;
      if (type->isPointerTy()) {
        isPtr = true;
        type = type->getPointerElementType();
      }
      if (equivTypes(type, clsType) || equivTypes(type, busType)) {
        StructType *devType = getDeviceTypeForClsOrBus(&gv, isPtr);
        map[&gv] = devType;
      }
    }
    return map;
  }

  Function *deviceGetter(
      Module &m, CallInst *call,
      DenseMap<StructType *, Function *> &structTypeReplacer,
      const DenseMap<const GlobalVariable *, StructType *> &clsOrBusToDevType) {
    Value *argBase = call->getArgOperand(0)->stripPointerCasts();
    GlobalVariable *gv;
    if (GlobalVariable *g = dyn_cast<GlobalVariable>(argBase)) {
      gv = g;
    } else if (LoadInst *load = dyn_cast<LoadInst>(argBase)) {
      gv = dyn_cast<GlobalVariable>(
          load->getPointerOperand()->stripPointerCasts());
    } else if (Argument *arg = dyn_cast<Argument>(argBase)) {
      return nullptr;
    } else {
      errs() << "TODO: deviceGetter " << *argBase << "\n";
      std::exit(1);
    }
    StructType *deviceType =
        StructType::getTypeByName(m.getContext(), "struct.device");
    StructType *t = clsOrBusToDevType.lookup(gv);
    if (!t) {
      t = deviceType;
    }
    if (Function *f = structTypeReplacer.lookup(t))
      return f;

    if (equivTypes(t, deviceType)) {
      Function *f = rawDeviceGetter(m, t);
      structTypeReplacer[t] = f;
      return f;
    }

    Optional<SmallVector<size_t>> devIndices = getEmbeddedDeviceIndices(t);
    if (!devIndices.hasValue()) {
      errs() << "surroundingDevType " << *t << " does not embed a device\n";
      std::exit(1);
    }
    Function *f = embeddedDeviceGetter(m, t, *devIndices);
    structTypeReplacer[t] = f;
    return f;
  }

  Function *rawDeviceGetter(Module &m, StructType *devType) {
    LLVMContext &ctx = m.getContext();
    Function *krefSetup = m.getFunction("drvhorn.setup_kref");
    PointerType *krefPtrType =
        cast<PointerType>(krefSetup->getArg(0)->getType());
    GlobalVariable *globalKref = new GlobalVariable(
        m, krefPtrType, false, GlobalValue::LinkageTypes::PrivateLinkage,
        ConstantPointerNull::get(krefPtrType), "drvhorn.kref.raw_device");
    PointerType *devPtrType = devType->getPointerTo();
    Function *getter =
        Function::Create(FunctionType::get(devPtrType, false),
                         GlobalValue::LinkageTypes::ExternalLinkage,
                         "drvhorn.device_getter.raw", &m);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", getter);
    BasicBlock *body = BasicBlock::Create(ctx, "body", getter);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", getter);
    IRBuilder<> b(entry);
    Value *ndCond = b.CreateCall(m.getFunction("nd_bool"));
    b.CreateCondBr(ndCond, body, ret);

    b.SetInsertPoint(body);
    Value *devPtr = b.CreateAlloca(devType);
    Value *krefPtr = b.CreateGEP(devType, devPtr,
                                 {ConstantInt::get(Type::getInt64Ty(ctx), 0),
                                  ConstantInt::get(Type::getInt32Ty(ctx), 0),
                                  ConstantInt::get(Type::getInt32Ty(ctx), 6)});
    callWithNecessaryBitCast(krefSetup, {krefPtr, globalKref}, b);
    callWithNecessaryBitCast(m.getFunction("get_device"), {devPtr}, b);
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    PHINode *phi = b.CreatePHI(devPtrType, 2);
    phi->addIncoming(ConstantPointerNull::get(devPtrType), entry);
    phi->addIncoming(devPtr, body);
    b.CreateRet(phi);
    return getter;
  }

  Function *embeddedDeviceGetter(Module &m, StructType *surroundingDevType,
                                 ArrayRef<size_t> devIndices) {
    LLVMContext &ctx = m.getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    Function *krefSetup = m.getFunction("drvhorn.setup_kref");
    PointerType *krefPtrType =
        cast<PointerType>(krefSetup->getArg(0)->getType());

    std::string suffix = surroundingDevType->getName().str();
    std::string funcName = "drvhorn.device_getter.embedded." + suffix;

    GlobalVariable *globalKref = new GlobalVariable(
        m, krefPtrType, false, GlobalValue::LinkageTypes::PrivateLinkage,
        ConstantPointerNull::get(krefPtrType), "drvhorn.kref." + suffix);

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
    b.CreateCondBr(ndCond, body, ret);

    b.SetInsertPoint(body);
    Value *surroundingDevPtr = b.CreateAlloca(surroundingDevType);
    SmallVector<Value *> gepIndices(devIndices.size() + 1);
    gepIndices[0] = ConstantInt::get(i64Ty, 0);
    for (size_t i = 0; i < devIndices.size(); i++) {
      gepIndices[i + 1] = ConstantInt::get(i32Ty, devIndices[i]);
    }
    Value *devPtr =
        b.CreateGEP(surroundingDevType, surroundingDevPtr, gepIndices);
    Value *krefPtr =
        b.CreateGEP(devPtr->getType()->getPointerElementType(), devPtr,
                    {ConstantInt::get(i64Ty, 0), ConstantInt::get(i32Ty, 0),
                     ConstantInt::get(i32Ty, 6)});
    callWithNecessaryBitCast(krefSetup, {krefPtr, globalKref}, b);
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

  void stubOfFunctions(Module &m) {
    StringRef names[] = {
        "of_phandle_iterator_next",
    };
    for (StringRef name : names) {
      Function *origFn = m.getFunction(name);
      if (!origFn)
        continue;
      Constant *newFn = m.getFunction("drvhorn." + name.str());
      if (origFn->getType() != newFn->getType())
        newFn = ConstantExpr::getBitCast(newFn, origFn->getType());
      origFn->replaceAllUsesWith(newFn);
      origFn->eraseFromParent();
    }
  }

  bool embedsDevice(const StructType *s) {
    if (!s)
      return false;
    SmallVector<const StructType *> workList{s};
    DenseSet<const StructType *> visited;
    const StructType *deviceType =
        StructType::getTypeByName(s->getContext(), "struct.device");
    if (equivTypes(s, deviceType))
      return true;
    while (!workList.empty()) {
      const StructType *s = workList.pop_back_val();
      for (const Type *elem : s->elements()) {
        if (const StructType *elemTy = dyn_cast<StructType>(elem)) {
          if (equivTypes(elemTy, deviceType)) {
            return true;
          }
          if (visited.insert(elemTy).second)
            workList.push_back(elemTy);
        }
      }
    }
    return false;
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
