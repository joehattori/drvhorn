#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

struct ContainerOfVisitor : InstVisitor<ContainerOfVisitor> {
public:
  ContainerOfVisitor(Value *gep, Value *containerOfReplacer)
      : gep(gep), containerOfReplacer(containerOfReplacer) {
    nullContainerOf = Constant::getNullValue(containerOfReplacer->getType());
  }

  void visitICmpInst(ICmpInst &icmp) {
    Value *lhs = icmp.getOperand(0);
    Value *rhs = icmp.getOperand(1);
    if (lhs == gep) {
      lhs = containerOfReplacer;
    } else if (isa<ConstantPointerNull>(lhs)) {
      lhs = nullContainerOf;
    } else {
      errs() << "ContainerOfVisitor: invalid operand" << icmp << "\n";
      std::exit(1);
    }
    if (rhs == gep) {
      rhs = containerOfReplacer;
    } else if (isa<ConstantPointerNull>(rhs)) {
      rhs = nullContainerOf;
    } else {
      errs() << "ContainerOfVisitor: invalid operand" << icmp << "\n";
      std::exit(1);
    }
    ICmpInst *newICmp = new ICmpInst(&icmp, icmp.getPredicate(), lhs, rhs, "");
    icmp.replaceAllUsesWith(newICmp);
    icmp.eraseFromParent();
  }

  void visitBitCastInst(BitCastInst &bitcast) {
    if (bitcast.getDestTy() != containerOfReplacer->getType()) {
      bitcast.replaceUsesOfWith(gep, containerOfReplacer);
    } else {
      bitcast.replaceAllUsesWith(containerOfReplacer);
      bitcast.eraseFromParent();
    }
  }

  void visitStoreInst(StoreInst &store) {
    if (store.getValueOperand() == gep) {
      store.setOperand(0, containerOfReplacer);
      Value *ptr = store.getPointerOperand();
      BitCastInst *bitcast = new BitCastInst(
          ptr, containerOfReplacer->getType()->getPointerTo(), "", &store);
      store.setOperand(1, bitcast);
    }
  }

  void visitInstruction(Instruction &inst) {
    inst.replaceUsesOfWith(gep, containerOfReplacer);
  }

private:
  Value *gep;
  Value *containerOfReplacer;
  Value *nullContainerOf;
};

#define STORAGE_SIZE 256

class HandleDevices : public ModulePass {
public:
  static char ID;

  HandleDevices() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    handleDeviceNodeFinders(m);
    handleFindDevice(m);
    handleDevmAddAction(m);

    stubOfFunctions(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "HandleDevices"; }

private:
  struct StorageGlobals {
    GlobalVariable *storage;
    GlobalVariable *curIndex;
    GlobalVariable *targetIndex;
  };

  void handleDeviceNodeFinders(Module &m) {
    struct FinderInfo {
      StringRef name;
      Optional<size_t> devNodeArgIndex;
      Optional<size_t> returnIfNullArgIndex;
    };
    FinderInfo namesAndDeviceNodeIndices[] = {
        {"of_find_node_opts_by_path", None, None},
        {"of_find_node_by_name", 0, None},
        {"of_find_node_by_type", 0, None},
        {"of_find_compatible_node", 0, None},
        {"of_find_node_by_phandle", None, None},
        {"of_find_matching_node_and_match", 0, None},
        {"of_find_node_with_property", 0, None},
        {"of_get_compatible_child", 0, None},
        {"of_get_child_by_name", 0, None},
        {"of_get_next_child", 1, 0},
        {"of_get_next_available_child", 1, 0},
    };
    LLVMContext &ctx = m.getContext();
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    Function *krefInit = m.getFunction("drvhorn.kref_init");
    Function *krefGet = m.getFunction("drvhorn.kref_get");
    Function *updateIndex = m.getFunction("drvhorn.update_index");
    Function *ofNodePut = m.getFunction("of_node_put");
    StructType *krefType = cast<StructType>(
        krefInit->getArg(0)->getType()->getPointerElementType());
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    for (const FinderInfo &info : namesAndDeviceNodeIndices) {
      Function *f = m.getFunction(info.name);
      if (!f)
        continue;
      f->deleteBody();
      StructType *devNodeType =
          cast<StructType>(f->getReturnType()->getPointerElementType());
      BasicBlock *earlyReturn = info.returnIfNullArgIndex.hasValue()
                                    ? BasicBlock::Create(ctx, "early_return", f)
                                    : nullptr;
      BasicBlock *entry = BasicBlock::Create(ctx, "entry", f);
      BasicBlock *body = BasicBlock::Create(ctx, "body", f);
      BasicBlock *ret = BasicBlock::Create(ctx, "ret", f);
      StorageGlobals globals = getStorageAndIndex(m, devNodeType);
      GlobalVariable *storage = globals.storage;
      GlobalVariable *index = globals.curIndex;
      GlobalVariable *targetIndex = globals.targetIndex;

      IRBuilder<> b(ctx);
      if (earlyReturn) {
        b.SetInsertPoint(earlyReturn);
        Value *cond = b.CreateIsNull(f->getArg(*info.returnIfNullArgIndex));
        b.CreateCondBr(cond, ret, entry);
      }

      b.SetInsertPoint(entry);
      CallInst *ndCond = b.CreateCall(ndBool);
      LoadInst *curIndex = b.CreateLoad(i64Ty, index);
      Value *withinRange =
          b.CreateICmpULT(curIndex, ConstantInt::get(i64Ty, STORAGE_SIZE));
      Value *cond = b.CreateAnd(ndCond, withinRange);
      b.CreateCondBr(cond, body, ret);

      b.SetInsertPoint(body);
      Value *devNode =
          b.CreateInBoundsGEP(storage->getValueType(), storage,
                              {ConstantInt::get(i64Ty, 0), curIndex});
      const SmallVector<unsigned> devIndices(
          indicesToStruct(devNodeType, krefType).getValue());
      SmallVector<Value *> gepIndices;
      gepIndices.push_back(ConstantInt::get(i64Ty, 0));
      for (unsigned i : devIndices) {
        gepIndices.push_back(ConstantInt::get(i32Ty, i));
      }
      Value *krefPtr = b.CreateInBoundsGEP(devNodeType, devNode, gepIndices);
      b.CreateCall(krefInit, krefPtr);
      b.CreateCall(krefGet, krefPtr);
      Value *nxtIndex = b.CreateAdd(curIndex, ConstantInt::get(i64Ty, 1));
      b.CreateStore(nxtIndex, index);
      b.CreateCall(updateIndex, {curIndex, targetIndex});
      b.CreateBr(ret);

      b.SetInsertPoint(ret);
      PHINode *retPhi = b.CreatePHI(f->getReturnType(), 3);
      Constant *null = Constant::getNullValue(devNodeType->getPointerTo());
      retPhi->addIncoming(null, entry);
      retPhi->addIncoming(devNode, body);
      if (earlyReturn) {
        retPhi->addIncoming(null, earlyReturn);
      }
      if (info.devNodeArgIndex.hasValue()) {
        Value *from = f->getArg(info.devNodeArgIndex.getValue());
        if (from->getType() != ofNodePut->getArg(0)->getType())
          from = b.CreateBitCast(from, ofNodePut->getArg(0)->getType());
        b.CreateCall(ofNodePut, {from});
      }
      b.CreateRet(retPhi);
    }
  }

  StorageGlobals getStorageAndIndex(Module &m, StructType *elemType) {
    StringRef suffix = elemType->getName();
    std::string storageName = "drvhorn.storage." + suffix.str();
    std::string indexName = "drvhorn.index." + suffix.str();
    std::string targetIndexName = "drvhorn.target_index." + suffix.str();
    GlobalVariable *storage = m.getGlobalVariable(storageName, true);
    GlobalVariable *index = m.getGlobalVariable(indexName, true);
    GlobalVariable *targetIndex = m.getGlobalVariable(targetIndexName, true);
    if (!storage) {
      ArrayType *storageType = ArrayType::get(elemType, STORAGE_SIZE);
      storage = new GlobalVariable(
          m, storageType, false, GlobalValue::LinkageTypes::PrivateLinkage,
          Constant::getNullValue(storageType), storageName);
      IntegerType *i64Ty = Type::getInt64Ty(m.getContext());
      index = new GlobalVariable(m, i64Ty, false,
                                 GlobalValue::LinkageTypes::PrivateLinkage,
                                 ConstantInt::get(i64Ty, 0), indexName);
      targetIndex = new GlobalVariable(
          m, i64Ty, false, GlobalValue::LinkageTypes::PrivateLinkage,
          ConstantInt::get(i64Ty, -1), targetIndexName);
    }
    return {storage, index, targetIndex};
  }

  void handleDevmAddAction(Module &m) {
    Function *devmAddAction = m.getFunction("__devm_add_action");
    if (!devmAddAction)
      return;
    Function *ndI32Fn = getOrCreateNdIntFn(m, 32);
    LLVMContext &ctx = m.getContext();
    ConstantInt *zero = ConstantInt::get(Type::getInt32Ty(ctx), 0);
    for (CallInst *call : getCalls(devmAddAction)) {
      BasicBlock *orig = call->getParent();
      Function *action =
          dyn_cast<Function>(call->getArgOperand(1)->stripPointerCasts());
      if (!action) {
        errs() << "TODO: 1st argument of __devm_add_action in "
               << call->getFunction()->getName() << " is not Function " << *call
               << "\n";
        continue;
      }
      Value *data = call->getArgOperand(2);
      BasicBlock *next = orig->splitBasicBlock(call, "__devm_add_action.next");
      BranchInst *origBr = cast<BranchInst>(orig->getTerminator());
      BasicBlock *execAction = BasicBlock::Create(
          ctx, "__devm_add_action.exec_action", orig->getParent(), next);

      IRBuilder<> b(origBr);
      Value *res = b.CreateCall(ndI32Fn);
      Value *isZero = b.CreateICmpEQ(res, zero);
      call->replaceAllUsesWith(res);
      BranchInst *br = b.CreateCondBr(isZero, execAction, next);
      origBr->replaceAllUsesWith(br);

      b.SetInsertPoint(execAction);
      if (data->getType() != action->getArg(0)->getType())
        data = b.CreateBitCast(data, action->getArg(0)->getType());
      b.CreateCall(action, data);
      b.CreateBr(next);

      call->eraseFromParent();
      origBr->eraseFromParent();
    }
  }

  void handleFindDevice(Module &m) {
    const DenseMap<const GlobalVariable *, StructType *> &clsOrBusToDevType =
        clsOrBusToDeviceMap(m);
    LLVMContext &ctx = m.getContext();
    StructType *deviceType = StructType::getTypeByName(ctx, "struct.device");
    SmallVector<GetElementPtrInst *> containerOfs;
    DenseMap<CallInst *, Value *> findCallToSurroundingDevPtr;
    for (StringRef name : {"class_find_device", "bus_find_device"}) {
      Function *finder = m.getFunction(name);
      if (!finder)
        continue;
      for (CallInst *call : getCalls(finder)) {
        StructType *surroundingDevType =
            getSurroundingDevType(m, call, clsOrBusToDevType);
        if (!surroundingDevType) {
          surroundingDevType = deviceType;
        }
        const SmallVector<unsigned> devIndices(
            indicesToStruct(surroundingDevType, deviceType).getValue());
        findCallToSurroundingDevPtr[call] =
            insertDeviceGetter(m, call, surroundingDevType, devIndices);
        collectContainersOfs(call, containerOfs);
      }
    }
    replaceContainerOfs(containerOfs, findCallToSurroundingDevPtr);
  }

  void collectContainersOfs(CallInst *call,
                            SmallVector<GetElementPtrInst *> &containerOfs) {
    SmallVector<User *> users(call->user_begin(), call->user_end());
    DenseSet<User *> visited;
    while (!users.empty()) {
      User *user = users.pop_back_val();
      if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(user)) {
        if (const ConstantInt *c = dyn_cast<ConstantInt>(gep->getOperand(1))) {
          if (c->isNegative())
            containerOfs.push_back(gep);
        }
      } else if (PHINode *phi = dyn_cast<PHINode>(user)) {
        for (User *u : phi->users()) {
          if (visited.insert(u).second)
            users.push_back(u);
        }
      }
    }
  }

  bool isEmbeddedStruct(const StructType *embedded, const StructType *base) {
    SmallVector<StructType *> workList;
    DenseSet<StructType *> visited;
    for (Type *elem : base->elements()) {
      if (StructType *s = dyn_cast<StructType>(elem)) {
        workList.push_back(s);
        visited.insert(s);
      }
    }
    while (!workList.empty()) {
      StructType *elem = workList.pop_back_val();
      if (equivTypes(elem, embedded))
        return true;
      for (Type *e : elem->elements()) {
        if (StructType *s = dyn_cast<StructType>(e)) {
          if (visited.insert(s).second)
            workList.push_back(s);
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
    const StructType *deviceType =
        StructType::getTypeByName(v->getContext(), "struct.device");
    auto recordTypeIfEmbedsDevice = [this, &res, deviceType](Type *type) {
      if (StructType *s = dyn_cast<StructType>(type)) {
        if (isEmbeddedStruct(deviceType, s))
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

  StructType *getSurroundingDevType(
      Module &m, CallInst *call,
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
      errs() << "TODO: getSurroundingDevTyps " << *argBase << "\n";
      std::exit(1);
    }
    return clsOrBusToDevType.lookup(gv);
  }

  // returns a pointer to the surrounding device.
  Value *insertDeviceGetter(Module &m, CallInst *call,
                            StructType *surroundingDevType,
                            const SmallVector<unsigned> &devIndices) {
    LLVMContext &ctx = m.getContext();
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    BasicBlock *origBlk = call->getParent();
    BasicBlock *nxtBlk = origBlk->splitBasicBlock(call, "device_getter.after");
    BasicBlock *genBlk = BasicBlock::Create(ctx, "device_getter.gen",
                                            origBlk->getParent(), nxtBlk);
    StorageGlobals globals = getStorageAndIndex(m, surroundingDevType);
    GlobalVariable *storage = globals.storage;
    GlobalVariable *index = globals.curIndex;
    GlobalVariable *targetIndex = globals.targetIndex;

    Instruction *term = origBlk->getTerminator();
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    Function *krefInit = m.getFunction("drvhorn.kref_init");
    Function *krefGet = m.getFunction("drvhorn.kref_get");
    Function *updateIndex = m.getFunction("drvhorn.update_index");

    IRBuilder<> b(term);
    CallInst *ndCond = b.CreateCall(ndBool);
    LoadInst *curIndex = b.CreateLoad(i64Ty, index);
    Value *surroundingDevPtr =
        b.CreateInBoundsGEP(storage->getValueType(), storage,
                            {ConstantInt::get(i64Ty, 0), curIndex});
    Value *withinRange =
        b.CreateICmpULT(curIndex, ConstantInt::get(i64Ty, STORAGE_SIZE));
    Value *cond = b.CreateAnd(ndCond, withinRange);
    b.CreateCondBr(cond, genBlk, nxtBlk);
    term->eraseFromParent();

    b.SetInsertPoint(genBlk);
    SmallVector<Value *> gepIndices;
    gepIndices.push_back(ConstantInt::get(i64Ty, 0));
    for (unsigned i : devIndices) {
      gepIndices.push_back(ConstantInt::get(i32Ty, i));
    }
    Value *devPtr =
        b.CreateInBoundsGEP(surroundingDevType, surroundingDevPtr, gepIndices);
    Value *krefPtr = b.CreateInBoundsGEP(
        devPtr->getType()->getPointerElementType(), devPtr,
        {ConstantInt::get(i64Ty, 0), ConstantInt::get(i32Ty, 0),
         ConstantInt::get(i32Ty, 6)});
    b.CreateCall(krefInit, krefPtr);
    b.CreateCall(krefGet, krefPtr);
    if (call->getType() != devPtr->getType())
      devPtr = b.CreateBitCast(devPtr, call->getType());
    Value *nxtIndex = b.CreateAdd(curIndex, ConstantInt::get(i64Ty, 1));
    b.CreateStore(nxtIndex, index);
    b.CreateCall(updateIndex, {curIndex, targetIndex});
    b.CreateBr(nxtBlk);

    b.SetInsertPoint(call);
    Type *devPtrType = devPtr->getType();
    PHINode *callReplacer = b.CreatePHI(devPtrType, 2);
    callReplacer->addIncoming(Constant::getNullValue(devPtrType), origBlk);
    callReplacer->addIncoming(devPtr, genBlk);
    call->replaceAllUsesWith(callReplacer);
    call->eraseFromParent();
    return surroundingDevPtr;
  }

  void replaceContainerOfs(
      ArrayRef<GetElementPtrInst *> containerOfs,
      const DenseMap<CallInst *, Value *> &findCallToSurroundingDevPtr) {

    auto replace = [findCallToSurroundingDevPtr](CallInst *call,
                                                 GetElementPtrInst *gep) {
      Value *surroundingDevPtr = findCallToSurroundingDevPtr.lookup(call);
      if (!surroundingDevPtr) {
        errs() << "replaceContainerOfs: no surroundingDevPtr for " << *call
               << "\n";
        std::exit(1);
      }
      ContainerOfVisitor replacer(gep, surroundingDevPtr);
      SmallVector<User *> users(gep->user_begin(), gep->user_end());
      for (User *user : users) {
        if (Instruction *inst = dyn_cast<Instruction>(user)) {
          replacer.visit(inst);
        }
      }
    };

    for (GetElementPtrInst *gep : containerOfs) {
      Value *v = getUnderlyingObject(gep);
      if (CallInst *call = dyn_cast<CallInst>(v)) {
        replace(call, gep);
      } else if (PHINode *phi = dyn_cast<PHINode>(v)) {
        for (Value *v : phi->incoming_values()) {
          if (CallInst *call = dyn_cast<CallInst>(v)) {
            replace(call, gep);
          } else if (!isa<Constant>(v)) {
            errs() << "replaceContainerOfs: unexpected PHINode " << *phi
                   << "\n";
            std::exit(1);
          }
        }
      } else {
        errs() << "replaceContainerOfs: unexpected container_of " << *v << "\n";
        std::exit(1);
      }
      gep->eraseFromParent();
    }
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
};

char HandleDevices::ID = 0;

Pass *createHandleDevicesPass() { return new HandleDevices(); }
}; // namespace seahorn
