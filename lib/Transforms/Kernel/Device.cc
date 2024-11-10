#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/Pass.h"

#include "seahorn/Analysis/SeaBuiltinsInfo.hh"
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

struct DeviceGEPGetter
    : InstVisitor<DeviceGEPGetter, Optional<SmallVector<uint64_t>>> {
public:
  DeviceGEPGetter(Function *devInit) : devInit(devInit) {}

  Optional<SmallVector<uint64_t>> getGEPIndices(CallInst *allocCall) {
    visited.insert(allocCall);
    prev = allocCall;
    for (User *user : allocCall->users()) {
      if (Optional<SmallVector<uint64_t>> res = visitUser(user)) {
        return res;
      }
    }
    return None;
  }

  Optional<SmallVector<uint64_t>>
  visitGetElementPtrInst(GetElementPtrInst &gep) {
    SmallVector<uint64_t> indices;
    for (Value *idx : gep.indices()) {
      if (ConstantInt *cidx = dyn_cast<ConstantInt>(idx)) {
        indices.push_back(cidx->getZExtValue());
      } else {
        return None;
      }
    }
    for (User *user : gep.users()) {
      if (Optional<SmallVector<uint64_t>> res = visitUser(user)) {
        indices.append(*res);
        return indices;
      }
    }
    return None;
  }

  Optional<SmallVector<uint64_t>> visitBitCastInst(BitCastInst &bitcast) {
    for (User *user : bitcast.users()) {
      if (Optional<SmallVector<uint64_t>> res = visitUser(user)) {
        return res;
      }
    }
    return None;
  }

  Optional<SmallVector<uint64_t>> visitCallInst(CallInst &call) {
    Function *f = extractCalledFunction(call);
    if (!f)
      return None;
    if (f == devInit) {
      return SmallVector<uint64_t>{};
    }
    User *argUser = prev;
    for (unsigned i = 0; i < call.arg_size(); i++) {
      if (call.getArgOperand(i) == argUser) {
        if (Optional<SmallVector<uint64_t>> res = visitArg(f->getArg(i)))
          return res;
        break;
      }
    }
    return None;
  }

  Optional<SmallVector<uint64_t>> visitInstruction(Instruction &inst) {
    return None;
  }

private:
  Function *devInit;
  DenseSet<const User *> visited;
  User *prev;

  Optional<SmallVector<uint64_t>> visitArg(Argument *arg) {
    for (User *user : arg->users()) {
      if (Optional<SmallVector<uint64_t>> res = visitUser(user))
        return res;
    }
    return None;
  }

  Optional<SmallVector<uint64_t>> visitUser(User *user) {
    if (!visited.insert(user).second)
      return None;
    prev = user;
    if (Instruction *inst = dyn_cast<Instruction>(user)) {
      return visit(inst);
    } else {
      for (User *u : user->users()) {
        if (Optional<SmallVector<uint64_t>> res = visitUser(u)) {
          return res;
        }
      }
      return None;
    }
  }
};

#define STORAGE_SIZE 256

class HandleDevices : public ModulePass {
public:
  static char ID;

  HandleDevices() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    Function *devNodeGetter = handleDeviceNodeFinders(m);
    handleFwnodePut(m);
    handleFwnodeFinders(m, devNodeGetter);
    handleFindDevice(m);
    handleDevmAddAction(m);
    handleDeviceLinkAdd(m);
    Function *devInit = handleDeviceInitialize(m);
    handleDeviceAllocation(m, devInit);
    // handleDevresAlloc(m);

    handleOfParsePhandleWithArgs(m, devNodeGetter);

    stubFwnodeConnectionFindMatch(m);
    stubFwnodeConnectionFindMatches(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "HandleDevices"; }

  void getAnalysisUsage(AnalysisUsage &au) const override {
    au.addRequired<SeaBuiltinsInfoWrapperPass>();
    au.setPreservesAll();
  }

private:
  struct StorageGlobals {
    GlobalVariable *storage;
    GlobalVariable *curIndex;
    GlobalVariable *targetIndex;
  };

  // returns the device node generator function
  Function *handleDeviceNodeFinders(Module &m) {
    struct FinderInfo {
      StringRef name;
      Optional<size_t> putNodeIndex;
      Optional<size_t> returnIfNullArgIndex;
    };
    FinderInfo finders[] = {
        {"of_find_node_opts_by_path", None, None},
        {"of_find_node_by_name", 0, None},
        {"of_find_node_by_type", 0, None},
        {"of_find_compatible_node", 0, None},
        {"of_find_node_by_phandle", None, None},
        {"of_find_matching_node_and_match", 0, None},
        {"of_find_node_with_property", 0, None},
        {"of_get_compatible_child", None, 0},
        {"of_get_child_by_name", None, 0},
        {"of_get_next_child", 1, 0},
        {"of_get_next_available_child", 1, 0},
    };

    auto getDeviceNodeType = [finders, &m]() -> StructType * {
      for (const FinderInfo &info : finders) {
        if (const Function *f = m.getFunction(info.name))
          return cast<StructType>(f->getReturnType()->getPointerElementType());
      }
      return nullptr;
    };

    LLVMContext &ctx = m.getContext();
    Constant *ofNodeGet = m.getFunction("of_node_get");
    Function *ofNodePut = m.getFunction("of_node_put");
    StructType *devNodeType = getDeviceNodeType();
    Function *deviceNodeGetter = buildDeviceNodeGetter(m, devNodeType);
    for (const FinderInfo &info : finders) {
      Function *f = m.getFunction(info.name);
      if (!f)
        continue;
      f->deleteBody();
      BasicBlock *earlyReturn = info.returnIfNullArgIndex.hasValue()
                                    ? BasicBlock::Create(ctx, "early_return", f)
                                    : nullptr;
      BasicBlock *body = BasicBlock::Create(ctx, "body", f);
      BasicBlock *ret = BasicBlock::Create(ctx, "ret", f);

      IRBuilder<> b(ctx);
      if (earlyReturn) {
        b.SetInsertPoint(earlyReturn);
        Value *cond = b.CreateIsNull(f->getArg(*info.returnIfNullArgIndex));
        b.CreateCondBr(cond, ret, body);
      }

      b.SetInsertPoint(body);
      Value *devNode = b.CreateCall(deviceNodeGetter);
      FunctionType *ofNodeGetType = FunctionType::get(
          devNodeType->getPointerTo(), devNodeType->getPointerTo(), false);
      if (ofNodeGet->getType() != ofNodeGetType->getPointerTo())
        ofNodeGet =
            ConstantExpr::getBitCast(ofNodeGet, ofNodeGetType->getPointerTo());
      b.CreateCall(ofNodeGetType, ofNodeGet, devNode);
      b.CreateBr(ret);

      b.SetInsertPoint(ret);
      PHINode *retPhi = b.CreatePHI(devNodeType->getPointerTo(), 2);
      retPhi->addIncoming(devNode, body);
      if (earlyReturn) {
        Constant *null = ConstantPointerNull::get(devNodeType->getPointerTo());
        retPhi->addIncoming(null, earlyReturn);
      }
      if (info.putNodeIndex.hasValue()) {
        Value *from = f->getArg(info.putNodeIndex.getValue());
        if (from->getType() != ofNodePut->getArg(0)->getType())
          from = b.CreateBitCast(from, ofNodePut->getArg(0)->getType());
        b.CreateCall(ofNodePut, from);
      }
      b.CreateRet(retPhi);
    }
    return deviceNodeGetter;
  }

  Function *buildDeviceNodeGetter(Module &m, StructType *devNodeType) {
    Function *krefInit = m.getFunction("drvhorn.kref_init");
    StructType *krefType = cast<StructType>(
        krefInit->getArg(0)->getType()->getPointerElementType());
    Function *updateIndex = m.getFunction("drvhorn.update_index");
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    Function *f = Function::Create(
        FunctionType::get(devNodeType->getPointerTo(), false),
        GlobalValue::PrivateLinkage, "drvhorn.gen_device_node", &m);
    StorageGlobals globals =
        getStorageAndIndex(m, devNodeType, devNodeType->getName().str());
    GlobalVariable *storage = globals.storage;
    GlobalVariable *index = globals.curIndex;
    GlobalVariable *targetIndex = globals.targetIndex;

    LLVMContext &ctx = m.getContext();
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", f);
    BasicBlock *body = BasicBlock::Create(ctx, "body", f);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", f);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);

    IRBuilder<> b(entry);
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
    Value *krefPtr = b.CreateInBoundsGEP(
        devNodeType, devNode,
        gepIndicesToStruct(devNodeType, krefType).getValue());
    b.CreateCall(krefInit, krefPtr);
    Value *nxtIndex = b.CreateAdd(curIndex, ConstantInt::get(i64Ty, 1));
    b.CreateStore(nxtIndex, index);
    b.CreateCall(updateIndex, {curIndex, targetIndex});
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    PHINode *retPhi = b.CreatePHI(devNodeType->getPointerTo(), 2);
    Constant *null = ConstantPointerNull::get(devNodeType->getPointerTo());
    retPhi->addIncoming(null, entry);
    retPhi->addIncoming(devNode, body);
    b.CreateRet(retPhi);

    return f;
  }

#define DEVNODE_FWNODE_INDEX 3
  void handleFwnodePut(Module &m) {
    Function *f = m.getFunction("fwnode_handle_put");
    if (!f)
      return;
    f->deleteBody();
    f->setName("drvhorn.fwnode_put");
    Argument *fwnode = f->getArg(0);
    LLVMContext &ctx = m.getContext();
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", f);
    BasicBlock *body = BasicBlock::Create(ctx, "body", f);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", f);
    Function *ofNodePut = m.getFunction("of_node_put");
    StructType *devNodeType = cast<StructType>(
        ofNodePut->getArg(0)->getType()->getPointerElementType());
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    IntegerType *i32Ty = Type::getInt32Ty(ctx);

    IRBuilder<> b(entry);
    Value *isNull = b.CreateIsNull(fwnode);
    b.CreateCondBr(isNull, ret, body);

    b.SetInsertPoint(body);
    // to_of_node() was translated to something like this:
    //   getelementptr %struct.fwnode_handle, %struct.fwnode_handle* %0, i64 -1,
    //   i32 4
    Value *devNode =
        b.CreateGEP(fwnode->getType()->getPointerElementType(), fwnode,
                    {ConstantInt::get(i64Ty, -1), ConstantInt::get(i32Ty, 4)});
    devNode = b.CreateBitCast(devNode, devNodeType->getPointerTo());
    b.CreateCall(ofNodePut, devNode);
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    b.CreateRetVoid();
  }

  void handleFwnodeFinders(Module &m, Function *devNodeGetter) {
    struct FinderInfo {
      StringRef name;
      Optional<unsigned> putIndex;
    };

    FinderInfo finders[] = {
        {"fwnode_find_reference", None},
        {"fwnode_get_parent", None},
        {"fwnode_get_next_parent", 0},
        {"fwnode_get_nth_parent", 0},
        {"fwnode_get_next_child_node", 1},
        {"fwnode_get_next_available_child_node", 1},
        {"device_get_next_child_node", 1},
        {"fwnode_get_named_child_node", None},
        {"device_get_named_child_node", None},
        {"fwnode_handle_get", None},
        {"fwnode_graph_get_next_endpoint", 1},
        {"fwnode_graph_get_port_parent", None},
        {"fwnode_graph_get_remote_port_parent", None},
        {"fwnode_graph_get_remote_port", None},
        {"fwnode_graph_get_remote_endpoint", None},
        {"fwnode_graph_get_endpoint_by_id", None},
    };
    LLVMContext &ctx = m.getContext();
    Function *putter = m.getFunction("drvhorn.fwnode_put");
    Type *devNodePtrType = devNodeGetter->getReturnType();
    FunctionType *ofNodeGetType =
        FunctionType::get(devNodePtrType, devNodePtrType, false);
    Constant *ofNodeGet = m.getFunction("of_node_get");
    Constant *ofNodeGetCasted =
        ConstantExpr::getBitCast(ofNodeGet, ofNodeGetType->getPointerTo());
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    IntegerType *i32Ty = Type::getInt32Ty(ctx);

    for (const FinderInfo &info : finders) {
      Function *f = m.getFunction(info.name);
      if (!f)
        continue;
      f->deleteBody();
      f->setName("drvhorn.fwnode_getter." + info.name);

      BasicBlock *entry = BasicBlock::Create(ctx, "entry", f);
      BasicBlock *body = BasicBlock::Create(ctx, "body", f);
      BasicBlock *ret = BasicBlock::Create(ctx, "ret", f);

      IRBuilder<> b(entry);
      if (info.putIndex.hasValue()) {
        Value *prev = f->getArg(*info.putIndex);
        if (putter->getArg(0)->getType() != prev->getType())
          prev = b.CreateBitCast(prev, putter->getArg(0)->getType());
        b.CreateCall(putter, prev);
      }
      Value *devNode = b.CreateCall(devNodeGetter);
      Value *isNull = b.CreateIsNull(devNode);
      b.CreateCondBr(isNull, ret, body);

      b.SetInsertPoint(body);
      b.CreateCall(ofNodeGetType, ofNodeGetCasted, devNode);
      Value *fwnode =
          b.CreateInBoundsGEP(devNodePtrType->getPointerElementType(), devNode,
                              {
                                  ConstantInt::get(i64Ty, 0),
                                  ConstantInt::get(i32Ty, DEVNODE_FWNODE_INDEX),
                              });
      b.CreateBr(ret);

      b.SetInsertPoint(ret);
      PHINode *retPhi = b.CreatePHI(fwnode->getType(), 2);
      Constant *null = Constant::getNullValue(fwnode->getType());
      retPhi->addIncoming(null, entry);
      retPhi->addIncoming(fwnode, body);
      if (retPhi->getType() == f->getReturnType())
        b.CreateRet(retPhi);
      else
        b.CreateRet(b.CreateBitCast(retPhi, f->getReturnType()));
    }
  }

  StorageGlobals getStorageAndIndex(Module &m, Type *elemType,
                                    std::string suffix) {
    std::string storageName = "drvhorn.storage." + suffix;
    std::string indexName = "drvhorn.index." + suffix;
    std::string targetIndexName = "drvhorn.target_index." + suffix;
    GlobalVariable *storage = m.getGlobalVariable(storageName, true);
    GlobalVariable *index = m.getGlobalVariable(indexName, true);
    GlobalVariable *targetIndex = m.getGlobalVariable(targetIndexName, true);
    if (!storage) {
      ArrayType *storageType = ArrayType::get(elemType, STORAGE_SIZE);
      storage =
          new GlobalVariable(m, storageType, false, GlobalValue::PrivateLinkage,
                             Constant::getNullValue(storageType), storageName);
      IntegerType *i64Ty = Type::getInt64Ty(m.getContext());
      index = new GlobalVariable(m, i64Ty, false, GlobalValue::PrivateLinkage,
                                 ConstantInt::get(i64Ty, 0), indexName);
      targetIndex =
          new GlobalVariable(m, i64Ty, false, GlobalValue::PrivateLinkage,
                             ConstantInt::get(i64Ty, -1), targetIndexName);
    }
    return {storage, index, targetIndex};
  }

  void handleDevmAddAction(Module &m) {
    Function *devmAddAction = m.getFunction("__devm_add_action");
    if (!devmAddAction)
      return;
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    LLVMContext &ctx = m.getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    ConstantInt *zero = ConstantInt::get(i32Ty, 0);
    ConstantInt *enomem = ConstantInt::get(i32Ty, -12);
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
      BasicBlock *next =
          orig->splitBasicBlock(call->getNextNode(), "__devm_add_action.next");
      Instruction *origBr = orig->getTerminator();
      BasicBlock *execAction = BasicBlock::Create(ctx, "__devm_add_action.exec",
                                                  orig->getParent(), next);

      IRBuilder<> b(orig);
      Value *isZero = b.CreateCall(ndBool);
      // __devm_add_action returns 0 or -ENOMEM
      Value *res = b.CreateSelect(isZero, zero, enomem);
      call->replaceAllUsesWith(res);
      b.CreateCondBr(isZero, execAction, next);
      origBr->eraseFromParent();

      b.SetInsertPoint(execAction);
      Value *data = call->getArgOperand(2);
      if (data->getType() != action->getArg(0)->getType())
        data = b.CreateBitCast(data, action->getArg(0)->getType());
      b.CreateCall(action, data);
      b.CreateBr(next);

      call->eraseFromParent();
    }
  }

#define DL_FLAG_AUTOREMOVE_SUPPLIER (1 << 4)
#define DL_FLAG_AUTOPROBE_CONSUMER (1 << 5)
  void handleDeviceLinkAdd(Module &m) {
    auto isAutoremove = [](CallInst *devLinkAddCall) -> bool {
      ConstantInt *flags =
          dyn_cast<ConstantInt>(devLinkAddCall->getArgOperand(2));
      if (!flags)
        return false;
      return flags->getZExtValue() &
             (DL_FLAG_AUTOREMOVE_SUPPLIER | DL_FLAG_AUTOPROBE_CONSUMER);
    };

    Function *f = m.getFunction("device_link_add");
    if (!f)
      return;
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    for (CallInst *call : getCalls(f)) {
      if (!isAutoremove(call))
        continue;
      SmallVector<ICmpInst *, 8> icmps;
      for (User *user : call->users()) {
        if (ICmpInst *icmp = dyn_cast<ICmpInst>(user)) {
          icmps.push_back(icmp);
        } else {
          errs() << "The result of device_link_add with a autoremove flag "
                    "should only be used in a null check\n";
          errs() << "user in " << call->getFunction()->getName() << *user
                 << "\n";
          std::exit(1);
        }
      }
      Value *ndCond =
          CallInst::Create(ndBool, {}, "device_link_add.result", call);
      for (ICmpInst *icmp : icmps) {
        icmp->replaceAllUsesWith(ndCond);
        icmp->eraseFromParent();
      }
      call->eraseFromParent();
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
        const SmallVector<Value *> &devIndices =
            gepIndicesToStruct(surroundingDevType, deviceType).getValue();
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
    auto recordTypeIfEmbedsDevice = [&res, deviceType](Type *type) {
      if (StructType *s = dyn_cast<StructType>(type)) {
        if (embedsStruct(s, deviceType))
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
      if (embedsStruct(baseTypes[i], cur)) {
        cur = baseTypes[i];
      }
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
  Value *insertDeviceGetter(Module &m, CallInst *finderCall,
                            StructType *surroundingDevType,
                            const SmallVector<Value *> &devIndices) {
    LLVMContext &ctx = m.getContext();
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    BasicBlock *origBlk = finderCall->getParent();
    BasicBlock *nxtBlk =
        origBlk->splitBasicBlock(finderCall, "device_getter.after");
    BasicBlock *genBlk = BasicBlock::Create(ctx, "device_getter.gen",
                                            origBlk->getParent(), nxtBlk);
    StorageGlobals globals = getStorageAndIndex(
        m, surroundingDevType, surroundingDevType->getName().str());
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
    Value *devPtr =
        b.CreateInBoundsGEP(surroundingDevType, surroundingDevPtr, devIndices);
    Value *krefPtr = b.CreateInBoundsGEP(
        devPtr->getType()->getPointerElementType(), devPtr,
        {ConstantInt::get(i64Ty, 0), ConstantInt::get(i32Ty, 0),
         ConstantInt::get(i32Ty, 6)});
    b.CreateCall(krefInit, krefPtr);
    b.CreateCall(krefGet, krefPtr);
    if (finderCall->getType() != devPtr->getType())
      devPtr = b.CreateBitCast(devPtr, finderCall->getType());
    Value *nxtIndex = b.CreateAdd(curIndex, ConstantInt::get(i64Ty, 1));
    b.CreateStore(nxtIndex, index);
    b.CreateCall(updateIndex, {curIndex, targetIndex});
    b.CreateBr(nxtBlk);

    b.SetInsertPoint(finderCall);
    Type *devPtrType = devPtr->getType();
    PHINode *callReplacer = b.CreatePHI(devPtrType, 2);
    callReplacer->addIncoming(Constant::getNullValue(devPtrType), origBlk);
    callReplacer->addIncoming(devPtr, genBlk);
    finderCall->replaceAllUsesWith(callReplacer);
    finderCall->eraseFromParent();
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

  Function *handleDeviceInitialize(Module &m) {
    Function *f = m.getFunction("device_initialize");
    if (!f)
      return nullptr;
    f->deleteBody();
    f->setName("drvhorn.device_initialize");
    LLVMContext &ctx = m.getContext();
    Function *krefInit = m.getFunction("drvhorn.kref_init");
    Function *krefGet = m.getFunction("drvhorn.kref_get");
    StructType *krefType = cast<StructType>(
        krefInit->getArg(0)->getType()->getPointerElementType());
    Argument *dev = f->getArg(0);
    StructType *devType =
        cast<StructType>(dev->getType()->getPointerElementType());
    BasicBlock *blk = BasicBlock::Create(ctx, "blk", f);
    IRBuilder<> b(blk);
    Value *krefGEP = b.CreateInBoundsGEP(
        devType, dev, gepIndicesToStruct(devType, krefType).getValue());
    b.CreateCall(krefInit, krefGEP);
    b.CreateCall(krefGet, krefGEP);
    b.CreateRetVoid();
    return f;
  }

  void handleDeviceAllocation(Module &m, Function *devInit) {
    if (!devInit)
      return;
    Function *alloc = m.getFunction("drvhorn.alloc");
    for (CallInst *call : getCalls(alloc)) {
      DeviceGEPGetter getter(devInit);
      Optional<SmallVector<uint64_t>> indices = getter.getGEPIndices(call);
      ConstantInt *sizeArg = dyn_cast<ConstantInt>(call->getArgOperand(0));
      if (!indices.hasValue() || !sizeArg)
        continue;
      uint64_t size = sizeArg->getZExtValue();
      StructType *allocatedDevType = getCustomDevType(m, size, *indices);
      if (!allocatedDevType)
        continue;
      Function *devAlloc = getOrCreateDeviceAllocator(
          m, allocatedDevType, allocatedDevType->getName().str());
      IRBuilder<> b(call);
      CallInst *newCall = b.CreateCall(devAlloc);
      Value *replace = b.CreateBitCast(newCall, call->getType());
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleDevresAlloc(Module &m) {
    Function *f = m.getFunction("__devres_alloc_node");
    if (!f)
      return;
    LLVMContext &ctx = m.getContext();
    Attribute attr = Attribute::get(ctx, "devres_release");
    for (CallInst *call : getCalls(f)) {
      Function *releaseFn =
          cast<Function>(call->getArgOperand(0)->stripPointerCasts());
      releaseFn->setLinkage(GlobalVariable::ExternalLinkage);
      releaseFn->addFnAttr(attr);
      ConstantInt *sizeArg = dyn_cast<ConstantInt>(call->getArgOperand(1));
      if (!sizeArg)
        continue;
      uint64_t size = sizeArg->getZExtValue();
      std::string suffix = "devres_alloc." + std::to_string(size);
      std::string fnName = "drvhorn.devres_alloc." + std::to_string(size);
      // Function *devAlloc = getOrCreateDeviceAllocator(m, size, fnName,
      // suffix); IRBuilder<> b(call); Value *newCall = b.CreateCall(devAlloc);
      // call->replaceAllUsesWith(newCall);
      // call->eraseFromParent();
    }
  }

  StructType *getCustomDevType(Module &m, uint64_t size,
                               const SmallVector<uint64_t> &devIndices) {
    DataLayout dl(&m);
    LLVMContext &ctx = m.getContext();
    StructType *devType = StructType::getTypeByName(ctx, "struct.device");
    for (StructType *st : m.getIdentifiedStructTypes()) {
      if (dl.getTypeAllocSize(st) != size)
        continue;
      if (hasDeviceAtIndices(st, devIndices, devType))
        return st;
    }
    return nullptr;
  }

  bool hasDeviceAtIndices(StructType *st, const SmallVector<uint64_t> &indices,
                          StructType *devType) {
    for (uint64_t index : indices) {
      if (st->getNumElements() <= index)
        return false;
      st = dyn_cast<StructType>(st->getElementType(index));
      if (!st)
        return false;
    }
    return equivTypes(st, devType);
  }

  Function *getOrCreateDeviceAllocator(Module &m, StructType *elemType,
                                       std::string suffix) {
    std::string fnName = "drvhorn.device_alloc." + suffix;
    if (Function *f = m.getFunction(fnName))
      return f;
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    Function *updateIndex = m.getFunction("drvhorn.update_index");
    LLVMContext &ctx = m.getContext();
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    StorageGlobals globals = getStorageAndIndex(m, elemType, suffix);
    GlobalVariable *storage = globals.storage;
    GlobalVariable *curIndex = globals.curIndex;
    GlobalVariable *targetIndex = globals.targetIndex;
    Function *f =
        Function::Create(FunctionType::get(elemType->getPointerTo(), false),
                         GlobalValue::InternalLinkage, fnName, m);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", f);
    BasicBlock *body = BasicBlock::Create(ctx, "body", f);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", f);

    IRBuilder<> b(entry);
    CallInst *ndCond = b.CreateCall(ndBool);
    LoadInst *index = b.CreateLoad(i64Ty, curIndex);
    Value *elemPtr = b.CreateInBoundsGEP(storage->getValueType(), storage,
                                         {ConstantInt::get(i64Ty, 0), index});
    Value *withinRange =
        b.CreateICmpULT(curIndex, ConstantInt::get(i64Ty, STORAGE_SIZE));
    Value *cond = b.CreateAnd(ndCond, withinRange);
    b.CreateCondBr(cond, body, ret);

    b.SetInsertPoint(body);
    Value *nxtIndex = b.CreateAdd(index, ConstantInt::get(i64Ty, 1));
    b.CreateStore(nxtIndex, curIndex);
    b.CreateCall(updateIndex, {index, targetIndex});
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    PHINode *retPhi = b.CreatePHI(elemType->getPointerTo(), 2);
    retPhi->addIncoming(Constant::getNullValue(elemType->getPointerTo()),
                        entry);
    retPhi->addIncoming(elemPtr, body);
    b.CreateRet(retPhi);
    return f;
  }

#define OF_PHANDLE_ARG_DEVNODE_INDEX 0
  void handleOfParsePhandleWithArgs(Module &m, Function *devNodeGetter) {
    Function *f = m.getFunction("__of_parse_phandle_with_args");
    if (!f)
      return;
    f->deleteBody();
    f->setName("drvhorn.__of_parse_phandle_with_args");
    Argument *outArg = f->getArg(f->arg_size() - 1);
    LLVMContext &ctx = m.getContext();
    Function *krefGet = m.getFunction("drvhorn.kref_get");
    Type *krefType = krefGet->getArg(0)->getType()->getPointerElementType();
    BasicBlock *blk = BasicBlock::Create(ctx, "blk", f);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    IRBuilder<> b(blk);
    Value *devNode = b.CreateCall(devNodeGetter);
    StructType *devNodeType =
        cast<StructType>(devNode->getType()->getPointerElementType());
    Value *krefPtr = b.CreateInBoundsGEP(
        devNodeType, devNode,
        gepIndicesToStruct(devNodeType, krefType).getValue());
    b.CreateCall(krefGet, krefPtr);
    Value *devNodeGEP = b.CreateInBoundsGEP(
        outArg->getType()->getPointerElementType(), outArg,
        {ConstantInt::get(i64Ty, 0),
         ConstantInt::get(i32Ty, OF_PHANDLE_ARG_DEVNODE_INDEX)});
    b.CreateStore(devNode, devNodeGEP);
    Value *ok = b.CreateIsNotNull(devNode);
    Value *ret = b.CreateSelect(ok, ConstantInt::get(i32Ty, 0),
                                ConstantInt::get(i32Ty, -EINVAL));
    b.CreateRet(ret);
  }

  void stubFwnodeConnectionFindMatch(Module &m) {
    Function *f = m.getFunction("fwnode_connection_find_match");
    if (!f)
      return;
    IntegerType *i8Ty = Type::getInt8Ty(m.getContext());
    ConstantInt *size = ConstantInt::get(i8Ty, 0x10000);
    for (CallInst *call : getCalls(f)) {
      IRBuilder<> b(call);
      AllocaInst *ret = b.CreateAlloca(i8Ty, size);
      call->replaceAllUsesWith(ret);
      call->eraseFromParent();
    }
  }

  void stubFwnodeConnectionFindMatches(Module &m) {
    Function *f = m.getFunction("fwnode_connection_find_matches");
    if (!f)
      return;
    f->deleteBody();
    f->setName("drvhorn.fwnode_connection_find_matches");

    LLVMContext &ctx = m.getContext();
    SeaBuiltinsInfo &sbi = getAnalysis<SeaBuiltinsInfoWrapperPass>().getSBI();
    Function *assumeFn = sbi.mkSeaBuiltinFn(SeaBuiltinsOp::ASSUME, m);
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    Function *ndI32 = getOrCreateNdIntFn(m, 32);
    IntegerType *i32Ty = Type::getInt32Ty(ctx);

    BasicBlock *entry = BasicBlock::Create(ctx, "entry", f);
    BasicBlock *body = BasicBlock::Create(ctx, "body", f);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", f);

    IRBuilder<> b(entry);
    Value *cond = b.CreateCall(ndBool);
    b.CreateCondBr(cond, body, ret);

    b.SetInsertPoint(body);
    Value *retVal = b.CreateCall(ndI32);
    Argument *len = f->getArg(5);
    Value *withinRange =
        b.CreateAnd(b.CreateICmpULT(retVal, len),
                    b.CreateICmpSGE(retVal, ConstantInt::get(i32Ty, 0)));
    b.CreateCall(assumeFn, withinRange);
    b.CreateBr(ret);

    b.SetInsertPoint(ret);
    PHINode *retPhi = b.CreatePHI(i32Ty, 2);
    retPhi->addIncoming(ConstantInt::get(i32Ty, -EINVAL), entry);
    retPhi->addIncoming(retVal, body);
    b.CreateRet(retPhi);
  }
};

char HandleDevices::ID = 0;

Pass *createHandleDevicesPass() { return new HandleDevices(); }
}; // namespace seahorn
