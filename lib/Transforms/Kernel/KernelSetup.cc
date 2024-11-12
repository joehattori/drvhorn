#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Pass.h"

#include "boost/algorithm/string.hpp"
#include "boost/range.hpp"
#include "seahorn/Support/SeaDebug.h"
#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

class KernelSetup : public ModulePass {
public:
  static char ID;

  KernelSetup() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    m.setModuleInlineAsm("");
    Function *allocStub = createAllocFn(m);
    stubAllocationFunctions(m, allocStub);
    stubKernelFunctions(m);
    handleKrefAPIs(m);
    killFree(m);
    handleKmemCache(m, allocStub);

    handleCallRcu(m);
    handleDevErrProbeCalls(m);
    handleIsErr(m);

    // handleMemset(m);
    handleMemCpy(m);
    handleMemMove(m);
    // handleStrCat(M);
    // handleStrNCmp(M);
    handleStrChr(m);

    renameDrvhornFunctions(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "KernelSetup"; }

private:
  DenseMap<const Type *, FunctionCallee> ndfn;

  Function *createAllocFn(Module &m) {
    LLVMContext &ctx = m.getContext();
    Function *ndBool = getOrCreateNdIntFn(m, 1);
    IntegerType *i8Ty = Type::getInt8Ty(ctx);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    Function *f =
        Function::Create(FunctionType::get(i8Ty->getPointerTo(), i64Ty, false),
                         GlobalValue::ExternalLinkage, "drvhorn.alloc", &m);
    Argument *size = f->getArg(0);
    BasicBlock *blk = BasicBlock::Create(ctx, "", f);
    IRBuilder<> b(blk);
    Value *cond = b.CreateCall(ndBool, {}, "alloc.cond");
    AllocaInst *alloca = b.CreateAlloca(i8Ty, size);
    Value *result = b.CreateSelect(
        cond, alloca, ConstantPointerNull::get(i8Ty->getPointerTo()));
    b.CreateRet(result);
    return f;
  }

  void stubAllocationFunctions(Module &m, Function *allocStub) {
    struct AllocFn {
      StringRef name;
      unsigned sizeIdx;
    };
    // TODO: handle flags for zero-init.
    AllocFn allocFns[] = {
        {"__kmalloc", 0},
        {"__kmalloc_node", 0},
        {"__kmalloc_node_track_caller", 0},
        {"kmalloc_large", 0},
        {"kmalloc_trace", 2},
        {"kmalloc_large_node", 0},
        {"__vmalloc_node_range", 0},
        {"slob_alloc", 0},
        {"pcpu_alloc", 0},
        {"__ioremap_caller", 1},
        {"__early_ioremap", 1},
        {"devm_kmalloc", 1},
        {"kvmalloc_node", 0},
    };
    for (const AllocFn &f : allocFns) {
      Function *orig = m.getFunction(f.name);
      if (!orig)
        continue;
      for (CallInst *call : getCalls(orig)) {
        IRBuilder<> b(call);
        Value *replace =
            b.CreateCall(allocStub, call->getArgOperand(f.sizeIdx));
        call->replaceAllUsesWith(replace);
        call->eraseFromParent();
      }
    }
  }

  void stubKernelFunctions(Module &m) {
    std::string mallocFns[] = {"strcpy",  "strncpy", "strlen",
                               "strnlen", "strcmp",  "strncmp"};
    for (const std::string &name : mallocFns) {
      Function *orig = m.getFunction(name);
      if (!orig)
        continue;
      std::string stubName = "__DRVHORN_" + name;
      Function *stub = m.getFunction(stubName);
      if (!stub) {
        errs() << "stub not found: " << stubName << "\n";
        std::exit(1);
      }
      orig->replaceAllUsesWith(stub);
      orig->eraseFromParent();
    }
  }

  Type *getKrefTy(Module &m) {
    Function *krefInit = m.getFunction("kref_init");
    return krefInit->getArg(0)->getType()->getPointerElementType();
  }

  Function *buildKrefInit(Module &m) {
    LLVMContext &ctx = m.getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    Type *krefTy = getKrefTy(m);
    FunctionType *krefInitTy = FunctionType::get(
        Type::getVoidTy(ctx), {krefTy->getPointerTo()}, false);
    Function *krefInit = Function::Create(
        krefInitTy, GlobalValue::ExternalLinkage, "drvhorn.kref_init", &m);
    BasicBlock *block = BasicBlock::Create(ctx, "", krefInit);
    IRBuilder<> b(block);
    Value *gep = b.CreateInBoundsGEP(
        krefTy, krefInit->getArg(0),
        {ConstantInt::get(i64Ty, 0), ConstantInt::get(i32Ty, 0),
         ConstantInt::get(i32Ty, 0), ConstantInt::get(i32Ty, 0)});
    b.CreateStore(ConstantInt::get(i32Ty, 1), gep);
    b.CreateRetVoid();

    return krefInit;
  }

  Function *buildKrefGet(Module &m) {
    LLVMContext &ctx = m.getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    Type *krefTy = getKrefTy(m);
    FunctionType *krefGetTy = FunctionType::get(
        Type::getVoidTy(ctx), {krefTy->getPointerTo()}, false);
    Function *krefGet = Function::Create(
        krefGetTy, GlobalValue::InternalLinkage, "drvhorn.kref_get", &m);
    BasicBlock *block = BasicBlock::Create(ctx, "", krefGet);
    IRBuilder<> b(block);
    Value *gep = b.CreateInBoundsGEP(
        krefTy, krefGet->getArg(0),
        {ConstantInt::get(i64Ty, 0), ConstantInt::get(i32Ty, 0),
         ConstantInt::get(i32Ty, 0), ConstantInt::get(i32Ty, 0)});
    LoadInst *load = b.CreateLoad(i32Ty, gep);
    Value *add = b.CreateAdd(load, ConstantInt::get(i32Ty, 1));
    b.CreateStore(add, gep);
    b.CreateRetVoid();
    return krefGet;
  }

  Function *buildKrefPut(Module &m) {
    LLVMContext &ctx = m.getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    Type *krefTy = getKrefTy(m);
    FunctionType *krefPutTy =
        FunctionType::get(i32Ty, {krefTy->getPointerTo()}, false);
    Function *krefPut = Function::Create(
        krefPutTy, GlobalValue::InternalLinkage, "drvhorn.kref_put", &m);
    BasicBlock *block = BasicBlock::Create(ctx, "", krefPut);

    IRBuilder<> b(block);
    Value *gep = b.CreateInBoundsGEP(
        krefTy, krefPut->getArg(0),
        {ConstantInt::get(i64Ty, 0), ConstantInt::get(i32Ty, 0),
         ConstantInt::get(i32Ty, 0), ConstantInt::get(i32Ty, 0)});
    LoadInst *load = b.CreateLoad(i32Ty, gep);
    Value *sub = b.CreateSub(load, ConstantInt::get(i32Ty, 1));
    b.CreateStore(sub, gep);
    Value *isZero = b.CreateICmpEQ(sub, ConstantInt::get(i32Ty, 0));
    Value *ret = b.CreateZExt(isZero, i32Ty);
    b.CreateRet(ret);
    return krefPut;
  }

  void handleKrefAPIs(Module &m) {
    Function *krefInit = buildKrefInit(m);
    Function *krefGet = buildKrefGet(m);
    Function *krefPut = buildKrefPut(m);

    auto replaceCalls = [](Function *orig, Function *newFn) {
      for (CallInst *call : getCalls(orig)) {
        Value *arg = call->getArgOperand(0);
        if (arg->getType() != newFn->getArg(0)->getType()) {
          arg = new BitCastInst(arg, newFn->getArg(0)->getType(), "", call);
        }
        CallInst *newCall = CallInst::Create(newFn, arg, "", call);
        call->replaceAllUsesWith(newCall);
        call->eraseFromParent();
      }
    };

    for (Function &f : m) {
      StringRef name = f.getName();
      if (name.equals("kref_init") || name.startswith("kref_init.")) {
        replaceCalls(&f, krefInit);
      } else if (name.equals("kref_get") || name.startswith("kref_get.")) {
        replaceCalls(&f, krefGet);
      } else if (name.equals("kref_put") || name.startswith("kref_put.")) {
        replaceCalls(&f, krefPut);
      }
    }
  }

  void killFree(Module &m) {
    std::string freeFuncNames[] = {
        "kfree",
        "vfree",
        "free_percpu",
    };
    for (const std::string &name : freeFuncNames) {
      if (Function *orig = m.getFunction(name)) {
        orig->deleteBody();
      }
    }
  }

  GlobalVariable *gVarOfKmemCacheAllocCall(Module &m, CallInst *call) {
    Value *cache = call->getArgOperand(0);
    if (LoadInst *load = dyn_cast<LoadInst>(cache)) {
      if (GlobalVariable *gv =
              dyn_cast<GlobalVariable>(load->getPointerOperand())) {
        return gv;
      }
    }
    return nullptr;
  }

  Optional<size_t> getKmemCacheSize(GlobalVariable *gv) {
    for (User *user : gv->users()) {
      if (StoreInst *store = dyn_cast<StoreInst>(user)) {
        if (store->getPointerOperand() == gv) {
          Value *src = store->getValueOperand();
          if (CallInst *call = dyn_cast<CallInst>(src)) {
            Function *f = call->getCalledFunction();
            if (f && (f->getName() == "kmem_cache_create" ||
                      f->getName() == "kmem_cache_create_usercopy")) {
              ConstantInt *ci = cast<ConstantInt>(call->getArgOperand(1));
              return ci->getZExtValue();
            } else {
              errs() << "TODO: getKmemCacheSize: unhandled function\n";
            }
          } else if (isa<ConstantPointerNull>(src)) {
            return 0;
          } else {
            errs() << "else " << *src << '\n';
          }
        }
      }
    }
    return None;
  }

  void handleKmemCache(Module &m, Function *allocStub) {
    StringRef kmemCacheFuncNames[] = {
        "kmem_cache_alloc",
        "kmem_cache_alloc_lru",
        "kmem_cache_alloc_node",
    };
    LLVMContext &ctx = m.getContext();
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    for (StringRef name : kmemCacheFuncNames) {
      Function *orig = m.getFunction(name);
      if (!orig)
        continue;
      for (User *user : orig->users()) {
        if (CallInst *call = dyn_cast<CallInst>(user)) {
          GlobalVariable *gv = gVarOfKmemCacheAllocCall(m, call);
          if (!gv) {
            errs() << "TODO: kmem_cache_alloc: global variable not found\n";
            continue;
          }
          Optional<size_t> size = getKmemCacheSize(gv);
          if (!size.hasValue()) {
            continue;
          }
          ConstantInt *sizeArg = ConstantInt::get(i64Ty, size.getValue());
          IRBuilder<> b(call);
          Value *newMalloc = b.CreateCall(allocStub, sizeArg);
          call->replaceAllUsesWith(newMalloc);
        }
      }
    }
  }

  void renameDrvhornFunctions(Module &m) {
    for (Function &f : m) {
      if (f.getName().startswith("__DRVHORN_")) {
        StringRef realName = f.getName().substr(10);
        std::string newName = "drvhorn." + realName.str();
        f.setName(newName);
      }
    }

    for (GlobalVariable &gv : m.globals()) {
      if (gv.getName().startswith("__DRVHORN_")) {
        StringRef realName = gv.getName().substr(10);
        std::string newName = "drvhorn." + realName.str();
        gv.setName(newName);
      }
    }
  }

  void handleCallRcu(Module &m) {
    LLVMContext &ctx = m.getContext();
    std::string name = "call_rcu";
    Function *orig = m.getFunction(name);
    if (!orig)
      return;
    std::string wrapperName = name + "_wrapper";
    Function *wrapper = Function::Create(
        orig->getFunctionType(), GlobalValue::ExternalLinkage, wrapperName, &m);
    BasicBlock *block = BasicBlock::Create(ctx, "", wrapper);
    Value *arg = wrapper->getArg(0);
    Value *fn = wrapper->getArg(1);
    // rcu_callback_t
    FunctionType *fnType =
        FunctionType::get(Type::getVoidTy(ctx), {arg->getType()}, false);
    FunctionCallee callee = FunctionCallee(fnType, fn);
    CallInst::Create(callee, {arg}, "", block);
    ReturnInst::Create(ctx, nullptr, block);
    orig->replaceAllUsesWith(wrapper);
    orig->eraseFromParent();
  }

  void handleDevErrProbeCalls(Module &m) {
    Function *f = m.getFunction("dev_err_probe");
    if (!f)
      return;
    for (CallInst *call : getCalls(f)) {
      Value *err = call->getArgOperand(1);
      call->replaceAllUsesWith(err);
      call->eraseFromParent();
    }
  }

  // The IS_ERR check is translated to something like the following LLVM IR:
  //   %1 = icmp ugt %struct.a* %0, inttoptr (i64 -4096 to %struct.a*)
  // This code may be evaluated to true even if %0 is a valid pointer.
  // We replace the IS_ERR check with comparison to 0, i.e.
  //   %1 = icmp ult %struct.a* %0, inttoptr (i64 0 to %struct.a*)
  void handleIsErr(Module &m) {
    auto isTarget = [](ICmpInst *icmp) {
      if (icmp->getPredicate() == CmpInst::ICMP_UGT) {
        if (ConstantExpr *ci = dyn_cast<ConstantExpr>(icmp->getOperand(1))) {
          if (ci->getOpcode() == Instruction::IntToPtr) {
            if (ConstantInt *intVal =
                    dyn_cast<ConstantInt>(ci->getOperand(0))) {
              return intVal->getSExtValue() == -4096;
            }
          }
        }
      }
      return false;
    };

    IntegerType *i64Ty = Type::getInt64Ty(m.getContext());
    for (Function &f : m) {
      for (Instruction &inst : instructions(f)) {
        if (ICmpInst *icmp = dyn_cast<ICmpInst>(&inst)) {
          if (isTarget(icmp)) {
            icmp->setPredicate(CmpInst::ICMP_ULT);
            Constant *rhs = ConstantExpr::getIntToPtr(
                ConstantInt::get(i64Ty, 0), icmp->getOperand(0)->getType());
            icmp->setOperand(1, rhs);
          }
        }
      }
    }
  }

  void handleMemset(Module &m) {
    if (Function *llvmMemset = m.getFunction("llvm.memset.p0i8.i64")) {
      Function *memsetFn = m.getFunction("__DRVHORN_memset");
      if (!memsetFn) {
        errs() << "__DRVHORN_memset not found\n";
        std::exit(1);
      }
      llvmMemset->replaceAllUsesWith(memsetFn);
      llvmMemset->eraseFromParent();
    }
  }

  void handleMemCpy(Module &m) {
    enum RetType {
      Void,
      Len,
      Dest,
    };

    struct MemcpyInfo {
      std::string name;
      RetType returnType;
    };

    LLVMContext &ctx = m.getContext();
    MemcpyInfo memcpyFuncNames[] = {
        MemcpyInfo{"memcpy", RetType::Dest},
        MemcpyInfo{"memcpy_fromio", RetType::Void},
        MemcpyInfo{"memcpy_toio", RetType::Void},
        MemcpyInfo{"_copy_user_ll", RetType::Len},
        MemcpyInfo{"_copy_user_ll_nocache_nozero", RetType::Len},
        MemcpyInfo{"_copy_to_user", RetType::Len},
        MemcpyInfo{"_copy_from_user", RetType::Len},
    };
    for (const MemcpyInfo &info : memcpyFuncNames) {
      Function *f = m.getFunction(info.name);
      if (!f)
        continue;
      std::string wrapperName = info.name + "_wrapper";
      Function *wrapper = Function::Create(
          f->getFunctionType(), GlobalValue::ExternalLinkage, wrapperName, &m);
      BasicBlock *block = BasicBlock::Create(ctx, "", wrapper);
      Value *dst = wrapper->getArg(0);
      Value *src = wrapper->getArg(1);
      Value *size = wrapper->getArg(2);
      IRBuilder<> B(block);
      B.CreateMemCpy(dst, MaybeAlign(), src, MaybeAlign(), size);
      switch (info.returnType) {
      case RetType::Void:
        B.CreateRetVoid();
        break;
      case RetType::Len:
        B.CreateRet(size);
        break;
      case RetType::Dest:
        B.CreateRet(dst);
        break;
      }
      f->replaceAllUsesWith(wrapper);
      f->eraseFromParent();
    }
  }

  void handleMemMove(Module &m) {
    LLVMContext &ctx = m.getContext();
    Function *f = m.getFunction("memmove");
    if (!f)
      return;
    std::string wrapperName = "memmove_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::ExternalLinkage, wrapperName, &m);
    BasicBlock *block = BasicBlock::Create(ctx, "", wrapper);
    Value *dst = wrapper->getArg(0);
    Value *src = wrapper->getArg(1);
    Value *size = wrapper->getArg(2);
    IRBuilder<> B(block);
    B.CreateMemMove(dst, MaybeAlign(), src, MaybeAlign(), size);
    B.CreateRet(dst);
    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  void handleStrCat(Module &m) {
    Function *f = m.getFunction("strcat");
    if (!f)
      return;
    LLVMContext &ctx = m.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strcat_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::ExternalLinkage, wrapperName, &m);
    Value *dst = wrapper->getArg(0);
    Value *src = wrapper->getArg(1);

    BasicBlock *entry = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *skipCond = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *skipBody = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *copyCond = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *copyBody = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *end = BasicBlock::Create(ctx, "", wrapper);

    IRBuilder<> B(entry);
    Value *it = B.CreateAlloca(i32Type);
    B.CreateStore(B.getInt32(0), it);
    B.CreateBr(skipCond);

    B.SetInsertPoint(skipCond);
    Value *loadedIt = B.CreateLoad(i32Type, it);
    Value *dstPtr = B.CreateGEP(i8Type, dst, loadedIt);
    Value *dstChar = B.CreateLoad(i8Type, dstPtr);
    B.CreateCondBr(B.CreateICmpEQ(dstChar, B.getInt8(0)), copyCond, skipBody);

    B.SetInsertPoint(skipBody);
    B.CreateStore(B.CreateAdd(loadedIt, B.getInt32(1)), it);
    B.CreateBr(skipCond);

    B.SetInsertPoint(copyCond);
    loadedIt = B.CreateLoad(i32Type, it);
    Value *srcPtr = B.CreateGEP(i8Type, src, loadedIt);
    Value *srcChar = B.CreateLoad(i8Type, srcPtr);
    Value *isEnd = B.CreateICmpEQ(srcChar, B.getInt8(0));
    B.CreateCondBr(isEnd, end, copyBody);

    B.SetInsertPoint(copyBody);
    loadedIt = B.CreateLoad(i32Type, it);
    dstPtr = B.CreateGEP(i8Type, dst, loadedIt);
    B.CreateStore(srcChar, dstPtr);
    B.CreateStore(B.CreateAdd(loadedIt, B.getInt32(1)), it);
    B.CreateBr(copyCond);

    B.SetInsertPoint(end);
    B.CreateRet(dst);
    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  void handleStrCmp(Module &m) {
    Function *f = m.getFunction("strcmp");
    if (!f)
      return;
    LLVMContext &ctx = m.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strcmp_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::ExternalLinkage, wrapperName, &m);
    Value *s1 = wrapper->getArg(0);
    Value *s2 = wrapper->getArg(1);

    BasicBlock *entry = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loop = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loopEnd = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *retZero = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *retNonZero = BasicBlock::Create(ctx, "", wrapper);

    IRBuilder<> B(entry);
    Value *it = B.CreateAlloca(i32Type);
    B.CreateStore(B.getInt32(0), it);
    B.CreateBr(loop);

    B.SetInsertPoint(loop);
    Value *loadedIt = B.CreateLoad(i32Type, it);
    Value *s1Ptr = B.CreateGEP(i8Type, s1, loadedIt);
    Value *s2Ptr = B.CreateGEP(i8Type, s2, loadedIt);
    Value *s1Char = B.CreateLoad(i8Type, s1Ptr);
    Value *s2Char = B.CreateLoad(i8Type, s2Ptr);
    B.CreateCondBr(B.CreateICmpNE(s1Char, s2Char), retNonZero, loopEnd);

    B.SetInsertPoint(retNonZero);
    Value *ret = B.CreateSelect(B.CreateICmpULT(s1Char, s2Char), B.getInt32(-1),
                                B.getInt32(1));
    B.CreateRet(ret);

    B.SetInsertPoint(loopEnd);
    Value *isEnd = B.CreateICmpEQ(s1Char, B.getInt8(0));
    loadedIt = B.CreateLoad(i32Type, it);
    B.CreateStore(B.CreateAdd(loadedIt, B.getInt32(1)), it);
    B.CreateCondBr(isEnd, retZero, loop);

    B.SetInsertPoint(retZero);
    B.CreateRet(B.getInt32(0));

    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  void handleStrNCmp(Module &m) {
    Function *f = m.getFunction("strncmp");
    if (!f)
      return;
    LLVMContext &ctx = m.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strncmp_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::ExternalLinkage, wrapperName, &m);
    Value *s1 = wrapper->getArg(0);
    Value *s2 = wrapper->getArg(1);
    Value *size = wrapper->getArg(2);

    BasicBlock *entry = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loop = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loopEnd = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *retZero = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *retNonZero = BasicBlock::Create(ctx, "", wrapper);

    IRBuilder<> B(entry);
    Value *it = B.CreateAlloca(i32Type);
    B.CreateStore(B.getInt32(0), it);
    B.CreateBr(loop);

    B.SetInsertPoint(loop);
    Value *loadedIt = B.CreateLoad(i32Type, it);
    Value *s1Ptr = B.CreateGEP(i8Type, s1, loadedIt);
    Value *s2Ptr = B.CreateGEP(i8Type, s2, loadedIt);
    Value *s1Char = B.CreateLoad(i8Type, s1Ptr);
    Value *s2Char = B.CreateLoad(i8Type, s2Ptr);
    B.CreateCondBr(B.CreateICmpNE(s1Char, s2Char), retNonZero, loopEnd);

    B.SetInsertPoint(retNonZero);
    Value *ret = B.CreateSelect(B.CreateICmpULT(s1Char, s2Char), B.getInt32(-1),
                                B.getInt32(1));
    B.CreateRet(ret);

    B.SetInsertPoint(loopEnd);
    loadedIt = B.CreateLoad(i32Type, it);
    Value *isNull = B.CreateICmpEQ(s1Char, B.getInt8(0));
    Value *isEnd = B.CreateOr(isNull, B.CreateICmpUGE(loadedIt, size));
    B.CreateStore(B.CreateAdd(loadedIt, B.getInt32(1)), it);
    B.CreateCondBr(isEnd, retZero, loop);

    B.SetInsertPoint(retZero);
    B.CreateRet(B.getInt32(0));

    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  void handleStrChr(Module &m) {
    Function *f = m.getFunction("strchr");
    if (!f)
      return;
    LLVMContext &ctx = m.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strchr_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::ExternalLinkage, wrapperName, &m);
    Value *str = wrapper->getArg(0);
    Value *chr = wrapper->getArg(1);

    BasicBlock *entry = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loop = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *retZero = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *cmpChar = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *ret = BasicBlock::Create(ctx, "", wrapper);

    IRBuilder<> B(entry);
    Value *it = B.CreateAlloca(i32Type);
    B.CreateStore(B.getInt32(0), it);
    B.CreateBr(loop);

    B.SetInsertPoint(loop);
    Value *loadedIt = B.CreateLoad(i32Type, it);
    Value *strPtr = B.CreateGEP(i8Type, str, loadedIt);
    Value *curChar = B.CreateLoad(i8Type, strPtr);
    Value *isNull = B.CreateICmpEQ(curChar, B.getInt8(0));
    B.CreateCondBr(isNull, retZero, cmpChar);

    B.SetInsertPoint(retZero);
    Value *null = B.CreateIntToPtr(B.getInt32(0), i8Type->getPointerTo());
    B.CreateRet(null);

    B.SetInsertPoint(cmpChar);
    Value *isHit = B.CreateICmpEQ(curChar, B.CreateTrunc(chr, i8Type));
    B.CreateStore(B.CreateAdd(loadedIt, B.getInt32(1)), it);
    B.CreateCondBr(isHit, ret, loop);

    B.SetInsertPoint(ret);
    B.CreateRet(strPtr);

    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  FunctionCallee makeNewNondetFn(Module &m, Type &type, unsigned num,
                                 std::string prefix) {
    std::string name;
    unsigned c = num;
    do {
      name = prefix + std::to_string(c++);
    } while (m.getNamedValue(name));
    FunctionCallee res = m.getOrInsertFunction(name, &type);
    return res;
  }

  FunctionCallee getNondetFn(Type *type, Module &m) {
    auto it = ndfn.find(type);
    if (it != ndfn.end()) {
      return it->second;
    }

    FunctionCallee res =
        makeNewNondetFn(m, *type, ndfn.size(), "verifier.nondet.");
    ndfn[type] = res;
    return res;
  }
};

char KernelSetup::ID = 0;

Pass *createKernelSetupPass() { return new KernelSetup(); }
} // namespace seahorn
