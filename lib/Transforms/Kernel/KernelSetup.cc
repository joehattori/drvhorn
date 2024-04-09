#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Pass.h"

#include "boost/range.hpp"
#include "seahorn/Support/SeaDebug.h"

#include <algorithm>
#include <llvm-14/llvm/IR/Operator.h>
#include <optional>
#include <regex>

using namespace llvm;

#define MOVL_POSITION_INDEPENDENT "movl ${1:P}, $0"

#define BARRIER_CONSTRAINTS "~{memory},~{dirflag},~{fpsr},~{flags}"
#define SPLIT_U64_CONSTRAINTS "={ax},={dx},A,~{dirflag},~{fpsr},~{flags}"

#define BIT_TEST_PREFIX " btl  $2,$1"
#define BIT_TEST_AND_SET_PREFIX " btsl  $1,$0"
#define BIT_TEST_AND_RESET_PREFIX " btrl  $1,$0"

#define INCL "incl $0"
#define DECL_PREFIX "decl $0"
#define XADDL_PREFIX "xaddl $0, $1"
#define MOVL "movl $1, $0"
#define ADDL "addl $1, $0"
#define MULL "mull $3"
#define DIVL "divl $2"
#define CMPXCHGL21 "cmpxchgl $2,$1"
#define CMPXCHGL31_PREFIX "cmpxchgl $3, $1"
#define CMPXCHG8B "cmpxchg8b $1"
#define FFS "rep; bsf $1,$0"
#define FLS "bsrl $1,$0;cmovzl $2,$0"
#define CLI "cli"
#define STI "sti"
#define RDPMC "rdpmc"
#define CALL0 "call ${0:P}"
#define CALL1 "call ${1:P}"
#define CALL2 "call ${2:P}"
#define ARRAY_INDEX_MASK_NOSPEC "cmp $1,$2; sbb $0,$0;"
#define CPUID "cpuid"

#define GET_USER "call __get_user_nocheck_${4:P}"
#define GET_USER_CONSTRAINTS                                                   \
  "={ax},={edx},={esp},0,i,{esp},~{dirflag},~{fpsr},~{flags}"

#define HWEIGHT                                                                \
  "# ALT: oldnstr;661:;call __sw_hweight32;662:;# ALT: padding;.skip "         \
  "-(((6651f-6641f)-(662b-661b)) > 0) * "                                      \
  "((6651f-6641f)-(662b-661b)),0x90;663:;.pushsection .altinstructions,'a'; "  \
  ".long 661b - .; .long 6641f - .; .word ( 4*32+23); .byte 663b-661b; .byte " \
  "6651f-6641f;.popsection;.pushsection .altinstr_replacement, 'ax';# ALT: "   \
  "replacement 1;6641:;popcntl $1, $0;6651:;.popsection;"
#define NATIVE_READ_MSR_SAFE                                                   \
  "1: rdmsr ; xor $0,$0;2:; .pushsection '__ex_table','a'; .balign 4; .long "  \
  "(1b) - .; .long (2b) - .;.macro extable_type_reg type:req reg:req;.set "    \
  ".Lfound, 0;.set .Lregnr, 0;.irp "                                           \
  "rs,rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15;.ifc "     \
  "\\reg, %\\rs;.set .Lfound, .Lfound+1;.long \\type + (.Lregnr << "           \
  "8);.endif;.set .Lregnr, .Lregnr+1;.endr;.set .Lregnr, 0;.irp "              \
  "rs,eax,ecx,edx,ebx,esp,ebp,esi,edi,r8d,r9d,r10d,r11d,r12d,r13d,r14d,r15d;." \
  "ifc \\reg, %\\rs;.set .Lfound, .Lfound+1;.long \\type + (.Lregnr << "       \
  "8);.endif;.set .Lregnr, .Lregnr+1;.endr;.if (.Lfound != 1);.error "         \
  "'extable_type_reg: bad register argument';.endif;.endm;extable_type_reg "   \
  "reg=$0, type=11 ;.purgem extable_type_reg; .popsection;"
#define NATIVE_WRITE_MSR_SAFE                                                  \
  "1: wrmsr ; xor $0,$0;2:; .pushsection '__ex_table','a'; .balign 4; .long "  \
  "(1b) - .; .long (2b) - .;.macro extable_type_reg type:req reg:req;.set "    \
  ".Lfound, 0;.set .Lregnr, 0;.irp "                                           \
  "rs,rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15;.ifc "     \
  "\\reg, %\\rs;.set .Lfound, .Lfound+1;.long \\type + (.Lregnr << "           \
  "8);.endif;.set .Lregnr, .Lregnr+1;.endr;.set .Lregnr, 0;.irp "              \
  "rs,eax,ecx,edx,ebx,esp,ebp,esi,edi,r8d,r9d,r10d,r11d,r12d,r13d,r14d,r15d;." \
  "ifc \\reg, %\\rs;.set .Lfound, .Lfound+1;.long \\type + (.Lregnr << "       \
  "8);.endif;.set .Lregnr, .Lregnr+1;.endr;.if (.Lfound != 1);.error "         \
  "'extable_type_reg: bad register argument';.endif;.endm;extable_type_reg "   \
  "reg=$0, type=10 ;.purgem extable_type_reg; .popsection;"
#define RDMSR                                                                  \
  "1: rdmsr;2:; .pushsection '__ex_table','a'; .balign 4; .long (1b) - .; "    \
  ".long (2b) - .; .long 9 ; .popsection;"
#define WRMSR                                                                  \
  "1: wrmsr;2:; .pushsection '__ex_table','a'; .balign 4; .long (1b) - .; "    \
  ".long (2b) - .; .long 8 ; .popsection;"

#define NATIVE_SAVE_FL "# __raw_save_flags;pushf ; pop $0"

#define ATOMIC64_COUNTER_INDEX 0

namespace seahorn {

struct MemAllocConversion {
  enum MemAllocType {
    Kmalloc,
    KmallocLarge,
    KmallocNode,
    KmallocLargeNode,
    PcpuAlloc
  };

  CallInst *call = nullptr;
  MemAllocType type;

  MemAllocConversion(CallInst *inst) {
    if (!inst)
      return;
    Function *fn = inst->getCalledFunction();
    if (!fn)
      return;
    StringRef name = fn->getName();
    if (name.equals("__kmalloc"))
      type = Kmalloc;
    else if (name.equals("kmalloc_large"))
      type = KmallocLarge;
    else if (name.equals("__kmalloc_node"))
      type = KmallocNode;
    else if (name.equals("kmalloc_large_node"))
      type = KmallocLargeNode;
    else if (name.equals("pcpu_alloc"))
      type = PcpuAlloc;
    else
      return;
    call = inst;
  }

  SmallVector<Value *, 2> getArgs() const {
    switch (type) {
    case Kmalloc:
    case KmallocLarge:
    case KmallocNode:
    case KmallocLargeNode:
      return {call->getArgOperand(0), call->getArgOperand(1)};
    case PcpuAlloc:
      return {call->getArgOperand(0), call->getArgOperand(3)};
    }
  }
};

class KernelSetup : public ModulePass {
public:
  static char ID;

  KernelSetup() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    handleKmalloc(M);
    handleInlineAssembly(M);
    insertMain(M);
    updateFunctionLinkage(M);
    return true;
  }

  virtual StringRef getPassName() const override { return "KernelSetup"; }

private:
  DenseMap<const Type *, FunctionCallee> ndfn;

  FunctionCallee createKmallocStub(Module &M) {
    LLVMContext &ctx = M.getContext();
    // void pointer type.
    Type *retType = Type::getInt8PtrTy(ctx);
    SmallVector<Type *, 2> argTypes = {Type::getInt32Ty(ctx),
                                       Type::getInt32Ty(ctx)};
    FunctionType *funcType = FunctionType::get(retType, argTypes, false);
    return M.getOrInsertFunction("malloc_stub", funcType);
  }

  void handleKmalloc(Module &M) {
    FunctionCallee stub = createKmallocStub(M);

    std::vector<MemAllocConversion> conversions;
    for (Function &fn : M) {
      for (Instruction &inst : instructions(fn)) {
        MemAllocConversion conv(dyn_cast<CallInst>(&inst));
        if (conv.call)
          conversions.push_back(conv);
      }
    }

    for (const MemAllocConversion &conv : conversions) {
      CallInst *call = conv.call;
      IRBuilder<> B(call);
      CallInst *new_call = B.CreateCall(stub, conv.getArgs());
      call->replaceAllUsesWith(new_call);
      call->eraseFromParent();
    }

    for (StringRef name : {"__kmalloc", "kmalloc_large", "__kmalloc_node",
                           "kmalloc_large_node", "pcpu_alloc"}) {
      if (Function *fn = M.getFunction(name))
        fn->eraseFromParent();
    }
  }

  void handleInlineAssembly(Module &M) {
    handleBitTest(M);
    handleBitTestAndSet(M);
    handleBitTestAndReset(M);
    handleFFS(M);
    handleFLS(M);
    handleHWeight(M);

    handleIncl(M);
    handleDecl(M);
    handleXAddl(M);
    handleMovl(M);
    handleAddl(M);
    handleMull(M);
    handleDivl(M);
    handleCpuid(M);

    handleAtomic64Read(M);
    handleAtomic64Set(M);
    handleAtomic64AddReturn(M);
    handleAtomic64SubReturn(M);
    handleCmpxchgl(M);
    handleCmpxchg8b(M);

    handleNativeSaveFL(M);
    handleCLI(M);
    handleSTI(M);
    handleRDPMC(M);

    handleNativeReadMSRSafe(M);
    handleNativeWriteMSRSafe(M);
    handleRDMSR(M);
    handleWRMSR(M);
    handleArrayIndexMaskNoSpec(M);

    handleCurrentTask(M);
    handleBarrier(M);
    handleSplitU64(M);
    handleGetUser(M);
  }

  std::vector<CallInst *>
  getTargetAsmCalls(Module &M, const std::string &asmStr, bool isPrefix,
                    const std::string &constraints = "") {
    auto formatInlineAsm = [](std::string s) {
      std::regex newLine("\n");
      s = std::regex_replace(s, newLine, ";");
      std::regex tab("\t");
      s = std::regex_replace(s, tab, "");
      std::regex quote("\"");
      return std::regex_replace(s, quote, "'");
    };

    auto isTargetAsm = [&](const CallInst *call) {
      const InlineAsm *inlineAsm =
          dyn_cast<InlineAsm>(call->getCalledOperand());
      if (!inlineAsm)
        return false;
      std::string formatted = formatInlineAsm(inlineAsm->getAsmString());
      if (isPrefix)
        return !formatted.rfind(asmStr, 0) &&
               (constraints.empty() ||
                inlineAsm->getConstraintString() == constraints);
      else
        return formatted == asmStr &&
               (constraints.empty() ||
                inlineAsm->getConstraintString() == constraints);
    };

    std::vector<CallInst *> calls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isTargetAsm(call))
            calls.push_back(call);
        }
      }
    }
    return calls;
  }

  void handleCurrentTask(Module &M) {
    auto isPtrToPtrToTask = [](Type *type) {
      if (!type->isPointerTy())
        return false;
      PointerType *ptrType = dyn_cast<PointerType>(type);
      Type *innerType = ptrType->getElementType();
      if (!innerType->isPointerTy())
        return false;
      PointerType *innerPtrType = dyn_cast<PointerType>(innerType);
      return innerPtrType->getElementType()->getStructName().startswith(
          "struct.task_struct");
    };

    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, MOVL_POSITION_INDEPENDENT, false);
    for (CallInst *call : calls) {
      Value *arg = call->getArgOperand(0);
      if (BitCastOperator *bitcast = dyn_cast<BitCastOperator>(arg)) {
        Value *task = bitcast->getOperand(0);
        if (isPtrToPtrToTask(bitcast->getSrcTy()) &&
            isPtrToPtrToTask(bitcast->getDestTy()) &&
            task->getName().equals("current_task")) {
          call->replaceAllUsesWith(task);
          call->eraseFromParent();
        }
      }
    }
  }

  void handleBarrier(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, "", false, BARRIER_CONSTRAINTS);
    for (CallInst *call : calls)
      call->eraseFromParent();
  }

  void handleSplitU64(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, "", false, SPLIT_U64_CONSTRAINTS);
    for (CallInst *call : calls) {
      Value *v = call->getArgOperand(0);
      IRBuilder<> B(call);
      Value *low = B.CreateTrunc(v, B.getInt32Ty());
      Value *high = B.CreateLShr(v, 32);
      Value *empty = UndefValue::get(call->getType());
      Value *setLow = B.CreateInsertValue(empty, low, {0});
      Value *replace = B.CreateInsertValue(setLow, high, {1});
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  Value *bitAddr(IRBuilder<> &B, Value *base, Value *offset) {
    Value *idx = B.CreateAShr(offset, B.getInt32(8));
    return B.CreateAdd(base, idx);
  }

  void handleBitTest(Module &M) {
    LLVMContext &ctx = M.getContext();
    std::vector<CallInst *> calls = getTargetAsmCalls(M, BIT_TEST_PREFIX, true);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *addr = call->getArgOperand(1);
      Value *offset = call->getArgOperand(2);

      Value *pos = bitAddr(B, addr, offset);
      Value *loaded = B.CreateLoad(Type::getInt1Ty(ctx), pos);
      Value *bit = B.CreateAnd(loaded, 1);
      Value *isSet = B.CreateICmpNE(bit, B.getInt32(0));
      call->replaceAllUsesWith(isSet);
      call->eraseFromParent();
    }
  }

  void handleBitTestAndSet(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, BIT_TEST_AND_SET_PREFIX, true);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *addr = call->getArgOperand(0);
      Value *offset = call->getArgOperand(1);

      Value *pos = bitAddr(B, addr, offset);
      Value *old =
          B.CreateAtomicRMW(AtomicRMWInst::Or, pos, B.getInt1(1), MaybeAlign(),
                            AtomicOrdering::SequentiallyConsistent);
      call->replaceAllUsesWith(old);
      call->eraseFromParent();
    }
  }

  void handleBitTestAndReset(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, BIT_TEST_AND_RESET_PREFIX, true);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *addr = call->getArgOperand(0);
      Value *offset = call->getArgOperand(1);

      Value *pos = bitAddr(B, addr, offset);
      Value *old =
          B.CreateAtomicRMW(AtomicRMWInst::And, pos, B.getInt1(0), MaybeAlign(),
                            AtomicOrdering::SequentiallyConsistent);
      call->replaceAllUsesWith(old);
      call->eraseFromParent();
    }
  }

  void handleIncl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, INCL, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      Value *inc = B.CreateAdd(val, B.getInt32(1));
      call->replaceAllUsesWith(inc);
      call->eraseFromParent();
    }
  }

  void handleDecl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, DECL_PREFIX, true);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      Value *dec = B.CreateSub(val, B.getInt32(1));
      call->replaceAllUsesWith(dec);
      call->eraseFromParent();
    }
  }

  void handleXAddl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, XADDL_PREFIX, true);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *ptr = call->getArgOperand(0);
      Value *inc = call->getArgOperand(1);
      Value *old = B.CreateAtomicRMW(AtomicRMWInst::Add, ptr, inc, MaybeAlign(),
                                     AtomicOrdering::SequentiallyConsistent);
      call->replaceAllUsesWith(old);
      call->eraseFromParent();
    }
  }

  void handleMovl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, MOVL, false);
    LLVMContext &ctx = M.getContext();
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *dst = call->getArgOperand(0);
      Value *src = call->getArgOperand(1);

      LoadInst *load = B.CreateLoad(Type::getInt32Ty(ctx), src);
      StoreInst *store = B.CreateStore(load, dst);
      call->replaceAllUsesWith(store);
      call->eraseFromParent();
    }
  }

  void handleAddl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, ADDL, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *dst = call->getArgOperand(0);
      Value *src = call->getArgOperand(1);

      Value *add = B.CreateAdd(dst, src);
      call->replaceAllUsesWith(add);
      call->eraseFromParent();
    }
  }

  void handleMull(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, MULL, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *v1 = B.CreateZExt(call->getArgOperand(0), B.getInt64Ty());
      Value *v2 = B.CreateZExt(call->getArgOperand(1), B.getInt64Ty());

      Value *mul = B.CreateMul(v1, v2);
      Value *low = B.CreateTrunc(mul, B.getInt32Ty());
      Value *upper = B.CreateLShr(mul, 32);
      StructType *type = cast<StructType>(call->getType());
      Value *empty = UndefValue::get(type);
      Value *setLow = B.CreateInsertValue(empty, low, {0});
      Value *replace = B.CreateInsertValue(setLow, upper, {1});
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleDivl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, DIVL, false);
    Type *i64Ty = Type::getInt64Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *divisor = B.CreateZExt(call->getArgOperand(0), i64Ty);
      Value *low = B.CreateZExt(call->getArgOperand(1), i64Ty);
      Value *upper = B.CreateZExt(call->getArgOperand(2), i64Ty);

      Value *v = B.CreateAdd(B.CreateShl(upper, 32), low);
      Value *quotient = B.CreateUDiv(v, divisor);
      Value *remainder = B.CreateURem(v, divisor);

      StructType *type = cast<StructType>(call->getType());
      Value *empty = UndefValue::get(type);
      Value *setQuotient = B.CreateInsertValue(empty, quotient, {0});
      Value *replace = B.CreateInsertValue(setQuotient, remainder, {1});
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleCpuid(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CPUID, false);
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    FunctionCallee ndf = getNondetFn(i32Ty, M);
    StructType *cpuidRetType = StructType::create(ctx);
    cpuidRetType->setBody({i32Ty, i32Ty, i32Ty, i32Ty});
    // return nondet values for eax, ebx, ecx, and edx
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *eax = B.CreateCall(ndf);
      Value *ebx = B.CreateCall(ndf);
      Value *ecx = B.CreateCall(ndf);
      Value *edx = B.CreateCall(ndf);

      Value *empty = UndefValue::get(cpuidRetType);
      Value *setEax = B.CreateInsertValue(empty, eax, {0});
      Value *setEbx = B.CreateInsertValue(setEax, ebx, {1});
      Value *setEcx = B.CreateInsertValue(setEbx, ecx, {2});
      Value *setEdx = B.CreateInsertValue(setEcx, edx, {3});
      call->replaceAllUsesWith(setEdx);
      call->eraseFromParent();
    }
  }

  void handleCmpxchgl(Module &M) {
    auto replaceCmpxchg = [&](Module &M, const std::string &targetAsm,
                              bool isPrefix, int cmpIdx) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, isPrefix);
      LLVMContext &ctx = M.getContext();
      Type *i8Ty = Type::getInt8Ty(ctx);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *acc = call->getArgOperand(0);
        Value *cmp = call->getArgOperand(cmpIdx);
        Value *new_ = call->getArgOperand(1);
        AtomicCmpXchgInst *inst =
            B.CreateAtomicCmpXchg(acc, cmp, new_, MaybeAlign(),
                                  AtomicOrdering::SequentiallyConsistent,
                                  AtomicOrdering::SequentiallyConsistent);

        // convert {ty, i1} to {i8, ty}
        Value *val = B.CreateExtractValue(inst, {0});
        Value *isSuccess = B.CreateExtractValue(inst, {1});
        StructType *type = cast<StructType>(call->getType());
        Value *castedSuccess = B.CreateZExt(isSuccess, i8Ty);
        Value *empty = UndefValue::get(type);
        Value *converted = B.CreateInsertValue(empty, castedSuccess, {0});
        Value *completed = B.CreateInsertValue(converted, val, {1});

        call->replaceAllUsesWith(completed);
        call->eraseFromParent();
      }
    };

    replaceCmpxchg(M, CMPXCHGL31_PREFIX, true, 3);
    replaceCmpxchg(M, CMPXCHGL21, false, 2);
  }

  void handleCmpxchg8b(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CMPXCHG8B, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      Value *lower = call->getArgOperand(1);
      Value *upper = call->getArgOperand(2);
      Value *prev = call->getArgOperand(3);
      Value *shiftedUpper = B.CreateShl(upper, B.getInt64(32));
      Value *new_ = B.CreateOr(shiftedUpper, lower);
      AtomicCmpXchgInst *cmpxchg = B.CreateAtomicCmpXchg(
          val, prev, new_, MaybeAlign(), AtomicOrdering::SequentiallyConsistent,
          AtomicOrdering::SequentiallyConsistent);
      call->replaceAllUsesWith(cmpxchg);
      call->eraseFromParent();
    }
  }

  void handleFFS(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, FFS, false);
    LLVMContext &ctx = M.getContext();
    Function *cttz =
        Intrinsic::getDeclaration(&M, Intrinsic::cttz, {Type::getInt32Ty(ctx)});
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *v = call->getArgOperand(0);
      Value *zero = B.getInt32(0);
      Value *isZero = B.CreateICmpEQ(v, zero);
      Value *cttzCall = B.CreateCall(cttz, {v, B.getFalse()});
      Value *nonZero = B.CreateAdd(cttzCall, B.getInt32(1));
      Value *replace = B.CreateSelect(isZero, zero, nonZero);
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleFLS(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, FLS, false);
    LLVMContext &ctx = M.getContext();
    Function *ctlz =
        Intrinsic::getDeclaration(&M, Intrinsic::ctlz, {Type::getInt32Ty(ctx)});
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *v = call->getArgOperand(0);
      Value *zero = B.getInt32(0);
      Value *isZero = B.CreateICmpEQ(v, zero);
      Value *ctlzCall = B.CreateCall(ctlz, {v, B.getFalse()});
      Value *nonZero = B.CreateSub(B.getInt32(32), ctlzCall);
      Value *replace = B.CreateSelect(isZero, zero, nonZero);
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleHWeight(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, HWEIGHT, false);
    LLVMContext &ctx = M.getContext();
    Function *ctpop = Intrinsic::getDeclaration(&M, Intrinsic::ctpop,
                                                {Type::getInt32Ty(ctx)});
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *v = call->getArgOperand(0);
      Value *ctpopCall = B.CreateCall(ctpop, {v});
      call->replaceAllUsesWith(ctpopCall);
      call->eraseFromParent();
    }
  }

  void handleNativeReadMSRSafe(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, NATIVE_READ_MSR_SAFE, false);
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt8Ty(ctx);
    Type *i64Ty = Type::getInt8Ty(ctx);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      StructType *type = cast<StructType>(call->getType());
      // return {0 (success), 0 (msr value)} for now.
      Value *empty = UndefValue::get(type);
      Value *setSuccess =
          B.CreateInsertValue(empty, Constant::getNullValue(i32Ty), {0});
      Value *retVal =
          B.CreateInsertValue(setSuccess, Constant::getNullValue(i64Ty), {1});
      call->replaceAllUsesWith(retVal);
      call->eraseFromParent();
    }
  }

  void handleNativeWriteMSRSafe(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, NATIVE_WRITE_MSR_SAFE, false);
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt8Ty(ctx);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      // return 0 (success) for now.
      Value *zero = Constant::getNullValue(i32Ty);
      call->replaceAllUsesWith(zero);
      call->eraseFromParent();
    }
  }

  void handleRDMSR(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, RDMSR, false);
    LLVMContext &ctx = M.getContext();
    Type *i64Ty = Type::getInt64Ty(ctx);
    FunctionCallee ndf = getNondetFn(i64Ty, M);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      // return a nondet unsigned long long for now.
      Value *ret = B.CreateCall(ndf);
      call->replaceAllUsesWith(ret);
      call->eraseFromParent();
    }
  }

  void handleWRMSR(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, WRMSR, false);
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt8Ty(ctx);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      // return 0 (success) for now.
      Value *zero = Constant::getNullValue(i32Ty);
      call->replaceAllUsesWith(zero);
      call->eraseFromParent();
    }
  }

  void handleAtomic64Read(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CALL1, false);
    LLVMContext &ctx = M.getContext();
    StructType *atomic64Type =
        StructType::getTypeByName(ctx, "struct.atomic64_t");
    Type *i64Ty = Type::getInt64Ty(ctx);
    for (CallInst *call : calls) {
      if (!call->getNumOperands())
        continue;
      Value *op = call->getOperand(0);
      if (!op->hasName() || !op->getName().equals("atomic64_read_cx8"))
        continue;
      Value *v = call->getOperand(1);
      IRBuilder<> B(call);
      Value *counterPtr =
          B.CreateStructGEP(atomic64Type, v, ATOMIC64_COUNTER_INDEX);
      Value *counter = B.CreateLoad(i64Ty, counterPtr);
      call->replaceAllUsesWith(counter);
      call->eraseFromParent();
    }
  }

  void handleAtomic64Set(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CALL0, false);
    LLVMContext &ctx = M.getContext();
    StructType *atomic64Type =
        StructType::getTypeByName(ctx, "struct.atomic64_t");
    for (CallInst *call : calls) {
      if (!call->getNumOperands())
        continue;
      Value *op = call->getOperand(0);
      if (!op->hasName() || !op->getName().equals("atomic64_set_cx8"))
        continue;
      Value *v = call->getOperand(1);
      Value *i = call->getOperand(2);
      IRBuilder<> B(call);
      Value *counterPtr =
          B.CreateStructGEP(atomic64Type, v, ATOMIC64_COUNTER_INDEX);
      Value *set = B.CreateStore(i, counterPtr);
      call->replaceAllUsesWith(set);
      call->eraseFromParent();
    }
  }

  void handleAtomic64AddReturn(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CALL2, false);
    LLVMContext &ctx = M.getContext();
    StructType *atomic64Type =
        StructType::getTypeByName(ctx, "struct.atomic64_t");
    Type *i64Ty = Type::getInt64Ty(ctx);
    for (CallInst *call : calls) {
      if (!call->getNumOperands())
        continue;
      Value *op = call->getOperand(0);
      if (!op->hasName() || !op->getName().equals("atomic64_add_return_cx8"))
        continue;
      Value *i = call->getOperand(2);
      Value *v = call->getOperand(3);
      IRBuilder<> B(call);
      Value *counterPtr =
          B.CreateStructGEP(atomic64Type, v, ATOMIC64_COUNTER_INDEX);
      Value *counter = B.CreateLoad(i64Ty, counterPtr);
      Value *add = B.CreateAdd(counter, i);
      B.CreateStore(add, counterPtr);
      call->replaceAllUsesWith(add);
      call->eraseFromParent();
    }
  }

  void handleAtomic64SubReturn(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CALL2, false);
    LLVMContext &ctx = M.getContext();
    StructType *atomic64Type =
        StructType::getTypeByName(ctx, "struct.atomic64_t");
    Type *i64Ty = Type::getInt64Ty(ctx);
    for (CallInst *call : calls) {
      if (!call->getNumOperands())
        continue;
      Value *op = call->getOperand(0);
      if (!op->hasName() || !op->getName().equals("atomic64_sub_return_cx8"))
        continue;
      Value *i = call->getOperand(2);
      Value *v = call->getOperand(3);
      IRBuilder<> B(call);
      Value *counterPtr =
          B.CreateStructGEP(atomic64Type, v, ATOMIC64_COUNTER_INDEX);
      Value *counter = B.CreateLoad(i64Ty, counterPtr);
      Value *sub = B.CreateSub(counter, i);
      B.CreateStore(sub, counterPtr);
      call->replaceAllUsesWith(sub);
      call->eraseFromParent();
    }
  }

  void handleNativeSaveFL(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, NATIVE_SAVE_FL, false);
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    FunctionCallee ndf = getNondetFn(i32Ty, M);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      // return a nondet unsigned long for now.
      Value *ret = B.CreateCall(ndf);
      call->replaceAllUsesWith(ret);
      call->eraseFromParent();
    }
  }

  void handleCLI(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CLI, false);
    // simply ignore the CLI instruction.
    for (CallInst *call : calls)
      call->eraseFromParent();
  }

  void handleSTI(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, STI, false);
    // simply ignore the STI instruction.
    for (CallInst *call : calls)
      call->eraseFromParent();
  }

  void handleRDPMC(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, RDPMC, false);
    Type *i64Ty = Type::getInt64Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      // return a nondet unsigned long long for now.
      FunctionCallee ndf = getNondetFn(i64Ty, M);
      Value *ret = B.CreateCall(ndf);
      call->replaceAllUsesWith(ret);
      call->eraseFromParent();
    }
  }

  void handleArrayIndexMaskNoSpec(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, ARRAY_INDEX_MASK_NOSPEC, false);
    for (CallInst *call : calls) {
      Value *index = call->getArgOperand(1);
      Value *size = call->getArgOperand(0);
      IRBuilder<> B(call);
      Value *isOk = B.CreateICmpULT(index, size);
      Value *mask = B.CreateSelect(isOk, B.getInt32(0xffffffff), B.getInt32(0));
      call->replaceAllUsesWith(mask);
      call->eraseFromParent();
    }
  }

  void handleGetUser(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, GET_USER, false, GET_USER_CONSTRAINTS);
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *addr = call->getArgOperand(0);
      Value *stackPointer = call->getArgOperand(2);
      StructType *type = cast<StructType>(call->getType());

      Value *empty = UndefValue::get(type);
      Value *ok = B.CreateInsertValue(empty, B.getInt32(0), {0});
      Value *loaded = B.CreateLoad(i32Ty, addr);
      Value *setLoaded = B.CreateInsertValue(ok, loaded, {1});
      Value *completed = B.CreateInsertValue(setLoaded, stackPointer, {2});
      call->replaceAllUsesWith(completed);
      call->eraseFromParent();
    }
  }

  void insertMain(Module &M) {
    if (M.getFunction("main")) {
      LOG("ACPI", errs() << "ACPI: Main already exists.\n");
      return;
    }

    Type *i32Ty = Type::getInt32Ty(M.getContext());
    ArrayRef<Type *> params;
    Function::Create(FunctionType::get(i32Ty, params, false),
                     GlobalValue::LinkageTypes::ExternalLinkage, "main", &M);
  }

  void updateFunctionLinkage(Module &M) {
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      if (!F.getName().equals("main"))
        F.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    }
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

  FunctionCallee getNondetFn(Type *type, Module &M) {
    auto it = ndfn.find(type);
    if (it != ndfn.end()) {
      return it->second;
    }

    FunctionCallee res =
        makeNewNondetFn(M, *type, ndfn.size(), "verifier.nondet.");
    ndfn[type] = res;
    return res;
  }
};

char KernelSetup::ID = 0;

Pass *createKernelSetupPass() { return new KernelSetup(); }
} // namespace seahorn
