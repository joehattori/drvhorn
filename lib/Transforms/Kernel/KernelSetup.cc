#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Pass.h"

#include "boost/range.hpp"
#include "seahorn/Support/SeaDebug.h"

#include <algorithm>
#include <optional>
#include <regex>

using namespace llvm;

#define currentTaskAsm "movl ${1:P}, $0"
#define currentTaskConstraints "=r,im,~{dirflag},~{fpsr},~{flags}"

#define barrierConstraints "~{memory},~{dirflag},~{fpsr},~{flags}"

#define bitTestAsmPrefix " btl  $2,$1"
#define bitTestAndSetAsmPrefix " btsl  $1,$0"
#define bitTestAndResetAsmPrefix " btrl  $1,$0"

#define inclAsm "incl $0"
#define declAsmPrefix "decl $0"
#define xaddlAsmPrefix "xaddl $0, $1"
#define movlAsm "movl $1, $0"
#define addlAsm "addl $1, $0"
#define atomicFetchAndUnlessAsmPrefix "cmpxchgl $3, $1"
#define atomicFetchAndUnlessAsmConstraints                                     \
  "={@ccz},=*m,={ax},r,*m,2,~{memory},~{dirflag},~{fpsr},~{flags}"
#define ffsAsm "rep; bsf $1,$0"
#define hweightAsm                                                             \
  "# ALT: oldnstr;661:;call __sw_hweight32;662:;# ALT: padding;.skip "         \
  "-(((6651f-6641f)-(662b-661b)) > 0) * "                                      \
  "((6651f-6641f)-(662b-661b)),0x90;663:;.pushsection .altinstructions,'a'; "  \
  ".long 661b - .; .long 6641f - .; .word ( 4*32+23); .byte 663b-661b; .byte " \
  "6651f-6641f;.popsection;.pushsection .altinstr_replacement, 'ax';# ALT: "   \
  "replacement 1;6641:;popcntl $1, $0;6651:;.popsection;"
#define nativeReadMSRSafeAsm                                                   \
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
#define nativeWriteMSRSafeAsm                                                  \
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
    handleCurrentTask(M);
    handleBarrier(M);
    handleBitTest(M);
    handleBitTestAndSet(M);
    handleBitTestAndReset(M);
    handleIncl(M);
    handleDecl(M);
    handleXAddl(M);
    handleMovl(M);
    handleAddl(M);
    handleAtomicFetchAndUnless(M);
    handleFFS(M);
    handleHWeight(M);
    handleNativeReadMSRSafe(M);
    handleNativeWriteMSRSafe(M);
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
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, currentTaskAsm, false, currentTaskConstraints);
    for (CallInst *call : calls) {
      Value *task = call->getArgOperand(0);
      call->replaceAllUsesWith(task);
      call->eraseFromParent();
    }
  }

  void handleBarrier(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, "", false, barrierConstraints);
    for (CallInst *call : calls)
      call->eraseFromParent();
  }

  Value *bitAddr(IRBuilder<> &B, Value *base, Value *offset) {
    Value *idx = B.CreateAShr(offset, B.getInt32(8));
    return B.CreateAdd(base, idx);
  }

  void handleBitTest(Module &M) {
    LLVMContext &ctx = M.getContext();
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, bitTestAsmPrefix, true);
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
        getTargetAsmCalls(M, bitTestAndSetAsmPrefix, true);
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
        getTargetAsmCalls(M, bitTestAndResetAsmPrefix, true);
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
    std::vector<CallInst *> calls = getTargetAsmCalls(M, inclAsm, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      Value *inc = B.CreateAdd(val, B.getInt32(1));
      call->replaceAllUsesWith(inc);
      call->eraseFromParent();
    }
  }

  void handleDecl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, declAsmPrefix, true);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      Value *dec = B.CreateSub(val, B.getInt32(1));
      call->replaceAllUsesWith(dec);
      call->eraseFromParent();
    }
  }

  void handleXAddl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, xaddlAsmPrefix, true);
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
    std::vector<CallInst *> calls = getTargetAsmCalls(M, movlAsm, false);
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
    std::vector<CallInst *> calls = getTargetAsmCalls(M, addlAsm, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *dst = call->getArgOperand(0);
      Value *src = call->getArgOperand(1);

      Value *add = B.CreateAdd(dst, src);
      call->replaceAllUsesWith(add);
      call->eraseFromParent();
    }
  }

  void handleAtomicFetchAndUnless(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, atomicFetchAndUnlessAsmPrefix, true,
                          atomicFetchAndUnlessAsmConstraints);
    LLVMContext &ctx = M.getContext();
    Type *i8Ty = Type::getInt8Ty(ctx);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *acc = call->getArgOperand(0);
      Value *cmp = call->getArgOperand(3);
      Value *new_ = call->getArgOperand(1);
      AtomicCmpXchgInst *inst = B.CreateAtomicCmpXchg(
          acc, cmp, new_, MaybeAlign(), AtomicOrdering::SequentiallyConsistent,
          AtomicOrdering::SequentiallyConsistent);

      // convert {ty, i1} to {i8, ty}
      Value *val = B.CreateExtractValue(inst, {0});
      Value *isSuccess = B.CreateExtractValue(inst, {1});
      StructType *type = cast<StructType>(call->getType());
      Value *castedSuccess = B.CreateZExt(isSuccess, i8Ty);
      Value *converted =
          B.CreateInsertValue(UndefValue::get(type), castedSuccess, {0});
      Value *completed = B.CreateInsertValue(converted, val, {1});

      call->replaceAllUsesWith(completed);
      call->eraseFromParent();
    }
  }

  void handleFFS(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, ffsAsm, false);
    LLVMContext &ctx = M.getContext();
    Function *cttz =
        Intrinsic::getDeclaration(&M, Intrinsic::cttz, {Type::getInt32Ty(ctx)});
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *v = call->getArgOperand(0);
      Value *zero = B.getFalse();
      Value *cttzCall = B.CreateCall(cttz, {v, zero});
      call->replaceAllUsesWith(cttzCall);
      call->eraseFromParent();
    }
  }

  void handleHWeight(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, hweightAsm, false);
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
        getTargetAsmCalls(M, nativeReadMSRSafeAsm, false);
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt8Ty(ctx);
    Type *i64Ty = Type::getInt8Ty(ctx);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      StructType *type = cast<StructType>(call->getType());
      // return {0 (success), 0 (msr value)} for now.
      Value *empty = B.CreateInsertValue(UndefValue::get(type),
                                         Constant::getNullValue(i32Ty), {0});
      Value *retVal =
          B.CreateInsertValue(empty, Constant::getNullValue(i64Ty), {1});
      call->replaceAllUsesWith(retVal);
      call->eraseFromParent();
    }
  }

  void handleNativeWriteMSRSafe(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, nativeWriteMSRSafeAsm, false);
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
};

char KernelSetup::ID = 0;

Pass *createKernelSetupPass() { return new KernelSetup(); }
} // namespace seahorn
