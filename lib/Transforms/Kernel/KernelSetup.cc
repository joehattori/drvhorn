#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Constants.h"
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

#define BARRIER_CONSTRAINTS "~{memory},~{dirflag},~{fpsr},~{flags}"
#define SPLIT_U64_CONSTRAINTS "={ax},={dx},A,~{dirflag},~{fpsr},~{flags}"
#define BUILD_U64_CONSTRAINTS "=A,{ax},{dx},~{dirflag},~{fpsr},~{flags}"
#define ARCH_ATOMIC64_XCHG_CONSTRAINTS                                         \
  "=&A,i,{si},{bx},{cx},~{memory},~{dirflag},~{fpsr},~{flags}"
#define OPTIMIZER_HIDE_VAR_CONSTRAINTS "=r,0,~{dirflag},~{fpsr},~{flags}"

#define BIT_TEST_PREFIX "btl $2,$1"
#define BIT_TEST_AND_SET_1_0_PREFIX "btsl $1,$0"
#define BIT_TEST_AND_SET_2_0_PREFIX "btsl $2,$0"
#define BIT_TEST_AND_SET_2_1_PREFIX "btsl $2,$1"
#define BIT_TEST_AND_RESET_1_0_PREFIX "btrl $1,$0"
#define BIT_TEST_AND_RESET_2_1_PREFIX "btrl $2,$1"

#define INCL "incl $0"
#define DECL_PREFIX "decl $0"
#define XADDL_PREFIX "xaddl $0,$1"
#define MOVB_0_1 "movb $0,$1"
#define MOVB_1_0 "movb $1,$0"
#define MOVW_0_1 "movw $0,$1"
#define MOVW_1_0 "movw $1,$0"
#define MOVL_0_1 "movl $0,$1"
#define MOVL_1_0 "movl $1,$0"
#define MOVL_POSITION_INDEPENDENT "movl ${1:P},$0"
#define ADDL "addl $1,$0"
#define ANDB "andb ${1:b},$0"
#define ANDL "andl $1,$0"
#define MULL "mull $3"
#define DIVL "divl $2"
#define ORB "orb ${1:b},$0"
#define ORL "orl $1,$0"
#define CMPXCHGL21 "cmpxchgl $2,$1"
#define CMPXCHGL31_PREFIX "cmpxchgl $3,$1"
#define CMPXCHG8B "cmpxchg8b $1"
#define XCHGL "xchgl $0,$1;"
#define XCGHL_CONSTRAINTS                                                      \
  "=r,=*m,0,*m,~{memory},~{cc},~{dirflag},~{fpsr},~{flags}"
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
#define INB "inb ${1:w},${0:b}"
#define INW "inw ${1:w},${0:w}"
#define INL "inl ${1:w},$0"
#define OUTB "outb ${0:b},${1:w}"
#define OUTW "outw ${0:w},${1:w}"
#define OUTL "outl $0,${1:w}"
#define OUT_AL_0x80 "outb %al,$$0x80"
#define OUT_AL_0xed "outb %al,$$0xed"

#define UD2 ".byte 0x0f,0x0b"
#define SERIALIZE ".byte 0xf,0x1,0xe8"
#define IRET_TO_SELF "pushfl;pushl %cs;pushl $$1f;iret;1:"
#define SET_DEBUG_REGISTER_PREFIX "mov $0,%db"
#define NOP "rep; nop"

#define LOAD_CR3 "mov $0,%cr3"
#define LIDT "lidt $0"

#define GET_USER "call __get_user_nocheck_${4:P}"
#define GET_USER_CONSTRAINTS                                                   \
  "={ax},={edx},={esp},0,i,{esp},~{dirflag},~{fpsr},~{flags}"

#define CALL_ON_STACK "xchgl%ebx,%esp;call *$2;movl%ebx,%esp;"

#define HWEIGHT                                                                \
  "# ALT: oldnstr;661:;call __sw_hweight32;662:;# ALT: padding;.skip "         \
  "-(((6651f-6641f)-(662b-661b)) > 0) * "                                      \
  "((6651f-6641f)-(662b-661b)),0x90;663:;.pushsection "                        \
  ".altinstructions,\"a\"; "                                                   \
  ".long 661b - .; .long 6641f - .; .word ( 4*32+23); .byte 663b-661b; .byte " \
  "6651f-6641f;.popsection;.pushsection .altinstr_replacement,\"ax\";# ALT: "  \
  "replacement 1;6641:;popcntl $1,$0;6651:;.popsection"
#define NATIVE_READ_MSR_SAFE                                                   \
  "1: rdmsr ; xor $0,$0;2:; .pushsection \"__ex_table\",\"a\"; .balign 4; "    \
  ".long "                                                                     \
  "(1b) - .; .long (2b) - .;.macro extable_type_reg type:req reg:req;.set "    \
  ".Lfound,0;.set .Lregnr,0;.irp "                                             \
  "rs,rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15;.ifc "     \
  "\\reg,%\\rs;.set .Lfound,.Lfound+1;.long \\type + (.Lregnr << "             \
  "8);.endif;.set .Lregnr,.Lregnr+1;.endr;.set .Lregnr,0;.irp "                \
  "rs,eax,ecx,edx,ebx,esp,ebp,esi,edi,r8d,r9d,r10d,r11d,r12d,r13d,r14d,r15d;." \
  "ifc \\reg,%\\rs;.set .Lfound,.Lfound+1;.long \\type + (.Lregnr << "         \
  "8);.endif;.set .Lregnr,.Lregnr+1;.endr;.if (.Lfound != 1);.error "          \
  "\"extable_type_reg: bad register argument\";.endif;.endm;extable_type_reg " \
  "reg=$0,type=11 ;.purgem extable_type_reg; .popsection"
#define NATIVE_WRITE_MSR_SAFE                                                  \
  "1: wrmsr ; xor $0,$0;2:; .pushsection \"__ex_table\",\"a\"; .balign 4; "    \
  ".long "                                                                     \
  "(1b) - .; .long (2b) - .;.macro extable_type_reg type:req reg:req;.set "    \
  ".Lfound,0;.set .Lregnr,0;.irp "                                             \
  "rs,rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15;.ifc "     \
  "\\reg,%\\rs;.set .Lfound,.Lfound+1;.long \\type + (.Lregnr << "             \
  "8);.endif;.set .Lregnr,.Lregnr+1;.endr;.set .Lregnr,0;.irp "                \
  "rs,eax,ecx,edx,ebx,esp,ebp,esi,edi,r8d,r9d,r10d,r11d,r12d,r13d,r14d,r15d;." \
  "ifc \\reg,%\\rs;.set .Lfound,.Lfound+1;.long \\type + (.Lregnr << "         \
  "8);.endif;.set .Lregnr,.Lregnr+1;.endr;.if (.Lfound != 1);.error "          \
  "\"extable_type_reg: bad register argument\";.endif;.endm;extable_type_reg " \
  "reg=$0,type=10 ;.purgem extable_type_reg; .popsection"
#define RDMSR                                                                  \
  "1: rdmsr;2:; .pushsection \"__ex_table\",\"a\"; .balign 4; .long (1b) - "   \
  ".; "                                                                        \
  ".long (2b) - .; .long 9 ; .popsection"
#define WRMSR                                                                  \
  "1: wrmsr;2:; .pushsection \"__ex_table\",\"a\"; .balign 4; .long (1b) - "   \
  ".; "                                                                        \
  ".long (2b) - .; .long 8 ; .popsection"
#define MB                                                                     \
  "# ALT: oldnstr;661:;lock; addl $$0,-4(%esp);662:;# ALT: padding;.skip "     \
  "-(((6651f-6641f)-(662b-661b)) > 0) * "                                      \
  "((6651f-6641f)-(662b-661b)),0x90;663:;.pushsection "                        \
  ".altinstructions,\"a\"; "                                                   \
  ".long 661b - .; .long 6641f - .; .word ( 0*32+26); .byte 663b-661b; .byte " \
  "6651f-6641f;.popsection;.pushsection .altinstr_replacement,\"ax\";# ALT: "  \
  "replacement 1;6641:;mfence;6651:;.popsection"
#define RMB                                                                    \
  "# ALT: oldnstr;661:;lock; addl $$0,-4(%esp);662:;# ALT: padding;.skip "     \
  "-(((6651f-6641f)-(662b-661b)) > 0) * "                                      \
  "((6651f-6641f)-(662b-661b)),0x90;663:;.pushsection "                        \
  ".altinstructions,\"a\"; "                                                   \
  ".long 661b - .; .long 6641f - .; .word ( 0*32+26); .byte 663b-661b; .byte " \
  "6651f-6641f;.popsection;.pushsection .altinstr_replacement,\"ax\";# ALT: "  \
  "replacement 1;6641:;lfence;6651:;.popsection"
#define WMB                                                                    \
  "# ALT: oldnstr;661:;lock; addl $$0,-4(%esp);662:;# ALT: padding;.skip "     \
  "-(((6651f-6641f)-(662b-661b)) > 0) * "                                      \
  "((6651f-6641f)-(662b-661b)),0x90;663:;.pushsection "                        \
  ".altinstructions,\"a\"; "                                                   \
  ".long 661b - .; .long 6641f - .; .word ( 0*32+26); .byte 663b-661b; .byte " \
  "6651f-6641f;.popsection;.pushsection .altinstr_replacement,\"ax\";# ALT: "  \
  "replacement 1;6641:;sfence;6651:;.popsection"
#define LOAD_GS                                                                \
  "1:movl ${0:k},%gs; .pushsection \"__ex_table\",\"a\"; .balign 4; .long "    \
  "(1b) "                                                                      \
  "- .; .long (1b) - .;.macro extable_type_reg type:req reg:req;.set "         \
  ".Lfound,0;.set .Lregnr,0;.irp "                                             \
  "rs,rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8,r9,r10,r11,r12,r13,r14,r15;.ifc "     \
  "\\reg,%\\rs;.set .Lfound,.Lfound+1;.long \\type + (.Lregnr << "             \
  "8);.endif;.set .Lregnr,.Lregnr+1;.endr;.set .Lregnr,0;.irp "                \
  "rs,eax,ecx,edx,ebx,esp,ebp,esi,edi,r8d,r9d,r10d,r11d,r12d,r13d,r14d,r15d;." \
  "ifc \\reg,%\\rs;.set .Lfound,.Lfound+1;.long \\type + (.Lregnr << "         \
  "8);.endif;.set .Lregnr,.Lregnr+1;.endr;.if (.Lfound != 1);.error "          \
  "\"extable_type_reg: bad register argument\";.endif;.endm;extable_type_reg " \
  "reg=${0:k},type=(17 $| ((0) << 16)) ;.purgem extable_type_reg; "            \
  ".popsection;"
#define RDTSC "rdtsc"
#define RDTSC_ORDERED                                                          \
  "# ALT: oldinstr2;661:;rdtsc;662:;# ALT: padding2;.skip -((((6651f-6641f) "  \
  "^ (((6651f-6641f) ^ (6652f-6642f)) & -(-((6651f-6641f) < "                  \
  "(6652f-6642f))))) - (662b-661b)) > 0) * (((6651f-6641f) ^ (((6651f-6641f) " \
  "^ (6652f-6642f)) & -(-((6651f-6641f) < (6652f-6642f))))) - "                \
  "(662b-661b)),0x90;663:;.pushsection .altinstructions,\"a\"; .long 661b "    \
  "- .; .long 6641f - .; .word ( 3*32+18); .byte 663b-661b; .byte "            \
  "6651f-6641f; .long 661b - .; .long 6642f - .; .word ( 1*32+27); .byte "     \
  "663b-661b; .byte 6652f-6642f;.popsection;.pushsection "                     \
  ".altinstr_replacement,\"ax\";# ALT: replacement 1;6641:;lfence; "           \
  "rdtsc;6651:;# ALT: replacement 2;6642:;rdtscp;6652:;.popsection"

#define NATIVE_SAVE_FL "# __raw_save_flags;pushf ; pop $0"

#define ATOMIC64_COUNTER_INDEX 0

namespace seahorn {

class KernelSetup : public ModulePass {
public:
  static char ID;

  KernelSetup() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    handleMalloc(M);
    handleFree(M);
    handleKmemCache(M);

    handleMemcpy(M);
    handleMemMove(M);
    handleStrCopy(M);
    handleStrNCopy(M);
    handleStrCat(M);
    handleStrCmp(M);
    handleStrNCmp(M);
    handleStrChr(M);
    handleStrLen(M);
    handleStrNLen(M);

    handleAcpiDivide(M);

    handleInlineAssembly(M);
    insertMain(M);
    return true;
  }

  virtual StringRef getPassName() const override { return "KernelSetup"; }

private:
  DenseMap<const Type *, FunctionCallee> ndfn;

  void handleMalloc(Module &M) {
    LLVMContext &ctx = M.getContext();
    Type *addrType = Type::getInt8Ty(ctx)->getPointerTo();
    FunctionCallee nd = getNondetFn(addrType, M);
    std::string mallocFuncNames[] = {
        "__kmalloc",     "__kmalloc_node",     "__kmalloc_node_track_caller",
        "kmalloc_large", "kmalloc_large_node", "__vmalloc_node_range",
        "pcpu_alloc",
    };
    for (const std::string &name : mallocFuncNames) {
      std::string wrapperName = name + "_wrapper";
      Function *orig = M.getFunction(name);
      if (!orig)
        continue;

      Function *wrapper = Function::Create(
          orig->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
          wrapperName, &M);
      BasicBlock *block = BasicBlock::Create(ctx, "", wrapper);
      CallInst *call = CallInst::Create(nd, "", block);
      ReturnInst::Create(ctx, call, block);
      orig->replaceAllUsesWith(wrapper);
      orig->eraseFromParent();
    }
  }

  void handleFree(Module &M) {
    LLVMContext &ctx = M.getContext();
    Type *addrType = Type::getInt8Ty(ctx)->getPointerTo();
    Type *voidType = Type::getVoidTy(ctx);
    FunctionType *freeStubType = FunctionType::get(voidType, {addrType}, false);
    FunctionCallee nd = M.getOrInsertFunction("free_stub", freeStubType);
    std::string freeFuncNames[] = {
        "kfree",
        "vfree",
    };
    for (const std::string &name : freeFuncNames) {
      std::string wrapperName = name + "_wrapper";
      Function *orig = M.getFunction(name);
      if (!orig)
        continue;

      Function *wrapper = Function::Create(
          orig->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
          wrapperName, &M);
      BasicBlock *block = BasicBlock::Create(ctx, "", wrapper);
      Argument *addr = wrapper->getArg(0);
      CallInst::Create(nd, {addr}, "", block);
      ReturnInst::Create(ctx, nullptr, block);
      orig->replaceAllUsesWith(wrapper);
      orig->eraseFromParent();
    }
  }

  void handleKmemCache(Module &M) {
    LLVMContext &ctx = M.getContext();
    std::string kmemCacheFuncNames[] = {
        "kmem_cache_create", "kmem_cache_alloc",   "kmem_cache_alloc_lru",
        "kmem_cache_free",   "kmem_cache_destroy",
    };
    for (const std::string &name : kmemCacheFuncNames) {
      Function *orig = M.getFunction(name);
      if (!orig)
        continue;
      Type *retType = orig->getReturnType();
      FunctionCallee nd = getNondetFn(retType, M);
      std::string wrapperName = name + "_wrapper";
      Function *wrapper = Function::Create(
          orig->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
          wrapperName, &M);
      BasicBlock *block = BasicBlock::Create(ctx, "", wrapper);
      CallInst *call = CallInst::Create(nd, "", block);
      if (retType->isVoidTy()) {
        ReturnInst::Create(ctx, nullptr, block);
      } else {
        ReturnInst::Create(ctx, call, block);
      }
      orig->replaceAllUsesWith(wrapper);
      orig->eraseFromParent();
    }
  }

  void handleMemcpy(Module &M) {
    enum RetType {
      Void,
      Len,
      Dest,
    };

    struct MemcpyInfo {
      std::string name;
      RetType returnType;
    };

    LLVMContext &ctx = M.getContext();
    MemcpyInfo memcpyFuncNames[] = {
        MemcpyInfo{"memcpy", RetType::Dest},
        MemcpyInfo{"memcpy_fromio", RetType::Void},
        MemcpyInfo{"memcpy_toio", RetType::Void},
        MemcpyInfo{"__copy_user_ll", RetType::Len},
        MemcpyInfo{"__copy_user_ll_nocache_nozero", RetType::Len},
    };
    for (const MemcpyInfo &info : memcpyFuncNames) {
      Function *f = M.getFunction(info.name);
      if (!f)
        continue;
      std::string wrapperName = info.name + "_wrapper";
      Function *wrapper = Function::Create(
          f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
          wrapperName, &M);
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

  void handleMemMove(Module &M) {
    LLVMContext &ctx = M.getContext();
    Function *f = M.getFunction("memmove");
    if (!f)
      return;
    std::string wrapperName = "memmove_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
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

  void handleStrCopy(Module &M) {
    LLVMContext &ctx = M.getContext();
    Function *f = M.getFunction("strcpy");
    if (!f)
      return;
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i64Type = Type::getInt64Ty(ctx);
    std::string wrapperName = "strcpy_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
    Value *dst = wrapper->getArg(0);
    Value *src = wrapper->getArg(1);

    BasicBlock *entry = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loopCond = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loopBody = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *end = BasicBlock::Create(ctx, "", wrapper);

    IRBuilder<> B(entry);
    Value *it = B.CreateAlloca(i64Type);
    B.CreateStore(B.getInt64(0), it);
    B.CreateBr(loopCond);

    B.SetInsertPoint(loopCond);
    Value *srcPtr = B.CreateGEP(i8Type, src, B.CreateLoad(i64Type, it));
    Value *srcChar = B.CreateLoad(i8Type, srcPtr);
    Value *isEnd = B.CreateICmpEQ(srcChar, B.getInt8(0));
    B.CreateCondBr(isEnd, end, loopBody);

    B.SetInsertPoint(loopBody);
    Value *loadedIt = B.CreateLoad(i64Type, it);
    Value *dstPtr = B.CreateGEP(i8Type, dst, loadedIt);
    B.CreateStore(srcChar, dstPtr);
    B.CreateStore(B.CreateAdd(loadedIt, B.getInt64(1)), it);
    B.CreateBr(loopCond);

    B.SetInsertPoint(end);
    B.CreateRet(dst);
    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  void handleStrNCopy(Module &M) {
    Function *f = M.getFunction("strncpy");
    if (!f)
      return;
    LLVMContext &ctx = M.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strncpy_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
    Value *dst = wrapper->getArg(0);
    Value *src = wrapper->getArg(1);
    Value *size = wrapper->getArg(2);

    BasicBlock *entry = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loopCond = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loopBody = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *end = BasicBlock::Create(ctx, "", wrapper);

    IRBuilder<> B(entry);
    Value *it = B.CreateAlloca(i32Type);
    B.CreateStore(B.getInt32(0), it);
    B.CreateBr(loopCond);

    B.SetInsertPoint(loopCond);
    Value *loadedIt = B.CreateLoad(i32Type, it);
    Value *srcPtr = B.CreateGEP(i8Type, src, loadedIt);
    Value *srcChar = B.CreateLoad(i8Type, srcPtr);
    Value *isNull = B.CreateICmpEQ(srcChar, B.getInt8(0));
    Value *isOver = B.CreateICmpUGE(loadedIt, size);
    Value *isEnd = B.CreateOr(isNull, isOver);
    B.CreateCondBr(isEnd, end, loopBody);

    B.SetInsertPoint(loopBody);
    loadedIt = B.CreateLoad(i32Type, it);
    Value *dstPtr = B.CreateGEP(i8Type, dst, loadedIt);
    B.CreateStore(srcChar, dstPtr);
    B.CreateStore(B.CreateAdd(loadedIt, B.getInt32(1)), it);
    B.CreateBr(loopCond);

    B.SetInsertPoint(end);
    B.CreateRet(dst);
    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  void handleStrCat(Module &M) {
    Function *f = M.getFunction("strcat");
    if (!f)
      return;
    LLVMContext &ctx = M.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strcat_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
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

  void handleStrCmp(Module &M) {
    Function *f = M.getFunction("strcmp");
    if (!f)
      return;
    LLVMContext &ctx = M.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strcmp_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
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

  void handleStrNCmp(Module &M) {
    Function *f = M.getFunction("strncmp");
    if (!f)
      return;
    LLVMContext &ctx = M.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strncmp_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
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

  void handleStrChr(Module &M) {
    Function *f = M.getFunction("strchr");
    if (!f)
      return;
    LLVMContext &ctx = M.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strchr_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
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

  void handleStrLen(Module &M) {
    Function *f = M.getFunction("strlen");
    if (!f)
      return;
    LLVMContext &ctx = M.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strlen_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
    Value *str = wrapper->getArg(0);

    BasicBlock *entry = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loop = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loopEnd = BasicBlock::Create(ctx, "", wrapper);
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
    B.CreateCondBr(isNull, ret, loopEnd);

    B.SetInsertPoint(ret);
    B.CreateRet(loadedIt);

    B.SetInsertPoint(loopEnd);
    B.CreateStore(B.CreateAdd(loadedIt, B.getInt32(1)), it);
    B.CreateBr(loop);

    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  void handleStrNLen(Module &M) {
    Function *f = M.getFunction("strnlen");
    if (!f)
      return;
    LLVMContext &ctx = M.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    std::string wrapperName = "strnlen_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
    Value *str = wrapper->getArg(0);
    Value *size = wrapper->getArg(1);

    BasicBlock *entry = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loop = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *loopEnd = BasicBlock::Create(ctx, "", wrapper);
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
    Value *isOver = B.CreateICmpUGE(loadedIt, size);
    Value *isEnd = B.CreateOr(isNull, isOver);
    B.CreateCondBr(isEnd, ret, loopEnd);

    B.SetInsertPoint(ret);
    B.CreateRet(loadedIt);

    B.SetInsertPoint(loopEnd);
    B.CreateStore(B.CreateAdd(loadedIt, B.getInt32(1)), it);
    B.CreateBr(loop);

    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  void handleAcpiDivide(Module &M) {
    Function *f = M.getFunction("acpi_ut_divide");
    if (!f)
      return;
    LLVMContext &ctx = M.getContext();
    Type *i32Type = Type::getInt32Ty(ctx);
    Type *i64Type = Type::getInt64Ty(ctx);
    std::string wrapperName = "acpi_ut_divide_wrapper";
    Function *wrapper = Function::Create(
        f->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
    BasicBlock *block = BasicBlock::Create(ctx, "", wrapper);

    Value *dividend = wrapper->getArg(0);
    Value *divisor = wrapper->getArg(1);
    Value *quotientPtr = wrapper->getArg(2);
    Value *remainderPtr = wrapper->getArg(3);

    BasicBlock *err = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *checkQuotient = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *storeQuotient = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *checkRemainder = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *storeRemainder = BasicBlock::Create(ctx, "", wrapper);
    BasicBlock *end = BasicBlock::Create(ctx, "", wrapper);

    IRBuilder<> B(block);
    Value *divisorIsZero = B.CreateICmpEQ(divisor, B.getInt64(0));
    B.CreateCondBr(divisorIsZero, err, checkQuotient);

    B.SetInsertPoint(err);
    B.CreateRet(ConstantInt::get(i32Type, 0xc));

    B.SetInsertPoint(checkQuotient);
    Value *quotientInt = B.CreatePtrToInt(quotientPtr, i64Type);
    Value *hasDivisor = B.CreateICmpNE(quotientInt, B.getInt64(0));
    B.CreateCondBr(hasDivisor, storeQuotient, checkRemainder);

    B.SetInsertPoint(storeQuotient);
    B.CreateStore(B.CreateUDiv(dividend, divisor), quotientPtr);
    B.CreateBr(checkRemainder);

    B.SetInsertPoint(checkRemainder);
    Value *remainderInt = B.CreatePtrToInt(remainderPtr, i64Type);
    Value *hasRemainder = B.CreateICmpNE(remainderInt, B.getInt64(0));
    B.CreateCondBr(hasRemainder, storeRemainder, end);

    B.SetInsertPoint(storeRemainder);
    B.CreateStore(B.CreateURem(dividend, divisor), remainderPtr);
    B.CreateBr(end);

    B.SetInsertPoint(end);
    B.CreateRet(ConstantInt::get(i32Type, 0x0));

    f->replaceAllUsesWith(wrapper);
    f->eraseFromParent();
  }

  void handleInlineAssembly(Module &M) {
    handleBitTest(M);
    handleBitTestAndSet(M);
    handleBitTestAndReset(M);
    handleFFS(M);
    handleFLS(M);
    // handleHWeight(M);

    handleIncl(M);
    handleDecl(M);
    handleXAddl(M);
    handleAddl(M);
    handleMull(M);
    handleDivl(M);
    handleAndl(M);
    handleOr(M);
    // handleCpuid(M);
    handleIn(M);
    handleOut(M);
    handleMov(M);

    handleAtomic64Read(M);
    handleAtomic64Set(M);
    handleAtomic64AddReturn(M);
    handleAtomic64SubReturn(M);
    handleAtomic64Xchg(M);
    handleXchgl(M);
    handleCmpxchgl(M);
    handleCmpxchg8b(M);

    handleNativeSaveFL(M);
    handleCLI(M);
    handleSTI(M);
    // handleRDPMC(M);

    // handleNativeReadMSRSafe(M);
    // handleNativeWriteMSRSafe(M);
    // handleRDMSR(M);
    // handleWRMSR(M);
    // handleRDTSC(M);
    // handleArrayIndexMaskNoSpec(M);

    handleCurrentTask(M);
    handleBarrier(M);
    removeFunctions(M);
    // handleSerialize(M);
    // handleIretToSelf(M);
    handleDebugRegisters(M);
    // handleLoadGs(M);
    // handleSplitU64(M);
    // handleBuildU64(M);
    // handleCallOnStack(M);
    // handleOptimizerHideVar(M);
    // // handleGetUser(M);
  }

  std::string formatInlineAsm(std::string s) {
    // trim leading whitespace
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char c) {
              return !std::isspace(c);
            }));
    std::regex newLine("\n");
    s = std::regex_replace(s, newLine, ";");
    std::regex tab("\t");
    s = std::regex_replace(s, tab, "");
    std::regex commaSpace(",\\s+");
    s = std::regex_replace(s, commaSpace, ",");
    std::regex spacesBeforeReg("\\s+\\$");
    s = std::regex_replace(s, spacesBeforeReg, " $");
    while (s.back() == ';')
      s.pop_back();
    return s;
  }

  std::vector<CallInst *>
  getTargetAsmCalls(Module &M, const std::string &asmStr, bool isPrefix,
                    const std::string &constraints = "") {
    auto isTargetAsm = [this, &asmStr, isPrefix,
                        constraints](const CallInst *call) {
      const InlineAsm *inlineAsm =
          dyn_cast<InlineAsm>(call->getCalledOperand());
      if (!inlineAsm)
        return false;
      // errs() << "before " << inlineAsm->getAsmString() << "\n";
      std::string formatted = formatInlineAsm(inlineAsm->getAsmString());
      // errs() << "after " << formatted << "\n";
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

  std::vector<CallInst *>
  getTargetAsmCalls(Module &M, const std::set<std::string> &asmStr) {
    auto isTargetAsm = [this, &asmStr](const CallInst *call) {
      const InlineAsm *inlineAsm =
          dyn_cast<InlineAsm>(call->getCalledOperand());
      if (!inlineAsm)
        return false;
      // errs() << "before " << inlineAsm->getAsmString() << "\n";
      std::string formatted = formatInlineAsm(inlineAsm->getAsmString());
      return !!asmStr.count(formatted);
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
      IRBuilder<> B(call);
      Value *arg = call->getArgOperand(0);
      Value *task;
      if (BitCastOperator *bitcast = dyn_cast<BitCastOperator>(arg)) {
        task = bitcast->getOperand(0);
      } else {
        task = arg;
      }
      if (isPtrToPtrToTask(arg->getType()) &&
          task->getName().equals("current_task")) {
        Value *currentTask =
            B.CreateLoad(task->getType()->getPointerElementType(), task);
        Value *cast = B.CreatePtrToInt(currentTask, B.getInt32Ty());
        call->replaceAllUsesWith(cast);
        call->eraseFromParent();
      }
    }
  }

  void handleBarrier(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, "", false, BARRIER_CONSTRAINTS);
    for (CallInst *call : calls)
      call->eraseFromParent();
  }

  void handleIretToSelf(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, IRET_TO_SELF, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      // iret_to_self() pops back the stack pointer.
      Value *sp = call->getArgOperand(0);
      call->replaceAllUsesWith(sp);
      call->eraseFromParent();
    }
  }

  void handleDebugRegisters(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, SET_DEBUG_REGISTER_PREFIX, true);
    for (CallInst *call : calls)
      call->eraseFromParent();
  }

  void removeFunctions(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, {MB, RMB, WMB, UD2, SERIALIZE,
                              SET_DEBUG_REGISTER_PREFIX, NOP, LOAD_CR3, LIDT});
    for (CallInst *call : calls)
      call->eraseFromParent();
  }

  void handleLoadGs(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, LOAD_GS, false);
    Type *i16Ty = Type::getInt16Ty(M.getContext());
    FunctionCallee ndf = getNondetFn(i16Ty, M);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *v = B.CreateCall(ndf);
      call->replaceAllUsesWith(v);
      call->eraseFromParent();
    }
  }

  void handleSplitU64(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, "", false, SPLIT_U64_CONSTRAINTS);
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    for (CallInst *call : calls) {
      Value *v = call->getArgOperand(0);
      IRBuilder<> B(call);
      Value *low = B.CreateTrunc(v, i32Ty);
      Value *high = B.CreateTrunc(B.CreateLShr(v, 32), i32Ty);
      Value *empty = UndefValue::get(call->getType());
      Value *setLow = B.CreateInsertValue(empty, low, {0});
      Value *replace = B.CreateInsertValue(setLow, high, {1});
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleBuildU64(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, "", false, BUILD_U64_CONSTRAINTS);
    Type *i64Ty = Type::getInt64Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *low = B.CreateZExt(call->getArgOperand(0), i64Ty);
      Value *upper = B.CreateZExt(call->getArgOperand(1), i64Ty);
      Value *v = B.CreateOr(low, B.CreateShl(upper, 32));
      call->replaceAllUsesWith(v);
      call->eraseFromParent();
    }
  }

  void handleBitTest(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, BIT_TEST_PREFIX, true);
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *base = call->getArgOperand(0);
      Value *offset = call->getArgOperand(1);

      Value *byteIdx = B.CreateLShr(offset, B.getInt32(5)); // divide by 32
      Value *bitIdx = B.CreateAnd(offset, B.getInt32(31));  // mod 32
      Value *byte = B.CreateGEP(i32Ty, base, byteIdx);
      Value *load = B.CreateLoad(i32Ty, byte);
      Value *mask = B.CreateShl(B.getInt32(1), bitIdx);
      Value *bit = B.CreateAnd(load, mask);
      Value *isSet = B.CreateICmpNE(bit, B.getInt32(0));
      Value *replace = B.CreateZExt(isSet, call->getType());
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleBitTestAndSet(Module &M) {
    Type *i32Ty = Type::getInt32Ty(M.getContext());

    auto replace = [this, &M, i32Ty](const std::string &targetAsmPrefix) {
      std::vector<CallInst *> calls =
          getTargetAsmCalls(M, targetAsmPrefix, true);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *base = call->getArgOperand(0);
        Value *offset = call->getArgOperand(1);

        Value *byteIdx = B.CreateLShr(offset, B.getInt32(5)); // divide by 32
        Value *bitIdx = B.CreateAnd(offset, B.getInt32(31));  // mod 32
        Value *byte = B.CreateGEP(i32Ty, base, byteIdx);
        Value *load = B.CreateLoad(i32Ty, byte);
        Value *mask = B.CreateShl(B.getInt32(1), bitIdx);
        Value *bit = B.CreateAnd(load, mask);
        Value *isSet = B.CreateICmpNE(bit, B.getInt32(0));
        B.CreateStore(B.CreateOr(load, mask), byte);
        if (!call->getType()->isVoidTy()) {
          Value *replace = B.CreateZExt(isSet, call->getType());
          call->replaceAllUsesWith(replace);
        }
        call->eraseFromParent();
      }
    };

    replace(BIT_TEST_AND_SET_1_0_PREFIX);
    replace(BIT_TEST_AND_SET_2_0_PREFIX);
    replace(BIT_TEST_AND_SET_2_1_PREFIX);
  }

  void handleBitTestAndReset(Module &M) {
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    auto replaceBtrl = [this, &M, i32Ty](const std::string &targetAsmPrefix,
                                         unsigned addrIdx, unsigned offIdx) {
      std::vector<CallInst *> calls =
          getTargetAsmCalls(M, targetAsmPrefix, true);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *base = call->getArgOperand(0);
        Value *offset = call->getArgOperand(1);

        Value *byteIdx = B.CreateLShr(offset, B.getInt32(5)); // divide by 32
        Value *bitIdx = B.CreateAnd(offset, B.getInt32(31));  // mod 32
        Value *byte = B.CreateGEP(i32Ty, base, byteIdx);
        Value *load = B.CreateLoad(i32Ty, byte);
        Value *mask = B.CreateShl(B.getInt32(1), bitIdx);
        Value *bit = B.CreateAnd(load, mask);
        Value *isSet = B.CreateICmpNE(bit, B.getInt32(0));
        Value *flipped = B.CreateXor(mask, B.getInt32(0xffffffff));
        B.CreateStore(B.CreateAnd(load, flipped), byte);
        if (!call->getType()->isVoidTy()) {
          Value *replace = B.CreateZExt(isSet, call->getType());
          call->replaceAllUsesWith(replace);
        }
        call->eraseFromParent();
      }
    };

    replaceBtrl(BIT_TEST_AND_RESET_1_0_PREFIX, 1, 0);
    replaceBtrl(BIT_TEST_AND_RESET_2_1_PREFIX, 2, 1);
  }

  void handleIncl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, INCL, false);
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      if (val->getType()->isPointerTy()) {
        Value *load = B.CreateLoad(i32Ty, val);
        Value *inc = B.CreateAdd(load, B.getInt32(1));
        B.CreateStore(inc, val);
        call->replaceAllUsesWith(inc);
      } else {
        errs() << "TODO: handleIncl\n";
      }
      call->eraseFromParent();
    }
  }

  void handleDecl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, DECL_PREFIX, true);
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    Type *i8Ty = Type::getInt8Ty(ctx);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      if (val->getType()->isPointerTy()) {
        Value *load = B.CreateLoad(i32Ty, val);
        Value *isZero = B.CreateICmpEQ(load, B.getInt32(0));
        Value *isZeroExt = B.CreateZExt(isZero, i8Ty);
        Value *dec = B.CreateSub(load, B.getInt32(1));
        B.CreateStore(dec, val);
        call->replaceAllUsesWith(isZeroExt);
      } else {
        errs() << "TODO: handleDecl\n";
      }
      call->eraseFromParent();
    }
  }

  void handleXAddl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, XADDL_PREFIX, true);
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *src = call->getArgOperand(0);
      Value *dst = call->getArgOperand(1);
      Value *load = B.CreateLoad(i32Ty, src);
      Value *add = B.CreateAdd(load, dst);
      B.CreateStore(dst, src);
      if (dst->getType()->isPointerTy()) {
        errs() << "TODO: handleXAddl\n";
      }
      call->replaceAllUsesWith(add);
      call->eraseFromParent();
    }
  }

  void handleAddl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, ADDL, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *dst = call->getArgOperand(0);
      Value *src = call->getArgOperand(1);
      Type *dstType = dst->getType();
      if (dstType->isPointerTy()) {
        Value *load = B.CreateLoad(dstType->getPointerElementType(), dst);
        Value *add = B.CreateAdd(load, src);
        B.CreateStore(add, dst);

        call->replaceAllUsesWith(add);
        call->eraseFromParent();
      } else {
        errs() << "TODO: handleAddl\n";
      }
    }
  }

  void handleMull(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, MULL, false);
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *v1 = B.CreateZExt(call->getArgOperand(0), B.getInt64Ty());
      Value *v2 = B.CreateZExt(call->getArgOperand(1), B.getInt64Ty());

      Value *mul = B.CreateMul(v1, v2);
      Value *low = B.CreateTrunc(mul, i32Ty);
      Value *upper = B.CreateTrunc(B.CreateLShr(mul, 32), i32Ty);
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
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    Type *i64Ty = Type::getInt64Ty(ctx);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *divisor = B.CreateZExt(call->getArgOperand(0), i64Ty);
      Value *low = B.CreateZExt(call->getArgOperand(1), i64Ty);
      Value *upper = B.CreateZExt(call->getArgOperand(2), i64Ty);

      Value *v = B.CreateOr(B.CreateShl(upper, 32), low);
      Value *quotient = B.CreateTrunc(B.CreateUDiv(v, divisor), i32Ty);
      Value *remainder = B.CreateTrunc(B.CreateURem(v, divisor), i32Ty);

      StructType *type = cast<StructType>(call->getType());
      Value *empty = UndefValue::get(type);
      Value *setQuotient = B.CreateInsertValue(empty, quotient, {0});
      Value *replace = B.CreateInsertValue(setQuotient, remainder, {1});
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleAndl(Module &M) {
    auto replace = [this, &M](const std::string &targetAsm) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, false);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *dst = call->getArgOperand(0);
        Value *src = call->getArgOperand(1);
        Type *dstType = dst->getType();
        if (dstType->isPointerTy()) {
          Value *load = B.CreateLoad(dstType->getPointerElementType(), dst);
          if (load->getType() != src->getType()) {
            src = B.CreateIntCast(src, load->getType(), true);
          }
          Value *and_ = B.CreateAnd(load, src);
          B.CreateStore(and_, dst);

          call->replaceAllUsesWith(and_);
          call->eraseFromParent();
        } else {
          errs() << "TODO: handleAndl\n";
        }
      }
    };

    replace(ANDB);
    replace(ANDL);
  }

  void handleOr(Module &M) {
    auto replace = [this, &M](const std::string &targetAsm) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, false);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *dst = call->getArgOperand(0);
        Value *src = call->getArgOperand(1);
        Type *dstType = dst->getType();

        if (dstType->isPointerTy()) {
          if (src->getType()->isIntegerTy()) {
            // LHS value does not exists.
            Type *innerType = dstType->getPointerElementType();
            Value *cast = B.CreateIntCast(src, innerType, true);
            Value *loaded = B.CreateLoad(innerType, dst);
            Value *or_ = B.CreateOr(loaded, cast);
            B.CreateStore(or_, dst);
          } else {
            Value *load = B.CreateLoad(dstType->getPointerElementType(), dst);
            Value *or_ = B.CreateOr(load, src);
            B.CreateStore(or_, dst);
            call->replaceAllUsesWith(or_);
          }
        } else {
          errs() << "TODO: handleOr\n";
        }
        call->eraseFromParent();
      }
    };

    replace(ORB);
    replace(ORL);
  }

  void handleCpuid(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CPUID, false);
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    FunctionCallee ndf = getNondetFn(i32Ty, M);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *eax = B.CreateCall(ndf);
      Value *ebx = B.CreateCall(ndf);
      Value *ecx = B.CreateCall(ndf);
      Value *edx = B.CreateCall(ndf);

      Type *cpuidRetType = call->getType();
      Value *empty = UndefValue::get(cpuidRetType);
      Value *setEax = B.CreateInsertValue(empty, eax, {0});
      Value *setEbx = B.CreateInsertValue(setEax, ebx, {1});
      Value *setEcx = B.CreateInsertValue(setEbx, ecx, {2});
      Value *setEdx = B.CreateInsertValue(setEcx, edx, {3});
      call->replaceAllUsesWith(setEdx);
      call->eraseFromParent();
    }
  }

  void handleIn(Module &M) {
    auto replace = [this, &M](const std::string &targetAsm, Type *type) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, false);
      FunctionCallee ndf = getNondetFn(type, M);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *replace = B.CreateCall(ndf);
        call->replaceAllUsesWith(replace);
        call->eraseFromParent();
      }
    };

    LLVMContext &ctx = M.getContext();
    replace(INB, Type::getInt8Ty(ctx));
    replace(INW, Type::getInt16Ty(ctx));
    replace(INL, Type::getInt32Ty(ctx));
  }

  void handleOut(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, {OUTB, OUTW, OUTL, OUT_AL_0x80, OUT_AL_0xed});
    for (CallInst *call : calls)
      call->eraseFromParent();
  }

  void handleMov(Module &M) {
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    Type *i8Ty = Type::getInt8Ty(ctx);

    auto replaceMov = [this, &M](const std::string &targetAsm, Type *intTy,
                                 unsigned srcIdx, unsigned dstIdx) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, false);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *replace;
        if (call->getType()->isVoidTy()) {
          Value *src = call->getArgOperand(srcIdx);
          Value *dst = call->getArgOperand(dstIdx);
          Type *srcType = src->getType();
          Type *dstType = dst->getType();
          if (srcType->isPointerTy()) {
            LoadInst *load =
                B.CreateLoad(srcType->getPointerElementType(), src);
            B.CreateStore(load, dst);
            replace = load;
          } else {
            Type *innerType = dstType->getPointerElementType();
            if (innerType->isPointerTy() && srcType->isIntegerTy()) {
              src = B.CreateIntToPtr(src, innerType);
            } else if (srcType != innerType) {
              errs() << "TODO: type mismatch in handleMov\n";
            }
            B.CreateStore(src, dst);
            replace = src;
          }
        } else {
          Value *src = call->getArgOperand(0);
          Type *srcType = src->getType();
          if (srcType->isPointerTy()) {
            if (srcType->getPointerElementType()->isFunctionTy()) {
              Function *f = M.getFunction(src->getName());
              replace = B.CreateCall(f);
            } else {
              replace = B.CreateLoad(srcType->getPointerElementType(), src);
            }
          } else {
            replace = src;
          }
        }
        if (replace->getType()->isPointerTy()) {
          replace = B.CreatePtrToInt(replace, intTy);
        }
        call->replaceAllUsesWith(replace);
        call->eraseFromParent();
      }
    };

    replaceMov(MOVB_0_1, i8Ty, 0, 1);
    replaceMov(MOVB_1_0, i8Ty, 1, 0);
    replaceMov(MOVW_0_1, i32Ty, 0, 1);
    replaceMov(MOVW_1_0, i32Ty, 1, 0);
    replaceMov(MOVL_0_1, i32Ty, 0, 1);
    replaceMov(MOVL_1_0, i32Ty, 1, 0);
  }

  void handleXchgl(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, XCHGL, false, XCGHL_CONSTRAINTS);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *src = call->getArgOperand(0);
      Value *dst = call->getArgOperand(1);
      if (src->getType() != dst->getType()->getPointerTo()) {
        errs() << "TODO: handleXchgl\n";
      }
      Value *loaded = B.CreateLoad(dst->getType(), src);
      B.CreateStore(dst, src);
      call->replaceAllUsesWith(loaded);
      call->eraseFromParent();
    }
  }

  void handleCmpxchgl(Module &M) {
    auto replaceCmpxchg = [this, &M](const std::string &targetAsm,
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

        Value *replace;
        Type *type = call->getType();
        if (type->isStructTy()) {
          Value *empty = UndefValue::get(type);
          Value *isSuccess = B.CreateExtractValue(inst, {1});
          Value *castedSuccess = B.CreateZExt(isSuccess, i8Ty);
          Value *converted = B.CreateInsertValue(empty, castedSuccess, {0});
          replace = B.CreateInsertValue(converted, val, {1});
        } else {
          replace = val;
        }

        call->replaceAllUsesWith(replace);
        call->eraseFromParent();
      }
    };

    replaceCmpxchg(CMPXCHGL31_PREFIX, true, 3);
    replaceCmpxchg(CMPXCHGL21, false, 2);
  }

  void handleCmpxchg8b(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CMPXCHG8B, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      Value *lower = call->getArgOperand(1);
      Value *upper = call->getArgOperand(2);
      Value *prev = call->getArgOperand(3);

      Value *shiftedUpper = B.CreateShl(upper, 32);
      Value *new_ = B.CreateOr(shiftedUpper, lower);
      Value *atomic = B.CreateAtomicCmpXchg(
          val, prev, new_, MaybeAlign(), AtomicOrdering::SequentiallyConsistent,
          AtomicOrdering::SequentiallyConsistent);
      Value *replace = B.CreateExtractValue(atomic, {0});
      call->replaceAllUsesWith(replace);
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
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      // return 0 (success) for now.
      Value *zero = B.getInt32(0);
      call->replaceAllUsesWith(zero);
      call->eraseFromParent();
    }
  }

  void handleRDMSR(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, RDMSR, false);
    Type *i64Ty = Type::getInt64Ty(M.getContext());
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
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      // return 0 (success) for now.
      Value *zero = B.getInt32(0);
      call->replaceAllUsesWith(zero);
      call->eraseFromParent();
    }
  }

  void handleRDTSC(Module &M) {
    LLVMContext &ctx = M.getContext();
    Type *i64Ty = Type::getInt64Ty(ctx);

    auto replace = [this, &M, i64Ty](const std::string &targetAsm) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, false);
      FunctionCallee ndf = getNondetFn(i64Ty, M);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        // return a nondet unsigned long long for now.
        Value *ret = B.CreateCall(ndf);
        call->replaceAllUsesWith(ret);
        call->eraseFromParent();
      }
    };

    replace(RDTSC);
    replace(RDTSC_ORDERED);
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
    Type *i64Ty = Type::getInt64Ty(ctx);
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
      if (!i->getType()->isIntegerTy(64)) {
        i = B.CreateZExt(i, i64Ty);
      }
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

      Value *empty = UndefValue::get(call->getType());
      Value *setResult = B.CreateInsertValue(empty, add, {0});
      Value *setCounter = B.CreateInsertValue(setResult, v, {1});
      call->replaceAllUsesWith(setCounter);
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

      Value *empty = UndefValue::get(call->getType());
      Value *setResult = B.CreateInsertValue(empty, sub, {0});
      Value *setCounter = B.CreateInsertValue(setResult, v, {1});
      call->replaceAllUsesWith(setCounter);
      call->eraseFromParent();
    }
  }

  void handleAtomic64Xchg(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, CALL1, false, ARCH_ATOMIC64_XCHG_CONSTRAINTS);
    LLVMContext &ctx = M.getContext();
    Type *i64Ty = Type::getInt64Ty(ctx);
    StructType *atomic64Type =
        StructType::getTypeByName(ctx, "struct.atomic64_t");
    for (CallInst *call : calls) {
      if (!call->getNumOperands())
        continue;
      Value *op = call->getOperand(0);
      if (!op->hasName() || !op->getName().equals("atomic64_xchg_cx8"))
        continue;
      IRBuilder<> B(call);
      Value *v = call->getOperand(1);
      Value *low = B.CreateZExt(call->getOperand(2), i64Ty);
      Value *high = B.CreateZExt(call->getOperand(3), i64Ty);
      Value *new_ = B.CreateOr(B.CreateLShr(high, 32), low);
      Value *counterPtr =
          B.CreateStructGEP(atomic64Type, v, ATOMIC64_COUNTER_INDEX);
      Value *old =
          B.CreateAtomicRMW(AtomicRMWInst::Xchg, counterPtr, new_, MaybeAlign(),
                            AtomicOrdering::SequentiallyConsistent);
      call->replaceAllUsesWith(old);
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
      IRBuilder<> B(call);
      Value *index = call->getArgOperand(1);
      Value *size = call->getArgOperand(0);
      Value *isOk = B.CreateICmpULT(index, size);
      Value *mask = B.CreateSelect(isOk, B.getInt32(0xffffffff), B.getInt32(0));
      call->replaceAllUsesWith(mask);
      call->eraseFromParent();
    }
  }

  // void handleGetUser(Module &M) {
  //   std::vector<CallInst *> calls =
  //       getTargetAsmCalls(M, GET_USER, false, GET_USER_CONSTRAINTS);
  //   for (CallInst *call : calls) {
  //     IRBuilder<> B(call);
  //     Value *addr = call->getArgOperand(0);
  //     Value *stackPointer = call->getArgOperand(2);
  //
  //     Value *empty = UndefValue::get(call->getType());
  //     Value *ok = B.CreateInsertValue(empty, B.getInt32(0), {0});
  //     Value *loaded = B.CreateLoad(addr->getType()->getPointerElementType(),
  //     addr); if (loaded->getType()->isIntegerTy()) {
  //     }
  //     Value *setLoaded = B.CreateInsertValue(ok, loaded, {1});
  //     Value *completed = B.CreateInsertValue(setLoaded, stackPointer, {2});
  //     call->replaceAllUsesWith(completed);
  //     call->eraseFromParent();
  //   }
  // }

  void handleCallOnStack(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, CALL_ON_STACK, false);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *funcPtr = call->getArgOperand(1);
      if (BitCastOperator *bitcast = dyn_cast<BitCastOperator>(funcPtr)) {
        Function *func = cast<Function>(bitcast->getOperand(0));
        Value *replace = B.CreateCall(func);
        call->replaceAllUsesWith(replace);
        call->eraseFromParent();
      } else {
        errs() << "TODO: handleCallOnStack\n";
      }
    }
  }

  void handleOptimizerHideVar(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, "", false, OPTIMIZER_HIDE_VAR_CONSTRAINTS);
    for (CallInst *call : calls) {
      Value *v = call->getArgOperand(0);
      call->replaceAllUsesWith(v);
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
