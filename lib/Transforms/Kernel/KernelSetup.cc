#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Pass.h"

#include "boost/algorithm/string.hpp"
#include "boost/range.hpp"
#include "seahorn/Support/SeaDebug.h"
#include "seahorn/Transforms/Kernel/Util.hh"

#include <algorithm>
#include <optional>
#include <regex>

using namespace llvm;

#define BARRIER_CONSTRAINTS "~{memory},~{dirflag},~{fpsr},~{flags}"
#define BUILD_U64_CONSTRAINTS "=A,{ax},{dx},~{dirflag},~{fpsr},~{flags}"
#define ARCH_ATOMIC64_XCHG_CONSTRAINTS                                         \
  "=&A,i,{si},{bx},{cx},~{memory},~{dirflag},~{fpsr},~{flags}"
#define OPTIMIZER_HIDE_VAR_CONSTRAINTS "=r,0,~{dirflag},~{fpsr},~{flags}"

#define BIT_TEST_PREFIX "btq $2,$1"
#define BIT_TEST_AND_SET_1_0_PREFIX "btsq $1,$0"
#define BIT_TEST_AND_SET_2_0_PREFIX "btsq $2,$0"
#define BIT_TEST_AND_SET_2_1_PREFIX "btsq $2,$1"
#define BIT_TEST_AND_RESET_1_0_PREFIX "btrq $1,$0"
#define BIT_TEST_AND_RESET_2_0_PREFIX "btrq $2,$0"
#define BIT_TEST_AND_RESET_2_1_PREFIX "btrq $2,$1"

#define INCL "incl $0"
#define DECL_PREFIX "decl $0"
#define ADD_WITH_CARRY "addl $2,$0;adcl $$0,$0"
#define XADDL "xaddl $0,$1"
#define XADDQ "xaddq ${0:q},$1"
#define MOVB_0_1 "movb $0,$1"
#define MOVB_1_0 "movb $1,$0"
#define MOVW_0_1 "movw $0,$1"
#define MOVW_1_0 "movw $1,$0"
#define MOVL_0_1 "movl $0,$1"
#define MOVL_1_0 "movl $1,$0"
#define MOVQ_0_1 "movq $0,$1"
#define MOVQ_1_0 "movq $1,$0"
#define MOVQ_POSITION_INDEPENDENT "movq ${1:P},$0"
#define ADDQ_1_0 "addq $1,$0"
#define ADDQ_2_0_PREFIX "addq $2,$0"
#define ADDL_1_0 "addl $1,$0"
#define ADDL_2_0_PREFIX "addl $2,$0"
#define ANDB_1_0 "andb ${1:b},$0"
#define ANDB_2_1_PREFIX "andb $2,$1"
#define ANDL "andl $1,$0"
#define ANDQ "andq $1,$0"
#define MULL "mull $3"
#define DIVL "divl $2"
#define ORB "orb ${1:b},$0"
#define ORL "orl $1,$0"
#define ORQ "orq $1,$0"
#define CMPXCHGL21 "cmpxchgl $2,$1"
#define CMPXCHGL21_CONSTRAINTS                                                 \
  "={ax},=*m,r,0,*m,~{memory},~{dirflag},~{fpsr},~{flags}"
#define CMPXCHGL31_PREFIX "cmpxchgl $3,$1"
#define CMPXCHGL31_CONSTRAINTS                                                 \
  "={@ccz},=*m,={ax},r,*m,2,~{memory},~{dirflag},~{fpsr},~{flags}"
#define CMPXCHGQ21 "cmpxchgq $2,$1"
#define CMPXCHGQ21_CONSTRAINTS                                                 \
  "={ax},=*m,r,0,*m,~{memory},~{dirflag},~{fpsr},~{flags}"
#define CMPXCHGQ31_PREFIX "cmpxchgq $3,$1"
#define CMPXCHGQ31_CONSTRAINTS                                                 \
  "={@ccz},=*m,={ax},r,*m,2,~{memory},~{dirflag},~{fpsr},~{flags}"
#define CMPXCHG8B "cmpxchg8b $1"
#define XCHGL "xchgl $0,$1;"
#define XCHGQ "xchgq ${0:q},$1"
#define XCHG_CONSTRAINTS                                                       \
  "=r,=*m,0,*m,~{memory},~{cc},~{dirflag},~{fpsr},~{flags}"
#define FFS "rep; bsf $1,$0"
#define FLSL "bsrl $1,$0"
#define FLSQ "bsrq $1,${0:q}"
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
#define LFENCE "lfence"
#define SFENCE "sfence"
#define MFENCE "mfence"
#define RDSEED_PREFIX "rdseed $1"
#define RDRAND_PREFIX "rdrand $1"

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
#define STATIC_CPU_HAS_BRANCH                                                  \
  "# ALT: oldinstr2;661:;jmp 6f;662:;# ALT: padding2;.skip -((((6651f-6641f) " \
  "^ (((6651f-6641f) ^ (6652f-6642f)) & -(-((6651f-6641f) < "                  \
  "(6652f-6642f))))) - (662b-661b)) > 0) * (((6651f-6641f) ^ (((6651f-6641f) " \
  "^ (6652f-6642f)) & -(-((6651f-6641f) < (6652f-6642f))))) - "                \
  "(662b-661b)),0x90;663:;.pushsection .altinstructions,\"a\";.long 661b - "   \
  ".;.long 6641f - .;.word ( 3*32+21);.byte 663b-661b;.byte "                  \
  "6651f-6641f;.long 661b - .;.long 6642f - .;.word ${0:P};.byte "             \
  "663b-661b;.byte 6652f-6642f;.popsection;.pushsection "                      \
  ".altinstr_replacement,\"ax\";# ALT: replacement 1;6641:;jmp "               \
  "${4:l};6651:;# ALT: replacement 2;6642:;6652:;.popsection;.pushsection "    \
  ".altinstr_aux,\"ax\";6:;testb $1,${2:P} (% rip);jnz ${3:l};jmp "            \
  "${4:l};.popsection"
#define GET_USER_ASM_Q                                                         \
  "1:movq $1,$0;.pushsection \"__ex_table\",\"a\";.balign 4;.long (1b) - "     \
  ".;.long (${2:l}) - .;.long 3;.popsection"
#define GET_USER_ASM_L                                                         \
  "1:movl $1,$0;.pushsection \"__ex_table\",\"a\";.balign 4;.long (1b) - "     \
  ".;.long (${2:l}) - .;.long 3;.popsection"
#define GET_USER_ASM_W                                                         \
  "1:movw $1,$0;.pushsection \"__ex_table\",\"a\";.balign 4;.long (1b) - "     \
  ".;.long (${2:l}) - .;.long 3;.popsection"
#define GET_USER_ASM_B                                                         \
  "1:movb $1,$0;.pushsection \"__ex_table\",\"a\";.balign 4;.long (1b) - "     \
  ".;.long (${2:l}) - .;.long 3;.popsection"
#define CPU_VMX_OFF                                                            \
  "1: vmxoff;.pushsection \"__ex_table\",\"a\";.balign 4;.long (1b) - "        \
  ".;.long (${0:l}) - .;.long 1;.popsection"

#define NATIVE_SAVE_FL "# __raw_save_flags;pushf ; pop $0"

#define ATOMIC64_COUNTER_INDEX 0

namespace seahorn {

class KernelSetup : public ModulePass {
public:
  static char ID;

  KernelSetup() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    stubKernelFunctions(m);
    stubAllocPages(m);
    handleFree(m);
    handleKmemCache(m);
    ignoreKernelFunctions(m);

    handleCallRcu(m);

    handleMemset(m);
    handleMemCpy(m);
    handleMemMove(m);
    // handleStrCat(M);
    // handleStrNCmp(M);
    handleStrChr(m);

    handleInlineAssembly(m);
    return true;
  }

  virtual StringRef getPassName() const override { return "KernelSetup"; }

private:
  DenseMap<const Type *, FunctionCallee> ndfn;

  void stubKernelFunctions(Module &M) {
    std::string mallocFns[] = {"__kmalloc",
                               "__kmalloc_node",
                               "__kmalloc_node_track_caller",
                               "kmalloc_large",
                               "kmalloc_large_node",
                               "__vmalloc_node_range",
                               "slob_alloc",
                               "pcpu_alloc",
                               "__ioremap_caller",
                               "__early_ioremap",
                               "strcpy",
                               "strncpy",
                               "strlen",
                               "strnlen",
                               "strcmp",
                               "strncmp"};
    for (const std::string &name : mallocFns) {
      Function *orig = M.getFunction(name);
      if (!orig)
        continue;
      std::string stubName = "__DRVHORN_" + name;
      Function *stub = M.getFunction(stubName);
      if (!stub) {
        errs() << "stub not found: " << stubName << "\n";
        std::exit(1);
      }
      orig->replaceAllUsesWith(stub);
      orig->eraseFromParent();
    }
  }

  void stubAllocPages(Module &M) {
    std::string names[] = {
        "__alloc_pages",
    };
    LLVMContext &ctx = M.getContext();
    for (const std::string &name : names) {
      std::string wrapperName = name + "_wrapper";
      Function *orig = M.getFunction(name);
      if (!orig)
        continue;
      std::string stubName = "__DRVHORN_" + name;
      Function *stub = M.getFunction(stubName);

      Function *wrapper = Function::Create(
          orig->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
          wrapperName, &M);
      BasicBlock *block = BasicBlock::Create(ctx, "", wrapper);
      IRBuilder<> B(block);
      CallInst *call = B.CreateCall(stub);
      if (orig->getReturnType() != call->getType()) {
        Value *bitCast = B.CreateBitCast(call, orig->getReturnType());
        B.CreateRet(bitCast);
      } else {
        B.CreateRet(call);
      }
      orig->replaceAllUsesWith(wrapper);
      orig->eraseFromParent();
    }
  }

  void handleFree(Module &M) {
    LLVMContext &ctx = M.getContext();
    Type *voidType = Type::getVoidTy(ctx);
    Type *voidPtrType = Type::getInt8Ty(ctx)->getPointerTo();
    FunctionCallee freeFunc =
        M.getOrInsertFunction("free", voidType, voidPtrType);
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
      IRBuilder<> B(block);
      Argument *addr = wrapper->getArg(0);
      CallInst *call = B.CreateCall(freeFunc, {addr});
      call->setTailCall();
      B.CreateRetVoid();
      orig->replaceAllUsesWith(wrapper);
      orig->eraseFromParent();
    }
  }

  GlobalVariable *gVarOfKmemCacheAllocCall(Module &M, CallInst *call) {
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

  void handleKmemCache(Module &M) {
    StringRef kmemCacheFuncNames[] = {
        "kmem_cache_alloc",
        "kmem_cache_alloc_lru",
        "kmem_cache_alloc_node",
    };
    LLVMContext &ctx = M.getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    Function *malloc = M.getFunction("__DRVHORN_malloc");
    for (StringRef name : kmemCacheFuncNames) {
      Function *orig = M.getFunction(name);
      if (!orig)
        continue;
      for (User *user : orig->users()) {
        if (CallInst *call = dyn_cast<CallInst>(user)) {
          GlobalVariable *gv = gVarOfKmemCacheAllocCall(M, call);
          if (!gv) {
            errs() << "TODO: kmem_cache_alloc: global variable not found\n";
            continue;
          }
          Optional<size_t> size = getKmemCacheSize(gv);
          if (size == None) {
            continue;
          }
          ConstantInt *sizeArg = ConstantInt::get(i64Ty, size.getValue());
          ConstantInt *flagArg = ConstantInt::get(i32Ty, 0);
          CallInst *newMalloc =
              CallInst::Create(malloc, {sizeArg, flagArg}, "kmemcache", call);
          call->replaceAllUsesWith(newMalloc);
        }
      }
    }
  }

  void ignoreKernelFunctions(Module &m) {
    StringRef names[] = {
        "slob_free",
        "refcount_warn_saturate",
        "__kobject_del",
    };
    for (StringRef name : names) {
      Function *f = m.getFunction(name);
      if (!f)
        return;
      std::string stubName = "drvhorn.stub." + name.str();
      FunctionType *ft = f->getFunctionType();
      if (!ft->getReturnType()->isVoidTy()) {
        errs() << "ignoreKernelFunctions: non-void return type\n";
        std::exit(1);
      }
      Function *stub = Function::Create(
          ft, GlobalValue::LinkageTypes::InternalLinkage, stubName, &m);
      BasicBlock *block = BasicBlock::Create(m.getContext(), "", stub);
      ReturnInst::Create(m.getContext(), block);
      f->replaceAllUsesWith(stub);
      f->eraseFromParent();
    }
  }

  void handleCallRcu(Module &M) {
    LLVMContext &ctx = M.getContext();
    std::string name = "call_rcu";
    Function *orig = M.getFunction(name);
    if (!orig)
      return;
    std::string wrapperName = name + "_wrapper";
    Function *wrapper = Function::Create(
        orig->getFunctionType(), GlobalValue::LinkageTypes::ExternalLinkage,
        wrapperName, &M);
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

  void handleMemset(Module &M) {
    if (Function *llvmMemset = M.getFunction("llvm.memset.p0i8.i64")) {
      Function *memsetFn = M.getFunction("__DRVHORN_memset");
      if (!memsetFn) {
        errs() << "__DRVHORN_memset not found\n";
        std::exit(1);
      }
      llvmMemset->replaceAllUsesWith(memsetFn);
      llvmMemset->eraseFromParent();
    }
  }

  void handleMemCpy(Module &M) {
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
        MemcpyInfo{"_copy_user_ll", RetType::Len},
        MemcpyInfo{"_copy_user_ll_nocache_nozero", RetType::Len},
        MemcpyInfo{"_copy_to_user", RetType::Len},
        MemcpyInfo{"_copy_from_user", RetType::Len},
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

  void handleInlineAssembly(Module &M) {
    handleBitTest(M);
    handleBitTestAndSet(M);
    handleBitTestAndReset(M);
    handleFFS(M);
    handleFLS(M);
    // handleHWeight(M);

    // should be called before handleAddl, since they have identical prefix.
    handleAddWithCarry(M);
    // handleIncl(M);
    handleDecl(M);
    handleXAddq(M);
    handleXAddl(M);
    handleAddq(M);
    handleAddl(M);
    // handleMull(M);
    // handleDivl(M);
    handleAnd(M);
    handleOr(M);
    // handleCpuid(M);
    handleIn(M);
    // handleOut(M);
    handleMov(M);

    // handleAtomic64Read(M);
    // handleAtomic64Set(M);
    // handleAtomic64AddReturn(M);
    // handleAtomic64SubReturn(M);
    // handleAtomic64Xchg(M);
    handleXchg(M);
    handleCmpxchgl(M);
    handleCmpxchgq(M);
    // handleCmpxchg8b(M);

    // handleNativeSaveFL(M);
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
    // removeFunctions(M);
    // handleSerialize(M);
    // handleIretToSelf(M);
    // handleDebugRegisters(M);
    // handleLoadGs(M);
    // handleBuildU64(M);
    // handleCallOnStack(M);
    // handleOptimizerHideVar(M);
    // handleGetUser(M);
    handleRandom(M);

    // handleFence(M);
    handleStaticCpuHas(M);
    handleGetUserAsm(M);
    handleCpuVmxOff(M);
  }

  std::string splitAndJoin(std::string s, std::string delimiter,
                           std::string joiner) {
    std::vector<std::string> parts;
    boost::split(parts, s, boost::is_any_of(delimiter),
                 boost::token_compress_on);
    for (std::string &part : parts)
      boost::trim(part);
    return boost::join(parts, joiner);
  }

  std::string formatInlineAsm(std::string s) {
    boost::trim(s);
    boost::erase_all(s, "\t");
    s = splitAndJoin(s, "\n", ";");
    s = splitAndJoin(s, " ", " ");
    s = splitAndJoin(s, ",", ",");
    // std::regex spacesBeforeReg("\\s+\\$");
    // s = std::regex_replace(s, spacesBeforeReg, " $");
    return s;
  }

  std::vector<CallBrInst *>
  getTargetAsmCallBrs(Module &M, const std::string &asmStr, bool isPrefix,
                      const std::string &constraints = "") {
    auto isTargetAsm = [this, &asmStr, isPrefix,
                        constraints](const CallBrInst *callbr) {
      const CallBase *call = dyn_cast<CallBase>(callbr);
      if (!call)
        return false;
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

    std::vector<CallBrInst *> calls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallBrInst *call = dyn_cast<CallBrInst>(&inst)) {
          if (isTargetAsm(call))
            calls.push_back(call);
        }
      }
    }
    return calls;
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
        getTargetAsmCalls(M, MOVQ_POSITION_INDEPENDENT, false);
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
        Value *cast = B.CreatePtrToInt(currentTask, B.getInt64Ty());
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
    Type *i64Ty = Type::getInt64Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *base = call->getArgOperand(0);
      Value *offset = call->getArgOperand(1);

      Value *byteIdx = B.CreateLShr(offset, B.getInt64(5)); // divide by 32
      Value *bitIdx = B.CreateAnd(offset, B.getInt64(31));  // mod 32
      Value *byte = B.CreateGEP(i64Ty, base, byteIdx);
      Value *load = B.CreateLoad(i64Ty, byte);
      Value *mask = B.CreateShl(B.getInt64(1), bitIdx);
      Value *bit = B.CreateAnd(load, mask);
      Value *isSet = B.CreateICmpNE(bit, B.getInt64(0));
      Value *replace = B.CreateZExt(isSet, call->getType());
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleBitTestAndSet(Module &M) {
    Type *i64Ty = Type::getInt64Ty(M.getContext());

    auto replace = [this, &M, i64Ty](const std::string &targetAsmPrefix) {
      std::vector<CallInst *> calls =
          getTargetAsmCalls(M, targetAsmPrefix, true);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *base = call->getArgOperand(0);
        Value *offset = call->getArgOperand(1);

        Value *byteIdx = B.CreateLShr(offset, B.getInt64(5)); // divide by 32
        Value *bitIdx = B.CreateAnd(offset, B.getInt64(31));  // mod 32
        Value *byte = B.CreateGEP(i64Ty, base, byteIdx);
        Value *load = B.CreateLoad(i64Ty, byte);
        Value *mask = B.CreateShl(B.getInt64(1), bitIdx);
        Value *bit = B.CreateAnd(load, mask);
        Value *isSet = B.CreateICmpNE(bit, B.getInt64(0));
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
    Type *i64Ty = Type::getInt64Ty(M.getContext());
    auto replaceBtrl = [this, &M, i64Ty](const std::string &targetAsmPrefix,
                                         unsigned addrIdx, unsigned offIdx) {
      std::vector<CallInst *> calls =
          getTargetAsmCalls(M, targetAsmPrefix, true);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *base = call->getArgOperand(0);
        Value *offset = call->getArgOperand(1);

        Value *byteIdx = B.CreateLShr(offset, B.getInt64(5)); // divide by 32
        Value *bitIdx = B.CreateAnd(offset, B.getInt64(31));  // mod 32
        Value *byte = B.CreateGEP(i64Ty, base, byteIdx);
        Value *load = B.CreateLoad(i64Ty, byte);
        Value *mask = B.CreateShl(B.getInt64(1), bitIdx);
        Value *bit = B.CreateAnd(load, mask);
        Value *isSet = B.CreateICmpNE(bit, B.getInt64(0));
        Value *flipped = B.CreateXor(mask, B.getInt64(0xffffffff));
        B.CreateStore(B.CreateAnd(load, flipped), byte);
        if (!call->getType()->isVoidTy()) {
          Value *replace = B.CreateZExt(isSet, call->getType());
          call->replaceAllUsesWith(replace);
        }
        call->eraseFromParent();
      }
    };

    replaceBtrl(BIT_TEST_AND_RESET_1_0_PREFIX, 1, 0);
    replaceBtrl(BIT_TEST_AND_RESET_2_0_PREFIX, 2, 0);
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

  void handleAddWithCarry(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, ADD_WITH_CARRY, false);
    LLVMContext &ctx = M.getContext();
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *v1 = call->getArgOperand(0);
      Value *v2 = call->getArgOperand(1);
      Function *uaddWithOverflow = Intrinsic::getDeclaration(
          &M, Intrinsic::uadd_with_overflow, {Type::getInt32Ty(ctx)});
      CallInst *newCall = B.CreateCall(uaddWithOverflow, {v1, v2});
      Value *sum = B.CreateExtractValue(newCall, 0);
      call->replaceAllUsesWith(sum);
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

  void handleXAddq(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, XADDQ, false);
    Type *i64Ty = Type::getInt64Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *src = call->getArgOperand(0);
      Value *load = B.CreateLoad(i64Ty, src);
      Value *add = B.CreateAdd(load, call->getArgOperand(1));
      B.CreateStore(add, src);
      call->replaceAllUsesWith(load);
      call->eraseFromParent();
    }
  }

  void handleXAddl(Module &M) {
    std::vector<CallInst *> calls = getTargetAsmCalls(M, XADDL, false);
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *src = call->getArgOperand(0);
      Value *load = B.CreateLoad(i32Ty, src);
      Value *add = B.CreateAdd(load, call->getArgOperand(1));
      B.CreateStore(add, src);
      call->replaceAllUsesWith(load);
      call->eraseFromParent();
    }
  }

  void handleAddq(Module &M) {
    auto replace = [this, &M](const std::string &targetAsm, bool isPrefix) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, isPrefix);
      LLVMContext &ctx = M.getContext();
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *dst = call->getArgOperand(0);
        Value *src = call->getArgOperand(1);
        Type *dstType = dst->getType();
        Value *load = B.CreateLoad(dstType->getPointerElementType(), dst);
        Value *add = B.CreateAdd(load, src);
        B.CreateStore(add, dst);
        Value *isNeg = B.CreateZExt(B.CreateICmpSLT(add, B.getInt64(0)),
                                    Type::getInt8Ty(ctx));
        call->replaceAllUsesWith(isNeg);
        call->eraseFromParent();
      }
    };

    replace(ADDQ_1_0, false);
    replace(ADDQ_2_0_PREFIX, true);
  }

  void handleAddl(Module &M) {
    auto replace = [this, &M](const std::string &targetAsm, bool isPrefix) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, isPrefix);
      LLVMContext &ctx = M.getContext();
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *dst = call->getArgOperand(0);
        Value *src = call->getArgOperand(1);
        Type *dstType = dst->getType();
        Value *load = B.CreateLoad(dstType->getPointerElementType(), dst);
        Value *add = B.CreateAdd(load, src);
        B.CreateStore(add, dst);
        Value *isNeg = B.CreateZExt(B.CreateICmpSLT(add, B.getInt32(0)),
                                    Type::getInt8Ty(ctx));
        call->replaceAllUsesWith(isNeg);
        call->eraseFromParent();
      }
    };

    replace(ADDL_1_0, false);
    replace(ADDL_2_0_PREFIX, true);
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

  void handleAnd(Module &M) {
    auto replace = [this, &M](const std::string &targetAsm, bool isPrefix) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, isPrefix);
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

    replace(ANDB_1_0, false);
    replace(ANDB_2_1_PREFIX, true);
    replace(ANDL, false);
    replace(ANDQ, false);
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
    replace(ORQ);
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
    Type *i8Ty = Type::getInt8Ty(ctx);
    Type *i32Ty = Type::getInt32Ty(ctx);
    Type *i64Ty = Type::getInt64Ty(ctx);

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
    replaceMov(MOVQ_0_1, i64Ty, 0, 1);
    replaceMov(MOVQ_1_0, i64Ty, 1, 0);
  }

  void handleXchg(Module &M) {
    auto replace = [&M, this](const std::string &targetAsm) {
      std::vector<CallInst *> calls =
          getTargetAsmCalls(M, targetAsm, false, XCHG_CONSTRAINTS);
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
    };
    replace(XCHGL);
    replace(XCHGQ);
  }

  void handleCmpxchgl(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, CMPXCHGL31_PREFIX, true, CMPXCHGL31_CONSTRAINTS);
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
      Type *type = call->getType();
      Value *empty = UndefValue::get(type);
      Value *isSuccess = B.CreateExtractValue(inst, {1});
      Value *castedSuccess = B.CreateZExt(isSuccess, i8Ty);
      Value *converted = B.CreateInsertValue(empty, castedSuccess, {0});
      Value *replace = B.CreateInsertValue(converted, val, {1});

      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }

    Type *i32Ty = Type::getInt32Ty(ctx);
    calls = getTargetAsmCalls(M, CMPXCHGL21, false, CMPXCHGL21_CONSTRAINTS);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *acc = call->getArgOperand(0);
      Value *cmp = call->getArgOperand(2);
      Value *new_ = call->getArgOperand(1);
      Type *type = call->getType();
      if (type != i32Ty) {
        acc = B.CreateBitCast(acc, type->getPointerTo());
      }
      AtomicCmpXchgInst *inst = B.CreateAtomicCmpXchg(
          acc, cmp, new_, MaybeAlign(), AtomicOrdering::SequentiallyConsistent,
          AtomicOrdering::SequentiallyConsistent);

      Value *replace = B.CreateExtractValue(inst, {0});
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleCmpxchgq(Module &M) {
    std::vector<CallInst *> calls =
        getTargetAsmCalls(M, CMPXCHGQ31_PREFIX, true, CMPXCHGQ31_CONSTRAINTS);
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
      Type *type = call->getType();
      Value *empty = UndefValue::get(type);
      Value *isSuccess = B.CreateExtractValue(inst, {1});
      Value *castedSuccess = B.CreateZExt(isSuccess, i8Ty);
      Value *converted = B.CreateInsertValue(empty, castedSuccess, {0});
      Value *replace = B.CreateInsertValue(converted, val, {1});

      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }

    Type *i64Ty = Type::getInt64Ty(ctx);
    calls = getTargetAsmCalls(M, CMPXCHGQ21, false, CMPXCHGQ21_CONSTRAINTS);
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *acc = call->getArgOperand(0);
      Value *cmp = call->getArgOperand(2);
      Value *new_ = call->getArgOperand(1);
      Type *type = call->getType();
      if (type != i64Ty) {
        acc = B.CreateBitCast(acc, type->getPointerTo());
      }
      AtomicCmpXchgInst *inst = B.CreateAtomicCmpXchg(
          acc, cmp, new_, MaybeAlign(), AtomicOrdering::SequentiallyConsistent,
          AtomicOrdering::SequentiallyConsistent);

      Value *replace = B.CreateExtractValue(inst, {0});
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
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
        Intrinsic::getDeclaration(&M, Intrinsic::cttz, {Type::getInt64Ty(ctx)});
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *v = call->getArgOperand(0);
      Value *zero = B.getInt64(0);
      Value *isZero = B.CreateICmpEQ(v, zero);
      Value *cttzCall = B.CreateCall(cttz, {v, B.getFalse()});
      Value *nonZero = B.CreateAdd(cttzCall, B.getInt64(1));
      Value *replace = B.CreateSelect(isZero, zero, nonZero);
      call->replaceAllUsesWith(replace);
      call->eraseFromParent();
    }
  }

  void handleFLS(Module &M) {
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    auto replace = [this, i32Ty, &ctx, &M](const std::string &targetAsm,
                                           unsigned bitWidth) {
      IntegerType *ty = IntegerType::get(ctx, bitWidth);
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, false);
      Function *ctlz = Intrinsic::getDeclaration(&M, Intrinsic::ctlz, {ty});
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        Value *v = call->getArgOperand(0);
        Value *zero = ConstantInt::get(ty, 0);
        Value *isZero = B.CreateICmpEQ(v, zero);
        Value *ctlzCall = B.CreateCall(ctlz, {v, B.getFalse()});
        Value *nonZero = B.CreateSub(ConstantInt::get(ty, bitWidth), ctlzCall);
        Value *replace = B.CreateSelect(isZero, zero, nonZero);
        if (replace->getType() != i32Ty) {
          replace = B.CreateTrunc(replace, i32Ty);
        }
        call->replaceAllUsesWith(replace);
        call->eraseFromParent();
      }
    };

    replace(FLSL, 32);
    replace(FLSQ, 64);
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

  void handleFence(Module &M) {
    // simply ignore the FENCE instruction.
    std::vector<CallInst *> calls = getTargetAsmCalls(M, LFENCE, false);
    for (CallInst *call : calls) {
      call->eraseFromParent();
    }
    calls = getTargetAsmCalls(M, SFENCE, false);
    for (CallInst *call : calls) {
      call->eraseFromParent();
    }
    calls = getTargetAsmCalls(M, MFENCE, false);
    for (CallInst *call : calls) {
      call->eraseFromParent();
    }
  }

  void handleStaticCpuHas(Module &M) {
    std::vector<CallBrInst *> calls =
        getTargetAsmCallBrs(M, STATIC_CPU_HAS_BRANCH, false);
    for (CallBrInst *callbr : calls) {
      IRBuilder<> B(callbr);
      // TODO: Randomizing the destination should be better.
      BranchInst *branch = B.CreateBr(callbr->getIndirectDest(1));
      callbr->replaceAllUsesWith(branch);
      callbr->eraseFromParent();
    }
  }

  void handleGetUserAsm(Module &M) {
    auto replace = [this, &M](const std::string &targetAsm,
                              const std::string &utilSuffix) {
      std::vector<CallBrInst *> calls =
          getTargetAsmCallBrs(M, targetAsm, false);
      Type *i8PtrType = Type::getInt8Ty(M.getContext())->getPointerTo();
      for (CallBrInst *callbr : calls) {
        IRBuilder<> B(callbr);
        Value *largeStruct = callbr->getArgOperand(0);
        Value *bytes =
            B.CreateGEP(largeStruct->getType(), largeStruct, B.getInt32(0));
        if (bytes->getType() != i8PtrType) {
          bytes = B.CreateBitCast(bytes, i8PtrType);
        }
        Function *f = M.getFunction("__DRVHORN_util_read_" + utilSuffix);
        CallInst *val = B.CreateCall(f, bytes);
        // TODO: Randomizing the destination should be better.
        B.CreateBr(callbr->getDefaultDest());
        callbr->replaceAllUsesWith(val);
        callbr->eraseFromParent();
      }
    };
    replace(GET_USER_ASM_Q, "u64");
    replace(GET_USER_ASM_L, "u32");
    replace(GET_USER_ASM_W, "u16");
    replace(GET_USER_ASM_B, "u8");
  }

  void handleCpuVmxOff(Module &M) {
    std::vector<CallBrInst *> calls =
        getTargetAsmCallBrs(M, CPU_VMX_OFF, false);
    for (CallBrInst *callbr : calls) {
      IRBuilder<> B(callbr);
      BasicBlock *block = callbr->getDefaultDest();
      BranchInst *br = B.CreateBr(block);
      callbr->replaceAllUsesWith(br);
      callbr->eraseFromParent();
    }
  }

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

  void handleRandom(Module &M) {
    Type *i64Ty = Type::getInt64Ty(M.getContext());
    auto replace = [this, &M, i64Ty](const std::string &targetAsm) {
      std::vector<CallInst *> calls = getTargetAsmCalls(M, targetAsm, true);
      for (CallInst *call : calls) {
        IRBuilder<> B(call);
        StructType *type = cast<StructType>(call->getType());
        Value *empty = UndefValue::get(type);
        Value *setLow = B.CreateInsertValue(empty, B.getInt8(1), {0});
        FunctionCallee nd = getNondetFn(i64Ty, M);
        Value *replace = B.CreateInsertValue(setLow, B.CreateCall(nd), {1});
        call->replaceAllUsesWith(replace);
        call->eraseFromParent();
      }
    };
    replace(RDSEED_PREFIX);
    replace(RDRAND_PREFIX);
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
