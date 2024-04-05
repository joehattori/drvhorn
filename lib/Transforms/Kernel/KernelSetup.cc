#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Pass.h"

#include "boost/range.hpp"
#include "seahorn/Support/SeaDebug.h"

#include <algorithm>
#include <optional>

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
  }

  bool isCurrentTaskCall(const CallInst *call) {
    const InlineAsm *inlineAsm = dyn_cast<InlineAsm>(call->getCalledOperand());
    if (!inlineAsm)
      return false;
    return inlineAsm->getAsmString() == currentTaskAsm &&
           inlineAsm->getConstraintString() == currentTaskConstraints;
  }

  void handleCurrentTask(Module &M) {
    std::vector<CallInst *> currentTaskCalls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isCurrentTaskCall(call))
            currentTaskCalls.push_back(call);
        }
      }
    }

    for (CallInst *call : currentTaskCalls) {
      Value *task = call->getArgOperand(0);
      call->replaceAllUsesWith(task);
      call->eraseFromParent();
    }
  }

  bool isBarrierCall(const CallInst *call) {
    const InlineAsm *inlineAsm = dyn_cast<InlineAsm>(call->getCalledOperand());
    if (!inlineAsm || !inlineAsm->hasSideEffects())
      return false;
    return inlineAsm->getAsmString().empty() &&
           inlineAsm->getConstraintString() == barrierConstraints;
  }

  void handleBarrier(Module &M) {
    std::vector<CallInst *> barrierCalls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isBarrierCall(call))
            barrierCalls.push_back(call);
        }
      }
    }

    for (CallInst *call : barrierCalls)
      call->eraseFromParent();
  }

  Value *bitAddr(IRBuilder<> &B, Value *base, Value *offset) {
    Value *idx = B.CreateAShr(offset, B.getInt32(8));
    return B.CreateAdd(base, idx);
  }

  bool isBitTestCall(const CallInst *call) {
    const InlineAsm *inlineAsm = dyn_cast<InlineAsm>(call->getCalledOperand());
    if (!inlineAsm || !inlineAsm->hasSideEffects())
      return false;
    return !inlineAsm->getAsmString().rfind(bitTestAsmPrefix, 0);
  }

  void handleBitTest(Module &M) {
    std::vector<CallInst *> calls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isBitTestCall(call))
            calls.push_back(call);
        }
      }
    }

    LLVMContext &ctx = M.getContext();
    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *addr = call->getArgOperand(0);
      Value *offset = call->getArgOperand(1);

      Value *pos = bitAddr(B, addr, offset);
      Value *loaded = B.CreateLoad(Type::getInt1Ty(ctx), pos);
      Value *bit = B.CreateAnd(loaded, 1);
      Value *isSet = B.CreateICmpNE(bit, B.getInt32(0));
      call->replaceAllUsesWith(isSet);
      call->eraseFromParent();
    }
  }

  bool isBitTestAndSetCall(const CallInst *call) {
    const InlineAsm *inlineAsm = dyn_cast<InlineAsm>(call->getCalledOperand());
    if (!inlineAsm || !inlineAsm->hasSideEffects())
      return false;
    return !inlineAsm->getAsmString().rfind(bitTestAndSetAsmPrefix, 0);
  }

  void handleBitTestAndSet(Module &M) {
    std::vector<CallInst *> calls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isBitTestAndSetCall(call))
            calls.push_back(call);
        }
      }
    }

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

  bool isBitTestAndResetCall(const CallInst *call) {
    const InlineAsm *inlineAsm = dyn_cast<InlineAsm>(call->getCalledOperand());
    if (!inlineAsm || !inlineAsm->hasSideEffects())
      return false;
    return !inlineAsm->getAsmString().rfind(bitTestAndResetAsmPrefix, 0);
  }

  void handleBitTestAndReset(Module &M) {
    std::vector<CallInst *> calls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isBitTestAndResetCall(call))
            calls.push_back(call);
        }
      }
    }

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

  bool isInclCall(const CallInst *call) {
    const InlineAsm *inlineAsm = dyn_cast<InlineAsm>(call->getCalledOperand());
    if (!inlineAsm || !inlineAsm->hasSideEffects())
      return false;
    return inlineAsm->getAsmString() == inclAsm;
  }

  void handleIncl(Module &M) {
    std::vector<CallInst *> calls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isInclCall(call))
            calls.push_back(call);
        }
      }
    }

    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      Value *inc = B.CreateAdd(val, B.getInt32(1));
      call->replaceAllUsesWith(inc);
      call->eraseFromParent();
    }
  }

  bool isDeclCall(const CallInst *call) {
    const InlineAsm *inlineAsm = dyn_cast<InlineAsm>(call->getCalledOperand());
    if (!inlineAsm || !inlineAsm->hasSideEffects())
      return false;
    return !inlineAsm->getAsmString().rfind(declAsmPrefix, 0);
  }

  void handleDecl(Module &M) {
    std::vector<CallInst *> calls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isDeclCall(call))
            calls.push_back(call);
        }
      }
    }

    for (CallInst *call : calls) {
      IRBuilder<> B(call);
      Value *val = call->getArgOperand(0);
      Value *dec = B.CreateSub(val, B.getInt32(1));
      call->replaceAllUsesWith(dec);
      call->eraseFromParent();
    }
  }

  bool isXAddlCall(const CallInst *call) {
    const InlineAsm *inlineAsm = dyn_cast<InlineAsm>(call->getCalledOperand());
    if (!inlineAsm || !inlineAsm->hasSideEffects())
      return false;
    return !inlineAsm->getAsmString().rfind(xaddlAsmPrefix, 0);
  }

  void handleXAddl(Module &M) {
    std::vector<CallInst *> xaddCalls;
    for (Function &F : M) {
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (isXAddlCall(call))
            xaddCalls.push_back(call);
        }
      }
    }

    for (CallInst *call : xaddCalls) {
      IRBuilder<> B(call);
      Value *ptr = call->getArgOperand(0);
      Value *inc = call->getArgOperand(1);
      Value *old = B.CreateAtomicRMW(AtomicRMWInst::Add, ptr, inc, MaybeAlign(),
                                     AtomicOrdering::SequentiallyConsistent);
      call->replaceAllUsesWith(old);
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
