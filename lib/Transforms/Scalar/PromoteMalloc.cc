#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

#include "boost/range.hpp"
#include "seahorn/Support/SeaDebug.h"

using namespace llvm;

namespace {
class PromoteMalloc : public FunctionPass {
public:
  static char ID;

  PromoteMalloc() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override {
    if (F.empty())
      return false;

    // -- only promote mallocs in top level functions
    if (!F.getName().equals("main"))
      return false;

    bool changed = false;

    SmallVector<Instruction *, 16> kill;

    for (auto &I : llvm::make_range(inst_begin(F), inst_end(F))) {
      Value *v = I.stripPointerCasts();
      if (!isa<CallInst>(v))
        continue;

      auto &CI = cast<CallInst>(*v);

      const Function *fn = CI.getCalledFunction();
      if (!fn && CI.getCalledOperand())
        fn = dyn_cast<const Function>(
            CI.getCalledOperand()->stripPointerCasts());

      if (fn &&
          (fn->getName().equals("malloc") || fn->getName().equals("zalloc") ||
           fn->getName().equals("_Znwj" /* new */) ||
           fn->getName().equals("_Znaj" /* new[] */))) {

        unsigned addrSpace = 0;
        Value *nv = nullptr;
        if (auto *ci = dyn_cast<Constant>(CI.getOperand(0))) {
          // malloc(0) == nullptr
          if (fn->getName().equals("malloc") && ci->isZeroValue()) {
            nv = Constant::getNullValue(CI.getType());
          }
        }

        if (!nv) {
          auto ai = new AllocaInst(v->getType()->getPointerElementType(),
                                   addrSpace, CI.getOperand(0), "malloc", &I);
          // -- set alignment based on stack, not alignment of the type
          ai->setAlignment(F.getParent()->getDataLayout().getStackAlignment());
          nv = ai;
          if (fn->getName().equals("zalloc")) {
            // -- zero out memory
            auto *zero = Constant::getNullValue(ai->getAllocatedType());
            auto *zeroed = new StoreInst(zero, ai, &I);
            zeroed->setAlignment(ai->getAlign());
          }
        }
        v->replaceAllUsesWith(nv);

        changed = true;
      } else if (fn && (fn->getName().equals("free") ||
                        fn->getName().equals("_ZdlPv" /* delete */) ||
                        fn->getName().equals("_ZdaPv" /* delete[] */)))
        kill.push_back(&I);
    }

    // -- remove all calls to free(). This is too much, but ensures
    // -- that all promoted mallocs() are not free'ed by mistake
    for (auto *I : kill)
      I->eraseFromParent();

    return changed;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }

  virtual StringRef getPassName() const override { return "PromoteMalloc"; }
};

char PromoteMalloc::ID = 0;
} // namespace

namespace seahorn {
Pass *createPromoteMallocPass() { return new PromoteMalloc(); }
} // namespace seahorn

static llvm::RegisterPass<PromoteMalloc>
    X("promote-malloc", "Promote top-level malloc calls to alloca");
