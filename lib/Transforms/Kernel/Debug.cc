#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"

#include <set>
#include <vector>

using namespace llvm;

namespace seahorn {

class Debug : public ModulePass {
public:
  static char ID;

  Debug() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    unsigned int counter = 0;
    // std::map<StringRef, std::set<StringRef>> callers = getCallers(M);
    // for (StringRef callee : {
    //     "x86_pmu_enable",
    //     "x86_get_pmu",
    //   }) {
    //   errs() << '\n' << callee.str() << "\n";
    //   for (StringRef caller : callers[callee]) {
    //     errs() << "Caller: " << caller.str() << "\n";
    //   }
    //   if (!callers[callee].size()) {
    //     errs() << "callers not found\n\n";
    //   }
    // }
    errs() << "\n";
    // for (StringRef name : {
    //     "wake_up_process",
    //   }) {
    //   int found = !!M.getFunction(name) || !!M.getGlobalVariable(name, true);
    //   errs() << name.str() << ' ' << found << "\n";
    // }
    for (StringRef name : {
             // "do_accept",
             // "io_accept",
             // "io_read",
             // "io_write",
             // "io_op_defs",
             // "io_setup_async_rw",
             // "io_uring_get_opcode",
             // "io_uring_show_fdinfo",
             // "io_uring_fops",
             // "io_file_get_flags",
             // "io_rw_init_file",
             // "io_register_rsrc_update",
             // "io_fixed_fd_install",
             // "acpi_ut_acquire_mutex",
             // "acpi_tb_get_table",
             // "crb_acpi_driver",
             // "crb_acpi_add",
             // "__tracepoint_xdp_redirect",
             // "xdp_do_generic_redirect_map",
             // "xdp_do_generic_redirect",
             // "do_xdp_generic",
             // "__netif_receive_skb_core",
             // "sync_exp_work_done.___tp_str",
             "native_cpu_up",
             "smp_ops",
             "smp_call_function_many_cond",
             "on_each_cpu_cond_mask",
             "pmu",
             "cpu_hw_events",
             "x86_pmu_start_txn",
             "x86_pmu_cancel_txn",
             "x86_get_pmu",
             "validate_group",
             "collect_events",
             "x86_pmu_aux_output_match",
         }) {
      printUses(M, name);
    }
    {
      unsigned c = 0;
      for (auto &g : M.globals()) {
        if (g.hasName()) {
          errs() << "global var: " << g.getName() << '\n';
          c++;
        }
      }
      errs() << "global vars " << c << '\n';
    }
    for (Function &F : M) {
      if (F.getName().startswith("__SCT__")) {
        errs() << "Func " << F.getName().str() << "\n";
      }
      errs() << "Func " << F.getName().str() << "\n";
      if (F.isDeclaration() || !F.hasName())
        continue;
      for (Instruction &inst : instructions(F)) {
        if (CallInst *call = dyn_cast<CallInst>(&inst)) {
          if (InlineAsm *inlineAsm =
                  dyn_cast<InlineAsm>(call->getCalledOperand())) {
            // if (counter < 10) {
            //   StringRef name = F.getName();
            //   errs() << "In func " << name.str() << "\n";
            //   errs() << "asm: " << inlineAsm->getAsmString() << "\n";
            //   errs() << "constraints " << inlineAsm->getConstraintString()
            //          << "\n";
            // }
            counter++;
          }
        }
      }
    }
    if (counter) {
      errs() << "Total number of inline asm instructions: " << counter << "\n";
    }
    return false;
  }

  virtual StringRef getPassName() const override { return "KernelDebug"; }

private:
  std::map<StringRef, std::set<StringRef>> getCallers(Module &M) {
    std::map<StringRef, std::set<StringRef>> callers;
    for (Function &F : M) {
      if (F.isDeclaration() || !F.hasName())
        continue;
      for (User *U : F.users()) {
        if (Instruction *I = dyn_cast<Instruction>(U)) {
          if (Function *caller = I->getFunction()) {
            callers[F.getName()].insert(caller->getName());
          }
        }
      }
    }
    return callers;
  }

  void printUses(Module &M, StringRef name) {
    GlobalValue *f = M.getNamedValue(name);
    if (!f) {
      errs() << "no such function or global var " << name.str() << "\n";
      return;
    }
    errs() << "uses of " << name.str() << "\n";
    int count = 0;
    for (User *use : f->users()) {
      printUseBelong(use);
      use->dump();
      count++;
    }
    if (!count) {
      errs() << "is droppable " << f->isDiscardableIfUnused() << '\n';
      errs() << "linkage " << f->getLinkage() << '\n';
      errs() << "isdecl " << f->isDeclaration() << '\n';
    }
    errs() << "use count: " << count << " droppable "
           << f->isDiscardableIfUnused() << "\n\n";
  }

  bool printUseBelong(User *use) {
    if (Instruction *inst = dyn_cast<Instruction>(use)) {
      errs() << "inst in func: " << inst->getFunction()->getName().str() << ' ';
      return true;
    } else if (GlobalVariable *g = dyn_cast<GlobalVariable>(use)) {
      errs() << "global var: " << g->getName() << ' ';
      return true;
    } else if (Constant *c = dyn_cast<Constant>(use)) {
      for (User *user : c->users()) {
        if (printUseBelong(user))
          return true;
      }
      errs() << "other constant ";
      return false;
    } else if (Operator *op = dyn_cast<Operator>(use)) {
      for (User *user : op->users()) {
        if (printUseBelong(user)) {
          return true;
        }
      }
      errs() << "other op ";
      return false;
    } else {
      errs() << "simple other ";
      return false;
    }
  }
};

char Debug::ID = 0;

Pass *createKernelDebugPass() { return new Debug(); };
} // namespace seahorn
