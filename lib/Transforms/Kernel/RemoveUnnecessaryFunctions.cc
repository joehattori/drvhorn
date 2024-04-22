#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"

#define COMPILER_USED_NAME "llvm.compiler.used"

using namespace llvm;

namespace seahorn {
enum ReplacementType {
  Zero,
  Nondet,
  Fail,
};

class RemoveUnnecessaryFunctions : public ModulePass {
public:
  static char ID;

  RemoveUnnecessaryFunctions() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    verify(M);
    updateLinkage(M);

    if (GlobalVariable *compilerUsed = M.getNamedGlobal(COMPILER_USED_NAME)) {
      Type *ty = compilerUsed->getType();
      compilerUsed->eraseFromParent();
      // llvm.compiler.used seems to be required, so insert an empty value
      M.getOrInsertGlobal(COMPILER_USED_NAME, ty->getPointerElementType());
    }

    removeFunctions(M);
    verify(M);

    legacy::PassManager pm;
    pm.add(createAggressiveDCEPass());
    pm.add(createGlobalDCEPass());

    while (pm.run(M))
      ;

    verify(M);
    return true;
  }

  virtual StringRef getPassName() const override {
    return "RemoveUnnecessaryFunctions";
  }

private:
  DenseMap<const Type *, Function *> ndvalfn;
  DenseMap<const FunctionType *, Function *> ndfn;
  DenseMap<const FunctionType *, Function *> failureFn;
  DenseMap<const FunctionType *, Function *> dummyFn;

  void debug(Module &M, StringRef name) {
    GlobalValue *f = M.getGlobalVariable(name);
    // GlobalValue *f = M.getFunction(name);
    if (f)
      errs() << name << " found: " << f->isDiscardableIfUnused() << "\n";
    else
      errs() << name << " not found\n";
  }

  void updateLinkage(Module &M) {
    for (Function &f : M) {
      if (f.isDeclaration())
        continue;
      if (!f.getName().equals("main"))
        f.setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
    }
    for (GlobalVariable &v : M.globals()) {
      if (v.isDeclaration())
        continue;
      v.setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
    }
    for (GlobalAlias &alias : M.aliases()) {
      if (alias.isDeclaration())
        continue;
      alias.setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
    }
  }

  struct ReplacePolicy {
    std::string name;
    ReplacementType type;
    std::vector<unsigned> indices_to_replace = {};
  };

  void removeFunctions(Module &M) {
    // first key: name of the function
    // second key: strategy to replace the function
    ReplacePolicy replacements[] = {
        // lock
        {"mutex_lock", ReplacementType::Zero},
        {"mutex_unlock", ReplacementType::Zero},
        {"__mutex_init", ReplacementType::Zero},
        // rcu
        {"__srcu_read_lock", ReplacementType::Zero},
        {"__srcu_read_unlock", ReplacementType::Zero},
        {"wakeme_after_rcu", ReplacementType::Zero},
        {"srcu_write_gp", ReplacementType::Zero},
        {"chip_bus_lock", ReplacementType::Zero},
        {"chip_bus_unlock", ReplacementType::Zero},
        {"synchronize_srcu", ReplacementType::Zero},
        {"srcu_drive_gp", ReplacementType::Zero},
        // semaphore
        {"up", ReplacementType::Zero},
        {"__up", ReplacementType::Zero},
        {"__init_rwsem", ReplacementType::Zero},
        {"down_read", ReplacementType::Zero},
        {"__down_read_common", ReplacementType::Zero},
        {"rwsem_mark_wake", ReplacementType::Zero},
        {"down_write", ReplacementType::Zero},
        {"rwsem_down_write_slowpath", ReplacementType::Zero},
        {"up_read", ReplacementType::Zero},
        {"rwsem_wake", ReplacementType::Zero},
        {"up_write", ReplacementType::Zero},
        {"down_timeout", ReplacementType::Zero},
        // scheduling
        {"__schedule", ReplacementType::Zero},
        {"schedule", ReplacementType::Zero},
        {"__cond_sched", ReplacementType::Zero},
        {"need_resched", ReplacementType::Zero},
        {"try_to_wake_up", ReplacementType::Zero},
        {"queue_work_on", ReplacementType::Zero},
        {"__queue_work", ReplacementType::Zero},
        {"queue_work_node", ReplacementType::Zero},
        {"queue_rcu_work", ReplacementType::Zero},
        {"call_rcu", ReplacementType::Zero},
        {"flush_workqueue_prep_pwqs", ReplacementType::Zero},
        {"check_flush_dependency", ReplacementType::Zero},
        {"kthread_unpark", ReplacementType::Zero},
        {"resched_curr", ReplacementType::Zero},
        {"resched_cpu", ReplacementType::Zero},
        {"wake_up_process", ReplacementType::Zero},
        {"__wake_up", ReplacementType::Zero},
        {"__wake_up_common", ReplacementType::Zero},
        {"__wake_up_common_lock", ReplacementType::Zero},
        {"__init_waitqueue_head", ReplacementType::Zero},
        {"add_wait_queue", ReplacementType::Zero},
        {"remove_wait_queue", ReplacementType::Zero},
        {"init_wait_entry", ReplacementType::Zero},
        // async
        {"async_schedule_node", ReplacementType::Nondet},
        // memory/page management
        {"is_vmalloc_addr", ReplacementType::Zero},
        {"slob_alloc", ReplacementType::Nondet},
        {"slob_new_pages", ReplacementType::Nondet},
        {"__alloc_pages", ReplacementType::Nondet},
        {"ioremap", ReplacementType::Nondet},
        {"ioremap_uc", ReplacementType::Nondet},
        {"ioremap_wc", ReplacementType::Nondet},
        {"ioremap_wt", ReplacementType::Nondet},
        {"ioremap_encrypted", ReplacementType::Nondet},
        {"ioremap_cache", ReplacementType::Nondet},
        {"ioremap_prot", ReplacementType::Nondet},
        {"__early_ioremap", ReplacementType::Nondet},
        {"__ioremap_caller", ReplacementType::Nondet},
        {"iounmap", ReplacementType::Zero},
        {"early_iounmap", ReplacementType::Zero},
        {"early_memremap_pgprot_adjust", ReplacementType::Zero},
        {"early_memremap", ReplacementType::Zero},
        {"early_memunmap", ReplacementType::Zero},
        {"set_pte_vaddr", ReplacementType::Zero},
        {"set_pte_vaddr_pud", ReplacementType::Zero},
        {"populate_extra_pmd", ReplacementType::Nondet},
        {"populate_extra_pte", ReplacementType::Nondet},
        {"pgd_free", ReplacementType::Zero},
        {"free_pages", ReplacementType::Zero},
        {"__get_free_pages", ReplacementType::Nondet},
        {"devm_ioremap", ReplacementType::Nondet},
        {"devm_ioremap_resource", ReplacementType::Nondet},
        {"__devm_ioremap_resource", ReplacementType::Nondet},
        {"devm_iounmap", ReplacementType::Zero},
        // resource
        {"__request_region", ReplacementType::Nondet},
        {"__release_region", ReplacementType::Nondet},
        // work_struct
        {"flush_work", ReplacementType::Zero},
        {"__flush_workqueue", ReplacementType::Zero},
        // irq
        {"raise_softirq", ReplacementType::Zero},
        {"raise_softirq_irqoff", ReplacementType::Zero},
        {"__do_softirq", ReplacementType::Zero},
        {"do_softirq", ReplacementType::Zero},
        {"invoke_softirq", ReplacementType::Zero},
        {"__local_bh_enable", ReplacementType::Zero},
        {"__local_bh_enable_ip", ReplacementType::Zero},
        {"__local_bh_disable_ip", ReplacementType::Zero},
        {"synchronize_irq", ReplacementType::Zero},
        {"synchronize_hardirq", ReplacementType::Zero},
        {"__synchronize_hardirq", ReplacementType::Zero},
        {"free_irq", ReplacementType::Zero},
        {"__free_irq", ReplacementType::Zero},
        {"__irq_disable", ReplacementType::Zero},
        // tasklet
        {"tasklet_action", ReplacementType::Zero},
        {"tasklet_action_common", ReplacementType::Zero},
        // notification
        {"kobject_uevent", ReplacementType::Zero},
        {"blocking_notifier_call_chain", ReplacementType::Zero},
        // timer
        {"schedule_hrtimeout_range", ReplacementType::Zero},
        {"schedule_hrtimeout_range_clock", ReplacementType::Zero},
        {"mod_timer", ReplacementType::Zero},
        {"del_timer", ReplacementType::Zero},
        {"__msecs_to_jiffies", ReplacementType::Zero},
        {"__usecs_to_jiffies", ReplacementType::Zero},
        {"durations_show", ReplacementType::Zero},
        {"timeouts_show", ReplacementType::Zero},
        {"init_timer_key", ReplacementType::Zero},
        {"lock_timer_base", ReplacementType::Zero},
        // time
        {"jiffies_to_msecs", ReplacementType::Zero},
        {"jiffies_to_usecs", ReplacementType::Zero},
        {"ktime_get", ReplacementType::Zero},
        {"get_jiffies_64", ReplacementType::Zero},
        // sleep
        {"msleep", ReplacementType::Zero},
        {"usleep_range_state", ReplacementType::Zero},
        // hardware
        {"default_get_nmi_reason", ReplacementType::Nondet},
        // delays
        {"delay_loop", ReplacementType::Zero},
        {"__udelay", ReplacementType::Zero},
        {"__const_udelay", ReplacementType::Zero},
        // drivers
        {"wait_for_device_probe", ReplacementType::Zero},
        {"driver_deferred_probe_trigger", ReplacementType::Zero},
        // print
        {"vsprintf", ReplacementType::Zero},
        {"vsnprintf", ReplacementType::Zero},
        {"sprintf", ReplacementType::Zero},
        {"snprintf", ReplacementType::Zero},
        {"scnprintf", ReplacementType::Zero},
        {"kvasprintf", ReplacementType::Zero},
        {"kvasprintf_const", ReplacementType::Zero},
        {"kasprintf", ReplacementType::Zero},
        // acpi
        {"__acpi_acquire_global_lock", ReplacementType::Zero},
        {"__acpi_release_global_lock", ReplacementType::Zero},
        {"acpi_ut_acquire_mutex", ReplacementType::Zero},
        {"acpi_ut_release_mutex", ReplacementType::Zero},
        {"acpi_dev_get_resources", ReplacementType::Nondet, {3}},
        {"acpi_evaluate_object", ReplacementType::Nondet, {3}},
        // others
        {"panic", ReplacementType::Fail},
        {"add_taint", ReplacementType::Zero},
        // debug
        {"devm_kzalloc", ReplacementType::Nondet},
        {"crb_map_io", ReplacementType::Zero},
        {"tpmm_chip_alloc", ReplacementType::Nondet},
        {"tpm_chip_register", ReplacementType::Zero},
        {"acpi_tb_validate_table", ReplacementType::Zero},
    };

    for (const ReplacePolicy &policy : replacements) {
      StringRef name = policy.name;
      if (Function *f = M.getFunction(name)) {
        Function *dummy;
        switch (policy.type) {
        case ReplacementType::Zero:
          dummy = getDummyFunction(f->getFunctionType(), M,
                                   policy.indices_to_replace);
          break;
        case ReplacementType::Nondet:
          dummy =
              getNondetFn(f->getFunctionType(), M, policy.indices_to_replace);
          break;
        case ReplacementType::Fail:
          dummy =
              getFailureFn(f->getFunctionType(), M, policy.indices_to_replace);
          break;
        };
        f->replaceAllUsesWith(dummy);
        f->eraseFromParent();
      }
    }
  }

  Function *getDummyFunction(FunctionType *type, Module &M,
                             const std::vector<unsigned> &indicesToReplace) {
    if (!indicesToReplace.empty()) {
      errs() << "getDummyFunction TODO\n";
    }
    auto it = dummyFn.find(type);
    if (it != dummyFn.end()) {
      return it->second;
    }

    LLVMContext &ctx = M.getContext();
    Function *f = makeNewFn(M, type, dummyFn.size(), "verifier.dummy.");
    BasicBlock *block = BasicBlock::Create(ctx, "", f);
    Type *retType = type->getReturnType();
    if (!retType->isVoidTy()) {
      Value *ret = Constant::getNullValue(retType);
      ReturnInst::Create(ctx, ret, block);
    } else {
      ReturnInst::Create(ctx, block);
    }
    return f;
  }

  Function *getFailureFn(FunctionType *type, Module &M,
                         const std::vector<unsigned> &indicesToReplace) {
    if (!indicesToReplace.empty()) {
      errs() << "getDummyFunction TODO\n";
    }
    auto it = failureFn.find(type);
    if (it != failureFn.end()) {
      return it->second;
    }

    LLVMContext &ctx = M.getContext();
    Function *res = makeNewFn(M, type, failureFn.size(), "verifier.failure.");
    BasicBlock *block = BasicBlock::Create(ctx, "", res);
    failureFn[type] = res;
    FunctionCallee err = M.getFunction("__VERIFIER_error");
    CallInst::Create(err, "", block);
    ReturnInst::Create(ctx, nullptr, block);
    return res;
  }

  Function *getNondetFn(FunctionType *type, Module &M,
                        const std::vector<unsigned> &indicesToReplace) {
    auto it = ndfn.find(type);
    if (it != ndfn.end() && indicesToReplace.empty()) {
      return it->second;
    }

    LLVMContext &ctx = M.getContext();
    Function *res = makeNewFn(M, type, ndfn.size(), "verifier.nondet.");
    BasicBlock *block = BasicBlock::Create(ctx, "", res);
    IRBuilder<> B(block);
    Type *retType = type->getReturnType();
    Type *i8Type = Type::getInt8Ty(ctx);
    for (unsigned index : indicesToReplace) {
      Value *arg = res->getArg(index);
      if (!arg->getType()->isPointerTy()) {
        errs() << "index should be a pointer\n";
      }
      Type *valType = arg->getType()->getPointerElementType();
      if (valType->isVoidTy()) {
        valType = i8Type;
      }
      Function *ndval = getNondetValueFn(valType, M);
      CallInst *call = B.CreateCall(ndval);
      B.CreateStore(call, arg);
    }
    if (retType->isVoidTy()) {
      B.CreateRetVoid();
    } else {
      Function *ndval = getNondetValueFn(retType, M);
      CallInst *call = B.CreateCall(ndval);
      B.CreateRet(call);
    }
    ndfn[type] = res;
    return res;
  }

  Function *getNondetValueFn(Type *retType, Module &M) {
    auto it = ndvalfn.find(retType);
    if (it != ndvalfn.end()) {
      return it->second;
    }

    Function *res =
        makeNewValFn(M, retType, ndvalfn.size(), "verifier.nondetvalue.");
    ndvalfn[retType] = res;
    return res;
  }

  Function *makeNewFn(Module &M, FunctionType *type, unsigned startFrom,
                      std::string prefix) {
    std::string name;
    unsigned c = startFrom;
    do {
      name = prefix + std::to_string(c++);
    } while (M.getNamedValue(name));
    return Function::Create(type, GlobalValue::LinkageTypes::ExternalLinkage,
                            name, &M);
  }

  Function *makeNewValFn(Module &M, Type *type, unsigned startFrom,
                         std::string prefix) {
    std::string name;
    unsigned c = startFrom;
    do {
      name = prefix + std::to_string(c++);
    } while (M.getNamedValue(name));
    return Function::Create(FunctionType::get(type, false),
                            GlobalValue::LinkageTypes::ExternalLinkage, name,
                            &M);
  }

  void verify(Module &M) {
    if (verifyModule(M, &errs())) {
      errs() << "Module verification failed\n";
    } else {
      errs() << "Module verification Ok\n";
    }
  }
};

char RemoveUnnecessaryFunctions::ID = 0;

Pass *createRemoveUnnecessaryFunctionsPass() {
  return new RemoveUnnecessaryFunctions();
}
} // namespace seahorn
