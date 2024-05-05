#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
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

    runDCE(M);

    if (GlobalVariable *compilerUsed = M.getNamedGlobal(COMPILER_USED_NAME)) {
      Type *ty = compilerUsed->getType();
      compilerUsed->eraseFromParent();
      // llvm.compiler.used seems to be required, so insert an empty value
      M.getOrInsertGlobal(COMPILER_USED_NAME, ty->getPointerElementType());
    }

    replaceSCTFunctions(M);
    runDCE(M);

    removeFunctions(M);
    verify(M);

    runDCE(M, true);

    verify(M);
    return true;
  }

  void runDCE(Module &M, bool removeArg = false) {
    legacy::PassManager pm;
    pm.add(createAggressiveDCEPass());
    pm.add(createGlobalDCEPass());
    if (removeArg)
      pm.add(createDeadArgEliminationPass());
    int c = 0;
    while (pm.run(M) && c++ < 10) {
    }
  }

  virtual StringRef getPassName() const override {
    return "RemoveUnnecessaryFunctions";
  }

private:
  DenseMap<const Type *, Function *> ndvalfn;
  DenseMap<const FunctionType *, Function *> ndfn;
  DenseMap<const FunctionType *, Function *> failureFn;
  DenseMap<const FunctionType *, Function *> dummyFn;

  void updateLinkage(Module &M) {
    for (Function &f : M) {
      if (f.isDeclaration())
        continue;
      if (f.getName().equals("main") || f.getName().startswith("__VERIFIER_"))
        continue;
      f.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    }
    for (GlobalVariable &v : M.globals()) {
      if (v.isDeclaration())
        continue;
      v.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    }
    for (GlobalAlias &alias : M.aliases()) {
      if (alias.isDeclaration())
        continue;
      alias.setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    }
  }

  struct ReplacePolicy {
    std::string name;
    ReplacementType type;
    std::vector<unsigned> indices_to_replace = {};
  };

  void replaceSCTFunctions(Module &M) {
    ReplacePolicy replacements[] = {
        {"__SCT__might_resched", ReplacementType::Zero},
        {"__SCT__cond_resched", ReplacementType::Zero},
        {"__SCT__pv_sched_clock", ReplacementType::Zero},
        {"__SCT__x86_pmu_del", ReplacementType::Zero},
        {"__SCT__x86_pmu_add", ReplacementType::Zero},
        {"__SCT__x86_pmu_enable", ReplacementType::Zero},
        {"__SCT__x86_pmu_disable", ReplacementType::Zero},
        {"__SCT__x86_pmu_enable_all", ReplacementType::Zero},
        {"__SCT__x86_pmu_disable_all", ReplacementType::Zero},
        {"__SCT__x86_pmu_schedule_events", ReplacementType::Zero},
        {"__SCT__x86_pmu_update", ReplacementType::Zero},
        {"__SCT__x86_pmu_set_period", ReplacementType::Zero},
        {"__SCT__x86_pmu_put_event_constraints", ReplacementType::Zero},
        {"__SCT__x86_pmu_assign", ReplacementType::Zero},
        {"__SCT__x86_pmu_swap_task_ctx", ReplacementType::Zero},
        {"__SCT__x86_pmu_sched_task", ReplacementType::Zero},
        {"__SCT__x86_pmu_read", ReplacementType::Zero},
        {"__SCT__pv_steal_clock", ReplacementType::Zero},
    };

    for (const ReplacePolicy &policy : replacements) {
      Function *f = M.getFunction(policy.name);
      if (!f) {
        errs() << "Could not find SCT function " << policy.name << "\n";
        continue;
      }
      Function *dummy;
      switch (policy.type) {
      case ReplacementType::Zero:
        dummy = getDummyFunction(f->getFunctionType(), M, {});
        break;
      case ReplacementType::Nondet:
        dummy = getNondetFn(f->getFunctionType(), M, {});
        break;
      default:
        errs() << "Unhandled case in replaceSCTFunctions\n";
        continue;
      };
      f->replaceAllUsesWith(dummy);
      f->eraseFromParent();
    }

    std::vector<std::pair<Function *, Function *>> toReplace;
    for (Function &f : M) {
      StringRef name = f.getName();
      if (name.startswith("__SCT__tp_func_")) {
        Function *dummy = getDummyFunction(f.getFunctionType(), M, {});
        toReplace.push_back({&f, dummy});
      }
    }

    for (std::pair<Function *, Function *> pair : toReplace) {
      Function *f = pair.first;
      Function *orig = pair.second;
      f->replaceAllUsesWith(orig);
      f->eraseFromParent();
    }
  }

  void removeFunctions(Module &M) {
    // first key: name of the function
    // second key: strategy to replace the function
    ReplacePolicy replacements[] = {
        // lock
        {"mutex_lock", ReplacementType::Zero},
        {"mutex_lock_interruptible", ReplacementType::Zero},
        {"mutex_trylock", ReplacementType::Zero},
        {"mutex_is_locked", ReplacementType::Zero},
        {"mutex_unlock", ReplacementType::Zero},
        {"__mutex_init", ReplacementType::Zero},
        {"spin_lock", ReplacementType::Zero},
        {"spin_unlock", ReplacementType::Zero},
        // rcu
        {"__srcu_read_lock", ReplacementType::Zero},
        {"__srcu_read_unlock", ReplacementType::Zero},
        {"wakeme_after_rcu", ReplacementType::Zero},
        {"srcu_write_gp", ReplacementType::Zero},
        {"chip_bus_lock", ReplacementType::Zero},
        {"chip_bus_unlock", ReplacementType::Zero},
        {"synchronize_srcu", ReplacementType::Zero},
        {"srcu_drive_gp", ReplacementType::Zero},
        {"__rcu_read_lock", ReplacementType::Zero},
        {"__rcu_read_unlock", ReplacementType::Zero},
        {"exit_rcu", ReplacementType::Zero},
        // semaphore
        {"up", ReplacementType::Zero},
        {"__up", ReplacementType::Zero},
        {"__init_rwsem", ReplacementType::Zero},
        {"down_read", ReplacementType::Zero},
        {"down_write", ReplacementType::Zero},
        {"up_read", ReplacementType::Zero},
        {"up_write", ReplacementType::Zero},
        {"__down_read_common", ReplacementType::Zero},
        {"rwsem_wake", ReplacementType::Zero},
        {"rwsem_mark_wake", ReplacementType::Zero},
        {"rwsem_down_write_slowpath", ReplacementType::Zero},
        {"down_timeout", ReplacementType::Zero},
        // scheduling
        {"__schedule", ReplacementType::Zero},
        {"schedule", ReplacementType::Zero},
        {"schedule_timeout", ReplacementType::Zero},
        {"might_resched", ReplacementType::Zero},
        {"__cond_sched", ReplacementType::Zero},
        {"need_resched", ReplacementType::Zero},
        {"try_to_wake_up", ReplacementType::Zero},
        {"queue_work_on", ReplacementType::Zero},
        {"__queue_work", ReplacementType::Zero},
        {"queue_work_node", ReplacementType::Zero},
        {"queue_rcu_work", ReplacementType::Zero},
        {"queue_delayed_work_on", ReplacementType::Zero},
        {"flush_workqueue_prep_pwqs", ReplacementType::Zero},
        {"check_flush_dependency", ReplacementType::Zero},
        {"kthread_create_on_node", ReplacementType::Zero},
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
        {"complete", ReplacementType::Zero},
        {"complete_all", ReplacementType::Zero},
        {"wait_for_common", ReplacementType::Nondet},
        {"wait_for_common_io", ReplacementType::Nondet},
        {"finish_wait", ReplacementType::Zero},
        {"prepare_to_wait_event", ReplacementType::Zero},
        // syscall
        {"syscall_init", ReplacementType::Zero},
        {"ret_from_fork", ReplacementType::Zero},
        {"task_current_syscall", ReplacementType::Zero},
        // smp
        {"asm_sysvec_reschedule_ipi", ReplacementType::Zero},
        {"asm_sysvec_call_function", ReplacementType::Zero},
        {"asm_sysvec_call_function_single", ReplacementType::Zero},
        {"asm_sysvec_call_irq_move_cleanup", ReplacementType::Zero},
        {"asm_sysvec_reboot", ReplacementType::Zero},
        {"asm_sysvec_thermal", ReplacementType::Zero},
        {"asm_sysvec_threshold", ReplacementType::Zero},
        {"asm_sysvec_deferred_error", ReplacementType::Zero},
        {"asm_sysvec_apic_timer_interrupt", ReplacementType::Zero},
        {"asm_sysvec_x86_platform_ipi", ReplacementType::Zero},
        {"asm_sysvec_kvm_posted_intr_ipi", ReplacementType::Zero},
        {"asm_sysvec_kvm_posted_intr_wakeup_ipi", ReplacementType::Zero},
        {"asm_sysvec_kvm_posted_intr_nested_ipi", ReplacementType::Zero},
        {"asm_sysvec_irq_move_cleanup", ReplacementType::Zero},
        {"asm_sysvec_irq_work", ReplacementType::Zero},
        {"asm_sysvec_spurious_apic_interrupt", ReplacementType::Zero},
        {"asm_sysvec_error_interrupt", ReplacementType::Zero},
        // virt
        {"_paravirt_nop", ReplacementType::Zero},
        // cpu
        {"start_cpu0", ReplacementType::Zero},
        {"start_secondary", ReplacementType::Zero},
        {"cpu_init", ReplacementType::Zero},
        {"cpu_init_secondary", ReplacementType::Zero},
        // async
        {"async_schedule_node", ReplacementType::Nondet},
        // memory/page management
        {"is_vmalloc_addr", ReplacementType::Zero},
        {"slob_alloc", ReplacementType::Nondet},
        {"slob_new_pages", ReplacementType::Nondet},
        {"__alloc_pages", ReplacementType::Nondet},
        {"__get_vm_area_node", ReplacementType::Nondet},
        {"vmap", ReplacementType::Nondet},
        {"vmap_pfn", ReplacementType::Nondet},
        {"vunmap", ReplacementType::Zero},
        {"vfree", ReplacementType::Zero},
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
        {"clear_page_orig", ReplacementType::Zero},
        {"clear_page_rep", ReplacementType::Zero},
        {"clear_page_erms", ReplacementType::Zero},
        // tlb
        {"flush_tlb_all", ReplacementType::Zero},
        {"flush_tlb_kernel_range", ReplacementType::Zero},
        {"native_flush_tlb_multi", ReplacementType::Zero},
        // resource
        {"__request_region", ReplacementType::Nondet},
        {"__release_region", ReplacementType::Nondet},
        // task_struct
        {"do_exit", ReplacementType::Zero},
        {"make_task_dead", ReplacementType::Zero},
        {"do_group_exit", ReplacementType::Zero},
        {"kernel_clone", ReplacementType::Nondet},
        {"kthread_stop", ReplacementType::Nondet},
        {"kthreadd", ReplacementType::Nondet},
        {"__kthread_init_worker", ReplacementType::Nondet},
        {"kthread_worker_fn", ReplacementType::Nondet},
        {"kthread_queue_work", ReplacementType::Nondet},
        // work_struct
        {"flush_work", ReplacementType::Zero},
        {"__flush_workqueue", ReplacementType::Zero},
        {"cancel_work_sync", ReplacementType::Zero},
        {"flush_delayed_work", ReplacementType::Zero},
        {"flush_rcu_work", ReplacementType::Zero},
        {"cancel_work", ReplacementType::Zero},
        {"cancel_delayed_work", ReplacementType::Zero},
        {"cancel_delayed_work_sync", ReplacementType::Zero},
        {"execute_in_process_context", ReplacementType::Zero},
        // io-wq
        {"io_wq_enqueue", ReplacementType::Zero},
        {"io_wq_put_and_exit", ReplacementType::Zero},
        {"io_wq_cpu_affinity", ReplacementType::Zero},
        // irq
        {"raise_softirq", ReplacementType::Zero},
        {"raise_softirq_irqoff", ReplacementType::Zero},
        {"__do_softirq", ReplacementType::Zero},
        {"do_softirq", ReplacementType::Zero},
        {"invoke_softirq", ReplacementType::Zero},
        {"__local_bh_enable", ReplacementType::Zero},
        {"local_bh_enable", ReplacementType::Zero},
        {"__local_bh_enable_ip", ReplacementType::Zero},
        {"__local_bh_disable_ip", ReplacementType::Zero},
        {"synchronize_irq", ReplacementType::Zero},
        {"synchronize_hardirq", ReplacementType::Zero},
        {"__synchronize_hardirq", ReplacementType::Zero},
        {"free_irq", ReplacementType::Zero},
        {"__free_irq", ReplacementType::Zero},
        {"__irq_disable", ReplacementType::Zero},
        {"invalidate_bh_lrus", ReplacementType::Zero},
        {"enable_irq", ReplacementType::Zero},
        {"request_threaded_irq", ReplacementType::Zero},
        {"request_nmi", ReplacementType::Zero},
        {"setup_percpu_irq", ReplacementType::Zero},
        {"__request_percpu_irq", ReplacementType::Zero},
        {"request_percpu_nmi", ReplacementType::Zero},
        // tasklet
        {"tasklet_action", ReplacementType::Zero},
        {"tasklet_action_common", ReplacementType::Zero},
        // notification
        {"kobject_uevent", ReplacementType::Zero},
        {"notifier_call_chain", ReplacementType::Zero},
        {"atomic_notifier_chain_register", ReplacementType::Zero},
        {"atomic_notifier_chain_register_unique_prio", ReplacementType::Zero},
        {"atomic_notifier_chain_unregister", ReplacementType::Zero},
        {"atomic_notifier_call_chain", ReplacementType::Zero},
        {"blocking_notifier_chain_register", ReplacementType::Zero},
        {"blocking_notifier_chain_register_unique_prio", ReplacementType::Zero},
        {"blocking_notifier_chain_unregister", ReplacementType::Zero},
        {"blocking_notifier_call_chain_robust", ReplacementType::Zero},
        {"blocking_notifier_call_chain", ReplacementType::Zero},
        {"raw_notifier_chain_register", ReplacementType::Zero},
        {"raw_notifier_chain_unregister", ReplacementType::Zero},
        {"raw_notifier_call_chain_robust", ReplacementType::Zero},
        {"raw_notifier_call_chain", ReplacementType::Zero},
        {"notify_die", ReplacementType::Zero},
        {"register_die_notifier", ReplacementType::Zero},
        {"unregister_die_notifier", ReplacementType::Zero},
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
        // iouring
        {"io_req_task_submit", ReplacementType::Zero},
        {"io_req_task_queue", ReplacementType::Zero},
        {"io_req_task_queue_failed", ReplacementType::Zero},
        {"io_req_task_complete", ReplacementType::Zero},
        // hardware
        {"default_get_nmi_reason", ReplacementType::Nondet},
        // delays
        {"delay_loop", ReplacementType::Zero},
        {"__udelay", ReplacementType::Zero},
        {"__const_udelay", ReplacementType::Zero},
        // drivers
        {"wait_for_device_probe", ReplacementType::Zero},
        {"driver_deferred_probe_trigger", ReplacementType::Zero},
        // devices
        {"device_add", ReplacementType::Zero},
        {"device_del", ReplacementType::Zero},
        {"dev_set_name", ReplacementType::Zero},
        {"device_get_ownership", ReplacementType::Zero},
        {"device_initialize", ReplacementType::Zero},
        {"device_release", ReplacementType::Zero},
        {"device_namespace", ReplacementType::Zero},
        {"dev_attr_show", ReplacementType::Zero},
        {"dev_attr_store", ReplacementType::Zero},
        // random
        {"rng_get_data", ReplacementType::Nondet},
        {"add_early_randomness", ReplacementType::Zero},
        {"hwrng_msleep", ReplacementType::Zero},
        // print/logging
        {"vsprintf", ReplacementType::Zero},
        {"vsnprintf", ReplacementType::Zero},
        {"sprintf", ReplacementType::Zero},
        {"snprintf", ReplacementType::Zero},
        {"scnprintf", ReplacementType::Zero},
        {"kvasprintf", ReplacementType::Zero},
        {"kvasprintf_const", ReplacementType::Zero},
        {"kasprintf", ReplacementType::Zero},
        {"_dev_emerg", ReplacementType::Zero},
        {"_dev_alert", ReplacementType::Zero},
        {"_dev_crit", ReplacementType::Zero},
        {"_dev_err", ReplacementType::Zero},
        {"_dev_warn", ReplacementType::Zero},
        {"_dev_notice", ReplacementType::Zero},
        {"_dev_info", ReplacementType::Zero},
        // reboot.c
        {"machine_power_off", ReplacementType::Fail},
        {"machine_shutdown", ReplacementType::Fail},
        {"machine_emergency_restart", ReplacementType::Fail},
        {"machine_restart", ReplacementType::Fail},
        {"machine_halt", ReplacementType::Zero},
        {"orderly_poweroff", ReplacementType::Fail},
        {"orderly_reboot", ReplacementType::Fail},
        {"kernel_can_power_off", ReplacementType::Zero},
        {"kernel_power_off", ReplacementType::Fail},
        {"hw_protection_shutdown", ReplacementType::Fail},
        // acpi
        {"__acpi_acquire_global_lock", ReplacementType::Zero},
        {"__acpi_release_global_lock", ReplacementType::Zero},
        {"acpi_acquire_global_lock", ReplacementType::Zero},
        {"acpi_release_global_lock", ReplacementType::Zero},
        {"acpi_ut_acquire_mutex", ReplacementType::Zero},
        {"acpi_ut_release_mutex", ReplacementType::Zero},
        {"acpi_ex_acquire_mutex", ReplacementType::Zero},
        {"acpi_ex_release_mutex", ReplacementType::Zero},
        {"acpi_os_acquire_lock", ReplacementType::Zero},
        {"acpi_os_release_lock", ReplacementType::Zero},
        {"acpi_dev_get_resources", ReplacementType::Nondet, {3}},
        {"acpi_dev_free_resource_list", ReplacementType::Zero},
        {"acpi_evaluate_object", ReplacementType::Zero},
        {"acpi_os_execute", ReplacementType::Nondet},
        {"acpi_os_vprintf", ReplacementType::Zero},
        {"acpi_os_unmap_iomem", ReplacementType::Zero},
        {"acpi_os_remove_interrupt_handler", ReplacementType::Zero},
        {"acpi_walk_resources", ReplacementType::Zero},
        {"acpi_enable_subsystem", ReplacementType::Zero},
        {"acpi_install_address_space_handler", ReplacementType::Zero},
        {"acpi_remove_address_space_handler", ReplacementType::Zero},
        {"acpi_handle_printk", ReplacementType::Zero},
        // others
        {"panic", ReplacementType::Fail},
        {"add_taint", ReplacementType::Zero},
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
      for (Function &f : M) {
        if (verifyFunction(f, &errs())) {
          errs() << "Function " << f.getName() << " verification failed\n";
        }
      }
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
