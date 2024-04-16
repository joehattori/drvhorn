#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
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

    GlobalVariable *compilerUsed = M.getNamedGlobal(COMPILER_USED_NAME);
    Type *ty = compilerUsed->getType();
    compilerUsed->eraseFromParent();
    // llvm.compiler.used seems to be required, so insert an empty value
    M.getOrInsertGlobal(COMPILER_USED_NAME, ty->getPointerElementType());

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

  void removeFunctions(Module &M) {
    // first key: name of the function
    // second key: strategy to replace the function
    std::pair<StringRef, ReplacementType> fns[] = {
        // lock
        {"mutex_lock", ReplacementType::Zero},
        {"mutex_unlock", ReplacementType::Zero},
        {"__acpi_acquire_global_lock", ReplacementType::Zero},
        {"__acpi_release_global_lock", ReplacementType::Zero},
        {"__srcu_read_lock", ReplacementType::Zero},
        {"__srcu_read_unlock", ReplacementType::Zero},
        {"chip_bus_lock", ReplacementType::Zero},
        {"chip_bus_unlock", ReplacementType::Zero},
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
        // memory management
        {"is_vmalloc_addr", ReplacementType::Zero},
        {"slob_alloc", ReplacementType::Nondet},
        {"slob_new_pages", ReplacementType::Nondet},
        {"__alloc_pages", ReplacementType::Nondet},
        {"ioremap", ReplacementType::Nondet},
        {"__early_ioremap", ReplacementType::Nondet},
        {"__ioremap_caller", ReplacementType::Nondet},
        {"iounmap", ReplacementType::Zero},
        {"early_iounmap", ReplacementType::Zero},
        {"set_pte_vaddr", ReplacementType::Zero},
        {"set_pte_vaddr_pud", ReplacementType::Zero},
        {"populate_extra_pmd", ReplacementType::Nondet},
        {"populate_extra_pte", ReplacementType::Nondet},
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
        {"__synchronize_irq", ReplacementType::Zero},
        {"synchronize_hardirq", ReplacementType::Zero},
        {"__synchronize_hardirq", ReplacementType::Zero},
        // tasklet
        {"tasklet_action", ReplacementType::Zero},
        {"tasklet_action_common", ReplacementType::Zero},
        // notification
        {"kobject_uevent", ReplacementType::Zero},
        // hardware
        {"default_get_nmi_reason", ReplacementType::Nondet},
        // others
        {"panic", ReplacementType::Fail},
    };
    for (const std::pair<StringRef, ReplacementType> &fn : fns) {
      StringRef name = fn.first;
      if (Function *f = M.getFunction(name)) {
        Function *dummy;
        switch (fn.second) {
        case ReplacementType::Zero:
          dummy = getDummyFunction(f->getFunctionType(), M);
          break;
        case ReplacementType::Nondet:
          dummy = getNondetFn(f->getFunctionType(), M);
          break;
        case ReplacementType::Fail:
          dummy = getFailureFn(f->getFunctionType(), M);
          break;
        };
        f->replaceAllUsesWith(dummy);
        f->eraseFromParent();
      }
    }
  }

  Function *getDummyFunction(FunctionType *type, Module &M) {
    auto it = dummyFn.find(type);
    if (it != failureFn.end()) {
      return it->second;
    }

    LLVMContext &ctx = M.getContext();
    Function *res = makeNewFn(M, type, dummyFn.size(), "verifier.dummy.");
    BasicBlock *block = BasicBlock::Create(ctx, "", res);
    Value *ret = nullptr;
    Type *retType = type->getReturnType();
    if (!retType->isVoidTy()) {
      ret = Constant::getNullValue(retType);
    }
    ReturnInst::Create(ctx, ret, block);
    return res;
  }

  Function *getFailureFn(FunctionType *type, Module &M) {
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

  Function *getNondetFn(FunctionType *type, Module &M) {
    auto it = ndfn.find(type);
    if (it != ndfn.end()) {
      return it->second;
    }

    Function *res = makeNewFn(M, type, ndfn.size(), "verifier.nondet.");
    ndfn[type] = res;
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
