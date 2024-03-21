#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Pass.h"

#include <iostream>

using namespace llvm;

namespace seahorn {

class AcpiSetup : public ModulePass {
public:
  static char ID;

  AcpiSetup() : ModulePass(ID) {}

  bool runOnModule(Module &M) override {
    Function *main = M.getFunction("main");
    assert(main && "main function not found");

    LLVMContext &ctx = M.getContext();
    IRBuilder<> B(ctx);
    BasicBlock *BB = BasicBlock::Create(ctx, "", main);
    B.SetInsertPoint(BB, BB->begin());

    Function *acpi_init = M.getFunction("acpi_locate_initial_tables");
    assert(acpi_init && "acpi_locate_initial_tables not found");
    B.CreateCall(acpi_init);

    // TODO(hattori): assert refcount is zero
    return true;
  }

  virtual StringRef getPassName() const override { return "AcpiSetup"; }
};

char AcpiSetup::ID = 0;

Pass *createAcpiSetupPass() { return new AcpiSetup(); }
}
