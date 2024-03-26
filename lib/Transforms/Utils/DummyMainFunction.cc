/** Insert dummy main function if one does not exist */

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "seahorn/Support/SeaDebug.h"

using namespace llvm;

namespace seahorn {

class DummyMainFunction : public ModulePass {
  DenseMap<const Type *, FunctionCallee> m_ndfn;
  std::string entry_point;

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
    auto it = m_ndfn.find(type);
    if (it != m_ndfn.end()) {
      return it->second;
    }

    FunctionCallee res =
        makeNewNondetFn(M, *type, m_ndfn.size(), "verifier.nondet.");
    m_ndfn[type] = res;
    return res;
  }

public:
  static char ID;

  DummyMainFunction(std::string entry) : ModulePass(ID), entry_point(entry) {}

  bool runOnModule(Module &M) override {

    if (M.getFunction("main")) {
      LOG("dummy-main", errs() << "DummyMainFunction: Main already exists.\n");

      return false;
    }

    Function *Entry = nullptr;
    if (entry_point != "")
      Entry = M.getFunction(entry_point);

    // --- Create main
    LLVMContext &ctx = M.getContext();
    Type *intTy = Type::getInt32Ty(ctx);

    ArrayRef<Type *> params;
    Function *main = Function::Create(
        FunctionType::get(intTy, params, false),
        GlobalValue::LinkageTypes::ExternalLinkage, "main", &M);

    IRBuilder<> B(ctx);
    BasicBlock *BB = BasicBlock::Create(ctx, "", main);
    B.SetInsertPoint(BB, BB->begin());

    std::vector<Function *> FunctionsToCall;
    if (Entry) {
      FunctionsToCall.push_back(Entry);
    } else {
      // --- if no selected entry found then we call to all
      //     non-declaration functions.
      for (auto &F : M) {
        if (F.getName() == "main") // avoid recursive call to main
          continue;
        if (F.isDeclaration())
          continue;
        FunctionsToCall.push_back(&F);
      }
    }

    for (auto F : FunctionsToCall) {
      // -- create a call with non-deterministic actual parameters
      SmallVector<Value *, 16> Args;
      for (auto &A : F->args()) {
        FunctionCallee ndf = getNondetFn(A.getType(), M);
        Args.push_back(B.CreateCall(ndf));
      }
      CallInst *CI = B.CreateCall(F, Args);
      LOG("dummy-main",
          errs() << "DummyMainFunction: created a call " << *CI << "\n");
    }

    // -- return of main
    // our favourite exit code
    B.CreateRet(ConstantInt::get(intTy, 42));

    return true;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
  }

  virtual StringRef getPassName() const override {
    return "Add dummy main function";
  }
};

char DummyMainFunction::ID = 0;

Pass *createDummyMainFunctionPass(std::string entry) {
  return new DummyMainFunction(entry);
}

} // namespace seahorn
