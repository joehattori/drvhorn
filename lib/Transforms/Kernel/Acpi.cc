#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Analysis/SeaBuiltinsInfo.hh"
#include "seahorn/Support/SeaDebug.h"

#include <iostream>

// index of struct acpi_table_desc in struct acpi_table_list
#define ACPI_TABLE_DESC_INDEX 0
// index of u32 validation_count in struct acpi_table_desc
#define VALIDATION_COUNT_INDEX 2

using namespace llvm;

namespace seahorn {

class AcpiSetup : public ModulePass {
public:
  static char ID;

  AcpiSetup(std::string entry) : ModulePass(ID), entry_point(entry) {}

  bool runOnModule(Module &M) override {
    Function *main = insertMain(M);
    if (!main)
      return false;
    CallInst *call = insertEntryCall(M, main);
    buildErrorPathAssertion(M, main, call);
    return true;
  }

  virtual StringRef getPassName() const override { return "AcpiSetup"; }

private:
  // Basically copied from DummyMainFunction.cc
  DenseMap<const Type *, FunctionCallee> ndfn;
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
    auto it = ndfn.find(type);
    if (it != ndfn.end()) {
      return it->second;
    }

    FunctionCallee res =
        makeNewNondetFn(M, *type, ndfn.size(), "verifier.nondet.");
    ndfn[type] = res;
    return res;
  }

  Function *insertMain(Module &M) {
    if (M.getFunction("main")) {
      LOG("ACPI", errs() << "ACPI: Main already exists.\n");
      return nullptr;
    }

    Type *i32Ty = Type::getInt32Ty(M.getContext());
    ArrayRef<Type *> params;
    return Function::Create(FunctionType::get(i32Ty, params, false),
                            GlobalValue::LinkageTypes::ExternalLinkage, "main",
                            &M);
  }

  CallInst *insertEntryCall(Module &M, Function *main) {
    BasicBlock *block = BasicBlock::Create(M.getContext(), "", main);
    IRBuilder<> B(block);
    assert(entry_point != "" && "entry-point not specified");
    Function *entry = M.getFunction(entry_point);
    assert(entry && "entry-point not found");
    SmallVector<Value *, 16> args;
    for (Argument &A : entry->args()) {
      FunctionCallee ndf = getNondetFn(A.getType(), M);
      args.push_back(B.CreateCall(ndf));
    }
    return B.CreateCall(entry, args);
  }

  void buildErrorPathAssertion(Module &M, Function *main, CallInst *entryCall) {
    LLVMContext &ctx = M.getContext();
    IRBuilder<> B(&main->back());
    Type *i32Ty = Type::getInt32Ty(ctx);
    Value *isFailure = B.CreateICmpNE(entryCall, ConstantInt::get(i32Ty, 0));
    BasicBlock *failBlock = BasicBlock::Create(ctx, "", main);
    BasicBlock *errBlock = BasicBlock::Create(ctx, "", main);
    BasicBlock *retBlock = BasicBlock::Create(ctx, "", main);

    B.CreateCondBr(isFailure, failBlock, retBlock);

    // build failure path
    B.SetInsertPoint(failBlock);
    StructType *acpiTableType =
        StructType::getTypeByName(ctx, "struct.acpi_table_list");
    GlobalVariable *acpiTable = M.getGlobalVariable("acpi_gbl_root_table_list");
    Value *tablesPtr =
        B.CreateStructGEP(acpiTableType, acpiTable, ACPI_TABLE_DESC_INDEX);
    StructType *descType =
        StructType::getTypeByName(ctx, "struct.acpi_table_desc");
    Value *firstTableDescPtr =
        B.CreateLoad(descType->getPointerTo(), tablesPtr);
    Value *validationCountPtr =
        B.CreateStructGEP(descType, firstTableDescPtr, VALIDATION_COUNT_INDEX);
    Type *i16Ty = Type::getInt16Ty(ctx);
    LoadInst *validationCount = B.CreateLoad(i16Ty, validationCountPtr);
    Value *isZero = B.CreateICmpEQ(validationCount, ConstantInt::get(i16Ty, 0));
    B.CreateCondBr(isZero, retBlock, errBlock);

    // build error path
    B.SetInsertPoint(errBlock);
    FunctionCallee errFn = M.getOrInsertFunction(
        "__VERIFIER_error", FunctionType::get(Type::getVoidTy(ctx), false));
    B.CreateCall(errFn);
    B.CreateBr(retBlock);

    // build success path
    B.SetInsertPoint(retBlock);
    B.CreateRet(ConstantInt::get(i32Ty, 42));
  }
};

char AcpiSetup::ID = 0;

Pass *createAcpiSetupPass(std::string entry) { return new AcpiSetup(entry); }
}
