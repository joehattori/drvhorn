#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include <iostream>

// indices of fields in struct acpi_table_list
#define ACPI_TABLE_DESC_INDEX 0
#define CURRENT_TABLE_COUNT_INDEX 1
#define MAX_TABLE_COUNT_INDEX 2
// indices of fields in struct acpi_table_desc
#define SIGNATURE_INDEX 3
#define VALIDATION_COUNT_INDEX 6

using namespace llvm;

namespace seahorn {

class AcpiSetup : public ModulePass {
public:
  static char ID;

  AcpiSetup(std::string entry) : ModulePass(ID), entry_point(entry) {}

  bool runOnModule(Module &M) override {
    Function *main = M.getFunction("main");
    acpiInitialization(M, main);
    buildAssertion(M, main);
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

  void acpiInitialization(Module &M, Function *main) {
    LLVMContext &ctx = M.getContext();
    BasicBlock *block = BasicBlock::Create(ctx, "", main);
    IRBuilder<> B(block);

    StructType *acpiTableType =
        StructType::getTypeByName(ctx, "struct.acpi_table_list");
    GlobalVariable *acpiTable = M.getGlobalVariable("acpi_gbl_root_table_list");
    assert(acpiTable && "initial_tables not found");

    StructType *descType =
        StructType::getTypeByName(ctx, "struct.acpi_table_desc");
    ArrayType *initialTablesType = ArrayType::get(descType, 128);
    Constant *initialTables =
        M.getOrInsertGlobal("initial_tables", initialTablesType);
    assert(initialTables && "initial_tables not found");
    Value *castedInitialTables =
        B.CreateBitCast(initialTables, descType->getPointerTo());
    Value *tablesPtr =
        B.CreateStructGEP(acpiTableType, acpiTable, ACPI_TABLE_DESC_INDEX);
    B.CreateStore(castedInitialTables, tablesPtr);

    // acpi_gbl_root_table_list.current_table_count = 1;
    Value *currentTableCountPtr =
        B.CreateStructGEP(acpiTableType, acpiTable, CURRENT_TABLE_COUNT_INDEX);
    Type *i32Ty = Type::getInt32Ty(ctx);
    Constant *one = ConstantInt::get(i32Ty, 1);
    B.CreateStore(one, currentTableCountPtr);

    // acpi_gbl_root_table_list.max_table_count = ACPI_MAX_TABLES;
    Value *maxTableCountPtr =
        B.CreateStructGEP(acpiTableType, acpiTable, MAX_TABLE_COUNT_INDEX);
    Constant *maxTableCount = ConstantInt::get(i32Ty, 128);
    B.CreateStore(maxTableCount, maxTableCountPtr);

    // acpi_gbl_root_table_list.tables[0].validation_count = 0;
    Value *firstTableDescPtr =
        B.CreateLoad(descType->getPointerTo(), tablesPtr);
    Value *validationCountPtr =
        B.CreateStructGEP(descType, firstTableDescPtr, VALIDATION_COUNT_INDEX);
    Type *i16Ty = Type::getInt16Ty(ctx);
    Constant *zero = ConstantInt::get(i16Ty, 0);
    B.CreateStore(zero, validationCountPtr);

    // acpi_gbl_root_table_list.tables[0].signature.integer = 0x324d5054;
    // // 0x324d5054: int of "2MPT", reversed "TPM2"
    Value *signaturePtr =
        B.CreateStructGEP(descType, firstTableDescPtr, SIGNATURE_INDEX);
    Value *intSignaturePtr = B.CreateStructGEP(
        signaturePtr->getType()->getPointerElementType(), signaturePtr, 0);
    Constant *tpm2Int = ConstantInt::get(i32Ty, 0x324d5054);
    B.CreateStore(tpm2Int, intSignaturePtr);
  }

  void buildAssertion(Module &M, Function *main) {
    LLVMContext &ctx = M.getContext();
    IRBuilder<> B(&main->back());

    assert(entry_point != "" && "entry-point not specified");
    Function *entry = M.getFunction(entry_point);
    assert(entry && "entry-point not found");
    SmallVector<Value *, 16> args;
    for (Argument &A : entry->args()) {
      FunctionCallee ndf = getNondetFn(A.getType(), M);
      args.push_back(B.CreateCall(ndf));
    }
    B.CreateCall(entry, args);

    Type *i32Ty = Type::getInt32Ty(ctx);
    BasicBlock *errBlock = BasicBlock::Create(ctx, "", main);
    BasicBlock *retBlock = BasicBlock::Create(ctx, "", main);

    // build failure path
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
} // namespace seahorn
