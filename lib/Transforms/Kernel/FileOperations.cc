#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Analysis/SeaBuiltinsInfo.hh"
#include "seahorn/Transforms/Kernel/Util.hh"

#include <algorithm>
#include <map>
#include <vector>

using namespace llvm;

namespace seahorn {

static unsigned iPrivateGEPIndex = 41;

class FileOperations : public ModulePass {
public:
  static char ID;

  FileOperations(const std::string &name) : ModulePass(ID) { funcName = name; }

  bool runOnModule(Module &M) override {
    seahorn::SeaBuiltinsInfo &sbi =
        getAnalysis<SeaBuiltinsInfoWrapperPass>().getSBI();
    Function *verifierError = sbi.mkSeaBuiltinFn(SeaBuiltinsOp::ERROR, M);
    constructMain(M, verifierError);
    return true;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<seahorn::SeaBuiltinsInfoWrapperPass>();
    AU.setPreservesAll();
  }

private:
  StringRef funcName;
  DenseMap<const Type *, Function *> ndfn;

  void constructMain(Module &M, Function *verifierError) {
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    Function *main = Function::Create(
        FunctionType::get(i32Ty, {}, false),
        GlobalValue::LinkageTypes::ExternalLinkage, "main", &M);
    BasicBlock *entry = BasicBlock::Create(M.getContext(), "entry", main);
    BasicBlock *fail = BasicBlock::Create(M.getContext(), "fail", main);
    BasicBlock *err = BasicBlock::Create(M.getContext(), "error", main);
    BasicBlock *ret = BasicBlock::Create(M.getContext(), "ret", main);

    Value *devicePtr = buildEntryBlock(M, entry, fail, ret);
    buildFailBlock(M, fail, err, ret, devicePtr);
    buildErrBlock(M, err, ret, verifierError);
    buildRetBlock(M, ret, entry, fail, err);
  }

  void callSetupDevice(Module &M, IRBuilder<> &B, Value *devicePtr) {
    Function *setupDevice = M.getFunction("__DRVHORN_setup_device");
    if (setupDevice->getArg(0)->getType() != devicePtr->getType())
      devicePtr = B.CreateBitCast(devicePtr, setupDevice->getArg(0)->getType());
    B.CreateCall(setupDevice, {devicePtr});
  }

  void callDeviceSassert(Module &M, IRBuilder<> &B, Value *devicePtr) {
    Function *deviceSassert = M.getFunction("__DRVHORN_device_sassert");
    if (deviceSassert->getArg(0)->getType() != devicePtr->getType())
      devicePtr =
          B.CreateBitCast(devicePtr, deviceSassert->getArg(0)->getType());
    B.CreateCall(deviceSassert, {devicePtr});
  }

  Value *buildEntryBlock(Module &M, BasicBlock *entry, BasicBlock *fail,
                         BasicBlock *ret) {
    IRBuilder<> B(entry);
    Function *open = M.getFunction(funcName);
    Type *i32Ty = Type::getInt32Ty(M.getContext());

    Type *inodePtrType = open->getArg(0)->getType();
    Type *inodeType = inodePtrType->getPointerElementType();
    const std::map<uint64_t, Type *> &fields =
        iPrivateFields(open, inodePtrType);
    Value *inode = allocType(M, B, inodeType);
    size_t byteSize = getIPrivateSize(M, fields);
    Value *iPrivate = buildIPrivate(M, B, inodeType, inode, byteSize);
    populateFields(M, B, iPrivate, fields);
    SmallVector<Value *, 8> devicePtrs =
        embeddedStructDevicePtrs(M, B, iPrivate, fields);
    switch (devicePtrs.size()) {
    case 0:
      errs() << "No struct device found\n";
      return {};
    case 1:
      break;
    default:
      errs() << "TODO: multiple struct device\n";
      return {};
    }
    Value *devicePtr = devicePtrs[0];
    callSetupDevice(M, B, devicePtr);

    Type *filePtrType = open->getArg(1)->getType();
    Value *file = allocType(M, B, filePtrType->getPointerElementType());
    CallInst *call = B.CreateCall(open->getFunctionType(), open, {inode, file});
    Value *notZero = B.CreateICmpNE(call, ConstantInt::get(i32Ty, 0));
    B.CreateCondBr(notZero, fail, ret);
    return devicePtr;
  }

  void buildFailBlock(Module &M, BasicBlock *fail, BasicBlock *err,
                      BasicBlock *ret, Value *devicePtr) {
    Function *counterFn = M.getFunction("__DRVHORN_util_get_device_counter");
    Type *i32Ty = Type::getInt32Ty(M.getContext());
    IRBuilder<> B(fail);
    if (counterFn->getArg(0)->getType() != devicePtr->getType())
      devicePtr = B.CreateBitCast(devicePtr, counterFn->getArg(0)->getType());
    CallInst *counter = B.CreateCall(counterFn, {devicePtr});
    Value *isOne = B.CreateICmpEQ(counter, ConstantInt::get(i32Ty, 1));
    B.CreateCondBr(isOne, ret, err);
  }

  void buildErrBlock(Module &M, BasicBlock *err, BasicBlock *ret,
                     Function *verifierError) {
    IRBuilder<> B(err);
    B.CreateCall(verifierError);
    B.CreateBr(ret);
  }

  void buildRetBlock(Module &M, BasicBlock *ret, BasicBlock *entry,
                     BasicBlock *fail, BasicBlock *err) {
    LLVMContext &ctx = M.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    ReturnInst::Create(ctx, ConstantInt::get(i32Ty, 0), ret);
  }

  std::map<uint64_t, Type *> iPrivateFields(Function *fn,
                                            const Type *inodePtrType) {
    const Instruction *iPrivate = iPrivatePtr(fn, inodePtrType);
    std::map<uint64_t, Type *> fields;
    if (!iPrivate) {
      errs() << "No i_private GEP found\n";
      return fields;
    }
    for (const User *u : iPrivate->users()) {
      collectIPrivateField(u, 0, iPrivate, fields);
    }
    return fields;
  }

  void collectIPrivateField(const User *user, uint64_t currentIndex,
                            const Instruction *iPrivate,
                            std::map<uint64_t, Type *> &fields) {
    if (const GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(user)) {
      if (gep->getNumIndices() != 1 || gep->getPointerOperand() != iPrivate) {
        errs() << "TODO: handle this GEP in " << __func__ << *gep << '\n';
        return;
      }
      const ConstantInt *idx = dyn_cast<ConstantInt>(gep->getOperand(1));
      if (!idx)
        return;
      uint64_t intIdx = idx->getZExtValue();
      for (const User *user : gep->users()) {
        collectIPrivateField(user, intIdx, gep, fields);
      }
    } else if (const BitCastInst *bitcast = dyn_cast<BitCastInst>(user)) {
      if (bitcast->getOperand(0) == iPrivate &&
          bitcast->getDestTy()->isPointerTy())
        fields[currentIndex] = bitcast->getDestTy()->getPointerElementType();
    }
  }

  const Instruction *iPrivatePtr(const Function *fn, const Type *inodePtrType) {
    for (const Instruction &inst : instructions(fn)) {
      if (const GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(&inst)) {
        if (isIPrivateGEP(gep, inodePtrType)) {
          for (const User *user : gep->users()) {
            if (const LoadInst *load = dyn_cast<LoadInst>(user)) {
              if (load->getPointerOperand() == gep)
                return load;
            }
          }
        }
      }
    }
    return nullptr;
  }

  bool isIPrivateGEP(const GetElementPtrInst *gep, const Type *inodePtrType) {
    if (gep->getNumIndices() != 2)
      return false;
    ConstantInt *idx = dyn_cast<ConstantInt>(gep->getOperand(2));
    if (!idx)
      return false;
    return gep->getPointerOperandType() == inodePtrType &&
           idx->getZExtValue() == iPrivateGEPIndex;
  }

  Value *allocType(Module &M, IRBuilder<> &B, Type *type) {
    AllocaInst *alloc = B.CreateAlloca(type);
    Function *nondet = getNondetFn(type, M);
    CallInst *val = B.CreateCall(nondet);
    // Fill the allocated memory with a nondet value.
    B.CreateStore(val, alloc);
    return alloc;
  }

  Function *createNewNondetFn(Module &m, Type &type, unsigned num,
                              std::string prefix) {
    std::string name;
    unsigned c = num;
    do {
      name = prefix + std::to_string(c++);
    } while (m.getNamedValue(name));
    return dyn_cast<Function>(m.getOrInsertFunction(name, &type).getCallee());
  }

  Function *getNondetFn(Type *type, Module &m) {
    auto it = ndfn.find(type);
    if (it != ndfn.end()) {
      return it->second;
    }
    Function *res =
        createNewNondetFn(m, *type, ndfn.size(), "verifier.nondet.");
    ndfn[type] = res;
    return res;
  }

  size_t getIPrivateSize(const Module &M,
                         const std::map<uint64_t, Type *> &fields) {
    size_t byteSize = 0;
    const DataLayout &dl = M.getDataLayout();
    for (const auto &field : fields) {
      byteSize += dl.getTypeAllocSize(field.second);
    }
    return byteSize;
  }

  Value *buildIPrivate(Module &M, IRBuilder<> &B, Type *inodeType,
                       Value *inodePtr, uint64_t byteSize) {
    Type *i8Type = Type::getInt8Ty(M.getContext());
    Type *i32Type = Type::getInt32Ty(M.getContext());
    Type *i64Type = Type::getInt64Ty(M.getContext());
    Constant *zero = ConstantInt::get(i64Type, 0);
    Constant *iPrivateOffset = ConstantInt::get(i32Type, iPrivateGEPIndex);
    Value *iPrivateGEP =
        B.CreateGEP(inodeType, inodePtr, {zero, iPrivateOffset});
    Value *iPrivatePtr =
        B.CreateAlloca(i8Type, ConstantInt::get(i64Type, byteSize));
    B.CreateStore(iPrivatePtr, iPrivateGEP);
    return iPrivatePtr;
  }

  SmallVector<Value *, 8>
  embeddedStructDevicePtrs(Module &M, IRBuilder<> &B, Value *iPrivate,
                           const std::map<uint64_t, Type *> &fields) {
    SmallVector<Value *, 8> devicePtrs;
    StructType *deviceType =
        StructType::getTypeByName(M.getContext(), "struct.device");
    if (!deviceType) {
      errs() << "`struct device` type not found?\n";
      return {};
    }
    LLVMContext &ctx = M.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    Type *i64Type = Type::getInt64Ty(ctx);
    for (const auto &field : fields) {
      uint64_t idx = field.first;
      Type *fieldType = field.second;
      if (StructType *structType =
              dyn_cast<StructType>(fieldType->getPointerElementType())) {
        Value *fieldPtrAddr =
            B.CreateGEP(i8Type, iPrivate, ConstantInt::get(i64Type, idx));
        Value *fieldPtr =
            B.CreateBitCast(fieldPtrAddr, fieldType->getPointerTo());
        Value *fieldValue = B.CreateLoad(fieldType, fieldPtr);

        SmallVector<uint64_t, 8> indices =
            indicesToDeviceType(structType, deviceType);
        if (indices.empty())
          continue;
        SmallVector<Value *, 8> gepIndices;
        gepIndices.push_back(ConstantInt::get(i64Type, 0));
        for (int i = indices.size() - 1; i >= 0; i--) {
          gepIndices.push_back(ConstantInt::get(i32Type, indices[i]));
        }

        Value *gep = B.CreateGEP(structType, fieldValue, gepIndices);
        devicePtrs.push_back(gep);
      }
    }
    return devicePtrs;
  }

  SmallVector<uint64_t, 8> indicesToDeviceType(const StructType *type,
                                               StructType *deviceType) {
    for (size_t i = 0; i < type->getNumElements(); i++) {
      const StructType *fieldType =
          dyn_cast<StructType>(type->getElementType(i));
      if (!fieldType)
        continue;
      if (equivTypes(fieldType, deviceType)) {
        return {i};
      }
      SmallVector<uint64_t, 8> indices =
          indicesToDeviceType(fieldType, deviceType);
      if (!indices.empty()) {
        indices.push_back(i);
        return indices;
      }
    }
    return {};
  }

  void populateFields(Module &M, IRBuilder<> &B, Value *instanceAddr,
                      const std::map<uint64_t, Type *> &fields) {
    Type *i8Type = Type::getInt8Ty(M.getContext());
    Type *i64Type = Type::getInt64Ty(M.getContext());
    for (const auto &field : fields) {
      Value *idx = ConstantInt::get(i64Type, field.first);
      Value *fieldAddr = B.CreateGEP(i8Type, instanceAddr, idx);
      Value *fieldPtrDest =
          B.CreateBitCast(fieldAddr, i8Type->getPointerTo()->getPointerTo());
      Value *fieldPtr = allocType(M, B, field.second->getPointerElementType());
      Value *casted = B.CreateBitCast(fieldPtr, i8Type->getPointerTo());
      B.CreateStore(casted, fieldPtrDest);
    }
  }
};

char FileOperations::ID = 0;

Pass *createFileOperationsSetupPass(const std::string &func) {
  return new FileOperations(func);
}
} // namespace seahorn
