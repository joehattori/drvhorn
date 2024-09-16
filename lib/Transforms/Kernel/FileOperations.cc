#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Analysis/SeaBuiltinsInfo.hh"
#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

static unsigned iPrivateGEPIndex = 41;
static unsigned fileOpOpenIndex = 13;

class FileOperations : public ModulePass {
public:
  static char ID;

  FileOperations(StringRef name) : ModulePass(ID) { fileOpName = name; }

  bool runOnModule(Module &m) override {
    Function *open = getOpenFunc(m);
    if (!open) {
      errs() << "No open function found for struct file_operations "
             << fileOpName << "\n";
      return false;
    }
    constructMain(m, open);
    return true;
  }

private:
  StringRef fileOpName;
  DenseMap<const Type *, Function *> ndfn;

  Function *getOpenFunc(Module &m) {
    GlobalVariable *fileOp = m.getNamedGlobal(fileOpName);
    Constant *open =
        fileOp->getInitializer()->getAggregateElement(fileOpOpenIndex);
    return dyn_cast_or_null<Function>(open);
  }

  void constructMain(Module &m, Function *open) {
    LLVMContext &ctx = m.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    Function *main = Function::Create(
        FunctionType::get(i32Ty, {}, false),
        GlobalValue::LinkageTypes::ExternalLinkage, "main", &m);
    BasicBlock *entry = BasicBlock::Create(ctx, "entry", main);
    BasicBlock *fail = BasicBlock::Create(ctx, "fail", main);
    BasicBlock *ret = BasicBlock::Create(ctx, "ret", main);

    buildEntryBlock(m, open, entry, fail, ret);
    buildFailBlock(m, fail, ret);
    buildRetBlock(m, ret);
  }

  void buildEntryBlock(Module &m, Function *open, BasicBlock *entry,
                       BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(entry);
    Type *i32Ty = Type::getInt32Ty(m.getContext());

    Type *inodePtrType = open->getArg(0)->getType();
    Type *inodeType = inodePtrType->getPointerElementType();
    const DenseMap<uint64_t, Type *> &fields =
        iPrivateFields(open, inodePtrType);
    Value *inode = allocType(m, b, inodeType);
    size_t byteSize = getIPrivateSize(m, fields);
    Value *iPrivate = buildIPrivate(m, b, inodeType, inode, byteSize);
    populateFields(m, b, iPrivate, fields);
    SmallVector<Value *, 8> devicePtrs =
        embeddedStructDevicePtrs(m, b, iPrivate, fields);
    switch (devicePtrs.size()) {
    case 0:
      errs() << "No struct device found\n";
      break;
    case 1:
      callSetupKref(m, b, devicePtrs[0]);
      break;
    default:
      errs() << "TODO: multiple struct device\n";
      return;
    }

    Type *filePtrType = open->getArg(1)->getType();
    Value *file = allocType(m, b, filePtrType->getPointerElementType());
    CallInst *call = b.CreateCall(open->getFunctionType(), open, {inode, file});
    Value *notZero = b.CreateICmpNE(call, ConstantInt::get(i32Ty, 0));
    b.CreateCondBr(notZero, fail, ret);
  }

  void callSetupKref(Module &m, IRBuilder<> &b, Value *devicePtr) {
    LLVMContext &ctx = m.getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);
    Function *setupKref = m.getFunction("drvhorn.setup_kref");
    PointerType *krefPtrType =
        StructType::getTypeByName(m.getContext(), "struct.kref")
            ->getPointerTo();
    GlobalVariable *globalKref = new GlobalVariable(
        m, setupKref->getArg(1)->getType()->getPointerElementType(), false,
        GlobalValue::LinkageTypes::PrivateLinkage,
        ConstantPointerNull::get(krefPtrType), "drvhorn.kref.struct.device");
    Value *krefPtr =
        b.CreateGEP(devicePtr->getType()->getPointerElementType(), devicePtr,
                    {ConstantInt::get(i64Ty, 0), ConstantInt::get(i32Ty, 0),
                     ConstantInt::get(i32Ty, 6)});
    if (setupKref->getArg(0)->getType() != krefPtr->getType())
      krefPtr = b.CreateBitCast(krefPtr, setupKref->getArg(0)->getType());
    b.CreateCall(setupKref, {krefPtr, globalKref});
  }

  void buildFailBlock(Module &m, BasicBlock *fail, BasicBlock *ret) {
    IRBuilder<> b(fail);
    Function *checker = m.getFunction("drvhorn.assert_kref");
    for (GlobalVariable *g : getKrefs(m)) {
      Value *v = b.CreateLoad(g->getValueType(), g);
      if (v->getType() != checker->getArg(0)->getType())
        v = b.CreateBitCast(v, checker->getArg(0)->getType());
      b.CreateCall(checker, v);
    }
    b.CreateBr(ret);
  }

  void buildRetBlock(Module &m, BasicBlock *ret) {
    LLVMContext &ctx = m.getContext();
    Type *i32Ty = Type::getInt32Ty(ctx);
    ReturnInst::Create(ctx, ConstantInt::get(i32Ty, 0), ret);
  }

  DenseMap<uint64_t, Type *> iPrivateFields(const Function *fn,
                                            const Type *inodePtrType) {
    const Instruction *iPrivate = iPrivatePtr(fn, inodePtrType);
    DenseMap<uint64_t, Type *> fields;
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
                            DenseMap<uint64_t, Type *> &fields) {
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

  Value *allocType(Module &m, IRBuilder<> &b, Type *type) {
    AllocaInst *alloc = b.CreateAlloca(type);
    Function *nondet = getNondetFn(type, m);
    CallInst *val = b.CreateCall(nondet);
    // Fill the allocated memory with a nondet value.
    b.CreateStore(val, alloc);
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

  size_t getIPrivateSize(const Module &m,
                         const DenseMap<uint64_t, Type *> &fields) {
    size_t byteSize = 0;
    const DataLayout &dl = m.getDataLayout();
    for (const auto &field : fields) {
      byteSize += dl.getTypeAllocSize(field.second);
    }
    return byteSize;
  }

  Value *buildIPrivate(Module &m, IRBuilder<> &b, Type *inodeType,
                       Value *inodePtr, uint64_t byteSize) {
    Type *i8Type = Type::getInt8Ty(m.getContext());
    Type *i32Type = Type::getInt32Ty(m.getContext());
    Type *i64Type = Type::getInt64Ty(m.getContext());
    Constant *zero = ConstantInt::get(i64Type, 0);
    Constant *iPrivateOffset = ConstantInt::get(i32Type, iPrivateGEPIndex);
    Value *iPrivateGEP =
        b.CreateGEP(inodeType, inodePtr, {zero, iPrivateOffset});
    Value *iPrivatePtr =
        b.CreateAlloca(i8Type, ConstantInt::get(i64Type, byteSize));
    b.CreateStore(iPrivatePtr, iPrivateGEP);
    return iPrivatePtr;
  }

  SmallVector<Value *, 8>
  embeddedStructDevicePtrs(Module &m, IRBuilder<> &b, Value *iPrivate,
                           const DenseMap<uint64_t, Type *> &fields) {
    SmallVector<Value *, 8> devicePtrs;
    StructType *deviceType =
        StructType::getTypeByName(m.getContext(), "struct.device");
    if (!deviceType) {
      errs() << "`struct device` type not found?\n";
      return {};
    }
    LLVMContext &ctx = m.getContext();
    Type *i8Type = Type::getInt8Ty(ctx);
    Type *i32Type = Type::getInt32Ty(ctx);
    Type *i64Type = Type::getInt64Ty(ctx);
    for (const auto &field : fields) {
      uint64_t idx = field.first;
      Type *fieldType = field.second;
      if (StructType *structType =
              dyn_cast<StructType>(fieldType->getPointerElementType())) {
        Value *fieldPtrAddr =
            b.CreateGEP(i8Type, iPrivate, ConstantInt::get(i64Type, idx));
        Value *fieldPtr =
            b.CreateBitCast(fieldPtrAddr, fieldType->getPointerTo());
        Value *fieldValue = b.CreateLoad(fieldType, fieldPtr);

        SmallVector<uint64_t, 8> indices =
            indicesToDeviceType(structType, deviceType);
        if (indices.empty())
          continue;
        SmallVector<Value *, 8> gepIndices;
        gepIndices.push_back(ConstantInt::get(i64Type, 0));
        for (int i = indices.size() - 1; i >= 0; i--) {
          gepIndices.push_back(ConstantInt::get(i32Type, indices[i]));
        }

        Value *gep = b.CreateGEP(structType, fieldValue, gepIndices);
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

  void populateFields(Module &m, IRBuilder<> &b, Value *instanceAddr,
                      const DenseMap<uint64_t, Type *> &fields) {
    Type *i8Type = Type::getInt8Ty(m.getContext());
    Type *i64Type = Type::getInt64Ty(m.getContext());
    for (const auto &field : fields) {
      Value *idx = ConstantInt::get(i64Type, field.first);
      Value *fieldAddr = b.CreateGEP(i8Type, instanceAddr, idx);
      Value *fieldPtrDest =
          b.CreateBitCast(fieldAddr, i8Type->getPointerTo()->getPointerTo());
      Value *fieldPtr = allocType(m, b, field.second->getPointerElementType());
      Value *casted = b.CreateBitCast(fieldPtr, i8Type->getPointerTo());
      b.CreateStore(casted, fieldPtrDest);
    }
  }
};

char FileOperations::ID = 0;

Pass *createFileOperationsSetupPass(StringRef name) {
  return new FileOperations(name);
}
} // namespace seahorn
