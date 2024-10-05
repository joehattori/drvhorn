#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

#include "seahorn/Transforms/Kernel/Util.hh"

using namespace llvm;

namespace seahorn {

static SmallVector<size_t> krefRevIndices(StructType *st,
                                          const StructType *krefType) {
  for (unsigned i = 0; i < st->getNumElements(); i++) {
    Type *elementType = st->getElementType(i);
    if (equivTypes(elementType, krefType)) {
      return {i};
    }
    if (StructType *fieldType = dyn_cast<StructType>(elementType)) {
      SmallVector<size_t> indices = krefRevIndices(fieldType, krefType);
      if (!indices.empty()) {
        indices.push_back(i);
        return indices;
      }
    }
  }
  return {};
}

static SmallVector<size_t> krefIndices(StructType *st,
                                       const StructType *krefType) {
  SmallVector<size_t> indices = krefRevIndices(st, krefType);
  std::reverse(indices.begin(), indices.end());
  return indices;
}

class InitGlobalKrefs : public ModulePass {
public:
  static char ID;
  InitGlobalKrefs() : ModulePass(ID) {}

  bool runOnModule(Module &m) override {
    LLVMContext &ctx = m.getContext();
    Function *checker = m.getFunction("drvhorn.assert_kref");
    StructType *krefType = cast<StructType>(
        checker->getArg(0)->getType()->getPointerElementType());

    bool changed = false;

    Function *prelude = Function::Create(
        FunctionType::get(Type::getVoidTy(ctx), false),
        GlobalValue::LinkageTypes::PrivateLinkage, "drvhorn.prelude", m);
    BasicBlock *blk = BasicBlock::Create(ctx, "entry", prelude);
    IRBuilder<> b(blk);

    SmallVector<GlobalVariable *, 16> globals;
    for (GlobalVariable &gv : m.globals())
      globals.push_back(&gv);

    for (GlobalVariable *gv : globals) {
      Type *t = gv->getValueType();
      if (StructType *st = dyn_cast<StructType>(t)) {
        const SmallVector<size_t> &indices = krefIndices(st, krefType);
        if (!indices.empty()) {
          std::string krefName = "drvhorn.kref." + st->getName().str();
          recordKref(gv, krefIndices(st, krefType), krefName, b);
          changed = true;
        }
      } else if (ArrayType *at = dyn_cast<ArrayType>(t)) {
        // currently we only handle array of pointers to structs.
        PointerType *et = dyn_cast<PointerType>(at->getElementType());
        if (!et)
          continue;
        StructType *innerType = dyn_cast<StructType>(et->getElementType());
        if (!innerType)
          continue;
        const SmallVector<size_t> &indices = krefIndices(innerType, krefType);
        if (!indices.empty()) {
          changed |= handleGlobalArrayElems(gv, b, indices);
        }
      }
    }
    b.CreateRetVoid();

    Function *main = m.getFunction("main");
    callPreludeInMain(main, prelude);
    insertKrefAssertions(main, checker);
    return changed;
  }

  virtual StringRef getPassName() const override { return "InitGlobalKrefs"; }

private:
  SmallVector<GlobalVariable *> krefsToAssert;

  bool handleGlobalArrayElems(GlobalVariable *gv, IRBuilder<> &b,
                              ArrayRef<size_t> indices) {
    Module *m = gv->getParent();
    bool ret = false;
    for (User *user : gv->users()) {
      if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(user)) {
        if (isElementAccess(gep)) {
          // since gv is an array of a pointer to a struct, load should follow.
          const SmallVector<LoadInst *> &loads = getElementLoads(gep);
          for (LoadInst *load : loads) {
            Type *t = load->getType()->getPointerElementType();
            std::string name = "drvhorn.arrayelem." + gv->getName().str();
            GlobalVariable *elem = new GlobalVariable(
                *m, t, false, GlobalValue::LinkageTypes::PrivateLinkage,
                Constant::getNullValue(t), name);
            load->replaceAllUsesWith(elem);
            std::string krefName =
                "drvhorn.kref.arrayelem." + gv->getName().str();
            recordKref(elem, indices, krefName, b);
            ret = true;
          }
        }
      }
    }
    return ret;
  }

  bool isElementAccess(const GetElementPtrInst *gep) {
    LLVMContext &ctx = gep->getContext();
    if (gep->getNumIndices() != 2)
      return false;
    // The first index should be an i64 0.
    if (gep->getOperand(1) != ConstantInt::get(Type::getInt64Ty(ctx), 0))
      return false;
    // The second index should be an i64.
    return gep->getOperand(2)->getType()->isIntegerTy(64);
  }

  SmallVector<LoadInst *> getElementLoads(GetElementPtrInst *gep) {
    SmallVector<LoadInst *> ret;
    for (User *user : gep->users()) {
      if (LoadInst *load = dyn_cast<LoadInst>(user))
        ret.push_back(load);
    }
    return ret;
  }

  void recordKref(GlobalVariable *gv, ArrayRef<size_t> indices,
                  StringRef krefName, IRBuilder<> &b) {
    Module *m = gv->getParent();
    LLVMContext &ctx = m->getContext();
    IntegerType *i32Ty = Type::getInt32Ty(ctx);
    IntegerType *i64Ty = Type::getInt64Ty(ctx);

    Function *setupKref = m->getFunction("drvhorn.setup_kref");

    SmallVector<Value *> gepIndices(indices.size() + 1);
    gepIndices[0] = ConstantInt::get(i64Ty, 0);
    for (unsigned i = 0; i < indices.size(); i++) {
      gepIndices[i + 1] = ConstantInt::get(i32Ty, indices[i]);
    }
    GlobalVariable *krefGlobal = m->getGlobalVariable(krefName, true);
    if (!krefGlobal) {
      PointerType *setupKrefParam =
          cast<PointerType>(setupKref->getFunctionType()->getParamType(1));
      PointerType *krefPtrType =
          cast<PointerType>(setupKrefParam->getElementType());
      krefGlobal = new GlobalVariable(
          *m, krefPtrType, false, GlobalValue::LinkageTypes::PrivateLinkage,
          ConstantPointerNull::get(krefPtrType), krefName);
      krefsToAssert.push_back(krefGlobal);
    }

    Value *kref =
        b.CreateGEP(gv->getType()->getPointerElementType(), gv, gepIndices);
    b.CreateCall(setupKref, {kref, krefGlobal});
  }

  void callPreludeInMain(Function *main, Function *prelude) {
    BasicBlock &entry = main->getEntryBlock();
    IRBuilder<> b(&*entry.begin());
    b.CreateCall(prelude);
  }

  void insertKrefAssertions(Function *main, Function *checker) {
    auto failBlock = main->end();
    failBlock--;
    failBlock--;
    Instruction *ip = failBlock->getTerminator();
    IRBuilder<> b(ip);
    for (GlobalVariable *kref : krefsToAssert) {
      Value *krefVal = b.CreateLoad(kref->getValueType(), kref);
      if (krefVal->getType() != checker->getFunctionType()->getParamType(0))
        krefVal = b.CreateBitCast(krefVal,
                                  checker->getFunctionType()->getParamType(0));
      b.CreateCall(checker, krefVal);
    }
  }
};

char InitGlobalKrefs::ID = 0;

Pass *createInitGlobalKrefsPass() { return new InitGlobalKrefs(); };
}; // namespace seahorn
