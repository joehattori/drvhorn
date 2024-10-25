#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include "seahorn/Transforms/Kernel/Util.hh"

namespace seahorn {
llvm::StringRef getStructName(llvm::StringRef name) {
  size_t p = name.find('.');
  if (p == llvm::StringRef::npos)
    return name;
  size_t q = name.find('.', p + 1);
  if (q == llvm::StringRef::npos)
    return name;
  return name.substr(0, q);
}

static bool equivTypes(const llvm::Type *t1, const llvm::Type *t2,
                       llvm::DenseSet<const llvm::Type *> &visited);

static bool equivTypes(const llvm::ArrayType *at1, const llvm::ArrayType *at2,
                       llvm::DenseSet<const llvm::Type *> &visited) {
  return at1->getNumElements() == at2->getNumElements() &&
         equivTypes(at1->getElementType(), at2->getElementType(), visited);
}

static bool equivTypes(const llvm::FunctionType *ft1,
                       const llvm::FunctionType *ft2,
                       llvm::DenseSet<const llvm::Type *> &visited) {
  if (ft1->getNumParams() != ft2->getNumParams())
    return false;
  if (!equivTypes(ft1->getReturnType(), ft2->getReturnType(), visited))
    return false;
  for (unsigned i = 0; i < ft1->getNumParams(); i++) {
    if (!equivTypes(ft1->getParamType(i), ft2->getParamType(i), visited))
      return false;
  }
  return true;
}

static bool equivTypes(const llvm::IntegerType *it1,
                       const llvm::IntegerType *it2) {
  return it1->getBitWidth() == it2->getBitWidth();
}

static bool equivTypes(const llvm::PointerType *pt1,
                       const llvm::PointerType *pt2,
                       llvm::DenseSet<const llvm::Type *> &visited) {
  return equivTypes(pt1->getElementType(), pt2->getElementType(), visited);
}

static bool equivTypes(const llvm::StructType *st1, const llvm::StructType *st2,
                       llvm::DenseSet<const llvm::Type *> &visited) {
  if (!st1->hasName() || !st2->hasName()) {
    if (st1->getNumElements() != st2->getNumElements())
      return false;
    for (unsigned i = 0; i < st1->getNumElements(); i++) {
      if (!equivTypes(st1->getElementType(i), st2->getElementType(i), visited))
        return false;
    }
    return true;
  }
  llvm::StringRef p1 = getStructName(st1->getName());
  llvm::StringRef p2 = getStructName(st2->getName());
  return p1 == p2;
}

static bool equivTypes(const llvm::VectorType *vt1, const llvm::VectorType *vt2,
                       llvm::DenseSet<const llvm::Type *> &visited) {
  return vt1->getElementCount() == vt2->getElementCount() &&
         equivTypes(vt1->getElementType(), vt2->getElementType(), visited);
}

static bool equivTypes(const llvm::Type *t1, const llvm::Type *t2,
                       llvm::DenseSet<const llvm::Type *> &visited) {
  if (!visited.insert(t1).second)
    return true;
  if (llvm::isa<llvm::ArrayType>(t1) && llvm::isa<llvm::ArrayType>(t2)) {
    return equivTypes(llvm::cast<llvm::ArrayType>(t1),
                      llvm::cast<llvm::ArrayType>(t2), visited);
  }
  if (llvm::isa<llvm::FunctionType>(t1) && llvm::isa<llvm::FunctionType>(t2)) {
    return equivTypes(llvm::cast<llvm::FunctionType>(t1),
                      llvm::cast<llvm::FunctionType>(t2), visited);
  }
  if (llvm::isa<llvm::IntegerType>(t1) && llvm::isa<llvm::IntegerType>(t2)) {
    return equivTypes(llvm::cast<llvm::IntegerType>(t1),
                      llvm::cast<llvm::IntegerType>(t2));
  }
  if (llvm::isa<llvm::PointerType>(t1) && llvm::isa<llvm::PointerType>(t2)) {
    return equivTypes(llvm::cast<llvm::PointerType>(t1),
                      llvm::cast<llvm::PointerType>(t2), visited);
  }
  if (llvm::isa<llvm::StructType>(t1) && llvm::isa<llvm::StructType>(t2)) {
    return equivTypes(llvm::cast<llvm::StructType>(t1),
                      llvm::cast<llvm::StructType>(t2), visited);
  }
  if (llvm::isa<llvm::VectorType>(t1) && llvm::isa<llvm::VectorType>(t2)) {
    return equivTypes(llvm::cast<llvm::VectorType>(t1),
                      llvm::cast<llvm::VectorType>(t2), visited);
  }
  return false;
}

bool equivTypes(const llvm::Type *t1, const llvm::Type *t2) {
  llvm::DenseSet<const llvm::Type *> visited;
  return equivTypes(t1, t2, visited);
}

const llvm::Function *extractCalledFunction(const llvm::CallInst *call) {
  return llvm::dyn_cast<llvm::Function>(
      call->getCalledOperand()->stripPointerCasts());
}

llvm::Function *extractCalledFunction(llvm::CallInst *call) {
  return llvm::dyn_cast<llvm::Function>(
      call->getCalledOperand()->stripPointerCasts());
}

const llvm::Function *extractCalledFunction(const llvm::CallInst &call) {
  return llvm::dyn_cast<llvm::Function>(
      call.getCalledOperand()->stripPointerCasts());
}

llvm::Function *extractCalledFunction(llvm::CallInst &call) {
  return llvm::dyn_cast<llvm::Function>(
      call.getCalledOperand()->stripPointerCasts());
}

static void collectCallUser(llvm::User *user,
                            llvm::SmallVector<llvm::CallInst *, 16> &res,
                            llvm::DenseSet<llvm::User *> &visited) {
  if (!visited.insert(user).second)
    return;
  if (llvm::isa<llvm::Instruction>(user)) {
    if (llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(user))
      res.push_back(call);
  } else {
    for (llvm::User *user : user->users()) {
      collectCallUser(user, res, visited);
    }
  }
}

static void collectCallUser(const llvm::User *user,
                            llvm::SmallVector<const llvm::CallInst *, 16> &res,
                            llvm::DenseSet<const llvm::User *> &visited) {
  if (!visited.insert(user).second)
    return;
  if (llvm::isa<llvm::Instruction>(user)) {
    if (const llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(user))
      res.push_back(call);
  } else {
    for (const llvm::User *user : user->users()) {
      collectCallUser(user, res, visited);
    }
  }
}

llvm::SmallVector<llvm::CallInst *, 16> getCalls(llvm::Function *fn) {
  llvm::SmallVector<llvm::CallInst *, 16> res;
  llvm::DenseSet<llvm::User *> visited;
  collectCallUser(fn, res, visited);
  return res;
}

llvm::SmallVector<const llvm::CallInst *, 16>
getCalls(const llvm::Function *fn) {
  llvm::SmallVector<const llvm::CallInst *, 16> res;
  llvm::DenseSet<const llvm::User *> visited;
  collectCallUser(fn, res, visited);
  return res;
}

llvm::Function *getOrCreateNdIntFn(llvm::Module &m, unsigned bitwidth) {
  std::string name = "nd.int" + std::to_string(bitwidth);
  if (llvm::Function *f = m.getFunction(name))
    return f;
  llvm::IntegerType *it = llvm::IntegerType::get(m.getContext(), bitwidth);
  llvm::FunctionType *ft = llvm::FunctionType::get(it, false);
  return llvm::Function::Create(ft, llvm::Function::ExternalLinkage, name, &m);
}

static llvm::Optional<llvm::SmallVector<unsigned>>
revIndicesToStruct(const llvm::StructType *s, const llvm::Type *target) {
  for (unsigned i = 0; i < s->getNumElements(); i++) {
    const llvm::Type *elemType = s->getElementType(i);
    if (equivTypes(elemType, target))
      return llvm::SmallVector<unsigned>{i};
    if (const llvm::StructType *sTy =
            llvm::dyn_cast<llvm::StructType>(elemType)) {
      llvm::Optional<llvm::SmallVector<unsigned>> indices =
          revIndicesToStruct(sTy, target);
      if (indices.hasValue()) {
        indices->push_back(i);
        return indices;
      }
    }
  }
  return llvm::None;
}

llvm::Optional<llvm::SmallVector<unsigned>>
indicesToStruct(const llvm::StructType *s, const llvm::Type *target) {
  if (equivTypes(s, target)) {
    return llvm::SmallVector<unsigned>{};
  }
  llvm::Optional<llvm::SmallVector<unsigned>> indices =
      revIndicesToStruct(s, target);
  if (!indices.hasValue())
    return llvm::None;
  return llvm::SmallVector<unsigned>(indices->rbegin(), indices->rend());
}

bool embedsStruct(const llvm::StructType *s, const llvm::Type *target) {
  for (unsigned i = 0; i < s->getNumElements(); i++) {
    const llvm::Type *elemType = s->getElementType(i);
    if (equivTypes(elemType, target))
      return true;
    if (const llvm::StructType *sTy =
            llvm::dyn_cast<llvm::StructType>(elemType)) {
      if (embedsStruct(sTy, target))
        return true;
    }
  }
  return false;
}
} // namespace seahorn
