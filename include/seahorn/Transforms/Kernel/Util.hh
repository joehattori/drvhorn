#pragma once

#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Casting.h"

namespace {
llvm::StringRef getStructName(llvm::StringRef name) {
  size_t p = name.find('.');
  if (p == llvm::StringRef::npos)
    return name;
  size_t q = name.find('.', p + 1);
  if (q == llvm::StringRef::npos)
    return name;
  return name.substr(0, q);
}

bool equivTypes(const llvm::Type *t1, const llvm::Type *t2) {
  if (t1 == t2)
    return true;
  const llvm::StructType *st1 = llvm::dyn_cast<llvm::StructType>(t1);
  const llvm::StructType *st2 = llvm::dyn_cast<llvm::StructType>(t2);
  if (!st1 || !st2 || !st1->hasName() || !st2->hasName())
    return false;
  llvm::StringRef p1 = getStructName(st1->getName());
  llvm::StringRef p2 = getStructName(st2->getName());
  return p1 == p2;
}

const llvm::Function *extractCalledFunction(const llvm::CallInst *call) {
  return llvm::dyn_cast<llvm::Function>(
      call->getCalledOperand()->stripPointerCasts());
}

llvm::Function *extractCalledFunction(llvm::CallInst *call) {
  return llvm::dyn_cast<llvm::Function>(
      call->getCalledOperand()->stripPointerCasts());
}
} // namespace
