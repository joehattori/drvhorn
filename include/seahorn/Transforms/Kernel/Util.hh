#pragma once

#include "llvm/IR/Instructions.h"

namespace seahorn {
llvm::StringRef getStructName(llvm::StringRef name);
bool equivTypes(const llvm::Type *t1, const llvm::Type *t2);
const llvm::Function *extractCalledFunction(const llvm::CallInst *call);
llvm::Function *extractCalledFunction(llvm::CallInst *call);
const llvm::Function *extractCalledFunction(const llvm::CallInst &call);
llvm::Function *extractCalledFunction(llvm::CallInst &call);
llvm::SmallVector<llvm::CallInst *, 16> getCalls(llvm::Function *fn);
llvm::SmallVector<const llvm::CallInst *, 16>
getCalls(const llvm::Function *fn);
llvm::Optional<size_t> getEmbeddedDeviceIndex(const llvm::StructType *s);
llvm::SmallVector<llvm::GlobalVariable *> getKobjects(llvm::Module &m);
} // namespace seahorn
