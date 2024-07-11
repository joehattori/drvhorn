#pragma once

#include "llvm/IR/Instructions.h"

namespace seahorn {
llvm::StringRef getStructName(llvm::StringRef name);
bool equivTypes(const llvm::Type *t1, const llvm::Type *t2);
const llvm::Function *extractCalledFunction(const llvm::CallInst *call);
llvm::Function *extractCalledFunction(llvm::CallInst *call);
static void collectCallUser(llvm::User *user,
                            llvm::SmallVector<llvm::CallInst *, 16> &res,
                            llvm::DenseSet<llvm::User *> &visited);
static void collectCallUser(const llvm::User *user,
                            llvm::SmallVector<const llvm::CallInst *, 16> &res,
                            llvm::DenseSet<const llvm::User *> &visited);
llvm::SmallVector<llvm::CallInst *, 16> getCalls(llvm::Function *fn);
llvm::SmallVector<const llvm::CallInst *, 16>
getCalls(const llvm::Function *fn);
} // namespace seahorn
