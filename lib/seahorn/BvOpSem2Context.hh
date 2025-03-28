#pragma once

#include "seahorn/BvOpSem2.hh"
#include "seahorn/Expr/Smt/Z3.hh"
#include "seahorn/Support/SeaDebug.h"
#include "seahorn/Support/SeaLog.hh"

#include "seahorn/Expr/ExprLlvm.hh"
#include "seahorn/Expr/Smt/EZ3.hh"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-value"
#include <boost/hana.hpp>
#pragma clang diagnostic pop

#include <type_traits>
#include <unordered_set>

namespace seahorn {
namespace details {

// This enumerates the different kinds of metadata memory used in Tracking
// memory.
enum class MetadataKind {
  READ = 0,
  WRITE = 1,
  ALLOC = 2,
  CUSTOM0 = 3,
};

namespace MemoryFeatures {
auto tracking_tag_of =
    [](auto t) -> hana::type<typename decltype(t)::type::TrackingTag> {
  return {};
};

auto fatmem_tag_of =
    [](auto t) -> hana::type<typename decltype(t)::type::FatMemTag> {
  return {};
};

auto widemem_tag_of =
    [](auto t) -> hana::type<typename decltype(t)::type::WideMemTag> {
  return {};
};

// This empty class is used as a 'tag' to mark containing classes as enabling
// features
// feature: tracking.
struct Tracking_tag {};
// feature: Fat Memory.
struct FatMem_tag {};
// feature: Wide Memory.
struct WideMem_tag {};

auto has_tracking = [](auto t) {
  return hana::sfinae(tracking_tag_of)(t) ==
         hana::just(hana::type<Tracking_tag>{});
};

auto has_fatmem = [](auto t) {
  return hana::sfinae(fatmem_tag_of)(t) == hana::just(hana::type<FatMem_tag>{});
};

auto has_widemem = [](auto t) {
  return hana::sfinae(widemem_tag_of)(t) ==
         hana::just(hana::type<WideMem_tag>{});
};

} // namespace MemoryFeatures

class OpSemAlu;
class OpSemMemManagerBase;
class OpSemMemManager;
struct OpSemVisitorBase;

/// \brief Operational Semantics Context, a.k.a. Semantic Machine
/// Keeps track of the state of the current semantic machine and provides
/// API to manipulate the machine.
class Bv2OpSemContext : public OpSemContext {
  friend struct OpSemVisitorBase;

private:
  /// \brief Set memory manager to be used by the machine
  void setMemManager(OpSemMemManager *man);

  /// \brief Reference to parent operational semantics
  Bv2OpSem &m_sem;

  /// \brief currently executing function
  const Function *m_func;

  /// \brief Currently executing basic block
  const BasicBlock *m_bb;

  /// \brief Current instruction to be executed
  BasicBlock::const_iterator m_inst;

  /// \brief True if the current instructions has to be repeated
  bool m_repeat{false};

  /// \brief Previous basic block (or null if not known)
  const BasicBlock *m_prev;

  /// \brief Meta register that contains the name of the register to be
  /// used in next memory load
  Expr m_readRegister;

  /// \brief Meta register that contains the name of the register to be
  /// used in next memory store
  Expr m_writeRegister;

  /// \brief Indicates whether the current in/out memory is a unique scalar
  /// memory cell. A unique scalar memory cell is a memory cell that contains a
  /// scalar and is never aliased.
  bool m_scalar;

  /// \brief An additional memory read register that is used in memory transfer
  /// instructions that read/write from multiple memory regions
  Expr m_trfrReadReg;

  /// \brief Argument stack for the current function call
  ExprVector m_fparams;

  /// \brief Instructions that were treated as a noop by the machine
  DenseSet<const Instruction *> m_ignored;

  using FlatExprSet = boost::container::flat_set<Expr>;

  /// \brief Declared symbolic registers
  FlatExprSet m_registers;

  using ValueExprMap = DenseMap<const llvm::Value *, Expr>;

  // \brief Map from \c llvm::Value to a registers
  ValueExprMap m_valueToRegister;

  using OpSemMemManagerPtr = std::unique_ptr<OpSemMemManager>;

  /// \brief Memory manager for the machine
  OpSemMemManagerPtr m_memManager;

  using OpSemAluPtr = std::unique_ptr<OpSemAlu>;

  /// \brief ALU for basic instructions
  OpSemAluPtr m_alu;
  /// \brief Pointer to the parent a parent context
  ///
  /// If not null, then the current context is a fork of the parent context
  /// Otherwise, the current context is the main context
  const Bv2OpSemContext *m_parent = nullptr;

  /// Cache for helper expressions. Avoids creating them on the fly.

  /// \brief Numeric zero
  Expr zeroE;
  /// \brief Numeric one
  Expr oneE;

  /// \brief local z3 objects
  std::shared_ptr<EZ3> m_z3;
  std::shared_ptr<ZSimplifier<EZ3>> m_z3_simplifier;
  std::shared_ptr<ZSolver<EZ3>> m_z3_solver;

  bool m_shouldSimplify = false;       // simplify memory exprs
  bool m_shouldSimplifyNonMem = false; // simplify non-mem exprs
  std::unordered_set<Expr> m_addedToSolver;

  bool m_trackingOn = false;

public:
  /// \brief Create a new context with given semantics, values, and side
  Bv2OpSemContext(Bv2OpSem &sem, SymStore &values, ExprVector &side);
  /// \brief Clone a context with possibly new values and side condition
  /// \sa Bv2OpSem::fork
  Bv2OpSemContext(SymStore &values, ExprVector &side,
                  const Bv2OpSemContext &other);
  Bv2OpSemContext(const Bv2OpSemContext &) = delete;
  ~Bv2OpSemContext() override = default;

  EZ3 *getZ3() const { return m_z3.get(); }
  Expr simplify(Expr u);

  bool shouldSimplify() { return m_shouldSimplify; }

  bool shouldSimplifyNonMem() { return m_shouldSimplifyNonMem; }

  bool isTrackingOn() { return m_trackingOn; }

  void setTracking(bool shouldTrack) { m_trackingOn = shouldTrack; }

  /// \brief Writes value \p u into symbolic register \p v
  void write(Expr v, Expr u);

  /// \brief Returns size of a pointer in bits
  unsigned ptrSzInBits() const;

  /// \brief Returns the memory manager
  OpSemMemManager &mem() const {
    // exactly one of m_memManager or m_parent are set
    assert(m_memManager || m_parent);
    assert(!m_parent || !m_memManager);
    if (m_memManager)
      return *m_memManager;
    if (m_parent)
      return m_parent->mem();
    llvm_unreachable("must have a memory manager");
  }

  OpSemAlu &alu() const {
    if (m_alu)
      return *m_alu;
    if (m_parent)
      return m_parent->alu();
    llvm_unreachable(nullptr);
  }

  /// \brief Push parameter on a stack for a function call
  void pushParameter(Expr v) { m_fparams.push_back(v); }
  /// \brief Update the value of \p idx parameter on the stack
  void setParameter(unsigned idx, Expr v) { m_fparams[idx] = v; }
  /// \brief Reset all parameters
  void resetParameters() { m_fparams.clear(); }
  /// \brief Return the current parameter stack as a vector
  const ExprVector &getParameters() const { return m_fparams; }

  /// \brief Return the currently executing basic block
  const BasicBlock *getCurrBb() const { return m_bb; }
  /// \brief Set the previously executed basic block
  void setPrevBb(const BasicBlock &prev) { m_prev = &prev; }

  /// \brief Return basic block executed prior to the current one (used to
  /// resolve PHI instructions)
  const BasicBlock *getPrevBb() const { return m_prev; }
  /// \brief Currently executed instruction
  const Instruction &getCurrentInst() const { return *m_inst; }
  /// \brief Set instruction to be executed next
  void setInstruction(const Instruction &inst, bool repeat = false) {
    m_inst = BasicBlock::const_iterator(&inst);
    m_repeat = repeat;
  }

  /// \brief True if the current instruction has to be executed again
  bool isRepeatInstruction() const { return m_repeat; }

  /// \brief Reset repeat instruction flag
  void resetRepeatInstruction() { m_repeat = false; }

  /// \brief True if executing the last instruction in the current basic block
  bool isAtBbEnd() const { return m_inst == m_bb->end(); }
  /// \brief Move to next instructions in the basic block to execute
  Bv2OpSemContext &operator++() {
    ++m_inst;
    return *this;
  }

  void setMemReadRegister(Expr r) { m_readRegister = r; }
  Expr getMemReadRegister() { return m_readRegister; }
  void setMemWriteRegister(Expr r) { m_writeRegister = r; }
  Expr getMemWriteRegister() { return m_writeRegister; }
  bool isMemScalar() { return m_scalar; }
  void setMemScalar(bool v) { m_scalar = v; }

  void setMemTrsfrReadReg(Expr r) { m_trfrReadReg = r; }
  Expr getMemTrsfrReadReg() { return m_trfrReadReg; }

  /// \brief Load value of type \p ty with alignment \align pointed by the
  /// symbolic pointer \ptr. Memory register being read from must be set via
  /// \f setMemReadRegister
  Expr loadValueFromMem(Expr ptr, const llvm::Type &ty, uint32_t align);

  /// \brief Store a value \val to symbolic memory at address \p ptr
  ///
  /// Read and write memory registers must be set with setMemReadRegister and
  /// setMemWriteRegister prior to this operation.
  Expr storeValueToMem(Expr val, Expr ptr, const llvm::Type &ty,
                       uint32_t align);

  /// \brief Symbolic memset with concrete length
  Expr MemSet(Expr ptr, Expr val, unsigned len, uint32_t align);

  /// \brief Symbolic memset with symbolic length
  Expr MemSet(Expr ptr, Expr val, Expr len, uint32_t align);

  /// \brief Perform symbolic memcpy with constant length
  Expr MemCpy(Expr dPtr, Expr sPtr, unsigned len, uint32_t align);

  /// \brief Perform symbolic memcpy with symbolic length
  Expr MemCpy(Expr dPtr, Expr sPtr, Expr len, uint32_t align);

  /// \brief Copy concrete memory into symbolic memory
  Expr MemFill(Expr dPtr, char *sPtr, unsigned len, uint32_t align = 0);

  /// \brief Execute inttoptr
  Expr inttoptr(Expr intValue, const Type &intTy, const Type &ptrTy) const;
  /// \brief Execute ptrtoint
  Expr ptrtoint(Expr ptrValue, const Type &ptrTy, const Type &intTy) const;
  /// \brief Execute gep
  Expr gep(Expr ptr, gep_type_iterator it, gep_type_iterator end) const;

  /// \brief Called when a module is entered
  void onModuleEntry(const Module &M) override;
  /// \brief Called when a function is entered
  void onFunctionEntry(const Function &fn) override;
  /// \brief Called when a function returns
  void onFunctionExit(const Function &fn) override {}

  /// \brief Call when a basic block is entered
  void onBasicBlockEntry(const BasicBlock &bb) override;

  /// \brief declare \p v as a new register for the machine
  void declareRegister(Expr v);
  /// \brief Returns true if \p is a known register
  bool isKnownRegister(Expr v);

  /// \brief Create a register of the correct sort to hold the value returned by
  /// the instruction
  Expr mkRegister(const llvm::Instruction &inst);
  /// \brief Create a register to hold control information of a basic block
  Expr mkRegister(const llvm::BasicBlock &bb);
  /// \brief Create a register to hold a pointer to a global variable
  Expr mkRegister(const llvm::GlobalVariable &gv);
  /// \brief Create a register to hold a pointer to a function
  Expr mkRegister(const llvm::Function &fn);
  /// \brief Create a register to hold a value
  Expr mkRegister(const llvm::Value &v);
  /// \brief Return a register that contains \p v, if it exists
  Expr getRegister(const llvm::Value &v) const {
    Expr res = m_valueToRegister.lookup(&v);
    if (!res && m_parent)
      res = m_parent->getRegister(v);
    return res;
  }

  /// \brief Return sort for a function pointer
  Expr mkPtrRegisterSort(const Function &fn) const;
  /// \brief Return a sort for a pointer to global variable register
  Expr mkPtrRegisterSort(const GlobalVariable &gv) const;
  /// \brief Return a sort for a pointer
  Expr mkPtrRegisterSort(const Instruction &inst) const;
  /// \brief Return a sort for a memory register
  Expr mkMemRegisterSort(const Instruction &inst) const;

  /// \brief Returns symbolic value of a constant expression \p c
  Expr getConstantValue(const llvm::Constant &c);

  std::pair<char *, unsigned>
  getGlobalVariableInitValue(const llvm::GlobalVariable &gv);

  /// \brief Return true if \p inst is ignored by the semantics
  bool isIgnored(const Instruction &inst) const {
    return m_ignored.count(&inst);
  }

  // \brief Mark \p inst to be ignored
  void ignore(const Instruction &inst) { m_ignored.insert(&inst); }

  /// \brief Fork current context and update new copy with a given store and
  /// side condition
  OpSemContextPtr fork(SymStore &values, ExprVector &side) override {
    return OpSemContextPtr(new Bv2OpSemContext(values, side, *this));
  }

  Expr ptrToAddr(Expr p) override;

  Expr getRawMem(Expr p) override;

  void resetSolver();
  void addToSolver(const Expr e);
  // dump solver state
  void toSmtLib(llvm::raw_ostream &o);
  boost::tribool solve();

private:
  static Bv2OpSemContext &ctx(OpSemContext &ctx) {
    return static_cast<Bv2OpSemContext &>(ctx);
  }
};

/// \brief ALU for basic arithmetic and logic operations
class OpSemAlu {
protected:
  Bv2OpSemContext &m_ctx;

public:
  OpSemAlu(Bv2OpSemContext &ctx);
  virtual ~OpSemAlu() = default;

  Bv2OpSemContext &ctx() const { return m_ctx; }
  ExprFactory &efac() const { return m_ctx.efac(); }

  // coerce between bv1 and bool.
  // XXX: These should be hidden inside ALU implementation
  // XXX: Should not be exposed to clients
  virtual Expr boolToBv1(Expr e) = 0;
  virtual Expr bv1ToBool(Expr e) = 0;

  /// \brief Integer type of a given bit width on the ALU
  virtual Expr intTy(unsigned bitWidth) = 0;
  /// \brief Boolean type of the ALU
  virtual Expr boolTy() = 0;

  virtual bool isNum(Expr v) = 0;
  virtual bool isNum(Expr v, unsigned &bitWidth) = 0;
  virtual expr::mpz_class toNum(Expr v) = 0;
  virtual Expr ui(unsigned k, unsigned bitWidth) = 0;
  virtual Expr num(expr::mpz_class k, unsigned bitWidth) = 0;
  virtual Expr si(int k, unsigned bitWidth) = 0;
  virtual Expr doAdd(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doSub(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doMul(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doUDiv(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doSDiv(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doURem(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doSRem(Expr op0, Expr op1, unsigned bitWidth) = 0;

  virtual Expr doAnd(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doOr(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doXor(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doNot(Expr op0, unsigned bitWidth) = 0;

  virtual Expr doEq(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doNe(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doUlt(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doSlt(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doUgt(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doSgt(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doUle(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doSle(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doUge(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr doSge(Expr op0, Expr op1, unsigned bitWidth) = 0;

  virtual Expr doTrunc(Expr op, unsigned bitWidth) = 0;
  virtual Expr doZext(Expr op, unsigned bitWidth, unsigned opBitWidth) = 0;
  virtual Expr doSext(Expr op, unsigned bitWidth, unsigned opBitWidth) = 0;
  virtual Expr Extract(std::pair<Expr, unsigned int> op, unsigned begin,
                       unsigned end) = 0;
  virtual Expr Concat(std::pair<Expr, unsigned int> opHigh,
                      std::pair<Expr, unsigned int> opLow) = 0;

  // Arithmetic intrinsics with overflow
  virtual Expr IsSaddNoOverflow(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr IsBaddNoUnderflow(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr IsUaddNoOverflow(Expr op0, Expr op1, unsigned bitWidth) = 0;

  virtual Expr IsBsubNoOverflow(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr IsSsubNoUnderflow(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr IsUsubNoUnderflow(Expr op0, Expr op1, unsigned bitWidth) = 0;

  virtual Expr IsSmulNoOverflow(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr IsUmulNoOverflow(Expr op0, Expr op1, unsigned bitWidth) = 0;
  virtual Expr IsBmulNoUnderflow(Expr op0, Expr op1, unsigned bitWidth) = 0;

  // get true and false expressions
  virtual Expr getFalse() = 0;
  virtual Expr getTrue() = 0;
};

std::unique_ptr<OpSemAlu> mkBvOpSemAlu(Bv2OpSemContext &ctx);

// TODO: merge this class with OpSemMemManager
class OpSemMemManagerBase {
protected:
  /// \brief Parent Operational Semantics
  Bv2OpSem &m_sem;
  /// \brief Parent Semantics Context
  Bv2OpSemContext &m_ctx;
  /// \brief Parent expression factory
  ExprFactory &m_efac;

  /// \brief Ptr size in bytes
  uint32_t m_ptrSz;
  /// \brief Word size in bytes
  uint32_t m_wordSz;
  /// \brief Preferred alignment in bytes
  ///
  /// Must be divisible by \t m_wordSz
  uint32_t m_alignment;

  /// \brief ignore alignment for memory accesses
  const bool m_ignoreAlignment;

  OpSemMemManagerBase(Bv2OpSem &sem, Bv2OpSemContext &ctx, unsigned int ptrSz,
                      unsigned int wordSz, bool ignoreAlignment);

  virtual ~OpSemMemManagerBase() = default;

public:
  Bv2OpSem &sem() const { return m_sem; }
  Bv2OpSemContext &ctx() const { return m_ctx; }

  unsigned ptrSzInBits() const { return m_ptrSz * 8; }
  unsigned ptrSzInBytes() const { return m_ptrSz; }
  unsigned wordSzInBytes() const { return m_wordSz; }
  unsigned wordSzInBits() const { return m_wordSz * 8; }
  uint32_t getAlignment(const llvm::Value &v) const { return m_alignment; }
  bool isIgnoreAlignment() const { return m_ignoreAlignment; }
};

class MemManagerCore {
protected:
  /// \brief Parent Operational Semantics
  Bv2OpSem &m_sem;
  /// \brief Parent Semantics Context
  Bv2OpSemContext &m_ctx;
  /// \brief Parent expression factory
  ExprFactory &m_efac;

  /// \brief Ptr size in bytes
  uint32_t m_ptrSz;
  /// \brief Word size in bytes
  uint32_t m_wordSz;
  /// \brief Preferred alignment in bytes
  ///
  /// Must be divisible by \t m_wordSz
  uint32_t m_alignment;

  /// \brief ignore alignment for memory accesses
  const bool m_ignoreAlignment;

  MemManagerCore(Bv2OpSem &sem, Bv2OpSemContext &ctx, unsigned int ptrSz,
                 unsigned int wordSz, bool ignoreAlignment);

  virtual ~MemManagerCore() = default;

public:
  Bv2OpSem &sem() const { return m_sem; }
  Bv2OpSemContext &ctx() const { return m_ctx; }

  unsigned ptrSizeInBits() const { return m_ptrSz * 8; }
  unsigned ptrSizeInBytes() const { return m_ptrSz; }
  unsigned wordSizeInBytes() const { return m_wordSz; }
  unsigned wordSizeInBits() const { return m_wordSz * 8; }
  uint32_t getAlignment(const llvm::Value &v) const { return m_alignment; }
  bool isIgnoreAlignment() const { return m_ignoreAlignment; }
};

/// \brief Memory manager for OpSem machine
class OpSemMemManager : public OpSemMemManagerBase {
public:
  /// \brief type for pointers
  /// Currently all expressions are of opaque type Expr. The extra type
  /// annotations are to communicate intent only.
  using PtrTy = Expr;
  using MemRegTy = Expr;
  using MemValTy = Expr;

  using PtrSortTy = Expr;
  using MemSortTy = Expr;

public:
  OpSemMemManager(Bv2OpSem &sem, Bv2OpSemContext &ctx, unsigned ptrSz,
                  unsigned wordSz, bool ignoreAlignment);

  virtual ~OpSemMemManager() = default;

  virtual PtrSortTy ptrSort() const = 0;

  /// \brief Allocates memory on the stack and returns a pointer to it
  /// \param align is requested alignment. If 0, default alignment is used
  virtual PtrTy salloc(unsigned bytes, uint32_t align = 0) = 0;

  /// \brief Allocates memory on the stack and returns a pointer to it
  virtual PtrTy salloc(Expr elmts, unsigned typeSz, uint32_t align = 0) = 0;

  /// \brief Returns a pointer value for a given stack allocation
  virtual PtrTy mkStackPtr(unsigned offset) = 0;

  /// \brief Pointer to start of the heap
  virtual PtrTy brk0Ptr() = 0;

  /// \brief Allocates memory on the heap and returns a pointer to it
  virtual PtrTy halloc(unsigned _bytes, uint32_t align = 0) = 0;

  /// \brief Allocates memory on the heap and returns pointer to it
  virtual PtrTy halloc(Expr bytes, uint32_t align = 0) = 0;

  /// \brief Allocates memory in global (data/bss) segment for given global
  virtual PtrTy galloc(const GlobalVariable &gv, uint32_t align = 0) = 0;

  /// \brief Allocates memory in code segment for the code of a given function
  virtual PtrTy falloc(const Function &fn) = 0;

  /// \brief Returns a function pointer value for a given function
  virtual PtrTy getPtrToFunction(const Function &F) = 0;

  /// \brief Returns a pointer to a global variable
  virtual PtrTy getPtrToGlobalVariable(const GlobalVariable &gv) = 0;

  /// \brief Initialize memory used by the global variable
  virtual void initGlobalVariable(const GlobalVariable &gv) const = 0;

  /// \brief Creates a non-deterministic pointer that is aligned
  ///
  /// Top bits of the pointer are named by \p name and last \c log2(align) bits
  /// are set to zero
  virtual PtrTy mkAlignedPtr(Expr name, uint32_t align) const = 0;

  /// \brief Returns sort of a pointer register for an instruction
  virtual PtrSortTy mkPtrRegisterSort(const Instruction &inst) const = 0;

  /// \brief Returns sort of a pointer register for a function pointer
  virtual PtrSortTy mkPtrRegisterSort(const Function &fn) const = 0;

  /// \brief Returns sort of a pointer register for a global pointer
  virtual PtrSortTy mkPtrRegisterSort(const GlobalVariable &gv) const = 0;

  /// \brief Returns sort of memory-holding register for an instruction
  virtual MemSortTy mkMemRegisterSort(const Instruction &inst) const = 0;

  /// \brief Returns a fresh aligned pointer value
  virtual PtrTy freshPtr() = 0;

  /// \brief Returns a null ptr
  virtual PtrTy nullPtr() const = 0;

  /// \brief Fixes the type of a havoced value to mach the representation used
  /// by mem repr.
  ///
  /// \param sort
  /// \param val
  /// \return the coerced value.
  virtual Expr coerce(Expr sort, Expr val) = 0;

  /// \brief Pointer addition with numeric offset
  virtual PtrTy ptrAdd(PtrTy ptr, int32_t _offset) const = 0;

  /// \brief Pointer addition with symbolic offset
  virtual PtrTy ptrAdd(PtrTy ptr, Expr offset) const = 0;

  /// \brief Loads an integer of a given size from memory register
  ///
  /// \param[in] ptr pointer being accessed
  /// \param[in] memReg memory register into which \p ptr points
  /// \param[in] byteSz size of the integer in bytes
  /// \param[in] align known alignment of \p ptr
  /// \return symbolic value of the read integer
  virtual Expr loadIntFromMem(PtrTy ptr, MemValTy mem, unsigned byteSz,
                              uint64_t align) = 0;

  /// \brief Loads a pointer stored in memory
  /// \sa loadIntFromMem
  virtual PtrTy loadPtrFromMem(PtrTy ptr, MemValTy mem, unsigned byteSz,
                               uint64_t align) = 0;

  /// \brief Stores an integer into memory
  ///
  /// Returns an expression describing the state of memory in \c memReadReg
  /// after the store
  /// \sa loadIntFromMem
  virtual MemValTy storeIntToMem(Expr _val, PtrTy ptr, MemValTy mem,
                                 unsigned byteSz, uint64_t align) = 0;

  /// \brief Stores a pointer into memory
  /// \sa storeIntToMem
  virtual MemValTy storePtrToMem(PtrTy val, PtrTy ptr, MemValTy mem,
                                 unsigned byteSz, uint64_t align) = 0;

  /// \brief Returns an expression corresponding to a load from memory
  ///
  /// \param[in] ptr is the pointer being dereferenced
  /// \param[in] mem is the memory value being read from
  /// \param[in] ty is the type of value being loaded
  /// \param[in] align is the known alignment of the load
  virtual Expr loadValueFromMem(PtrTy ptr, MemValTy mem, const llvm::Type &ty,
                                uint64_t align) = 0;

  virtual MemValTy storeValueToMem(Expr _val, PtrTy ptr, MemValTy memIn,
                                   const llvm::Type &ty, uint32_t align) = 0;

  /// \brief Executes symbolic memset with a concrete length
  virtual MemValTy MemSet(PtrTy ptr, Expr _val, unsigned len, MemValTy mem,
                          uint32_t align) = 0;

  /// \brief Executes symbolic memset with symbolic length
  virtual MemValTy MemSet(PtrTy ptr, Expr _val, Expr len, MemValTy mem,
                          uint32_t align) = 0;

  /// \brief Executes symbolic memcpy with concrete length
  virtual MemValTy MemCpy(PtrTy dPtr, PtrTy sPtr, unsigned len,
                          MemValTy memTrsfrRead, MemValTy memRead,
                          uint32_t align) = 0;

  /// \brief Executes symbolic memcpy with symbolic length
  virtual MemValTy MemCpy(PtrTy dPtr, PtrTy sPtr, Expr len,
                          MemValTy memTrsfrRead, MemValTy memRead,
                          uint32_t align) = 0;

  /// \brief Executes symbolic memcpy from physical memory with concrete length
  virtual MemValTy MemFill(PtrTy dPtr, char *sPtr, unsigned len, MemValTy mem,
                           uint32_t align = 0) = 0;

  /// \brief Executes inttoptr conversion
  virtual PtrTy inttoptr(Expr intVal, const Type &intTy,
                         const Type &ptrTy) const = 0;

  /// \brief Executes ptrtoint conversion
  virtual Expr ptrtoint(PtrTy ptr, const Type &ptrTy,
                        const Type &intTy) const = 0;

  virtual Expr ptrUlt(PtrTy p1, PtrTy p2) const = 0;
  virtual Expr ptrSlt(PtrTy p1, PtrTy p2) const = 0;
  virtual Expr ptrUle(PtrTy p1, PtrTy p2) const = 0;
  virtual Expr ptrSle(PtrTy p1, PtrTy p2) const = 0;
  virtual Expr ptrUgt(PtrTy p1, PtrTy p2) const = 0;
  virtual Expr ptrSgt(PtrTy p1, PtrTy p2) const = 0;
  virtual Expr ptrUge(PtrTy p1, PtrTy p2) const = 0;
  virtual Expr ptrSge(PtrTy p1, PtrTy p2) const = 0;

  /// \brief Checks if two pointers are equal.
  virtual Expr ptrEq(PtrTy p1, PtrTy p2) const = 0;
  virtual Expr ptrNe(PtrTy p1, PtrTy p2) const = 0;

  virtual Expr ptrSub(PtrTy p1, PtrTy p2) const = 0;

  /// \brief Computes a pointer corresponding to the gep instruction
  virtual PtrTy gep(PtrTy ptr, gep_type_iterator it,
                    gep_type_iterator end) const = 0;

  /// \brief Called when a function is entered for the first time
  virtual void onFunctionEntry(const Function &fn) = 0;

  /// \brief Called when a module entered for the first time
  virtual void onModuleEntry(const Module &M) = 0;

  /// \brief Debug helper
  virtual void dumpGlobalsMap() = 0;

  virtual std::pair<char *, unsigned>
  getGlobalVariableInitValue(const llvm::GlobalVariable &gv) = 0;

  /// \brief returns a constant that represents zero-initialized memory region
  virtual MemValTy zeroedMemory() const = 0;

  /// \brief Checks if \p a <= b <= c.
  Expr ptrInRangeCheck(PtrTy a, PtrTy b, PtrTy c) {
    return mk<AND>(ptrUle(a, b), ptrUle(b, c));
  }
  /// \brief Calculates an offset of a pointer from its base.
  Expr ptrOffsetFromBase(PtrTy base, PtrTy ptr) { return ptrSub(ptr, base); }

  /// \brief returns Expr after getting data.
  virtual Expr getFatData(PtrTy p, unsigned SlotIdx) = 0;

  /// \brief returns Expr after setting data.
  virtual PtrTy setFatData(PtrTy p, unsigned SlotIdx, Expr data) = 0;

  /// \brief return True expr if number of bytes(byteSz) is within allocated
  /// bounds, False expr otherwise.
  virtual Expr isDereferenceable(PtrTy p, Expr byteSz) = 0;

  /// \brief return True expr if memory has been modified since setMetadata
  // or allocation, whichever is later.
  virtual Expr isMetadataSet(MetadataKind kind, PtrTy p, MemValTy mem) = 0;

  /// \brief reset memory modified state; used in conjuction with isMetadataSet
  virtual MemValTy setMetadata(MetadataKind kind, PtrTy p, MemValTy mem,
                               Expr val) = 0;
  virtual Expr getMetadata(MetadataKind kind, PtrTy p, MemValTy memIn,
                           unsigned int byteSz) = 0;
  virtual unsigned int getMetadataMemWordSzInBits() = 0;
  /// \brief given a properly encoded pointer Expr \p p , return the raw
  /// expression representing memory address only
  virtual Expr ptrToAddr(Expr p) = 0;

  /// \brief given a properly encoded memory map Expr \p p , return the base
  /// expression representing raw memory only
  virtual Expr getRawMem(Expr p) = 0;

  virtual size_t getNumOfMetadataSlots() = 0;
};

OpSemMemManager *mkRawMemManager(Bv2OpSem &sem, Bv2OpSemContext &ctx,
                                 unsigned ptrSz, unsigned wordSz,
                                 bool useLambdas = false);

OpSemMemManager *mkFatMemManager(Bv2OpSem &sem, Bv2OpSemContext &ctx,
                                 unsigned ptrSz, unsigned wordSz,
                                 bool useLambdas = false);

OpSemMemManager *mkWideMemManager(Bv2OpSem &sem, Bv2OpSemContext &ctx,
                                  unsigned ptrSz, unsigned wordSz,
                                  bool useLambdas = false);

OpSemMemManager *mkExtraWideMemManager(Bv2OpSem &sem, Bv2OpSemContext &ctx,
                                       unsigned ptrSz, unsigned wordSz,
                                       bool useLambdas = false);

/// Evaluates constant expressions
class ConstantExprEvaluator {
  const DataLayout &m_td;
  Bv2OpSemContext *m_ctx;

  const DataLayout &getDataLayout() const { return m_td; }

  bool hasContext() const { return m_ctx; }
  Bv2OpSemContext &getContext() {
    assert(m_ctx);
    return *m_ctx;
  }
  /// \brief Stores a value in \p Val to memory pointed by \p Ptr. The store
  /// is of type \p Ty
  void storeValueToMemory(const GenericValue &Val, GenericValue *Ptr, Type *Ty);

public:
  ConstantExprEvaluator(const DataLayout &td) : m_td(td), m_ctx(nullptr) {}
  void setContext(Bv2OpSemContext &ctx) { m_ctx = &ctx; }

  /// \brief Evaluate a constant expression
  Optional<GenericValue> evaluate(const Constant *C);
  Optional<GenericValue> operator()(const Constant *c) { return evaluate(c); }

  /// \brief Initialize given memory with the value of a constant expression
  /// from: llvm/lib/ExecutionEngine/ExecutionEngine.cpp
  void initMemory(const Constant *Init, void *Addr);
};

} // namespace details
} // namespace seahorn
