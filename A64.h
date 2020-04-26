#pragma once

#include <binaryninjaapi.h>
#include <capstone/capstone.h>

using namespace BinaryNinja;

// #define CAPSTONE_NEXT

#define A64_INSTR_SIZE (4)

/*
 * Disassembler _must_ be thread_local because on multi-threaded analysis
 * GetInstructionLowLevelIL may be called from multiple threads, thus causing
 * Capstone to malfunction. Note that on thread exit the destructor will be
 * called and the associated Capstone resources will be released.
 */
static thread_local class Disassembler {
private:
  csh mCapstone{};
  bool mIsOK = true;

public:
  Disassembler() noexcept {
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &mCapstone) != CS_ERR_OK) {
      mIsOK = false;
      return;
    }

    cs_option(mCapstone, CS_OPT_DETAIL, CS_OPT_ON);
  }

  ~Disassembler() { cs_close(&mCapstone); }

  bool IsOK() const { return mIsOK; }

  csh Get() const { return mCapstone; }
} disassembler;

/**
 * Convert a Capstone condition code to BNIL condition code.
 *
 * @param condition AArch64 condition code
 * @return BNIL condition, or -1
 */
static BNLowLevelILFlagCondition LiftCondition(arm64_cc condition) {
  switch (condition) {
  case ARM64_CC_EQ:
    return LLFC_E;
  case ARM64_CC_NE:
    return LLFC_NE;
  case ARM64_CC_HS:
    return LLFC_UGE;
  case ARM64_CC_LO:
    return LLFC_ULE;
  case ARM64_CC_MI:
    return LLFC_NEG;
  case ARM64_CC_PL:
    return LLFC_POS;
  case ARM64_CC_VS:
    return LLFC_O;
  case ARM64_CC_VC:
    return LLFC_NO;
  case ARM64_CC_HI:
    return LLFC_UGE;
  case ARM64_CC_LS:
    return LLFC_ULE;
  case ARM64_CC_GE:
    return LLFC_SGE;
  case ARM64_CC_LT:
    return LLFC_SLT;
  case ARM64_CC_GT:
    return LLFC_SGT;
  case ARM64_CC_LE:
    return LLFC_SLE;
  case ARM64_CC_INVALID:
    return (BNLowLevelILFlagCondition) ARM64_CC_INVALID;
  case ARM64_CC_AL:
    return (BNLowLevelILFlagCondition) ARM64_CC_AL;
  case ARM64_CC_NV:
    return (BNLowLevelILFlagCondition) ARM64_CC_NV;
  }

  return (BNLowLevelILFlagCondition) -1;
}

class A64 : public ArchitectureHook {
public:
  class Lifter {
  public:
    using LifterMap = std::unordered_map<enum arm64_insn,
        bool (*)(A64&, cs_insn*, LowLevelILFunction&)>;
    virtual bool Init(A64&, LifterMap&) = 0;
  };

private:
  std::map<uint32_t, NameAndType> mIntrinsics;
  std::map<const char*, uint32_t> mIntrinsicNames;

  std::map<uint32_t, std::pair<std::string, BNRegisterInfo>> mRegisters;
  std::map<std::string, uint32_t> mRegisterNames;

  Lifter::LifterMap mLifters;

  // These classes access VecSubRegister.
  friend class LiftFP;
  friend class LiftVT;

  // This class accesses LiftMemoryOperand.
  friend class LiftDT;

  /**
   * Get the vector sub-register corresponding to an element size and base
   * register.
   *
   * @param baseRegister
   * @param elemSize
   * @param index
   * @return the vector sub-register, or 0
   */
  uint32_t VecSubRegister(uint32_t baseRegister, size_t elemSize,
                          size_t index) {
    for (auto& regPair : mRegisters) {
      uint32_t id = regPair.first;
      BNRegisterInfo reg = regPair.second.second;

      if (reg.fullWidthRegister == baseRegister &&
          reg.offset == elemSize * index && reg.size == elemSize) {
        return id;
      }
    }
    return 0;
  }

  std::optional<ExprId>
  LiftMemoryOperand(uint64_t address, LowLevelILFunction& il, cs_arm64_op& op) {
    uint32_t Rn = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), op.mem.base));
    int32_t imm = op.mem.disp;

    size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;

    if (8 != Rn_size) {
      LogError("%#lx: Invalid disassembly: Rn register (memory operand base) "
               "must be 8 bytes, not %zu",
               address, Rn_size);
      return {};
    }

    if (ARM64_REG_INVALID == op.mem.index) {
      /* No index register, no shifts/extends, just an immediate offset */
      if (0 != imm) {
        return il.Add(Rn_size, il.Register(Rn_size, Rn), il.Const(4, imm));
      } else {
        return il.Register(Rn_size, Rn);
      }
    } else {
      uint32_t Rm = this->m_base->GetRegisterByName(
          cs_reg_name(disassembler.Get(), op.mem.index));
      size_t Rm_size = this->m_base->GetRegisterInfo(Rm).size;

      arm64_shifter shiftType = op.shift.type;
      unsigned int shiftAmt = op.shift.value;

      arm64_extender extend = op.ext;

      if (8 != Rm_size && 4 != Rm_size) {
        LogError("%#lx: Invalid disassembly: Rm register (memory operand "
                 "index) must be 4 or 8 bytes, not %zu",
                 address, Rm_size);
        return {};
      }

      if (0 != imm) {
        LogError("%#lx: Invalid disassembly: register and immediate offset "
                 "cannot be combined",
                 address);
        return {};
      }

      ExprId disp = il.Register(Rm_size, Rm);

      /*
       * First switch on extend in case Rm is 4 bytes and must be implicitly
       * extended to 8 before any shifting.
       * See the ExtendReg() pseudocode in the manual for this logic.
       */
      switch (extend) {
      case ARM64_EXT_UXTB:
      case ARM64_EXT_UXTH:
      case ARM64_EXT_UXTW:
      case ARM64_EXT_UXTX:
        disp = il.ZeroExtend(Rn_size, disp);
        break;
      case ARM64_EXT_SXTB:
      case ARM64_EXT_SXTH:
      case ARM64_EXT_SXTW:
      case ARM64_EXT_SXTX:
        disp = il.SignExtend(Rn_size, disp);
        break;
      case ARM64_EXT_INVALID:
        /* No extend */
        if (Rn_size != Rm_size) {
          LogError(
              "%#lx: Rn and Rm register sizes mismatched and no extend given",
              address);
          return {};
        }
        break;
      default:
        LogError("%#lx: Invalid extend type %d", address, extend);
        return {};
      }

      if (shiftAmt > 4) {
        LogError("%#lx: Invalid disassembly: shift amount must be <= 4, not %u",
                 address, shiftAmt);
        return {};
      }

      switch (shiftType) {
      case ARM64_SFT_LSL:
        disp = il.ShiftLeft(Rn_size, disp, il.Const(1, shiftAmt));
        break;
      case ARM64_SFT_INVALID:
        /* No shift */
        break;
      case ARM64_SFT_MSL:
      case ARM64_SFT_LSR:
      case ARM64_SFT_ASR:
      case ARM64_SFT_ROR:
      default:
        LogError("%#lx: Invalid shift type %d", address, shiftType);
        return {};
      }

      /* Switch on extend again to do the outer extend */
      switch (extend) {
      case ARM64_EXT_UXTB:
      case ARM64_EXT_UXTH:
      case ARM64_EXT_UXTW:
      case ARM64_EXT_UXTX:
        disp = il.ZeroExtend(Rn_size, disp);
        break;
      case ARM64_EXT_SXTB:
      case ARM64_EXT_SXTH:
      case ARM64_EXT_SXTW:
      case ARM64_EXT_SXTX:
        disp = il.SignExtend(Rn_size, disp);
        break;
      case ARM64_EXT_INVALID:
      default:
        /* Should be caught above first */
        __builtin_unreachable();
      }

      return il.Add(Rn_size, il.Register(Rn_size, Rn), disp);
    }
  }

public:
  explicit A64(Architecture* a64) : ArchitectureHook(a64) {}

  bool Init();

  bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len,
                                LowLevelILFunction& il) override;

  uint32_t GetIntrinsicByName(const char* name) {
    return mIntrinsicNames[name];
  }

  std::string GetIntrinsicName(uint32_t intrinsic) override;
  std::vector<uint32_t> GetAllIntrinsics() override;
  std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
  std::vector<Confidence<Ref<Type>>>
  GetIntrinsicOutputs(uint32_t intrinsic) override;
  BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
  std::string GetRegisterName(uint32_t reg) override;
  std::vector<uint32_t> GetAllRegisters() override;
};