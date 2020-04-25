#include <algorithm>
#include <binaryninjaapi.h>
#include <capstone/capstone.h>
#include <errno.h>
#include <lowlevelilinstruction.h>
#include <string.h>

using namespace BinaryNinja;
using string = std::string;

// #define AARCH64_TRACE_INSTR
// #define CAPSTONE_NEXT

#define AARCH64_MAX_INSTR_SIZE (4)

/**
 * Returns 1s expanded to count, e.g.: Count<uint8_t>(7) == 0b01111111
 *
 * @tparam T integral type to expand into
 * @param count expansion specifier
 * @return 1s expanded to count
 */
template <typename T> inline T Ones(size_t count) {
  if (count == sizeof(T) * 8) {
    return static_cast<T>(~static_cast<T>(0));
  } else {
    return ~(static_cast<T>(~static_cast<T>(0)) << count);
  }
}

/**
 * Given a Vector Arrangement Specifier, return the _element_ size to be
 * operated on.
 *
 * Verify that the VAS is indeed valid before calling this function.
 *
 * @param vas vector arrangement specifier
 * @return the _element_ size to be operated on
 */
static std::optional<size_t> VecElementSize(enum arm64_vas vas) {
  switch (vas) {
  case ARM64_VAS_16B:
  case ARM64_VAS_8B:
#ifdef CAPSTONE_NEXT
  case ARM64_VAS_4B:
  case ARM64_VAS_1B:
#endif /* #ifdef CAPSTONE_NEXT */
    return (1);
  case ARM64_VAS_8H:
  case ARM64_VAS_4H:
#ifdef CAPSTONE_NEXT
  case ARM64_VAS_2H:
  case ARM64_VAS_1H:
#endif /* #ifdef CAPSTONE_NEXT */
    return (2);
  case ARM64_VAS_4S:
  case ARM64_VAS_2S:
#ifdef CAPSTONE_NEXT
  case ARM64_VAS_1S:
#endif /* #ifdef CAPSTONE_NEXT */
    return (4);
  case ARM64_VAS_2D:
  case ARM64_VAS_1D:
    return (8);
  case ARM64_VAS_1Q:
    return (16);
  default:
    /*
     * If we've called this with ARM64_VAS_INVALID we're missing new enum
     * members, we need to fix the caller.
     */
    LogError("%s() called with invalid VAS %d", __FUNCTION__, vas);
    return {};
  }
}

class Disassembler {
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
};

/*
 * Disassembler _must_ be thread_local because on multi-threaded analysis
 * GetInstructionLowLevelIL may be called from multiple threads, thus causing
 * Capstone to malfunction. Note that on thread exit the destructor will be
 * called and the associated Capstone resources will be released
 */
static thread_local Disassembler disassembler;

struct VectorAccess {
  char elemType;
  size_t elemSize;
  size_t vectorIndex;
};

/*
 * Vector arrangement forms used to generate Binary Ninja sub-registers.
 */
const struct VectorAccess regForms[] = {
    {'d', 8, 0},  {'d', 8, 1},

    {'s', 4, 0},  {'s', 4, 1},  {'s', 4, 2},  {'s', 4, 3},

    {'h', 2, 0},  {'h', 2, 1},  {'h', 2, 2},  {'h', 2, 3},
    {'h', 2, 4},  {'h', 2, 5},  {'h', 2, 6},  {'h', 2, 7},

    {'b', 1, 0},  {'b', 1, 1},  {'b', 1, 2},  {'b', 1, 3},
    {'b', 1, 4},  {'b', 1, 5},  {'b', 1, 6},  {'b', 1, 7},
    {'b', 1, 8},  {'b', 1, 9},  {'b', 1, 10}, {'b', 1, 11},
    {'b', 1, 12}, {'b', 1, 13}, {'b', 1, 14}, {'b', 1, 15}};

class AArch64ArchitectureExtension : public ArchitectureHook {
private:
  std::map<uint32_t, NameAndType> mIntrinsics;
  std::map<const char*, uint32_t> mIntrinsicNames;

  std::map<uint32_t, std::pair<string, BNRegisterInfo>> mRegisters;
  std::map<string, uint32_t> mRegisterNames;

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
  explicit AArch64ArchitectureExtension(Architecture* aarch64)
      : ArchitectureHook(aarch64) {}

  /**
   * Initialize the plugin. Returns false on error.
   *
   * @return success
   */
  bool Init() {
    std::vector<uint32_t> intrinsics = this->m_base->GetAllIntrinsics();
    uint32_t intrinsic = 0;
    if (!intrinsics.empty()) {
      intrinsic = 1 + *max_element(intrinsics.begin(), intrinsics.end());
    }

    // Declare new architecture intrinsics (MRS/MSR)
    mIntrinsicNames["__builtin_mrs"] = intrinsic;
    mIntrinsics[intrinsic++] = NameAndType(
        "__builtin_mrs",
        Type::FunctionType(
            Type::IntegerType(8, true, ""),
            this->m_base->GetDefaultCallingConvention(),
            {{"reg", Type::IntegerType(8, true, ""), true, Variable()}}, false,
            0));

    mIntrinsicNames["__builtin_msr"] = intrinsic;
    mIntrinsics[intrinsic++] = NameAndType(
        "__builtin_msr",
        Type::FunctionType(
            Type::VoidType(), this->m_base->GetDefaultCallingConvention(),
            {{"reg", Type::IntegerType(8, true, ""), true, Variable()},
             {"val", Type::IntegerType(8, true, ""), true, Variable()}},
            false, 0));

    std::vector<uint32_t> registers = this->m_base->GetAllRegisters();
    uint32_t reg = 0;
    if (!registers.empty()) {
      reg = 1 + *max_element(registers.begin(), registers.end());
    }

    for (size_t Vd = 0; Vd < 32; Vd++) {
      char baseRegisterName[3];

      snprintf(baseRegisterName, sizeof(baseRegisterName), "v%zu", Vd);

      for (auto& form : regForms) {
        BNRegisterInfo regInfo{};
        char* regNameCStr = nullptr;

        if (asprintf(&regNameCStr, "v%zu%c[%zu]", Vd, form.elemType,
                     form.vectorIndex) < 0 ||
            nullptr == regNameCStr) {
          LogError("Error allocating register names: %s", strerror(errno));
          return false;
        }

        string regName = regNameCStr;
        free(regNameCStr);

        regInfo.fullWidthRegister =
            this->m_base->GetRegisterByName(baseRegisterName);
        regInfo.offset = form.elemSize * form.vectorIndex;
        regInfo.size = form.elemSize;
        regInfo.extend = NoExtend;

        mRegisterNames[regName] = reg;
        mRegisters[reg++] = std::pair<string, BNRegisterInfo>(regName, regInfo);
      }
    }

    return true;
  }

  bool LiftCSINC(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 3) {
      return false;
    }

    uint32_t Rd = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));
    uint32_t Rn = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[1].reg));
    uint32_t Rm = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[2].reg));
    size_t Rd_size = this->m_base->GetRegisterInfo(Rd).size;
    size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;
    size_t Rm_size = this->m_base->GetRegisterInfo(Rm).size;

    if (detail->cc == ARM64_CC_INVALID ||
        (Rd_size != Rn_size && Rn_size != Rm_size)) {
      return false;
    }

    // Never is actually _always_, Capstone internal
    if (detail->cc == ARM64_CC_AL || detail->cc == ARM64_CC_NV) {
      il.AddInstruction(il.SetRegister(Rd_size, il.Register(Rd_size, Rd),
                                       il.Register(Rn_size, Rn)));
      return true;
    }

    LowLevelILLabel assignmentLabel, incrementLabel, afterLabel;

    il.AddInstruction(il.If(il.FlagCondition(LiftCondition(detail->cc)),
                            assignmentLabel, incrementLabel));

    // Rd = Rn
    il.MarkLabel(assignmentLabel);
    il.AddInstruction(il.SetRegister(Rd_size, Rd, il.Register(Rn_size, Rn)));
    il.AddInstruction(il.Goto(afterLabel));

    // Rd = Rm + 1
    il.MarkLabel(incrementLabel);
    il.AddInstruction(il.SetRegister(
        Rd_size, Rd,
        il.Add(Rd_size, il.Register(Rm_size, Rm), il.Const(Rd_size, 1))));

    il.MarkLabel(afterLabel);

    return true;
  }

  bool LiftUMULL(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 3) {
      return false;
    }

    uint32_t Xd = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));
    uint32_t Wn = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[1].reg));
    uint32_t Wm = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[2].reg));

    il.AddInstruction(il.SetRegister(
        8, Xd, il.Mult(8, il.Register(4, Wn), il.Register(4, Wm))));

    return true;
  }

  bool LiftCINC(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 2) {
      return false;
    }

    uint32_t Rd = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));
    uint32_t Rn = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[1].reg));
    size_t Rd_size = this->m_base->GetRegisterInfo(Rd).size;
    size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;

    if (detail->cc == ARM64_CC_INVALID) {
      return false;
    }

    if (detail->cc == ARM64_CC_AL || detail->cc == ARM64_CC_NV) {
      // Rd = Rn + 1
      il.AddInstruction(il.SetRegister(
          Rd_size, Rd,
          il.Add(Rd_size, il.Register(Rn_size, Rn), il.Const(Rd_size, 1))));
      return true;
    }

    LowLevelILLabel incrementLabel, assignmentLabel, afterLabel;

    il.AddInstruction(il.If(il.FlagCondition(LiftCondition(detail->cc)),
                            incrementLabel, assignmentLabel));

    // Rd = Rn + 1
    il.MarkLabel(incrementLabel);
    il.AddInstruction(il.SetRegister(
        Rd_size, Rd,
        il.Add(Rd_size, il.Register(Rn_size, Rn), il.Const(Rd_size, 1))));
    il.AddInstruction(il.Goto(afterLabel));

    // Rd = Rn
    il.MarkLabel(assignmentLabel);
    il.AddInstruction(il.SetRegister(Rd_size, Rd, il.Register(Rn_size, Rn)));

    il.MarkLabel(afterLabel);

    return true;
  }

  bool LiftBFI(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 4) {
      return false;
    }

    uint32_t Rd = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));
    uint32_t Rn = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[1].reg));
    size_t Rd_size = this->m_base->GetRegisterInfo(Rd).size;
    size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;
    int64_t lsb = detail->operands[2].imm;
    int64_t width = detail->operands[3].imm;

    // Continue if the both are same size and either 32-bit or 64-bit
    if (Rd_size != Rn_size && !(Rd_size == 4 ^ Rd_size == 8)) {
      return false;
    }

    uint64_t inclusion_mask;
    if (Rd_size == 8) {
      inclusion_mask = Ones<uint64_t>(width) << lsb;
    } else {
      inclusion_mask = Ones<uint32_t>(width) << lsb;
    }

    ExprId left = il.And(Rd_size, il.Register(Rd_size, Rd),
                         il.Const(Rd_size, ~inclusion_mask));
    ExprId right = il.And(
        Rd_size,
        il.ShiftLeft(Rd_size, il.Register(Rd_size, Rn), il.Const(1, lsb)),
        il.Const(Rd_size, inclusion_mask));
    il.AddInstruction(il.SetRegister(Rd_size, Rd, il.Or(Rd_size, left, right)));

    return true;
  }

  bool LiftROR(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 3) {
      return false;
    }

    uint32_t Rd = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));
    uint32_t Rn = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[1].reg));

    size_t Rd_size = this->m_base->GetRegisterInfo(Rd).size;
    size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;

    if (Rd_size != Rn_size) {
      return false;
    }

    if (detail->operands[2].type == ARM64_OP_REG) {
      uint32_t Rm = this->m_base->GetRegisterByName(
          cs_reg_name(disassembler.Get(), detail->operands[2].reg));

      il.AddInstruction(
          il.SetRegister(Rd_size, Rd,
                         il.RotateRight(Rd_size, il.Register(Rd_size, Rn),
                                        il.Register(Rd_size, Rm))));
      return true;
    } else if (detail->operands[2].type == ARM64_OP_IMM) {
      uint32_t shift = detail->operands[2].imm;

      il.AddInstruction(
          il.SetRegister(Rd_size, Rd,
                         il.RotateRight(Rd_size, il.Register(Rd_size, Rn),
                                        il.Const(Rd_size, shift))));
      return true;
    }

    return false;
  }

  bool LiftFMOV(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 2) {
      return false;
    }

    if (detail->operands[0].type == ARM64_OP_REG &&
        detail->operands[1].type == ARM64_OP_FP) {
      uint32_t Rd = this->m_base->GetRegisterByName(
          cs_reg_name(disassembler.Get(), detail->operands[0].reg));
      size_t Rd_size = this->m_base->GetRegisterInfo(Rd).size;

      double rhsConst = detail->operands[1].fp;

      if (16 == Rd_size) {
        /*
         * FMOV (vector, immediate) not supported
         */
        return false;
      } else if (Rd_size <= 8) {
        /*
         * FMOV (scalar, immediate)
         */
        il.AddInstruction(
            il.SetRegister(Rd_size, Rd,
                           il.FloatConstDouble(
                               rhsConst, ILSourceLocation(instr->address, 1))));
        return true;
      } else {
        return false;
      }
    } else if (detail->operands[0].type == ARM64_OP_REG &&
               detail->operands[1].type == ARM64_OP_REG) {
      uint32_t Rd = this->m_base->GetRegisterByName(
          cs_reg_name(disassembler.Get(), detail->operands[0].reg));
      uint32_t Rn = this->m_base->GetRegisterByName(
          cs_reg_name(disassembler.Get(), detail->operands[1].reg));

      size_t Rd_size = this->m_base->GetRegisterInfo(Rd).size;
      size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;

      if (-1 == detail->operands[0].vector_index &&
          1 == detail->operands[1].vector_index && 8 == Rd_size &&
          16 == Rn_size) {
        /* FMOV <Xn>, <Vd>.D[1] */
        uint32_t subRn = VecSubRegister(Rn, Rd_size, 1);
        if (0 == subRn) {
          LogError("%#lx: Invalid vector element access in operand 1",
                   instr->address);
          return false;
        }

        il.AddInstruction(
            il.SetRegister(Rd_size, Rd, il.Register(Rd_size, subRn)));
        return true;
      } else if (1 == detail->operands[0].vector_index &&
                 -1 == detail->operands[1].vector_index && 16 == Rd_size &&
                 8 == Rn_size) {
        /* FMOV <Vd>.D[1], <Xn> */
        uint32_t subRd = VecSubRegister(Rd, Rn_size, 1);
        if (0 == subRd) {
          LogError("%#lx: Invalid vector element access in operand 0",
                   instr->address);
          return false;
        }

        il.AddInstruction(
            il.SetRegister(Rn_size, subRd, il.Register(Rn_size, Rn)));
        return true;
      } else if (-1 == detail->operands[0].vector_index &&
                 -1 == detail->operands[1].vector_index) {
        if (Rd_size != Rn_size && 2 != Rd_size && 2 != Rn_size) {
          return false;
        }

        ExprId rhs;

        if (Rd_size > Rn_size) {
          /* FMOV (general, extend) */
          rhs = il.ZeroExtend(Rd_size, il.Register(Rn_size, Rn));
        } else if (Rd_size < Rn_size) {
          /* FMOV (general, truncate) */
          rhs = il.Register(Rd_size, Rn);
        } else {
          /* FMOV (general, same size) */
          rhs = il.Register(Rn_size, Rn);
        }

        il.AddInstruction(il.SetRegister(Rd_size, Rd, rhs));
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool LiftMRS(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 2) {
      return false;
    }

    if (detail->operands[0].type != ARM64_OP_REG ||
        detail->operands[1].type != ARM64_OP_REG_MRS) {
      return false;
    }

    uint32_t Rd = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));
    uint32_t Rn = detail->operands[1].reg;

    size_t Rd_size = this->m_base->GetRegisterInfo(Rd).size;
    size_t Rn_size = 8;

    if (Rd_size != Rn_size) {
      return false;
    }

    il.AddInstruction(il.Intrinsic(
        {RegisterOrFlag(false, Rd)}, mIntrinsicNames["__builtin_mrs"],
        {il.Const(Rn_size, Rn, ILSourceLocation(instr->address, 1))}, 0,
        ILSourceLocation(instr->address, 0)));

    return true;
  }

  bool LiftMSR(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 2) {
      return false;
    }

    if (detail->operands[0].type != ARM64_OP_REG_MSR) {
      return false;
    }

    uint32_t Rd = detail->operands[0].reg;
    const size_t Rd_size = 8;

    ExprId srcExpr;

    switch (detail->operands[1].type) {
    case ARM64_OP_REG_MSR: {
      uint32_t Rn = this->m_base->GetRegisterByName(
          cs_reg_name(disassembler.Get(), detail->operands[1].reg));

      size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;

      if (Rd_size != Rn_size) {
        return false;
      }

      srcExpr = il.Register(Rn_size, Rn);
    } break;
    case ARM64_OP_IMM:
      srcExpr = il.Const(Rd_size, detail->operands[0].imm,
                         ILSourceLocation(instr->address, 1));
      break;
    default:
      return false;
    }

    il.AddInstruction(il.Intrinsic(
        {}, mIntrinsicNames["__builtin_msr"],
        {il.Const(Rd_size, Rd, ILSourceLocation(instr->address, 0)), srcExpr},
        0, ILSourceLocation(instr->address, 0)));

    return true;
  }

  bool LiftINS(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 2) {
      return false;
    }

    if (detail->operands[0].type != ARM64_OP_REG ||
        -1 == detail->operands[0].vector_index ||
        ARM64_VAS_INVALID == detail->operands[0].vas ||
        detail->operands[1].type != ARM64_OP_REG) {
      return false;
    }

    uint32_t Rd = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));
    uint32_t Rn = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[1].reg));

    size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;

    auto Rd_elem_size_opt = VecElementSize(detail->operands[0].vas);
    if (!Rd_elem_size_opt.has_value()) {
      return false;
    }
    size_t Rd_elem_size = *Rd_elem_size_opt;

    int Rd_index = detail->operands[0].vector_index;
    int Rn_index = detail->operands[1].vector_index;

    uint32_t subRd = VecSubRegister(Rd, Rn_size, Rd_index);
    if (0 == subRd) {
      LogError("%#lx: Invalid vector element access in operand 0",
               instr->address);
      return false;
    }

    if (-1 == Rn_index) {
      /* INS (general) */
      if (Rd_elem_size != Rn_size) {
        LogError("%#lx: Operand size mismatch: Vd.Ts size %zu, Rn size %zu",
                 instr->address, Rd_elem_size, Rn_size);
        return false;
      }

      il.AddInstruction(
          il.SetRegister(Rn_size, subRd, il.Register(Rn_size, Rn)));
    } else {
      /* INS (element) */

      if (ARM64_VAS_INVALID == detail->operands[1].vas) {
        LogError("%#lx: Vector operand 1 missing arrangement specifier",
                 instr->address);
        return false;
      }

      auto Rn_elem_size_opt = VecElementSize(detail->operands[0].vas);
      if (!Rn_elem_size_opt.has_value()) {
        return false;
      }
      size_t Rn_elem_size = *Rn_elem_size_opt;

      if (Rd_elem_size != Rn_elem_size) {
        LogError("%#lx: Vector operand element size mismatch: %zu != %zu",
                 instr->address, Rd_elem_size, Rn_elem_size);
        return false;
      }

      uint32_t subRn = VecSubRegister(Rn, Rn_size, Rd_index);
      if (0 == subRn) {
        LogError("%#lx: Invalid vector element access in operand 1",
                 instr->address);
        return false;
      }

      il.AddInstruction(il.SetRegister(Rd_elem_size, subRd,
                                       il.Register(Rn_elem_size, subRn)));
    }

    return true;
  }

  bool LiftSTR(cs_insn* instr, LowLevelILFunction& il) {
    cs_arm64* detail = &(instr->detail->arm64);

    if (detail->op_count != 2 && detail->op_count != 3) {
      return false;
    }

    if (detail->operands[0].type != ARM64_OP_REG ||
        detail->operands[1].type != ARM64_OP_MEM) {
      return false;
    }

    uint32_t Rt = this->m_base->GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));

    size_t Rt_size = this->m_base->GetRegisterInfo(Rt).size;

    auto address_opt =
        LiftMemoryOperand(instr->address, il, detail->operands[1]);
    if (!address_opt.has_value()) {
      return false;
    }
    ExprId address = *address_opt;
    ExprId value;

    if (ARM64_REG_WZR == detail->operands[0].reg ||
        ARM64_REG_XZR == detail->operands[0].reg) {
      /* The zero register doesn't count */
      value = il.Const(1, 0);
    } else {
      value = il.Register(Rt_size, Rt);
    }

    il.AddInstruction(il.Store(Rt_size, address, value));

    if (detail->writeback) {
      /* Lift write-back to base register (Rn) */
      uint32_t Rn = this->m_base->GetRegisterByName(
          cs_reg_name(disassembler.Get(), detail->operands[1].mem.base));
      size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;

      /* Lift address expr again for writeback */
      auto address_opt =
          LiftMemoryOperand(instr->address, il, detail->operands[1]);
      if (!address_opt.has_value()) {
        return false;
      }
      ExprId address = *address_opt;

      if (3 == detail->op_count) {
        /* Add post-index */
        if (ARM64_OP_IMM != detail->operands[2].type) {
          LogError("%#lx: Expected immediate or nothing for operand 2",
                   instr->address);
          return false;
        }

        if (detail->operands[2].imm > 255 || detail->operands[2].imm < -256) {
          /* This should be a 9-bit encoding, so that's odd ... */
          LogError("%#lx: Invalid disassembly: 9-bit immediate post-index out "
                   "of range: %ld",
                   instr->address, detail->operands[2].imm);
          return false;
        }

        address =
            il.Add(Rn_size, address, il.Const(2, detail->operands[2].imm));
      }

      il.AddInstruction(il.SetRegister(Rn_size, Rn, address));
    }

    return true;
  }

  bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len,
                                LowLevelILFunction& il) override {
    cs_insn* instr;
    size_t count = cs_disasm(disassembler.Get(), data, AARCH64_MAX_INSTR_SIZE,
                             addr, 0, &instr);

    bool supported = false;
    if (count > 0) {
      switch (instr->id) {
      case ARM64_INS_CSINC:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("CSINC @ 0x%lx", instr->address);
#endif
        supported = LiftCSINC(instr, il);
        break;
      case ARM64_INS_UMULL:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("UMULL @ 0x%lx", instr->address);
#endif
        supported = LiftUMULL(instr, il);
        break;
      case ARM64_INS_CINC:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("CINC @ 0x%lx", instr->address);
#endif
        supported = LiftCINC(instr, il);
        break;
      case ARM64_INS_BFI:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("BFI @ 0x%lx", instr->address);
#endif
        supported = LiftBFI(instr, il);
        break;
      case ARM64_INS_ROR:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("ROR @ 0x%lx", instr->address);
#endif
        supported = LiftROR(instr, il);
        break;
      case ARM64_INS_FMOV:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("FMOV @ 0x%lx", instr->address);
#endif
        supported = LiftFMOV(instr, il);
        break;
      case ARM64_INS_MRS:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("MRS @ 0x%lx", instr->address);
#endif
        supported = LiftMRS(instr, il);
        break;
      case ARM64_INS_MSR:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("MSR @ 0x%lx", instr->address);
#endif
        supported = LiftMSR(instr, il);
        break;
      case ARM64_INS_MOV:
        /* Capstone (sometimes?) uses this alias for INS... */
        /* fall through, only handles INS-like operands */
      case ARM64_INS_INS:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("INS @ 0x%lx", instr->address);
#endif
        supported = LiftINS(instr, il);
        break;
      case ARM64_INS_STR:
#ifdef AARCH64_TRACE_INSTR
        LogInfo("STR @ 0x%lx", instr->address);
#endif
        supported = LiftSTR(instr, il);
        break;
      }
    }

    if (count > 0) {
      len = instr->size;
      cs_free(instr, count);
    }

    if (!supported) {
      return ArchitectureHook::GetInstructionLowLevelIL(data, addr, len, il);
    }

    return true;
  }

  string GetIntrinsicName(uint32_t intrinsic) override {
    if (mIntrinsics.find(intrinsic) == mIntrinsics.end()) {
      return ArchitectureHook::GetIntrinsicName(intrinsic);
    } else {
      return mIntrinsics[intrinsic].name;
    }
  }

  std::vector<uint32_t> GetAllIntrinsics() override {
    auto base = ArchitectureHook::GetAllIntrinsics();

    for (auto& instr : mIntrinsics) {
      base.push_back(instr.first);
    }

    return base;
  }

  std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override {
    if (mIntrinsics.find(intrinsic) == mIntrinsics.end()) {
      return ArchitectureHook::GetIntrinsicInputs(intrinsic);
    } else {
      std::vector<FunctionParameter> parms =
          mIntrinsics[intrinsic].type.GetValue()->GetParameters();
      std::vector<NameAndType> inputs;

      inputs.reserve(parms.size());

      for (auto& parm : parms) {
        inputs.emplace_back(parm.name, parm.type);
      }

      return inputs;
    }
  }

  std::vector<Confidence<Ref<Type>>>
  GetIntrinsicOutputs(uint32_t intrinsic) override {
    if (mIntrinsics.find(intrinsic) == mIntrinsics.end()) {
      return ArchitectureHook::GetIntrinsicOutputs(intrinsic);
    } else {
      Confidence<Ref<Type>> retType =
          mIntrinsics[intrinsic].type.GetValue()->GetChildType();
      if (retType.GetValue() == Type::VoidType()) {
        return {};
      } else {
        return {retType};
      }
    }
  }

  BNRegisterInfo GetRegisterInfo(uint32_t reg) override {
    if (mRegisters.find(reg) == mRegisters.end()) {
      return ArchitectureHook::GetRegisterInfo(reg);
    } else {
      return mRegisters[reg].second;
    }
  }

  string GetRegisterName(uint32_t reg) override {
    if (mRegisters.find(reg) == mRegisters.end()) {
      return ArchitectureHook::GetRegisterName(reg);
    } else {
      return mRegisters[reg].first;
    }
  }

  std::vector<uint32_t> GetAllRegisters() override {
    auto base = ArchitectureHook::GetAllRegisters();

    base.reserve(base.size() + mRegisters.size());
    for (auto& reg : mRegisters) {
      base.push_back(reg.first);
    }

    return base;
  }
};

extern "C" {
BINARYNINJAPLUGIN void CorePluginDependencies() {
  AddRequiredPluginDependency("arch_arm64");
}

BINARYNINJAPLUGIN bool CorePluginInit() {
  if (!disassembler.IsOK()) {
    LogError("Failed to create AArch64 disassembler engine");
    return false;
  }

  auto* aarch64Ext =
      new AArch64ArchitectureExtension(Architecture::GetByName("aarch64"));

  if (aarch64Ext->Init()) {
    Architecture::Register(aarch64Ext);
    LogInfo("Registered AArch64 extensions plugin");
  } else {
    LogError("Failed to initialize AArch64 extensions plugin");
    return false;
  }

  return true;
}
}
