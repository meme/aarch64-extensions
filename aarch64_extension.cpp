#include <algorithm>
#include <assert.h>
#include <binaryninjaapi.h>
#include <capstone/capstone.h>
#include <errno.h>
#include <lowlevelilinstruction.h>
#include <string.h>

using namespace BinaryNinja;
using string = std::string;

// #define AARCH64_TRACE_INSTR
// #define CAPSTONE_NEXT

#define AARCH64_MAX_INSN_SIZE (4)

// Returns 1s expanded to count, e.g.: Count<uint8_t>(7) == 0b01111111
template <typename T> inline T Ones(size_t count) {
  if (count == sizeof(T) * 8) {
    return static_cast<T>(~static_cast<T>(0));
  } else {
    return ~(static_cast<T>(~static_cast<T>(0)) << count);
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

// Disassembler _must_ be thread_local because on multi-threaded analysis
// GetInstructionLowLevelIL may be called from multiple threads, thus causing
// Capstone to malfunction. Note that on thread exit the destructor will be
// called and the associated Capstone resources will be released
static thread_local Disassembler disassembler;

struct vector_access {
  char elemType;
  size_t elemSize;
  size_t vectorIndex;
};

/*
 * Vector arrangement forms used to generate BinaryNinja subregisters
 */
const struct vector_access regForms[] = {
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
   * Convert a Capstone condition code to BNIL condition code
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

  uint32_t getVectorSubregister(uint32_t baseRegister, size_t elemSize,
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

public:
  explicit AArch64ArchitectureExtension(Architecture* aarch64)
      : ArchitectureHook(aarch64) {}

  /*
   * Initialize the plugin. Returns false on error.
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
        BNRegisterInfo regInfo;
        char* regNameCStr = NULL;

        if (asprintf(&regNameCStr, "v%zu%c[%zu]", Vd, form.elemType,
                     form.vectorIndex) < 0) {
          LogError("Error allocating register names: %s", strerror(errno));
          return false;
        }
        assert(NULL != regNameCStr);

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
        uint32_t subRn = getVectorSubregister(Rn, Rd_size, 1);
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
        uint32_t subRd = getVectorSubregister(Rd, Rn_size, 1);
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

  bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len,
                                LowLevelILFunction& il) override {
    cs_insn* instr;
    size_t count = cs_disasm(disassembler.Get(), data, AARCH64_MAX_INSN_SIZE,
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

  AArch64ArchitectureExtension* aarch64Ext =
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
