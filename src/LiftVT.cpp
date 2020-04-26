#include "LiftVT.h"

#include <cstring>

bool LiftVT::Init(A64& base, LifterMap& handlers) {
  std::vector<uint32_t> registers = base.GetAllRegisters();
  uint32_t reg = 0;
  if (!registers.empty()) {
    reg = 1 + *max_element(registers.begin(), registers.end());
  }

  for (size_t Vd = 0; Vd < 32; Vd++) {
    char baseRegisterName[4];

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

      std::string regName = regNameCStr;
      free(regNameCStr);

      regInfo.fullWidthRegister =
          base.GetRegisterByName(baseRegisterName);
      regInfo.offset = form.elemSize * form.vectorIndex;
      regInfo.size = form.elemSize;
      regInfo.extend = NoExtend;

      base.mRegisterNames[regName] = reg;
      base.mRegisters[reg++] =
          std::pair<std::string, BNRegisterInfo>(regName, regInfo);
    }
  }

  // Capstone (sometimes?) uses this alias for INS. Fall through, only handles
  // INS-like operands.
  handlers[ARM64_INS_MOV] = &LiftINS;
  handlers[ARM64_INS_INS] = &LiftINS;
  return true;
}

bool LiftVT::LiftINS(A64& base, cs_insn* instr, LowLevelILFunction& il) {
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

  uint32_t Rd = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[0].reg));
  uint32_t Rn = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[1].reg));

  size_t Rn_size = base.GetRegisterInfo(Rn).size;

  auto Rd_elem_size_opt = VecElementSize(detail->operands[0].vas);
  if (!Rd_elem_size_opt.has_value()) {
    return false;
  }
  size_t Rd_elem_size = *Rd_elem_size_opt;

  int Rd_index = detail->operands[0].vector_index;
  int Rn_index = detail->operands[1].vector_index;

  uint32_t subRd = base.VecSubRegister(Rd, Rn_size, Rd_index);
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

    il.AddInstruction(il.SetRegister(Rn_size, subRd, il.Register(Rn_size, Rn)));
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

    uint32_t subRn = base.VecSubRegister(Rn, Rn_size, Rd_index);
    if (0 == subRn) {
      LogError("%#lx: Invalid vector element access in operand 1",
               instr->address);
      return false;
    }

    il.AddInstruction(
        il.SetRegister(Rd_elem_size, subRd, il.Register(Rn_elem_size, subRn)));
  }

  return true;
}
