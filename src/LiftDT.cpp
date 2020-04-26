#include "LiftDT.h"

bool LiftDT::Init(A64&, LifterMap& handlers) {
  handlers[ARM64_INS_STR] = &LiftSTR;
  return true;
}

bool LiftDT::LiftSTR(A64& base, cs_insn* instr, LowLevelILFunction& il) {
  cs_arm64* detail = &(instr->detail->arm64);

  if (detail->op_count != 2 && detail->op_count != 3) {
    return false;
  }

  if (detail->operands[0].type != ARM64_OP_REG ||
      detail->operands[1].type != ARM64_OP_MEM) {
    return false;
  }

  uint32_t Rt = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[0].reg));

  size_t Rt_size = base.GetRegisterInfo(Rt).size;

  auto address_opt =
      base.LiftMemoryOperand(instr->address, il, detail->operands[1]);
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
    uint32_t Rn = base.GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[1].mem.base));
    size_t Rn_size = base.GetRegisterInfo(Rn).size;

    /* Lift address expr again for writeback */
    auto address_opt =
        base.LiftMemoryOperand(instr->address, il, detail->operands[1]);
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
