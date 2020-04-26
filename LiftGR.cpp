#include "LiftGR.h"

#include <lowlevelilinstruction.h>

bool LiftGR::Init(A64&, LifterMap& handlers) {
  handlers[ARM64_INS_CSINC] = &LiftCSINC;
  handlers[ARM64_INS_UMULL] = &LiftUMULL;
  handlers[ARM64_INS_CINC] = &LiftCINC;
  handlers[ARM64_INS_BFI] = &LiftBFI;
  handlers[ARM64_INS_ROR] = &LiftROR;
  handlers[ARM64_INS_MRS] = &LiftMRS;
  handlers[ARM64_INS_MSR] = &LiftMSR;
  return true;
}

bool LiftGR::LiftCSINC(A64& base, cs_insn* instr, LowLevelILFunction& il) {
  cs_arm64* detail = &(instr->detail->arm64);

  if (detail->op_count != 3) {
    return false;
  }

  uint32_t Rd = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[0].reg));
  uint32_t Rn = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[1].reg));
  uint32_t Rm = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[2].reg));
  size_t Rd_size = base.GetRegisterInfo(Rd).size;
  size_t Rn_size = base.GetRegisterInfo(Rn).size;
  size_t Rm_size = base.GetRegisterInfo(Rm).size;

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

bool LiftGR::LiftUMULL(A64& base, cs_insn* instr, LowLevelILFunction& il) {
  cs_arm64* detail = &(instr->detail->arm64);

  if (detail->op_count != 3) {
    return false;
  }

  uint32_t Xd = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[0].reg));
  uint32_t Wn = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[1].reg));
  uint32_t Wm = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[2].reg));

  il.AddInstruction(il.SetRegister(
      8, Xd, il.Mult(8, il.Register(4, Wn), il.Register(4, Wm))));

  return true;
}

bool LiftGR::LiftCINC(A64& base, cs_insn* instr, LowLevelILFunction& il) {
  cs_arm64* detail = &(instr->detail->arm64);

  if (detail->op_count != 2) {
    return false;
  }

  uint32_t Rd = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[0].reg));
  uint32_t Rn = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[1].reg));
  size_t Rd_size = base.GetRegisterInfo(Rd).size;
  size_t Rn_size = base.GetRegisterInfo(Rn).size;

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

bool LiftGR::LiftBFI(A64& base, cs_insn* instr, LowLevelILFunction& il) {
  cs_arm64* detail = &(instr->detail->arm64);

  if (detail->op_count != 4) {
    return false;
  }

  uint32_t Rd = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[0].reg));
  uint32_t Rn = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[1].reg));
  size_t Rd_size = base.GetRegisterInfo(Rd).size;
  size_t Rn_size = base.GetRegisterInfo(Rn).size;
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

bool LiftGR::LiftROR(A64& base, cs_insn* instr, LowLevelILFunction& il) {
  cs_arm64* detail = &(instr->detail->arm64);

  if (detail->op_count != 3) {
    return false;
  }

  uint32_t Rd = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[0].reg));
  uint32_t Rn = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[1].reg));

  size_t Rd_size = base.GetRegisterInfo(Rd).size;
  size_t Rn_size = base.GetRegisterInfo(Rn).size;

  if (Rd_size != Rn_size) {
    return false;
  }

  if (detail->operands[2].type == ARM64_OP_REG) {
    uint32_t Rm = base.GetRegisterByName(
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

bool LiftGR::LiftMRS(A64& base, cs_insn* instr, LowLevelILFunction& il) {
  cs_arm64* detail = &(instr->detail->arm64);

  if (detail->op_count != 2) {
    return false;
  }

  if (detail->operands[0].type != ARM64_OP_REG ||
      detail->operands[1].type != ARM64_OP_REG_MRS) {
    return false;
  }

  uint32_t Rd = base.GetRegisterByName(
      cs_reg_name(disassembler.Get(), detail->operands[0].reg));
  uint32_t Rn = detail->operands[1].reg;

  size_t Rd_size = base.GetRegisterInfo(Rd).size;
  size_t Rn_size = 8;

  if (Rd_size != Rn_size) {
    return false;
  }

  il.AddInstruction(il.Intrinsic(
      {RegisterOrFlag(false, Rd)}, base.GetIntrinsicByName("__builtin_mrs"),
      {il.Const(Rn_size, Rn, ILSourceLocation(instr->address, 1))}, 0,
      ILSourceLocation(instr->address, 0)));

  return true;
}

bool LiftGR::LiftMSR(A64& base, cs_insn* instr, LowLevelILFunction& il) {
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
    uint32_t Rn = base.GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[1].reg));

    size_t Rn_size = base.GetRegisterInfo(Rn).size;

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
      {}, base.GetIntrinsicByName("__builtin_msr"),
      {il.Const(Rd_size, Rd, ILSourceLocation(instr->address, 0)), srcExpr},
      0, ILSourceLocation(instr->address, 0)));

  return true;
}
