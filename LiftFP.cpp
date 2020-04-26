#include "LiftFP.h"

bool LiftFP::Init(A64&, LifterMap& handlers) {
  handlers[ARM64_INS_FMOV] = &LiftFMOV;
  return true;
}

bool LiftFP::LiftFMOV(A64& base, cs_insn* instr, LowLevelILFunction& il) {
  cs_arm64* detail = &(instr->detail->arm64);

  if (detail->op_count != 2) {
    return false;
  }

  if (detail->operands[0].type == ARM64_OP_REG &&
      detail->operands[1].type == ARM64_OP_FP) {
    uint32_t Rd = base.GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));
    size_t Rd_size = base.GetRegisterInfo(Rd).size;

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
    uint32_t Rd = base.GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[0].reg));
    uint32_t Rn = base.GetRegisterByName(
        cs_reg_name(disassembler.Get(), detail->operands[1].reg));

    size_t Rd_size = base.GetRegisterInfo(Rd).size;
    size_t Rn_size = base.GetRegisterInfo(Rn).size;

    if (-1 == detail->operands[0].vector_index &&
        1 == detail->operands[1].vector_index && 8 == Rd_size &&
        16 == Rn_size) {
      /* FMOV <Xn>, <Vd>.D[1] */
      uint32_t subRn = base.VecSubRegister(Rn, Rd_size, 1);
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
      uint32_t subRd = base.VecSubRegister(Rd, Rn_size, 1);
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
