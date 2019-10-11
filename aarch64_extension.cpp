#include <binaryninjaapi.h>
#include <capstone/capstone.h>

using namespace BinaryNinja;

class AArch64ArchitectureExtension : public ArchitectureHook {
private:
    csh capstone_ {};

public:
	explicit AArch64ArchitectureExtension(Architecture* aarch64) : ArchitectureHook(aarch64) {
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstone_) != CS_ERR_OK) {
            LogError("Failed to create AArch64 disassembler engine");
        }

        cs_option(capstone_, CS_OPT_DETAIL, CS_OPT_ON);
	}

	~AArch64ArchitectureExtension() override {
	    cs_close(&capstone_);
	}

    static BNLowLevelILFlagCondition LiftCondition(arm64_cc condition)  {
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

	bool LiftCSINC(cs_insn* instr, LowLevelILFunction& il) {
        cs_arm64* detail = &(instr->detail->arm64);

        // FIXME(keegan) assert op_count == 3, all registers are Xd, or Rd and that all 3 operands are registers!

        uint32_t Rd = this->m_base->GetRegisterByName(cs_reg_name(capstone_, detail->operands[0].reg));
        uint32_t Rn = this->m_base->GetRegisterByName(cs_reg_name(capstone_, detail->operands[1].reg));
        uint32_t Rm = this->m_base->GetRegisterByName(cs_reg_name(capstone_, detail->operands[2].reg));

//        LogInfo("%s %s %s", this->m_base->GetRegisterName(Rd).c_str(), this->m_base->GetRegisterName(Rn).c_str(), this->m_base->GetRegisterName(Rm).c_str());

        size_t Rd_size = this->m_base->GetRegisterInfo(Rd).size;
        size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;
        size_t Rm_size = this->m_base->GetRegisterInfo(Rm).size;

//        LogInfo("Rd %lu, Rn %lu, Rm %lu", Rd_size, Rn_size, Rm_size);

        // FIXME(keegan) XZR needs to be lifted to a constant 0
        // FIXME(keegan) assert all sizes are the same

        if (detail->cc == ARM64_CC_INVALID) {
            return false;
        }

        // Never is actually _always_, Capstone internal
        if (detail->cc == ARM64_CC_AL || detail->cc == ARM64_CC_NV) {
            il.AddInstruction(il.SetRegister(Rd_size, il.Register(Rd_size, Rd), il.Register(Rn_size, Rn)));
            return true;
        }

        LowLevelILLabel assignment_label;
        LowLevelILLabel increment_label;
        LowLevelILLabel after_label;

        il.AddInstruction(il.If(il.FlagCondition(LiftCondition(detail->cc)), assignment_label, increment_label));

        // Rd = Rn
        il.MarkLabel(assignment_label);
        il.AddInstruction(il.SetRegister(Rd_size, Rd, il.Register(Rn_size, Rn)));
        il.AddInstruction(il.Goto(after_label));

        // Rd = Rm + 1
        il.MarkLabel(increment_label);
        il.AddInstruction(
                il.SetRegister(Rd_size, Rd, il.Add(Rd_size, il.Register(Rm_size, Rm), il.Const(Rd_size, 1))));

        il.MarkLabel(after_label);

	    return true;
	}

	bool LiftUMULL(cs_insn* instr, LowLevelILFunction& il) {
        cs_arm64* detail = &(instr->detail->arm64);

        // FIXME(keegan) ensure 64-bit, 32-bit, 32-bit respectively
        uint32_t Xd = this->m_base->GetRegisterByName(cs_reg_name(capstone_, detail->operands[0].reg));
        uint32_t Wn = this->m_base->GetRegisterByName(cs_reg_name(capstone_, detail->operands[1].reg));
        uint32_t Wm = this->m_base->GetRegisterByName(cs_reg_name(capstone_, detail->operands[2].reg));

        il.AddInstruction(
                il.SetRegister(8,
                        Xd,
                        il.Mult(8, il.Register(4, Wn), il.Register(4, Wm))));

	    return true;
	}

	bool LiftCINC(cs_insn* instr, LowLevelILFunction& il) {
        cs_arm64* detail = &(instr->detail->arm64);

        // FIXME(keegan) ensure 64-bit-64-bit or 32-bit-32-bit
        uint32_t Rd = this->m_base->GetRegisterByName(cs_reg_name(capstone_, detail->operands[0].reg));
        uint32_t Rn = this->m_base->GetRegisterByName(cs_reg_name(capstone_, detail->operands[1].reg));

        size_t Rd_size = this->m_base->GetRegisterInfo(Rd).size;
        size_t Rn_size = this->m_base->GetRegisterInfo(Rn).size;

        if (detail->cc == ARM64_CC_INVALID) {
            return false;
        }

        if (detail->cc == ARM64_CC_AL || detail->cc == ARM64_CC_NV) {
            // Rd = Rn + 1
            il.AddInstruction(
                    il.SetRegister(Rd_size,
                            Rd,
                            il.Add(Rd_size,il.Register(Rn_size, Rn),il.Const(Rd_size, 1))));
            return true;
        }

        LowLevelILLabel increment_label;
        LowLevelILLabel assignment_label;
        LowLevelILLabel after_label;

        il.AddInstruction(il.If(il.FlagCondition(LiftCondition(detail->cc)), increment_label, assignment_label));

        // Rd = Rn + 1
        il.MarkLabel(increment_label);
        il.AddInstruction(
                il.SetRegister(Rd_size,
                               Rd,
                               il.Add(Rd_size,il.Register(Rn_size, Rn),il.Const(Rd_size, 1))));
        il.AddInstruction(il.Goto(after_label));

        // Rd = Rn
        il.MarkLabel(assignment_label);
        il.AddInstruction(il.SetRegister(Rd_size, Rd, il.Register(Rn_size, Rn)));

        il.MarkLabel(after_label);

	    return true;
	}

	bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override {
        cs_insn* instr;
	    size_t count = cs_disasm(capstone_, data, len, addr, 0, &instr);

        bool supported = false;
	    if (count == 1) {
            switch (instr->id) {
            case ARM64_INS_CSINC:
//                LogInfo("CSINC @ 0x%lx", addr);
                supported = LiftCSINC(instr, il);
                break;
            case ARM64_INS_UMULL:
//                LogInfo("UMULL @ 0x%lx", addr);
                supported = LiftUMULL(instr, il);
                break;
            case ARM64_INS_CINC:
//                LogInfo("CINC @ 0x%lx", addr);
                supported = LiftCINC(instr, il);
                break;
            }
        }

	    /*
	     * >>> for basic_block in current_llil:
...     for instr in basic_block:
...         if instr.operation == LowLevelILOperation.LLIL_UNIMPL:
...             print(bv.get_disassembly(instr.address))
	     *
	     * */
	    // CSETM
	    // MNEG
	    // BFI

	    // EOR with ASR
	    // ORN with ASR
	    // AND with ASR
	    // Anything with ASR?

	    // ROR reg, reg, imm
	    // ADDS reg, reg, imm

	    // MRS & friends should be lifted as an intrinsic

	    // These are unimplemented?
	    // ldr q0, [x1]
	    // str q0, [x0]

	    len = instr->size;
        cs_free(instr, count);

        if (!supported) {
            return ArchitectureHook::GetInstructionLowLevelIL(data, addr, len, il);
        }

        return true;
	}
};

extern "C" {
	BINARYNINJAPLUGIN void CorePluginDependencies() {
		AddRequiredPluginDependency("arch_arm64");
	}

	BINARYNINJAPLUGIN bool CorePluginInit() {
        LogInfo("Registered AArch64 extensions plugin");
		Architecture* aarch64Ext = new AArch64ArchitectureExtension(Architecture::GetByName("aarch64"));
		Architecture::Register(aarch64Ext);
		return true;
	}
}