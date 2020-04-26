#include "A64.h"

#include "LiftDT.h"
#include "LiftFP.h"
#include "LiftGR.h"
#include "LiftVT.h"

bool A64::Init() {
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

  LiftDT().Init(*this, mLifters);
  LiftFP().Init(*this, mLifters);
  LiftGR().Init(*this, mLifters);
  LiftVT().Init(*this, mLifters);

  return true;
}

bool A64::GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr,
                                   size_t& len, LowLevelILFunction& il) {
  cs_insn* instr;
  size_t count =
      cs_disasm(disassembler.Get(), data, A64_INSTR_SIZE, addr, 0, &instr);

  bool supported = false;
  if (count > 0) {
    const auto id = static_cast<arm64_insn>(instr->id);
    if (mLifters.find(id) != mLifters.end()) {
      supported = mLifters[id];
    }

    len = instr->size;
    cs_free(instr, count);
  }

  if (!supported) {
    return ArchitectureHook::GetInstructionLowLevelIL(data, addr, len, il);
  }

  return true;
}

std::string A64::GetIntrinsicName(uint32_t intrinsic) {
  if (mIntrinsics.find(intrinsic) == mIntrinsics.end()) {
    return ArchitectureHook::GetIntrinsicName(intrinsic);
  } else {
    return mIntrinsics[intrinsic].name;
  }
}

std::vector<uint32_t> A64::GetAllIntrinsics() {
  auto base = ArchitectureHook::GetAllIntrinsics();

  for (auto& instr : mIntrinsics) {
    base.push_back(instr.first);
  }

  return base;
}

std::vector<NameAndType> A64::GetIntrinsicInputs(uint32_t intrinsic) {
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
A64::GetIntrinsicOutputs(uint32_t intrinsic) {
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

BNRegisterInfo A64::GetRegisterInfo(uint32_t reg) {
  if (mRegisters.find(reg) == mRegisters.end()) {
    return ArchitectureHook::GetRegisterInfo(reg);
  } else {
    return mRegisters[reg].second;
  }
}

std::string A64::GetRegisterName(uint32_t reg) {
  if (mRegisters.find(reg) == mRegisters.end()) {
    return ArchitectureHook::GetRegisterName(reg);
  } else {
    return mRegisters[reg].first;
  }
}

std::vector<uint32_t> A64::GetAllRegisters() {
  auto base = ArchitectureHook::GetAllRegisters();

  base.reserve(base.size() + mRegisters.size());
  for (auto& reg : mRegisters) {
    base.push_back(reg.first);
  }

  return base;
}

extern "C" {
BINARYNINJAPLUGIN void CorePluginDependencies() {
  AddRequiredPluginDependency("arch_arm64");
}

BINARYNINJAPLUGIN bool CorePluginInit() {
  if (!disassembler.IsOK()) {
    LogError("Failed to create AArch64 disassembler engine");
    return false;
  }

  auto* aarch64Ext = new A64(Architecture::GetByName("aarch64"));

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
