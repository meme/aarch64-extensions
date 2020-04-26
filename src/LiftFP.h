#pragma once

#include <cstdint>
#include <optional>

#include "A64.h"

class LiftFP final : A64::Lifter {
private:
  static bool LiftFMOV(A64&, cs_insn*, LowLevelILFunction&);

public:
  bool Init(A64&, LifterMap&) override;
};