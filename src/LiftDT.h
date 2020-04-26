#pragma once

#include "A64.h"

class LiftDT final : A64::Lifter {
private:
  static bool LiftSTR(A64&, cs_insn*, LowLevelILFunction&);

public:
  bool Init(A64&, LifterMap&) override;
};