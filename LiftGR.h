#pragma once

#include "A64.h"

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

class LiftGR final : A64::Lifter {
private:
  static bool LiftCSINC(A64&, cs_insn*, LowLevelILFunction&);
  static bool LiftUMULL(A64&, cs_insn*, LowLevelILFunction&);
  static bool LiftCINC(A64&, cs_insn*, LowLevelILFunction&);
  static bool LiftBFI(A64&, cs_insn*, LowLevelILFunction&);
  static bool LiftROR(A64&, cs_insn*, LowLevelILFunction&);
  static bool LiftMRS(A64&, cs_insn*, LowLevelILFunction&);
  static bool LiftMSR(A64&, cs_insn*, LowLevelILFunction&);

public:
  bool Init(A64&, LifterMap&) override;
};