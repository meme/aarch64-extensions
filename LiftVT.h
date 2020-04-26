#pragma once

#include "A64.h"

/**
 * Given a Vector Arrangement Specifier, return the _element_ size to be
 * operated on.
 *
 * Verify that the VAS is indeed valid before calling this function.
 *
 * @param vas vector arrangement specifier
 * @return the _element_ size to be operated on
 */
static std::optional<size_t> VecElementSize(enum arm64_vas vas) {
  switch (vas) {
  case ARM64_VAS_16B:
  case ARM64_VAS_8B:
#ifdef CAPSTONE_NEXT
    case ARM64_VAS_4B:
  case ARM64_VAS_1B:
#endif /* #ifdef CAPSTONE_NEXT */
    return (1);
  case ARM64_VAS_8H:
  case ARM64_VAS_4H:
#ifdef CAPSTONE_NEXT
    case ARM64_VAS_2H:
  case ARM64_VAS_1H:
#endif /* #ifdef CAPSTONE_NEXT */
    return (2);
  case ARM64_VAS_4S:
  case ARM64_VAS_2S:
#ifdef CAPSTONE_NEXT
    case ARM64_VAS_1S:
#endif /* #ifdef CAPSTONE_NEXT */
    return (4);
  case ARM64_VAS_2D:
  case ARM64_VAS_1D:
    return (8);
  case ARM64_VAS_1Q:
    return (16);
  default:
    /*
     * If we've called this with ARM64_VAS_INVALID we're missing new enum
     * members, we need to fix the caller.
     */
    LogError("%s() called with invalid VAS %d", __FUNCTION__, vas);
    return {};
  }
}

struct VectorAccess {
  char elemType;
  size_t elemSize;
  size_t vectorIndex;
};

/*
 * Vector arrangement forms used to generate Binary Ninja sub-registers.
 */
const struct VectorAccess regForms[] = {
    {'d', 8, 0},  {'d', 8, 1},

    {'s', 4, 0},  {'s', 4, 1},  {'s', 4, 2},  {'s', 4, 3},

    {'h', 2, 0},  {'h', 2, 1},  {'h', 2, 2},  {'h', 2, 3},
    {'h', 2, 4},  {'h', 2, 5},  {'h', 2, 6},  {'h', 2, 7},

    {'b', 1, 0},  {'b', 1, 1},  {'b', 1, 2},  {'b', 1, 3},
    {'b', 1, 4},  {'b', 1, 5},  {'b', 1, 6},  {'b', 1, 7},
    {'b', 1, 8},  {'b', 1, 9},  {'b', 1, 10}, {'b', 1, 11},
    {'b', 1, 12}, {'b', 1, 13}, {'b', 1, 14}, {'b', 1, 15}};

class LiftVT final : A64::Lifter {
private:
  static bool LiftINS(A64&, cs_insn*, LowLevelILFunction&);

public:
  bool Init(A64&, LifterMap&) override;
};