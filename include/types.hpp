#pragma once

#include <iostream>
#include <variant>
#include <vector>

namespace ipmi
{

constexpr size_t amdFourBytesPostCode = 4;

namespace dimm
{
using hostId = size_t;
struct dimmLoop
{
    size_t totalErrorCount;
    bool gotPattern;  // It gets the whole pattern success.
    bool startDetect; // Dimm loop detection to use. After getting the anchor
                      // tag start to detected.
    std::vector<std::vector<uint8_t>> postCode;
};
} // namespace dimm
} // namespace ipmi
