#pragma once

#include <iostream>
#include <variant>
#include <vector>

namespace ipmi
{

constexpr size_t amdPostCodeSize = 4;

namespace dimm
{
using hostId = size_t;
struct dimmLoop
{
    size_t totalErrorCount;
    std::vector<std::vector<uint8_t>> postCode;
};
} // namespace dimm
} // namespace ipmi
