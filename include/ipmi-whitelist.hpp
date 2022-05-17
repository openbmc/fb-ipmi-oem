#pragma once

#include <utility>
#include <vector>

using netfncmd_pair = std::pair<unsigned char, unsigned char>;

constexpr int IpmbChannel = 0x0;

extern const std::vector<netfncmd_pair> whitelist;
