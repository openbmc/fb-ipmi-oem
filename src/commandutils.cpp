/*
 * Copyright (c)  2023-present Facebook.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <commandutils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>

#include <fstream>

std::vector<FruIdDevice> getFruIdDevice(int devId)
{
    std::vector<FruIdDevice> devices;

    std::ifstream fruidMapFile("/usr/share/fb-ipmi-oem/fruid.json");
    if (!fruidMapFile)
    {
        return devices;
    }

    nlohmann::json fruidMap;
    try
    {
        fruidMapFile >> fruidMap;
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Error parsing fruidMapFile");
        return devices;
    }

    std::string idStr = std::to_string(devId);
    if (fruidMap.contains(idStr))
    {
        uint8_t bus = fruidMap[idStr]["bus"];
        std::string addrStr = fruidMap[idStr]["address"];
        uint8_t addr = std::stoi(addrStr, nullptr, 0);
        devices.emplace_back(devId, bus, addr);
        return devices;
    }

    if (devId < 1)
    {
        for (auto& [key, value] : fruidMap.items())
        {
            uint8_t keyInt = std::stoi(key, nullptr, 0);
            uint8_t bus = value["bus"];
            std::string addrStr = value["address"];
            uint8_t addr = std::stoi(addrStr, nullptr, 0);
            devices.emplace_back(keyInt, bus, addr);
        }
    }

    return devices;
}
