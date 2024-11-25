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

#include <fstream>

namespace
{
static constexpr auto eepromIface = "xyz.openbmc_project.Configuration.EEPROM";
static constexpr auto entityManager = "xyz.openbmc_project.EntityManager";
static constexpr auto inventoryPath = "/xyz/openbmc_project/inventory/system/";
static constexpr auto objectMapper = "xyz.openbmc_project.ObjectMapper";
static constexpr auto objectMapperPath = "/xyz/openbmc_project/object_mapper";

std::vector<std::string> getEepromPaths(sdbusplus::bus_t& dbus)
{
    auto mapperCall = dbus.new_method_call(objectMapper, objectMapperPath,
                                           objectMapper, "GetSubTreePaths");

    mapperCall.append(inventoryPath, 0, std::vector<std::string>{eepromIface});
    std::vector<std::string> paths;
    try
    {
        auto resp = dbus.call(mapperCall);
        resp.read(paths);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("GetSubTreePaths failed: {ERROR}", "ERROR", e);
    }

    return paths;
}

std::optional<std::pair<uint64_t, uint64_t>>
    getEepromProperties(sdbusplus::bus_t& dbus, const std::string& path)
{
    try
    {
        auto method =
            dbus.new_method_call(entityManager, path.c_str(),
                                 "org.freedesktop.DBus.Properties", "GetAll");
        method.append(eepromIface);
        std::map<std::string, std::variant<uint64_t>> props;
        dbus.call(method).read(props);

        auto busIt = props.find("Bus");
        auto addrIt = props.find("Address");
        if (busIt == props.end() || addrIt == props.end())
        {
            lg2::error("Missing Bus or Address for {PATH}", "PATH", path);
            return std::nullopt;
        }

        return std::make_pair(std::get<uint64_t>(busIt->second),
                              std::get<uint64_t>(addrIt->second));
    }
    catch (const std::exception& e)
    {
        lg2::error("Get EEPROM properties failed: {ERROR}", "ERROR", e);
        return std::nullopt;
    }
}
} // namespace

namespace ipmi
{
std::optional<std::pair<uint8_t, uint8_t>> getMbFruDevice(void)
{
    static std::optional<std::pair<uint8_t, uint8_t>> device = std::nullopt;

    if (device)
    {
        return device;
    }

    sdbusplus::bus_t dbus(ipmid_get_sd_bus_connection());
    auto paths = getEepromPaths(dbus);
    if (paths.empty())
    {
        return std::nullopt;
    }

    for (const auto& path : paths)
    {
        if (path.ends_with("/MB_FRU"))
        {
            device = getEepromProperties(dbus, path);
            break;
        }
    }

    return device;
}

std::vector<FruDevice> getFruDevices(void)
{
    static std::vector<FruDevice> devices;

    if (!devices.empty())
    {
        return devices;
    }

    std::ifstream mapFile("/usr/share/fb-ipmi-oem/fruid.json");
    if (!mapFile)
    {
        return devices;
    }

    nlohmann::json fruidMap;
    try
    {
        mapFile >> fruidMap;
    }
    catch (const std::exception& e)
    {
        lg2::error("Error parsing FRUID map file: {ERROR}", "ERROR", e);
        return devices;
    }

    sdbusplus::bus_t dbus(ipmid_get_sd_bus_connection());
    auto paths = getEepromPaths(dbus);
    if (paths.empty())
    {
        return devices;
    }

    std::unordered_map<std::string, uint8_t> pathToId;
    pathToId.reserve(fruidMap["fru_map"].size());
    for (const auto& [path, id] : fruidMap["fru_map"].items())
    {
        pathToId.emplace(std::string(inventoryPath) + path, id.get<uint8_t>());
    }

    std::map<uint8_t, std::pair<uint64_t, uint64_t>> fruDevices;
    for (const auto& path : paths)
    {
        if (auto it = pathToId.find(path); it != pathToId.end())
        {
            if (auto props = getEepromProperties(dbus, path))
            {
                fruDevices.try_emplace(it->second, props->first, props->second);
            }
        }
    }

    devices.reserve(fruDevices.size());
    for (const auto& [id, dev] : fruDevices)
    {
        devices.emplace_back(id, dev.first, dev.second);
    }

    return devices;
}
} // namespace ipmi
