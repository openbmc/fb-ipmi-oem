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
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>

#include <fstream>

std::optional<std::pair<uint8_t, uint8_t>> getMbFruDevice(void)
{
    static std::optional<std::pair<uint8_t, uint8_t>> device = std::nullopt;

    if (device)
    {
        return device;
    }

    sdbusplus::bus_t dbus(ipmid_get_sd_bus_connection());
    auto mapperCall = dbus.new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");
    static constexpr int32_t depth = 0;
    static constexpr auto iface = "xyz.openbmc_project.Configuration.EEPROM";
    static constexpr auto entityManager = "xyz.openbmc_project.EntityManager";
    static constexpr std::array<const char*, 1> interface = {iface};
    mapperCall.append("/xyz/openbmc_project/inventory/", depth, interface);

    std::vector<std::string> paths;
    try
    {
        auto resp = dbus.call(mapperCall);
        resp.read(paths);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return std::nullopt;
    }

    const std::string suffix = "/MB_FRU";
    for (const auto& path : paths)
    {
        if (path.ends_with(suffix))
        {
            uint8_t fruBus = std::get<uint64_t>(
                ipmi::getDbusProperty(dbus, entityManager, path, iface, "Bus"));
            uint8_t fruAddr = std::get<uint64_t>(ipmi::getDbusProperty(
                dbus, entityManager, path, iface, "Address"));
            device = std::make_pair(fruBus, fruAddr);
            break;
        }
    }

    return device;
}

std::optional<std::vector<std::tuple<uint8_t, uint8_t, uint8_t>>>
    getFruDevices(void)
{
    static std::optional<std::vector<std::tuple<uint8_t, uint8_t, uint8_t>>>
        devices = std::nullopt;

    if (devices)
    {
        return devices;
    }

    std::ifstream mapFile("/usr/share/fb-ipmi-oem/fruid.json");
    if (!mapFile)
    {
        return std::nullopt;
    }

    nlohmann::json fruidMap;
    try
    {
        mapFile >> fruidMap;
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "Error parsing FRUID map file");
        return std::nullopt;
    }

    sdbusplus::bus_t dbus(ipmid_get_sd_bus_connection());
    auto mapperCall = dbus.new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");
    static constexpr int32_t depth = 0;
    static constexpr auto iface = "xyz.openbmc_project.Configuration.EEPROM";
    static constexpr auto entityManager = "xyz.openbmc_project.EntityManager";
    static constexpr std::array<const char*, 1> interface = {iface};
    mapperCall.append("/xyz/openbmc_project/inventory/", depth, interface);

    std::vector<std::string> paths;
    try
    {
        auto resp = dbus.call(mapperCall);
        resp.read(paths);
    }
    catch (const sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return std::nullopt;
    }

    std::vector<std::tuple<uint8_t, uint8_t, uint8_t>> fruDevices;
    for (const auto& fru : fruidMap["fru_map"])
    {
        uint8_t id = fru["id"].get<uint8_t>();
        if (std::ranges::find_if(fruDevices, [id](const auto& device) {
                return std::get<0>(device) == id;
            }) != fruDevices.end())
        {
            continue;
        }

        if (auto it = std::ranges::find_if(
                paths,
                [suffix = fru["path_suffix"].get<std::string_view>()](
                    std::string_view path) { return path.ends_with(suffix); });
            it != paths.end())
        {
            try
            {
                uint8_t fruBus = std::get<uint64_t>(ipmi::getDbusProperty(
                    dbus, entityManager, *it, iface, "Bus"));
                uint8_t fruAddr = std::get<uint64_t>(ipmi::getDbusProperty(
                    dbus, entityManager, *it, iface, "Address"));
                fruDevices.emplace_back(id, fruBus, fruAddr);
            }
            catch (const std::exception&)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to get EEPROM properties");
            }
        }
    }

    if (fruDevices.empty())
    {
        return std::nullopt;
    }
    devices = std::move(fruDevices);

    return devices;
}
