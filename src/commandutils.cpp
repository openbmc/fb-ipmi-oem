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

#include <fcntl.h>
#include <unistd.h>

#include <commandutils.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

#include <cerrno>
#include <cstring>

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

bool writeFileAtomic(const std::filesystem::path& path, std::string_view data)
{
    std::filesystem::path tmpPath = path;
    tmpPath += ".tmp";

    int fd =
        open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        lg2::error("Failed to create {FILE}: {ERROR}", "FILE", tmpPath.string(),
                   "ERROR", std::strerror(errno));
        return false;
    }

    auto fail = [&](const char* step) {
        lg2::error("Failed to {STEP} {FILE}: {ERROR}", "STEP", step, "FILE",
                   tmpPath.string(), "ERROR", std::strerror(errno));
        if (fd >= 0)
        {
            close(fd);
        }
        unlink(tmpPath.c_str());
        return false;
    };

    while (!data.empty())
    {
        ssize_t n = write(fd, data.data(), data.size());
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return fail("write");
        }
        data.remove_prefix(n);
    }

    if (fsync(fd) < 0)
    {
        return fail("sync");
    }

    int rc = close(fd);
    fd = -1;
    if (rc < 0)
    {
        return fail("close");
    }

    if (rename(tmpPath.c_str(), path.c_str()) < 0)
    {
        return fail("rename");
    }

    return true;
}
