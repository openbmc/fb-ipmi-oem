/*
 * Copyright (c)  2018 Intel Corporation.
 * Copyright (c)  2018-present Facebook.
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
#include <ipmid/api.h>
#include <sys/stat.h>
#include <unistd.h>

#include <appcommands.hpp>
#include <commandutils.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>

#include <algorithm>
#include <format>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>
#include <stdexcept>

namespace ipmi
{

static void registerAPPFunctions() __attribute__((constructor));
static constexpr size_t GUID_SIZE = 16;
// TODO Make offset and location runtime configurable to ensure we
// can make each define their own locations.
static constexpr off_t OFFSET_SYS_GUID = 0x17F0;
static constexpr const char* FRU_EEPROM = "/sys/bus/i2c/devices/6-0054/eeprom";

// TODO: Need to store this info after identifying proper storage
static uint8_t globEna = 0x09;
static SysInfoParam sysInfoParams;
nlohmann::json appData __attribute__((init_priority(101)));

// Custom completion codes can be defined in individual modules for command
// specific errors in the 0x80-0xBE range
constexpr ipmi::Cc ccSystemInfoParameterNotSupported = 0x80;

int sendBicCmd(uint8_t, uint8_t, uint8_t, std::vector<uint8_t>&,
               std::vector<uint8_t>&);

static inline auto responseSystemInfoParamterNotSupportCommand()
{
    return response(ccSystemInfoParameterNotSupported);
}

void printGUID(uint8_t* guid, off_t offset)
{
    std::cout << "Read GUID from offset : " << offset << " :\n";
    for (size_t i = 0; i < GUID_SIZE; i++)
    {
        int data = guid[i];
        std::cout << std::hex << data << " ";
    }
    std::cout << std::endl;
}

int getGUID(off_t offset, uint8_t* guid)
{
    int fd = -1;
    ssize_t bytes_rd;
    int ret = 0;
    std::string eepromPath = FRU_EEPROM;

    // find the eeprom path of MB FRU
    auto device = getMbFruDevice();
    if (device)
    {
        auto [bus, address] = *device;
        std::stringstream ss;
        ss << "/sys/bus/i2c/devices/" << static_cast<int>(bus) << "-"
           << std::setw(4) << std::setfill('0') << std::hex
           << static_cast<int>(address) << "/eeprom";
        eepromPath = ss.str();
    }

    errno = 0;

    // Check if file is present
    if (access(eepromPath.c_str(), F_OK) == -1)
    {
        std::cerr << "Unable to access: " << eepromPath << std::endl;
        return errno;
    }

    // Open the file
    fd = open(eepromPath.c_str(), O_RDONLY);
    if (fd == -1)
    {
        std::cerr << "Unable to open: " << eepromPath << std::endl;
        return errno;
    }

    // seek to the offset
    lseek(fd, offset, SEEK_SET);

    // Read bytes from location
    bytes_rd = read(fd, guid, GUID_SIZE);
    if (bytes_rd != GUID_SIZE)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GUID read data from EEPROM failed");
        ret = errno;
    }
    else
    {
        printGUID(guid, offset);
    }
    close(fd);
    return ret;
}

int getSystemGUID(uint8_t* guid)
{
    return getGUID(OFFSET_SYS_GUID, guid);
}

//----------------------------------------------------------------------
// Get Self Test Results (IPMI/Section 20.4) (CMD_APP_GET_SELFTEST_RESULTS)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppGetSTResults(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                               ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* res = reinterpret_cast<uint8_t*>(response);

    // TODO: Following data needs to be updated based on self-test results
    *res++ = 0x55; // Self-Test result
    *res++ = 0x00; // Extra error info in case of failure

    *data_len = 2;

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Manufacturing Test On (IPMI/Section 20.5) (CMD_APP_MFR_TEST_ON)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppMfrTestOn(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                            ipmi_response_t, ipmi_data_len_t data_len,
                            ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    std::string mfrTest = "sled-cycle";
    ipmi_ret_t rc = ipmi::ccSuccess;

    if (!memcmp(req, mfrTest.data(), mfrTest.length()) &&
        (*data_len == mfrTest.length()))
    {
        /* sled-cycle the BMC */
        auto ret = system("/usr/sbin/power-util sled-cycle");
        if (ret)
        {
            rc = ipmi::ccUnspecifiedError;
        }
    }
    else
    {
        rc = ccSystemInfoParameterNotSupported;
    }

    *data_len = 0;

    return rc;
}

//----------------------------------------------------------------------
// Set Global Enables (CMD_APP_SET_GLOBAL_ENABLES)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppSetGlobalEnables(ipmi_netfn_t, ipmi_cmd_t,
                                   ipmi_request_t request, ipmi_response_t,
                                   ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);

    globEna = *req;
    *data_len = 0;

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get Global Enables (CMD_APP_GET_GLOBAL_ENABLES)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppGetGlobalEnables(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* res = reinterpret_cast<uint8_t*>(response);

    *data_len = 1;
    *res++ = globEna;

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Clear Message flags (IPMI/Section 22.3) (CMD_APP_CLEAR_MESSAGE_FLAGS)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppClearMsgFlags(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                                ipmi_response_t, ipmi_data_len_t data_len,
                                ipmi_context_t)
{
    // Do Nothing and just return success
    *data_len = 0;

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get System GUID (CMD_APP_GET_SYS_GUID)
//----------------------------------------------------------------------
#if BIC_ENABLED
ipmi::RspType<std::vector<uint8_t>> ipmiAppGetSysGUID(
    ipmi::Context::ptr ctx, std::vector<uint8_t> reqData)

{
    std::vector<uint8_t> respData;

    uint8_t bicAddr = (uint8_t)ctx->hostIdx << 2;

    if (sendBicCmd(ctx->netFn, ctx->cmd, bicAddr, reqData, respData))
        return ipmi::responseUnspecifiedError();

    return ipmi::responseSuccess(respData);
}

#else
ipmi_ret_t ipmiAppGetSysGUID(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                             ipmi_response_t response, ipmi_data_len_t data_len,
                             ipmi_context_t)
{
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
    if (getSystemGUID(res))
    {
        return ipmi::ccUnspecifiedError;
    }
    *data_len = GUID_SIZE;
    return ipmi::ccSuccess;
}

#endif

//----------------------------------------------------------------------
// Platform specific functions for storing app data
//----------------------------------------------------------------------

void flush_app_data()
{
    /* Strings come from the host and may not be valid UTF-8; replace bad
     * bytes rather than throw and lose the whole file. */
    writeFileAtomic(
        JSON_APP_DATA_FILE,
        appData.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
}

static int platSetSysFWVer(std::span<const uint8_t> ver, const size_t hostId)
{
    std::stringstream ss;

    /* TODO: implement byte 1: Set selector
     * byte 2: encodeing, currently only supported
     * ASCII which is value 0, UTF and unicode are
     * not supported yet.
     */
    if (ver.size() < 3 || (ver[1] & 0x0f))
        return -1;

    /* Byte 3 is the string length; never read past the received data. */
    auto str = ver.subspan(3);
    size_t len = std::min<size_t>(ver[2], str.size());
    for (size_t i = 0; i < len; i++)
    {
        ss << (char)str[i];
    }

    /* Save to legacy sysfw version file for backward compatibility */
    appData[KEY_SYSFW_VER + std::to_string(hostId)] = ss.str();
    flush_app_data();

    auto sysfwVersionFile = std::format(SYSFW_VER_FILE, hostId);
    std::ofstream file(sysfwVersionFile);

    if (!file)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open system firmware version file for writing",
            phosphor::logging::entry("FILE=%s", sysfwVersionFile.c_str()));
        return -1;
    }

    file << ss.str();
    file.close();

    return 0;
}

static int platGetSysFWVer(std::vector<uint8_t>& respData, const size_t hostId)
{
    constexpr size_t headerSize = 3; // selector + encoding + version size

    std::string sysfwVersionFile = std::format(SYSFW_VER_FILE, hostId);
    std::ifstream file(sysfwVersionFile);

    if (!file)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open system firmware version file for reading",
            phosphor::logging::entry("FILE=%s", sysfwVersionFile.c_str()));
        return -1;
    }

    std::string version;
    std::getline(file, version);
    file.close();

    // Truncate if longer than allowed
    if (version.size() > SIZE_SYSFW_VER - headerSize)
    {
        version.resize(SIZE_SYSFW_VER - headerSize);
    }

    respData.push_back(0);              // Byte 1: set selector not supported
    respData.push_back(0);              // Byte 2: only ASCII supported
    respData.push_back(version.size()); // Byte 3: length of version

    for (auto c : version)
    {
        respData.push_back(c);
    }

    // Remaining byte fill to 0
    for (size_t i = 0; i < SIZE_SYSFW_VER - (version.size() + headerSize); i++)
    {
        respData.push_back(0);
    }

    return (version.size() + headerSize);
}

//----------------------------------------------------------------------
// Set Sys Info Params (IPMI/Sec 22.14a) (CMD_APP_SET_SYS_INFO_PARAMS)
//----------------------------------------------------------------------
/* Copy a request payload into a fixed-size parameter buffer and zero the
 * rest. Returns false, leaving dst untouched, if the payload is too long.
 */
template <size_t N>
static bool copySysInfoParam(uint8_t (&dst)[N], std::span<const uint8_t> data)
{
    if (data.size() > N)
    {
        return false;
    }
    std::ranges::fill(dst, 0);
    std::ranges::copy(data, dst);
    return true;
}

ipmi::RspType<uint8_t> ipmiAppSetSysInfoParams(ipmi::Context::ptr ctx,
                                               std::vector<uint8_t> req)
{
    if (req.empty())
    {
        return ipmi::responseReqDataLenInvalid();
    }

    uint8_t param = req[0];
    std::span<const uint8_t> data(req.begin() + 1, req.end());
    std::optional<size_t> hostId = findHost(ctx->hostIdx);

    if (!hostId)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }

    switch (param)
    {
        case SYS_INFO_PARAM_SET_IN_PROG:
            if (data.empty())
                return ipmi::responseReqDataLenInvalid();
            sysInfoParams.set_in_prog = data[0];
            break;
        case SYS_INFO_PARAM_SYSFW_VER:
        {
            if (!copySysInfoParam(sysInfoParams.sysfw_ver, data))
                return ipmi::responseReqDataLenInvalid();
            if (platSetSysFWVer(data, *hostId))
                return ipmi::responseSystemInfoParamterNotSupportCommand();
            break;
        }
        case SYS_INFO_PARAM_SYS_NAME:
            if (!copySysInfoParam(sysInfoParams.sys_name, data))
                return ipmi::responseReqDataLenInvalid();
            break;
        case SYS_INFO_PARAM_PRI_OS_NAME:
            if (!copySysInfoParam(sysInfoParams.pri_os_name, data))
                return ipmi::responseReqDataLenInvalid();
            break;
        case SYS_INFO_PARAM_PRESENT_OS_NAME:
            if (!copySysInfoParam(sysInfoParams.present_os_name, data))
                return ipmi::responseReqDataLenInvalid();
            break;
        case SYS_INFO_PARAM_PRESENT_OS_VER:
            if (!copySysInfoParam(sysInfoParams.present_os_ver, data))
                return ipmi::responseReqDataLenInvalid();
            break;
        case SYS_INFO_PARAM_BMC_URL:
            if (!copySysInfoParam(sysInfoParams.bmc_url, data))
                return ipmi::responseReqDataLenInvalid();
            break;
        case SYS_INFO_PARAM_OS_HV_URL:
            if (!copySysInfoParam(sysInfoParams.os_hv_url, data))
                return ipmi::responseReqDataLenInvalid();
            break;
        case SYS_INFO_PARAM_BIOS_CURRENT_BOOT_LIST:
            if (!copySysInfoParam(sysInfoParams.bios_current_boot_list, data))
                return ipmi::responseReqDataLenInvalid();
            appData[KEY_BIOS_BOOT_LEN] = data.size();
            flush_app_data();
            break;
        case SYS_INFO_PARAM_BIOS_FIXED_BOOT_DEVICE:
            if (data.size() != SIZE_BIOS_FIXED_BOOT_DEVICE)
                break;
            copySysInfoParam(sysInfoParams.bios_fixed_boot_device, data);
            break;
        case SYS_INFO_PARAM_BIOS_RSTR_DFLT_SETTING:
            if (data.size() != SIZE_BIOS_RSTR_DFLT_SETTING)
                break;
            copySysInfoParam(sysInfoParams.bios_rstr_dflt_setting, data);
            break;
        case SYS_INFO_PARAM_LAST_BOOT_TIME:
            if (data.size() != SIZE_LAST_BOOT_TIME)
                break;
            copySysInfoParam(sysInfoParams.last_boot_time, data);
            break;
        default:
            return ipmi::responseSystemInfoParamterNotSupportCommand();
            break;
    }

    return ipmi::responseSuccess();
}

//----------------------------------------------------------------------
// Get Sys Info Params (IPMI/Sec 22.14b) (CMD_APP_GET_SYS_INFO_PARAMS)
//----------------------------------------------------------------------
ipmi::RspType<std::vector<uint8_t>> ipmiAppGetSysInfoParams(
    ipmi::Context::ptr ctx, uint8_t, uint8_t param, uint8_t, uint8_t)
{
    int len;
    std::vector<uint8_t> respData;
    respData.push_back(1); // Parameter revision

    std::optional<size_t> hostId = findHost(ctx->hostIdx);

    if (!hostId)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }

    switch (param)
    {
        case SYS_INFO_PARAM_SET_IN_PROG:
            respData.push_back(sysInfoParams.set_in_prog);
            break;
        case SYS_INFO_PARAM_SYSFW_VER:
        {
            if ((platGetSysFWVer(respData, *hostId)) < 0)
                return ipmi::responseSystemInfoParamterNotSupportCommand();
            break;
        }
        case SYS_INFO_PARAM_SYS_NAME:
            respData.insert(respData.end(), std::begin(sysInfoParams.sys_name),
                            std::end(sysInfoParams.sys_name));
            break;
        case SYS_INFO_PARAM_PRI_OS_NAME:
            respData.insert(respData.end(),
                            std::begin(sysInfoParams.pri_os_name),
                            std::end(sysInfoParams.pri_os_name));
            break;
        case SYS_INFO_PARAM_PRESENT_OS_NAME:
            respData.insert(respData.end(),
                            std::begin(sysInfoParams.present_os_name),
                            std::end(sysInfoParams.present_os_name));
            break;
        case SYS_INFO_PARAM_PRESENT_OS_VER:
            respData.insert(respData.end(),
                            std::begin(sysInfoParams.present_os_ver),
                            std::end(sysInfoParams.present_os_ver));
            break;
        case SYS_INFO_PARAM_BMC_URL:
            respData.insert(respData.end(), std::begin(sysInfoParams.bmc_url),
                            std::end(sysInfoParams.bmc_url));
            break;
        case SYS_INFO_PARAM_OS_HV_URL:
            respData.insert(respData.end(), std::begin(sysInfoParams.os_hv_url),
                            std::end(sysInfoParams.os_hv_url));
            break;
        case SYS_INFO_PARAM_BIOS_CURRENT_BOOT_LIST:
        {
            len = 0;
            try
            {
                if (appData.contains(KEY_BIOS_BOOT_LEN))
                {
                    len = appData[KEY_BIOS_BOOT_LEN].get<uint8_t>();
                }
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Exception getting BIOS boot list len",
                    phosphor::logging::entry("ERROR=%s", e.what()));
            }

            if (len > SIZE_BIOS_CURRENT_BOOT_LIST)
            {
                len = SIZE_BIOS_CURRENT_BOOT_LIST;
            }

            respData.insert(
                respData.end(),
                std::begin(sysInfoParams.bios_current_boot_list),
                std::begin(sysInfoParams.bios_current_boot_list) + len);
            break;
        }
        case SYS_INFO_PARAM_BIOS_FIXED_BOOT_DEVICE:
            respData.insert(respData.end(),
                            std::begin(sysInfoParams.bios_fixed_boot_device),
                            std::end(sysInfoParams.bios_fixed_boot_device));
            break;
        case SYS_INFO_PARAM_BIOS_RSTR_DFLT_SETTING:
            respData.insert(respData.end(),
                            std::begin(sysInfoParams.bios_rstr_dflt_setting),
                            std::end(sysInfoParams.bios_rstr_dflt_setting));
            break;
        case SYS_INFO_PARAM_LAST_BOOT_TIME:
            respData.insert(respData.end(),
                            std::begin(sysInfoParams.last_boot_time),
                            std::end(sysInfoParams.last_boot_time));
            break;
        default:
            return ipmi::responseSystemInfoParamterNotSupportCommand();
            break;
    }

    return ipmi::responseSuccess(respData);
}

void registerAPPFunctions()
{
    /* Get App data stored in json file */
    std::ifstream file(JSON_APP_DATA_FILE);
    if (file)
    {
        try
        {
            appData = nlohmann::json::parse(file, nullptr, false);
            if (appData.is_discarded())
            {
                throw std::runtime_error("Error parsing APP JSON file");
            }
        }
        catch (const std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Exception parsing APP JSON file",
                phosphor::logging::entry("FILE=%s", JSON_APP_DATA_FILE),
                phosphor::logging::entry("ERROR=%s", e.what()));
            appData = nlohmann::json::object();
            writeFileAtomic(JSON_APP_DATA_FILE, appData.dump(4));
        }
        file.close();
    }
    else
    {
        appData = nlohmann::json::object();
    }

    ipmiPrintAndRegister(ipmi::netFnApp, CMD_APP_GET_SELFTEST_RESULTS, NULL,
                         ipmiAppGetSTResults,
                         PRIVILEGE_USER); // Get Self Test Results
    ipmiPrintAndRegister(ipmi::netFnApp, CMD_APP_MFR_TEST_ON, NULL,
                         ipmiAppMfrTestOn,
                         PRIVILEGE_USER); // Manufacturing Test On
    ipmiPrintAndRegister(ipmi::netFnApp, CMD_APP_SET_GLOBAL_ENABLES, NULL,
                         ipmiAppSetGlobalEnables,
                         PRIVILEGE_USER); // Set Global Enables
    ipmiPrintAndRegister(ipmi::netFnApp, CMD_APP_GET_GLOBAL_ENABLES, NULL,
                         ipmiAppGetGlobalEnables,
                         PRIVILEGE_USER); // Get Global Enables
    ipmiPrintAndRegister(ipmi::netFnApp, CMD_APP_CLEAR_MESSAGE_FLAGS, NULL,
                         ipmiAppClearMsgFlags,
                         PRIVILEGE_USER); // Clear Message flags
#if BIC_ENABLED
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSystemGuid, ipmi::Privilege::User,
                          ipmiAppGetSysGUID);
#else
    ipmiPrintAndRegister(ipmi::netFnApp, CMD_APP_GET_SYS_GUID, NULL,
                         ipmiAppGetSysGUID,
                         PRIVILEGE_USER); // Get System GUID
#endif
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdSetSystemInfoParameters,
                          ipmi::Privilege::User, ipmiAppSetSysInfoParams);

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSystemInfoParameters,
                          ipmi::Privilege::User, ipmiAppGetSysInfoParams);
    return;
}

} // namespace ipmi
