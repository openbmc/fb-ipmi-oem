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

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

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

int sendBicCmd(uint8_t, uint8_t, uint8_t, std::vector<uint8_t>&,
               std::vector<uint8_t>&);

static inline auto responseSystemInfoParamterNotSupportCommand()
{
    return response(IPMI_CC_SYSTEM_INFO_PARAMETER_NOT_SUPPORTED);
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

    return IPMI_CC_OK;
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
    ipmi_ret_t rc = IPMI_CC_OK;

    if (!memcmp(req, mfrTest.data(), mfrTest.length()) &&
        (*data_len == mfrTest.length()))
    {
        /* sled-cycle the BMC */
        auto ret = system("/usr/sbin/power-util sled-cycle");
        if (ret)
        {
            rc = IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    else
    {
        rc = IPMI_CC_SYSTEM_INFO_PARAMETER_NOT_SUPPORTED;
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

    return IPMI_CC_OK;
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

    return IPMI_CC_OK;
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

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get System GUID (CMD_APP_GET_SYS_GUID)
//----------------------------------------------------------------------
#if BIC_ENABLED
ipmi::RspType<std::vector<uint8_t>>
    ipmiAppGetSysGUID(ipmi::Context::ptr ctx, std::vector<uint8_t> reqData)

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
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = GUID_SIZE;
    return IPMI_CC_OK;
}

#endif

//----------------------------------------------------------------------
// Platform specific functions for storing app data
//----------------------------------------------------------------------

void flush_app_data()
{
    std::ofstream file(JSON_APP_DATA_FILE);
    file << appData;
    file.close();
    return;
}

static int platSetSysFWVer(uint8_t* ver, const std::string key)
{
    std::stringstream ss;
    int i;

    /* TODO: implement byte 1: Set selector
     * byte 2: encodeing, currently only supported
     * ASCII which is value 0, UTF and unicode are
     * not supported yet.
     */
    if (ver[1] & 0x0f)
        return -1;

    for (i = 3; i < 3 + ver[2]; i++)
    {
        ss << (char)ver[i];
    }

    appData[key] = ss.str();
    flush_app_data();

    return 0;
}

static int platGetSysFWVer(std::vector<uint8_t>& respData,
                           const std::string key)
{
    int len = -1;

    if (!appData.contains(std::string(key)))
    {
        return -1;
    }
    std::string str = appData[key].get<std::string>();

    respData.push_back(0); // byte 1: Set selector not supported
    respData.push_back(0); // byte 2: Only ASCII supported

    len = str.length();
    respData.push_back(len); // byte 3: Size of version

    for (auto c : str)
    {
        respData.push_back(c);
    }

    // Remaining byte fill to 0
    for (int i = 0; i < SIZE_SYSFW_VER - (len + 3); i++)
    {
        respData.push_back(0);
    }

    return (len + 3);
}

//----------------------------------------------------------------------
// Set Sys Info Params (IPMI/Sec 22.14a) (CMD_APP_SET_SYS_INFO_PARAMS)
//----------------------------------------------------------------------
ipmi::RspType<uint8_t> ipmiAppSetSysInfoParams(ipmi::Context::ptr ctx,
                                               std::vector<uint8_t> req)
{
    uint8_t param = req[0];
    uint8_t req_len = req.size();
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
            sysInfoParams.set_in_prog = req[1];
            break;
        case SYS_INFO_PARAM_SYSFW_VER:
        {
            memcpy(sysInfoParams.sysfw_ver, &req[1], SIZE_SYSFW_VER);
            std::string version_key = KEY_SYSFW_VER + std::to_string(*hostId);
            if (platSetSysFWVer(sysInfoParams.sysfw_ver, version_key))
                return ipmi::responseSystemInfoParamterNotSupportCommand();
            break;
        }
        case SYS_INFO_PARAM_SYS_NAME:
            memcpy(sysInfoParams.sys_name, &req[1], SIZE_SYS_NAME);
            break;
        case SYS_INFO_PARAM_PRI_OS_NAME:
            memcpy(sysInfoParams.pri_os_name, &req[1], SIZE_OS_NAME);
            break;
        case SYS_INFO_PARAM_PRESENT_OS_NAME:
            memcpy(sysInfoParams.present_os_name, &req[1], SIZE_OS_NAME);
            break;
        case SYS_INFO_PARAM_PRESENT_OS_VER:
            memcpy(sysInfoParams.present_os_ver, &req[1], SIZE_OS_VER);
            break;
        case SYS_INFO_PARAM_BMC_URL:
            memcpy(sysInfoParams.bmc_url, &req[1], SIZE_BMC_URL);
            break;
        case SYS_INFO_PARAM_OS_HV_URL:
            memcpy(sysInfoParams.os_hv_url, &req[1], SIZE_OS_HV_URL);
            break;
        case SYS_INFO_PARAM_BIOS_CURRENT_BOOT_LIST:
            memcpy(sysInfoParams.bios_current_boot_list, &req[1], req_len);
            appData[KEY_BIOS_BOOT_LEN] = req_len;
            flush_app_data();
            break;
        case SYS_INFO_PARAM_BIOS_FIXED_BOOT_DEVICE:
            if (SIZE_BIOS_FIXED_BOOT_DEVICE != req_len)
                break;
            memcpy(sysInfoParams.bios_fixed_boot_device, &req[1],
                   SIZE_BIOS_FIXED_BOOT_DEVICE);
            break;
        case SYS_INFO_PARAM_BIOS_RSTR_DFLT_SETTING:
            if (SIZE_BIOS_RSTR_DFLT_SETTING != req_len)
                break;
            memcpy(sysInfoParams.bios_rstr_dflt_setting, &req[1],
                   SIZE_BIOS_RSTR_DFLT_SETTING);
            break;
        case SYS_INFO_PARAM_LAST_BOOT_TIME:
            if (SIZE_LAST_BOOT_TIME != req_len)
                break;
            memcpy(sysInfoParams.last_boot_time, &req[1], SIZE_LAST_BOOT_TIME);
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
ipmi::RspType<std::vector<uint8_t>>
    ipmiAppGetSysInfoParams(ipmi::Context::ptr ctx, uint8_t, uint8_t param,
                            uint8_t, uint8_t)
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
            std::string version_key = KEY_SYSFW_VER + std::to_string(*hostId);
            if ((platGetSysFWVer(respData, version_key)) < 0)
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
            len = appData[KEY_BIOS_BOOT_LEN].get<uint8_t>();
            respData.insert(respData.end(),
                            std::begin(sysInfoParams.bios_current_boot_list),
                            std::begin(sysInfoParams.bios_current_boot_list) +
                                len);
            break;
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
        file >> appData;
        file.close();
    }

    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_SELFTEST_RESULTS, NULL,
                         ipmiAppGetSTResults,
                         PRIVILEGE_USER); // Get Self Test Results
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_MFR_TEST_ON, NULL,
                         ipmiAppMfrTestOn,
                         PRIVILEGE_USER); // Manufacturing Test On
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_SET_GLOBAL_ENABLES, NULL,
                         ipmiAppSetGlobalEnables,
                         PRIVILEGE_USER); // Set Global Enables
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_GLOBAL_ENABLES, NULL,
                         ipmiAppGetGlobalEnables,
                         PRIVILEGE_USER); // Get Global Enables
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_CLEAR_MESSAGE_FLAGS, NULL,
                         ipmiAppClearMsgFlags,
                         PRIVILEGE_USER); // Clear Message flags
#if BIC_ENABLED
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnApp,
                          ipmi::app::cmdGetSystemGuid, ipmi::Privilege::User,
                          ipmiAppGetSysGUID);
#else
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_SYS_GUID, NULL,
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
