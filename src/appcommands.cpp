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

#include <ipmid/api.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <commandutils.hpp>
#include <iostream>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <appcommands.hpp>

namespace ipmi
{

static void registerAPPFunctions() __attribute__((constructor));
static constexpr size_t GUID_SIZE = 16;
// TODO Make offset and location runtime configurable to ensure we
// can make each define their own locations.
static constexpr off_t OFFSET_SYS_GUID = 0x17F0;
static constexpr off_t OFFSET_DEV_GUID = 0x1800;
static constexpr const char *FRU_EEPROM = "/sys/bus/i2c/devices/6-0054/eeprom";
static uint8_t globEna = 0x09;

void printGUID(uint8_t *guid)
{
    for (int i = 0; i < GUID_SIZE; i++)
    {
        int data = guid[i];
        std::cout << std::hex << data << " ";
    }
    std::cout << std::endl;
}

int getGUID(off_t offset, uint8_t *guid)
{
    int fd = -1;
    ssize_t bytes_rd;
    int ret = 0;

    errno = 0;

    // Check if file is present
    if (access(FRU_EEPROM, F_OK) == -1)
    {
        std::cerr << "Unable to access: " << FRU_EEPROM << std::endl;
        return errno;
    }

    // Open the file
    fd = open(FRU_EEPROM, O_RDONLY);
    if (fd == -1)
    {
        std::cerr << "Unable to open: " << FRU_EEPROM << std::endl;
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
    close(fd);
    if (ret == 0)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Read GUID from EEPROM ",
            phosphor::logging::entry("offset : ", offset));
        printGUID(guid);
    }
    return ret;
}

int getSystemGUID(uint8_t *guid)
{
    return getGUID(OFFSET_SYS_GUID, guid);
}

int getDeviceGUID(uint8_t *guid)
{
    return getGUID(OFFSET_DEV_GUID, guid);
}

//----------------------------------------------------------------------
// Get Device GUID (CMD_APP_GET_DEV_GUID)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppGetDevGUID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    if (getDeviceGUID(res))
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = GUID_SIZE;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set Global Enables (CMD_APP_SET_GLOBAL_ENABLES)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppSetGlobalEnables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);

    globEna = *req;
    *data_len = 0;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Global Enables (CMD_APP_GET_GLOBAL_ENABLES)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppGetGlobalEnables(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    *data_len = 1;
    *res++ = globEna;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get System GUID (CMD_APP_GET_SYS_GUID)
//----------------------------------------------------------------------
ipmi_ret_t ipmiAppGetSysGUID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    if (getSystemGUID(res))
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = GUID_SIZE;
    return IPMI_CC_OK;
}

void registerAPPFunctions()
{
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_DEV_GUID, NULL,
                         ipmiAppGetDevGUID,
                         PRIVILEGE_USER); // Get Device GUID
                                          /*
                                        ipmiPrintAndRegister(NETFUN_APP, CMD_APP_SET_WD, NULL, ipmiAppSetWD,
                                                             PRIVILEGE_USER); // Set WD
                                        ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_WD, NULL, ipmiAppGetWD,
                                                             PRIVILEGE_USER); // Get WD
                                        ipmiPrintAndRegister(NETFUN_APP, CMD_APP_READ_EVENT, NULL,
                                                             ipmiAppReadEvent,
                                                             SYSTEM_INTERFACE); // Read Event Message Buffer
                                           */

    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_SET_GLOBAL_ENABLES, NULL,
                         ipmiAppSetGlobalEnables,
                         PRIVILEGE_USER); // Get Global Enables
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_GLOBAL_ENABLES, NULL,
                         ipmiAppGetGlobalEnables,
                         PRIVILEGE_USER); // Get Global Enables
    ipmiPrintAndRegister(NETFUN_APP, CMD_APP_GET_SYS_GUID, NULL,
                         ipmiAppGetSysGUID,
                         PRIVILEGE_USER); // Get System GUID

    return;
}

} // namespace ipmi
