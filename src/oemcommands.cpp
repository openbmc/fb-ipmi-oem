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

#include "xyz/openbmc_project/Common/error.hpp"
#include <ipmid/api.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <array>
#include <commandutils.hpp>
#include <cstring>
#include <iostream>
#include <oemcommands.hpp>
#include <phosphor-ipmi-host/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <string>
#include <vector>

#define SIZE_IANA_ID 3

namespace ipmi
{
static void registerOEMFunctions() __attribute__((constructor));
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection()); // from ipmid/api.h
static constexpr size_t maxFRUStringLength = 0x3F;

static constexpr size_t GUID_SIZE = 16;
// TODO Make offset and location runtime configurable to ensure we
// can make each define their own locations.
static constexpr off_t OFFSET_SYS_GUID = 0x17F0;
static constexpr off_t OFFSET_DEV_GUID = 0x1800;
static constexpr char *FRU_EEPROM = "/sys/bus/i2c/devices/6-0054/eeprom";

ipmi_ret_t plat_udbg_get_post_desc(uint8_t, uint8_t *, uint8_t, uint8_t *,
                                   uint8_t *, uint8_t *);
ipmi_ret_t plat_udbg_get_frame_data(uint8_t, uint8_t, uint8_t *, uint8_t *,
                                    uint8_t *);
ipmi_ret_t plat_udbg_control_panel(uint8_t, uint8_t, uint8_t, uint8_t *,
                                   uint8_t *);

void printGUID(char *guid)
{
    for (int i = 0; i < GUID_SIZE; i++)
    {
        std::cout << guid[i] << " ";
    }
    std::cout << std::endl;
}

int getGUID(off_t offset, char *guid)
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
        std::cerr << "Read: " << bytes_rd << " instead of " << GUID_SIZE
                  << std::endl;
        ret = errno;
    }
    close(fd);
    if (ret == 0)
    {
        std::cout << "Got GUID from offset : " << offset << " : ";
        printGUID(guid);
    }
    return ret;
}

int getSystemGUID(char *guid)
{
    return getGUID(OFFSET_SYS_GUID, guid);
}

int getDeviceGUID(char *guid)
{
    return getGUID(OFFSET_DEV_GUID, guid);
}

//----------------------------------------------------------------------
// Get System GUID
//----------------------------------------------------------------------
ipmi_ret_t ipmiGetSystemGUID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (getSystemGUID((char *)response))
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = GUID_SIZE;
    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Device GUID
//----------------------------------------------------------------------
ipmi_ret_t ipmiGetDeviceGUID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (getDeviceGUID((char *)response))
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = GUID_SIZE;
    return IPMI_CC_OK;
}

// return code: 0 successful
int8_t getFruData(std::string &data, std::string &name)
{
    std::string objpath = "/xyz/openbmc_project/FruDevice";
    std::string intf = "xyz.openbmc_project.FruDeviceManager";
    std::string service = getService(dbus, intf, objpath);
    ObjectValueTree valueTree = getManagedObjects(dbus, service, "/");
    if (valueTree.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No object implements interface",
            phosphor::logging::entry("INTF=%s", intf.c_str()));
        return -1;
    }

    for (const auto &item : valueTree)
    {
        auto interface = item.second.find("xyz.openbmc_project.FruDevice");
        if (interface == item.second.end())
        {
            continue;
        }

        auto property = interface->second.find(name.c_str());
        if (property == interface->second.end())
        {
            continue;
        }

        try
        {
            Value variant = property->second;
            std::string &result =
                sdbusplus::message::variant_ns::get<std::string>(variant);
            if (result.size() > maxFRUStringLength)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "FRU serial number exceed maximum length");
                return -1;
            }
            data = result;
            return 0;
        }
        catch (sdbusplus::message::variant_ns::bad_variant_access &e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
    }
    return -1;
}

typedef struct
{
    uint8_t cur_power_state;
    uint8_t last_power_event;
    uint8_t misc_power_state;
    uint8_t front_panel_button_cap_status;
} ipmi_get_chassis_status_t;

// Todo: Needs to update this as per power policy when integrated
//----------------------------------------------------------------------
// Get Chassis Status commands
//----------------------------------------------------------------------
ipmi_ret_t ipmiGetChassisStatus(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    ipmi_get_chassis_status_t chassis_status;
    uint8_t s = 2;

    *data_len = 4;

    // Current Power State
    // [7] reserved
    // [6..5] power restore policy
    //          00b = chassis stays powered off after AC/mains returns
    //          01b = after AC returns, power is restored to the state that was
    //          in effect when AC/mains was lost.
    //          10b = chassis always powers up after AC/mains returns
    //          11b = unknow
    //        Set to 00b, by observing the hardware behavior.
    //        Do we need to define a dbus property to identify the restore
    //        policy?

    // [4] power control fault
    //       1b = controller attempted to turn system power on or off, but
    //       system did not enter desired state.
    //       Set to 0b, since We don't support it..

    // [3] power fault
    //       1b = fault detected in main power subsystem.
    //       set to 0b. for we don't support it.

    // [2] 1b = interlock (chassis is presently shut down because a chassis
    //       panel interlock switch is active). (IPMI 1.5)
    //       set to 0b,  for we don't support it.

    // [1] power overload
    //      1b = system shutdown because of power overload condition.
    //       set to 0b,  for we don't support it.

    // [0] power is on
    //       1b = system power is on
    //       0b = system power is off(soft-off S4/S5, or mechanical off)

    chassis_status.cur_power_state = ((s & 0x3) << 5) | (1 & 0x1);

    // Last Power Event
    // [7..5] – reserved
    // [4] – 1b = last ‘Power is on’ state was entered via IPMI command
    // [3] – 1b = last power down caused by power fault
    // [2] – 1b = last power down caused by a power interlock being activated
    // [1] – 1b = last power down caused by a Power overload
    // [0] – 1b = AC failed
    // set to 0x0,  for we don't support these fields.

    chassis_status.last_power_event = 0;

    // Misc. Chassis State
    // [7] – reserved
    // [6] – 1b = Chassis Identify command and state info supported (Optional)
    //       0b = Chassis Identify command support unspecified via this command.
    //       (The Get Command Support command , if implemented, would still
    //       indicate support for the Chassis Identify command)
    // [5..4] – Chassis Identify State. Mandatory when bit[6] =1b, reserved
    // (return
    //          as 00b) otherwise. Returns the present chassis identify state.
    //           Refer to the Chassis Identify command for more info.
    //         00b = chassis identify state = Off
    //         01b = chassis identify state = Temporary(timed) On
    //         10b = chassis identify state = Indefinite On
    //         11b = reserved
    // [3] – 1b = Cooling/fan fault detected
    // [2] – 1b = Drive Fault
    // [1] – 1b = Front Panel Lockout active (power off and reset via chassis
    //       push-buttons disabled.)
    // [0] – 1b = Chassis Intrusion active
    //  set to 0,  for we don't support them.
    chassis_status.misc_power_state = 0x40;

    //  Front Panel Button Capabilities and disable/enable status(Optional)
    //  set to 0,  for we don't support them.
    chassis_status.front_panel_button_cap_status = 0;

    // Pack the actual response
    std::memcpy(response, &chassis_status, *data_len);

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Debug Frame Info
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetFrameInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    uint8_t num_frames = 3;

    std::memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[SIZE_IANA_ID] = num_frames;
    *data_len = SIZE_IANA_ID + 1;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Debug Updated Frames
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetUpdFrames(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    uint8_t num_updates = 3;
    *data_len = 4;

    std::memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[SIZE_IANA_ID] = num_updates;
    *data_len = SIZE_IANA_ID + num_updates + 1;
    res[SIZE_IANA_ID + 1] = 1; // info page update
    res[SIZE_IANA_ID + 2] = 2; // cri sel update
    res[SIZE_IANA_ID + 3] = 3; // cri sensor update

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Debug POST Description
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetPostDesc(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    uint8_t index = 0;
    uint8_t next = 0;
    uint8_t end = 0;
    uint8_t phase = 0;
    uint8_t count = 0;
    int ret;

    index = req[3];
    phase = req[4];

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Get POST Description Event");

    ret = plat_udbg_get_post_desc(index, &next, phase, &end, &count, &res[8]);
    if (ret)
    {
        memcpy(res, req, SIZE_IANA_ID); // IANA ID
        *data_len = SIZE_IANA_ID;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[3] = index;
    res[4] = next;
    res[5] = phase;
    res[6] = end;
    res[7] = count;
    *data_len = SIZE_IANA_ID + 5 + count;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Debug GPIO Description
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetGpioDesc(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Get GPIO Description Event");

    std::memcpy(res, req, SIZE_IANA_ID + 1); // IANA ID
    *data_len = SIZE_IANA_ID + 1;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Debug Frame Data
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetFrameData(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    uint8_t frame;
    uint8_t page;
    uint8_t next;
    uint8_t count;
    int ret;

    frame = req[3];
    page = req[4];
    int fr = frame;
    int pg = page;

    ret = plat_udbg_get_frame_data(frame, page, &next, &count, &res[7]);
    if (ret)
    {
        memcpy(res, req, SIZE_IANA_ID); // IANA ID
        *data_len = SIZE_IANA_ID;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[3] = frame;
    res[4] = page;
    res[5] = next;
    res[6] = count;
    *data_len = SIZE_IANA_ID + 4 + count;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Debug Control Panel
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetCtrlPanel(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    uint8_t panel;
    uint8_t operation;
    uint8_t item;
    uint8_t count;
    ipmi_ret_t ret;

    panel = req[3];
    operation = req[4];
    item = req[5];

    ret = plat_udbg_control_panel(panel, operation, item, &count, &res[3]);

    std::memcpy(res, req, SIZE_IANA_ID); // IANA ID
    *data_len = SIZE_IANA_ID + count;

    return ret;
}

// Todo: Need to implement all below functions for oem commands
//----------------------------------------------------------------------
// Set Dimm Info (CMD_OEM_SET_DIMM_INFO)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetDimmInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    std::memcpy(res, req, SIZE_IANA_ID + 1); // IANA ID
    *data_len = SIZE_IANA_ID + 1;
    *data_len = 0;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Boot Order (CMD_OEM_GET_BOOT_ORDER)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemGetBootOrder(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    *res++ = 0x01;
    *res++ = 0x00;
    *res++ = 0x09;
    *res++ = 0x02;
    *res++ = 0x03;
    *res++ = 0xff;
    *data_len = 6;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set Machine Config Info (CMD_OEM_SET_MACHINE_CONFIG_INFO)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetMachineCfgInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    *data_len = 0;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set POST start (CMD_OEM_SET_POST_START)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetPostStart(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    phosphor::logging::log<phosphor::logging::level::INFO>("POST Start Event");

    *data_len = 0;
    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set POST End (CMD_OEM_SET_POST_END)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetPostEnd(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    phosphor::logging::log<phosphor::logging::level::INFO>("POST End Event");

    *data_len = 0;
    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set Bios Flash Info (CMD_OEM_SET_BIOS_FLASH_INFO)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetBiosFlashInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    *data_len = 0;
    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set PPR (CMD_OEM_SET_PPR)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetPpr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                         ipmi_request_t request, ipmi_response_t response,
                         ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    *data_len = 0;
    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get PPR (CMD_OEM_GET_PPR)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemGetPpr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                         ipmi_request_t request, ipmi_response_t response,
                         ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    res[0] = 0x00;
    *data_len = 1;

    return IPMI_CC_OK;
}

static void registerOEMFunctions(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering OEM commands");
    ipmiPrintAndRegister(NETFUN_CHASSIS, 1, NULL, ipmiGetChassisStatus,
                         PRIVILEGE_USER); // get chassis status
    ipmiPrintAndRegister(NETFN_OEM_USB_DBG_REQ, CMD_OEM_USB_DBG_GET_FRAME_INFO,
                         NULL, ipmiOemDbgGetFrameInfo,
                         PRIVILEGE_USER); // get debug frame info
    ipmiPrintAndRegister(NETFN_OEM_USB_DBG_REQ,
                         CMD_OEM_USB_DBG_GET_UPDATED_FRAMES, NULL,
                         ipmiOemDbgGetUpdFrames,
                         PRIVILEGE_USER); // get debug updated frames
    ipmiPrintAndRegister(NETFN_OEM_USB_DBG_REQ, CMD_OEM_USB_DBG_GET_POST_DESC,
                         NULL, ipmiOemDbgGetPostDesc,
                         PRIVILEGE_USER); // get debug post description
    ipmiPrintAndRegister(NETFN_OEM_USB_DBG_REQ, CMD_OEM_USB_DBG_GET_GPIO_DESC,
                         NULL, ipmiOemDbgGetGpioDesc,
                         PRIVILEGE_USER); // get debug gpio description
    ipmiPrintAndRegister(NETFN_OEM_USB_DBG_REQ, CMD_OEM_USB_DBG_GET_FRAME_DATA,
                         NULL, ipmiOemDbgGetFrameData,
                         PRIVILEGE_USER); // get debug frame data
    ipmiPrintAndRegister(NETFN_OEM_USB_DBG_REQ, CMD_OEM_USB_DBG_CTRL_PANEL,
                         NULL, ipmiOemDbgGetCtrlPanel,
                         PRIVILEGE_USER); // get debug control panel
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_DIMM_INFO, NULL,
                         ipmiOemSetDimmInfo,
                         PRIVILEGE_USER); // Set Dimm Info
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_GET_BOOT_ORDER, NULL,
                         ipmiOemGetBootOrder,
                         PRIVILEGE_USER); // Get Boot Order
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_MACHINE_CONFIG_INFO, NULL,
                         ipmiOemSetMachineCfgInfo,
                         PRIVILEGE_USER); // Set Machine Config Info
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_POST_START, NULL,
                         ipmiOemSetPostStart,
                         PRIVILEGE_USER); // Set POST start
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_POST_END, NULL,
                         ipmiOemSetPostEnd,
                         PRIVILEGE_USER); // Set POST End
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_BIOS_FLASH_INFO, NULL,
                         ipmiOemSetBiosFlashInfo,
                         PRIVILEGE_USER); // Set Bios Flash Info
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_PPR, NULL, ipmiOemSetPpr,
                         PRIVILEGE_USER); // Set PPR
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_GET_PPR, NULL, ipmiOemGetPpr,
                         PRIVILEGE_USER); // Get PPR
    ipmiPrintAndRegister(NETFUN_APP, 0x8, NULL, ipmiGetDeviceGUID,
                         PRIVILEGE_USER); // get device GUID
    ipmiPrintAndRegister(NETFUN_APP, 0x37, NULL, ipmiGetSystemGUID,
                         PRIVILEGE_USER); // get system GUID
    return;
}

} // namespace ipmi
