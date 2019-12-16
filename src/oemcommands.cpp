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

#include <nlohmann/json.hpp>
#include <array>
#include <commandutils.hpp>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <oemcommands.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <string>
#include <vector>

#define SIZE_IANA_ID 3

namespace ipmi
{

using namespace phosphor::logging;

static void registerOEMFunctions() __attribute__((constructor));
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection()); // from ipmid/api.h
static constexpr size_t maxFRUStringLength = 0x3F;

int plat_udbg_get_post_desc(uint8_t, uint8_t *, uint8_t, uint8_t *, uint8_t *,
                            uint8_t *);
int plat_udbg_get_gpio_desc(uint8_t, uint8_t *, uint8_t *, uint8_t *, uint8_t *,
                            uint8_t *);
ipmi_ret_t plat_udbg_get_frame_data(uint8_t, uint8_t, uint8_t *, uint8_t *,
                                    uint8_t *);
ipmi_ret_t plat_udbg_control_panel(uint8_t, uint8_t, uint8_t, uint8_t *,
                                   uint8_t *);
namespace variant_ns = sdbusplus::message::variant_ns;
nlohmann::json oemData __attribute__((init_priority(101)));

enum class LanParam : uint8_t
{
    INPROGRESS = 0,
    AUTHSUPPORT = 1,
    AUTHENABLES = 2,
    IP = 3,
    IPSRC = 4,
    MAC = 5,
    SUBNET = 6,
    GATEWAY = 12,
    VLAN = 20,
    CIPHER_SUITE_COUNT = 22,
    CIPHER_SUITE_ENTRIES = 23,
    IPV6 = 59,
};

namespace network
{

constexpr auto ROOT = "/xyz/openbmc_project/network";
constexpr auto SERVICE = "xyz.openbmc_project.Network";
constexpr auto IPV4_TYPE = "ipv4";
constexpr auto IPV6_TYPE = "ipv6";
constexpr auto IPV4_PREFIX = "169.254";
constexpr auto IPV6_PREFIX = "fe80";
constexpr auto IP_INTERFACE = "xyz.openbmc_project.Network.IP";
constexpr auto MAC_INTERFACE = "xyz.openbmc_project.Network.MACAddress";

bool isLinkLocalIP(const std::string &address)
{
    return address.find(IPV4_PREFIX) == 0 || address.find(IPV6_PREFIX) == 0;
}

DbusObjectInfo getIPObject(sdbusplus::bus::bus &bus,
                           const std::string &interface,
                           const std::string &serviceRoot,
                           const std::string &match)
{
    auto objectTree = getAllDbusObjects(bus, serviceRoot, interface, match);

    if (objectTree.empty())
    {
        log<level::ERR>("No Object has implemented the IP interface",
                        entry("INTERFACE=%s", interface.c_str()));
    }

    DbusObjectInfo objectInfo;

    for (auto &object : objectTree)
    {
        auto variant =
            ipmi::getDbusProperty(bus, object.second.begin()->first,
                                  object.first, IP_INTERFACE, "Address");

        objectInfo = std::make_pair(object.first, object.second.begin()->first);

        // if LinkLocalIP found look for Non-LinkLocalIP
        if (isLinkLocalIP(std::get<std::string>(variant)))
        {
            continue;
        }
        else
        {
            break;
        }
    }
    return objectInfo;
}

} // namespace network

//----------------------------------------------------------------------
// Helper functions for storing oem data
//----------------------------------------------------------------------

void flushOemData()
{
    std::ofstream file(JSON_OEM_DATA_FILE);
    file << oemData;
    file.close();
    return;
}

std::string bytesToStr(uint8_t *byte, int len)
{
    std::stringstream ss;
    int i;

    ss << std::hex;
    for (i = 0; i < len; i++)
    {
        ss << std::setw(2) << std::setfill('0') << (int)byte[i];
    }

    return ss.str();
}

int strToBytes(std::string &str, uint8_t *data)
{
    std::string sstr;
    int i;

    for (i = 0; i < (str.length()) / 2; i++)
    {
        sstr = str.substr(i * 2, 2);
        data[i] = (uint8_t)std::strtol(sstr.c_str(), NULL, 16);
    }
    return i;
}

ipmi_ret_t getNetworkData(uint8_t lan_param, char *data)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

    const std::string ethdevice = "eth0";

    switch (static_cast<LanParam>(lan_param))
    {
        case LanParam::IP:
        {
            auto ethIP = ethdevice + "/" + ipmi::network::IPV4_TYPE;
            std::string ipaddress;
            auto ipObjectInfo = ipmi::network::getIPObject(
                bus, ipmi::network::IP_INTERFACE, ipmi::network::ROOT, ethIP);

            auto properties = ipmi::getAllDbusProperties(
                bus, ipObjectInfo.second, ipObjectInfo.first,
                ipmi::network::IP_INTERFACE);

            ipaddress = variant_ns::get<std::string>(properties["Address"]);

            std::strcpy(data, ipaddress.c_str());
        }
        break;

        case LanParam::IPV6:
        {
            auto ethIP = ethdevice + "/" + ipmi::network::IPV6_TYPE;
            std::string ipaddress;
            auto ipObjectInfo = ipmi::network::getIPObject(
                bus, ipmi::network::IP_INTERFACE, ipmi::network::ROOT, ethIP);

            auto properties = ipmi::getAllDbusProperties(
                bus, ipObjectInfo.second, ipObjectInfo.first,
                ipmi::network::IP_INTERFACE);

            ipaddress = variant_ns::get<std::string>(properties["Address"]);

            std::strcpy(data, ipaddress.c_str());
        }
        break;

        case LanParam::MAC:
        {
            std::string macAddress;
            auto macObjectInfo =
                ipmi::getDbusObject(bus, ipmi::network::MAC_INTERFACE,
                                    ipmi::network::ROOT, ethdevice);

            auto variant = ipmi::getDbusProperty(
                bus, macObjectInfo.second, macObjectInfo.first,
                ipmi::network::MAC_INTERFACE, "MACAddress");

            macAddress = variant_ns::get<std::string>(variant);

            sscanf(macAddress.c_str(), ipmi::network::MAC_ADDRESS_FORMAT,
                   (data), (data + 1), (data + 2), (data + 3), (data + 4),
                   (data + 5));
            std::strcpy(data, macAddress.c_str());
        }
        break;

        default:
            rc = IPMI_CC_PARM_OUT_OF_RANGE;
    }
    return rc;
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
    uint8_t descLen = 0;
    int ret;

    index = req[3];
    phase = req[4];

    ret = plat_udbg_get_post_desc(index, &next, phase, &end, &descLen, &res[8]);
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
    res[7] = descLen;
    *data_len = SIZE_IANA_ID + 5 + descLen;

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

    uint8_t index = 0;
    uint8_t next = 0;
    uint8_t level = 0;
    uint8_t pinDef = 0;
    uint8_t descLen = 0;
    int ret;

    index = req[3];

    ret = plat_udbg_get_gpio_desc(index, &next, &level, &pinDef, &descLen,
                                  &res[8]);
    if (ret)
    {
        memcpy(res, req, SIZE_IANA_ID); // IANA ID
        *data_len = SIZE_IANA_ID;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[3] = index;
    res[4] = next;
    res[5] = level;
    res[6] = pinDef;
    res[7] = descLen;
    *data_len = SIZE_IANA_ID + 5 + descLen;

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

//----------------------------------------------------------------------
// Set Dimm Info (CMD_OEM_SET_DIMM_INFO)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetDimmInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);

    uint8_t index = req[0];
    uint8_t type = req[1];
    uint16_t speed;
    uint32_t size;

    memcpy(&speed, &req[2], 2);
    memcpy(&size, &req[4], 4);

    std::stringstream ss;
    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)index;

    oemData[KEY_SYS_CONFIG][ss.str()][KEY_DIMM_INDEX] = index;
    oemData[KEY_SYS_CONFIG][ss.str()][KEY_DIMM_TYPE] = type;
    oemData[KEY_SYS_CONFIG][ss.str()][KEY_DIMM_SPEED] = speed;
    oemData[KEY_SYS_CONFIG][ss.str()][KEY_DIMM_SIZE] = size;

    flushOemData();

    *data_len = 0;

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Board ID (CMD_OEM_GET_BOARD_ID)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemGetBoardID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);

    /* TODO: Needs to implement this after GPIO implementation */
    *data_len = 0;

    return IPMI_CC_OK;
}

/* Helper functions to set boot order */
void setBootOrder(uint8_t *data)
{
    nlohmann::json bootMode;
    uint8_t mode = data[0];
    int i;

    bootMode["UEFI"] = (mode & BOOT_MODE_UEFI ? true : false);
    bootMode["CMOS_CLR"] = (mode & BOOT_MODE_CMOS_CLR ? true : false);
    bootMode["FORCE_BOOT"] = (mode & BOOT_MODE_FORCE_BOOT ? true : false);
    bootMode["BOOT_FLAG"] = (mode & BOOT_MODE_BOOT_FLAG ? true : false);
    oemData[KEY_BOOT_ORDER][KEY_BOOT_MODE] = bootMode;

    /* Initialize boot sequence array */
    oemData[KEY_BOOT_ORDER][KEY_BOOT_SEQ] = {};
    for (i = 1; i < SIZE_BOOT_ORDER; i++)
    {
        if (data[i] >= BOOT_SEQ_ARRAY_SIZE)
            oemData[KEY_BOOT_ORDER][KEY_BOOT_SEQ][i - 1] = "NA";
        else
            oemData[KEY_BOOT_ORDER][KEY_BOOT_SEQ][i - 1] = bootSeq[data[i]];
    }

    flushOemData();
}

//----------------------------------------------------------------------
// Set Boot Order (CMD_OEM_SET_BOOT_ORDER)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetBootOrder(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t len = *data_len;

    *data_len = 0;

    if (len != SIZE_BOOT_ORDER)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Boot order length received");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    setBootOrder(req);

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Boot Order (CMD_OEM_GET_BOOT_ORDER)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemGetBootOrder(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    uint8_t mode = 0;
    int i;

    *data_len = SIZE_BOOT_ORDER;

    if (oemData.find(KEY_BOOT_ORDER) == oemData.end())
    {
        /* Return default boot order 0100090203ff */
        uint8_t defaultBoot[SIZE_BOOT_ORDER] = {
            BOOT_MODE_UEFI,      bootMap["USB_DEV"], bootMap["NET_IPV6"],
            bootMap["SATA_HDD"], bootMap["SATA_CD"], 0xff};

        memcpy(res, defaultBoot, SIZE_BOOT_ORDER);
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Set default boot order");
        setBootOrder(defaultBoot);
    }
    else
    {
        nlohmann::json bootMode = oemData[KEY_BOOT_ORDER][KEY_BOOT_MODE];
        if (bootMode["UEFI"])
            mode |= BOOT_MODE_UEFI;
        if (bootMode["CMOS_CLR"])
            mode |= BOOT_MODE_CMOS_CLR;
        if (bootMode["BOOT_FLAG"])
            mode |= BOOT_MODE_BOOT_FLAG;

        res[0] = mode;

        for (i = 1; i < SIZE_BOOT_ORDER; i++)
        {
            std::string seqStr = oemData[KEY_BOOT_ORDER][KEY_BOOT_SEQ][i - 1];
            if (bootMap.find(seqStr) != bootMap.end())
                res[i] = bootMap[seqStr];
            else
                res[i] = 0xff;
        }
    }

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
    machineConfigInfo_t *req = reinterpret_cast<machineConfigInfo_t *>(request);
    uint8_t len = *data_len;

    *data_len = 0;

    if (len < sizeof(machineConfigInfo_t))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid machine configuration length received");
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    if (req->chassis_type >= sizeof(chassisType) / sizeof(uint8_t *))
        oemData[KEY_MC_CONFIG][KEY_MC_CHAS_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_CHAS_TYPE] =
            chassisType[req->chassis_type];

    if (req->mb_type >= sizeof(mbType) / sizeof(uint8_t *))
        oemData[KEY_MC_CONFIG][KEY_MC_MB_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_MB_TYPE] = mbType[req->mb_type];

    oemData[KEY_MC_CONFIG][KEY_MC_PROC_CNT] = req->proc_cnt;
    oemData[KEY_MC_CONFIG][KEY_MC_MEM_CNT] = req->mem_cnt;
    oemData[KEY_MC_CONFIG][KEY_MC_HDD35_CNT] = req->hdd35_cnt;
    oemData[KEY_MC_CONFIG][KEY_MC_HDD25_CNT] = req->hdd25_cnt;

    if (req->riser_type >= sizeof(riserType) / sizeof(uint8_t *))
        oemData[KEY_MC_CONFIG][KEY_MC_RSR_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_RSR_TYPE] = riserType[req->riser_type];

    oemData[KEY_MC_CONFIG][KEY_MC_PCIE_LOC] = {};
    int i = 0;
    if (req->pcie_card_loc & BIT_0)
        oemData[KEY_MC_CONFIG][KEY_MC_PCIE_LOC][i++] = "SLOT1";
    if (req->pcie_card_loc & BIT_1)
        oemData[KEY_MC_CONFIG][KEY_MC_PCIE_LOC][i++] = "SLOT2";
    if (req->pcie_card_loc & BIT_2)
        oemData[KEY_MC_CONFIG][KEY_MC_PCIE_LOC][i++] = "SLOT3";
    if (req->pcie_card_loc & BIT_3)
        oemData[KEY_MC_CONFIG][KEY_MC_PCIE_LOC][i++] = "SLOT4";

    if (req->slot1_pcie_type >= sizeof(pcieType) / sizeof(uint8_t *))
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT1_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT1_TYPE] =
            pcieType[req->slot1_pcie_type];

    if (req->slot2_pcie_type >= sizeof(pcieType) / sizeof(uint8_t *))
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT2_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT2_TYPE] =
            pcieType[req->slot2_pcie_type];

    if (req->slot3_pcie_type >= sizeof(pcieType) / sizeof(uint8_t *))
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT3_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT3_TYPE] =
            pcieType[req->slot3_pcie_type];

    if (req->slot4_pcie_type >= sizeof(pcieType) / sizeof(uint8_t *))
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT4_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT4_TYPE] =
            pcieType[req->slot4_pcie_type];

    oemData[KEY_MC_CONFIG][KEY_MC_AEP_CNT] = req->aep_mem_cnt;

    flushOemData();

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set POST start (CMD_OEM_SET_POST_START)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetPostStart(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    phosphor::logging::log<phosphor::logging::level::INFO>("POST Start Event");

    /* Do nothing, return success */
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
    struct timespec ts;

    phosphor::logging::log<phosphor::logging::level::INFO>("POST End Event");

    *data_len = 0;

    // Timestamp post end time.
    clock_gettime(CLOCK_REALTIME, &ts);
    oemData[KEY_TS_SLED] = ts.tv_sec;
    flushOemData();

    // Sync time with system
    // TODO: Add code for syncing time

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set PPIN Info (CMD_OEM_SET_PPIN_INFO)
//----------------------------------------------------------------------
// Inform BMC about PPIN data of 8 bytes for each CPU
//
// Request:
// Byte 1:8 – CPU0 PPIN data
// Optional:
// Byte 9:16 – CPU1 PPIN data
//
// Response:
// Byte 1 – Completion Code
ipmi_ret_t ipmiOemSetPPINInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    std::string ppinStr;
    int len;

    if (*data_len > SIZE_CPU_PPIN * 2)
        len = SIZE_CPU_PPIN * 2;
    else
        len = *data_len;
    *data_len = 0;

    ppinStr = bytesToStr(req, len);
    oemData[KEY_PPIN_INFO] = ppinStr.c_str();
    flushOemData();

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set ADR Trigger (CMD_OEM_SET_ADR_TRIGGER)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetAdrTrigger(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    /* Do nothing, return success */
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
    /* Do nothing, return success */
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
    uint8_t pprCnt, pprAct, pprIndex;
    uint8_t selParam = req[0];
    uint8_t len = *data_len;
    std::stringstream ss;
    std::string str;

    *data_len = 0;

    switch (selParam)
    {
        case PPR_ACTION:
            if (oemData[KEY_PPR].find(KEY_PPR_ROW_COUNT) ==
                oemData[KEY_PPR].end())
                return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

            pprCnt = oemData[KEY_PPR][KEY_PPR_ROW_COUNT];
            if (pprCnt == 0)
                return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

            pprAct = req[1];
            /* Check if ppr is enabled or disabled */
            if (!(pprAct & 0x80))
                pprAct = 0;

            oemData[KEY_PPR][KEY_PPR_ACTION] = pprAct;
            break;
        case PPR_ROW_COUNT:
            if (req[1] > 100)
                return IPMI_CC_PARM_OUT_OF_RANGE;

            oemData[KEY_PPR][KEY_PPR_ROW_COUNT] = req[1];
            break;
        case PPR_ROW_ADDR:
            pprIndex = req[1];
            if (pprIndex > 100)
                return IPMI_CC_PARM_OUT_OF_RANGE;

            if (len < PPR_ROW_ADDR_LEN + 1)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Invalid PPR Row Address length received");
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            ss << std::hex;
            ss << std::setw(2) << std::setfill('0') << (int)pprIndex;

            oemData[KEY_PPR][ss.str()][KEY_PPR_INDEX] = pprIndex;

            str = bytesToStr(&req[1], PPR_ROW_ADDR_LEN);
            oemData[KEY_PPR][ss.str()][KEY_PPR_ROW_ADDR] = str.c_str();
            break;
        case PPR_HISTORY_DATA:
            pprIndex = req[1];
            if (pprIndex > 100)
                return IPMI_CC_PARM_OUT_OF_RANGE;

            if (len < PPR_HST_DATA_LEN + 1)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Invalid PPR history data length received");
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            ss << std::hex;
            ss << std::setw(2) << std::setfill('0') << (int)pprIndex;

            oemData[KEY_PPR][ss.str()][KEY_PPR_INDEX] = pprIndex;

            str = bytesToStr(&req[1], PPR_HST_DATA_LEN);
            oemData[KEY_PPR][ss.str()][KEY_PPR_HST_DATA] = str.c_str();
            break;
        default:
            return IPMI_CC_PARM_OUT_OF_RANGE;
            break;
    }

    flushOemData();

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
    uint8_t pprCnt, pprIndex;
    uint8_t selParam = req[0];
    std::stringstream ss;
    std::string str;

    /* Any failure will return zero length data */
    *data_len = 0;

    switch (selParam)
    {
        case PPR_ACTION:
            res[0] = 0;
            *data_len = 1;

            if (oemData[KEY_PPR].find(KEY_PPR_ROW_COUNT) !=
                oemData[KEY_PPR].end())
            {
                pprCnt = oemData[KEY_PPR][KEY_PPR_ROW_COUNT];
                if (pprCnt != 0)
                {
                    if (oemData[KEY_PPR].find(KEY_PPR_ACTION) !=
                        oemData[KEY_PPR].end())
                    {
                        res[0] = oemData[KEY_PPR][KEY_PPR_ACTION];
                    }
                }
            }
            break;
        case PPR_ROW_COUNT:
            res[0] = 0;
            *data_len = 1;
            if (oemData[KEY_PPR].find(KEY_PPR_ROW_COUNT) !=
                oemData[KEY_PPR].end())
                res[0] = oemData[KEY_PPR][KEY_PPR_ROW_COUNT];
            break;
        case PPR_ROW_ADDR:
            pprIndex = req[1];
            if (pprIndex > 100)
                return IPMI_CC_PARM_OUT_OF_RANGE;

            ss << std::hex;
            ss << std::setw(2) << std::setfill('0') << (int)pprIndex;

            if (oemData[KEY_PPR].find(ss.str()) == oemData[KEY_PPR].end())
                return IPMI_CC_PARM_OUT_OF_RANGE;

            if (oemData[KEY_PPR][ss.str()].find(KEY_PPR_ROW_ADDR) ==
                oemData[KEY_PPR][ss.str()].end())
                return IPMI_CC_PARM_OUT_OF_RANGE;

            str = oemData[KEY_PPR][ss.str()][KEY_PPR_ROW_ADDR];
            *data_len = strToBytes(str, res);
            break;
        case PPR_HISTORY_DATA:
            pprIndex = req[1];
            if (pprIndex > 100)
                return IPMI_CC_PARM_OUT_OF_RANGE;

            ss << std::hex;
            ss << std::setw(2) << std::setfill('0') << (int)pprIndex;

            if (oemData[KEY_PPR].find(ss.str()) == oemData[KEY_PPR].end())
                return IPMI_CC_PARM_OUT_OF_RANGE;

            if (oemData[KEY_PPR][ss.str()].find(KEY_PPR_HST_DATA) ==
                oemData[KEY_PPR][ss.str()].end())
                return IPMI_CC_PARM_OUT_OF_RANGE;

            str = oemData[KEY_PPR][ss.str()][KEY_PPR_HST_DATA];
            *data_len = strToBytes(str, res);
            break;
        default:
            return IPMI_CC_PARM_OUT_OF_RANGE;
            break;
    }

    return IPMI_CC_OK;
}

/* FB OEM QC Commands */

//----------------------------------------------------------------------
// Set Proc Info (CMD_OEM_Q_SET_PROC_INFO)
//----------------------------------------------------------------------
//"Request:
// Byte 1:3 – Manufacturer ID – XXYYZZ h, LSB first
// Byte 4 – Processor Index, 0 base
// Byte 5 – Parameter Selector
// Byte 6..N – Configuration parameter data (see below for Parameters
// of Processor Information)
// Response:
// Byte 1 – Completion code
//
// Parameter#1: (Processor Product Name)
//
// Byte 1..48 –Product name(ASCII code)
// Ex. Intel(R) Xeon(R) CPU E5-2685 v3 @ 2.60GHz
//
// Param#2: Processor Basic Information
// Byte 1 – Core Number
// Byte 2 – Thread Number (LSB)
// Byte 3 – Thread Number (MSB)
// Byte 4 – Processor frequency in MHz (LSB)
// Byte 5 – Processor frequency in MHz (MSB)
// Byte 6..7 – Revision
//
ipmi_ret_t ipmiOemQSetProcInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    qProcInfo_t *req = reinterpret_cast<qProcInfo_t *>(request);
    uint8_t numParam = sizeof(cpuInfoKey) / sizeof(uint8_t *);
    std::stringstream ss;
    std::string str;
    uint8_t len = *data_len;

    *data_len = 0;

    /* check for requested data params */
    if (len < 5 || req->paramSel < 1 || req->paramSel >= numParam)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    len = len - 5; // Get Actual data length

    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)req->procIndex;
    oemData[KEY_Q_PROC_INFO][ss.str()][KEY_PROC_INDEX] = req->procIndex;

    str = bytesToStr(req->data, len);
    oemData[KEY_Q_PROC_INFO][ss.str()][cpuInfoKey[req->paramSel]] = str.c_str();
    flushOemData();

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Proc Info (CMD_OEM_Q_GET_PROC_INFO)
//----------------------------------------------------------------------
// Request:
// Byte 1:3 –  Manufacturer ID – XXYYZZ h, LSB first
// Byte 4 – Processor Index, 0 base
// Byte 5 – Parameter Selector
// Response:
// Byte 1 – Completion code
// Byte 2..N – Configuration Parameter Data (see below for Parameters
// of Processor Information)
//
// Parameter#1: (Processor Product Name)
//
// Byte 1..48 –Product name(ASCII code)
// Ex. Intel(R) Xeon(R) CPU E5-2685 v3 @ 2.60GHz
//
// Param#2: Processor Basic Information
// Byte 1 – Core Number
// Byte 2 – Thread Number (LSB)
// Byte 3 – Thread Number (MSB)
// Byte 4 – Processor frequency in MHz (LSB)
// Byte 5 – Processor frequency in MHz (MSB)
// Byte 6..7 – Revision
//
ipmi_ret_t ipmiOemQGetProcInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    qProcInfo_t *req = reinterpret_cast<qProcInfo_t *>(request);
    uint8_t numParam = sizeof(cpuInfoKey) / sizeof(uint8_t *);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    std::stringstream ss;
    std::string str;

    *data_len = 0;

    /* check for requested data params */
    if (req->paramSel < 1 || req->paramSel >= numParam)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)req->procIndex;

    if (oemData[KEY_Q_PROC_INFO].find(ss.str()) ==
        oemData[KEY_Q_PROC_INFO].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    if (oemData[KEY_Q_PROC_INFO][ss.str()].find(cpuInfoKey[req->paramSel]) ==
        oemData[KEY_Q_PROC_INFO][ss.str()].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    str = oemData[KEY_Q_PROC_INFO][ss.str()][cpuInfoKey[req->paramSel]];
    *data_len = strToBytes(str, res);

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set Dimm Info (CMD_OEM_Q_SET_DIMM_INFO)
//----------------------------------------------------------------------
// Request:
// Byte 1:3 – Manufacturer ID – XXYYZZh, LSB first
// Byte 4 – DIMM Index, 0 base
// Byte 5 – Parameter Selector
// Byte 6..N – Configuration parameter data (see below for Parameters
// of DIMM Information)
// Response:
// Byte 1 – Completion code
//
// Param#1 (DIMM Location):
// Byte 1 – DIMM Present
// Byte 1 – DIMM Present
// 01h – Present
// FFh – Not Present
// Byte 2 – Node Number, 0 base
// Byte 3 – Channel Number , 0 base
// Byte 4 – DIMM Number , 0 base
//
// Param#2 (DIMM Type):
// Byte 1 – DIMM Type
// Bit [7:6]
// For DDR3
//  00 – Normal Voltage (1.5V)
//  01 – Ultra Low Voltage (1.25V)
//  10 – Low Voltage (1.35V)
//  11 – Reserved
// For DDR4
//  00 – Reserved
//  01 – Reserved
//  10 – Reserved
//  11 – Normal Voltage (1.2V)
// Bit [5:0]
//  0x00 – SDRAM
//  0x01 – DDR-1 RAM
//  0x02 – Rambus
//  0x03 – DDR-2 RAM
//  0x04 – FBDIMM
//  0x05 – DDR-3 RAM
//  0x06 – DDR-4 RAM
//
// Param#3 (DIMM Speed):
// Byte 1..2 – DIMM speed in MHz, LSB
// Byte 3..6 – DIMM size in Mbytes, LSB
//
// Param#4 (Module Part Number):
// Byte 1..20 –Module Part Number (JEDEC Standard No. 21-C)
//
// Param#5 (Module Serial Number):
// Byte 1..4 –Module Serial Number (JEDEC Standard No. 21-C)
//
// Param#6 (Module Manufacturer ID):
// Byte 1 - Module Manufacturer ID, LSB
// Byte 2 - Module Manufacturer ID, MSB
//
ipmi_ret_t ipmiOemQSetDimmInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    qDimmInfo_t *req = reinterpret_cast<qDimmInfo_t *>(request);
    uint8_t numParam = sizeof(dimmInfoKey) / sizeof(uint8_t *);
    std::stringstream ss;
    std::string str;
    uint8_t len = *data_len;

    *data_len = 0;

    /* check for requested data params */
    if (len < 5 || req->paramSel < 1 || req->paramSel >= numParam)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    len = len - 5; // Get Actual data length

    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)req->dimmIndex;
    oemData[KEY_Q_DIMM_INFO][ss.str()][KEY_DIMM_INDEX] = req->dimmIndex;

    str = bytesToStr(req->data, len);
    oemData[KEY_Q_DIMM_INFO][ss.str()][dimmInfoKey[req->paramSel]] =
        str.c_str();
    flushOemData();

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Dimm Info (CMD_OEM_Q_GET_DIMM_INFO)
//----------------------------------------------------------------------
// Request:
// Byte 1:3 – Manufacturer ID – XXYYZZh, LSB first
// Byte 4 – DIMM Index, 0 base
// Byte 5 – Parameter Selector
// Byte 6..N – Configuration parameter data (see below for Parameters
// of DIMM Information)
// Response:
// Byte 1 – Completion code
// Byte 2..N – Configuration Parameter Data (see Table_1213h Parameters
// of DIMM Information)
//
// Param#1 (DIMM Location):
// Byte 1 – DIMM Present
// Byte 1 – DIMM Present
// 01h – Present
// FFh – Not Present
// Byte 2 – Node Number, 0 base
// Byte 3 – Channel Number , 0 base
// Byte 4 – DIMM Number , 0 base
//
// Param#2 (DIMM Type):
// Byte 1 – DIMM Type
// Bit [7:6]
// For DDR3
//  00 – Normal Voltage (1.5V)
//  01 – Ultra Low Voltage (1.25V)
//  10 – Low Voltage (1.35V)
//  11 – Reserved
// For DDR4
//  00 – Reserved
//  01 – Reserved
//  10 – Reserved
//  11 – Normal Voltage (1.2V)
// Bit [5:0]
//  0x00 – SDRAM
//  0x01 – DDR-1 RAM
//  0x02 – Rambus
//  0x03 – DDR-2 RAM
//  0x04 – FBDIMM
//  0x05 – DDR-3 RAM
//  0x06 – DDR-4 RAM
//
// Param#3 (DIMM Speed):
// Byte 1..2 – DIMM speed in MHz, LSB
// Byte 3..6 – DIMM size in Mbytes, LSB
//
// Param#4 (Module Part Number):
// Byte 1..20 –Module Part Number (JEDEC Standard No. 21-C)
//
// Param#5 (Module Serial Number):
// Byte 1..4 –Module Serial Number (JEDEC Standard No. 21-C)
//
// Param#6 (Module Manufacturer ID):
// Byte 1 - Module Manufacturer ID, LSB
// Byte 2 - Module Manufacturer ID, MSB
//
ipmi_ret_t ipmiOemQGetDimmInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    qDimmInfo_t *req = reinterpret_cast<qDimmInfo_t *>(request);
    uint8_t numParam = sizeof(dimmInfoKey) / sizeof(uint8_t *);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    std::stringstream ss;
    std::string str;

    *data_len = 0;

    /* check for requested data params */
    if (req->paramSel < 1 || req->paramSel >= numParam)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)req->dimmIndex;

    if (oemData[KEY_Q_DIMM_INFO].find(ss.str()) ==
        oemData[KEY_Q_DIMM_INFO].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    if (oemData[KEY_Q_DIMM_INFO][ss.str()].find(dimmInfoKey[req->paramSel]) ==
        oemData[KEY_Q_DIMM_INFO][ss.str()].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    str = oemData[KEY_Q_DIMM_INFO][ss.str()][dimmInfoKey[req->paramSel]];
    *data_len = strToBytes(str, res);

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Set Drive Info (CMD_OEM_Q_SET_DRIVE_INFO)
//----------------------------------------------------------------------
// BIOS issue this command to provide HDD information to BMC.
//
// BIOS just can get information by standard ATA / SMART command for
// OB SATA controller.
// BIOS can get
// 1.     Serial Number
// 2.     Model Name
// 3.     HDD FW Version
// 4.     HDD Capacity
// 5.     HDD WWN
//
//  Use Get HDD info Param #5 to know the MAX HDD info index.
//
//  Request:
//  Byte 1:3 – Quanta Manufacturer ID – 001C4Ch, LSB first
//  Byte 4 –
//  [7:4] Reserved
//  [3:0] HDD Controller Type
//     0x00 – BIOS
//     0x01 – Expander
//     0x02 – LSI
//  Byte 5 – HDD Info Index, 0 base
//  Byte 6 – Parameter Selector
//  Byte 7..N – Configuration parameter data (see Table_1415h Parameters of HDD
//  Information)
//
//  Response:
//  Byte 1 – Completion Code
//
//  Param#0 (HDD Location):
//  Byte 1 – Controller
//    [7:3] Device Number
//    [2:0] Function Number
//  For Intel C610 series (Wellsburg)
//    D31:F2 (0xFA) – SATA control 1
//    D31:F5 (0xFD) – SATA control 2
//    D17:F4 (0x8C) – sSata control
//  Byte 2 – Port Number
//  Byte 3 – Location (0xFF: No HDD Present)
//  BIOS default set Byte 3 to 0xFF, if No HDD Present. And then skip send param
//  #1~4, #6,  #7 to BMC (still send param #5) BIOS default set Byte 3 to 0, if
//  the HDD present. BMC or other people who know the HDD location has
//  responsibility for update Location info
//
//  Param#1 (Serial Number):
//  Bytes 1..33: HDD Serial Number
//
//  Param#2 (Model Name):
//  Byte 1..33 – HDD Model Name
//
//  Param#3 (HDD FW Version):
//  Byte 1..17 –HDD FW version
//
//  Param#4 (Capacity):
//  Byte 1..4 –HDD Block Size, LSB
//  Byte 5..12 - HDD Block Number, LSB
//  HDD Capacity = HDD Block size * HDD BLock number  (Unit Byte)
//
//  Param#5 (Max HDD Quantity):
//  Byte 1 - Max HDD Quantity
//  Max supported port numbers in this PCH
//
//  Param#6 (HDD Type)
//  Byte 1 – HDD Type
//  0h – Reserved
//  1h – SAS
//  2h – SATA
//  3h – PCIE SSD (NVME)
//
//  Param#7 (HDD WWN)
//  Data 1...8: HDD World Wide Name, LSB
//
ipmi_ret_t ipmiOemQSetDriveInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    qDriveInfo_t *req = reinterpret_cast<qDriveInfo_t *>(request);
    uint8_t numParam = sizeof(driveInfoKey) / sizeof(uint8_t *);
    uint8_t ctrlType = req->hddCtrlType & 0x0f;
    std::stringstream ss;
    std::string str;
    uint8_t len = *data_len;

    *data_len = 0;

    /* check for requested data params */
    if (len < 6 || req->paramSel < 1 || req->paramSel >= numParam ||
        ctrlType > 2)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    len = len - 6; // Get Actual data length

    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)req->hddIndex;
    oemData[KEY_Q_DRIVE_INFO][KEY_HDD_CTRL_TYPE] = req->hddCtrlType;
    oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]][ss.str()][KEY_HDD_INDEX] =
        req->hddIndex;

    str = bytesToStr(req->data, len);
    oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]][ss.str()]
           [driveInfoKey[req->paramSel]] = str.c_str();
    flushOemData();

    return IPMI_CC_OK;
}

//----------------------------------------------------------------------
// Get Drive Info (CMD_OEM_Q_GET_DRIVE_INFO)
//----------------------------------------------------------------------
// BMC needs to check HDD presented or not first. If NOT presented, return
// completion code 0xD5.
//
// Request:
// Byte 1:3 – Quanta Manufacturer ID – 001C4Ch, LSB first
// Byte 4 –
//[7:4] Reserved
//[3:0] HDD Controller Type
//   0x00 – BIOS
//   0x01 – Expander
//   0x02 – LSI
// Byte 5 – HDD Index, 0 base
// Byte 6 – Parameter Selector (See Above Set HDD Information)
// Response:
// Byte 1 – Completion Code
//   0xD5 – Not support in current status (HDD Not Present)
// Byte 2..N – Configuration parameter data (see Table_1415h Parameters of HDD
// Information)
//
ipmi_ret_t ipmiOemQGetDriveInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    qDriveInfo_t *req = reinterpret_cast<qDriveInfo_t *>(request);
    uint8_t numParam = sizeof(driveInfoKey) / sizeof(uint8_t *);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    uint8_t ctrlType = req->hddCtrlType & 0x0f;
    std::stringstream ss;
    std::string str;

    *data_len = 0;

    /* check for requested data params */
    if (req->paramSel < 1 || req->paramSel >= numParam || ctrlType > 2)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    if (oemData[KEY_Q_DRIVE_INFO].find(ctrlTypeKey[ctrlType]) ==
        oemData[KEY_Q_DRIVE_INFO].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)req->hddIndex;

    if (oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]].find(ss.str()) ==
        oemData[KEY_Q_DRIVE_INFO].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    if (oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]][ss.str()].find(
            dimmInfoKey[req->paramSel]) ==
        oemData[KEY_Q_DRIVE_INFO][ss.str()].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    str = oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]][ss.str()]
                 [dimmInfoKey[req->paramSel]];
    *data_len = strToBytes(str, res);

    return IPMI_CC_OK;
}

static void registerOEMFunctions(void)
{
    /* Get OEM data from json file */
    std::ifstream file(JSON_OEM_DATA_FILE);
    if (file)
    {
        file >> oemData;
        file.close();
    }

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
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_GET_BOARD_ID, NULL,
                         ipmiOemGetBoardID,
                         PRIVILEGE_USER); // Get Board ID
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_BOOT_ORDER, NULL,
                         ipmiOemSetBootOrder,
                         PRIVILEGE_USER); // Set Boot Order
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
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_PPIN_INFO, NULL,
                         ipmiOemSetPPINInfo,
                         PRIVILEGE_USER); // Set PPIN Info
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_ADR_TRIGGER, NULL,
                         ipmiOemSetAdrTrigger,
                         PRIVILEGE_USER); // Set ADR Trigger
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_BIOS_FLASH_INFO, NULL,
                         ipmiOemSetBiosFlashInfo,
                         PRIVILEGE_USER); // Set Bios Flash Info
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_SET_PPR, NULL, ipmiOemSetPpr,
                         PRIVILEGE_USER); // Set PPR
    ipmiPrintAndRegister(NETFUN_NONE, CMD_OEM_GET_PPR, NULL, ipmiOemGetPpr,
                         PRIVILEGE_USER); // Get PPR
    /* FB OEM QC Commands */
    ipmiPrintAndRegister(NETFUN_FB_OEM_QC, CMD_OEM_Q_SET_PROC_INFO, NULL,
                         ipmiOemQSetProcInfo,
                         PRIVILEGE_USER); // Set Proc Info
    ipmiPrintAndRegister(NETFUN_FB_OEM_QC, CMD_OEM_Q_GET_PROC_INFO, NULL,
                         ipmiOemQGetProcInfo,
                         PRIVILEGE_USER); // Get Proc Info
    ipmiPrintAndRegister(NETFUN_FB_OEM_QC, CMD_OEM_Q_SET_DIMM_INFO, NULL,
                         ipmiOemQSetDimmInfo,
                         PRIVILEGE_USER); // Set Dimm Info
    ipmiPrintAndRegister(NETFUN_FB_OEM_QC, CMD_OEM_Q_GET_DIMM_INFO, NULL,
                         ipmiOemQGetDimmInfo,
                         PRIVILEGE_USER); // Get Dimm Info
    ipmiPrintAndRegister(NETFUN_FB_OEM_QC, CMD_OEM_Q_SET_DRIVE_INFO, NULL,
                         ipmiOemQSetDriveInfo,
                         PRIVILEGE_USER); // Set Drive Info
    ipmiPrintAndRegister(NETFUN_FB_OEM_QC, CMD_OEM_Q_GET_DRIVE_INFO, NULL,
                         ipmiOemQGetDriveInfo,
                         PRIVILEGE_USER); // Get Drive Info
    return;
}

} // namespace ipmi
