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

#include <boost/crc.hpp>
#include <commandutils.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <oemcommands.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Control/Boot/Mode/server.hpp>
#include <xyz/openbmc_project/Control/Boot/Source/server.hpp>
#include <xyz/openbmc_project/Control/Boot/Type/server.hpp>

#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#define SIZE_IANA_ID 3

namespace ipmi
{

using namespace phosphor::logging;

void getSelectorPosition(size_t& position);
static void registerOEMFunctions() __attribute__((constructor));
sdbusplus::bus_t dbus(ipmid_get_sd_bus_connection()); // from ipmid/api.h
static constexpr size_t maxFRUStringLength = 0x3F;
constexpr uint8_t cmdSetSystemGuid = 0xEF;

constexpr uint8_t cmdSetQDimmInfo = 0x12;
constexpr uint8_t cmdGetQDimmInfo = 0x13;

constexpr ipmi_ret_t ccInvalidParam = 0x80;

int plat_udbg_get_post_desc(uint8_t, uint8_t*, uint8_t, uint8_t*, uint8_t*,
                            uint8_t*);
int plat_udbg_get_gpio_desc(uint8_t, uint8_t*, uint8_t*, uint8_t*, uint8_t*,
                            uint8_t*);
int plat_udbg_get_frame_data(uint8_t, uint8_t, uint8_t*, uint8_t*, uint8_t*);
ipmi_ret_t plat_udbg_control_panel(uint8_t, uint8_t, uint8_t, uint8_t*,
                                   uint8_t*);
int sendMeCmd(uint8_t, uint8_t, std::vector<uint8_t>&, std::vector<uint8_t>&);

int sendBicCmd(uint8_t, uint8_t, uint8_t, std::vector<uint8_t>&,
               std::vector<uint8_t>&);

nlohmann::json oemData __attribute__((init_priority(101)));

constexpr const char* certPath = "/mnt/data/host/bios-rootcert";

static constexpr size_t GUID_SIZE = 16;
// TODO Make offset and location runtime configurable to ensure we
// can make each define their own locations.
static constexpr off_t OFFSET_SYS_GUID = 0x17F0;
static constexpr const char* FRU_EEPROM = "/sys/bus/i2c/devices/6-0054/eeprom";
void flushOemData();

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
constexpr auto IPV4_PROTOCOL = "xyz.openbmc_project.Network.IP.Protocol.IPv4";
constexpr auto IPV6_PROTOCOL = "xyz.openbmc_project.Network.IP.Protocol.IPv6";

bool isLinkLocalIP(const std::string& address)
{
    return address.find(IPV4_PREFIX) == 0 || address.find(IPV6_PREFIX) == 0;
}

DbusObjectInfo getIPObject(sdbusplus::bus_t& bus, const std::string& interface,
                           const std::string& serviceRoot,
                           const std::string& protocol,
                           const std::string& ethdev)
{
    auto objectTree = getAllDbusObjects(bus, serviceRoot, interface, ethdev);

    if (objectTree.empty())
    {
        log<level::ERR>("No Object has implemented the IP interface",
                        entry("INTERFACE=%s", interface.c_str()));
    }

    DbusObjectInfo objectInfo;

    for (auto& object : objectTree)
    {
        auto variant =
            ipmi::getDbusProperty(bus, object.second.begin()->first,
                                  object.first, IP_INTERFACE, "Type");
        if (std::get<std::string>(variant) != protocol)
        {
            continue;
        }

        variant = ipmi::getDbusProperty(bus, object.second.begin()->first,
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

namespace boot
{
using BootSource =
    sdbusplus::xyz::openbmc_project::Control::Boot::server::Source::Sources;
using BootMode =
    sdbusplus::xyz::openbmc_project::Control::Boot::server::Mode::Modes;
using BootType =
    sdbusplus::xyz::openbmc_project::Control::Boot::server::Type::Types;

using IpmiValue = uint8_t;

std::map<IpmiValue, BootSource> sourceIpmiToDbus = {
    {0x0f, BootSource::Default},       {0x00, BootSource::RemovableMedia},
    {0x01, BootSource::Network},       {0x02, BootSource::Disk},
    {0x03, BootSource::ExternalMedia}, {0x04, BootSource::RemovableMedia},
    {0x09, BootSource::Network}};

std::map<IpmiValue, BootMode> modeIpmiToDbus = {{0x04, BootMode::Setup},
                                                {0x00, BootMode::Regular}};

std::map<IpmiValue, BootType> typeIpmiToDbus = {{0x00, BootType::Legacy},
                                                {0x01, BootType::EFI}};

std::map<std::optional<BootSource>, IpmiValue> sourceDbusToIpmi = {
    {BootSource::Default, 0x0f},
    {BootSource::RemovableMedia, 0x00},
    {BootSource::Network, 0x01},
    {BootSource::Disk, 0x02},
    {BootSource::ExternalMedia, 0x03}};

std::map<std::optional<BootMode>, IpmiValue> modeDbusToIpmi = {
    {BootMode::Setup, 0x04}, {BootMode::Regular, 0x00}};

std::map<std::optional<BootType>, IpmiValue> typeDbusToIpmi = {
    {BootType::Legacy, 0x00}, {BootType::EFI, 0x01}};

static constexpr auto bootEnableIntf = "xyz.openbmc_project.Object.Enable";
static constexpr auto bootModeIntf = "xyz.openbmc_project.Control.Boot.Mode";
static constexpr auto bootSourceIntf =
    "xyz.openbmc_project.Control.Boot.Source";
static constexpr auto bootTypeIntf = "xyz.openbmc_project.Control.Boot.Type";
static constexpr auto bootSourceProp = "BootSource";
static constexpr auto bootModeProp = "BootMode";
static constexpr auto bootTypeProp = "BootType";
static constexpr auto bootEnableProp = "Enabled";

std::tuple<std::string, std::string> objPath(size_t id)
{
    std::string hostName = "host" + std::to_string(id);
    std::string bootObjPath =
        "/xyz/openbmc_project/control/" + hostName + "/boot";
    return std::make_tuple(std::move(bootObjPath), std::move(hostName));
}

/* Helper functions to set boot order */
void setBootOrder(std::string bootObjPath, const std::vector<uint8_t>& bootSeq,
                  std::string bootOrderKey)
{
    if (bootSeq.size() != SIZE_BOOT_ORDER)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Boot order length received");
        return;
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    uint8_t mode = bootSeq.front();

    // SETTING BOOT MODE PROPERTY
    uint8_t bootModeBit = mode & 0x04;
    auto bootValue = ipmi::boot::modeIpmiToDbus.at(bootModeBit);

    std::string bootOption =
        sdbusplus::message::convert_to_string<boot::BootMode>(bootValue);

    std::string service =
        getService(*dbus, ipmi::boot::bootModeIntf, bootObjPath);
    setDbusProperty(*dbus, service, bootObjPath, ipmi::boot::bootModeIntf,
                    ipmi::boot::bootModeProp, bootOption);

    // SETTING BOOT SOURCE PROPERTY
    auto bootOrder = ipmi::boot::sourceIpmiToDbus.at(bootSeq.at(1));
    std::string bootSource =
        sdbusplus::message::convert_to_string<boot::BootSource>(bootOrder);

    service = getService(*dbus, ipmi::boot::bootSourceIntf, bootObjPath);
    setDbusProperty(*dbus, service, bootObjPath, ipmi::boot::bootSourceIntf,
                    ipmi::boot::bootSourceProp, bootSource);

    // SETTING BOOT TYPE PROPERTY
    uint8_t bootTypeBit = mode & 0x01;
    auto bootTypeVal = ipmi::boot::typeIpmiToDbus.at(bootTypeBit);

    std::string bootType =
        sdbusplus::message::convert_to_string<boot::BootType>(bootTypeVal);

    service = getService(*dbus, ipmi::boot::bootTypeIntf, bootObjPath);

    setDbusProperty(*dbus, service, bootObjPath, ipmi::boot::bootTypeIntf,
                    ipmi::boot::bootTypeProp, bootType);

    // Set the valid bit to boot enabled property
    service = getService(*dbus, ipmi::boot::bootEnableIntf, bootObjPath);

    setDbusProperty(*dbus, service, bootObjPath, ipmi::boot::bootEnableIntf,
                    ipmi::boot::bootEnableProp,
                    (mode & BOOT_MODE_BOOT_FLAG) ? true : false);

    nlohmann::json bootMode;

    bootMode["UEFI"] = (mode & BOOT_MODE_UEFI) ? true : false;
    bootMode["CMOS_CLR"] = (mode & BOOT_MODE_CMOS_CLR) ? true : false;
    bootMode["FORCE_BOOT"] = (mode & BOOT_MODE_FORCE_BOOT) ? true : false;
    bootMode["BOOT_FLAG"] = (mode & BOOT_MODE_BOOT_FLAG) ? true : false;
    oemData[bootOrderKey][KEY_BOOT_MODE] = bootMode;

    /* Initialize boot sequence array */
    oemData[bootOrderKey][KEY_BOOT_SEQ] = {};
    for (size_t i = 1; i < SIZE_BOOT_ORDER; i++)
    {
        if (bootSeq.at(i) >= BOOT_SEQ_ARRAY_SIZE)
            oemData[bootOrderKey][KEY_BOOT_SEQ][i - 1] = "NA";
        else
            oemData[bootOrderKey][KEY_BOOT_SEQ][i - 1] =
                bootSeqDefine[bootSeq.at(i)];
    }

    flushOemData();
}

void getBootOrder(std::string bootObjPath, std::vector<uint8_t>& bootSeq,
                  std::string hostName)
{
    if (oemData.find(hostName) == oemData.end())
    {
        /* Return default boot order 0100090203ff */
        bootSeq.push_back(BOOT_MODE_UEFI);
        bootSeq.push_back(static_cast<uint8_t>(bootMap["USB_DEV"]));
        bootSeq.push_back(static_cast<uint8_t>(bootMap["NET_IPV6"]));
        bootSeq.push_back(static_cast<uint8_t>(bootMap["SATA_HDD"]));
        bootSeq.push_back(static_cast<uint8_t>(bootMap["SATA_CD"]));
        bootSeq.push_back(0xff);

        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Set default boot order");
        setBootOrder(bootObjPath, bootSeq, hostName);
        return;
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();

    // GETTING PROPERTY OF MODE INTERFACE

    std::string service =
        getService(*dbus, ipmi::boot::bootModeIntf, bootObjPath);
    Value variant =
        getDbusProperty(*dbus, service, bootObjPath, ipmi::boot::bootModeIntf,
                        ipmi::boot::bootModeProp);

    auto bootMode = sdbusplus::message::convert_from_string<boot::BootMode>(
        std::get<std::string>(variant));

    uint8_t bootOption = ipmi::boot::modeDbusToIpmi.at(bootMode);

    // GETTING PROPERTY OF TYPE INTERFACE

    service = getService(*dbus, ipmi::boot::bootTypeIntf, bootObjPath);
    variant =
        getDbusProperty(*dbus, service, bootObjPath, ipmi::boot::bootTypeIntf,
                        ipmi::boot::bootTypeProp);

    auto bootType = sdbusplus::message::convert_from_string<boot::BootType>(
        std::get<std::string>(variant));

    // Get the valid bit to boot enabled property
    service = getService(*dbus, ipmi::boot::bootEnableIntf, bootObjPath);
    variant =
        getDbusProperty(*dbus, service, bootObjPath, ipmi::boot::bootEnableIntf,
                        ipmi::boot::bootEnableProp);

    bool validFlag = std::get<bool>(variant);

    uint8_t bootTypeVal = ipmi::boot::typeDbusToIpmi.at(bootType);

    bootSeq.push_back(bootOption | bootTypeVal);

    if (validFlag)
    {
        bootSeq.front() |= BOOT_MODE_BOOT_FLAG;
    }

    nlohmann::json bootModeJson = oemData[hostName][KEY_BOOT_MODE];
    if (bootModeJson["CMOS_CLR"])
        bootSeq.front() |= BOOT_MODE_CMOS_CLR;

    for (int i = 1; i < SIZE_BOOT_ORDER; i++)
    {
        std::string seqStr = oemData[hostName][KEY_BOOT_SEQ][i - 1];
        if (bootMap.find(seqStr) != bootMap.end())
            bootSeq.push_back(bootMap[seqStr]);
        else
            bootSeq.push_back(0xff);
    }
}

} // namespace boot

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

std::string bytesToStr(uint8_t* byte, int len)
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

int strToBytes(std::string& str, uint8_t* data)
{
    std::string sstr;
    size_t i;

    for (i = 0; i < (str.length()) / 2; i++)
    {
        sstr = str.substr(i * 2, 2);
        data[i] = (uint8_t)std::strtol(sstr.c_str(), NULL, 16);
    }
    return i;
}

int readDimmType(std::string& data, uint8_t param)
{
    nlohmann::json dimmObj;
    /* Get dimm type names stored in json file */
    std::ifstream file(JSON_DIMM_TYPE_FILE);
    if (file)
    {
        file >> dimmObj;
        file.close();
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "DIMM type names file not found",
            phosphor::logging::entry("DIMM_TYPE_FILE=%s", JSON_DIMM_TYPE_FILE));
        return -1;
    }

    std::string dimmKey = "dimm_type" + std::to_string(param);
    auto obj = dimmObj[dimmKey]["short_name"];
    data = obj;
    return 0;
}

ipmi_ret_t getNetworkData(uint8_t lan_param, char* data)
{
    ipmi_ret_t rc = ipmi::ccSuccess;
    sdbusplus::bus_t bus(ipmid_get_sd_bus_connection());

    const std::string ethdevice = "eth0";

    switch (static_cast<LanParam>(lan_param))
    {
        case LanParam::IP:
        {
            std::string ipaddress;
            auto ipObjectInfo = ipmi::network::getIPObject(
                bus, ipmi::network::IP_INTERFACE, ipmi::network::ROOT,
                ipmi::network::IPV4_PROTOCOL, ethdevice);

            auto properties = ipmi::getAllDbusProperties(
                bus, ipObjectInfo.second, ipObjectInfo.first,
                ipmi::network::IP_INTERFACE);

            ipaddress = std::get<std::string>(properties["Address"]);

            std::strcpy(data, ipaddress.c_str());
        }
        break;

        case LanParam::IPV6:
        {
            std::string ipaddress;
            auto ipObjectInfo = ipmi::network::getIPObject(
                bus, ipmi::network::IP_INTERFACE, ipmi::network::ROOT,
                ipmi::network::IPV6_PROTOCOL, ethdevice);

            auto properties = ipmi::getAllDbusProperties(
                bus, ipObjectInfo.second, ipObjectInfo.first,
                ipmi::network::IP_INTERFACE);

            ipaddress = std::get<std::string>(properties["Address"]);

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

            macAddress = std::get<std::string>(variant);

            sscanf(macAddress.c_str(), ipmi::network::MAC_ADDRESS_FORMAT,
                   (data), (data + 1), (data + 2), (data + 3), (data + 4),
                   (data + 5));
            std::strcpy(data, macAddress.c_str());
        }
        break;

        default:
            rc = ipmi::ccParmOutOfRange;
    }
    return rc;
}

bool isMultiHostPlatform()
{
    bool platform;
    if (hostInstances == "0")
    {
        platform = false;
    }
    else
    {
        platform = true;
    }
    return platform;
}

// return "" equals failed
std::string getMotherBoardFruPath()
{
    std::vector<std::string> paths;
    static constexpr const auto depth = 0;
    sdbusplus::bus_t dbus(ipmid_get_sd_bus_connection());

    auto mapperCall = dbus.new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");
    static constexpr auto interface = {
        "xyz.openbmc_project.Inventory.Item.Board.Motherboard"};

    mapperCall.append("/xyz/openbmc_project/inventory/", depth, interface);
    try
    {
        auto reply = dbus.call(mapperCall);
        reply.read(paths);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return "";
    }

    for (const auto& path : paths)
    {
        return path;
    }

    return "";
}

// return "" equals failed
std::string getMotherBoardFruName()
{
    std::string path = getMotherBoardFruPath();
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service = "xyz.openbmc_project.EntityManager";

    try
    {
        auto value = ipmi::getDbusProperty(
            *dbus, service, path, "xyz.openbmc_project.Inventory.Item.Board",
            "Name");
        return std::get<std::string>(value);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return "";
    }
}

// return code: 0 successful
int8_t getFruData(std::string& data, std::string& name)
{
    size_t pos;
    static constexpr const auto depth = 0;
    std::vector<std::string> paths;
    std::string machinePath;
    std::string baseBoard = getMotherBoardFruPath();
    baseBoard = baseBoard.empty() ? "Baseboard" : baseBoard;

    bool platform = isMultiHostPlatform();
    if (platform == true)
    {
        getSelectorPosition(pos);
    }

    sd_bus* bus = NULL;
    int ret = sd_bus_default_system(&bus);
    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to connect to system bus",
            phosphor::logging::entry("ERRNO=0x%X", -ret));
        sd_bus_unref(bus);
        return -1;
    }
    sdbusplus::bus_t dbus(bus);
    auto mapperCall = dbus.new_method_call(
        "xyz.openbmc_project.ObjectMapper",
        "/xyz/openbmc_project/object_mapper",
        "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");
    static constexpr std::array<const char*, 1> interface = {
        "xyz.openbmc_project.Inventory.Decorator.Asset"};
    mapperCall.append("/xyz/openbmc_project/inventory/", depth, interface);

    try
    {
        auto reply = dbus.call(mapperCall);
        reply.read(paths);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -1;
    }

    for (const auto& path : paths)
    {
        if (platform == true)
        {
            if (pos == BMC_POS)
            {
                machinePath = baseBoard;
            }
            else
            {
                machinePath = "_" + std::to_string(pos);
            }
        }
        else
        {
            machinePath = baseBoard;
        }

        auto found = path.find(machinePath);
        if (found == std::string::npos)
        {
            continue;
        }

        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service = getService(
            *dbus, "xyz.openbmc_project.Inventory.Decorator.Asset", path);

        auto Value = ipmi::getDbusProperty(
            *dbus, service, path,
            "xyz.openbmc_project.Inventory.Decorator.Asset", name);

        data = std::get<std::string>(Value);
        return 0;
    }
    return -1;
}

int8_t sysConfig(std::vector<std::string>& data, size_t pos)
{
    nlohmann::json sysObj;
    std::string dimmInfo = KEY_Q_DIMM_INFO + std::to_string(pos);
    std::string result, typeName;
    uint8_t res[MAX_BUF];

    /* Get sysConfig data stored in json file */
    std::ifstream file(JSON_OEM_DATA_FILE);
    if (file)
    {
        file >> sysObj;
        file.close();
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "oemData file not found",
            phosphor::logging::entry("OEM_DATA_FILE=%s", JSON_OEM_DATA_FILE));
        return -1;
    }

    if (sysObj.find(dimmInfo) == sysObj.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "sysconfig key not available",
            phosphor::logging::entry("SYS_JSON_KEY=%s", dimmInfo.c_str()));
        return -1;
    }
    /* Get dimm type names stored in json file */
    nlohmann::json dimmObj;
    std::ifstream dimmFile(JSON_DIMM_TYPE_FILE);
    if (file)
    {
        dimmFile >> dimmObj;
        dimmFile.close();
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "DIMM type names file not found",
            phosphor::logging::entry("DIMM_TYPE_FILE=%s", JSON_DIMM_TYPE_FILE));
        return -1;
    }
    std::vector<std::string> a;
    for (auto& j : dimmObj.items())
    {
        std::string name = j.key();
        a.push_back(name);
    }

    uint8_t len = a.size();
    for (uint8_t ii = 0; ii < len; ii++)
    {
        std::string indKey = std::to_string(ii);
        std::string speedSize = sysObj[dimmInfo][indKey][DIMM_SPEED];
        strToBytes(speedSize, res);
        auto speed = (res[1] << 8 | res[0]);
        size_t dimmSize = ((res[3] << 8 | res[2]) / 1000);

        if (dimmSize == 0)
        {
            std::cerr << "Dimm information not available for slot_" +
                             std::to_string(ii)
                      << std::endl;
            continue;
        }
        std::string type = sysObj[dimmInfo][indKey][DIMM_TYPE];
        std::string dualInlineMem = sysObj[dimmInfo][indKey][KEY_DIMM_TYPE];
        strToBytes(type, res);
        size_t dimmType = res[0];
        if (dimmVenMap.find(dimmType) == dimmVenMap.end())
        {
            typeName = "unknown";
        }
        else
        {
            typeName = dimmVenMap[dimmType];
        }
        result = dualInlineMem + "/" + typeName + "/" + std::to_string(speed) +
                 "MHz" + "/" + std::to_string(dimmSize) + "GB";
        data.push_back(result);
    }
    return 0;
}

int8_t procInfo(std::string& result, size_t pos)
{
    std::vector<char> data;
    uint8_t res[MAX_BUF];
    std::string procIndex = "00";
    nlohmann::json proObj;
    std::string procInfo = KEY_Q_PROC_INFO + std::to_string(pos);
    /* Get processor data stored in json file */
    std::ifstream file(JSON_OEM_DATA_FILE);
    if (file)
    {
        file >> proObj;
        file.close();
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "oemData file not found",
            phosphor::logging::entry("OEM_DATA_FILE=%s", JSON_OEM_DATA_FILE));
        return -1;
    }
    if (proObj.find(procInfo) == proObj.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "processor info key not available",
            phosphor::logging::entry("PROC_JSON_KEY=%s", procInfo.c_str()));
        return -1;
    }
    std::string procName = proObj[procInfo][procIndex][KEY_PROC_NAME];
    std::string basicInfo = proObj[procInfo][procIndex][KEY_BASIC_INFO];
    // Processor Product Name
    strToBytes(procName, res);
    data.assign(reinterpret_cast<char*>(&res),
                reinterpret_cast<char*>(&res) + sizeof(res));

    std::string s(data.begin(), data.end());
    std::regex regex(" ");
    std::vector<std::string> productName(
        std::sregex_token_iterator(s.begin(), s.end(), regex, -1),
        std::sregex_token_iterator());

    // Processor core and frequency
    strToBytes(basicInfo, res);
    uint16_t coreNum = res[0];
    double procFrequency = (float)(res[4] << 8 | res[3]) / 1000;
    result = "CPU:" + productName[2] + "/" + std::to_string(procFrequency) +
             "GHz" + "/" + std::to_string(coreNum) + "c";
    return 0;
}

typedef struct
{
    uint8_t cur_power_state;
    uint8_t last_power_event;
    uint8_t misc_power_state;
    uint8_t front_panel_button_cap_status;
} ipmi_get_chassis_status_t;

//----------------------------------------------------------------------
// Get Debug Frame Info
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetFrameInfo(
    ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
    uint8_t num_frames = debugCardFrameSize;

    std::memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[SIZE_IANA_ID] = num_frames;
    *data_len = SIZE_IANA_ID + 1;

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get Debug Updated Frames
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetUpdFrames(
    ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
    uint8_t num_updates = 3;
    *data_len = 4;

    std::memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[SIZE_IANA_ID] = num_updates;
    *data_len = SIZE_IANA_ID + num_updates + 1;
    res[SIZE_IANA_ID + 1] = 1; // info page update
    res[SIZE_IANA_ID + 2] = 2; // cri sel update
    res[SIZE_IANA_ID + 3] = 3; // cri sensor update

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get Debug POST Description
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetPostDesc(
    ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
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
        return ipmi::ccUnspecifiedError;
    }

    memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[3] = index;
    res[4] = next;
    res[5] = phase;
    res[6] = end;
    res[7] = descLen;
    *data_len = SIZE_IANA_ID + 5 + descLen;

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get Debug GPIO Description
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetGpioDesc(
    ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);

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
        return ipmi::ccUnspecifiedError;
    }

    memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[3] = index;
    res[4] = next;
    res[5] = level;
    res[6] = pinDef;
    res[7] = descLen;
    *data_len = SIZE_IANA_ID + 5 + descLen;

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get Debug Frame Data
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetFrameData(
    ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
    uint8_t frame;
    uint8_t page;
    uint8_t next;
    uint8_t count;
    int ret;

    frame = req[3];
    page = req[4];

    ret = plat_udbg_get_frame_data(frame, page, &next, &count, &res[7]);
    if (ret)
    {
        memcpy(res, req, SIZE_IANA_ID); // IANA ID
        *data_len = SIZE_IANA_ID;
        return ipmi::ccUnspecifiedError;
    }

    memcpy(res, req, SIZE_IANA_ID); // IANA ID
    res[3] = frame;
    res[4] = page;
    res[5] = next;
    res[6] = count;
    *data_len = SIZE_IANA_ID + 4 + count;

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get Debug Control Panel
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemDbgGetCtrlPanel(
    ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);

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
ipmi_ret_t ipmiOemSetDimmInfo(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                              ipmi_response_t, ipmi_data_len_t data_len,
                              ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);

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

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get Board ID (CMD_OEM_GET_BOARD_ID)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemGetBoardID(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                             ipmi_response_t, ipmi_data_len_t data_len,
                             ipmi_context_t)
{
    /* TODO: Needs to implement this after GPIO implementation */
    *data_len = 0;

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get port 80 record (CMD_OEM_GET_80PORT_RECORD)
//----------------------------------------------------------------------
ipmi::RspType<std::vector<uint8_t>> ipmiOemGet80PortRecord(
    ipmi::Context::ptr ctx)
{
    auto postCodeService = "xyz.openbmc_project.State.Boot.PostCode" +
                           std::to_string(ctx->hostIdx + 1);
    auto postCodeObjPath = "/xyz/openbmc_project/State/Boot/PostCode" +
                           std::to_string(ctx->hostIdx + 1);
    constexpr auto postCodeInterface =
        "xyz.openbmc_project.State.Boot.PostCode";
    const static uint16_t lastestPostCodeIndex = 1;
    constexpr const auto maxPostCodeLen =
        224; // The length must be lower than IPMB limitation
    size_t startIndex = 0;

    std::vector<std::tuple<uint64_t, std::vector<uint8_t>>> postCodes;
    std::vector<uint8_t> resData;

    auto conn = getSdBus();
    /* Get the post codes by calling GetPostCodes method */
    auto msg =
        conn->new_method_call(postCodeService.c_str(), postCodeObjPath.c_str(),
                              postCodeInterface, "GetPostCodes");
    msg.append(lastestPostCodeIndex);

    try
    {
        auto reply = conn->call(msg);
        reply.read(postCodes);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "IPMI Get80PortRecord Failed in call method",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    /* Get post code data */
    for (size_t i = 0; i < postCodes.size(); ++i)
    {
        uint64_t primaryPostCode = std::get<uint64_t>(postCodes[i]);
        for (int j = postCodeSize - 1; j >= 0; --j)
        {
            uint8_t postCode =
                ((primaryPostCode >> (sizeof(uint64_t) * j)) & 0xFF);
            resData.emplace_back(postCode);
        }
    }

    std::vector<uint8_t> response;
    if (resData.size() > maxPostCodeLen)
    {
        startIndex = resData.size() - maxPostCodeLen;
    }

    response.assign(resData.begin() + startIndex, resData.end());

    return ipmi::responseSuccess(response);
}

//----------------------------------------------------------------------
// Set Boot Order (CMD_OEM_SET_BOOT_ORDER)
//----------------------------------------------------------------------
ipmi::RspType<std::vector<uint8_t>> ipmiOemSetBootOrder(
    ipmi::Context::ptr ctx, std::vector<uint8_t> bootSeq)
{
    size_t len = bootSeq.size();

    if (len != SIZE_BOOT_ORDER)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Boot order length received");
        return ipmi::responseReqDataLenInvalid();
    }

    std::optional<size_t> hostId = findHost(ctx->hostIdx);

    if (!hostId)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }
    auto [bootObjPath, hostName] = ipmi::boot::objPath(*hostId);

    ipmi::boot::setBootOrder(bootObjPath, bootSeq, hostName);

    return ipmi::responseSuccess(bootSeq);
}

//----------------------------------------------------------------------
// Get Boot Order (CMD_OEM_GET_BOOT_ORDER)
//----------------------------------------------------------------------
ipmi::RspType<std::vector<uint8_t>> ipmiOemGetBootOrder(ipmi::Context::ptr ctx)
{
    std::vector<uint8_t> bootSeq;

    std::optional<size_t> hostId = findHost(ctx->hostIdx);

    if (!hostId)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }
    auto [bootObjPath, hostName] = ipmi::boot::objPath(*hostId);

    ipmi::boot::getBootOrder(bootObjPath, bootSeq, hostName);

    return ipmi::responseSuccess(bootSeq);
}
// Set Machine Config Info (CMD_OEM_SET_MACHINE_CONFIG_INFO)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetMachineCfgInfo(ipmi_netfn_t, ipmi_cmd_t,
                                    ipmi_request_t request, ipmi_response_t,
                                    ipmi_data_len_t data_len, ipmi_context_t)
{
    machineConfigInfo_t* req = reinterpret_cast<machineConfigInfo_t*>(request);
    uint8_t len = *data_len;

    *data_len = 0;

    if (len < sizeof(machineConfigInfo_t))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid machine configuration length received");
        return ipmi::ccReqDataLenInvalid;
    }

    if (req->chassis_type >= sizeof(chassisType) / sizeof(uint8_t*))
        oemData[KEY_MC_CONFIG][KEY_MC_CHAS_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_CHAS_TYPE] =
            chassisType[req->chassis_type];

    if (req->mb_type >= sizeof(mbType) / sizeof(uint8_t*))
        oemData[KEY_MC_CONFIG][KEY_MC_MB_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_MB_TYPE] = mbType[req->mb_type];

    oemData[KEY_MC_CONFIG][KEY_MC_PROC_CNT] = req->proc_cnt;
    oemData[KEY_MC_CONFIG][KEY_MC_MEM_CNT] = req->mem_cnt;
    oemData[KEY_MC_CONFIG][KEY_MC_HDD35_CNT] = req->hdd35_cnt;
    oemData[KEY_MC_CONFIG][KEY_MC_HDD25_CNT] = req->hdd25_cnt;

    if (req->riser_type >= sizeof(riserType) / sizeof(uint8_t*))
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

    if (req->slot1_pcie_type >= sizeof(pcieType) / sizeof(uint8_t*))
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT1_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT1_TYPE] =
            pcieType[req->slot1_pcie_type];

    if (req->slot2_pcie_type >= sizeof(pcieType) / sizeof(uint8_t*))
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT2_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT2_TYPE] =
            pcieType[req->slot2_pcie_type];

    if (req->slot3_pcie_type >= sizeof(pcieType) / sizeof(uint8_t*))
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT3_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT3_TYPE] =
            pcieType[req->slot3_pcie_type];

    if (req->slot4_pcie_type >= sizeof(pcieType) / sizeof(uint8_t*))
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT4_TYPE] = "UNKNOWN";
    else
        oemData[KEY_MC_CONFIG][KEY_MC_SLOT4_TYPE] =
            pcieType[req->slot4_pcie_type];

    oemData[KEY_MC_CONFIG][KEY_MC_AEP_CNT] = req->aep_mem_cnt;

    flushOemData();

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Set POST start (CMD_OEM_SET_POST_START)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetPostStart(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                               ipmi_response_t, ipmi_data_len_t data_len,
                               ipmi_context_t)
{
    phosphor::logging::log<phosphor::logging::level::INFO>("POST Start Event");

    /* Do nothing, return success */
    *data_len = 0;
    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Set POST End (CMD_OEM_SET_POST_END)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetPostEnd(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                             ipmi_response_t, ipmi_data_len_t data_len,
                             ipmi_context_t)
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

    return ipmi::ccSuccess;
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
ipmi_ret_t ipmiOemSetPPINInfo(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                              ipmi_response_t, ipmi_data_len_t data_len,
                              ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
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

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Set ADR Trigger (CMD_OEM_SET_ADR_TRIGGER)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetAdrTrigger(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                                ipmi_response_t, ipmi_data_len_t data_len,
                                ipmi_context_t)
{
    /* Do nothing, return success */
    *data_len = 0;
    return ipmi::ccSuccess;
}

// Helper function to set guid at offset in EEPROM
[[maybe_unused]] static int setGUID(off_t offset, uint8_t* guid)
{
    int fd = -1;
    ssize_t len;
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
    fd = open(eepromPath.c_str(), O_WRONLY);
    if (fd == -1)
    {
        std::cerr << "Unable to open: " << eepromPath << std::endl;
        return errno;
    }

    // seek to the offset
    lseek(fd, offset, SEEK_SET);

    // Write bytes to location
    len = write(fd, guid, GUID_SIZE);
    if (len != GUID_SIZE)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GUID write data to EEPROM failed");
        ret = errno;
    }

    close(fd);
    return ret;
}

//----------------------------------------------------------------------
// Set System GUID (CMD_OEM_SET_SYSTEM_GUID)
//----------------------------------------------------------------------
#if BIC_ENABLED
ipmi::RspType<> ipmiOemSetSystemGuid(ipmi::Context::ptr ctx,
                                     std::vector<uint8_t> reqData)
{
    std::vector<uint8_t> respData;

    if (reqData.size() != GUID_SIZE) // 16bytes
    {
        return ipmi::responseReqDataLenInvalid();
    }

    uint8_t bicAddr = (uint8_t)ctx->hostIdx << 2;

    if (sendBicCmd(ctx->netFn, ctx->cmd, bicAddr, reqData, respData))
        return ipmi::responseUnspecifiedError();

    return ipmi::responseSuccess();
}

#else
ipmi_ret_t ipmiOemSetSystemGuid(ipmi_netfn_t, ipmi_cmd_t,
                                ipmi_request_t request, ipmi_response_t,
                                ipmi_data_len_t data_len, ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);

    if (*data_len != GUID_SIZE) // 16bytes
    {
        *data_len = 0;
        return ipmi::ccReqDataLenInvalid;
    }

    *data_len = 0;

    if (setGUID(OFFSET_SYS_GUID, req))
    {
        return ipmi::ccUnspecifiedError;
    }
    return ipmi::ccSuccess;
}
#endif

//----------------------------------------------------------------------
// Set Bios Flash Info (CMD_OEM_SET_BIOS_FLASH_INFO)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetBiosFlashInfo(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t,
                                   ipmi_response_t, ipmi_data_len_t data_len,
                                   ipmi_context_t)
{
    /* Do nothing, return success */
    *data_len = 0;
    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Set PPR (CMD_OEM_SET_PPR)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemSetPpr(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                         ipmi_response_t, ipmi_data_len_t data_len,
                         ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
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
                return ipmi::ccParmOutOfRange;

            oemData[KEY_PPR][KEY_PPR_ROW_COUNT] = req[1];
            break;
        case PPR_ROW_ADDR:
            pprIndex = req[1];
            if (pprIndex > 100)
                return ipmi::ccParmOutOfRange;

            if (len < PPR_ROW_ADDR_LEN + 1)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Invalid PPR Row Address length received");
                return ipmi::ccReqDataLenInvalid;
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
                return ipmi::ccParmOutOfRange;

            if (len < PPR_HST_DATA_LEN + 1)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Invalid PPR history data length received");
                return ipmi::ccReqDataLenInvalid;
            }

            ss << std::hex;
            ss << std::setw(2) << std::setfill('0') << (int)pprIndex;

            oemData[KEY_PPR][ss.str()][KEY_PPR_INDEX] = pprIndex;

            str = bytesToStr(&req[1], PPR_HST_DATA_LEN);
            oemData[KEY_PPR][ss.str()][KEY_PPR_HST_DATA] = str.c_str();
            break;
        default:
            return ipmi::ccParmOutOfRange;
            break;
    }

    flushOemData();

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get PPR (CMD_OEM_GET_PPR)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemGetPpr(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                         ipmi_response_t response, ipmi_data_len_t data_len,
                         ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
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
                return ipmi::ccParmOutOfRange;

            ss << std::hex;
            ss << std::setw(2) << std::setfill('0') << (int)pprIndex;

            if (oemData[KEY_PPR].find(ss.str()) == oemData[KEY_PPR].end())
                return ipmi::ccParmOutOfRange;

            if (oemData[KEY_PPR][ss.str()].find(KEY_PPR_ROW_ADDR) ==
                oemData[KEY_PPR][ss.str()].end())
                return ipmi::ccParmOutOfRange;

            str = oemData[KEY_PPR][ss.str()][KEY_PPR_ROW_ADDR];
            *data_len = strToBytes(str, res);
            break;
        case PPR_HISTORY_DATA:
            pprIndex = req[1];
            if (pprIndex > 100)
                return ipmi::ccParmOutOfRange;

            ss << std::hex;
            ss << std::setw(2) << std::setfill('0') << (int)pprIndex;

            if (oemData[KEY_PPR].find(ss.str()) == oemData[KEY_PPR].end())
                return ipmi::ccParmOutOfRange;

            if (oemData[KEY_PPR][ss.str()].find(KEY_PPR_HST_DATA) ==
                oemData[KEY_PPR][ss.str()].end())
                return ipmi::ccParmOutOfRange;

            str = oemData[KEY_PPR][ss.str()][KEY_PPR_HST_DATA];
            *data_len = strToBytes(str, res);
            break;
        default:
            return ipmi::ccParmOutOfRange;
            break;
    }

    return ipmi::ccSuccess;
}

//----------------------------------------------------------------------
// Get FRU ID (CMD_OEM_GET_FRU_ID)
//----------------------------------------------------------------------
ipmi_ret_t ipmiOemGetEeprom(ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request,
                            ipmi_response_t response, ipmi_data_len_t data_len,
                            ipmi_context_t)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
    auto bus = sdbusplus::bus::new_default();

    const uint32_t targetBus = req[0];
    const uint32_t targetAddress = req[1];
    *data_len = 1;

    const std::string service = "xyz.openbmc_project.FruDevice";
    const std::string rootPath = "/xyz/openbmc_project/FruDevice";

    auto method = bus.new_method_call(service.c_str(), "/",
                                      "org.freedesktop.DBus.ObjectManager",
                                      "GetManagedObjects");

    auto reply = bus.call(method);

    using PropertyValue = std::variant<std::string, uint32_t, int32_t, bool>;

    std::map<sdbusplus::message::object_path,
             std::map<std::string, std::map<std::string, PropertyValue>>>
        objects;

    reply.read(objects);

    int index = 0;
    bool found = false;

    for (const auto& [path, interfaces] : objects)
    {
        if (path.str.find(rootPath) != 0)
            continue;

        auto it = interfaces.find("xyz.openbmc_project.FruDevice");
        if (it != interfaces.end())
        {
            const auto& properties = it->second;

            auto busIt = properties.find("BUS");
            auto addrIt = properties.find("ADDRESS");

            if (busIt != properties.end() && addrIt != properties.end())
            {
                try
                {
                    uint32_t busValue = std::get<uint32_t>(busIt->second);
                    uint32_t addrValue = std::get<uint32_t>(addrIt->second);

                    if (busValue == targetBus && addrValue == targetAddress)
                    {
                        std::cout
                            << "Match found at index: " << index << std::endl;
                        std::cout << "Path: " << path.str << std::endl;
                        res[0] = index;
                        found = true;
                        break;
                    }
                }
                catch (const std::bad_variant_access& e)
                {
                    std::cerr << "️Unexpected property type at index " << index
                              << std::endl;
                    return -1;
                }
            }
            index++;
        }
    }

    if (!found)
    {
        std::cout << "No matching FRU device found for BUS=" << targetBus
                  << " and ADDRESS=" << targetAddress << std::endl;
        return -1;
    }

    return ipmi::ccSuccess;
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

ipmi::RspType<> ipmiOemQSetProcInfo(
    ipmi::Context::ptr ctx, uint8_t, uint8_t, uint8_t, uint8_t procIndex,
    uint8_t paramSel, std::vector<uint8_t> request)
{
    uint8_t numParam = sizeof(cpuInfoKey) / sizeof(uint8_t*);
    std::stringstream ss;
    std::string str;
    uint8_t len = request.size();
    auto hostId = findHost(ctx->hostIdx);
    if (!hostId)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }
    std::string procInfo = KEY_Q_PROC_INFO + std::to_string(*hostId);
    /* check for requested data params */
    if (len < 5 || paramSel < 1 || paramSel >= numParam)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return ipmi::responseParmOutOfRange();
    }
    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)procIndex;
    oemData[procInfo][ss.str()][KEY_PROC_INDEX] = procIndex;
    str = bytesToStr(request.data(), len);
    oemData[procInfo][ss.str()][cpuInfoKey[paramSel]] = str.c_str();
    flushOemData();
    return ipmi::responseSuccess();
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

ipmi::RspType<std::vector<uint8_t>> ipmiOemQGetProcInfo(
    ipmi::Context::ptr ctx, uint8_t, uint8_t, uint8_t, uint8_t procIndex,
    uint8_t paramSel)
{
    uint8_t numParam = sizeof(cpuInfoKey) / sizeof(uint8_t*);
    std::stringstream ss;
    std::string str;
    uint8_t res[MAX_BUF];
    auto hostId = findHost(ctx->hostIdx);
    if (!hostId)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }
    std::string procInfo = KEY_Q_PROC_INFO + std::to_string(*hostId);
    if (paramSel < 1 || paramSel >= numParam)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return ipmi::responseParmOutOfRange();
    }
    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)procIndex;
    if (oemData[procInfo].find(ss.str()) == oemData[procInfo].end())
        return ipmi::responseCommandNotAvailable();
    if (oemData[procInfo][ss.str()].find(cpuInfoKey[paramSel]) ==
        oemData[procInfo][ss.str()].end())
        return ipmi::responseCommandNotAvailable();
    str = oemData[procInfo][ss.str()][cpuInfoKey[paramSel]];
    int dataLen = strToBytes(str, res);
    std::vector<uint8_t> response(&res[0], &res[dataLen]);
    return ipmi::responseSuccess(response);
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
ipmi::RspType<> ipmiOemQSetDimmInfo(
    ipmi::Context::ptr ctx, uint8_t, uint8_t, uint8_t, uint8_t dimmIndex,
    uint8_t paramSel, std::vector<uint8_t> request)
{
    uint8_t numParam = sizeof(dimmInfoKey) / sizeof(uint8_t*);
    std::stringstream ss;
    std::string str;
    uint8_t len = request.size();
    std::string dimmType;
    readDimmType(dimmType, dimmIndex);
    auto hostId = findHost(ctx->hostIdx);
    if (!hostId)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }

    std::string dimmInfo = KEY_Q_DIMM_INFO + std::to_string(*hostId);

    if (len < 3 || paramSel < 1 || paramSel >= numParam)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return ipmi::responseParmOutOfRange();
    }

    ss << std::hex;
    ss << (int)dimmIndex;
    oemData[dimmInfo][ss.str()][KEY_DIMM_INDEX] = dimmIndex;
    oemData[dimmInfo][ss.str()][KEY_DIMM_TYPE] = dimmType;
    str = bytesToStr(request.data(), len);
    oemData[dimmInfo][ss.str()][dimmInfoKey[paramSel]] = str.c_str();
    flushOemData();
    return ipmi::responseSuccess();
}

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
ipmi::RspType<std::vector<uint8_t>> ipmiOemQGetDimmInfo(
    ipmi::Context::ptr ctx, uint8_t, uint8_t, uint8_t, uint8_t dimmIndex,
    uint8_t paramSel)
{
    uint8_t numParam = sizeof(dimmInfoKey) / sizeof(uint8_t*);
    uint8_t res[MAX_BUF];
    std::stringstream ss;
    std::string str;
    std::string dimmType;
    readDimmType(dimmType, dimmIndex);
    auto hostId = findHost(ctx->hostIdx);
    if (!hostId)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }
    std::string dimmInfo = KEY_Q_DIMM_INFO + std::to_string(*hostId);

    if (paramSel < 1 || paramSel >= numParam)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return ipmi::responseParmOutOfRange();
    }
    ss << std::hex;
    ss << (int)dimmIndex;
    oemData[dimmInfo][ss.str()][KEY_DIMM_TYPE] = dimmType;
    if (oemData[dimmInfo].find(ss.str()) == oemData[dimmInfo].end())
        return ipmi::responseCommandNotAvailable();
    if (oemData[dimmInfo][ss.str()].find(dimmInfoKey[paramSel]) ==
        oemData[dimmInfo][ss.str()].end())
        return ipmi::responseCommandNotAvailable();
    str = oemData[dimmInfo][ss.str()][dimmInfoKey[paramSel]];
    int data_length = strToBytes(str, res);
    std::vector<uint8_t> response(&res[0], &res[data_length]);
    return ipmi::responseSuccess(response);
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
ipmi_ret_t ipmiOemQSetDriveInfo(ipmi_netfn_t, ipmi_cmd_t,
                                ipmi_request_t request, ipmi_response_t,
                                ipmi_data_len_t data_len, ipmi_context_t)
{
    qDriveInfo_t* req = reinterpret_cast<qDriveInfo_t*>(request);
    uint8_t numParam = sizeof(driveInfoKey) / sizeof(uint8_t*);
    uint8_t ctrlType = req->hddCtrlType & 0x0f;
    std::stringstream ss;
    std::string str;
    uint8_t len = *data_len;

    *data_len = 0;

    /* check for requested data params */
    if (len < 6 || req->paramSel >= numParam || ctrlType > 2)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return ipmi::ccParmOutOfRange;
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

    return ipmi::ccSuccess;
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
ipmi_ret_t ipmiOemQGetDriveInfo(
    ipmi_netfn_t, ipmi_cmd_t, ipmi_request_t request, ipmi_response_t response,
    ipmi_data_len_t data_len, ipmi_context_t)
{
    qDriveInfo_t* req = reinterpret_cast<qDriveInfo_t*>(request);
    uint8_t numParam = sizeof(driveInfoKey) / sizeof(uint8_t*);
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
    uint8_t ctrlType = req->hddCtrlType & 0x0f;
    std::stringstream ss;
    std::string str;

    *data_len = 0;

    /* check for requested data params */
    if (req->paramSel >= numParam || ctrlType > 2)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid parameter received");
        return ipmi::ccParmOutOfRange;
    }

    if (oemData[KEY_Q_DRIVE_INFO].find(ctrlTypeKey[ctrlType]) ==
        oemData[KEY_Q_DRIVE_INFO].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << (int)req->hddIndex;

    if (oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]].find(ss.str()) ==
        oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    if (oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]][ss.str()].find(
            driveInfoKey[req->paramSel]) ==
        oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]][ss.str()].end())
        return CC_PARAM_NOT_SUPP_IN_CURR_STATE;

    str = oemData[KEY_Q_DRIVE_INFO][ctrlTypeKey[ctrlType]][ss.str()]
                 [driveInfoKey[req->paramSel]];
    *data_len = strToBytes(str, res);

    return ipmi::ccSuccess;
}

/* Helper function for sending DCMI commands to ME/BIC and
 * getting response back
 */
ipmi::RspType<std::vector<uint8_t>> sendDCMICmd(
    [[maybe_unused]] ipmi::Context::ptr ctx, [[maybe_unused]] uint8_t cmd,
    std::vector<uint8_t>& cmdData)
{
    std::vector<uint8_t> respData;

#if BIC_ENABLED

    uint8_t bicAddr = (uint8_t)ctx->hostIdx << 2;

    if (sendBicCmd(ctx->netFn, ctx->cmd, bicAddr, cmdData, respData))
    {
        return ipmi::responseUnspecifiedError();
    }

#else

    /* Add group id as first byte to request for ME command */
    cmdData.insert(cmdData.begin(), groupDCMI);

    if (sendMeCmd(ipmi::netFnGroup, cmd, cmdData, respData))
    {
        return ipmi::responseUnspecifiedError();
    }

    /* Remove group id as first byte as it will be added by IPMID */
    respData.erase(respData.begin());

#endif

    return ipmi::responseSuccess(std::move(respData));
}

/* DCMI Command handellers. */

ipmi::RspType<std::vector<uint8_t>> ipmiOemDCMIGetPowerReading(
    ipmi::Context::ptr ctx, std::vector<uint8_t> reqData)
{
    return sendDCMICmd(ctx, ipmi::dcmi::cmdGetPowerReading, reqData);
}

ipmi::RspType<std::vector<uint8_t>> ipmiOemDCMIGetPowerLimit(
    ipmi::Context::ptr ctx, std::vector<uint8_t> reqData)
{
    return sendDCMICmd(ctx, ipmi::dcmi::cmdGetPowerLimit, reqData);
}

ipmi::RspType<std::vector<uint8_t>> ipmiOemDCMISetPowerLimit(
    ipmi::Context::ptr ctx, std::vector<uint8_t> reqData)
{
    return sendDCMICmd(ctx, ipmi::dcmi::cmdSetPowerLimit, reqData);
}

ipmi::RspType<std::vector<uint8_t>> ipmiOemDCMIApplyPowerLimit(
    ipmi::Context::ptr ctx, std::vector<uint8_t> reqData)
{
    return sendDCMICmd(ctx, ipmi::dcmi::cmdActDeactivatePwrLimit, reqData);
}

// Https Boot related functions
ipmi::RspType<std::vector<uint8_t>> ipmiOemGetHttpsData(
    [[maybe_unused]] ipmi::Context::ptr ctx, std::vector<uint8_t> reqData)
{
    if (reqData.size() < sizeof(HttpsDataReq))
        return ipmi::responseReqDataLenInvalid();

    const auto* pReq = reinterpret_cast<const HttpsDataReq*>(reqData.data());
    std::error_code ec;
    auto fileSize = std::filesystem::file_size(certPath, ec);
    if (ec)
        return ipmi::responseUnspecifiedError();

    if (pReq->offset >= fileSize)
        return ipmi::responseInvalidFieldRequest();

    std::ifstream file(certPath, std::ios::binary);
    if (!file)
        return ipmi::responseUnspecifiedError();

    auto readLen = std::min<uint16_t>(pReq->length, fileSize - pReq->offset);
    std::vector<uint8_t> resData(readLen + 1);
    resData[0] = readLen;
    file.seekg(pReq->offset);
    file.read(reinterpret_cast<char*>(resData.data() + 1), readLen);

    return ipmi::responseSuccess(resData);
}

ipmi::RspType<std::vector<uint8_t>> ipmiOemGetHttpsAttr(
    [[maybe_unused]] ipmi::Context::ptr ctx, std::vector<uint8_t> reqData)
{
    if (reqData.size() < sizeof(HttpsBootAttr))
        return ipmi::responseReqDataLenInvalid();

    std::vector<uint8_t> resData;

    switch (static_cast<HttpsBootAttr>(reqData[0]))
    {
        case HttpsBootAttr::certSize:
        {
            std::error_code ec;
            auto fileSize = std::filesystem::file_size(certPath, ec);
            if (ec || fileSize > std::numeric_limits<uint16_t>::max())
                return ipmi::responseUnspecifiedError();

            uint16_t size = static_cast<uint16_t>(fileSize);
            resData.resize(sizeof(uint16_t));
            std::memcpy(resData.data(), &size, sizeof(uint16_t));
            break;
        }
        case HttpsBootAttr::certCrc:
        {
            std::ifstream file(certPath, std::ios::binary);
            if (!file)
                return ipmi::responseUnspecifiedError();

            boost::crc_32_type result;
            char data[1024];
            while (file.read(data, sizeof(data)))
                result.process_bytes(data, file.gcount());
            if (file.gcount() > 0)
                result.process_bytes(data, file.gcount());

            uint32_t crc = result.checksum();
            resData.resize(sizeof(uint32_t));
            std::memcpy(resData.data(), &crc, sizeof(uint32_t));
            break;
        }
        default:
            return ipmi::responseInvalidFieldRequest();
    }

    return ipmi::responseSuccess(resData);
}

// OEM Crashdump related functions
static ipmi_ret_t setDumpState(CrdState& currState, CrdState newState)
{
    switch (newState)
    {
        case CrdState::waitData:
            if (currState == CrdState::packing)
                return CC_PARAM_NOT_SUPP_IN_CURR_STATE;
            break;
        case CrdState::packing:
            if (currState != CrdState::waitData)
                return CC_PARAM_NOT_SUPP_IN_CURR_STATE;
            break;
        case CrdState::free:
            break;
        default:
            return ipmi::ccUnspecifiedError;
    }
    currState = newState;

    return ipmi::ccSuccess;
}

static ipmi_ret_t handleMcaBank(const CrashDumpHdr& hdr,
                                std::span<const uint8_t> data,
                                CrdState& currState, std::stringstream& ss)
{
    if (data.size() < sizeof(CrdMcaBank))
        return ipmi::ccReqDataLenInvalid;

    ipmi_ret_t res = setDumpState(currState, CrdState::waitData);
    if (res)
        return res;

    const auto* pBank = reinterpret_cast<const CrdMcaBank*>(data.data());
    ss << std::format(" Bank ID : 0x{:02X}, Core ID : 0x{:02X}\n",
                      hdr.bankHdr.bankId, hdr.bankHdr.coreId);
    ss << std::format(" MCA_CTRL      : 0x{:016X}\n", pBank->mcaCtrl);
    ss << std::format(" MCA_STATUS    : 0x{:016X}\n", pBank->mcaSts);
    ss << std::format(" MCA_ADDR      : 0x{:016X}\n", pBank->mcaAddr);
    ss << std::format(" MCA_MISC0     : 0x{:016X}\n", pBank->mcaMisc0);
    ss << std::format(" MCA_CTRL_MASK : 0x{:016X}\n", pBank->mcaCtrlMask);
    ss << std::format(" MCA_CONFIG    : 0x{:016X}\n", pBank->mcaConfig);
    ss << std::format(" MCA_IPID      : 0x{:016X}\n", pBank->mcaIpid);
    ss << std::format(" MCA_SYND      : 0x{:016X}\n", pBank->mcaSynd);
    ss << std::format(" MCA_DESTAT    : 0x{:016X}\n", pBank->mcaDestat);
    ss << std::format(" MCA_DEADDR    : 0x{:016X}\n", pBank->mcaDeaddr);
    ss << std::format(" MCA_MISC1     : 0x{:016X}\n", pBank->mcaMisc1);
    ss << "\n";

    return ipmi::ccSuccess;
}

template <typename T>
static ipmi_ret_t handleVirtualBank(std::span<const uint8_t> data,
                                    CrdState& currState, std::stringstream& ss)
{
    if (data.size() < sizeof(T))
        return ipmi::ccReqDataLenInvalid;

    const auto* pBank = reinterpret_cast<const T*>(data.data());

    if (data.size() < sizeof(T) + sizeof(BankCorePair) * pBank->mcaCount)
        return ipmi::ccReqDataLenInvalid;

    ipmi_ret_t res = setDumpState(currState, CrdState::waitData);
    if (res)
        return res;

    ss << " Virtual Bank\n";
    ss << std::format(" S5_RESET_STATUS   : 0x{:08X}\n", pBank->s5ResetSts);
    ss << std::format(" PM_BREAKEVENT     : 0x{:08X}\n", pBank->breakevent);
    if constexpr (std::is_same_v<T, CrdVirtualBankV3>)
    {
        ss << std::format(" WARMCOLDRSTSTATUS : 0x{:08X}\n", pBank->rstSts);
    }
    ss << std::format(" PROCESSOR NUMBER  : 0x{:04X}\n", pBank->procNum);
    ss << std::format(" APIC ID           : 0x{:08X}\n", pBank->apicId);
    ss << std::format(" EAX               : 0x{:08X}\n", pBank->eax);
    ss << std::format(" EBX               : 0x{:08X}\n", pBank->ebx);
    ss << std::format(" ECX               : 0x{:08X}\n", pBank->ecx);
    ss << std::format(" EDX               : 0x{:08X}\n", pBank->edx);
    ss << " VALID LIST        : ";
    for (size_t i = 0; i < pBank->mcaCount; i++)
    {
        ss << std::format("(0x{:02X},0x{:02X}) ", pBank->mcaList[i].bankId,
                          pBank->mcaList[i].coreId);
    }
    ss << "\n\n";

    return ipmi::ccSuccess;
}

static ipmi_ret_t handleCpuWdtBank(std::span<const uint8_t> data,
                                   CrdState& currState, std::stringstream& ss)
{
    if (data.size() < sizeof(CrdCpuWdtBank))
        return ipmi::ccReqDataLenInvalid;

    ipmi_ret_t res = setDumpState(currState, CrdState::waitData);
    if (res)
        return res;

    const auto* pBank = reinterpret_cast<const CrdCpuWdtBank*>(data.data());
    for (size_t i = 0; i < ccmNum; i++)
    {
        ss << std::format("  [CCM{}]\n", i);
        ss << std::format("    HwAssertStsHi      : 0x{:08X}\n",
                          pBank->hwAssertStsHi[i]);
        ss << std::format("    HwAssertStsLo      : 0x{:08X}\n",
                          pBank->hwAssertStsLo[i]);
        ss << std::format("    OrigWdtAddrLogHi   : 0x{:08X}\n",
                          pBank->origWdtAddrLogHi[i]);
        ss << std::format("    OrigWdtAddrLogLo   : 0x{:08X}\n",
                          pBank->origWdtAddrLogLo[i]);
        ss << std::format("    HwAssertMskHi      : 0x{:08X}\n",
                          pBank->hwAssertMskHi[i]);
        ss << std::format("    HwAssertMskLo      : 0x{:08X}\n",
                          pBank->hwAssertMskLo[i]);
        ss << std::format("    OrigWdtAddrLogStat : 0x{:08X}\n",
                          pBank->origWdtAddrLogStat[i]);
    }
    ss << "\n";

    return ipmi::ccSuccess;
}

template <size_t N>
static ipmi_ret_t handleHwAssertBank(const char* name,
                                     std::span<const uint8_t> data,
                                     CrdState& currState, std::stringstream& ss)
{
    if (data.size() < sizeof(CrdHwAssertBank<N>))
        return ipmi::ccReqDataLenInvalid;

    ipmi_ret_t res = setDumpState(currState, CrdState::waitData);
    if (res)
        return res;

    const CrdHwAssertBank<N>* pBank =
        reinterpret_cast<const CrdHwAssertBank<N>*>(data.data());

    for (size_t i = 0; i < N; i++)
    {
        ss << std::format("  [{}{}]\n", name, i);
        ss << std::format("    HwAssertStsHi : 0x{:08X}\n",
                          pBank->hwAssertStsHi[i]);
        ss << std::format("    HwAssertStsLo : 0x{:08X}\n",
                          pBank->hwAssertStsLo[i]);
        ss << std::format("    HwAssertMskHi : 0x{:08X}\n",
                          pBank->hwAssertMskHi[i]);
        ss << std::format("    HwAssertMskLo : 0x{:08X}\n",
                          pBank->hwAssertMskLo[i]);
    }
    ss << "\n";

    return ipmi::ccSuccess;
}

static ipmi_ret_t handlePcieAerBank(std::span<const uint8_t> data,
                                    CrdState& currState, std::stringstream& ss)
{
    if (data.size() < sizeof(CrdPcieAerBank))
        return ipmi::ccReqDataLenInvalid;

    ipmi_ret_t res = setDumpState(currState, CrdState::waitData);
    if (res)
        return res;

    const auto* pBank = reinterpret_cast<const CrdPcieAerBank*>(data.data());
    ss << std::format("  [Bus{} Dev{} Fun{}]\n", pBank->bus, pBank->dev,
                      pBank->fun);
    ss << std::format("    Command                      : 0x{:04X}\n",
                      pBank->cmd);
    ss << std::format("    Status                       : 0x{:04X}\n",
                      pBank->sts);
    ss << std::format("    Slot                         : 0x{:04X}\n",
                      pBank->slot);
    ss << std::format("    Secondary Bus                : 0x{:02X}\n",
                      pBank->secondBus);
    ss << std::format("    Vendor ID                    : 0x{:04X}\n",
                      pBank->vendorId);
    ss << std::format("    Device ID                    : 0x{:04X}\n",
                      pBank->devId);
    ss << std::format("    Class Code                   : 0x{:02X}{:04X}\n",
                      pBank->classCodeHi, pBank->classCodeLo);
    ss << std::format("    Bridge: Secondary Status     : 0x{:04X}\n",
                      pBank->secondSts);
    ss << std::format("    Bridge: Control              : 0x{:04X}\n",
                      pBank->ctrl);
    ss << std::format("    Uncorrectable Error Status   : 0x{:08X}\n",
                      pBank->uncorrErrSts);
    ss << std::format("    Uncorrectable Error Mask     : 0x{:08X}\n",
                      pBank->uncorrErrMsk);
    ss << std::format("    Uncorrectable Error Severity : 0x{:08X}\n",
                      pBank->uncorrErrSeverity);
    ss << std::format("    Correctable Error Status     : 0x{:08X}\n",
                      pBank->corrErrSts);
    ss << std::format("    Correctable Error Mask       : 0x{:08X}\n",
                      pBank->corrErrMsk);
    ss << std::format("    Header Log DW0               : 0x{:08X}\n",
                      pBank->hdrLogDw0);
    ss << std::format("    Header Log DW1               : 0x{:08X}\n",
                      pBank->hdrLogDw1);
    ss << std::format("    Header Log DW2               : 0x{:08X}\n",
                      pBank->hdrLogDw2);
    ss << std::format("    Header Log DW3               : 0x{:08X}\n",
                      pBank->hdrLogDw3);
    ss << std::format("    Root Error Status            : 0x{:08X}\n",
                      pBank->rootErrSts);
    ss << std::format("    Correctable Error Source ID  : 0x{:04X}\n",
                      pBank->corrErrSrcId);
    ss << std::format("    Error Source ID              : 0x{:04X}\n",
                      pBank->errSrcId);
    ss << std::format("    Lane Error Status            : 0x{:08X}\n",
                      pBank->laneErrSts);
    ss << "\n";

    return ipmi::ccSuccess;
}

static ipmi_ret_t handleWdtRegBank(std::span<const uint8_t> data,
                                   CrdState& currState, std::stringstream& ss)
{
    if (data.size() < sizeof(CrdWdtRegBank))
        return ipmi::ccReqDataLenInvalid;

    const auto* pBank = reinterpret_cast<const CrdWdtRegBank*>(data.data());
    if (data.size() < sizeof(CrdWdtRegBank) + sizeof(uint32_t) * pBank->count)
        return ipmi::ccReqDataLenInvalid;

    ipmi_ret_t res = setDumpState(currState, CrdState::waitData);
    if (res)
        return res;

    ss << std::format("  [NBIO{}] {}\n", pBank->nbio, pBank->name);
    ss << std::format("    Address: 0x{:08X}\n", pBank->addr);
    ss << std::format("    Data Count: {}\n", pBank->count);
    ss << "    Data:\n";
    for (size_t i = 0; i < pBank->count; i++)
    {
        ss << std::format("      {}: 0x{:08X}\n", i, pBank->data[i]);
    }
    ss << "\n";

    return ipmi::ccSuccess;
}

static ipmi_ret_t handleCrdHdrBank(std::span<const uint8_t> data,
                                   CrdState& currState, std::stringstream& ss)
{
    if (data.size() < sizeof(CrdHdrBank))
        return ipmi::ccReqDataLenInvalid;

    ipmi_ret_t res = setDumpState(currState, CrdState::waitData);
    if (res)
        return res;

    const auto* pBank = reinterpret_cast<const CrdHdrBank*>(data.data());
    ss << " Crashdump Header\n";
    ss << std::format(" CPU PPIN      : 0x{:016X}\n", pBank->ppin);
    ss << std::format(" UCODE VERSION : 0x{:08X}\n", pBank->ucodeVer);
    ss << std::format(" PMIO 80h      : 0x{:08X}\n", pBank->pmio);
    ss << std::format(
        "    BIT0 - SMN Parity/SMN Timeouts PSP/SMU Parity and ECC/SMN On-Package Link Error : {}\n",
        pBank->pmio & 0x1);
    ss << std::format("    BIT2 - PSP Parity and ECC : {}\n",
                      (pBank->pmio & 0x4) >> 2);
    ss << std::format("    BIT3 - SMN Timeouts SMU : {}\n",
                      (pBank->pmio & 0x8) >> 3);
    ss << std::format("    BIT4 - SMN Off-Package Link Packet Error : {}\n",
                      (pBank->pmio & 0x10) >> 4);
    ss << "\n";

    return ipmi::ccSuccess;
}

static std::string getFilename(const std::filesystem::path& dir,
                               const std::string& prefix)
{
    std::vector<int> indices;
    std::regex pattern(prefix + "(\\d+)\\.txt");

    for (const auto& entry : std::filesystem::directory_iterator(dir))
    {
        std::string filename = entry.path().filename().string();
        std::smatch match;
        if (std::regex_match(filename, match, pattern))
            indices.push_back(std::stoi(match[1]));
    }

    std::sort(indices.rbegin(), indices.rend());
    while (indices.size() > 2) // keep 3 files, so remove if more than 2
    {
        std::filesystem::remove(
            dir / (prefix + std::to_string(indices.back()) + ".txt"));
        indices.pop_back();
    }

    int nextIndex = indices.empty() ? 1 : indices.front() + 1;
    return prefix + std::to_string(nextIndex) + ".txt";
}

static ipmi_ret_t handleCtrlBank(std::span<const uint8_t> data,
                                 CrdState& currState, std::stringstream& ss)
{
    if (data.empty())
        return ipmi::ccReqDataLenInvalid;

    switch (static_cast<CrdCtrl>(data[0]))
    {
        case CrdCtrl::getState:
            break;
        case CrdCtrl::finish:
        {
            ipmi_ret_t res = setDumpState(currState, CrdState::packing);
            if (res)
                return res;

            const std::filesystem::path dumpDir = "/var/lib/fb-ipmi-oem";
            std::string filename = getFilename(dumpDir, "crashdump_");
            std::ofstream outFile(dumpDir / filename);
            if (!outFile.is_open())
                return ipmi::ccUnspecifiedError;

            auto now = std::chrono::system_clock::to_time_t(
                std::chrono::system_clock::now());
            outFile << "Crash Dump generated at: "
                    << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S")
                    << "\n\n";
            outFile << ss.str();
            outFile.close();
            ss.str("");
            ss.clear();
            setDumpState(currState, CrdState::free);
            break;
        }
        default:
            return ccInvalidParam;
    }

    return ipmi::ccSuccess;
}

ipmi::RspType<std::vector<uint8_t>> ipmiOemCrashdump(
    [[maybe_unused]] ipmi::Context::ptr ctx, std::vector<uint8_t> reqData)
{
    static CrdState dumpState = CrdState::free;
    static std::stringstream ss;

    if (reqData.size() < sizeof(CrashDumpHdr))
        return ipmi::responseReqDataLenInvalid();

    const auto* pHdr = reinterpret_cast<const CrashDumpHdr*>(reqData.data());
    std::span<const uint8_t> bData{reqData.data() + sizeof(CrashDumpHdr),
                                   reqData.size() - sizeof(CrashDumpHdr)};
    ipmi_ret_t res;

    switch (pHdr->bankHdr.bankType)
    {
        case BankType::mca:
            res = handleMcaBank(*pHdr, bData, dumpState, ss);
            break;
        case BankType::virt:
            if (pHdr->bankHdr.version >= 3)
            {
                res = handleVirtualBank<CrdVirtualBankV3>(bData, dumpState, ss);
                break;
            }
            res = handleVirtualBank<CrdVirtualBankV2>(bData, dumpState, ss);
            break;
        case BankType::cpuWdt:
            res = handleCpuWdtBank(bData, dumpState, ss);
            break;
        case BankType::tcdx:
            res = handleHwAssertBank<tcdxNum>("TCDX", bData, dumpState, ss);
            break;
        case BankType::cake:
            res = handleHwAssertBank<cakeNum>("CAKE", bData, dumpState, ss);
            break;
        case BankType::pie0:
            res = handleHwAssertBank<pie0Num>("PIE", bData, dumpState, ss);
            break;
        case BankType::iom:
            res = handleHwAssertBank<iomNum>("IOM", bData, dumpState, ss);
            break;
        case BankType::ccix:
            res = handleHwAssertBank<ccixNum>("CCIX", bData, dumpState, ss);
            break;
        case BankType::cs:
            res = handleHwAssertBank<csNum>("CS", bData, dumpState, ss);
            break;
        case BankType::pcieAer:
            res = handlePcieAerBank(bData, dumpState, ss);
            break;
        case BankType::wdtReg:
            res = handleWdtRegBank(bData, dumpState, ss);
            break;
        case BankType::ctrl:
            res = handleCtrlBank(bData, dumpState, ss);
            if (res == ipmi::ccSuccess &&
                static_cast<CrdCtrl>(bData[0]) == CrdCtrl::getState)
            {
                return ipmi::responseSuccess(
                    std::vector<uint8_t>{static_cast<uint8_t>(dumpState)});
            }
            break;
        case BankType::crdHdr:
            res = handleCrdHdrBank(bData, dumpState, ss);
            break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }

    return ipmi::response(res);
}

static void registerOEMFunctions(void)
{
    /* Get OEM data from json file */
    std::ifstream file(JSON_OEM_DATA_FILE);
    if (file)
    {
        try
        {
            file >> oemData;
        }
        // If parsing fails, initialize oemData as an empty JSON and
        // overwrite the file
        catch (const nlohmann::json::parse_error& e)
        {
            lg2::error("Error parsing JSON file: {ERROR}", "ERROR", e);
            oemData = nlohmann::json::object();
            std::ofstream outFile(JSON_OEM_DATA_FILE, std::ofstream::trunc);
            outFile << oemData.dump(4); // Write empty JSON object to the file
            outFile.close();
        }
        file.close();
    }
    else
    {
        lg2::info("Failed to open JSON file.");
    }

    lg2::info("Registering OEM commands.");

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
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_SET_DIMM_INFO, NULL,
                         ipmiOemSetDimmInfo,
                         PRIVILEGE_USER); // Set Dimm Info
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_GET_BOARD_ID, NULL,
                         ipmiOemGetBoardID,
                         PRIVILEGE_USER); // Get Board ID
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnOemOne,
                          CMD_OEM_GET_80PORT_RECORD, ipmi::Privilege::User,
                          ipmiOemGet80PortRecord); // Get 80 Port Record
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_SET_MACHINE_CONFIG_INFO,
                         NULL, ipmiOemSetMachineCfgInfo,
                         PRIVILEGE_USER); // Set Machine Config Info
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_SET_POST_START, NULL,
                         ipmiOemSetPostStart,
                         PRIVILEGE_USER); // Set POST start
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_SET_POST_END, NULL,
                         ipmiOemSetPostEnd,
                         PRIVILEGE_USER); // Set POST End
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_SET_PPIN_INFO, NULL,
                         ipmiOemSetPPINInfo,
                         PRIVILEGE_USER); // Set PPIN Info
#if BIC_ENABLED

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne,
                          ipmi::cmdSetSystemGuid, ipmi::Privilege::User,
                          ipmiOemSetSystemGuid);
#else

    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_SET_SYSTEM_GUID, NULL,
                         ipmiOemSetSystemGuid,
                         PRIVILEGE_USER); // Set System GUID
#endif
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_SET_ADR_TRIGGER, NULL,
                         ipmiOemSetAdrTrigger,
                         PRIVILEGE_USER); // Set ADR Trigger
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_SET_BIOS_FLASH_INFO, NULL,
                         ipmiOemSetBiosFlashInfo,
                         PRIVILEGE_USER); // Set Bios Flash Info
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_SET_PPR, NULL,
                         ipmiOemSetPpr,
                         PRIVILEGE_USER); // Set PPR
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_GET_PPR, NULL,
                         ipmiOemGetPpr,
                         PRIVILEGE_USER); // Get PPR
    ipmiPrintAndRegister(ipmi::netFnOemOne, CMD_OEM_GET_FRU_ID, NULL,
                         ipmiOemGetEeprom,
                         PRIVILEGE_USER); // Get FRU ID
    /* FB OEM QC Commands */
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFour,
                          CMD_OEM_Q_SET_PROC_INFO, ipmi::Privilege::User,
                          ipmiOemQSetProcInfo); // Set Proc Info
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFour,
                          CMD_OEM_Q_GET_PROC_INFO, ipmi::Privilege::User,
                          ipmiOemQGetProcInfo); // Get Proc Info
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFour,
                          ipmi::cmdSetQDimmInfo, ipmi::Privilege::User,
                          ipmiOemQSetDimmInfo); // Set Dimm Info
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFour,
                          ipmi::cmdGetQDimmInfo, ipmi::Privilege::User,
                          ipmiOemQGetDimmInfo); // Get Dimm Info
    ipmiPrintAndRegister(NETFUN_FB_OEM_QC, CMD_OEM_Q_SET_DRIVE_INFO, NULL,
                         ipmiOemQSetDriveInfo,
                         PRIVILEGE_USER); // Set Drive Info
    ipmiPrintAndRegister(NETFUN_FB_OEM_QC, CMD_OEM_Q_GET_DRIVE_INFO, NULL,
                         ipmiOemQGetDriveInfo,
                         PRIVILEGE_USER); // Get Drive Info

    /* FB OEM DCMI Commands as per DCMI spec 1.5 Section 6 */
    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, groupDCMI, ipmi::dcmi::cmdGetPowerReading,
        ipmi::Privilege::User,
        ipmiOemDCMIGetPowerReading); // Get Power Reading

    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, groupDCMI, ipmi::dcmi::cmdGetPowerLimit,
        ipmi::Privilege::User,
        ipmiOemDCMIGetPowerLimit); // Get Power Limit

    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, groupDCMI, ipmi::dcmi::cmdSetPowerLimit,
        ipmi::Privilege::Operator,
        ipmiOemDCMISetPowerLimit); // Set Power Limit

    ipmi::registerGroupHandler(
        ipmi::prioOpenBmcBase, groupDCMI, ipmi::dcmi::cmdActDeactivatePwrLimit,
        ipmi::Privilege::Operator,
        ipmiOemDCMIApplyPowerLimit); // Apply Power Limit

    /* FB OEM BOOT ORDER COMMANDS */
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne,
                          CMD_OEM_GET_BOOT_ORDER, ipmi::Privilege::User,
                          ipmiOemGetBootOrder); // Get Boot Order

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne,
                          CMD_OEM_SET_BOOT_ORDER, ipmi::Privilege::User,
                          ipmiOemSetBootOrder); // Set Boot Order

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne,
                          CMD_OEM_GET_HTTPS_BOOT_DATA, ipmi::Privilege::User,
                          ipmiOemGetHttpsData);

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne,
                          CMD_OEM_GET_HTTPS_BOOT_ATTR, ipmi::Privilege::User,
                          ipmiOemGetHttpsAttr);

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemOne,
                          CMD_OEM_CRASHDUMP, ipmi::Privilege::User,
                          ipmiOemCrashdump);

    return;
}

} // namespace ipmi
