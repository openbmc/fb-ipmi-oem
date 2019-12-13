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

#include <boost/container/flat_map.hpp>
#include <commandutils.hpp>
#include <iostream>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>
#include <sensorutils.hpp>
#include <storagecommands.hpp>

namespace ipmi
{

namespace storage
{
void registerStorageFunctions() __attribute__((constructor));

constexpr static const size_t maxMessageSize = 64;
constexpr static const size_t maxFruSdrNameSize = 16;
static constexpr int sensorMapUpdatePeriod = 2;
using SensorMap = std::map<std::string, std::map<std::string, DbusVariant>>;
namespace variant_ns = sdbusplus::message::variant_ns;

using ManagedObjectSensor =
    std::map<sdbusplus::message::object_path,
             std::map<std::string, std::map<std::string, DbusVariant>>>;

static uint16_t sdrReservationID;

static boost::container::flat_map<std::string, ManagedObjectSensor> SensorCache;
static SensorSubTree sensorTree;

void registerSensorFunctions() __attribute__((constructor));
using ManagedObjectType = boost::container::flat_map<
    sdbusplus::message::object_path,
    boost::container::flat_map<
        std::string, boost::container::flat_map<std::string, DbusVariant>>>;
using ManagedEntry = std::pair<
    sdbusplus::message::object_path,
    boost::container::flat_map<
        std::string, boost::container::flat_map<std::string, DbusVariant>>>;

constexpr static const char *fruDeviceServiceName =
    "xyz.openbmc_project.FruDevice";
constexpr static const size_t cacheTimeoutSeconds = 10;

static std::vector<uint8_t> fruCache;
static uint8_t cacheBus = 0xFF;
static uint8_t cacheAddr = 0XFF;

std::unique_ptr<phosphor::Timer> cacheTimer = nullptr;

// we unfortunately have to build a map of hashes in case there is a
// collision to verify our dev-id
boost::container::flat_map<uint8_t, std::pair<uint8_t, uint8_t>> deviceHashes;

static sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());

static bool getSensorMap(std::string sensorConnection, std::string sensorPath,
                         SensorMap &sensorMap)
{
    static boost::container::flat_map<
        std::string, std::chrono::time_point<std::chrono::steady_clock>>
        updateTimeMap;

    auto updateFind = updateTimeMap.find(sensorConnection);
    auto lastUpdate = std::chrono::time_point<std::chrono::steady_clock>();
    if (updateFind != updateTimeMap.end())
    {
        lastUpdate = updateFind->second;
    }

    auto now = std::chrono::steady_clock::now();

    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastUpdate)
            .count() > sensorMapUpdatePeriod)
    {
        updateTimeMap[sensorConnection] = now;

        auto managedObj = dbus.new_method_call(
            sensorConnection.c_str(), "/", "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects");

        ManagedObjectSensor managedObjects;
        try
        {
            auto reply = dbus.call(managedObj);
            reply.read(managedObjects);
        }
        catch (sdbusplus::exception_t &)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error getting managed objects from connection",
                phosphor::logging::entry("CONNECTION=%s",
                                         sensorConnection.c_str()));
            return false;
        }

        SensorCache[sensorConnection] = managedObjects;
    }
    auto connection = SensorCache.find(sensorConnection);
    if (connection == SensorCache.end())
    {
        return false;
    }
    auto path = connection->second.find(sensorPath);
    if (path == connection->second.end())
    {
        return false;
    }
    sensorMap = path->second;

    return true;
}

bool writeFru()
{
    sdbusplus::message::message writeFru = dbus.new_method_call(
        fruDeviceServiceName, "/xyz/openbmc_project/FruDevice",
        "xyz.openbmc_project.FruDeviceManager", "WriteFru");
    writeFru.append(cacheBus, cacheAddr, fruCache);
    try
    {
        sdbusplus::message::message writeFruResp = dbus.call(writeFru);
    }
    catch (sdbusplus::exception_t &)
    {
        // todo: log sel?
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "error writing fru");
        return false;
    }
    return true;
}

void createTimer()
{
    if (cacheTimer == nullptr)
    {
        cacheTimer = std::make_unique<phosphor::Timer>(writeFru);
    }
}

ipmi_ret_t replaceCacheFru(uint8_t devId)
{
    static uint8_t lastDevId = 0xFF;

    bool timerRunning = (cacheTimer != nullptr) && !cacheTimer->isExpired();
    if (lastDevId == devId && timerRunning)
    {
        return IPMI_CC_OK; // cache already up to date
    }
    // if timer is running, stop it and writeFru manually
    else if (timerRunning)
    {
        cacheTimer->stop();
        writeFru();
    }

    sdbusplus::message::message getObjects = dbus.new_method_call(
        fruDeviceServiceName, "/", "org.freedesktop.DBus.ObjectManager",
        "GetManagedObjects");
    ManagedObjectType frus;
    try
    {
        sdbusplus::message::message resp = dbus.call(getObjects);
        resp.read(frus);
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "replaceCacheFru: error getting managed objects");
        return IPMI_CC_RESPONSE_ERROR;
    }

    deviceHashes.clear();

    // hash the object paths to create unique device id's. increment on
    // collision
    std::hash<std::string> hasher;
    for (const auto &fru : frus)
    {
        auto fruIface = fru.second.find("xyz.openbmc_project.FruDevice");
        if (fruIface == fru.second.end())
        {
            continue;
        }

        auto busFind = fruIface->second.find("BUS");
        auto addrFind = fruIface->second.find("ADDRESS");
        if (busFind == fruIface->second.end() ||
            addrFind == fruIface->second.end())
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "fru device missing Bus or Address",
                phosphor::logging::entry("FRU=%s", fru.first.str.c_str()));
            continue;
        }

        uint8_t fruBus =
            sdbusplus::message::variant_ns::get<uint32_t>(busFind->second);
        uint8_t fruAddr =
            sdbusplus::message::variant_ns::get<uint32_t>(addrFind->second);

        uint8_t fruHash = 0;
        // Need to revise this strategy for dev id
        /*
        if (fruBus != 0 || fruAddr != 0)
        {
          fruHash = hasher(fru.first.str);
          // can't be 0xFF based on spec, and 0 is reserved for baseboard
          if (fruHash == 0 || fruHash == 0xFF)
          {
            fruHash = 1;
          }
        }
        */
        std::pair<uint8_t, uint8_t> newDev(fruBus, fruAddr);

        bool emplacePassed = false;
        while (!emplacePassed)
        {
            auto resp = deviceHashes.emplace(fruHash, newDev);
            emplacePassed = resp.second;
            if (!emplacePassed)
            {
                fruHash++;
                // can't be 0xFF based on spec, and 0 is reserved for
                // baseboard
                if (fruHash == 0XFF)
                {
                    fruHash = 0x1;
                }
            }
        }
    }
    auto deviceFind = deviceHashes.find(devId);
    if (deviceFind == deviceHashes.end())
    {
        return IPMI_CC_SENSOR_INVALID;
    }

    fruCache.clear();
    sdbusplus::message::message getRawFru = dbus.new_method_call(
        fruDeviceServiceName, "/xyz/openbmc_project/FruDevice",
        "xyz.openbmc_project.FruDeviceManager", "GetRawFru");
    cacheBus = deviceFind->second.first;
    cacheAddr = deviceFind->second.second;
    getRawFru.append(cacheBus, cacheAddr);
    try
    {
        sdbusplus::message::message getRawResp = dbus.call(getRawFru);
        getRawResp.read(fruCache);
    }
    catch (sdbusplus::exception_t &)
    {
        lastDevId = 0xFF;
        cacheBus = 0xFF;
        cacheAddr = 0xFF;
        return IPMI_CC_RESPONSE_ERROR;
    }

    lastDevId = devId;
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageReadFRUData(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t dataLen,
                                  ipmi_context_t context)
{
    if (*dataLen != 4)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error

    auto req = static_cast<GetFRUAreaReq *>(request);

    if (req->countToRead > maxMessageSize - 1)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    ipmi_ret_t status = replaceCacheFru(req->fruDeviceID);

    if (status != IPMI_CC_OK)
    {
        return status;
    }

    size_t fromFRUByteLen = 0;
    if (req->countToRead + req->fruInventoryOffset < fruCache.size())
    {
        fromFRUByteLen = req->countToRead;
    }
    else if (fruCache.size() > req->fruInventoryOffset)
    {
        fromFRUByteLen = fruCache.size() - req->fruInventoryOffset;
    }
    size_t padByteLen = req->countToRead - fromFRUByteLen;
    uint8_t *respPtr = static_cast<uint8_t *>(response);
    *respPtr = req->countToRead;
    std::copy(fruCache.begin() + req->fruInventoryOffset,
              fruCache.begin() + req->fruInventoryOffset + fromFRUByteLen,
              ++respPtr);
    // if longer than the fru is requested, fill with 0xFF
    if (padByteLen)
    {
        respPtr += fromFRUByteLen;
        std::fill(respPtr, respPtr + padByteLen, 0xFF);
    }
    *dataLen = fromFRUByteLen + 1;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageWriteFRUData(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t dataLen,
                                   ipmi_context_t context)
{
    if (*dataLen < 4 ||
        *dataLen >=
            0xFF + 3) // count written return is one byte, so limit to one
                      // byte of data after the three request data bytes
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    auto req = static_cast<WriteFRUDataReq *>(request);
    size_t writeLen = *dataLen - 3;
    *dataLen = 0; // default to 0 in case of an error

    ipmi_ret_t status = replaceCacheFru(req->fruDeviceID);
    if (status != IPMI_CC_OK)
    {
        return status;
    }
    int lastWriteAddr = req->fruInventoryOffset + writeLen;
    if (fruCache.size() < lastWriteAddr)
    {
        fruCache.resize(req->fruInventoryOffset + writeLen);
    }

    std::copy(req->data, req->data + writeLen,
              fruCache.begin() + req->fruInventoryOffset);

    bool atEnd = false;

    if (fruCache.size() >= sizeof(FRUHeader))
    {

        FRUHeader *header = reinterpret_cast<FRUHeader *>(fruCache.data());

        int lastRecordStart = std::max(
            header->internalOffset,
            std::max(header->chassisOffset,
                     std::max(header->boardOffset, header->productOffset)));
        // TODO: Handle Multi-Record FRUs?

        lastRecordStart *= 8; // header starts in are multiples of 8 bytes

        // get the length of the area in multiples of 8 bytes
        if (lastWriteAddr > (lastRecordStart + 1))
        {
            // second byte in record area is the length
            int areaLength(fruCache[lastRecordStart + 1]);
            areaLength *= 8; // it is in multiples of 8 bytes

            if (lastWriteAddr >= (areaLength + lastRecordStart))
            {
                atEnd = true;
            }
        }
    }
    uint8_t *respPtr = static_cast<uint8_t *>(response);
    if (atEnd)
    {
        // cancel timer, we're at the end so might as well send it
        cacheTimer->stop();
        if (!writeFru())
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        *respPtr = std::min(fruCache.size(), static_cast<size_t>(0xFF));
    }
    else
    {
        // start a timer, if no further data is sent in cacheTimeoutSeconds
        // seconds, check to see if it is valid
        createTimer();
        cacheTimer->start(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds(cacheTimeoutSeconds)));
        *respPtr = 0;
    }

    *dataLen = 1;

    return IPMI_CC_OK;
}

ipmi_ret_t getFruSdrCount(size_t &count)
{
    ipmi_ret_t ret = replaceCacheFru(0);
    if (ret != IPMI_CC_OK)
    {
        return ret;
    }
    count = deviceHashes.size();
    return IPMI_CC_OK;
}

ipmi_ret_t getFruSdrs(size_t index, get_sdr::SensorDataFruRecord &resp)
{
    ipmi_ret_t ret = replaceCacheFru(0); // this will update the hash list
    if (ret != IPMI_CC_OK)
    {
        return ret;
    }
    if (deviceHashes.size() < index)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto device = deviceHashes.begin() + index;
    uint8_t &bus = device->second.first;
    uint8_t &address = device->second.second;

    ManagedObjectType frus;

    sdbusplus::message::message getObjects = dbus.new_method_call(
        fruDeviceServiceName, "/", "org.freedesktop.DBus.ObjectManager",
        "GetManagedObjects");
    try
    {
        sdbusplus::message::message resp = dbus.call(getObjects);
        resp.read(frus);
    }
    catch (sdbusplus::exception_t &)
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    boost::container::flat_map<std::string, DbusVariant> *fruData = nullptr;
    auto fru =
        std::find_if(frus.begin(), frus.end(),
                     [bus, address, &fruData](ManagedEntry &entry) {
                         auto findFruDevice =
                             entry.second.find("xyz.openbmc_project.FruDevice");
                         if (findFruDevice == entry.second.end())
                         {
                             return false;
                         }
                         fruData = &(findFruDevice->second);
                         auto findBus = findFruDevice->second.find("BUS");
                         auto findAddress =
                             findFruDevice->second.find("ADDRESS");
                         if (findBus == findFruDevice->second.end() ||
                             findAddress == findFruDevice->second.end())
                         {
                             return false;
                         }
                         if (sdbusplus::message::variant_ns::get<uint32_t>(
                                 findBus->second) != bus)
                         {
                             return false;
                         }
                         if (sdbusplus::message::variant_ns::get<uint32_t>(
                                 findAddress->second) != address)
                         {
                             return false;
                         }
                         return true;
                     });
    if (fru == frus.end())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    std::string name;
    auto findProductName = fruData->find("BOARD_PRODUCT_NAME");
    auto findBoardName = fruData->find("PRODUCT_PRODUCT_NAME");
    if (findProductName != fruData->end())
    {
        name = sdbusplus::message::variant_ns::get<std::string>(
            findProductName->second);
    }
    else if (findBoardName != fruData->end())
    {
        name = sdbusplus::message::variant_ns::get<std::string>(
            findBoardName->second);
    }
    else
    {
        name = "UNKNOWN";
    }
    if (name.size() > maxFruSdrNameSize)
    {
        name = name.substr(0, maxFruSdrNameSize);
    }
    size_t sizeDiff = maxFruSdrNameSize - name.size();

    resp.header.record_id_lsb = 0x0; // calling code is to implement these
    resp.header.record_id_msb = 0x0;
    resp.header.sdr_version = ipmiSdrVersion;
    resp.header.record_type = 0x11; // FRU Device Locator
    resp.header.record_length = sizeof(resp.body) + sizeof(resp.key) - sizeDiff;
    resp.key.deviceAddress = 0x20;
    resp.key.fruID = device->first;
    resp.key.accessLun = 0x80; // logical / physical fru device
    resp.key.channelNumber = 0x0;
    resp.body.reserved = 0x0;
    resp.body.deviceType = 0x10;
    resp.body.entityID = 0x0;
    resp.body.entityInstance = 0x1;
    resp.body.oem = 0x0;
    resp.body.deviceIDLen = name.size();
    name.copy(resp.body.deviceID, name.size());

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageReserveSDR(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t dataLen,
                                 ipmi_context_t context)
{
    printCommand(+netfn, +cmd);

    if (*dataLen)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error
    sdrReservationID++;
    if (sdrReservationID == 0)
    {
        sdrReservationID++;
    }
    *dataLen = 2;
    auto resp = static_cast<uint8_t *>(response);
    resp[0] = sdrReservationID & 0xFF;
    resp[1] = sdrReservationID >> 8;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageGetSDR(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t dataLen, ipmi_context_t context)
{
    printCommand(+netfn, +cmd);

    if (*dataLen != 6)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    auto requestedSize = *dataLen;
    *dataLen = 0; // default to 0 in case of an error

    constexpr uint16_t lastRecordIndex = 0xFFFF;
    auto req = static_cast<GetSDRReq *>(request);

    // reservation required for partial reads with non zero offset into
    // record
    if ((sdrReservationID == 0 || req->reservationID != sdrReservationID) &&
        req->offset)
    {
        return IPMI_CC_INVALID_RESERVATION_ID;
    }

    if (sensorTree.empty() && !getSensorSubtree(sensorTree))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    size_t fruCount = 0;
    ipmi_ret_t ret = ipmi::storage::getFruSdrCount(fruCount);
    if (ret != IPMI_CC_OK)
    {
        return ret;
    }

    size_t lastRecord = sensorTree.size() + fruCount - 1;
    if (req->recordID == lastRecordIndex)
    {
        req->recordID = lastRecord;
    }
    if (req->recordID > lastRecord)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    uint16_t nextRecord =
        lastRecord > (req->recordID + 1) ? req->recordID + 1 : 0XFFFF;

    auto responseClear = static_cast<uint8_t *>(response);
    std::fill(responseClear, responseClear + requestedSize, 0);

    auto resp = static_cast<get_sdr::GetSdrResp *>(response);
    resp->next_record_id_lsb = nextRecord & 0xFF;
    resp->next_record_id_msb = nextRecord >> 8;

    if (req->recordID >= sensorTree.size())
    {
        size_t fruIndex = req->recordID - sensorTree.size();
        if (fruIndex >= fruCount)
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        get_sdr::SensorDataFruRecord data;
        if (req->offset > sizeof(data))
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        ret = ipmi::storage::getFruSdrs(fruIndex, data);
        if (ret != IPMI_CC_OK)
        {
            return ret;
        }
        data.header.record_id_msb = req->recordID << 8;
        data.header.record_id_lsb = req->recordID & 0xFF;
        if (sizeof(data) < (req->offset + req->bytesToRead))
        {
            req->bytesToRead = sizeof(data) - req->offset;
        }
        *dataLen = req->bytesToRead + 2; // next record
        std::memcpy(&resp->record_data, (char *)&data + req->offset,
                    req->bytesToRead);
        return IPMI_CC_OK;
    }

    std::string connection;
    std::string path;
    uint16_t sensorIndex = req->recordID;
    for (const auto &sensor : sensorTree)
    {
        if (sensorIndex-- == 0)
        {
            if (!sensor.second.size())
            {
                return IPMI_CC_RESPONSE_ERROR;
            }
            connection = sensor.second.begin()->first;
            path = sensor.first;
            break;
        }
    }

    SensorMap sensorMap;
    if (!getSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    uint8_t sensornumber = (req->recordID & 0xFF);
    get_sdr::SensorDataFullRecord record = {0};

    record.header.record_id_msb = req->recordID << 8;
    record.header.record_id_lsb = req->recordID & 0xFF;
    record.header.sdr_version = ipmiSdrVersion;
    record.header.record_type = get_sdr::SENSOR_DATA_FULL_RECORD;
    record.header.record_length = sizeof(get_sdr::SensorDataFullRecord) -
                                  sizeof(get_sdr::SensorDataRecordHeader);
    record.key.owner_id = 0x20;
    record.key.owner_lun = 0x0;
    record.key.sensor_number = sensornumber;

    record.body.entity_id = 0x0;
    record.body.entity_instance = 0x01;
    record.body.sensor_capabilities = 0x60; // auto rearm - todo hysteresis
    record.body.sensor_type = getSensorTypeFromPath(path);
    std::string type = getSensorTypeStringFromPath(path);
    auto typeCstr = type.c_str();
    auto findUnits = sensorUnits.find(typeCstr);
    if (findUnits != sensorUnits.end())
    {
        record.body.sensor_units_2_base =
            static_cast<uint8_t>(findUnits->second);
    } // else default 0x0 unspecified

    record.body.event_reading_type = getSensorEventTypeFromPath(path);

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");
    if (sensorObject == sensorMap.end())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    auto maxObject = sensorObject->second.find("MaxValue");
    auto minObject = sensorObject->second.find("MinValue");
    double max = 128;
    double min = -127;
    if (maxObject != sensorObject->second.end())
    {
        max = variant_ns::visit(VariantToDoubleVisitor(), maxObject->second);
    }

    if (minObject != sensorObject->second.end())
    {
        min = variant_ns::visit(VariantToDoubleVisitor(), minObject->second);
    }

    int16_t mValue;
    int8_t rExp;
    int16_t bValue;
    int8_t bExp;
    bool bSigned;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    // apply M, B, and exponents, M and B are 10 bit values, exponents are 4
    record.body.m_lsb = mValue & 0xFF;

    // move the smallest bit of the MSB into place (bit 9)
    // the MSbs are bits 7:8 in m_msb_and_tolerance
    uint8_t mMsb = (mValue & (1 << 8)) > 0 ? (1 << 6) : 0;

    // assign the negative
    if (mValue < 0)
    {
        mMsb |= (1 << 7);
    }
    record.body.m_msb_and_tolerance = mMsb;

    record.body.b_lsb = bValue & 0xFF;

    // move the smallest bit of the MSB into place
    // the MSbs are bits 7:8 in b_msb_and_accuracy_lsb
    uint8_t bMsb = (bValue & (1 << 8)) > 0 ? (1 << 6) : 0;

    // assign the negative
    if (bValue < 0)
    {
        bMsb |= (1 << 7);
    }
    record.body.b_msb_and_accuracy_lsb = bMsb;

    record.body.r_b_exponents = bExp & 0x7;
    if (bExp < 0)
    {
        record.body.r_b_exponents |= 1 << 3;
    }
    record.body.r_b_exponents = (rExp & 0x7) << 4;
    if (rExp < 0)
    {
        record.body.r_b_exponents |= 1 << 7;
    }

    // todo fill out rest of units
    if (bSigned)
    {
        record.body.sensor_units_1 = 1 << 7;
    }

    // populate sensor name from path
    std::string name;
    size_t nameStart = path.rfind("/");
    if (nameStart != std::string::npos)
    {
        name = path.substr(nameStart + 1, std::string::npos - nameStart);
    }

    std::replace(name.begin(), name.end(), '_', ' ');
    if (name.size() > FULL_RECORD_ID_STR_MAX_LENGTH)
    {
        name.resize(FULL_RECORD_ID_STR_MAX_LENGTH);
    }
    record.body.id_string_info = name.size();
    std::strncpy(record.body.id_string, name.c_str(),
                 sizeof(record.body.id_string));

    if (sizeof(get_sdr::SensorDataFullRecord) <
        (req->offset + req->bytesToRead))
    {
        req->bytesToRead = sizeof(get_sdr::SensorDataFullRecord) - req->offset;
    }

    *dataLen =
        2 + req->bytesToRead; // bytesToRead + MSB and LSB of next record id

    std::memcpy(&resp->record_data, (char *)&record + req->offset,
                req->bytesToRead);

    return IPMI_CC_OK;
}

static int getSensorConnectionByName(std::string &name, std::string &connection,
                                     std::string &path)
{
    if (sensorTree.empty() && !getSensorSubtree(sensorTree))
    {
        return -1;
    }

    for (const auto &sensor : sensorTree)
    {
        path = sensor.first;
        if (path.find(name) != std::string::npos)
        {
            connection = sensor.second.begin()->first;
            return 0;
        }
    }
    return -1;
}

int getSensorValue(std::string &name, double &val)
{
    std::string connection;
    std::string path;
    int ret = -1;

    ret = getSensorConnectionByName(name, connection, path);
    if (ret < 0)
    {
        return ret;
    }

    SensorMap sensorMap;
    if (!getSensorMap(connection, path, sensorMap))
    {
        return ret;
    }
    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");

    if (sensorObject == sensorMap.end() ||
        sensorObject->second.find("Value") == sensorObject->second.end())
    {
        return ret;
    }
    auto &valueVariant = sensorObject->second["Value"];
    val = std::visit(VariantToDoubleVisitor(), valueVariant);

    return 0;
}

const static boost::container::flat_map<const char *, std::string, CmpStr>
    sensorUnitStr{{{"temperature", "C"},
                   {"voltage", "V"},
                   {"current", "mA"},
                   {"fan_tach", "RPM"},
                   {"fan_pwm", "RPM"},
                   {"power", "W"}}};

int getSensorUnit(std::string &name, std::string &unit)
{
    std::string connection;
    std::string path;
    int ret = -1;

    ret = getSensorConnectionByName(name, connection, path);
    if (ret < 0)
    {
        return ret;
    }

    std::string sensorTypeStr = getSensorTypeStringFromPath(path);
    auto findSensor = sensorUnitStr.find(sensorTypeStr.c_str());
    if (findSensor != sensorUnitStr.end())
    {
        unit = findSensor->second;
        return 0;
    }
    else
        return -1;
}

void registerStorageFunctions()
{
    // <READ FRU Data>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdReadFRUData), NULL,
        ipmiStorageReadFRUData, PRIVILEGE_OPERATOR);

    // <WRITE FRU Data>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdWriteFRUData),
        NULL, ipmiStorageWriteFRUData, PRIVILEGE_OPERATOR);

    // <Reserve SDR Repo>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdReserveSDR),
        nullptr, ipmiStorageReserveSDR, PRIVILEGE_USER);

    // <Get Sdr>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdGetSDR), nullptr,
        ipmiStorageGetSDR, PRIVILEGE_USER);
    return;
}
} // namespace storage
} // namespace ipmi
