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

#include <ipmid/api.hpp>

#include <boost/algorithm/string/join.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <fstream>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>
#include <storagecommands.hpp>

//----------------------------------------------------------------------
// Platform specific functions for storing app data
//----------------------------------------------------------------------

static void toHexStr(std::vector<uint8_t> &bytes, std::string &hexStr)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (const uint8_t byte : bytes)
    {
        stream << std::setw(2) << static_cast<int>(byte);
    }
    hexStr = stream.str();
}

static int fromHexStr(const std::string hexStr, std::vector<uint8_t> &data)
{
    for (unsigned int i = 0; i < hexStr.size(); i += 2)
    {
        try
        {
            data.push_back(static_cast<uint8_t>(
                std::stoul(hexStr.substr(i, 2), nullptr, 16)));
        }
        catch (std::invalid_argument &e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
        catch (std::out_of_range &e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
    }
    return 0;
}

namespace ipmi
{

namespace storage
{
static void registerSELFunctions() __attribute__((constructor));
static nlohmann::json selDataObj __attribute__((init_priority(101)));

static void flushSelData()
{
    std::ofstream file(SEL_JSON_DATA_FILE);
    file << selDataObj;
    file.close();
    return;
}

static void initSELData()
{
    selDataObj[KEY_SEL_VER] = fb_oem::ipmi::sel::selVersion;
    selDataObj[KEY_SEL_COUNT] = 0;
    selDataObj[KEY_ADD_TIME] = fb_oem::ipmi::sel::invalidTimeStamp;
    selDataObj[KEY_ERASE_TIME] = fb_oem::ipmi::sel::invalidTimeStamp;
    selDataObj[KEY_OPER_SUPP] = fb_oem::ipmi::sel::selOperationSupport;
    /* Spec indicates that more than 64kB is free */
    selDataObj[KEY_FREE_SPACE] = fb_oem::ipmi::sel::freeSpace;
    flushSelData();
}

ipmi::RspType<uint8_t,  // SEL version
              uint16_t, // SEL entry count
              uint16_t, // free space
              uint32_t, // last add timestamp
              uint32_t, // last erase timestamp
              uint8_t>  // operation support
    ipmiStorageGetSELInfo()
{
    uint8_t selVersion = selDataObj[KEY_SEL_VER];
    uint16_t entries = selDataObj[KEY_SEL_COUNT];
    uint16_t freeSpace = selDataObj[KEY_FREE_SPACE];
    uint32_t addTimeStamp = selDataObj[KEY_ADD_TIME];
    uint32_t eraseTimeStamp = selDataObj[KEY_ERASE_TIME];
    uint8_t operationSupport = selDataObj[KEY_OPER_SUPP];

    return ipmi::responseSuccess(selVersion, entries, freeSpace, addTimeStamp,
                                 eraseTimeStamp, operationSupport);
}

ipmi::RspType<uint16_t, std::vector<uint8_t>>
    ipmiStorageGetSELEntry(std::vector<uint8_t> data)
{

    if (data.size() != sizeof(fb_oem::ipmi::sel::GetSELEntryRequest))
    {
        return ipmi::responseReqDataLenInvalid();
    }

    fb_oem::ipmi::sel::GetSELEntryRequest *reqData =
        reinterpret_cast<fb_oem::ipmi::sel::GetSELEntryRequest *>(&data[0]);

    if (reqData->reservID != 0)
    {
        if (!checkSELReservation(reqData->reservID))
        {
            return ipmi::responseInvalidReservationId();
        }
    }

    uint16_t selCnt = selDataObj[KEY_SEL_COUNT];
    if (selCnt == 0)
    {
        return ipmi::responseSensorInvalid();
    }

    /* If it is asked for first entry */
    if (reqData->recordID == fb_oem::ipmi::sel::firstEntry)
    {
        /* First Entry (0x0000) as per Spec */
        reqData->recordID = 1;
    }
    else if (reqData->recordID == fb_oem::ipmi::sel::lastEntry)
    {
        /* Last entry (0xFFFF) as per Spec */
        reqData->recordID = selCnt;
    }

    std::stringstream ss;
    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << reqData->recordID;

    /* Check or the requested SEL Entry, if record is available */
    if (selDataObj.find(ss.str()) == selDataObj.end())
    {
        return ipmi::responseSensorInvalid();
    }

    std::string ipmiRaw = selDataObj[ss.str()][KEY_SEL_ENTRY_RAW];

    std::vector<uint8_t> recDataBytes;
    if (fromHexStr(ipmiRaw, recDataBytes) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    /* Identify the next SEL record ID. If recordID is same as
     * total SeL count then next id should be last entry else
     * it should be incremented by 1 to current RecordID
     */
    uint16_t nextRecord;
    if (reqData->recordID == selCnt)
    {
        nextRecord = fb_oem::ipmi::sel::lastEntry;
    }
    else
    {
        nextRecord = reqData->recordID + 1;
    }

    if (reqData->readLen == fb_oem::ipmi::sel::entireRecord)
    {
        return ipmi::responseSuccess(nextRecord, recDataBytes);
    }
    else
    {
        if (reqData->offset >= fb_oem::ipmi::sel::selRecordSize ||
            reqData->readLen > fb_oem::ipmi::sel::selRecordSize)
        {
            return ipmi::responseUnspecifiedError();
        }
        std::vector<uint8_t> recPartData;

        auto diff = fb_oem::ipmi::sel::selRecordSize - reqData->offset;
        auto readLength = std::min(diff, static_cast<int>(reqData->readLen));

        for (int i = 0; i < readLength; i++)
        {
            recPartData.push_back(recDataBytes[i + reqData->offset]);
        }
        return ipmi::responseSuccess(nextRecord, recPartData);
    }
}

ipmi::RspType<uint16_t> ipmiStorageAddSELEntry(std::vector<uint8_t> data)
{
    /* Per the IPMI spec, need to cancel any reservation when a
     * SEL entry is added
     */
    cancelSELReservation();

    if (data.size() != fb_oem::ipmi::sel::selRecordSize)
    {
        return ipmi::responseReqDataLenInvalid();
    }

    std::string ipmiRaw, logErr;
    toHexStr(data, ipmiRaw);

    /* Log the Raw SEL message to the journal */
    std::string journalMsg = "SEL Entry Added: " + ipmiRaw;
    phosphor::logging::log<phosphor::logging::level::INFO>(
        journalMsg.c_str());

    struct timespec selTime = {};

    if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    selDataObj[KEY_ADD_TIME] = selTime.tv_sec;

    int selCount = selDataObj[KEY_SEL_COUNT];
    selDataObj[KEY_SEL_COUNT] = ++selCount;

    std::stringstream ss;
    ss << std::hex;
    ss << std::setw(2) << std::setfill('0') << selCount;

    selDataObj[ss.str()][KEY_SEL_ENTRY_RAW] = ipmiRaw.c_str();
    flushSelData();

    uint16_t responseID = selCount;
    return ipmi::responseSuccess(responseID);
}

ipmi::RspType<uint8_t> ipmiStorageClearSEL(uint16_t reservationID,
                                           const std::array<uint8_t, 3> &clr,
                                           uint8_t eraseOperation)
{
    if (!checkSELReservation(reservationID))
    {
        return ipmi::responseInvalidReservationId();
    }

    static constexpr std::array<uint8_t, 3> clrExpected = {'C', 'L', 'R'};
    if (clr != clrExpected)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    /* If there is no sel then return erase complete */
    uint16_t selCnt = selDataObj[KEY_SEL_COUNT];
    if (selCnt == 0)
    {
        return ipmi::responseSuccess(fb_oem::ipmi::sel::eraseComplete);
    }

    /* Erasure status cannot be fetched, so always return erasure
     * status as `erase completed`.
     */
    if (eraseOperation == fb_oem::ipmi::sel::getEraseStatus)
    {
        return ipmi::responseSuccess(fb_oem::ipmi::sel::eraseComplete);
    }

    /* Check that initiate erase is correct */
    if (eraseOperation != fb_oem::ipmi::sel::initiateErase)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    /* Per the IPMI spec, need to cancel any reservation when the
     * SEL is cleared
     */
    cancelSELReservation();

    /* Clear the complete Sel Json object and reinitialize it */
    selDataObj.clear();
    initSELData();

    /* Save the erase time */
    struct timespec selTime = {};
    if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }
    selDataObj[KEY_ERASE_TIME] = selTime.tv_sec;
    flushSelData();

    return ipmi::responseSuccess(fb_oem::ipmi::sel::eraseComplete);
}

ipmi::RspType<uint32_t> ipmiStorageGetSELTime()
{
    struct timespec selTime = {};

    if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(selTime.tv_sec);
}

ipmi::RspType<> ipmiStorageSetSELTime(uint32_t selTime)
{
    // Set SEL Time is not supported
    return ipmi::responseInvalidCommand();
}

ipmi::RspType<uint16_t> ipmiStorageGetSELTimeUtcOffset()
{
    /* TODO: For now, the SEL time stamp is based on UTC time,
     * so return 0x0000 as offset. Might need to change once
     * supporting zones in SEL time stamps
     */

    uint16_t utcOffset = 0x0000;
    return ipmi::responseSuccess(utcOffset);
}

void registerSELFunctions()
{
    /* Get App data stored in json file */
    std::ifstream file(SEL_JSON_DATA_FILE);
    if (file)
    {
        file >> selDataObj;
        file.close();
    }

    /* Initialize SelData object if no entries. */
    if (selDataObj.find(KEY_SEL_COUNT) == selDataObj.end())
    {
        initSELData();
    }

    // <Get SEL Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelInfo, ipmi::Privilege::User,
                          ipmiStorageGetSELInfo);

    // <Get SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelEntry, ipmi::Privilege::User,
                          ipmiStorageGetSELEntry);

    // <Add SEL Entry>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdAddSelEntry,
                          ipmi::Privilege::Operator, ipmiStorageAddSELEntry);

    // <Clear SEL>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdClearSel, ipmi::Privilege::Operator,
                          ipmiStorageClearSEL);

    // <Get SEL Time>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelTime, ipmi::Privilege::User,
                          ipmiStorageGetSELTime);

    // <Set SEL Time>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdSetSelTime,
                          ipmi::Privilege::Operator, ipmiStorageSetSELTime);

    // <Get SEL Time UTC Offset>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelTimeUtcOffset,
                          ipmi::Privilege::User,
                          ipmiStorageGetSELTimeUtcOffset);

    return;
}

} // namespace storage
} // namespace ipmi
