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

#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <fstream>
#include <phosphor-logging/log.hpp>
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

namespace fb_oem::ipmi::sel
{

class SELData
{
  private:
    nlohmann::json selDataObj;

    void flush()
    {
        std::ofstream file(SEL_JSON_DATA_FILE);
        file << selDataObj;
        file.close();
    }

    void init()
    {
        selDataObj[KEY_SEL_VER] = 0x51;
        selDataObj[KEY_SEL_COUNT] = 0;
        selDataObj[KEY_ADD_TIME] = 0xFFFFFFFF;
        selDataObj[KEY_ERASE_TIME] = 0xFFFFFFFF;
        selDataObj[KEY_OPER_SUPP] = 0x02;
        /* Spec indicates that more than 64kB is free */
        selDataObj[KEY_FREE_SPACE] = 0xFFFF;
    }

  public:
    SELData()
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
            init();
        }
    }

    int clear()
    {
        /* Clear the complete Sel Json object */
        selDataObj.clear();
        /* Reinitialize it with basic data */
        init();
        /* Save the erase time */
        struct timespec selTime = {};
        if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
        {
            return -1;
        }
        selDataObj[KEY_ERASE_TIME] = selTime.tv_sec;
        flush();
        return 0;
    }

    uint32_t getCount()
    {
        return selDataObj[KEY_SEL_COUNT];
    }

    void getInfo(GetSELInfoData &info)
    {
        info.selVersion = selDataObj[KEY_SEL_VER];
        info.entries = selDataObj[KEY_SEL_COUNT];
        info.freeSpace = selDataObj[KEY_FREE_SPACE];
        info.addTimeStamp = selDataObj[KEY_ADD_TIME];
        info.eraseTimeStamp = selDataObj[KEY_ERASE_TIME];
        info.operationSupport = selDataObj[KEY_OPER_SUPP];
    }

    int getEntry(uint32_t index, std::string &rawStr)
    {
        std::stringstream ss;
        ss << std::hex;
        ss << std::setw(2) << std::setfill('0') << index;

        /* Check or the requested SEL Entry, if record is available */
        if (selDataObj.find(ss.str()) == selDataObj.end())
        {
            return -1;
        }

        rawStr = selDataObj[ss.str()][KEY_SEL_ENTRY_RAW];
        return 0;
    }

    int addEntry(std::string keyStr)
    {
        struct timespec selTime = {};

        if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
        {
            return -1;
        }

        selDataObj[KEY_ADD_TIME] = selTime.tv_sec;

        int selCount = selDataObj[KEY_SEL_COUNT];
        selDataObj[KEY_SEL_COUNT] = ++selCount;

        std::stringstream ss;
        ss << std::hex;
        ss << std::setw(2) << std::setfill('0') << selCount;

        selDataObj[ss.str()][KEY_SEL_ENTRY_RAW] = keyStr;
        flush();
        return selCount;
    }
};

} // namespace fb_oem::ipmi::sel

namespace ipmi
{

namespace storage
{

static void registerSELFunctions() __attribute__((constructor));
static fb_oem::ipmi::sel::SELData selObj __attribute__((init_priority(101)));

ipmi::RspType<uint8_t,  // SEL version
              uint16_t, // SEL entry count
              uint16_t, // free space
              uint32_t, // last add timestamp
              uint32_t, // last erase timestamp
              uint8_t>  // operation support
    ipmiStorageGetSELInfo()
{

    fb_oem::ipmi::sel::GetSELInfoData info;

    selObj.getInfo(info);
    return ipmi::responseSuccess(info.selVersion, info.entries, info.freeSpace,
                                 info.addTimeStamp, info.eraseTimeStamp,
                                 info.operationSupport);
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

    uint16_t selCnt = selObj.getCount();
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

    std::string ipmiRaw;

    if (selObj.getEntry(reqData->recordID, ipmiRaw) < 0)
    {
        return ipmi::responseSensorInvalid();
    }

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
    phosphor::logging::log<phosphor::logging::level::INFO>(journalMsg.c_str());

    int responseID = selObj.addEntry(ipmiRaw.c_str());
    if (responseID < 0)
    {
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess((uint16_t)responseID);
}

void registerSELFunctions()
{
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

    return;
}

} // namespace storage
} // namespace ipmi
