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

static void parseStdSel(StdSELEntry *data, std::string &errStr)
{
    std::stringstream tmpStream;
    tmpStream << std::hex << std::uppercase;

    /* TODO: add pal_add_cri_sel */
    switch (data->sensorNum)
    {
        case memoryEccError:
            switch (data->eventData1 & 0x0F)
            {
                case 0x00:
                    errStr = "Correctable";
                    tmpStream << "DIMM" << std::setw(2) << std::setfill('0')
                              << data->eventData3 << " ECC err";
                    break;
                case 0x01:
                    errStr = "Uncorrectable";
                    tmpStream << "DIMM" << std::setw(2) << std::setfill('0')
                              << data->eventData3 << " UECC err";
                    break;
                case 0x02:
                    errStr = "Parity";
                    break;
                case 0x05:
                    errStr = "Correctable ECC error Logging Limit Reached";
                    break;
                default:
                    errStr = "Unknown";
            }
            break;
        case memoryErrLogDIS:
            if ((data->eventData1 & 0x0F) == 0)
            {
                errStr = "Correctable Memory Error Logging Disabled";
            }
            else
            {
                errStr = "Unknown";
            }
            break;
        default:

            /* TODO: parse sel helper */
            errStr = "Unknown";
            return;
    }

    errStr += " (DIMM " + std::to_string(data->eventData3) + ")";
    errStr += " Logical Rank " + std::to_string(data->eventData2 & 0x03);

    switch ((data->eventData2 & 0x0C) >> 2)
    {
        case 0x00:
            // Ignore when " All info available"
            break;
        case 0x01:
            errStr += " DIMM info not valid";
            break;
        case 0x02:
            errStr += " CHN info not valid";
            break;
        case 0x03:
            errStr += " CPU info not valid";
            break;
        default:
            errStr += " Unknown";
    }

    if (((data->eventType & 0x80) >> 7) == 0)
    {
        errStr += " Assertion";
    }
    else
    {
        errStr += " Deassertion";
    }

    return;
}

static void parseOemSel(TsOemSELEntry *data, std::string &errStr)
{
    std::stringstream tmpStream;
    tmpStream << std::hex << std::uppercase << std::setfill('0');

    switch (data->recordType)
    {
        case 0xC0:
            tmpStream << "VID:0x" << std::setw(2) << (int)data->oemData[1]
                      << std::setw(2) << (int)data->oemData[0] << " DID:0x"
                      << std::setw(2) << (int)data->oemData[3] << std::setw(2)
                      << (int)data->oemData[2] << " Slot:0x" << std::setw(2)
                      << (int)data->oemData[4] << " Error ID:0x" << std::setw(2)
                      << (int)data->oemData[5];
            break;
        case 0xC2:
            tmpStream << "Extra info:0x" << std::setw(2)
                      << (int)data->oemData[1] << " MSCOD:0x" << std::setw(2)
                      << (int)data->oemData[3] << std::setw(2)
                      << (int)data->oemData[2] << " MCACOD:0x" << std::setw(2)
                      << (int)data->oemData[5] << std::setw(2)
                      << (int)data->oemData[4];
            break;
        case 0xC3:
            int bank = (data->oemData[1] & 0xf0) >> 4;
            int col = ((data->oemData[1] & 0x0f) << 8) | data->oemData[2];

            tmpStream << "Fail Device:0x" << std::setw(2)
                      << (int)data->oemData[0] << " Bank:0x" << std::setw(2)
                      << bank << " Column:0x" << std::setw(2) << col
                      << " Failed Row:0x" << std::setw(2)
                      << (int)data->oemData[3] << std::setw(2)
                      << (int)data->oemData[4] << std::setw(2)
                      << (int)data->oemData[5];
    }

    errStr = tmpStream.str();

    return;
}

static void parseOemUnifiedSel(NtsOemSELEntry *data, std::string &errStr)
{
    uint8_t *ptr = data->oemData;
    int genInfo = ptr[0];
    int errType = genInfo & 0x0f;
    std::vector<std::string> dimmEvent = {
        "Memory training failure", "Memory correctable error",
        "Memory uncorrectable error", "Reserved"};

    std::stringstream tmpStream;
    tmpStream << std::hex << std::uppercase << std::setfill('0');

    switch (errType)
    {
        case unifiedPcieErr:
            if (((genInfo & 0x10) >> 4) == 0) // x86
            {
                tmpStream << "GeneralInfo: x86/PCIeErr(0x" << std::setw(2)
                          << genInfo << "),";
            }
            else
            {
                tmpStream << "GeneralInfo: ARM/PCIeErr(0x" << std::setw(2)
                          << genInfo << "), Aux. Info: 0x" << std::setw(4)
                          << (int)((ptr[6] << 8) | ptr[5]) << ",";
            }

            tmpStream << " Bus " << std::setw(2) << (int)(ptr[8]) << "/Dev "
                      << std::setw(2) << (int)(ptr[7] >> 3) << "/Fun "
                      << std::setw(2) << (int)(ptr[7] & 0x7)
                      << ", TotalErrID1Cnt: 0x" << std::setw(4)
                      << (int)((ptr[10] << 8) | ptr[9]) << ", ErrID2: 0x"
                      << std::setw(2) << (int)(ptr[11]) << ", ErrID1: 0x"
                      << std::setw(2) << (int)(ptr[12]);

            break;
        case unifiedMemErr:
            tmpStream << "GeneralInfo: MemErr(0x" << std::setw(2) << genInfo
                      << "), DIMM Slot Location: Sled " << std::setw(2)
                      << (int)((ptr[5] >> 4) & 0x03) << "/Socket "
                      << std::setw(2) << (int)(ptr[5] & 0x0f) << ", Channel "
                      << std::setw(2) << (int)(ptr[6] & 0x0f) << ", Slot "
                      << std::setw(2) << (int)(ptr[7] & 0x0f)
                      << ", DIMM Failure Event: " << dimmEvent[(ptr[9] & 0x03)]
                      << ", Major Code: 0x" << std::setw(2) << (int)(ptr[10])
                      << ", Minor Code: 0x" << std::setw(2) << (int)(ptr[11]);

            break;
        default:
            std::vector<uint8_t> oemData(ptr, ptr + 13);
            std::string oemDataStr;
            toHexStr(oemData, oemDataStr);
            tmpStream << "Undefined Error Type(0x" << std::setw(2) << errType
                      << "), Raw: " << oemDataStr;
    }

    errStr = tmpStream.str();

    return;
}

static void parseSelData(std::vector<uint8_t> &reqData, std::string &msgLog)
{

    /* Get record type */
    int recType = reqData[2];
    std::string errType, errLog;

    uint8_t *ptr = NULL;

    std::stringstream recTypeStream;
    recTypeStream << std::hex << std::uppercase << std::setfill('0')
                  << std::setw(2) << recType;

    msgLog = "SEL Entry: FRU: 1, Record: ";

    if (recType == stdErrType)
    {
        StdSELEntry *data = reinterpret_cast<StdSELEntry *>(&reqData[0]);
        std::string sensorName;

        errType = stdErr;
        if (data->sensorType == 0x1F)
        {
            sensorName = "OS";
        }
        else
        {
            auto findSensorName = sensorNameTable.find(data->sensorNum);
            if (findSensorName == sensorNameTable.end())
            {
                sensorName = "Unknown";
            }
            else
            {
                sensorName = findSensorName->second;
            }
        }

        std::tm *ts = localtime((time_t *)(&(data->timeStamp)));
        std::string timeStr = std::asctime(ts);

        parseStdSel(data, errLog);
        ptr = &(data->eventData1);
        std::vector<uint8_t> evtData(ptr, ptr + 3);
        std::string eventData;
        toHexStr(evtData, eventData);

        std::stringstream senNumStream;
        senNumStream << std::hex << std::uppercase << std::setfill('0')
                     << std::setw(2) << (int)(data->sensorNum);

        msgLog += errType + " (0x" + recTypeStream.str() +
                  "), Time: " + timeStr + ", Sensor: " + sensorName + " (0x" +
                  senNumStream.str() + "), Event Data: (" + eventData + ") " +
                  errLog;
    }
    else if ((recType >= oemTSErrTypeMin) && (recType <= oemTSErrTypeMax))
    {
        /* timestamped OEM SEL records */
        TsOemSELEntry *data = reinterpret_cast<TsOemSELEntry *>(&reqData[0]);
        ptr = data->mfrId;
        std::vector<uint8_t> mfrIdData(ptr, ptr + 3);
        std::string mfrIdStr;
        toHexStr(mfrIdData, mfrIdStr);

        ptr = data->oemData;
        std::vector<uint8_t> oemData(ptr, ptr + 6);
        std::string oemDataStr;
        toHexStr(oemData, oemDataStr);

        std::tm *ts = localtime((time_t *)(&(data->timeStamp)));
        std::string timeStr = std::asctime(ts);

        errType = oemTSErr;
        parseOemSel(data, errLog);

        msgLog += errType + " (0x" + recTypeStream.str() +
                  "), Time: " + timeStr + ", MFG ID: " + mfrIdStr +
                  ", OEM Data: (" + oemDataStr + ") " + errLog;
    }
    else if (recType == fbUniErrType)
    {
        NtsOemSELEntry *data = reinterpret_cast<NtsOemSELEntry *>(&reqData[0]);
        errType = fbUniSELErr;
        parseOemUnifiedSel(data, errLog);
        msgLog += errType + " (0x" + recTypeStream.str() + "), " + errLog;
    }
    else if ((recType >= oemNTSErrTypeMin) && (recType <= oemNTSErrTypeMax))
    {
        /* Non timestamped OEM SEL records */
        NtsOemSELEntry *data = reinterpret_cast<NtsOemSELEntry *>(&reqData[0]);
        errType = oemNTSErr;

        ptr = data->oemData;
        std::vector<uint8_t> oemData(ptr, ptr + 13);
        std::string oemDataStr;
        toHexStr(oemData, oemDataStr);

        parseOemSel((TsOemSELEntry *)data, errLog);
        msgLog += errType + " (0x" + recTypeStream.str() + "), OEM Data: (" +
                  oemDataStr + ") " + errLog;
    }
    else
    {
        errType = unknownErr;
        toHexStr(reqData, errLog);
        msgLog +=
            errType + " (0x" + recTypeStream.str() + ") RawData: " + errLog;
    }
}

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

    /* Parse sel data and get an error log to be filed */
    fb_oem::ipmi::sel::parseSelData(data, logErr);

    /* Log the Raw SEL message to the journal */
    std::string journalMsg = "SEL Entry Added: " + ipmiRaw;

    phosphor::logging::log<phosphor::logging::level::INFO>(journalMsg.c_str());
    phosphor::logging::log<phosphor::logging::level::INFO>(logErr.c_str());

    int responseID = selObj.addEntry(ipmiRaw.c_str());
    if (responseID < 0)
    {
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess((uint16_t)responseID);
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
    if (selObj.getCount() == 0)
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

    /* Clear the complete Sel Json object */
    if (selObj.clear() < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

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
