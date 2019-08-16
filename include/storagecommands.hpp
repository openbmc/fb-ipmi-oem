/*
 * Copyright (c)  2018-present Facebook. All Rights Reserved.
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

#pragma once
#include "sdrutils.hpp"

#define SEL_JSON_DATA_FILE "/var/log/fbSelRaw.json"
#define KEY_SEL_COUNT "SelCount"
#define KEY_SEL_ENTRY_RAW "SelEntry"
#define KEY_ADD_TIME "AddTimeStamp"
#define KEY_ERASE_TIME "EraseTimeStamp"
#define KEY_FREE_SPACE "FreeSpace"
#define KEY_OPER_SUPP "OperationalSupport"
#define KEY_SEL_VER "SELVersion"
#define BIT(value, index) ((value >> index) & 1)

static constexpr uint8_t ipmiSdrVersion = 0x51;

#pragma pack(push, 1)

struct GetSDRReq
{
    uint16_t reservationID;
    uint16_t recordID;
    uint8_t offset;
    uint8_t bytesToRead;
};

struct GetFRUAreaReq
{
    uint8_t fruDeviceID;
    uint16_t fruInventoryOffset;
    uint8_t countToRead;
};

struct WriteFRUDataReq
{
    uint8_t fruDeviceID;
    uint16_t fruInventoryOffset;
    uint8_t data[];
};

#pragma pack(pop)

enum class GetFRUAreaAccessType : uint8_t
{
    byte = 0x0,
    words = 0x1
};

enum class IPMINetfnStorageCmds : ipmi_cmd_t
{
    ipmiCmdGetFRUInvAreaInfo = 0x10,
    ipmiCmdReadFRUData = 0x11,
    ipmiCmdWriteFRUData = 0x12,
    ipmiCmdGetRepositoryInfo = 0x20,
    ipmiCmdGetSDRAllocationInfo = 0x21,
    ipmiCmdReserveSDR = 0x22,
    ipmiCmdGetSDR = 0x23,
    ipmiCmdGetSELInfo = 0x40,
    ipmiCmdReserveSEL = 0x42,
    ipmiCmdGetSELEntry = 0x43,
    ipmiCmdAddSEL = 0x44,
    ipmiCmdDeleteSEL = 0x46,
    ipmiCmdClearSEL = 0x47,
    ipmiCmdGetSELTime = 0x48,
    ipmiCmdSetSELTime = 0x49,
};

#pragma pack(push, 1)
struct FRUHeader
{
    uint8_t commonHeaderFormat;
    uint8_t internalOffset;
    uint8_t chassisOffset;
    uint8_t boardOffset;
    uint8_t productOffset;
    uint8_t multiRecordOffset;
    uint8_t pad;
    uint8_t checksum;
};
#pragma pack(pop)

namespace fb_oem::ipmi::sel
{

static constexpr auto selVersion = 0x51;
static constexpr auto invalidTimeStamp = 0xFFFFFFFF;
/* Spec indicates that more than 64kB is free */
static constexpr auto freeSpace = 0xFFFF;
static constexpr uint8_t selOperationSupport = 0x02;

static constexpr auto firstEntry = 0x0000;
static constexpr auto lastEntry = 0xFFFF;
static constexpr auto entireRecord = 0xFF;
static constexpr auto selRecordSize = 16;

static constexpr auto stdErr = "Standard";
static constexpr auto oemTSErr = "OEM timestamped";
static constexpr auto fbUniSELErr = "Facebook Unified SEL";
static constexpr auto oemNTSErr = "OEM non-timestamped";
static constexpr auto unknownErr = "Unknown";

static constexpr uint8_t stdErrType = 0x02;
static constexpr uint8_t oemTSErrTypeMin = 0xC0;
static constexpr uint8_t oemTSErrTypeMax = 0xDF;
static constexpr uint8_t oemNTSErrTypeMin = 0xE0;
static constexpr uint8_t fbUniErrType = 0xFB;
static constexpr uint8_t oemNTSErrTypeMax = 0xFF;

static constexpr uint8_t unifiedPcieErr = 0;
static constexpr uint8_t unifiedMemErr = 1;

/* event sensor name in processing SEL */
static constexpr uint8_t memoryEccError = 0x63;
static constexpr uint8_t memoryErrLogDIS = 0x87;

/** @struct GetSELInfoData
 *
 * IPMI response payload data for Get SEL Info request
 */
struct GetSELInfoData
{
    uint8_t selVersion;
    uint16_t entries;
    uint16_t freeSpace;
    uint32_t addTimeStamp;
    uint32_t eraseTimeStamp;
    uint8_t operationSupport;
};

/** @struct GetSELEntryRequest
 *
 *  IPMI payload for Get SEL Entry command request.
 */
struct GetSELEntryRequest
{
    uint16_t reservID; //!< Reservation ID.
    uint16_t recordID; //!< SEL Record ID.
    uint8_t offset;    //!< Offset into record.
    uint8_t readLen;   //!< Bytes to read.
} __attribute__((packed));

/** @struct GetSELEntryResponse
 *
 *  IPMI payload for Get SEL Entry command response.
 */
struct GetSELEntryResponse
{
    uint16_t nextRecordID;  //!< Next RecordID.
    uint8_t recordData[16]; //!< Record Data.
} __attribute__((packed));

/** @struct AddSELEntryRequest
 *
 *  IPMI payload for ADD SEL Entry command request.
 */
struct StdSELEntry
{
    uint16_t recordID;        //!< Record ID.
    uint8_t recordType;       //!< Record Type.
    uint32_t timeStamp;       //!< Timestamp.
    uint16_t generatorID;     //!< Generator ID.
    uint8_t eventMsgRevision; //!< Event Message Revision.
    uint8_t sensorType;       //!< Sensor Type.
    uint8_t sensorNum;        //!< Sensor Number.
    uint8_t eventType;        //!< Event Dir | Event Type.
    uint8_t eventData1;       //!< Event Data 1.
    uint8_t eventData2;       //!< Event Data 2.
    uint8_t eventData3;       //!< Event Data 3.
} __attribute__((packed));

struct TsOemSELEntry
{
    uint16_t recordID;  //!< Record ID.
    uint8_t recordType; //!< Record Type.
    uint32_t timeStamp; //!< Timestamp.
    uint8_t mfrId[3];   //!< Manufacturer Id.
    uint8_t oemData[6]; //!< OEM Data.
} __attribute__((packed));

struct NtsOemSELEntry
{
    uint16_t recordID;   //!< Record ID.
    uint8_t recordType;  //!< Record Type.
    uint8_t oemData[13]; //!< OEM Data.
} __attribute__((packed));

static constexpr auto initiateErase = 0xAA;
static constexpr auto getEraseStatus = 0x00;
static constexpr auto eraseComplete = 0x01;

} // namespace fb_oem::ipmi::sel
