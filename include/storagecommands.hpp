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
#include <phosphor-ipmi-host/sensorhandler.hpp>

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
