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
#include <commandutils.hpp>
#include <iostream>
#include <sstream>
#include <fstream>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <storagecommands.hpp>

#define SEL_JSON_DATA_FILE "/etc/appSel.json"
#define KEY_SEL_COUNT "SelCount"
#define KEY_SEL_ENTRY_RAW "SelEntry"
namespace ipmi
{

namespace storage
{
static void registerSELFunctions() __attribute__((constructor));
static nlohmann::json appSelData;


//----------------------------------------------------------------------
// Platform specific functions for storing app data
//----------------------------------------------------------------------

static void flushSelData()
{
    std::ofstream file("/etc/appSel.json");
    file << appSelData;
    return;
}

static void toHexStr(std::vector<uint8_t>& bytes,
                     std::string& hexStr)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (const uint8_t byte : bytes)
    {
        stream << std::setw(2) << static_cast<int>(byte);
    }
    hexStr = stream.str();
}

ipmi::RspType<> ipmiStorageGetSELInfo(uint32_t selTime)
{
    // Set SEL Time is not supported
    return ipmi::responseInvalidCommand();
}

ipmi::RspType<> ipmiStorageGetSELEntry(uint32_t selTime)
{
    // Set SEL Time is not supported
    return ipmi::responseInvalidCommand();
}

ipmi::RspType<uint16_t> ipmiStorageAddSELEntry1(std::vector<uint8_t> data)
{
		//std::cout << "Vijay sel count: " << appSelData[KEY_SEL_COUNT] << "\n";
    // Per the IPMI spec, need to cancel any reservation when a SEL entry is
    // added
    // cancelSELReservation();

		std::string ipmiRaw;
		toHexStr(data, ipmiRaw);

    static const std::string openBMCMessageRegistryVersion("0.2");
    std::string messageID =
        "OpenBMC." + openBMCMessageRegistryVersion + ".SELEntryAdded";

    std::vector<std::string> messageArgs;
    messageArgs.push_back(ipmiRaw);

    // Log the Redfish message to the journal with the appropriate metadata
    std::string journalMsg = "BIOS SEL Entry Added: " + ipmiRaw;
    //std::string messageArgsString = boost::algorithm::join(messageArgs, ",");
    std::string messageArgsString = messageArgs[0];
    phosphor::logging::log<phosphor::logging::level::INFO>(
        journalMsg.c_str(),
        phosphor::logging::entry("REDFISH_MESSAGE_ID=%s", messageID.c_str()),
        phosphor::logging::entry("REDFISH_MESSAGE_ARGS=%s",
                                 messageArgsString.c_str()));

		std::cout << "Vijay sel count: " << appSelData[KEY_SEL_COUNT] << "\n";

		int selCount = appSelData[KEY_SEL_COUNT];
		appSelData[KEY_SEL_COUNT] = ++selCount;
		std::cout << "Vijay sel count: " << selCount << "\n";

		std::stringstream ss;
		ss << std::hex;
		ss << std::setw(2) << std::setfill('0') << selCount;
		std::cout << "Vijay sel count: " << ss.str() << "\n";

		appSelData[ss.str()][KEY_SEL_ENTRY_RAW] = ipmiRaw.c_str();
		flushSelData();
    uint16_t responseID = 0x1111;
    return ipmi::responseSuccess(responseID);
}

ipmi::RspType<> ipmiStorageClearSEL(uint32_t selTime)
{
    // Set SEL Time is not supported
    return ipmi::responseInvalidCommand();
}

ipmi::RspType<> ipmiStorageGetSELTime(uint32_t selTime)
{
    // Set SEL Time is not supported
    return ipmi::responseInvalidCommand();
}

ipmi::RspType<> ipmiStorageSetSELTime(uint32_t selTime)
{
    // Set SEL Time is not supported
    return ipmi::responseInvalidCommand();
}

void registerSELFunctions()
{
    /* Get App data stored in json file */
    std::ifstream file("/etc/appSel.json");
    if (file)
        file >> appSelData;

		if (appSelData.find(KEY_SEL_COUNT) == appSelData.end())
			appSelData[KEY_SEL_COUNT] = 0;
		else
			std::cout << "Vijay data exist: " << appSelData << "\n";

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
                          ipmi::Privilege::Operator, ipmiStorageAddSELEntry1);

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

    return;
}

}
} // namespace ipmi
