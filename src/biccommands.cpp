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
#include <ipmid/api-types.hpp>

#include <commandutils.hpp>
#include <biccommands.hpp>
#include <phosphor-logging/log.hpp>

#include <vector>
#include <iostream>

namespace ipmi
{

using namespace phosphor::logging;

static void registerBICFunctions() __attribute__((constructor));

extern message::Response::ptr executeIpmiCommand(message::Request::ptr);

//----------------------------------------------------------------------
// ipmiOemBicHandler (IPMI/Section - ) (CMD_OEM_BIC_INFO)
// This Function will handle BIC request for netfn=0x38 and cmd=1
// send the response back to the sender.
//----------------------------------------------------------------------
 
ipmi::RspType<std::vector<uint8_t>> ipmiOemBicHandler(std::vector<uint8_t> inputReq)
{

    uint8_t netfnReq = 0;
    uint8_t netfnRes = 0;
    uint8_t cmdReq = 0;
    uint8_t respHeader = 0;
    uint8_t rqSA = 0;
    uint8_t userId = 0;
    uint32_t sessionId = 0;
    uint8_t channel = 0;
    uint8_t dataLen = 0;

    std::vector<uint8_t> data;
    std::vector<uint8_t> outputRes;

    ipmi::message::Response::ptr res;
    boost::asio::io_service io_service;

    // Get the request data length
    dataLen = inputReq.size();

    // Parsing netfn, cmd from the request
    netfnReq = inputReq.at(NETFN_IDX) >> SHIFT_TWO;
    cmdReq = inputReq.at(CMD_IDX);

    // copy the data from the request
    if(dataLen > DATA_BYTE_IDX)
    {
       std::copy(&inputReq.at(DATA_BYTE_IDX), &inputReq.at(DATA_BYTE_IDX)+(dataLen-DATA_BYTE_IDX), back_inserter(data));
    }

    // Boot spwan is used for calling executeipmi command
    boost::asio::spawn(io_service, [&](boost::asio::yield_context yield) {

       std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
       auto ctx = std::make_shared<ipmi::Context>(
               bus, netfnReq, cmdReq, channel, userId, sessionId,
               ipmi::Privilege::Admin, rqSA, yield);
       auto req = std::make_shared<ipmi::message::Request>(
               ctx, std::forward<std::vector<uint8_t>>(data));

       // Calling executeIpmiCommand request function
       res = ipmi::executeIpmiCommand(req);
    });

    // Run the io service
    io_service.run_one();

    // Add 1 to netfn to send the resposne netfn
    netfnRes = netfnReq + ONE_IDX;

    // copy the IANA 3 bytes and interface 1 bytes to Resp buffer
    std::copy(&inputReq.at(ZERO_IDX), &inputReq.at(INTERFACE_IDX), back_inserter(outputRes));
    outputRes.push_back(inputReq.at(INTERFACE_IDX));

    // copy the netfn, cmd, completion code to Resp buffer
    outputRes.push_back(netfnRes << SHIFT_TWO);
    outputRes.push_back(cmdReq);
    outputRes.push_back(res->cc);

    // copy the payload to the Resp buffer
    std::copy(res->payload.raw.data(), res->payload.raw.data() + res->payload.size(), back_inserter(outputRes));

    return ipmi::responseSuccess(outputRes);
}

static void registerBICFunctions(void)
{

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering BIC commands");

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFive,
                          cmdOemBicInfo, ipmi::Privilege::User,
                          ipmiOemBicHandler);
    return;
} 

} // namespace ipmi
