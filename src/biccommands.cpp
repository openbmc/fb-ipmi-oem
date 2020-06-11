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

ipmi_ret_t ipmiOemBicHandler(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
        uint8_t* reqData =  reinterpret_cast<uint8_t*>(request);
        uint8_t* resp = reinterpret_cast<uint8_t*>(response); 

        uint8_t netfnReq   = 0;
        uint8_t netfnRes   = 0;
        uint8_t cmdReq     = 0;
        int respHeader     = 0;
        int rqSA           = 0;
        uint8_t userId     = 0;
        uint32_t sessionId = 0;
        uint8_t channel    = 0;

        std::vector<uint8_t> data;

        ipmi::message::Response::ptr res;
        boost::asio::io_service io_service;

        //Parsing netfn, cmd from the request
        netfnReq = reqData[4] >> 2;
        cmdReq = reqData[5];

        //copy the data from the request
        if(*data_len > DATA_BYTE_IDX)
        {
            std::copy(&reqData[DATA_BYTE_IDX], &reqData[*data_len], back_inserter(data));
        }


        //Boot spwan is used for calling executeipmi command
        boost::asio::spawn(io_service, [&](boost::asio::yield_context yield) {

            std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
            auto ctx = std::make_shared<ipmi::Context>(
                bus, netfnReq, cmdReq, channel, userId, sessionId,
                ipmi::Privilege::Admin, rqSA, yield);
            auto req = std::make_shared<ipmi::message::Request>(
                ctx, std::forward<std::vector<uint8_t>>(data));

        //Calling executeIpmiCommand request function
        res = ipmi::executeIpmiCommand(req);
        });

        // Run the io service
        io_service.run_one();

        *data_len = 0;

        //Add 1 to netfn to send the resposne netfn
        netfnRes = netfnReq + 1;

        //copy the IANA 3 bytes and interface 1 bytes to Resp buffer
        std::memcpy(resp, reqData, SIZE_IANA_ID);
        resp[SIZE_IANA_ID + respHeader++] = reqData[3];

        //copy the netfn, cmd, completion code to Resp buffer
        resp[SIZE_IANA_ID + respHeader++] = netfnRes << 2;
        resp[SIZE_IANA_ID + respHeader++] = cmdReq;
        resp[SIZE_IANA_ID + respHeader++] = res->cc;

        //copy the payload to the Resp buffer
        std::memcpy(resp+(SIZE_IANA_ID+respHeader), res->payload.raw.data(), res->payload.size());
        *data_len =  SIZE_IANA_ID + res->payload.size() + respHeader;

        return IPMI_CC_OK;
}

static void registerBICFunctions(void)
{

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering BIC commands");

    //Yv2 BIC command handler for netfn=0x38 cmd=1
    ipmiPrintAndRegister(NETFUN_FB_OEM_BIC, CMD_OEM_BIC_INFO, NULL,
                          ipmiOemBicHandler, PRIVILEGE_USER);
    return;

}

} // namespace ipmi
