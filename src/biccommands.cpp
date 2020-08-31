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
#include <variant>
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

ipmi::RspType<std::array<uint8_t, 3>, uint8_t, uint2_t, uint6_t, uint8_t,
              uint8_t, ipmi::message::Payload>
    ipmiOemBicHandler(ipmi::Context::ptr ctx, std::array<uint8_t, 3> iana,
                      uint8_t interface, uint2_t lun, uint6_t netFnReq,
                      uint8_t cmdReq, std::vector<uint8_t> data)
{

    ipmi::message::Response::ptr res;

    // Updating the correct netfn and cmd in the ipmi Context
    ctx->netFn = ((uint8_t)netFnReq);
    ctx->cmd = cmdReq;

    // creating ipmi message request for calling executeIpmiCommand function
    auto req = std::make_shared<ipmi::message::Request>(
        ctx, std::forward<std::vector<uint8_t>>(data));

    // Calling executeIpmiCommand request function
    res = ipmi::executeIpmiCommand(req);

    // sending the response with headers and payload
    return ipmi::responseSuccess(iana, interface, lun, ++netFnReq, cmdReq,
                                 res->cc, res->payload);
}

//----------------------------------------------------------------------
// ipmiOemPostCodeHandler (CMD_OEM_BIC_POST_BUFFER_INFO)
// This Function will handle BIC incomming postcode from multi-host for
// netfn=0x38 and cmd=0x08 send the response back to the sender.
//----------------------------------------------------------------------

ipmi::RspType<std::array<uint8_t, 3>, uint8_t>
    ipmiOemPostCodeHandler(ipmi::Context::ptr ctx, std::array<uint8_t, 3> iana,
                           uint8_t interface, uint8_t data)
{
    // creating bus connection
    auto conn = getSdBus();

    try
    {
        // storing post code as varaint
        std::variant<uint64_t> postCode = static_cast<uint64_t>(data);

        // creating dbus objects for 1 to N process
        const std::string dbusObj = "/xyz/openbmc_project/state/boot/raw" +
                                    std::to_string((ctx->hostIdx + 1));

        // const std::string dbusService = "xyz.openbmc_project.State.Boot.Raw";
        constexpr char* dbusService = "xyz.openbmc_project.State.Boot.Raw";

        // creating method call to update postd value
        auto method = conn->new_method_call(
            "xyz.openbmc_project.State.Boot.Raw", dbusObj.c_str(),
            "org.freedesktop.DBus.Properties", "Set");

        // Adding paramters to method call
        method.append(dbusService, "Value", postCode);

        // Invoke method call function
        auto reply = conn->call(method);
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "post code handler error\n");
    }

    // sending the response with headers
    return ipmi::responseSuccess(iana, interface);
}

static void registerBICFunctions(void)
{

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering BIC commands");

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFive,
                          cmdOemBicInfo, ipmi::Privilege::User,
                          ipmiOemBicHandler);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFive,
                          cmdOemSendPostBufferToBMC, ipmi::Privilege::User,
                          ipmiOemPostCodeHandler);
    return;
}

} // namespace ipmi
