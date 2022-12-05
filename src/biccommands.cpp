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

int sendBicCmd(uint8_t, uint8_t, uint8_t, std::vector<uint8_t>&,
               std::vector<uint8_t>&);

using namespace phosphor::logging;

#ifdef BIC_ENABLED
static void registerBICFunctions() __attribute__((constructor));
#endif

extern message::Response::ptr executeIpmiCommand(message::Request::ptr);

int sendBicCmd(uint8_t, uint8_t, uint8_t, std::vector<uint8_t>&,
               std::vector<uint8_t>&);

//----------------------------------------------------------------------
// ipmiOemBicHandler (IPMI/Section - ) (CMD_OEM_BIC_INFO)
// This Function will handle BIC request for netfn=0x38 and cmd=1
// send the response back to the sender.
//----------------------------------------------------------------------

ipmi::RspType<IanaType, uint8_t, uint2_t, uint6_t, uint8_t, uint8_t,
              ipmi::message::Payload>
    ipmiOemBicHandler(ipmi::Context::ptr ctx, IanaType reqIana,
                      uint8_t interface, uint2_t lun, uint6_t netFnReq,
                      uint8_t cmdReq, SecureBuffer data)
{

    ipmi::message::Response::ptr res;

    // Updating the correct netfn and cmd in the ipmi Context
    ctx->netFn = ((uint8_t)netFnReq);
    ctx->cmd = cmdReq;

    // creating ipmi message request for calling executeIpmiCommand function
    auto req = std::make_shared<ipmi::message::Request>(ctx, std::move(data));

    // Calling executeIpmiCommand request function
    res = ipmi::executeIpmiCommand(req);

    // sending the response with headers and payload
    return ipmi::responseSuccess(reqIana, interface, lun, ++netFnReq, cmdReq,
                                 res->cc, res->payload);
}

//----------------------------------------------------------------------
// ipmiOemPostCodeHandler (CMD_OEM_BIC_POST_BUFFER_INFO)
// This Function will handle BIC incomming postcode from multi-host for
// netfn=0x38 and cmd=0x08 send the response back to the sender.
//----------------------------------------------------------------------

ipmi::RspType<IanaType> ipmiOemPostCodeHandler(ipmi::Context::ptr ctx,
                                               IanaType reqIana,
                                               uint8_t dataLen,
                                               std::vector<uint8_t> data)
{
    // creating bus connection
    auto conn = getSdBus();

    using postcode_t = std::tuple<uint64_t, std::vector<uint8_t>>;

    std::string dbusObjStr = dbusObj + std::to_string((ctx->hostIdx + 1));

    for (unsigned int index = 0; index < dataLen; index++)
    {
        uint64_t primaryPostCode = static_cast<uint64_t>(data[index]);
        auto postCode = postcode_t(primaryPostCode, {});

        try
        {
            auto method = conn->new_method_call(
                "xyz.openbmc_project.State.Boot.Raw", dbusObjStr.c_str(),
                "org.freedesktop.DBus.Properties", "Set");

            // Adding paramters to method call
            method.append(dbusService, "Value",
                          std::variant<postcode_t>(postCode));

            // Invoke method call function
            auto reply = conn->call(method);
        }

        catch (std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "post code handler error\n");

            // sending the Error response
            return ipmi::responseResponseError();
        }
    }

    return ipmi::responseSuccess(reqIana);
}

//----------------------------------------------------------------------
// ipmiOemGetBicGpioState (CMD_OEM_GET_BIC_GPIO_STATE)
// This Function will handle BIC GPIO stats for
// netfn=0x38 and cmd=0x03 send the response back to the sender.
//----------------------------------------------------------------------

ipmi::RspType<IanaType, std::vector<uint8_t>>
    ipmiOemGetBicGpioState(ipmi::Context::ptr ctx, std::vector<uint8_t> reqIana)
{
    std::vector<uint8_t> respData;

    if (std::equal(reqIana.begin(), reqIana.end(), iana.begin()) == false)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid IANA number");
        return ipmi::responseInvalidFieldRequest();
    }

    uint8_t bicAddr = (uint8_t)ctx->hostIdx << 2;

    if (sendBicCmd(ctx->netFn, ctx->cmd, bicAddr, reqIana, respData))
    {
        return ipmi::responseUnspecifiedError();
    }

    std::vector<uint8_t> gpioState;
    IanaType respIana;

    auto r =
        std::ranges::copy_n(respData.begin(), iana.size(), respIana.begin()).in;
    std::copy(r, respData.end(), std::back_inserter(gpioState));

    return ipmi::responseSuccess(respIana, gpioState);
}

//----------------------------------------------------------------------
// ipmiOemSetHostPowerState (CMD_OEM_SET_HOST_POWER_STATE)
// This Function will handle BIC incomming IPMI request for
// setting host current state for netfn=0x38 and cmd=0x0C
// send the response back to the sender.
//----------------------------------------------------------------------

ipmi::RspType<IanaType> ipmiOemSetHostPowerState(ipmi::Context::ptr ctx,
                                                 IanaType reqIana,
                                                 uint8_t status)
{
    std::string targetUnit;

    switch (static_cast<HostPowerState>(status))
    {
        case HostPowerState::HOST_POWER_ON:
            targetUnit = "obmc-host-startmin@.target";
            break;
        case HostPowerState::HOST_POWER_OFF:
            targetUnit = "obmc-host-stop@.target";
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "IPMI ipmiOemHostPowerStatus power status error");
            return ipmi::responseUnspecifiedError();
    }

    int mousePos = targetUnit.find('@');
    targetUnit.insert(mousePos + 1, std::to_string(ctx->hostIdx + 1));

    auto conn = getSdBus();
    auto method = conn->new_method_call(systemdService, systemdObjPath,
                                        systemdInterface, "StartUnit");
    method.append(targetUnit);
    method.append("replace");

    try
    {
        conn->call_noreply(method);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "IPMI ipmiOemHostPowerStatus Failed in call method",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(reqIana);
}

//----------------------------------------------------------------------
// ipmiOemGetBiosFlashSize (CMD_OEM_GET_FLASH_SIZE)
// This Function will return the bios flash size
// netfn=0x38 and cmd=0x19 send the response back to the sender.
//----------------------------------------------------------------------

ipmi::RspType<IanaType, flashSize>
    ipmiOemGetBiosFlashSize(ipmi::Context::ptr ctx, IanaType ianaReq,
                            uint8_t target)
{
    if (iana != ianaReq)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid IANA ID length received");
        return ipmi::responseReqDataLenInvalid();
    }

    std::vector<uint8_t> respData;
    uint8_t bicAddr = (uint8_t)ctx->hostIdx << 2;
    std::vector<uint8_t> reqData(ianaReq.begin(), ianaReq.end());
    reqData.emplace_back(target);

    if (sendBicCmd(ctx->netFn, ctx->cmd, bicAddr, reqData, respData))
    {
        return ipmi::responseUnspecifiedError();
    }

    if (respData.size() != flashSizeRespLen)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Response Data length received");
        return ipmi::responseReqDataLenInvalid();
    }

    IanaType ianaResp;
    std::copy_n(respData.begin(), ianaResp.size(), ianaResp.begin());

    if (iana != ianaResp)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid IANA ID received");
        return ipmi::responseInvalidCommand();
    }

    flashSize flashResp;
    std::vector<uint8_t>::iterator respDataIter = respData.begin();
    std::advance(respDataIter, ianaResp.size());
    std::copy_n(respDataIter, flashResp.size(), flashResp.begin());

    // sending the success response.
    return ipmi::responseSuccess(ianaResp, flashResp);
}

//----------------------------------------------------------------------
// ipmiOemClearCmos (CMD_OEM_CLEAR_CMOS)
// This Function will clear the CMOS.
// netfn=0x38 and cmd=0x25
//----------------------------------------------------------------------
ipmi::RspType<IanaType> ipmiOemClearCmos(ipmi::Context::ptr ctx,
                                         IanaType ianaReq)
{
    if (iana != ianaReq)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid request of IANA ID length received");
        return ipmi::responseReqDataLenInvalid();
    }

    uint8_t bicAddr = (uint8_t)ctx->hostIdx << 2;

    std::vector<uint8_t> respData;
    std::vector<uint8_t> reqData(ianaReq.begin(), ianaReq.end());

    if (sendBicCmd(ctx->netFn, ctx->cmd, bicAddr, reqData, respData))
    {
        return ipmi::responseUnspecifiedError();
    }

    if (respData.size() != iana.size())
    {
        return ipmi::responseReqDataLenInvalid();
    }

    IanaType resp;
    std::copy_n(respData.begin(), resp.size(), resp.begin());

    if (iana != resp)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid response of IANA ID received");
        return ipmi::responseUnspecifiedError();
    }

    // sending the success response.
    return ipmi::responseSuccess(resp);
}

[[maybe_unused]] static void registerBICFunctions(void)
{

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering BIC commands");

    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFive,
                          static_cast<Cmd>(fb_bic_cmds::CMD_OEM_BIC_INFO),
                          ipmi::Privilege::User, ipmiOemBicHandler);
    ipmi::registerHandler(
        ipmi::prioOpenBmcBase, ipmi::netFnOemFive,
        static_cast<Cmd>(fb_bic_cmds::CMD_OEM_SEND_POST_BUFFER_TO_BMC),
        ipmi::Privilege::User, ipmiOemPostCodeHandler);
    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::netFnOemFive,
        static_cast<Cmd>(fb_bic_cmds::CMD_OEM_GET_BIC_GPIO_STATE),
        ipmi::Privilege::User, ipmiOemGetBicGpioState);
    ipmi::registerHandler(
        ipmi::prioOpenBmcBase, ipmi::netFnOemFive,
        static_cast<Cmd>(fb_bic_cmds::CMD_OEM_SET_HOST_POWER_STATE),
        ipmi::Privilege::User, ipmiOemSetHostPowerState);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFive,
                          static_cast<Cmd>(fb_bic_cmds::CMD_OEM_GET_FLASH_SIZE),
                          ipmi::Privilege::User, ipmiOemGetBiosFlashSize);
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnOemFive,
                          static_cast<Cmd>(fb_bic_cmds::CMD_OEM_CLEAR_CMOS),
                          ipmi::Privilege::User, ipmiOemClearCmos);
    return;
}

} // namespace ipmi
