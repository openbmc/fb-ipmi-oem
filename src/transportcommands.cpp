/*
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

#include <ipmid/api.h>
#include <commandutils.hpp>

#define IPMI_CC_PARAMETER_NOT_SUPPORTED 0x80

namespace ipmi
{

void registerTransportFunctions() __attribute__((constructor));

// Transport Command Codes (IPMI/Table H-1)
enum
{
    CMD_TRANSPORT_GET_SOL_CONFIG = 0x22,
};

// SOL Configuration parameters (IPMI/Table 26-5)
enum
{
    SOL_PARAM_SET_IN_PROG,
    SOL_PARAM_SOL_ENABLE,
    SOL_PARAM_SOL_AUTH,
    SOL_PARAM_SOL_THRESHOLD,
    SOL_PARAM_SOL_RETRY,
    SOL_PARAM_SOL_BITRATE,
    SOL_PARAM_SOL_NV_BITRATE,
};

//----------------------------------------------------------------------
// Get SoL Config (IPMI/Section 26.3) (CMD_TRANSPORT_GET_SOL_CONFIG)
//----------------------------------------------------------------------
ipmi_ret_t ipmiTransGetSolConfig(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    uint8_t *req = reinterpret_cast<uint8_t *>(request);
    uint8_t *res = reinterpret_cast<uint8_t *>(response);
    uint8_t param = req[0];
    uint8_t paramSel = req[1];

    *res++ = 0x01; // Parameter revision
    *data_len = 1;

    /* If request for revision only then return
     * with only one byte of data
     */
    if (param & 0x80)
        return IPMI_CC_OK;

    switch (paramSel)
    {
        case SOL_PARAM_SET_IN_PROG:
            *res++ = 0x00; // Set this value as (set complete)
            *data_len += 1;
            break;
        case SOL_PARAM_SOL_ENABLE:
            *res++ = 0x01; // Enable SoL payload
            *data_len += 1;
            break;
        case SOL_PARAM_SOL_AUTH:
            *res++ = 0x02; // Set as (User Level)
            *data_len += 1;
            break;
        case SOL_PARAM_SOL_THRESHOLD:
            *res++ = 0x00;
            /* Byte 2: Char send thresold: setting this value to 1 means
             * that BMC to send packet as soon as first character arrived.
             */
            *res++ = 0x01;
            *data_len += 2;
            break;
        case SOL_PARAM_SOL_RETRY:
            *res++ = 0x00; // Retry count: No retry after packet transmission.
            *res++ = 0x00; // Retry interval
            *data_len += 2;
            break;
        case SOL_PARAM_SOL_BITRATE:
        case SOL_PARAM_SOL_NV_BITRATE:
            *res++ = 0x09; // Bit rate: set as 57.6 kbps
            *data_len += 1;
            break;
        default:
            *data_len = 0;
            return IPMI_CC_PARAMETER_NOT_SUPPORTED;
            break;
    }

    return IPMI_CC_OK;
}

void registerTransportFunctions()
{
    ipmiPrintAndRegister(NETFUN_TRANSPORT, CMD_TRANSPORT_GET_SOL_CONFIG, NULL,
                         ipmiTransGetSolConfig,
                         PRIVILEGE_OPERATOR); // Get Sol Config

    return;
}
} // namespace ipmi
