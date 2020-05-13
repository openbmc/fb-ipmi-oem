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

#include "xyz/openbmc_project/Common/error.hpp"
#include <ipmid/api.h>
#include <ipmid/api.hpp>

#include <nlohmann/json.hpp>
#include <array>
#include <commandutils.hpp>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <biccommands.hpp>
//#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>

#include <boost/algorithm/string/replace.hpp>



namespace ipmi
{

using namespace phosphor::logging;

static void registerBICFunctions() __attribute__((constructor));

int getMeStatus(std::string &status);

//sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection()); // from ipmid/api.h



/* This function handling the BIC request and send back the response to the ipmb */
ipmi_ret_t ipmiOemBicHandler(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
          "[FBOEM][IPMI BIC HANDLER] \n");

	ipmi_bic_req_t *bic_req = reinterpret_cast<ipmi_bic_req_t *>(request);

	printf(" header : %x\t%x\t%x\t%x \n", bic_req->data[0], bic_req->data[1], bic_req->data[2], bic_req->data[3]);
	printf(" netfn : %x\n", bic_req->ipmi_req.netfn);
	printf(" cmd : %x\n", bic_req->ipmi_req.cmd);


	/*  METHOD 1 : Synchronous -  using getSdBus() function to get the connection bus.
	 *  Using the connection bus to call the dbus method execute of ipmi host. */

	std::map<std::string, std::variant<int>> options{{}};
        uint8_t rsLun = 1;

        std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

	auto method = bus->new_method_call("xyz.openbmc_project.Ipmi.Host",
                                "/xyz/openbmc_project/Ipmi",
                                     "xyz.openbmc_project.Ipmi.Server", "execute");
        method.append(bic_req->ipmi_req.netfn,
            rsLun, bic_req->ipmi_req.cmd, bic_req->ipmi_req.data, options); 

        auto reply = bus->call(method);
        if (reply.is_method_error())
        {
                std::cerr << "Error reading from ipmid\n";
                return -1;
        }

        using IpmiDbusRspType = std::tuple<uint8_t, uint8_t, uint8_t, uint8_t,
                                           std::vector<uint8_t>>;

        IpmiDbusRspType resp;
        reply.read(resp);

        std::vector<uint8_t> data;
        data = std::get<4>(resp);
        
        if (true)
        {

          std::cout << "Get Dev ID: ";
          for (size_t d : data)
          {
            std::cout << d << " ";
          }
          std::cout << "\n";
        }

	std::cout.flush(); 


	/*  METHOD 2 : Asynchronous -  using asio connection to get the connection bus.
	 *  Using the connection bus to call the dbus method execute of ipmi host. */

	boost::asio::io_service io;
	auto bic_conn = std::make_shared<sdbusplus::asio::connection>(io);
        static constexpr const char *hostBus = "xyz.openbmc_project.Ipmi.Host";

	if(bic_conn == NULL)
	{
                std::cerr << "bic_conn is null. \n";
                return -1;
	}

	bic_conn->request_name(hostBus);

        std::map<std::string, std::variant<int>> options{{"rqSA", 32}};
        using IpmiDbusRspType = std::tuple<uint8_t, uint8_t, uint8_t, uint8_t,
       	                                    std::vector<uint8_t>>;

	uint8_t rsLun = 0;

        bic_conn->async_method_call(
	        [](const boost::system::error_code &ec,
                const IpmiDbusRspType &resp) {
                const auto &[netfn, lun, cmd, cc, payload] = resp;
                if (ec)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "processI2cEvent: error getting response from IPMI");
                    return;
                }
                if(ec == boost::asio::error::operation_not_supported)
                {
	              std::cout << "Printing the error messages "  << std::endl;
                      std::cout << ec.message() << std::endl;
                }

		try
                {
		    printf("[FBOEM][IPMI BIC INFO] Response execute - NetFn : %x \n", netfn);
		    printf("[FBOEM][IPMI BIC INFO] Response execute - cmd : %x \n", cmd);
		    printf("[FBOEM][IPMI BIC INFO] Response execute - cc : %x \n", cc);
	            std::cout.flush();
                }
                catch (std::exception& e)
                {
                    std::cerr << "Exception caught : " << e.what() << std::endl;
                } 
	     },
            "xyz.openbmc_project.Ipmi.Host", "/xyz/openbmc_project/Ipmi",
            "xyz.openbmc_project.Ipmi.Server", "execute", bic_req->ipmi_req.netfn, 
	     rsLun, bic_req->ipmi_req.cmd, bic_req->ipmi_req.data, options); 

             io.run(); 

         return IPMI_CC_OK;
}

static void registerBICFunctions(void)
{

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering BIC commands");

    ipmiPrintAndRegister(NETFUN_FB_OEM_BIC, CMD_OEM_BIC_INFO, NULL,
                          ipmiOemBicHandler,
                         PRIVILEGE_USER); // Yv2 Bic Info
    return;
} 

} // namespace ipmi
