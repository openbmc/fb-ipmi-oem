#include "phosphor-ipmi-host/utils.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <ipmid/api.h>
#include <iostream>
#include <cstring>

namespace ipmi
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

// Parameters
enum class LanParam : uint8_t
{
    INPROGRESS = 0,
    AUTHSUPPORT = 1,
    AUTHENABLES = 2,
    IP = 3,
    IPSRC = 4,
    MAC = 5,
    SUBNET = 6,
    GATEWAY = 12,
    VLAN = 20,
    CIPHER_SUITE_COUNT = 22,
    CIPHER_SUITE_ENTRIES = 23,
		IPV6 = 59,
};

namespace network
{

/** @brief checks if the given ip is Link Local Ip or not.
 *  @param[in] ipaddress - IPAddress.
 */
bool isLinkLocalIP(const std::string& address)
{
    return address.find(IPV4_PREFIX) == 0 || address.find(IPV6_PREFIX) == 0;
}

} // namespace network

// TODO There may be cases where an interface is implemented by multiple
//  objects,to handle such cases we are interested on that object
//  which are on interested busname.
//  Currently mapper doesn't give the readable busname(gives busid) so we can't
//  use busname to find the object,will do later once the support is there.

DbusObjectInfo getDbusObject(sdbusplus::bus::bus& bus,
                             const std::string& interface,
                             const std::string& serviceRoot,
                             const std::string& match)
{
    std::vector<DbusInterface> interfaces;
    interfaces.emplace_back(interface);

    auto depth = 0;

    auto mapperCall = bus.new_method_call(MAPPER_BUS_NAME, MAPPER_OBJ,
                                          MAPPER_INTF, "GetSubTree");

    mapperCall.append(serviceRoot, depth, interfaces);

    ObjectTree objectTree;
    try
    {
        auto mapperReply = bus.call(mapperCall);
        mapperReply.read(objectTree);
    }
    catch (sdbusplus::exception_t&)
    {
        log<level::ERR>("Error in mapper call");
        elog<InternalFailure>();
    }

    if (objectTree.empty())
    {
        log<level::ERR>("No Object has implemented the interface",
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }

    DbusObjectInfo objectInfo;

    // if match is empty then return the first object
    if (match == "")
    {
        objectInfo = std::make_pair(
            objectTree.begin()->first,
            std::move(objectTree.begin()->second.begin()->first));
        return objectInfo;
    }

    // else search the match string in the object path
    auto objectFound = false;
    for (auto& object : objectTree)
    {
        if (object.first.find(match) != std::string::npos)
        {
            objectFound = true;
            objectInfo = make_pair(object.first,
                                   std::move(object.second.begin()->first));
            break;
        }
    }

    if (!objectFound)
    {
        log<level::ERR>("Failed to find object which matches",
                        entry("MATCH=%s", match.c_str()));
        elog<InternalFailure>();
    }
    return objectInfo;
}

DbusObjectInfo getIPObject(sdbusplus::bus::bus& bus,
                           const std::string& interface,
                           const std::string& serviceRoot,
                           const std::string& match)
{
    auto objectTree = getAllDbusObjects(bus, serviceRoot, interface, match);

    if (objectTree.empty())
    {
        log<level::ERR>("No Object has implemented the IP interface",
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }

    DbusObjectInfo objectInfo;

    for (auto& object : objectTree)
    {
        auto variant = ipmi::getDbusProperty(
            bus, object.second.begin()->first, object.first,
            ipmi::network::IP_INTERFACE, "Address");

        objectInfo = std::make_pair(object.first, object.second.begin()->first);

        // if LinkLocalIP found look for Non-LinkLocalIP
        if (ipmi::network::isLinkLocalIP(
                sdbusplus::message::variant_ns::get<std::string>(variant)))
        {
            continue;
        }
        else
        {
            break;
        }
    }
    return objectInfo;
}

Value getDbusProperty(sdbusplus::bus::bus& bus, const std::string& service,
                      const std::string& objPath, const std::string& interface,
                      const std::string& property)
{

    Value value;

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      PROP_INTF, METHOD_GET);

    method.append(interface, property);

    try
    {
        auto reply = bus.call(method);
        reply.read(value);
    }
    catch (sdbusplus::exception_t&)
    {
        log<level::ERR>("Failed to get property",
                        entry("PROPERTY=%s", property.c_str()),
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }

    return value;
}

PropertyMap getAllDbusProperties(sdbusplus::bus::bus& bus,
                                 const std::string& service,
                                 const std::string& objPath,
                                 const std::string& interface)
{
    PropertyMap properties;

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      PROP_INTF, METHOD_GET_ALL);

    method.append(interface);

    try
    {
        auto reply = bus.call(method);
        reply.read(properties);
    }
    catch (sdbusplus::exception_t&)
    {
        log<level::ERR>("Failed to get all properties",
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }

    return properties;
}

ObjectValueTree getManagedObjects(sdbusplus::bus::bus& bus,
                                  const std::string& service,
                                  const std::string& objPath)
{
    ipmi::ObjectValueTree interfaces;

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      "org.freedesktop.DBus.ObjectManager",
                                      "GetManagedObjects");

    try
    {
        auto reply = bus.call(method);
        reply.read(interfaces);
    }
    catch (sdbusplus::exception_t&)
    {
        log<level::ERR>("Failed to get managed objects",
                        entry("PATH=%s", objPath.c_str()));
        elog<InternalFailure>();
    }

    return interfaces;
}

void setDbusProperty(sdbusplus::bus::bus& bus, const std::string& service,
                     const std::string& objPath, const std::string& interface,
                     const std::string& property, const Value& value)
{
    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      PROP_INTF, METHOD_SET);

    method.append(interface, property, value);

    try
    {
        bus.call(method);
    }
    catch (sdbusplus::exception_t&)
    {
        log<level::ERR>("Failed to set property",
                        entry("PROPERTY=%s", property.c_str()),
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }
}

ServiceCache::ServiceCache(const std::string& intf, const std::string& path) :
    intf(intf), path(path), cachedService(std::nullopt),
    cachedBusName(std::nullopt)
{
}

ServiceCache::ServiceCache(std::string&& intf, std::string&& path) :
    intf(std::move(intf)), path(std::move(path)),
    cachedService(std::nullopt),
    cachedBusName(std::nullopt)
{
}

const std::string& ServiceCache::getService(sdbusplus::bus::bus& bus)
{
    if (!isValid(bus))
    {
        cachedBusName = bus.get_unique_name();
        cachedService = ::ipmi::getService(bus, intf, path);
    }
    return cachedService.value();
}

void ServiceCache::invalidate()
{
    cachedBusName = std::nullopt;
    cachedService = std::nullopt;
}

sdbusplus::message::message
    ServiceCache::newMethodCall(sdbusplus::bus::bus& bus, const char* intf,
                                const char* method)
{
    return bus.new_method_call(getService(bus).c_str(), path.c_str(), intf,
                               method);
}

bool ServiceCache::isValid(sdbusplus::bus::bus& bus) const
{
    return cachedService && cachedBusName == bus.get_unique_name();
}

std::string getService(sdbusplus::bus::bus& bus, const std::string& intf,
                       const std::string& path)
{
    auto mapperCall =
        bus.new_method_call("xyz.openbmc_project.ObjectMapper",
                            "/xyz/openbmc_project/object_mapper",
                            "xyz.openbmc_project.ObjectMapper", "GetObject");

    mapperCall.append(path);
    mapperCall.append(std::vector<std::string>({intf}));

    std::map<std::string, std::vector<std::string>> mapperResponse;
    try
    {
        auto mapperResponseMsg = bus.call(mapperCall);
        mapperResponseMsg.read(mapperResponse);
    }
    catch (sdbusplus::exception_t&)
    {
        throw std::runtime_error("ERROR in mapper call");
    }

    if (mapperResponse.begin() == mapperResponse.end())
    {
        throw std::runtime_error("ERROR in reading the mapper response");
    }

    return mapperResponse.begin()->first;
}

ipmi::ObjectTree getAllDbusObjects(sdbusplus::bus::bus& bus,
                                   const std::string& serviceRoot,
                                   const std::string& interface,
                                   const std::string& match)
{
    std::vector<std::string> interfaces;
    interfaces.emplace_back(interface);

    auto depth = 0;

    auto mapperCall = bus.new_method_call(MAPPER_BUS_NAME, MAPPER_OBJ,
                                          MAPPER_INTF, "GetSubTree");

    mapperCall.append(serviceRoot, depth, interfaces);

    ObjectTree objectTree;
    try
    {
        auto mapperReply = bus.call(mapperCall);
        mapperReply.read(objectTree);
    }
    catch (sdbusplus::exception_t&)
    {
        log<level::ERR>("Error in mapper call",
                        entry("SERVICEROOT=%s", serviceRoot.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));

        elog<InternalFailure>();
    }

    for (auto it = objectTree.begin(); it != objectTree.end();)
    {
        if (it->first.find(match) == std::string::npos)
        {
            it = objectTree.erase(it);
        }
        else
        {
            ++it;
        }
    }

    return objectTree;
}

void deleteAllDbusObjects(sdbusplus::bus::bus& bus,
                          const std::string& serviceRoot,
                          const std::string& interface,
                          const std::string& match)
{
    try
    {
        auto objectTree = getAllDbusObjects(bus, serviceRoot, interface, match);

        for (auto& object : objectTree)
        {
            method_no_args::callDbusMethod(bus, object.second.begin()->first,
                                           object.first, DELETE_INTERFACE,
                                           "Delete");
        }
    }
    catch (sdbusplus::exception::exception& e)
    {
        log<level::INFO>("sdbusplus exception - Unable to delete the objects",
                         entry("ERROR=%s", e.what()),
                         entry("INTERFACE=%s", interface.c_str()),
                         entry("SERVICE=%s", serviceRoot.c_str()));
    }
}

namespace variant_ns = sdbusplus::message::variant_ns;
ipmi_ret_t getNetworkData(uint8_t lan_param, char* data)
{
	ipmi_ret_t rc = IPMI_CC_OK;
	sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

	const std::string ethdevice = "eth0";

	switch (static_cast<LanParam>(lan_param))
	{
		case LanParam::IP:
		{
			auto ethIP = ethdevice + "/" + ipmi::network::IP_TYPE;
			std::string ipaddress;
			auto ipObjectInfo =
					ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
					                     ipmi::network::ROOT, ethIP);

			auto properties = ipmi::getAllDbusProperties(
				    bus, ipObjectInfo.second, ipObjectInfo.first,
				        ipmi::network::IP_INTERFACE);

			ipaddress = variant_ns::get<std::string>(properties["Address"]);

			std::strcpy(data, ipaddress.c_str());
		}
		break;

		case LanParam::IPV6:
		{
			auto ethIP = ethdevice + "/ipv6";
      std::string ipaddress;
			auto ipObjectInfo =
			       ipmi::getIPObject(bus, ipmi::network::IP_INTERFACE,
					                    ipmi::network::ROOT, ethIP);

		  auto properties = ipmi::getAllDbusProperties(
             bus, ipObjectInfo.second, ipObjectInfo.first,
                            ipmi::network::IP_INTERFACE);

      ipaddress = variant_ns::get<std::string>(properties["Address"]);

			std::strcpy(data, ipaddress.c_str());
    }
    break;

    case LanParam::MAC:
    {
			std::string macAddress;
			auto macObjectInfo =
					   ipmi::getDbusObject(bus, ipmi::network::MAC_INTERFACE,
						                     ipmi::network::ROOT, ethdevice);

			auto variant = ipmi::getDbusProperty(
                        bus, macObjectInfo.second, macObjectInfo.first,
                        ipmi::network::MAC_INTERFACE, "MACAddress");

			macAddress = variant_ns::get<std::string>(variant);

			sscanf(macAddress.c_str(), ipmi::network::MAC_ADDRESS_FORMAT,
			       (data), (data + 1), (data + 2), (data + 3), (data + 4),
			       (data + 5));
			std::strcpy(data, macAddress.c_str());
    }
    break;

    default:
    rc = IPMI_CC_PARM_OUT_OF_RANGE;
  }
  return rc;
}

namespace method_no_args
{

void callDbusMethod(sdbusplus::bus::bus& bus, const std::string& service,
                    const std::string& objPath, const std::string& interface,
                    const std::string& method)

{
    auto busMethod = bus.new_method_call(service.c_str(), objPath.c_str(),
                                         interface.c_str(), method.c_str());

    try
    {
        bus.call(busMethod);
    }
    catch (sdbusplus::exception_t&)
    {
        log<level::ERR>("Failed to execute method",
                        entry("METHOD=%s", method.c_str()),
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", interface.c_str()));
        elog<InternalFailure>();
    }
}

} // namespace method_no_args

} // namespace ipmi
