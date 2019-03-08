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
#include <ipmid/api.h>

#include <cmath>
#include <iostream>
#include <phosphor-logging/log.hpp>

namespace ipmi
{

static constexpr int16_t maxInt10 = 0x1FF;
static constexpr int16_t minInt10 = -0x200;
static constexpr int8_t maxInt4 = 7;
static constexpr int8_t minInt4 = -8;

enum class SensorUnits : uint8_t
{
    unspecified = 0x0,
    degreesC = 0x1,
    volts = 0x4,
    amps = 0x5,
    watts = 0x6,
    rpm = 0x12,
};

enum class SensorTypeCodes : uint8_t
{
    reserved = 0x0,
    temperature = 0x1,
    voltage = 0x2,
    current = 0x3,
    fan = 0x4,
    other = 0xB,
};

struct CmpStrVersion
{
    bool operator()(std::string a, std::string b) const
    {
        return strverscmp(a.c_str(), b.c_str()) < 0;
    }
};

using SensorSubTree = boost::container::flat_map<
    std::string,
    boost::container::flat_map<std::string, std::vector<std::string>>,
    CmpStrVersion>;

inline static bool getSensorSubtree(SensorSubTree& subtree)
{
    sd_bus* bus = NULL;
    int ret = sd_bus_default_system(&bus);
    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to connect to system bus",
            phosphor::logging::entry("ERRNO=0x%X", -ret));
        sd_bus_unref(bus);
        return false;
    }
    sdbusplus::bus::bus dbus(bus);
    auto mapperCall =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");
    static constexpr const auto depth = 2;
    static constexpr std::array<const char*, 3> interfaces = {
        "xyz.openbmc_project.Sensor.Value",
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical"};
    mapperCall.append("/xyz/openbmc_project/sensors", depth, interfaces);

    try
    {
        auto mapperReply = dbus.call(mapperCall);
        subtree.clear();
        mapperReply.read(subtree);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return false;
    }
    return true;
}

// Specify the comparison required to sort and find char* map objects
struct CmpStr
{
    bool operator()(const char* a, const char* b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

const static boost::container::flat_map<const char *, SensorUnits, CmpStr>
    sensorUnits{{{"temperature", SensorUnits::degreesC},
                 {"voltage", SensorUnits::volts},
                 {"current", SensorUnits::amps},
                 {"fan_tach", SensorUnits::rpm},
                 {"power", SensorUnits::watts}}};


const static boost::container::flat_map<const char*, SensorTypeCodes, CmpStr>
    sensorTypes{{{"temperature", SensorTypeCodes::temperature},
                 {"voltage", SensorTypeCodes::voltage},
                 {"current", SensorTypeCodes::current},
                 {"fan_tach", SensorTypeCodes::fan},
                 {"fan_pwm", SensorTypeCodes::fan},
                 {"power", SensorTypeCodes::other}}};

inline static std::string getSensorTypeStringFromPath(const std::string& path)
{
    // get sensor type string from path, path is defined as
    // /xyz/openbmc_project/sensors/<type>/label
    size_t typeEnd = path.rfind("/");
    if (typeEnd == std::string::npos)
    {
        return path;
    }
    size_t typeStart = path.rfind("/", typeEnd - 1);
    if (typeStart == std::string::npos)
    {
        return path;
    }
    // Start at the character after the '/'
    typeStart++;
    return path.substr(typeStart, typeEnd - typeStart);
}

inline static uint8_t getSensorTypeFromPath(const std::string& path)
{
    uint8_t sensorType = 0;
    std::string type = getSensorTypeStringFromPath(path);
    auto findSensor = sensorTypes.find(type.c_str());
    if (findSensor != sensorTypes.end())
    {
        sensorType = static_cast<uint8_t>(findSensor->second);
    } // else default 0x0 RESERVED

    return sensorType;
}

inline static uint8_t getSensorEventTypeFromPath(const std::string& path)
{
    // TODO: Add support for additional reading types as needed
    return 0x1; // reading type = threshold
}

static inline bool getSensorAttributes(const double max, const double min,
                                       int16_t& mValue, int8_t& rExp,
                                       int16_t& bValue, int8_t& bExp,
                                       bool& bSigned)
{
    // computing y = (10^rRexp) * (Mx + (B*(10^Bexp)))
    // check for 0, assume always positive
    double mDouble;
    double bDouble;
    if (max <= min)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "getSensorAttributes: Max must be greater than min");
        return false;
    }

    mDouble = (max - min) / 0xFF;

    if (min < 0)
    {
        bSigned = true;
        bDouble = floor(0.5 + ((max + min) / 2));
    }
    else
    {
        bSigned = false;
        bDouble = min;
    }

    rExp = 0;

    // M too big for 10 bit variable
    while (mDouble > maxInt10)
    {
        if (rExp >= maxInt4)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "rExp Too big, Max and Min range too far",
                phosphor::logging::entry("REXP=%d", rExp));
            return false;
        }
        mDouble /= 10;
        rExp++;
    }

    // M too small, loop until we lose less than 1 eight bit count of precision
    while (((mDouble - floor(mDouble)) / mDouble) > (1.0 / 255))
    {
        if (rExp <= minInt4)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "rExp Too Small, Max and Min range too close");
            return false;
        }
        // check to see if we reached the limit of where we can adjust back the
        // B value
        if (bDouble / std::pow(10, rExp + minInt4 - 1) > bDouble)
        {
            if (mDouble < 1.0)
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "Could not find mValue and B value with enough "
                    "precision.");
                return false;
            }
            break;
        }
        // can't multiply M any more, max precision reached
        else if (mDouble * 10 > maxInt10)
        {
            break;
        }
        mDouble *= 10;
        rExp--;
    }

    bDouble /= std::pow(10, rExp);
    bExp = 0;

    // B too big for 10 bit variable
    while (bDouble > maxInt10 || bDouble < minInt10)
    {
        if (bExp >= maxInt4)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "bExp Too Big, Max and Min range need to be adjusted");
            return false;
        }
        bDouble /= 10;
        bExp++;
    }

    while (((fabs(bDouble) - floor(fabs(bDouble))) / fabs(bDouble)) >
           (1.0 / 255))
    {
        if (bExp <= minInt4)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "bExp Too Small, Max and Min range need to be adjusted");
            return false;
        }
        bDouble *= 10;
        bExp -= 1;
    }

    mValue = static_cast<int16_t>(mDouble) & maxInt10;
    bValue = static_cast<int16_t>(bDouble) & maxInt10;

    return true;
}

static inline uint8_t
    scaleIPMIValueFromDouble(const double value, const uint16_t mValue,
                             const int8_t rExp, const uint16_t bValue,
                             const int8_t bExp, const bool bSigned)
{
    uint32_t scaledValue =
        (value - (bValue * std::pow(10, bExp) * std::pow(10, rExp))) /
        (mValue * std::pow(10, rExp));

    if (scaledValue > std::numeric_limits<uint8_t>::max() ||
        scaledValue < std::numeric_limits<uint8_t>::lowest())
    {
        throw std::out_of_range("Value out of range");
    }
    if (bSigned)
    {
        return static_cast<int8_t>(scaledValue);
    }
    else
    {
        return static_cast<uint8_t>(scaledValue);
    }
}

static inline uint8_t getScaledIPMIValue(const double value, const double max,
                                         const double min)
{
    int16_t mValue = 0;
    int8_t rExp = 0;
    int16_t bValue = 0;
    int8_t bExp = 0;
    bool bSigned = 0;
    bool result = 0;

    result = getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned);
    if (!result)
    {
        throw std::runtime_error("Illegal sensor attributes");
    }
    return scaleIPMIValueFromDouble(value, mValue, rExp, bValue, bExp, bSigned);
}
} // namespace ipmi

