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

#include <boost/algorithm/string/join.hpp>
#include <ipmid/api.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/timer.hpp>
#include <storagecommands.hpp>

#include <fstream>
#include <iostream>
#include <sstream>

//----------------------------------------------------------------------
// Platform specific functions for storing app data
//----------------------------------------------------------------------

static std::string byteToStr(uint8_t byte)
{
    std::stringstream ss;

    ss << std::hex << std::uppercase << std::setfill('0');
    ss << std::setw(2) << (int)byte;

    return ss.str();
}

static void toHexStr(std::vector<uint8_t>& bytes, std::string& hexStr)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (const uint8_t byte : bytes)
    {
        stream << std::setw(2) << static_cast<int>(byte);
    }
    hexStr = stream.str();
}

static int fromHexStr(const std::string hexStr, std::vector<uint8_t>& data)
{
    for (unsigned int i = 0; i < hexStr.size(); i += 2)
    {
        try
        {
            data.push_back(static_cast<uint8_t>(
                std::stoul(hexStr.substr(i, 2), nullptr, 16)));
        }
        catch (std::invalid_argument& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
        catch (std::out_of_range& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
    }
    return 0;
}

namespace fb_oem::ipmi::sel
{

class SELData
{
  private:
    nlohmann::json selDataObj;

    void flush()
    {
        std::ofstream file(SEL_JSON_DATA_FILE);
        file << selDataObj;
        file.close();
    }

    void init()
    {
        selDataObj[KEY_SEL_VER] = 0x51;
        selDataObj[KEY_SEL_COUNT] = 0;
        selDataObj[KEY_ADD_TIME] = 0xFFFFFFFF;
        selDataObj[KEY_ERASE_TIME] = 0xFFFFFFFF;
        selDataObj[KEY_OPER_SUPP] = 0x02;
        /* Spec indicates that more than 64kB is free */
        selDataObj[KEY_FREE_SPACE] = 0xFFFF;
    }

  public:
    SELData()
    {
        /* Get App data stored in json file */
        std::ifstream file(SEL_JSON_DATA_FILE);
        if (file)
        {
            file >> selDataObj;
            file.close();
        }

        /* Initialize SelData object if no entries. */
        if (selDataObj.find(KEY_SEL_COUNT) == selDataObj.end())
        {
            init();
        }
    }

    int clear()
    {
        /* Clear the complete Sel Json object */
        selDataObj.clear();
        /* Reinitialize it with basic data */
        init();
        /* Save the erase time */
        struct timespec selTime = {};
        if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
        {
            return -1;
        }
        selDataObj[KEY_ERASE_TIME] = selTime.tv_sec;
        flush();
        return 0;
    }

    uint32_t getCount()
    {
        return selDataObj[KEY_SEL_COUNT];
    }

    void getInfo(GetSELInfoData& info)
    {
        info.selVersion = selDataObj[KEY_SEL_VER];
        info.entries = selDataObj[KEY_SEL_COUNT];
        info.freeSpace = selDataObj[KEY_FREE_SPACE];
        info.addTimeStamp = selDataObj[KEY_ADD_TIME];
        info.eraseTimeStamp = selDataObj[KEY_ERASE_TIME];
        info.operationSupport = selDataObj[KEY_OPER_SUPP];
    }

    int getEntry(uint32_t index, std::string& rawStr)
    {
        std::stringstream ss;
        ss << std::hex;
        ss << std::setw(2) << std::setfill('0') << index;

        /* Check or the requested SEL Entry, if record is available */
        if (selDataObj.find(ss.str()) == selDataObj.end())
        {
            return -1;
        }

        rawStr = selDataObj[ss.str()][KEY_SEL_ENTRY_RAW];
        return 0;
    }

    int addEntry(std::string keyStr)
    {
        struct timespec selTime = {};

        if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
        {
            return -1;
        }

        selDataObj[KEY_ADD_TIME] = selTime.tv_sec;

        int selCount = selDataObj[KEY_SEL_COUNT];
        selDataObj[KEY_SEL_COUNT] = ++selCount;

        std::stringstream ss;
        ss << std::hex;
        ss << std::setw(2) << std::setfill('0') << selCount;

        selDataObj[ss.str()][KEY_SEL_ENTRY_RAW] = keyStr;
        flush();
        return selCount;
    }
};

/*
 * A Function to parse common SEL message, a helper funciton
 * for parseStdSel.
 *
 * Note that this function __CANNOT__ be overriden.
 * To add board specific routine, please override parseStdSel.
 */

/*Used by decoding ME event*/
std::vector<std::string> nmDomName = {
    "Entire Platform",          "CPU Subsystem",
    "Memory Subsystem",         "HW Protection",
    "High Power I/O subsystem", "Unknown"};

/* Default log message for unknown type */
static void logDefault(uint8_t* data, std::string& errLog)
{
    errLog = "Unknown";
}

static void logSysEvent(uint8_t* data, std::string& errLog)
{
    if (data[0] == 0xE5)
    {
        errLog = "Cause of Time change - ";
        switch (data[2])
        {
            case 0x00:
                errLog += "NTP";
                break;
            case 0x01:
                errLog += "Host RTL";
                break;
            case 0x02:
                errLog += "Set SEL time cmd";
                break;
            case 0x03:
                errLog += "Set SEL time UTC offset cmd";
                break;
            default:
                errLog += "Unknown";
        }

        if (data[1] == 0x00)
            errLog += " - First Time";
        else if (data[1] == 0x80)
            errLog += " - Second Time";
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logThermalEvent(uint8_t* data, std::string& errLog)
{
    if (data[0] == 0x1)
    {
        errLog = "Limit Exceeded";
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logCritIrq(uint8_t* data, std::string& errLog)
{

    if (data[0] == 0x0)
    {
        errLog = "NMI / Diagnostic Interrupt";
    }
    else if (data[0] == 0x03)
    {
        errLog = "Software NMI";
    }
    else
    {
        errLog = "Unknown";
    }

    /* TODO: Call add_cri_sel for CRITICAL_IRQ */
}

static void logPostErr(uint8_t* data, std::string& errLog)
{

    if ((data[0] & 0x0F) == 0x0)
    {
        errLog = "System Firmware Error";
    }
    else
    {
        errLog = "Unknown";
    }

    if (((data[0] >> 6) & 0x03) == 0x3)
    {
        // TODO: Need to implement IPMI spec based Post Code
        errLog += ", IPMI Post Code";
    }
    else if (((data[0] >> 6) & 0x03) == 0x2)
    {
        errLog +=
            ", OEM Post Code 0x" + byteToStr(data[2]) + byteToStr(data[1]);

        switch ((data[2] << 8) | data[1])
        {
            case 0xA105:
                errLog += ", BMC Failed (No Response)";
                break;
            case 0xA106:
                errLog += ", BMC Failed (Self Test Fail)";
                break;
            case 0xA10A:
                errLog += ", System Firmware Corruption Detected";
                break;
            case 0xA10B:
                errLog += ", TPM Self-Test FAIL Detected";
        }
    }
}

static void logMchChkErr(uint8_t* data, std::string& errLog)
{
    /* TODO: Call add_cri_sel for CRITICAL_IRQ */
    if ((data[0] & 0x0F) == 0x0B)
    {
        errLog = "Uncorrectable";
    }
    else if ((data[0] & 0x0F) == 0x0C)
    {
        errLog = "Correctable";
    }
    else
    {
        errLog = "Unknown";
    }

    errLog += ", Machine Check bank Number " + std::to_string(data[1]) +
              ", CPU " + std::to_string(data[2] >> 5) + ", Core " +
              std::to_string(data[2] & 0x1F);
}

static void logPcieErr(uint8_t* data, std::string& errLog)
{
    std::stringstream tmp1, tmp2;
    tmp1 << std::hex << std::uppercase << std::setfill('0');
    tmp2 << std::hex << std::uppercase << std::setfill('0');
    tmp1 << " (Bus " << std::setw(2) << (int)(data[2]) << " / Dev "
         << std::setw(2) << (int)(data[1] >> 3) << " / Fun " << std::setw(2)
         << (int)(data[1] & 0x7) << ")";

    switch (data[0] & 0xF)
    {
        case 0x4:
            errLog = "PCI PERR" + tmp1.str();
            break;
        case 0x5:
            errLog = "PCI SERR" + tmp1.str();
            break;
        case 0x7:
            errLog = "Correctable" + tmp1.str();
            break;
        case 0x8:
            errLog = "Uncorrectable" + tmp1.str();
            break;
        case 0xA:
            errLog = "Bus Fatal" + tmp1.str();
            break;
        case 0xD:
        {
            uint32_t venId = (uint32_t)data[1] << 8 | (uint32_t)data[2];
            tmp2 << "Vendor ID: 0x" << std::setw(4) << venId;
            errLog = tmp2.str();
        }
        break;
        case 0xE:
        {
            uint32_t devId = (uint32_t)data[1] << 8 | (uint32_t)data[2];
            tmp2 << "Device ID: 0x" << std::setw(4) << devId;
            errLog = tmp2.str();
        }
        break;
        case 0xF:
            tmp2 << "Error ID from downstream: 0x" << std::setw(2)
                 << (int)(data[1]) << std::setw(2) << (int)(data[2]);
            errLog = tmp2.str();
            break;
        default:
            errLog = "Unknown";
    }
}

static void logIioErr(uint8_t* data, std::string& errLog)
{
    std::vector<std::string> tmpStr = {
        "IRP0", "IRP1", " IIO-Core", "VT-d", "Intel Quick Data",
        "Misc", " DMA", "ITC",       "OTC",  "CI"};

    if ((data[0] & 0xF) == 0)
    {
        errLog += "CPU " + std::to_string(data[2] >> 5) + ", Error ID 0x" +
                  byteToStr(data[1]) + " - ";

        if ((data[2] & 0xF) <= 0x9)
        {
            errLog += tmpStr[(data[2] & 0xF)];
        }
        else
        {
            errLog += "Reserved";
        }
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logMemErr(uint8_t* dataPtr, std::string& errLog)
{
    uint8_t snrType = dataPtr[0];
    uint8_t snrNum = dataPtr[1];
    uint8_t* data = &(dataPtr[3]);

    /* TODO: add pal_add_cri_sel */

    if (snrNum == memoryEccError)
    {
        /* SEL from MEMORY_ECC_ERR Sensor */
        switch (data[0] & 0x0F)
        {
            case 0x0:
                if (snrType == 0x0C)
                {
                    errLog = "Correctable";
                }
                else if (snrType == 0x10)
                {
                    errLog = "Correctable ECC error Logging Disabled";
                }
                break;
            case 0x1:
                errLog = "Uncorrectable";
                break;
            case 0x5:
                errLog = "Correctable ECC error Logging Limit Disabled";
                break;
            default:
                errLog = "Unknown";
        }
    }
    else if (snrNum == memoryErrLogDIS)
    {
        // SEL from MEMORY_ERR_LOG_DIS Sensor
        if ((data[0] & 0x0F) == 0x0)
        {
            errLog = "Correctable Memory Error Logging Disabled";
        }
        else
        {
            errLog = "Unknown";
        }
    }
    else
    {
        errLog = "Unknown";
        return;
    }

    /* Common routine for both MEM_ECC_ERR and MEMORY_ERR_LOG_DIS */

    errLog += " (DIMM " + byteToStr(data[2]) + ") Logical Rank " +
              std::to_string(data[1] & 0x03);

    /* DIMM number (data[2]):
     * Bit[7:5]: Socket number  (Range: 0-7)
     * Bit[4:3]: Channel number (Range: 0-3)
     * Bit[2:0]: DIMM number    (Range: 0-7)
     */

    /* TODO: Verify these bits */
    std::string cpuStr = "CPU# " + std::to_string((data[2] & 0xE0) >> 5);
    std::string chStr = "CHN# " + std::to_string((data[2] & 0x18) >> 3);
    std::string dimmStr = "DIMM# " + std::to_string(data[2] & 0x7);

    switch ((data[1] & 0xC) >> 2)
    {
        case 0x0:
        {

            /* All Info Valid */
            uint8_t chnNum = (data[2] & 0x1C) >> 2;
            uint8_t dimmNum = data[2] & 0x3;

            /* TODO: If critical SEL logging is available, do it */
            if (snrType == 0x0C)
            {
                if ((data[0] & 0x0F) == 0x0)
                {
                    /* TODO: add_cri_sel */
                    /* "DIMM"+ 'A'+ chnNum + dimmNum + " ECC err,FRU:1"
                     */
                }
                else if ((data[0] & 0x0F) == 0x1)
                {
                    /* TODO: add_cri_sel */
                    /* "DIMM"+ 'A'+ chnNum + dimmNum + " UECC err,FRU:1"
                     */
                }
            }
            /* Continue to parse the error into a string. All Info Valid
             */
            errLog += " (" + cpuStr + ", " + chStr + ", " + dimmStr + ")";
        }

        break;
        case 0x1:

            /* DIMM info not valid */
            errLog += " (" + cpuStr + ", " + chStr + ")";
            break;
        case 0x2:

            /* CHN info not valid */
            errLog += " (" + cpuStr + ", " + dimmStr + ")";
            break;
        case 0x3:

            /* CPU info not valid */
            errLog += " (" + chStr + ", " + dimmStr + ")";
            break;
    }
}

static void logPwrErr(uint8_t* data, std::string& errLog)
{

    if (data[0] == 0x1)
    {
        errLog = "SYS_PWROK failure";
        /* Also try logging to Critial log file, if available */
        /* "SYS_PWROK failure,FRU:1" */
    }
    else if (data[0] == 0x2)
    {
        errLog = "PCH_PWROK failure";
        /* Also try logging to Critial log file, if available */
        /* "PCH_PWROK failure,FRU:1" */
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logCatErr(uint8_t* data, std::string& errLog)
{

    if (data[0] == 0x0)
    {
        errLog = "IERR/CATERR";
        /* Also try logging to Critial log file, if available */
        /* "IERR,FRU:1 */
    }
    else if (data[0] == 0xB)
    {
        errLog = "MCERR/CATERR";
        /* Also try logging to Critial log file, if available */
        /* "MCERR,FRU:1 */
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logDimmHot(uint8_t* data, std::string& errLog)
{
    if ((data[0] << 16 | data[1] << 8 | data[2]) == 0x01FFFF)
    {
        errLog = "SOC MEMHOT";
    }
    else
    {
        errLog = "Unknown";
        /* Also try logging to Critial log file, if available */
        /* ""CPU_DIMM_HOT %s,FRU:1" */
    }
}

static void logSwNMI(uint8_t* data, std::string& errLog)
{
    if ((data[0] << 16 | data[1] << 8 | data[2]) == 0x03FFFF)
    {
        errLog = "Software NMI";
    }
    else
    {
        errLog = "Unknown SW NMI";
    }
}

static void logCPUThermalSts(uint8_t* data, std::string& errLog)
{
    switch (data[0])
    {
        case 0x0:
            errLog = "CPU Critical Temperature";
            break;
        case 0x1:
            errLog = "PROCHOT#";
            break;
        case 0x2:
            errLog = "TCC Activation";
            break;
        default:
            errLog = "Unknown";
    }
}

static void logMEPwrState(uint8_t* data, std::string& errLog)
{
    switch (data[0])
    {
        case 0:
            errLog = "RUNNING";
            break;
        case 2:
            errLog = "POWER_OFF";
            break;
        default:
            errLog = "Unknown[" + std::to_string(data[0]) + "]";
            break;
    }
}

static void logSPSFwHealth(uint8_t* data, std::string& errLog)
{
    if ((data[0] & 0x0F) == 0x00)
    {
        const std::vector<std::string> tmpStr = {
            "Recovery GPIO forced",
            "Image execution failed",
            "Flash erase error",
            "Flash state information",
            "Internal error",
            "BMC did not respond",
            "Direct Flash update",
            "Manufacturing error",
            "Automatic Restore to Factory Presets",
            "Firmware Exception",
            "Flash Wear-Out Protection Warning",
            "Unknown",
            "Unknown",
            "DMI interface error",
            "MCTP interface error",
            "Auto-configuration finished",
            "Unsupported Segment Defined Feature",
            "Unknown",
            "CPU Debug Capability Disabled",
            "UMA operation error"};

        if (data[1] < 0x14)
        {
            errLog = tmpStr[data[1]];
        }
        else
        {
            errLog = "Unknown";
        }
    }
    else if ((data[0] & 0x0F) == 0x01)
    {
        errLog = "SMBus link failure";
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logNmExcA(uint8_t* data, std::string& errLog)
{
    /*NM4.0 #550710, Revision 1.95, and turn to p.155*/
    if (data[0] == 0xA8)
    {
        errLog = "Policy Correction Time Exceeded";
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logPCHThermal(uint8_t* data, std::string& errLog)
{
    const std::vector<std::string> thresEvtName = {"Lower Non-critical",
                                                   "Unknown",
                                                   "Lower Critical",
                                                   "Unknown",
                                                   "Lower Non-recoverable",
                                                   "Unknown",
                                                   "Unknown",
                                                   "Upper Non-critical",
                                                   "Unknown",
                                                   "Upper Critical",
                                                   "Unknown",
                                                   "Upper Non-recoverable"};

    if ((data[0] & 0x0f) < 12)
    {
        errLog = thresEvtName[(data[0] & 0x0f)];
    }
    else
    {
        errLog = "Unknown";
    }

    errLog += ", curr_val: " + std::to_string(data[1]) +
              " C, thresh_val: " + std::to_string(data[2]) + " C";
}

static void logNmHealth(uint8_t* data, std::string& errLog)
{
    std::vector<std::string> nmErrType = {
        "Unknown",
        "Unknown",
        "Unknown",
        "Unknown",
        "Unknown",
        "Unknown",
        "Unknown",
        "Extended Telemetry Device Reading Failure",
        "Outlet Temperature Reading Failure",
        "Volumetric Airflow Reading Failure",
        "Policy Misconfiguration",
        "Power Sensor Reading Failure",
        "Inlet Temperature Reading Failure",
        "Host Communication Error",
        "Real-time Clock Synchronization Failure",
        "Platform Shutdown Initiated by Intel NM Policy",
        "Unknown"};
    uint8_t nmTypeIdx = (data[0] & 0xf);
    uint8_t domIdx = (data[1] & 0xf);
    uint8_t errIdx = ((data[1] >> 4) & 0xf);

    if (nmTypeIdx == 2)
    {
        errLog = "SensorIntelNM";
    }
    else
    {
        errLog = "Unknown";
    }

    errLog += ", Domain:" + nmDomName[domIdx] +
              ", ErrType:" + nmErrType[errIdx] + ", Err:0x" +
              byteToStr(data[2]);
}

static void logNmCap(uint8_t* data, std::string& errLog)
{

    const std::vector<std::string> nmCapStsStr = {"Not Available", "Available"};
    if (data[0] & 0x7) // BIT1=policy, BIT2=monitoring, BIT3=pwr
                       // limit and the others are reserved
    {
        errLog = "PolicyInterface:" + nmCapStsStr[BIT(data[0], 0)] +
                 ",Monitoring:" + nmCapStsStr[BIT(data[0], 1)] +
                 ",PowerLimit:" + nmCapStsStr[BIT(data[0], 2)];
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logNmThreshold(uint8_t* data, std::string& errLog)
{
    uint8_t thresNum = (data[0] & 0x3);
    uint8_t domIdx = (data[1] & 0xf);
    uint8_t polId = data[2];
    uint8_t polEvtIdx = BIT(data[0], 3);
    const std::vector<std::string> polEvtStr = {
        "Threshold Exceeded", "Policy Correction Time Exceeded"};

    errLog = "Threshold Number:" + std::to_string(thresNum) + "-" +
             polEvtStr[polEvtIdx] + ", Domain:" + nmDomName[domIdx] +
             ", PolicyID:0x" + byteToStr(polId);
}

static void logPwrThreshold(uint8_t* data, std::string& errLog)
{
    if (data[0] == 0x00)
    {
        errLog = "Limit Not Exceeded";
    }
    else if (data[0] == 0x01)
    {
        errLog = "Limit Exceeded";
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logMSMI(uint8_t* data, std::string& errLog)
{

    if (data[0] == 0x0)
    {
        errLog = "IERR/MSMI";
    }
    else if (data[0] == 0x0B)
    {
        errLog = "MCERR/MSMI";
    }
    else
    {
        errLog = "Unknown";
    }
}

static void logHprWarn(uint8_t* data, std::string& errLog)
{
    if (data[2] == 0x01)
    {
        if (data[1] == 0xFF)
        {
            errLog = "Infinite Time";
        }
        else
        {
            errLog = std::to_string(data[1]) + " minutes";
        }
    }
    else
    {
        errLog = "Unknown";
    }
}

static const boost::container::flat_map<
    uint8_t,
    std::pair<std::string, std::function<void(uint8_t*, std::string&)>>>
    sensorNameTable = {{0xE9, {"SYSTEM_EVENT", logSysEvent}},
                       {0x7D, {"THERM_THRESH_EVT", logThermalEvent}},
                       {0xAA, {"BUTTON", logDefault}},
                       {0xAB, {"POWER_STATE", logDefault}},
                       {0xEA, {"CRITICAL_IRQ", logCritIrq}},
                       {0x2B, {"POST_ERROR", logPostErr}},
                       {0x40, {"MACHINE_CHK_ERR", logMchChkErr}},
                       {0x41, {"PCIE_ERR", logPcieErr}},
                       {0x43, {"IIO_ERR", logIioErr}},
                       {0X63, {"MEMORY_ECC_ERR", logDefault}},
                       {0X87, {"MEMORY_ERR_LOG_DIS", logDefault}},
                       {0X51, {"PROCHOT_EXT", logDefault}},
                       {0X56, {"PWR_ERR", logPwrErr}},
                       {0xE6, {"CATERR_A", logCatErr}},
                       {0xEB, {"CATERR_B", logCatErr}},
                       {0xB3, {"CPU_DIMM_HOT", logDimmHot}},
                       {0x90, {"SOFTWARE_NMI", logSwNMI}},
                       {0x1C, {"CPU0_THERM_STATUS", logCPUThermalSts}},
                       {0x1D, {"CPU1_THERM_STATUS", logCPUThermalSts}},
                       {0x16, {"ME_POWER_STATE", logMEPwrState}},
                       {0x17, {"SPS_FW_HEALTH", logSPSFwHealth}},
                       {0x18, {"NM_EXCEPTION_A", logNmExcA}},
                       {0x08, {"PCH_THERM_THRESHOLD", logPCHThermal}},
                       {0x19, {"NM_HEALTH", logNmHealth}},
                       {0x1A, {"NM_CAPABILITIES", logNmCap}},
                       {0x1B, {"NM_THRESHOLD", logNmThreshold}},
                       {0x3B, {"PWR_THRESH_EVT", logPwrThreshold}},
                       {0xE7, {"MSMI", logMSMI}},
                       {0xC5, {"HPR_WARNING", logHprWarn}}};

static void parseSelHelper(StdSELEntry* data, std::string& errStr)
{

    /* Check if sensor type is OS_BOOT (0x1f) */
    if (data->sensorType == 0x1F)
    {
        /* OS_BOOT used by OS */
        switch (data->eventData1 & 0xF)
        {
            case 0x07:
                errStr = "Base OS/Hypervisor Installation started";
                break;
            case 0x08:
                errStr = "Base OS/Hypervisor Installation completed";
                break;
            case 0x09:
                errStr = "Base OS/Hypervisor Installation aborted";
                break;
            case 0x0A:
                errStr = "Base OS/Hypervisor Installation failed";
                break;
            default:
                errStr = "Unknown";
        }
        return;
    }

    auto findSensorName = sensorNameTable.find(data->sensorNum);
    if (findSensorName == sensorNameTable.end())
    {
        errStr = "Unknown";
        return;
    }
    else
    {
        switch (data->sensorNum)
        {
            /* logMemErr function needs data from sensor type */
            case memoryEccError:
            case memoryErrLogDIS:
                findSensorName->second.second(&(data->sensorType), errStr);
                break;
            /* Other sensor function needs only event data for parsing */
            default:
                findSensorName->second.second(&(data->eventData1), errStr);
        }
    }

    if (((data->eventData3 & 0x80) >> 7) == 0)
    {
        errStr += " Assertion";
    }
    else
    {
        errStr += " Deassertion";
    }
}

static void parseDimmPhyloc(StdSELEntry* data, std::string& errStr)
{
    // Log when " All info available"
    uint8_t chNum = (data->eventData3 & 0x18) >> 3;
    uint8_t dimmNum = data->eventData3 & 0x7;
    uint8_t rankNum = data->eventData2 & 0x03;
    uint8_t nodeNum = (data->eventData3 & 0xE0) >> 5;

    if (chNum == 3 && dimmNum == 0)
    {
        errStr += " Node: " + std::to_string(nodeNum) + "," +
                  " Card: " + std::to_string(chNum) + "," +
                  " Module: " + std::to_string(dimmNum) + "," +
                  " Rank Number: " + std::to_string(rankNum) + "," +
                  "  Location: DIMM A0";
    }
    else if (chNum == 2 && dimmNum == 0)
    {
        errStr += " Node: " + std::to_string(nodeNum) + "," +
                  " Card: " + std::to_string(chNum) + "," +
                  " Module: " + std::to_string(dimmNum) + "," +
                  " Rank Number: " + std::to_string(rankNum) + "," +
                  " Location: DIMM B0";
    }
    else if (chNum == 4 && dimmNum == 0)
    {
        errStr += " Node: " + std::to_string(nodeNum) + "," +
                  " Card: " + std::to_string(chNum) + "," +
                  " Module: " + std::to_string(dimmNum) + "," +
                  " Rank Number: " + std::to_string(rankNum) + "," +
                  " Location: DIMM C0 ";
    }
    else if (chNum == 5 && dimmNum == 0)
    {
        errStr += " Node: " + std::to_string(nodeNum) + "," +
                  " Card: " + std::to_string(chNum) + "," +
                  " Module: " + std::to_string(dimmNum) + "," +
                  " Rank Number: " + std::to_string(rankNum) + "," +
                  " Location: DIMM D0";
    }
    else
    {
        errStr += " Node: " + std::to_string(nodeNum) + "," +
                  " Card: " + std::to_string(chNum) + "," +
                  " Module: " + std::to_string(dimmNum) + "," +
                  " Rank Number: " + std::to_string(rankNum) + "," +
                  " Location: DIMM Unknow";
    }
}

static void parseStdSel(StdSELEntry* data, std::string& errStr)
{
    std::stringstream tmpStream;
    tmpStream << std::hex << std::uppercase;

    /* TODO: add pal_add_cri_sel */
    switch (data->sensorNum)
    {
        case memoryEccError:
            switch (data->eventData1 & 0x0F)
            {
                case 0x00:
                    errStr = "Correctable";
                    tmpStream << "DIMM" << std::setw(2) << std::setfill('0')
                              << data->eventData3 << " ECC err";
                    parseDimmPhyloc(data, errStr);
                    break;
                case 0x01:
                    errStr = "Uncorrectable";
                    tmpStream << "DIMM" << std::setw(2) << std::setfill('0')
                              << data->eventData3 << " UECC err";
                    parseDimmPhyloc(data, errStr);
                    break;
                case 0x02:
                    errStr = "Parity";
                    break;
                case 0x05:
                    errStr = "Correctable ECC error Logging Limit Reached";
                    break;
                default:
                    errStr = "Unknown";
            }
            break;
        case memoryErrLogDIS:
            if ((data->eventData1 & 0x0F) == 0)
            {
                errStr = "Correctable Memory Error Logging Disabled";
            }
            else
            {
                errStr = "Unknown";
            }
            break;
        default:
            parseSelHelper(data, errStr);
            return;
    }

    errStr += " (DIMM " + std::to_string(data->eventData3) + ")";
    errStr += " Logical Rank " + std::to_string(data->eventData2 & 0x03);

    switch ((data->eventData2 & 0x0C) >> 2)
    {
        case 0x00:
            // Ignore when " All info available"
            break;
        case 0x01:
            errStr += " DIMM info not valid";
            break;
        case 0x02:
            errStr += " CHN info not valid";
            break;
        case 0x03:
            errStr += " CPU info not valid";
            break;
        default:
            errStr += " Unknown";
    }

    if (((data->eventType & 0x80) >> 7) == 0)
    {
        errStr += " Assertion";
    }
    else
    {
        errStr += " Deassertion";
    }

    return;
}

static void parseOemSel(TsOemSELEntry* data, std::string& errStr)
{
    std::stringstream tmpStream;
    tmpStream << std::hex << std::uppercase << std::setfill('0');

    switch (data->recordType)
    {
        case 0xC0:
            tmpStream << "VID:0x" << std::setw(2) << (int)data->oemData[1]
                      << std::setw(2) << (int)data->oemData[0] << " DID:0x"
                      << std::setw(2) << (int)data->oemData[3] << std::setw(2)
                      << (int)data->oemData[2] << " Slot:0x" << std::setw(2)
                      << (int)data->oemData[4] << " Error ID:0x" << std::setw(2)
                      << (int)data->oemData[5];
            break;
        case 0xC2:
            tmpStream << "Extra info:0x" << std::setw(2)
                      << (int)data->oemData[1] << " MSCOD:0x" << std::setw(2)
                      << (int)data->oemData[3] << std::setw(2)
                      << (int)data->oemData[2] << " MCACOD:0x" << std::setw(2)
                      << (int)data->oemData[5] << std::setw(2)
                      << (int)data->oemData[4];
            break;
        case 0xC3:
            int bank = (data->oemData[1] & 0xf0) >> 4;
            int col = ((data->oemData[1] & 0x0f) << 8) | data->oemData[2];

            tmpStream << "Fail Device:0x" << std::setw(2)
                      << (int)data->oemData[0] << " Bank:0x" << std::setw(2)
                      << bank << " Column:0x" << std::setw(2) << col
                      << " Failed Row:0x" << std::setw(2)
                      << (int)data->oemData[3] << std::setw(2)
                      << (int)data->oemData[4] << std::setw(2)
                      << (int)data->oemData[5];
    }

    errStr = tmpStream.str();

    return;
}

static void parseOemUnifiedSel(NtsOemSELEntry* data, std::string& errStr)
{
    uint8_t* ptr = data->oemData;
    int genInfo = ptr[0];
    int errType = genInfo & 0x0f;
    std::vector<std::string> dimmEvent = {
        "Memory training failure", "Memory correctable error",
        "Memory uncorrectable error", "Reserved"};

    std::stringstream tmpStream;
    tmpStream << std::hex << std::uppercase << std::setfill('0');

    switch (errType)
    {
        case unifiedPcieErr:
            if (((genInfo & 0x10) >> 4) == 0) // x86
            {
                tmpStream << "GeneralInfo: x86/PCIeErr(0x" << std::setw(2)
                          << genInfo << "),";
            }

            tmpStream << " Bus " << std::setw(2) << (int)(ptr[8]) << "/Dev "
                      << std::setw(2) << (int)(ptr[7] >> 3) << "/Fun "
                      << std::setw(2) << (int)(ptr[7] & 0x7)
                      << ", TotalErrID1Cnt: 0x" << std::setw(4)
                      << (int)((ptr[10] << 8) | ptr[9]) << ", ErrID2: 0x"
                      << std::setw(2) << (int)(ptr[11]) << ", ErrID1: 0x"
                      << std::setw(2) << (int)(ptr[12]);

            break;
        case unifiedMemErr:
            tmpStream << "GeneralInfo: MemErr(0x" << std::setw(2) << genInfo
                      << "), DIMM Slot Location: Sled " << std::setw(2)
                      << (int)((ptr[5] >> 4) & 0x03) << "/Socket "
                      << std::setw(2) << (int)(ptr[5] & 0x0f) << ", Channel "
                      << std::setw(2) << (int)(ptr[6] & 0x0f) << ", Slot "
                      << std::setw(2) << (int)(ptr[7] & 0x0f)
                      << ", DIMM Failure Event: " << dimmEvent[(ptr[9] & 0x03)]
                      << ", Major Code: 0x" << std::setw(2) << (int)(ptr[10])
                      << ", Minor Code: 0x" << std::setw(2) << (int)(ptr[11]);

            break;
        default:
            std::vector<uint8_t> oemData(ptr, ptr + 13);
            std::string oemDataStr;
            toHexStr(oemData, oemDataStr);
            tmpStream << "Undefined Error Type(0x" << std::setw(2) << errType
                      << "), Raw: " << oemDataStr;
    }

    errStr = tmpStream.str();

    return;
}

static void parseSelData(uint8_t fruId, std::vector<uint8_t>& reqData,
                         std::string& msgLog)
{

    /* Get record type */
    int recType = reqData[2];
    std::string errType, errLog;

    uint8_t* ptr = NULL;

    std::stringstream recTypeStream;
    recTypeStream << std::hex << std::uppercase << std::setfill('0')
                  << std::setw(2) << recType;

    msgLog = "SEL Entry: FRU:" + std::to_string(fruId) + ", Record: ";

    if (recType == stdErrType)
    {
        StdSELEntry* data = reinterpret_cast<StdSELEntry*>(&reqData[0]);
        std::string sensorName;

        errType = stdErr;
        if (data->sensorType == 0x1F)
        {
            sensorName = "OS";
        }
        else
        {
            auto findSensorName = sensorNameTable.find(data->sensorNum);
            if (findSensorName == sensorNameTable.end())
            {
                sensorName = "Unknown";
            }
            else
            {
                sensorName = findSensorName->second.first;
            }
        }

        std::tm* ts = localtime((time_t*)(&(data->timeStamp)));
        std::string timeStr = std::asctime(ts);

        parseStdSel(data, errLog);
        ptr = &(data->eventData1);
        std::vector<uint8_t> evtData(ptr, ptr + 3);
        std::string eventData;
        toHexStr(evtData, eventData);

        std::stringstream senNumStream;
        senNumStream << std::hex << std::uppercase << std::setfill('0')
                     << std::setw(2) << (int)(data->sensorNum);

        msgLog += errType + " (0x" + recTypeStream.str() +
                  "), Time: " + timeStr + ", Sensor: " + sensorName + " (0x" +
                  senNumStream.str() + "), Event Data: (" + eventData + ") " +
                  errLog;
    }
    else if ((recType >= oemTSErrTypeMin) && (recType <= oemTSErrTypeMax))
    {
        /* timestamped OEM SEL records */
        TsOemSELEntry* data = reinterpret_cast<TsOemSELEntry*>(&reqData[0]);
        ptr = data->mfrId;
        std::vector<uint8_t> mfrIdData(ptr, ptr + 3);
        std::string mfrIdStr;
        toHexStr(mfrIdData, mfrIdStr);

        ptr = data->oemData;
        std::vector<uint8_t> oemData(ptr, ptr + 6);
        std::string oemDataStr;
        toHexStr(oemData, oemDataStr);

        std::tm* ts = localtime((time_t*)(&(data->timeStamp)));
        std::string timeStr = std::asctime(ts);

        errType = oemTSErr;
        parseOemSel(data, errLog);

        msgLog += errType + " (0x" + recTypeStream.str() +
                  "), Time: " + timeStr + ", MFG ID: " + mfrIdStr +
                  ", OEM Data: (" + oemDataStr + ") " + errLog;
    }
    else if (recType == fbUniErrType)
    {
        NtsOemSELEntry* data = reinterpret_cast<NtsOemSELEntry*>(&reqData[0]);
        errType = fbUniSELErr;
        parseOemUnifiedSel(data, errLog);
        msgLog += errType + " (0x" + recTypeStream.str() + "), " + errLog;
    }
    else if ((recType >= oemNTSErrTypeMin) && (recType <= oemNTSErrTypeMax))
    {
        /* Non timestamped OEM SEL records */
        NtsOemSELEntry* data = reinterpret_cast<NtsOemSELEntry*>(&reqData[0]);
        errType = oemNTSErr;

        ptr = data->oemData;
        std::vector<uint8_t> oemData(ptr, ptr + 13);
        std::string oemDataStr;
        toHexStr(oemData, oemDataStr);

        parseOemSel((TsOemSELEntry*)data, errLog);
        msgLog += errType + " (0x" + recTypeStream.str() + "), OEM Data: (" +
                  oemDataStr + ") " + errLog;
    }
    else
    {
        errType = unknownErr;
        toHexStr(reqData, errLog);
        msgLog +=
            errType + " (0x" + recTypeStream.str() + ") RawData: " + errLog;
    }
}

} // namespace fb_oem::ipmi::sel

namespace ipmi
{

namespace storage
{

static void registerSELFunctions() __attribute__((constructor));
static fb_oem::ipmi::sel::SELData selObj __attribute__((init_priority(101)));

ipmi::RspType<uint8_t,  // SEL version
              uint16_t, // SEL entry count
              uint16_t, // free space
              uint32_t, // last add timestamp
              uint32_t, // last erase timestamp
              uint8_t>  // operation support
    ipmiStorageGetSELInfo()
{

    fb_oem::ipmi::sel::GetSELInfoData info;

    selObj.getInfo(info);
    return ipmi::responseSuccess(info.selVersion, info.entries, info.freeSpace,
                                 info.addTimeStamp, info.eraseTimeStamp,
                                 info.operationSupport);
}

ipmi::RspType<uint16_t, std::vector<uint8_t>>
    ipmiStorageGetSELEntry(std::vector<uint8_t> data)
{

    if (data.size() != sizeof(fb_oem::ipmi::sel::GetSELEntryRequest))
    {
        return ipmi::responseReqDataLenInvalid();
    }

    fb_oem::ipmi::sel::GetSELEntryRequest* reqData =
        reinterpret_cast<fb_oem::ipmi::sel::GetSELEntryRequest*>(&data[0]);

    if (reqData->reservID != 0)
    {
        if (!checkSELReservation(reqData->reservID))
        {
            return ipmi::responseInvalidReservationId();
        }
    }

    uint16_t selCnt = selObj.getCount();
    if (selCnt == 0)
    {
        return ipmi::responseSensorInvalid();
    }

    /* If it is asked for first entry */
    if (reqData->recordID == fb_oem::ipmi::sel::firstEntry)
    {
        /* First Entry (0x0000) as per Spec */
        reqData->recordID = 1;
    }
    else if (reqData->recordID == fb_oem::ipmi::sel::lastEntry)
    {
        /* Last entry (0xFFFF) as per Spec */
        reqData->recordID = selCnt;
    }

    std::string ipmiRaw;

    if (selObj.getEntry(reqData->recordID, ipmiRaw) < 0)
    {
        return ipmi::responseSensorInvalid();
    }

    std::vector<uint8_t> recDataBytes;
    if (fromHexStr(ipmiRaw, recDataBytes) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    /* Identify the next SEL record ID. If recordID is same as
     * total SeL count then next id should be last entry else
     * it should be incremented by 1 to current RecordID
     */
    uint16_t nextRecord;
    if (reqData->recordID == selCnt)
    {
        nextRecord = fb_oem::ipmi::sel::lastEntry;
    }
    else
    {
        nextRecord = reqData->recordID + 1;
    }

    if (reqData->readLen == fb_oem::ipmi::sel::entireRecord)
    {
        return ipmi::responseSuccess(nextRecord, recDataBytes);
    }
    else
    {
        if (reqData->offset >= fb_oem::ipmi::sel::selRecordSize ||
            reqData->readLen > fb_oem::ipmi::sel::selRecordSize)
        {
            return ipmi::responseUnspecifiedError();
        }
        std::vector<uint8_t> recPartData;

        auto diff = fb_oem::ipmi::sel::selRecordSize - reqData->offset;
        auto readLength = std::min(diff, static_cast<int>(reqData->readLen));

        for (int i = 0; i < readLength; i++)
        {
            recPartData.push_back(recDataBytes[i + reqData->offset]);
        }
        return ipmi::responseSuccess(nextRecord, recPartData);
    }
}

ipmi::RspType<uint16_t> ipmiStorageAddSELEntry(ipmi::Context::ptr ctx,
                                               std::vector<uint8_t> data)
{
    /* Per the IPMI spec, need to cancel any reservation when a
     * SEL entry is added
     */
    cancelSELReservation();

    if (data.size() != fb_oem::ipmi::sel::selRecordSize)
    {
        return ipmi::responseReqDataLenInvalid();
    }

    std::string ipmiRaw, logErr;
    toHexStr(data, ipmiRaw);

    /* Parse sel data and get an error log to be filed */
    fb_oem::ipmi::sel::parseSelData((ctx->hostIdx + 1), data, logErr);

    static const std::string openBMCMessageRegistryVersion("0.1");
    std::string messageID =
        "OpenBMC." + openBMCMessageRegistryVersion + ".SELEntryAdded";

    /* Log the Raw SEL message to the journal */
    std::string journalMsg = "SEL Entry Added: " + ipmiRaw;

    phosphor::logging::log<phosphor::logging::level::INFO>(
        journalMsg.c_str(),
        phosphor::logging::entry("IPMISEL_MESSAGE_ID=%s", messageID.c_str()),
        phosphor::logging::entry("IPMISEL_MESSAGE_ARGS=%s", logErr.c_str()));

    int responseID = selObj.addEntry(ipmiRaw.c_str());
    if (responseID < 0)
    {
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess((uint16_t)responseID);
}

ipmi::RspType<uint8_t> ipmiStorageClearSEL(uint16_t reservationID,
                                           const std::array<uint8_t, 3>& clr,
                                           uint8_t eraseOperation)
{
    if (!checkSELReservation(reservationID))
    {
        return ipmi::responseInvalidReservationId();
    }

    static constexpr std::array<uint8_t, 3> clrExpected = {'C', 'L', 'R'};
    if (clr != clrExpected)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    /* If there is no sel then return erase complete */
    if (selObj.getCount() == 0)
    {
        return ipmi::responseSuccess(fb_oem::ipmi::sel::eraseComplete);
    }

    /* Erasure status cannot be fetched, so always return erasure
     * status as `erase completed`.
     */
    if (eraseOperation == fb_oem::ipmi::sel::getEraseStatus)
    {
        return ipmi::responseSuccess(fb_oem::ipmi::sel::eraseComplete);
    }

    /* Check that initiate erase is correct */
    if (eraseOperation != fb_oem::ipmi::sel::initiateErase)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    /* Per the IPMI spec, need to cancel any reservation when the
     * SEL is cleared
     */
    cancelSELReservation();

    /* Clear the complete Sel Json object */
    if (selObj.clear() < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(fb_oem::ipmi::sel::eraseComplete);
}

ipmi::RspType<uint32_t> ipmiStorageGetSELTime()
{
    struct timespec selTime = {};

    if (clock_gettime(CLOCK_REALTIME, &selTime) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(selTime.tv_sec);
}

ipmi::RspType<> ipmiStorageSetSELTime(uint32_t selTime)
{
    // Set SEL Time is not supported
    return ipmi::responseInvalidCommand();
}

ipmi::RspType<uint16_t> ipmiStorageGetSELTimeUtcOffset()
{
    /* TODO: For now, the SEL time stamp is based on UTC time,
     * so return 0x0000 as offset. Might need to change once
     * supporting zones in SEL time stamps
     */

    uint16_t utcOffset = 0x0000;
    return ipmi::responseSuccess(utcOffset);
}

void registerSELFunctions()
{
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
                          ipmi::Privilege::Operator, ipmiStorageAddSELEntry);

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

    // <Get SEL Time UTC Offset>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSelTimeUtcOffset,
                          ipmi::Privilege::User,
                          ipmiStorageGetSELTimeUtcOffset);

    return;
}

} // namespace storage
} // namespace ipmi
