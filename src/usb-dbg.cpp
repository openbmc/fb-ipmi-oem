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

#include <commandutils.hpp>
#include <usb-dbg.hpp>

namespace ipmi
{

ipmi_ret_t getNetworkData(uint8_t lan_param, char* data);
std::string getMotherBoardFruName();
int8_t getFruData(std::string& serial, std::string& name);
int8_t sysConfig(std::vector<std::string>& data, size_t pos);
int8_t procInfo(std::string& result, size_t pos);
std::vector<std::pair<std::string, std::string>> getHostFWVersions(int hostNum);

bool isMultiHostPlatform();

/* Declare Host Selector interface and path */
namespace selector
{
const std::string path = "/xyz/openbmc_project/Chassis/Buttons/HostSelector";
const std::string interface =
    "xyz.openbmc_project.Chassis.Buttons.HostSelector";
} // namespace selector

/* Declare storage functions used here */
namespace storage
{
int getSensorValue(std::string&, double&);
int getSensorUnit(std::string&, std::string&);
int getSensorThreshold(std::string&, std::string&);
} // namespace storage

namespace boot
{
std::tuple<std::string, std::string> objPath(size_t id);
void setBootOrder(std::string bootObjPath, const std::vector<uint8_t>& bootSeq,
                  std::string hostName);
void getBootOrder(std::string bootObjPath, std::vector<uint8_t>& bootSeq,
                  std::string hostName);
} // namespace boot

void getMaxHostPosition(size_t& maxPosition)
{
    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, ipmi::selector::interface, ipmi::selector::path);
        Value variant =
            getDbusProperty(*dbus, service, ipmi::selector::path,
                            ipmi::selector::interface, "MaxPosition");
        maxPosition = std::get<size_t>(variant);
    }
    catch (const std::exception& e)
    {
        lg2::error("Unable to get max host position - {MAXPOSITION}",
                   "MAXPOSITION", maxPosition);
        throw e;
    }
}

void getSelectorPosition(size_t& hostPosition)
{
    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, ipmi::selector::interface, ipmi::selector::path);
        Value variant = getDbusProperty(*dbus, service, ipmi::selector::path,
                                        ipmi::selector::interface, "Position");
        hostPosition = std::get<size_t>(variant);
    }
    catch (const std::exception& e)
    {
        lg2::error("Unable to get host position - {POSITION}", "POSITION",
                   hostPosition);
        throw e;
    }
}

static int panelNum = (sizeof(panels) / sizeof(struct ctrl_panel)) - 1;

/* Returns the FRU the hand-switch is switched to. If it is switched to BMC
 * it returns FRU_ALL. Note, if in err, it returns FRU_ALL */
static size_t plat_get_fru_sel()
{
    size_t position;
    bool platform = isMultiHostPlatform();
    if (platform == true)
    {
        getSelectorPosition(position);
        if (position == BMC_POSITION)
        {
            return FRU_ALL;
        }
    }
    else
    {
        /* For Tiogapass it just return 1,
         *  can modify to support more platform */
        position = 1;
    }
    return position;
}

// return 0 on seccuess
void frame::init(size_t size)
{
    // Reset status
    idx_head = idx_tail = 0;
    lines = 0;
    esc_sts = 0;
    pages = 1;

    if (buf != nullptr && max_size == size)
    {
        return;
    }

    if (buf != nullptr && max_size != size)
    {
        delete[] buf;
    }
    // Initialize Configuration
    title[0] = '\0';
    buf = new char[size];
    max_size = size;
    max_page = size;
    line_per_page = 7;
    line_width = 16;
    overwrite = false;

    return;
}

// return 0 on seccuess
void frame::append(const std::string& str, size_t indent)
{
    for (auto ch : parse(str, indent))
    {
        if (isFull())
        {
            if (overwrite)
            {
                if (buf[idx_head] == LINE_DELIMITER)
                    lines--;
                idx_head = (idx_head + 1) % max_size;
            }
            else
            {
                throw std::overflow_error("No room in buffer");
            }
        }

        buf[idx_tail] = ch;
        if (ch == LINE_DELIMITER)
            lines++;

        idx_tail = (idx_tail + 1) % max_size;
    }

    pages = (lines / line_per_page) + ((lines % line_per_page) ? 1 : 0);

    if (pages > max_page)
        pages = max_page;

    return;
}

// return page size
int frame::getPage(size_t page, char* page_buf, size_t page_buf_size)
{
    int ret;
    uint16_t line = 0;
    uint16_t idx, len;

    if (buf == nullptr)
        return -1;

    // 1-based page
    if (page > pages || page < 1)
        return -1;

    if (page_buf == nullptr || page_buf_size == 0)
        return -1;

    ret = snprintf(page_buf, 17, "%-10s %02zd/%02zd", title, page, pages);
    len = strlen(page_buf);
    if (ret < 0)
        return -1;

    line = 0;
    idx = idx_head;
    while (line < ((page - 1) * line_per_page) && idx != idx_tail)
    {
        if (buf[idx] == LINE_DELIMITER)
            line++;
        idx = (idx + 1) % max_size;
    }

    while (line < ((page)*line_per_page) && idx != idx_tail)
    {
        if (buf[idx] == LINE_DELIMITER)
        {
            line++;
        }
        else
        {
            page_buf[len++] = buf[idx];
            if (len == (page_buf_size - 1))
            {
                break;
            }
        }
        idx = (idx + 1) % max_size;
    }

    return len;
}

bool frame::isFull() const
{
    if (buf == nullptr)
        return true;

    if ((idx_tail + 1) % max_size == idx_head)
        return true;
    else
        return false;
}

// return 1 for Escape Sequence
bool frame::isEscSeq(char chr)
{
    uint8_t curr_sts = esc_sts;

    if (esc_sts == 0 && (chr == 0x1b))
        esc_sts = 1; // Escape Sequence
    else if (esc_sts == 1 && (chr == 0x5b))
        esc_sts = 2; // Control Sequence Introducer(CSI)
    else if (esc_sts == 1 && (chr != 0x5b))
        esc_sts = 0;
    else if (esc_sts == 2 && (chr >= 0x40 && chr <= 0x7e))
        esc_sts = 0;

    if (curr_sts || esc_sts)
        return true;
    else
        return false;
}

// return 0 on success
auto frame::parse(const std::string& input, size_t indent) -> std::string
{
    if (indent > line_width)
        return {};

    std::string result;
    size_t linepos = 0;

    for (auto ch : input)
    {
        if (linepos == 0)
        {
            result.append(indent, ' ');
            linepos = indent;
        }

        // Insert character.
        result.push_back(ch);

        if (!isEscSeq(ch))
        {
            // Check if new line is needed.
            if (++linepos == line_width)
            {
                result.push_back(LINE_DELIMITER);
                linepos = 0;
            }
        }
    }

    // Fill out remaining line.
    result.append(line_width - linepos, ' ');
    result.push_back(LINE_DELIMITER);

    return result;
}

static int chk_cri_sel_update(uint8_t* cri_sel_up)
{
    FILE* fp;
    struct stat file_stat;
    size_t pos = plat_get_fru_sel();
    static uint8_t pre_pos = 0xff;

    fp = fopen("/mnt/data/cri_sel", "r");
    if (fp)
    {
        if ((stat("/mnt/data/cri_sel", &file_stat) == 0) &&
            (file_stat.st_mtime != frame_sel.mtime || pre_pos != pos))
        {
            *cri_sel_up = 1;
        }
        else
        {
            *cri_sel_up = 0;
        }
        fclose(fp);
    }
    else
    {
        if (frame_sel.buf == nullptr || frame_sel.lines != 0 || pre_pos != pos)
        {
            *cri_sel_up = 1;
        }
        else
        {
            *cri_sel_up = 0;
        }
    }
    pre_pos = pos;
    return 0;
}

int plat_udbg_get_frame_info(uint8_t* num)
{
    *num = 3;
    return 0;
}

int plat_udbg_get_updated_frames(uint8_t* count, uint8_t* buffer)
{
    uint8_t cri_sel_up = 0;
    uint8_t info_page_up = 1;

    *count = 0;

    // info page update
    if (info_page_up == 1)
    {
        buffer[*count] = 1;
        *count += 1;
    }

    // cri sel update
    chk_cri_sel_update(&cri_sel_up);
    if (cri_sel_up == 1)
    {
        buffer[*count] = 2;
        *count += 1;
    }

    // cri sensor update
    buffer[*count] = 3;
    *count += 1;

    return 0;
}

int plat_udbg_get_post_desc(uint8_t index, uint8_t* next, uint8_t phase,
                            uint8_t* end, uint8_t* length, uint8_t* buffer)
{
    nlohmann::json postObj;
    std::string postCode;

    /* Get post description data stored in json file */
    std::ifstream file(JSON_POST_DATA_FILE);
    if (file)
    {
        file >> postObj;
        file.close();
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Post code description file not found",
            phosphor::logging::entry("POST_CODE_FILE=%s", JSON_POST_DATA_FILE));
        return -1;
    }

    std::string phaseStr = "PhaseAny";
    if (postObj.find(phaseStr) == postObj.end())
    {
        phaseStr = "Phase" + std::to_string(phase);
    }

    if (postObj.find(phaseStr) == postObj.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Post code phase not available",
            phosphor::logging::entry("PHASE=%d", phase));
        return -1;
    }

    auto phaseObj = postObj[phaseStr];
    int phaseSize = phaseObj.size();

    for (int i = 0; i < phaseSize; i++)
    {
        postCode = phaseObj[i][0];
        if (index == stoul(postCode, nullptr, 16))
        {
            std::string postDesc = phaseObj[i][1];
            *length = postDesc.size();
            memcpy(buffer, postDesc.data(), *length);
            buffer[*length] = '\0';

            if (phaseSize != i + 1)
            {
                postCode = phaseObj[i + 1][0];
                *next = stoul(postCode, nullptr, 16);
                *end = 0;
            }
            else
            {
                if (postObj.size() != phase)
                {
                    std::string nextPhaseStr =
                        "Phase" + std::to_string(phase + 1);
                    postCode = postObj[nextPhaseStr][0][0];
                    *next = stoul(postCode, nullptr, 16);
                    *end = 0;
                }
                else
                {
                    *next = 0xff;
                    *end = 1;
                }
            }

            return 0;
        }
    }

    phosphor::logging::log<phosphor::logging::level::ERR>(
        "Post code description data not available",
        phosphor::logging::entry("PHASE_CODE=%d_0x%x", phase, index));
    return -1;
}

int plat_udbg_get_gpio_desc(uint8_t index, uint8_t* next, uint8_t* level,
                            uint8_t* def, uint8_t* length, uint8_t* buffer)
{
    nlohmann::json gpioObj;
    std::string gpioPin;

    /* Get gpio data stored in json file */
    std::ifstream file(JSON_GPIO_DATA_FILE);
    if (file)
    {
        file >> gpioObj;
        file.close();
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GPIO pin description file not found",
            phosphor::logging::entry("GPIO_PIN_DETAILS_FILE=%s",
                                     JSON_GPIO_DATA_FILE));
        return -1;
    }

    if (gpioObj.find(DEBUG_GPIO_KEY) == gpioObj.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "GPIO pin details not available",
            phosphor::logging::entry("GPIO_JSON_KEY=%d", DEBUG_GPIO_KEY));
        return -1;
    }

    auto obj = gpioObj[DEBUG_GPIO_KEY];
    int objSize = obj.size();

    for (int i = 0; i < objSize; i++)
    {
        if (obj[i].size() != GPIO_ARRAY_SIZE)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Size of gpio array is incorrect",
                phosphor::logging::entry("EXPECTED_SIZE=%d", GPIO_ARRAY_SIZE));
            return -1;
        }

        gpioPin = obj[i][GPIO_PIN_INDEX];
        if (index == stoul(gpioPin, nullptr, 16))
        {
            if (objSize != i + 1)
            {
                gpioPin = obj[i + 1][GPIO_PIN_INDEX];
                *next = stoul(gpioPin, nullptr, 16);
            }
            else
            {
                *next = 0xff;
            }

            *level = obj[i][GPIO_LEVEL_INDEX];
            *def = obj[i][GPIO_DEF_INDEX];
            std::string gpioDesc = obj[i][GPIO_DESC_INDEX];
            *length = gpioDesc.size();
            memcpy(buffer, gpioDesc.data(), *length);
            buffer[*length] = '\0';

            return 0;
        }
    }

    phosphor::logging::log<phosphor::logging::level::ERR>(
        "GPIO pin description data not available",
        phosphor::logging::entry("GPIO_PIN=0x%x", index));
    return -1;
}

static int getBiosVer(std::string& ver, size_t hostPosition)
{
    std::string sysfwVersionFile = std::format(SYSFW_VER_FILE, hostPosition);
    std::ifstream file(sysfwVersionFile);
    if (!file)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open system firmware version file",
            phosphor::logging::entry("FILE=%s", sysfwVersionFile.c_str()));
        return -1;
    }

    std::getline(file, ver);
    file.close();

    return 0;
}

int sendBicCmd(uint8_t netFn, uint8_t cmd, uint8_t bicAddr,
               std::vector<uint8_t>& cmdData, std::vector<uint8_t>& respData)
{
    static constexpr uint8_t lun = 0;

    auto bus = getSdBus();

    auto method = bus->new_method_call("xyz.openbmc_project.Ipmi.Channel.Ipmb",
                                       "/xyz/openbmc_project/Ipmi/Channel/Ipmb",
                                       "org.openbmc.Ipmb", "sendRequest");
    method.append(bicAddr, netFn, lun, cmd, cmdData);

    auto reply = bus->call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error reading from BIC");
        return -1;
    }

    IpmbMethodType resp;
    reply.read(resp);

    respData =
        std::move(std::get<std::remove_reference_t<decltype(respData)>>(resp));

    return 0;
}

int sendMeCmd(uint8_t netFn, uint8_t cmd, std::vector<uint8_t>& cmdData,
              std::vector<uint8_t>& respData)
{
    auto bus = getSdBus();

    if (DEBUG)
    {
        std::cout << "ME NetFn:cmd " << (int)netFn << ":" << (int)cmd << "\n";
        std::cout << "ME req data: ";
        for (auto d : cmdData)
        {
            std::cout << d << " ";
        }
        std::cout << "\n";
    }

    auto method = bus->new_method_call("xyz.openbmc_project.Ipmi.Channel.Ipmb",
                                       "/xyz/openbmc_project/Ipmi/Channel/Ipmb",
                                       "org.openbmc.Ipmb", "sendRequest");
    method.append(meAddress, netFn, lun, cmd, cmdData);

    auto reply = bus->call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error reading from ME");
        return -1;
    }

    IpmbMethodType resp;
    reply.read(resp);

    respData =
        std::move(std::get<std::remove_reference_t<decltype(respData)>>(resp));

    if (DEBUG)
    {
        std::cout << "ME resp data: ";
        for (auto d : respData)
        {
            std::cout << d << " ";
        }
        std::cout << "\n";
    }

    return 0;
}

static int udbg_get_info_page(uint8_t, uint8_t page, uint8_t* next,
                              uint8_t* count, uint8_t* buffer)
{
    char line_buff[1000];
    [[maybe_unused]] char* pres_dev = line_buff;
    [[maybe_unused]] size_t pos = plat_get_fru_sel();
    int ret;
    std::string serialName = "SerialNumber";
    std::string partName = "PartNumber";
    std::string verDel = "VERSION=";
    std::string verPath = "/etc/os-release";
    size_t hostPosition = 0;
    size_t maxPosition;

    if (page == 1)
    {
        // Only update frame data while getting page 1

        // initialize and clear frame
        frame_info.init();
        snprintf(frame_info.title, 32, "SYS_Info");

        bool platform = isMultiHostPlatform();
        if (platform == true)
        {
            hostPosition = plat_get_fru_sel();
        }

        getMaxHostPosition(maxPosition);
        std::string data;
        if (hostPosition == BMC_POSITION || hostInstances == "0")
        {
            data = "FRU:" + getMotherBoardFruName();
        }
        else if (hostPosition != BMC_POSITION && hostPosition <= maxPosition)
        {
            if (getMotherBoardFruName() != "")
            {
                data = "FRU:" + getMotherBoardFruName();
            }
            else
            {
                data = "FRU:slot" + std::to_string(hostPosition);
            }
        }
        frame_info.append(data);

        if (hostPosition <= 8 && hostPosition >= 1)
        {
            auto fwVec = getHostFWVersions(hostPosition);
            if (fwVec.empty())
            {
                std::cout << "No FW version found for host " << hostPosition
                          << std::endl;
            }
            else
            {
                for (const auto& fw : fwVec)
                {
                    frame_info.append(fw.first + "_FW_ver:");
                    frame_info.append(fw.second, 1);
                }
            }
        }

        // FRU
        frame_info.append("SN:");
        if (getFruData(data, serialName) != 0)
        {
            data = "Not Found";
        }
        frame_info.append(data, 1);
        frame_info.append("PN:");
        if (getFruData(data, partName) != 0)
        {
            data = "Not Found";
        }
        frame_info.append(data, 1);

        // LAN
        getNetworkData(3, line_buff);
        frame_info.append("BMC_IP:");
        frame_info.append(line_buff, 1);
        getNetworkData(59, line_buff);
        frame_info.append("BMC_IPv6:");
        frame_info.append(line_buff, 1);

        // BMC ver
        std::ifstream file(verPath);
        if (file)
        {
            std::string line;
            while (std::getline(file, line))
            {
                if (line.find(verDel) != std::string::npos)
                {
                    std::string bmcVer = line.substr(verDel.size());
                    frame_info.append("BMC_FW_ver:");
                    frame_info.append(bmcVer, 1);
                    break;
                }
            }
        }

        if (hostPosition != BMC_POSITION || hostInstances == "0")
        {
            // BIOS ver
            std::string biosVer;
            if (getBiosVer(biosVer, hostPosition) == 0)
            {
                frame_info.append("BIOS_FW_ver:");
                frame_info.append(biosVer, 1);
            }
        }

        /* TBD: Board ID needs implementation */
        // Board ID

        // Battery - Use Escape sequence
        frame_info.append("Battery:");
        frame_info.append(ESC_BAT "     ", 1);
        // frame_info.append(&frame_info, esc_bat, 1);

        // MCU Version - Use Escape sequence
        frame_info.append("MCUbl_ver:");
        frame_info.append(ESC_MCU_BL_VER, 1);
        frame_info.append("MCU_ver:");
        frame_info.append(ESC_MCU_RUN_VER, 1);

        // Sys config present device
        if (hostPosition != BMC_POSITION)
        {
            frame_info.append("Sys Conf. info:");

            // Dimm info
            std::vector<std::string> data;
            if (sysConfig(data, pos) == 0)
            {
                for (auto& info : data)
                {
                    frame_info.append(info, 1);
                }
            }
            else
            {
                frame_info.append("Not Found", 1);
            }

            // Processor info
            std::string result;
            if (procInfo(result, pos) != 0)
            {
                result = "Not Found";
            }
            frame_info.append(result, 1);
        }

    } // End of update frame

    if (page > frame_info.pages)
    {
        return -1;
    }

    ret = frame_info.getPage(page, (char*)buffer, FRAME_PAGE_BUF_SIZE);
    if (ret < 0)
    {
        *count = 0;
        return -1;
    }
    *count = (uint8_t)ret;

    if (page < frame_info.pages)
        *next = page + 1;
    else
        *next = 0xFF; // Set the value of next to 0xFF to indicate this is the
                      // last page

    return 0;
}

static int udbg_get_postcode(uint8_t, uint8_t page, uint8_t* next,
                             uint8_t* count, uint8_t* buffer)
{
    // up to 70 codes can be displayed on 10 pages
    static constexpr size_t maxPostcodes = 70;
    bool platform = isMultiHostPlatform();
    size_t hostPosition = 0;

    if (page == 1)
    {
        // Initialize and clear frame (example initialization)
        frame_postcode.init();
        snprintf(frame_postcode.title, 32, "POST CODE");
        frame_postcode.max_page = 10;

        if (platform)
            getSelectorPosition(hostPosition);

        // Synchronously get D-Bus connection
        auto bus = sdbusplus::bus::new_default();
        std::string serviceName =
            BOOT_POSTCODE_SERVICE + std::to_string(hostPosition);
        std::string objectPath =
            BOOT_POSTCODE_OBJECTPATH + std::to_string(hostPosition);

        // Build D-Bus method call
        auto method = bus.new_method_call(
            serviceName.c_str(),     // Target service name
            objectPath.c_str(),      // Object path
            BOOT_POSTCODE_INTERFACE, // Interface name
            "GetPostCodes");         // Method name

        method.append(uint16_t(1));  // Add method parameter, assuming it's pag
        try
        {
            auto reply = bus.call(method); // Send synchronous method call

            // Read postcode value
            std::vector<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>>
                postcodes;
            reply.read(postcodes);

            // retrieve the latest postcodes
            size_t numEntries = std::min(maxPostcodes, postcodes.size());
            auto range = std::ranges::subrange(postcodes.rbegin(),
                                               postcodes.rbegin() + numEntries);
            for (const auto& [code, extra] : range)
            {
                std::string result;
                result.reserve(2 * code.size());
                for (const auto& byte : code)
                {
                    result += std::format("{:02X}", byte);
                }

                frame_postcode.append(result);
                if (frame_postcode.lines >= maxPostcodes)
                {
                    break;
                }
            }
        }
        catch (const std::exception& e)
        {
            // Handle exceptions
            std::cerr << "Error retrieving postcodes: " << e.what()
                      << std::endl;
            return -1;
        }
    }

    if (page > frame_postcode.pages)
    {
        return -1;
    }

    int ret = frame_postcode.getPage(page, (char*)buffer, FRAME_PAGE_BUF_SIZE);
    if (ret < 0)
    {
        *count = 0;
        return -1;
    }
    *count = (uint8_t)ret;

    if (page < frame_postcode.pages)
        *next = page + 1;
    else
        *next = 0xFF; // Set next to 0xFF to indicate last page
    return 0;
}

int plat_udbg_get_frame_data(uint8_t frame, uint8_t page, uint8_t* next,
                             uint8_t* count, uint8_t* buffer)
{
    switch (frame)
    {
        case 1: // info_page
            return udbg_get_info_page(frame, page, next, count, buffer);
        case 2: // Extra Post Code
            return udbg_get_postcode(frame, page, next, count, buffer);
        default:
            return -1;
    }
}

static panel panel_main(size_t item)
{
    // Update item list when select item 0
    switch (item)
    {
        case 1:
            return panels[std::to_underlying(panel::BOOT_ORDER)].select(0);
        case 2:
            return panels[std::to_underlying(panel::POWER_POLICY)].select(0);
        default:
            return panel::MAIN;
    }
}

static panel panel_boot_order(size_t selectedItemIndex)
{
    static constexpr size_t sizeBootOrder = 6;
    static constexpr size_t bootValid = 0x80;

    std::vector<uint8_t> bootSeq;

    ctrl_panel& bootOrderPanel = panels[std::to_underlying(panel::BOOT_ORDER)];

    size_t pos = plat_get_fru_sel();

    if (pos == FRU_ALL)
    {
        bootOrderPanel.item_num = 0;
        return panel::BOOT_ORDER;
    }

    auto [bootObjPath, hostName] = ipmi::boot::objPath(pos);
    ipmi::boot::getBootOrder(bootObjPath, bootSeq, hostName);

    uint8_t& bootMode = bootSeq.front();

    // One item is selected to set a new boot sequence.
    // The selected item become the first boot order.
    if (selectedItemIndex > 0 && selectedItemIndex < sizeBootOrder)
    {
        // Move the selected item to second element (the first one is boot mode)
        std::rotate(bootSeq.begin() + 1, bootSeq.begin() + selectedItemIndex,
                    bootSeq.begin() + selectedItemIndex + 1);

        bootMode |= bootValid;
        try
        {
            ipmi::boot::setBootOrder(bootObjPath, bootSeq, hostName);
        }
        catch (const std::exception& e)
        {
            lg2::error("Fail to set boot order : {ERROR}", "ERROR", e);
        }

        // refresh items
        return bootOrderPanel.select(0);
    }

    // '*': boot flags valid, BIOS has not yet read
    bootOrderPanel.item_str[0] =
        std::string("Boot Order") + ((bootMode & bootValid) ? "*" : "");

    static const std::unordered_map<uint8_t, const char*>
        bootOrderMappingTable = {
            {0x00, " USB device"}, {0x01, " Network v4"}, {0x02, " SATA HDD"},
            {0x03, " SATA-CDROM"}, {0x04, " Other"},      {0x09, " Network v6"},
        };

    size_t validItem = 0;
    for (size_t i = 1; i < sizeBootOrder; i++)
    {
        auto find = bootOrderMappingTable.find(bootSeq[i]);
        if (find == bootOrderMappingTable.end())
        {
            lg2::error("Unknown boot order : {BOOTORDER}", "BOOTORDER",
                       bootSeq[i]);
            break;
        }

        bootOrderPanel.item_str[i] = find->second;

        validItem++;
    }

    bootOrderPanel.item_num = validItem;
    return panel::BOOT_ORDER;
}

static panel panel_power_policy(size_t)
{
/* To be cleaned */
#if 0
    uint8_t buff[32] = {0};
    uint8_t res_len;
    size_t pos = plat_get_fru_sel();
    uint8_t policy;
    uint8_t pwr_policy_item_map[3] = {POWER_CFG_ON, POWER_CFG_LPS,
                                      POWER_CFG_OFF};

    if (pos != FRU_ALL)
    {
        if (item > 0 && item <= sizeof(pwr_policy_item_map))
        {
            policy = pwr_policy_item_map[item - 1];
            pal_set_power_restore_policy(pos, &policy, nullptr);
        }
        pal_get_chassis_status(pos, nullptr, buff, &res_len);
        policy = (((uint8_t)buff[0]) >> 5) & 0x7;
        snprintf(panels[PANEL_POWER_POLICY].item_str[1], 32, "%cPower On",
                 policy == POWER_CFG_ON ? '*' : ' ');
        snprintf(panels[PANEL_POWER_POLICY].item_str[2], 32, "%cLast State",
                 policy == POWER_CFG_LPS ? '*' : ' ');
        snprintf(panels[PANEL_POWER_POLICY].item_str[3], 32, "%cPower Off",
                 policy == POWER_CFG_OFF ? '*' : ' ');
        panels[PANEL_POWER_POLICY].item_num = 3;
    }
    else
    {
        panels[PANEL_POWER_POLICY].item_num = 0;
    }
#endif
    return panel::POWER_POLICY;
}

ipmi_ret_t plat_udbg_control_panel(uint8_t cur_panel, uint8_t operation,
                                   uint8_t item, uint8_t* count,
                                   uint8_t* buffer)
{
    if (cur_panel > panelNum || cur_panel < std::to_underlying(panel::MAIN))
        return ipmi::ccParmOutOfRange;

    // No more item; End of item list
    if (item > panels[cur_panel].item_num)
        return ipmi::ccParmOutOfRange;

    switch (operation)
    {
        case 0: // Get Description
            break;
        case 1: // Select item
            cur_panel = std::to_underlying(panels[cur_panel].select(item));
            item = 0;
            break;
        case 2: // Back
            cur_panel = std::to_underlying(panels[cur_panel].parent);
            item = 0;
            break;
        default:
            return ipmi::ccParmOutOfRange;
    }

    buffer[0] = cur_panel;
    buffer[1] = item;
    buffer[2] = std::size(panels[cur_panel].item_str[item]);

    if (buffer[2] > 0 && (buffer[2] + 3u) < FRAME_PAGE_BUF_SIZE)
    {
        std::memcpy(&buffer[3], (panels[cur_panel].item_str[item]).c_str(),
                    buffer[2]);
    }
    *count = buffer[2] + 3;
    return ipmi::ccSuccess;
}

} // end of namespace ipmi
