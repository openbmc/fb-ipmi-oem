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

#include <host-ipmid/ipmid-api.h>
#include <nlohmann/json.hpp>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>

#include <fstream>
#include <iostream>
#include <phosphor-logging/log.hpp>
#include <appcommands.hpp>

namespace ipmi
{

#define JSON_POST_DATA_FILE "/usr/share/ipmi-providers/post_desc.json"
#define ETH_INTF_NAME "eth0"

#define ESCAPE "\x1B"
#define ESC_BAT ESCAPE "B"
#define ESC_MCU_BL_VER ESCAPE "U"
#define ESC_MCU_RUN_VER ESCAPE "R"
#define ESC_ALT ESCAPE "[5;7m"
#define ESC_RST ESCAPE "[m"

#define LINE_DELIMITER '\x1F'

#define FRAME_BUFF_SIZE 4096
#define FRAME_PAGE_BUF_SIZE 256
#define FRU_ALL 0
#define MAX_VALUE_LEN 64

/* Used for systems which do not specifically have a
 * phase, and we want to ignore the phase provided by the
 * debug card */
#define PHASE_ANY 0xff

ipmi_ret_t getNetworkData(uint8_t lan_param, char *data);
int8_t getFruData(std::string &serial, std::string &name);

typedef struct _gpio_desc
{
    uint8_t pin;
    uint8_t level;
    uint8_t def;
    char desc[32];
} gpio_desc_t;

typedef struct _sensor_desc
{
    char name[16];
    uint8_t sensor_num;
    char unit[5];
    uint8_t fru;
    uint8_t disp_prec;
} sensor_desc_t;

struct frame
{
    char title[32];
    size_t max_size;
    size_t max_page;
    char *buf;
    uint16_t idx_head, idx_tail;
    uint8_t line_per_page;
    uint8_t line_width;
    uint16_t lines, pages;
    uint8_t esc_sts;
    uint8_t overwrite;
    time_t mtime;
    frame() : buf(NULL), pages(0), mtime(0)
    {
    }
    int init(size_t size);
    int append(const char *string, int indent);
    int insert(const char *string, int indent);
    int getPage(int page, char *page_buf, size_t page_buf_size);
    int isFull();
    int isEscSeq(char chr);
    int parse(char *buf, size_t buf_size, const char *input, int indent);
};

struct frame frame_info;
struct frame frame_sel;
struct frame frame_snr;

enum ENUM_PANEL
{
    PANEL_MAIN = 1,
    PANEL_BOOT_ORDER = 2,
    PANEL_POWER_POLICY = 3,
};

struct ctrl_panel
{
    uint8_t parent;
    uint8_t item_num;
    char item_str[8][32];
    uint8_t (*select)(uint8_t item);
};

static uint8_t panel_main(uint8_t item);
static uint8_t panel_boot_order(uint8_t item);
static uint8_t panel_power_policy(uint8_t item);

static struct ctrl_panel panels[] = {
    {/* dummy entry for making other to 1-based */},
    {
        .parent = PANEL_MAIN,
        .item_num = 2,
        .item_str =
            {
                "User Setting",
                ">Boot Order",
                ">Power Policy",
            },
        .select = panel_main,
    },
    {
        .parent = PANEL_MAIN,
        .item_num = 0,
        .item_str =
            {
                "Boot Order",
            },
        .select = panel_boot_order,
    },
    {
        .parent = PANEL_MAIN,
        .item_num = 0,
        .item_str =
            {
                "Power Policy",
            },
        .select = panel_power_policy,
    },
};

static int panelNum = (sizeof(panels) / sizeof(struct ctrl_panel)) - 1;

/* Returns the FRU the hand-switch is switched to. If it is switched to BMC
 * it returns FRU_ALL. Note, if in err, it returns FRU_ALL */
static uint8_t plat_get_fru_sel()
{
    // For Tiogapass it just return 1, can modify to support more platform
    return 1;
}

// return 0 on seccuess
int frame::init(size_t size)
{
    // Reset status
    idx_head = idx_tail = 0;
    lines = 0;
    esc_sts = 0;
    pages = 1;

    if (buf != NULL && max_size == size)
    {
        // reinit
        return 0;
    }

    if (buf != NULL && max_size != size)
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
    overwrite = 0;

    if (buf)
        return 0;
    else
        return -1;
}

// return 0 on seccuess
int frame::append(const char *string, int indent)
{
    const size_t buf_size = 64;
    char lbuf[buf_size];
    char *ptr;
    int ret;

    ret = parse(lbuf, buf_size, string, indent);

    if (ret < 0)
        return ret;

    int len = strlen(string);
    for (ptr = lbuf; *ptr != '\0'; ptr++)
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
                return -1;
        }

        buf[idx_tail] = *ptr;
        if (*ptr == LINE_DELIMITER)
            lines++;

        idx_tail = (idx_tail + 1) % max_size;
    }

    pages = (lines / line_per_page) + ((lines % line_per_page) ? 1 : 0);

    if (pages > max_page)
        pages = max_page;

    return 0;
}

// return 0 on seccuess
int frame::insert(const char *string, int indent)
{
    const size_t buf_size = 128;
    char lbuf[buf_size];
    char *ptr;
    int ret;
    int i;

    ret = parse(lbuf, buf_size, string, indent);

    if (ret < 0)
        return ret;

    for (i = strlen(lbuf) - 1; i >= 0; i--)
    {
        ptr = &lbuf[i];
        if (isFull())
        {
            if (overwrite)
            {
                idx_tail = (idx_tail + max_size - 1) % max_size;
                if (buf[idx_tail] == LINE_DELIMITER)
                    lines--;
            }
            else
                return -1;
        }

        idx_head = (idx_head + max_size - 1) % max_size;

        buf[idx_head] = *ptr;
        if (*ptr == LINE_DELIMITER)
            lines++;
    }

    pages = (lines / line_per_page) + ((lines % line_per_page) ? 1 : 0);

    if (pages > max_page)
        pages = max_page;

    return 0;
}

// return page size
int frame::getPage(int page, char *page_buf, size_t page_buf_size)
{
    int ret;
    uint16_t line = 0;
    uint16_t idx, len;

    if (buf == NULL)
        return -1;

    // 1-based page
    if (page > pages || page < 1)
        return -1;

    if (page_buf == NULL || page_buf_size < 0)
        return -1;

    ret = snprintf(page_buf, 17, "%-10s %02d/%02d", title, page, pages);
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

// return 1 for frame buffer full
int frame::isFull()
{
    if (buf == NULL)
        return -1;

    if ((idx_tail + 1) % max_size == idx_head)
        return 1;
    else
        return 0;
}

// return 1 for Escape Sequence
int frame::isEscSeq(char chr)
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
        return 1;
    else
        return 0;
}

// return 0 on success
int frame::parse(char *lbuf, size_t buf_size, const char *input, int indent)
{
    uint8_t pos, esc;
    int i;
    const char *in, *end;

    if (buf == NULL || input == NULL)
        return -1;

    if (indent >= line_width || indent < 0)
        return -1;

    in = input;
    end = in + strlen(input);
    pos = 0; // line position
    esc = 0; // escape state
    i = 0;   // buf index
    while (in != end)
    {
        if (i >= buf_size)
            break;

        if (pos < indent)
        {
            // fill indent
            lbuf[i++] = ' ';
            pos++;
            continue;
        }

        esc = isEscSeq(*in);

        if (!esc && pos == line_width)
        {
            lbuf[i++] = LINE_DELIMITER;
            pos = 0;
            continue;
        }

        if (!esc)
            pos++;

        // fill input data
        lbuf[i++] = *(in++);
    }

    // padding
    while (pos <= line_width)
    {
        if (i >= buf_size)
            break;
        if (pos < line_width)
            lbuf[i++] = ' ';
        else
            lbuf[i++] = LINE_DELIMITER;
        pos++;
    }

    // full
    if (i >= buf_size)
        return -1;

    lbuf[i++] = '\0';

    return 0;
}

static int chk_cri_sel_update(uint8_t *cri_sel_up)
{
    FILE *fp;
    struct stat file_stat;
    uint8_t pos = plat_get_fru_sel();
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
        if (frame_sel.buf == NULL || frame_sel.lines != 0 || pre_pos != pos)
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

int plat_udbg_get_frame_info(uint8_t *num)
{
    *num = 3;
    return 0;
}

int plat_udbg_get_updated_frames(uint8_t *count, uint8_t *buffer)
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

int plat_udbg_get_post_desc(uint8_t index, uint8_t *next, uint8_t phase,
                            uint8_t *end, uint8_t *length, uint8_t *buffer)
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

/* Need to implement this */
int plat_udbg_get_gpio_desc(uint8_t index, uint8_t *next, uint8_t *level,
                            uint8_t *def, uint8_t *count, uint8_t *buffer)
{
    return 0;
}

static int udbg_get_cri_sel(uint8_t frame, uint8_t page, uint8_t *next,
                            uint8_t *count, uint8_t *buffer)
{
    int len;
    int ret;
    char line_buff[FRAME_PAGE_BUF_SIZE], *fptr;
    const char *ptr;
    FILE *fp;
    struct stat file_stat;
    uint8_t pos = plat_get_fru_sel();
    static uint8_t pre_pos = FRU_ALL;
    bool pos_changed = pre_pos != pos;

    pre_pos = pos;

    /* Revisit this */
    fp = fopen("/mnt/data/cri_sel", "r");
    if (fp)
    {
        if ((stat("/mnt/data/cri_sel", &file_stat) == 0) &&
            (file_stat.st_mtime != frame_sel.mtime || pos_changed))
        {
            // initialize and clear frame
            frame_sel.init(FRAME_BUFF_SIZE);
            frame_sel.overwrite = 1;
            frame_sel.max_page = 20;
            frame_sel.mtime = file_stat.st_mtime;
            snprintf(frame_sel.title, 32, "Cri SEL");

            while (fgets(line_buff, FRAME_PAGE_BUF_SIZE, fp))
            {
                // Remove newline
                line_buff[strlen(line_buff) - 1] = '\0';
                ptr = line_buff;
                // Find message
                ptr = strstr(ptr, "local0.err");
                if (ptr == NULL)
                {
                    continue;
                }

                if ((ptr = strrchr(ptr, ':')) == NULL)
                {
                    continue;
                }
                len = strlen(ptr);
                if (len > 2)
                {
                    // to skip log string ": "
                    ptr += 2;
                }
                // Write new message
                frame_sel.insert(ptr, 0);
            }
        }
        fclose(fp);
    }
    else
    {
        // Title only
        frame_sel.init(FRAME_BUFF_SIZE);
        snprintf(frame_sel.title, 32, "Cri SEL");
        frame_sel.mtime = 0;
    }

    if (page > frame_sel.pages)
    {
        return -1;
    }

    ret = frame_sel.getPage(page, (char *)buffer, FRAME_PAGE_BUF_SIZE);
    if (ret < 0)
    {
        *count = 0;
        return -1;
    }
    *count = (uint8_t)ret;

    if (page < frame_sel.pages)
        *next = page + 1;
    else
        *next = 0xFF; // Set the value of next to 0xFF to indicate this is the
                      // last page

    return 0;
}

static int udbg_get_cri_sensor(uint8_t frame, uint8_t page, uint8_t *next,
                               uint8_t *count, uint8_t *buffer)
{
    char str[32], temp_val[16], temp_thresh[8], print_format[32];
    int i, ret;
    float fvalue;
    sensor_desc_t *cri_sensor = NULL;
    size_t sensor_count = 0;
    uint8_t pos = plat_get_fru_sel();
    uint8_t fru;

    if (page == 1)
    {
        // Only update frame data while getting page 1

        // initialize and clear frame
        frame_snr.init(FRAME_BUFF_SIZE);
        snprintf(frame_snr.title, 32, "CriSensor");
        frame_snr.append(str, 0);
    } // End of update frame

    if (page > frame_snr.pages)
    {
        return -1;
    }

    ret = frame_snr.getPage(page, (char *)buffer, FRAME_PAGE_BUF_SIZE);
    if (ret < 0)
    {
        *count = 0;
        return -1;
    }
    *count = (uint8_t)ret;

    if (page < frame_snr.pages)
        *next = page + 1;
    else
        *next = 0xFF; // Set the value of next to 0xFF to indicate this is the
                      // last page

    return 0;
}

static int getBiosVer(std::string &ver)
{
    nlohmann::json appObj;

    std::ifstream file(JSON_APP_DATA_FILE);
    if (file)
    {
        file >> appObj;
        file.close();
        if (appObj.find(KEY_SYSFW_VER) != appObj.end())
        {
            ver = appObj[KEY_SYSFW_VER].get<std::string>();
            std::cout << "Vijay: Bios Ver: " << ver << "\n";
            return 0;
        }
    }

    return -1;
}

static int udbg_get_info_page(uint8_t frame, uint8_t page, uint8_t *next,
                              uint8_t *count, uint8_t *buffer)
{
    char line_buff[1000], *pres_dev = line_buff;
    uint8_t pos = plat_get_fru_sel();
    const char *delim = "\n";
    int ret;
    std::string serialName = "BOARD_SERIAL_NUMBER";
    std::string partName = "BOARD_PART_NUMBER";
    std::string verDel = "VERSION=";
    std::string verPath = "/etc/os-release";

    if (page == 1)
    {
        // Only update frame data while getting page 1

        // initialize and clear frame
        frame_info.init(FRAME_BUFF_SIZE);
        snprintf(frame_info.title, 32, "SYS_Info");

        // FRU TBD:
        std::string data;
        frame_info.append("SN:", 0);
        if (getFruData(data, serialName) != 0)
        {
            data = "Not Found";
        }
        frame_info.append(data.c_str(), 1);
        frame_info.append("PN:", 0);
        if (getFruData(data, partName) != 0)
        {
            data = "Not Found";
        }
        frame_info.append(data.c_str(), 1);

        // LAN
        getNetworkData(3, line_buff);
        frame_info.append("BMC_IP:", 0);
        frame_info.append(line_buff, 1);
        getNetworkData(59, line_buff);
        frame_info.append("BMC_IPv6:", 0);
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
                    frame_info.append("BMC_FW_ver:", 0);
                    frame_info.append(bmcVer.c_str(), 1);
                    break;
                }
            }
        }

        // BIOS ver
        std::string biosVer;
        if (getBiosVer(biosVer) == 0)
        {
            frame_info.append("BIOS_FW_ver:", 0);
            frame_info.append(biosVer.c_str(), 1);
        }

        /* TBD: ME status and Board ID needs implementation */
        // ME status

        // Board ID

        // Battery - Use Escape sequence
        frame_info.append("Battery:", 0);
        frame_info.append(ESC_BAT "     ", 1);
        // frame_info.append(&frame_info, esc_bat, 1);

        // MCU Version - Use Escape sequence
        frame_info.append("MCUbl_ver:", 0);
        frame_info.append(ESC_MCU_BL_VER, 1);
        frame_info.append("MCU_ver:", 0);
        frame_info.append(ESC_MCU_RUN_VER, 1);

        // TBD:
        // Sys config present device

    } // End of update frame

    if (page > frame_info.pages)
    {
        return -1;
    }

    ret = frame_info.getPage(page, (char *)buffer, FRAME_PAGE_BUF_SIZE);
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

int plat_udbg_get_frame_data(uint8_t frame, uint8_t page, uint8_t *next,
                             uint8_t *count, uint8_t *buffer)
{
    switch (frame)
    {
        case 1: // info_page
            return udbg_get_info_page(frame, page, next, count, buffer);
        case 2: // critical SEL
            return udbg_get_cri_sel(frame, page, next, count, buffer);
        case 3: // critical Sensor
            return udbg_get_cri_sensor(frame, page, next, count, buffer);
        default:
            return -1;
    }
}

static uint8_t panel_main(uint8_t item)
{
    // Update item list when select item 0
    switch (item)
    {
        case 1:
            return panels[PANEL_BOOT_ORDER].select(0);
        case 2:
            return panels[PANEL_POWER_POLICY].select(0);
        default:
            return PANEL_MAIN;
    }
}

static uint8_t panel_boot_order(uint8_t item)
{
    int i;
    unsigned char buff[MAX_VALUE_LEN], pickup, len;
    uint8_t pos = plat_get_fru_sel();

    /* To be implemented */
    /*
  if (pos != FRU_ALL && pal_get_boot_order(pos, buff, buff, &len) == 0)
  {
  if (item > 0 && item < SIZE_BOOT_ORDER)
  {
  pickup = buff[item];
  while (item > 1)
  {
    buff[item] = buff[item -1];
    item--;
  }
  buff[item] = pickup;
  buff[0] |= 0x80;
  pal_set_boot_order(pos, buff, buff, &len);

  // refresh items
  return panels[PANEL_BOOT_ORDER].select(0);
  }

  // '*': boot flags valid, BIOS has not yet read
  snprintf(panels[PANEL_BOOT_ORDER].item_str[0], 32,
  "Boot Order%c", (buff[0] & 0x80)?'*':'\0');

  for (i = 1; i < SIZE_BOOT_ORDER; i++)
  {
  switch (buff[i])
  {
    case 0x0:
      snprintf(panels[PANEL_BOOT_ORDER].item_str[i], 32,
        " USB device");
      break;
    case 0x1:
      snprintf(panels[PANEL_BOOT_ORDER].item_str[i], 32,
        " Network v4");
      break;
    case (0x1 | 0x8):
      snprintf(panels[PANEL_BOOT_ORDER].item_str[i], 32,
        " Network v6");
      break;
    case 0x2:
      snprintf(panels[PANEL_BOOT_ORDER].item_str[i], 32,
        " SATA HDD");
      break;
    case 0x3:
      snprintf(panels[PANEL_BOOT_ORDER].item_str[i], 32,
        " SATA-CDROM");
      break;
    case 0x4:
      snprintf(panels[PANEL_BOOT_ORDER].item_str[i], 32,
        " Other");
      break;
    default:
      panels[PANEL_BOOT_ORDER].item_str[i][0] = '\0';
      break;
  }
  }

  // remove empty items
  for (i--; (strlen(panels[PANEL_BOOT_ORDER].item_str[i]) == 0) && (i > 0); i--)
  ;

  panels[PANEL_BOOT_ORDER].item_num = i;
  } else
  {
  panels[PANEL_BOOT_ORDER].item_num = 0;
  }
            */
    return PANEL_BOOT_ORDER;
}

static uint8_t panel_power_policy(uint8_t item)
{
    uint8_t buff[32] = {0};
    uint8_t res_len;
    uint8_t pos = plat_get_fru_sel();
    uint8_t policy;
    //  uint8_t pwr_policy_item_map[3] = {POWER_CFG_ON, POWER_CFG_LPS,
    //  POWER_CFG_OFF};

    /* To be cleaned */
    /*
  if (pos != FRU_ALL) {
  if (item > 0 && item <= sizeof(pwr_policy_item_map)) {
  policy = pwr_policy_item_map[item - 1];
  pal_set_power_restore_policy(pos, &policy, NULL);
  }
  pal_get_chassis_status(pos, NULL, buff, &res_len);
  policy = (((uint8_t)buff[0]) >> 5) & 0x7;
  snprintf(panels[PANEL_POWER_POLICY].item_str[1], 32,
    "%cPower On", policy == POWER_CFG_ON ? '*' : ' ');
  snprintf(panels[PANEL_POWER_POLICY].item_str[2], 32,
    "%cLast State", policy == POWER_CFG_LPS ? '*' : ' ');
  snprintf(panels[PANEL_POWER_POLICY].item_str[3], 32,
    "%cPower Off", policy == POWER_CFG_OFF ? '*' : ' ');
  panels[PANEL_POWER_POLICY].item_num = 3;
  } else {
  panels[PANEL_POWER_POLICY].item_num = 0;
  }
    */
    return PANEL_POWER_POLICY;
}

int plat_udbg_control_panel(uint8_t panel, uint8_t operation, uint8_t item,
                            uint8_t *count, uint8_t *buffer)
{
    if (panel > panelNum || panel < PANEL_MAIN)
        return IPMI_CC_PARM_OUT_OF_RANGE;

    // No more item; End of item list
    if (item > panels[panel].item_num)
        return IPMI_CC_PARM_OUT_OF_RANGE;

    switch (operation)
    {
        case 0: // Get Description
            break;
        case 1: // Select item
            panel = panels[panel].select(item);
            item = 0;
            break;
        case 2: // Back
            panel = panels[panel].parent;
            item = 0;
            break;
        default:
            return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    buffer[0] = panel;
    buffer[1] = item;
    buffer[2] = strlen(panels[panel].item_str[item]);
    if (buffer[2] > 0 && (buffer[2] + 3) < FRAME_PAGE_BUF_SIZE)
    {
        memcpy(&buffer[3], panels[panel].item_str[item], buffer[2]);
    }
    *count = buffer[2] + 3;
    return IPMI_CC_OK;
}

} // end of namespace ipmi
