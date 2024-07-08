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

#include <ipmid/api.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>

#include <appcommands.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/property.hpp>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace ipmi
{

#define JSON_POST_DATA_FILE "/usr/share/lcd-debug/post_desc.json"
#define JSON_GPIO_DATA_FILE "/usr/share/lcd-debug/gpio_desc.json"
#define JSON_SENSOR_NAMES_FILE "/usr/share/lcd-debug/cri_sensors.json"

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

#define DEBUG_GPIO_KEY "GpioDesc"
#define GPIO_ARRAY_SIZE 4
#define GPIO_PIN_INDEX 0
#define GPIO_LEVEL_INDEX 1
#define GPIO_DEF_INDEX 2
#define GPIO_DESC_INDEX 3
#define BMC_POSITION 0
#define MAX_HOST_POS 4

/* Used for systems which do not specifically have a
 * phase, and we want to ignore the phase provided by the
 * debug card */
#define PHASE_ANY 0xff

static constexpr bool DEBUG = false;
static const uint8_t meAddress = 1;
static constexpr uint8_t lun = 0;

using IpmbMethodType =
    std::tuple<int, uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>;

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
    char* buf;
    uint16_t idx_head, idx_tail;
    uint8_t line_per_page;
    uint8_t line_width;
    uint16_t lines, pages;
    uint8_t esc_sts;
    uint8_t overwrite;
    time_t mtime;
    frame() : buf(NULL), pages(0), mtime(0) {}
    int init(size_t size);
    int append(const char* string, int indent);
    int insert(const char* string, int indent);
    int getPage(int page, char* page_buf, size_t page_buf_size);
    int isFull();
    int isEscSeq(char chr);
    int parse(char* buf, size_t buf_size, const char* input, int indent);
};

struct frame frame_info;
struct frame frame_sel;
struct frame frame_snr;
struct frame frame_postcode;

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
    std::string item_str[8];
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

} // end of namespace ipmi
