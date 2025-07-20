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

static constexpr bool DEBUG = false;

static constexpr auto JSON_POST_DATA_FILE =
    "/usr/share/lcd-debug/post_desc.json";
static constexpr auto JSON_GPIO_DATA_FILE =
    "/usr/share/lcd-debug/gpio_desc.json";
static constexpr auto JSON_SENSOR_NAMES_FILE =
    "/usr/share/lcd-debug/cri_sensors.json";

static constexpr auto ETH_INTF_NAME = "eth0";

#define ESCAPE "\x1B"
#define ESC_BAT ESCAPE "B"
#define ESC_MCU_BL_VER ESCAPE "U"
#define ESC_MCU_RUN_VER ESCAPE "R"
#define ESC_ALT ESCAPE "[5;7m"
#define ESC_RST ESCAPE "[m"

static constexpr char LINE_DELIMITER = '\x1F';

static constexpr size_t FRAME_BUFF_SIZE = 4096;
static constexpr size_t FRAME_PAGE_BUF_SIZE = 256;

#define FRU_ALL 0
#define BOOT_POSTCODE_SERVICE "xyz.openbmc_project.State.Boot.PostCode"
#define BOOT_POSTCODE_OBJECTPATH "/xyz/openbmc_project/State/Boot/PostCode"
#define BOOT_POSTCODE_INTERFACE "xyz.openbmc_project.State.Boot.PostCode"

static constexpr auto DEBUG_GPIO_KEY = "GpioDesc";
static constexpr auto GPIO_ARRAY_SIZE = 4;
static constexpr auto GPIO_PIN_INDEX = 0;
static constexpr auto GPIO_LEVEL_INDEX = 1;
static constexpr auto GPIO_DEF_INDEX = 2;
static constexpr auto GPIO_DESC_INDEX = 3;

static constexpr size_t BMC_POSITION = 0;

static constexpr uint8_t meAddress = 1;
static constexpr uint8_t lun = 0;

using IpmbMethodType =
    std::tuple<int, uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>;

struct frame
{
    char title[32];
    size_t max_size;
    size_t max_page;
    char* buf;
    size_t idx_head, idx_tail;
    size_t line_per_page;
    size_t line_width;
    size_t lines, pages;
    uint8_t esc_sts;
    bool overwrite;
    time_t mtime;

    frame() : buf(nullptr), pages(0), mtime(0) {}

    void init(size_t size = FRAME_BUFF_SIZE);
    void append(const std::string& str, size_t indent = 0);
    int getPage(size_t page, char* page_buf, size_t page_buf_size);
    bool isFull() const;
    bool isEscSeq(char chr);

  private:
    auto parse(const std::string& input, size_t indent) -> std::string;
};

frame frame_info;
frame frame_sel;
frame frame_snr;
frame frame_postcode;

enum class panel : uint8_t
{
    NONE = 0,
    MAIN = 1,
    BOOT_ORDER = 2,
    POWER_POLICY = 3,
};

struct ctrl_panel
{
    panel parent;
    size_t item_num;
    std::array<std::string, 8> item_str;
    panel (*select)(size_t item);
};

static panel panel_main(size_t item);
static panel panel_boot_order(size_t item);
static panel panel_power_policy(size_t item);

static ctrl_panel panels[] = {
    {/* dummy entry for making other to 1-based */},
    {
        .parent = panel::MAIN,
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
        .parent = panel::MAIN,
        .item_num = 0,
        .item_str =
            {
                "Boot Order",
            },
        .select = panel_boot_order,
    },
    {
        .parent = panel::MAIN,
        .item_num = 0,
        .item_str =
            {
                "Power Policy",
            },
        .select = panel_power_policy,
    },
};

} // end of namespace ipmi
