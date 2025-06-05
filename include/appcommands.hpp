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

enum fb_app_cmds
{
    CMD_APP_GET_SELFTEST_RESULTS = 0x04,
    CMD_APP_MFR_TEST_ON = 0x05,
    CMD_APP_SET_ACPI = 0x06,
    CMD_APP_GET_ACPI = 0x07,
    CMD_APP_GET_DEV_GUID = 0x08,
    CMD_APP_SET_GLOBAL_ENABLES = 0x2E,
    CMD_APP_GET_GLOBAL_ENABLES = 0x2F,
    CMD_APP_CLEAR_MESSAGE_FLAGS = 0x30,
    CMD_APP_GET_SYS_GUID = 0x37,
    CMD_APP_SET_SYS_INFO_PARAMS = 0x58,
    CMD_APP_GET_SYS_INFO_PARAMS = 0x59,

};

#define SIZE_SYSFW_VER 17
#define SIZE_SYS_NAME 17
#define SIZE_OS_NAME 17
#define SIZE_OS_VER 17
#define SIZE_BMC_URL 17
#define SIZE_OS_HV_URL 17
#define SIZE_BIOS_CURRENT_BOOT_LIST 250
#define SIZE_BIOS_FIXED_BOOT_DEVICE 1
#define SIZE_BIOS_RSTR_DFLT_SETTING 1
#define SIZE_LAST_BOOT_TIME 4
#define SIZE_PCIE_PORT_CONFIG 2

#define JSON_APP_DATA_FILE "/var/lib/fb-ipmi-oem/appData.json"
#define SYSFW_VER_FILE "/var/bios/host{}_bios_version.txt"
#define KEY_SYSFW_VER "sysfw_ver_server"
#define KEY_BIOS_BOOT_LEN "bios_boot_list_len"

// System Info Parameters (IPMI/Table 22-16c)
enum SysInfoParams
{
    SYS_INFO_PARAM_SET_IN_PROG,
    SYS_INFO_PARAM_SYSFW_VER,
    SYS_INFO_PARAM_SYS_NAME,
    SYS_INFO_PARAM_PRI_OS_NAME,
    SYS_INFO_PARAM_PRESENT_OS_NAME,
    SYS_INFO_PARAM_PRESENT_OS_VER,
    SYS_INFO_PARAM_BMC_URL,
    SYS_INFO_PARAM_OS_HV_URL,
    SYS_INFO_PARAM_BIOS_CURRENT_BOOT_LIST = 0xC1,
    SYS_INFO_PARAM_BIOS_FIXED_BOOT_DEVICE = 0xC2,
    SYS_INFO_PARAM_BIOS_RSTR_DFLT_SETTING = 0xC3,
    SYS_INFO_PARAM_LAST_BOOT_TIME = 0xC4,
};

// Structure for System Info Params (IPMI/Section 22.14a)
struct SysInfoParam
{
    uint8_t set_in_prog;
    uint8_t sysfw_ver[SIZE_SYSFW_VER];
    uint8_t sys_name[SIZE_SYS_NAME];
    uint8_t pri_os_name[SIZE_OS_NAME];
    uint8_t present_os_name[SIZE_OS_NAME];
    uint8_t present_os_ver[SIZE_OS_VER];
    uint8_t bmc_url[SIZE_BMC_URL];
    uint8_t os_hv_url[SIZE_OS_HV_URL];
    uint8_t bios_current_boot_list[SIZE_BIOS_CURRENT_BOOT_LIST];
    uint8_t bios_fixed_boot_device[SIZE_BIOS_FIXED_BOOT_DEVICE];
    uint8_t bios_rstr_dflt_setting[SIZE_BIOS_RSTR_DFLT_SETTING];
    uint8_t last_boot_time[SIZE_LAST_BOOT_TIME];

} __attribute__((packed));
