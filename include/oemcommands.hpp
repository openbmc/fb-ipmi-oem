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

enum ipmi_fb_net_fns
{
    NETFN_OEM_USB_DBG_REQ = 0x3C,
    NETFN_OEM_USB_DBG_RES = 0x3D,
};

// OEM Command Codes for USB basded Debug Card
enum oem_usb_dbg_cmds
{
    CMD_OEM_USB_DBG_GET_FRAME_INFO = 0x1,
    CMD_OEM_USB_DBG_GET_UPDATED_FRAMES = 0x2,
    CMD_OEM_USB_DBG_GET_POST_DESC = 0x3,
    CMD_OEM_USB_DBG_GET_GPIO_DESC = 0x4,
    CMD_OEM_USB_DBG_GET_FRAME_DATA = 0x5,
    CMD_OEM_USB_DBG_CTRL_PANEL = 0x6,
};

// OEM Command Codes for FB 1S/2S servers
enum fb_oem_cmds
{
    CMD_OEM_ADD_RAS_SEL = 0x10,
    CMD_OEM_ADD_IMC_LOG = 0x11,
    CMD_OEM_SET_MAC_ADDR = 0x18,
    CMD_OEM_GET_MAC_ADDR = 0x19,
    CMD_OEM_SET_PROC_INFO = 0x1A,
    CMD_OEM_GET_PROC_INFO = 0x1B,
    CMD_OEM_SET_DIMM_INFO = 0x1C,
    CMD_OEM_GET_DIMM_INFO = 0x1D,
    CMD_OEM_BYPASS_CMD = 0x34,
    CMD_OEM_GET_BOARD_ID = 0x37,
    CMD_OEM_GET_80PORT_RECORD = 0x49,
    CMD_OEM_SET_BOOT_ORDER = 0x52,
    CMD_OEM_GET_BOOT_ORDER = 0x53,
    CMD_OEM_SET_MACHINE_CONFIG_INFO = 0x6A,
    CMD_OEM_LEGACY_SET_PPR = 0x6E,
    CMD_OEM_LEGACY_GET_PPR = 0x6F,
    CMD_OEM_SET_POST_START = 0x73,
    CMD_OEM_SET_POST_END = 0x74,
    CMD_OEM_SET_PPIN_INFO = 0x77,
    CMD_OEM_SET_ADR_TRIGGER = 0x7A,
    CMD_OEM_GET_PLAT_INFO = 0x7E,
    CMD_OEM_SET_SYSTEM_GUID = 0xEF,
    CMD_OEM_GET_FW_INFO = 0xF2,
    CMD_OEM_SLED_AC_CYCLE = 0xF3,
    CMD_OEM_GET_PCIE_CONFIG = 0xF4,
    CMD_OEM_SET_IMC_VERSION = 0xF5,
    CMD_OEM_SET_FW_UPDATE_STATE = 0xF6,
    CMD_OEM_GET_BIOS_FLASH_INFO = 0x55,
    CMD_OEM_GET_PCIE_PORT_CONFIG = 0x80,
    CMD_OEM_SET_PCIE_PORT_CONFIG = 0x81,
    CMD_OEM_GET_TPM_PRESENCE = 0x82,
    CMD_OEM_SET_TPM_PRESENCE = 0x83,
    CMD_OEM_SET_BIOS_FLASH_INFO = 0x87,
    CMD_OEM_SET_PPR = 0x90,
    CMD_OEM_GET_PPR = 0x91,
    CMD_OEM_SET_IPMB_OFFONLINE = 0xE6,
    CMD_OEM_RISER_SENSOR_MON_CRL = 0xE7,
    CMD_OEM_BBV_POWER_CYCLE = 0xE9,
    CMD_OEM_ADD_CPER_LOG = 0x70,

};

// OEM Command Codes for QC
enum fb_oem_qc_cmds
{
    CMD_OEM_Q_SET_PROC_INFO = 0x10,
    CMD_OEM_Q_GET_PROC_INFO = 0x11,
    CMD_OEM_Q_SET_DIMM_INFO = 0x12,
    CMD_OEM_Q_GET_DIMM_INFO = 0x13,
    CMD_OEM_Q_SET_DRIVE_INFO = 0x14,
    CMD_OEM_Q_GET_DRIVE_INFO = 0x15,
};

#define DIMM_TYPE1 0xce
#define DIMM_TYPE2 0xad
#define DIMM_TYPE3 0x2c
#define MAX_BUF 150
#define SIZE_CPU_PPIN 8
#define SIZE_BOOT_ORDER 6
#define BOOT_MODE_UEFI 0x01
#define BOOT_MODE_CMOS_CLR 0x02
#define BOOT_MODE_FORCE_BOOT 0x04
#define BOOT_MODE_BOOT_FLAG 0x80
#define BIT_0 0x01
#define BIT_1 0x02
#define BIT_2 0x04
#define BIT_3 0x08
#define BMC_POSITION 0

namespace ipmi
{
constexpr uint8_t cmdSetQDimmInfo = 0x12;
constexpr uint8_t cmdGetQDimmInfo = 0x13;
} // namespace ipmi

#define JSON_OEM_DATA_FILE "/etc/oemData.json"
#define KEY_PPIN_INFO "mb_cpu_ppin"
#define KEY_MC_CONFIG "mb_machine_config"
#define KEY_MC_CHAS_TYPE "chassis_type"
#define KEY_MC_MB_TYPE "mb_type"
#define KEY_MC_PROC_CNT "processor_count"
#define KEY_MC_MEM_CNT "memory_count"
#define KEY_MC_HDD35_CNT "hdd35_count"
#define KEY_MC_HDD25_CNT "hdd25_count"
#define KEY_MC_RSR_TYPE "riser_type"
#define KEY_MC_PCIE_LOC "pcie_card_loc"
#define KEY_MC_SLOT1_TYPE "slot1_pcie_type"
#define KEY_MC_SLOT2_TYPE "slot2_pcie_type"
#define KEY_MC_SLOT3_TYPE "slot3_pcie_type"
#define KEY_MC_SLOT4_TYPE "slot4_pcie_type"
#define KEY_MC_AEP_CNT "aep_mem_count"

#define KEY_TS_SLED "timestamp_sled"
#define KEY_BOOT_ORDER "server_boot_order"
#define KEY_BOOT_MODE "boot_mode"
#define KEY_BOOT_SEQ "boot_sequence"
#define KEY_SYS_CONFIG "sys_config"
#define KEY_DIMM_INDEX "dimm_index"
#define KEY_DIMM_TYPE "dimm_type"
#define KEY_DIMM_SPEED "dimm_speed"
#define KEY_DIMM_SIZE "dimm_size"
#define KEY_PPR "ppr"
#define KEY_PPR_ACTION "ppr_row_action"
#define KEY_PPR_ROW_COUNT "ppr_row_count"
#define KEY_PPR_INDEX "ppr_index"
#define KEY_PPR_ROW_ADDR "ppr_row_addr"
#define KEY_PPR_HST_DATA "ppr_history_data"
#define CC_PARAM_NOT_SUPP_IN_CURR_STATE 0xD5
#define PPR_ROW_ADDR_LEN 8
#define PPR_HST_DATA_LEN 17

#define BOOT_SEQ_ARRAY_SIZE 10

const char* bootSeq[] = {"USB_DEV", "NET_IPV4", "SATA_HDD", "SATA_CD",
                         "OTHER",   "",         "",         "",
                         "",        "NET_IPV6"};
std::map<std::string, int> bootMap = {{"USB_DEV", 0},  {"NET_IPV4", 1},
                                      {"NET_IPV6", 9}, {"SATA_HDD", 2},
                                      {"SATA_CD", 3},  {"OTHER", 4}};

const char* chassisType[] = {"ORV1", "ORV2"};
const char* mbType[] = {"SS", "DS", "TYPE3"};
const char* riserType[] = {"NO_CARD", "2_SLOT", "3_SLOT"};
const char* pcieType[] = {"ABSENT", "AVA1",     "AVA2", "AVA3",
                          "AVA4",   "Re-timer", "HBA",  "OTHER"};

enum fb_ppr_sel
{
    PPR_ACTION = 1,
    PPR_ROW_COUNT,
    PPR_ROW_ADDR,
    PPR_HISTORY_DATA,
};

typedef struct
{
    uint8_t chassis_type; // 00 - ORv1, 01 - ORv2 (FBTP)
    uint8_t mb_type;      // 00 - SS, 01 - DS, 02 - Type3
    uint8_t proc_cnt;
    uint8_t mem_cnt;
    uint8_t hdd35_cnt;       // 0/1 in FBTP, ff - unknown
    uint8_t hdd25_cnt;       // 0 for FBTP
    uint8_t riser_type;      // 00 - not installed, 01 - 2 slot, 02 - 3 slot
    uint8_t pcie_card_loc;   // Bit0 - Slot1 Present/Absent, Bit1 - Slot 2
                             // Present/Absent etc.
    uint8_t slot1_pcie_type; // Always NIC for FBTP
    uint8_t slot2_pcie_type; // 2-4: 00 - Absent, 01 - AVA 2 x m.2, 02 - AVA
                             // 3x m.2,
    uint8_t slot3_pcie_type; // 03 - AVA 4 x m.2, 04 - Re-timer, 05 - HBA
    uint8_t slot4_pcie_type; // 06 - Other flash cards (Intel, HGST),
                             // 80 - Unknown
    uint8_t aep_mem_cnt;
} machineConfigInfo_t;

/* FB OEM QC commands data structures */

#define NETFUN_FB_OEM_QC 0x36

#define KEY_Q_PROC_INFO "q_proc_info"
#define KEY_PROC_INDEX "proc_index"
#define KEY_Q_DIMM_INFO "q_dimm_info"
#define KEY_DIMM_INDEX "dimm_index"
#define KEY_Q_DRIVE_INFO "q_drive_info"
#define KEY_HDD_CTRL_TYPE "hdd_ctrl_type"
#define KEY_HDD_INDEX "hdd_index"

typedef struct
{
    uint8_t mfrId[3];
    uint8_t procIndex;
    uint8_t paramSel;
    uint8_t data[];
} qProcInfo_t;

typedef struct
{
    uint8_t mfrId[3];
    uint8_t dimmIndex;
    uint8_t paramSel;
    uint8_t data[];
} qDimmInfo_t;

typedef struct
{
    uint8_t mfrId[3];
    uint8_t hddCtrlType;
    uint8_t hddIndex;
    uint8_t paramSel;
    uint8_t data[];
} qDriveInfo_t;

const char* cpuInfoKey[] = {"",     "product_name", "basic_info",
                            "type", "micro_code",   "turbo_mode"};

const char* dimmInfoKey[] = {
    "",           "location",        "type",   "speed",      "part_name",
    "serial_num", "manufacturer_id", "status", "present_bit"};

const char* driveInfoKey[] = {"location",   "serial_num", "model_name",
                              "fw_version", "capacity",   "quantity",
                              "type",       "wwn"};

const char* ctrlTypeKey[] = {"bios", "expander", "lsi"};
