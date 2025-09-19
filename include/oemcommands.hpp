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
    CMD_OEM_GET_HTTPS_BOOT_DATA = 0x57,
    CMD_OEM_GET_HTTPS_BOOT_ATTR = 0x58,
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
    CMD_OEM_CRASHDUMP = 0x70,
    CMD_OEM_GET_FRU_ID = 0x84,
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

/* To handle the processor product
 * name (ASCII code). */
#define MAX_BUF 50

#define BMC_POS 0
#define SIZE_CPU_PPIN 16
#define SIZE_BOOT_ORDER 6
#define BOOT_MODE_UEFI 0x01
#define BOOT_MODE_CMOS_CLR 0x02
#define BOOT_MODE_FORCE_BOOT 0x04
#define BOOT_MODE_BOOT_FLAG 0x80
#define BIT_0 0x01
#define BIT_1 0x02
#define BIT_2 0x04
#define BIT_3 0x08

#define KEY_PROC_NAME "product_name"
#define KEY_BASIC_INFO "basic_info"
#define DIMM_TYPE "type"
#define DIMM_SPEED "speed"
#define JSON_DIMM_TYPE_FILE "/usr/share/lcd-debug/dimm_type.json"
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

const char* bootSeqDefine[] = {"USB_DEV", "NET_IPV4", "SATA_HDD", "SATA_CD",
                               "OTHER",   "",         "",         "",
                               "",        "NET_IPV6"};

/*
Byte 2-6– Boot sequence
    Bit 2:0 – boot device id
        000b: USB device
        001b: Network
        010b: SATA HDD
        011b: SATA-CDROM
        100b: Other removable Device
    Bit 7:3 – reserve for boot device special request
        If Bit 2:0 is 001b (Network), Bit3 is IPv4/IPv6 order
           Bit3=0b: IPv4 first
           Bit3=1b: IPv6 first
*/
std::map<std::string, int> bootMap = {
    {"USB_DEV", 0},  {"NET_IPV4", 1}, {"NET_IPV6", 9},
    {"SATA_HDD", 2}, {"SATA_CD", 3},  {"OTHER", 4}};

std::map<size_t, std::string> dimmVenMap = {
    {0xce, "Samsung"}, {0xad, "Hynix"}, {0x2c, "Micron"}};

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

enum class HttpsBootAttr : uint8_t
{
    certSize = 0x00,
    certCrc = 0x01
};

enum class BankType : uint8_t
{
    mca = 0x01,
    virt = 0x02,
    cpuWdt = 0x03,
    tcdx = 0x06,
    cake = 0x07,
    pie0 = 0x08,
    iom = 0x09,
    ccix = 0x0a,
    cs = 0x0b,
    pcieAer = 0x0c,
    wdtReg = 0x0d,
    ctrl = 0x80,
    crdHdr = 0x81
};

enum class CrdState
{
    free = 0x01,
    waitData = 0x02,
    packing = 0x03
};

enum class CrdCtrl
{
    getState = 0x01,
    finish = 0x02
};

constexpr uint8_t ccmNum = 8;
constexpr uint8_t tcdxNum = 12;
constexpr uint8_t cakeNum = 6;
constexpr uint8_t pie0Num = 1;
constexpr uint8_t iomNum = 4;
constexpr uint8_t ccixNum = 4;
constexpr uint8_t csNum = 8;

#pragma pack(push, 1)

struct HttpsDataReq
{
    uint16_t offset;
    uint8_t length;
};

struct CrdCmdHdr
{
    uint8_t version;
    uint8_t reserved[3];
};

struct CrdBankHdr
{
    BankType bankType;
    uint8_t version;
    union
    {
        struct
        {
            uint8_t bankId;
            uint8_t coreId;
        };
        uint8_t reserved[2];
    };
};

struct CrashDumpHdr
{
    CrdCmdHdr cmdHdr;
    CrdBankHdr bankHdr;
};

// Type 0x01: MCA Bank
struct CrdMcaBank
{
    uint64_t mcaCtrl;
    uint64_t mcaSts;
    uint64_t mcaAddr;
    uint64_t mcaMisc0;
    uint64_t mcaCtrlMask;
    uint64_t mcaConfig;
    uint64_t mcaIpid;
    uint64_t mcaSynd;
    uint64_t mcaDestat;
    uint64_t mcaDeaddr;
    uint64_t mcaMisc1;
};

struct BankCorePair
{
    uint8_t bankId;
    uint8_t coreId;
};

// Type 0x02: Virtual/Global Bank
struct CrdVirtualBankV2
{
    uint32_t s5ResetSts;
    uint32_t breakevent;
    uint16_t mcaCount;
    uint16_t procNum;
    uint32_t apicId;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    struct BankCorePair mcaList[];
};

struct CrdVirtualBankV3
{
    uint32_t s5ResetSts;
    uint32_t breakevent;
    uint32_t rstSts;
    uint16_t mcaCount;
    uint16_t procNum;
    uint32_t apicId;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    struct BankCorePair mcaList[];
};

// Type 0x03: CPU/Data Fabric Watchdog Timer Bank
struct CrdCpuWdtBank
{
    uint32_t hwAssertStsHi[ccmNum];
    uint32_t hwAssertStsLo[ccmNum];
    uint32_t origWdtAddrLogHi[ccmNum];
    uint32_t origWdtAddrLogLo[ccmNum];
    uint32_t hwAssertMskHi[ccmNum];
    uint32_t hwAssertMskLo[ccmNum];
    uint32_t origWdtAddrLogStat[ccmNum];
};

template <size_t N>
struct CrdHwAssertBank
{
    uint32_t hwAssertStsHi[N];
    uint32_t hwAssertStsLo[N];
    uint32_t hwAssertMskHi[N];
    uint32_t hwAssertMskLo[N];
};

// Type 0x0C: PCIe AER Bank
struct CrdPcieAerBank
{
    uint8_t bus;
    uint8_t dev;
    uint8_t fun;
    uint16_t cmd;
    uint16_t sts;
    uint16_t slot;
    uint8_t secondBus;
    uint16_t vendorId;
    uint16_t devId;
    uint16_t classCodeLo; // Class Code 3 byte
    uint8_t classCodeHi;
    uint16_t secondSts;
    uint16_t ctrl;
    uint32_t uncorrErrSts;
    uint32_t uncorrErrMsk;
    uint32_t uncorrErrSeverity;
    uint32_t corrErrSts;
    uint32_t corrErrMsk;
    uint32_t hdrLogDw0;
    uint32_t hdrLogDw1;
    uint32_t hdrLogDw2;
    uint32_t hdrLogDw3;
    uint32_t rootErrSts;
    uint16_t corrErrSrcId;
    uint16_t errSrcId;
    uint32_t laneErrSts;
};

// Type 0x0D: SMU/PSP/PTDMA Watchdog Timers Register Bank
struct CrdWdtRegBank
{
    uint8_t nbio;
    char name[32];
    uint32_t addr;
    uint8_t count;
    uint32_t data[];
};

// Type 0x81: Crashdump Header
struct CrdHdrBank
{
    uint64_t ppin;
    uint32_t ucodeVer;
    uint32_t pmio;
};

#pragma pack(pop)

const char* cpuInfoKey[] = {"",     "product_name", "basic_info",
                            "type", "micro_code",   "turbo_mode"};

const char* dimmInfoKey[] = {
    "",           "location",        "type",   "speed",      "part_name",
    "serial_num", "manufacturer_id", "status", "present_bit"};

const char* driveInfoKey[] = {"location",   "serial_num", "model_name",
                              "fw_version", "capacity",   "quantity",
                              "type",       "wwn"};

const char* ctrlTypeKey[] = {"bios", "expander", "lsi"};
