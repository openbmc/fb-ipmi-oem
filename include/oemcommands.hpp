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
