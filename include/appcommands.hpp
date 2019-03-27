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
    CMD_APP_SET_ACPI = 0x06,
    CMD_APP_GET_ACPI = 0x07,
    CMD_APP_GET_DEV_GUID = 0x08,
    CMD_APP_RESET_WD = 0x22,
    CMD_APP_SET_WD = 0x24,
    CMD_APP_GET_WD = 0x25,
    CMD_APP_SET_GLOBAL_ENABLES = 0x2E,
    CMD_APP_GET_GLOBAL_ENABLES = 0x2F,
    CMD_APP_GET_MSG_FLAGS = 0x31,
    CMD_APP_READ_EVENT = 0x35,
    CMD_APP_GET_CAP_BIT = 0x36,
    CMD_APP_GET_SYS_GUID = 0x37,
    CMD_APP_SET_CHAN_ACCESS = 0x40,
    CMD_APP_GET_CHANNEL_ACCESS = 0x41,
    CMD_APP_GET_CHAN_INFO = 0x42,

};
