/*
 * Copyright (c)  2024-present Facebook. All Rights Reserved.
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

static constexpr auto bootRawObjPrefix = "/xyz/openbmc_project/state/boot/raw";
static constexpr auto bootRawBusName = "xyz.openbmc_project.State.Boot.Raw";
static constexpr auto bootRawIntf = "xyz.openbmc_project.State.Boot.Raw";

namespace ipmi
{

using Group = uint8_t;
constexpr Group groupSBMR = 0xAE;

namespace sbmr
{
constexpr Cmd cmdSendBootProgress = 0x02;
} // namespace sbmr

} // namespace ipmi
