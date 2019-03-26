#pragma once

#include <ipmid/types.hpp>

#include <ipmid/api.h>
#include <stdint.h>

/**
 * Get SDR
 */
namespace get_sdr
{

// Response
struct GetSdrResp
{
    uint8_t next_record_id_lsb;
    uint8_t next_record_id_msb;
    uint8_t record_data[64];
} __attribute__((packed));

// Record header
struct SensorDataRecordHeader
{
    uint8_t record_id_lsb;
    uint8_t record_id_msb;
    uint8_t sdr_version;
    uint8_t record_type;
    uint8_t record_length; // Length not counting the header
} __attribute__((packed));

enum SensorDataRecordType
{
    SENSOR_DATA_FULL_RECORD = 0x1,
    SENSOR_DATA_FRU_RECORD = 0x11,
    SENSOR_DATA_ENTITY_RECORD = 0x8,
};

// Record key
struct SensorDataRecordKey
{
    uint8_t owner_id;
    uint8_t owner_lun;
    uint8_t sensor_number;
} __attribute__((packed));

/** @struct SensorDataFruRecordKey
 *
 *  FRU Device Locator Record(key) - SDR Type 11
 */
struct SensorDataFruRecordKey
{
    uint8_t deviceAddress;
    uint8_t fruID;
    uint8_t accessLun;
    uint8_t channelNumber;
} __attribute__((packed));

// Body - full record
#define FULL_RECORD_ID_STR_MAX_LENGTH 16

static const int FRU_RECORD_DEVICE_ID_MAX_LENGTH = 16;

struct SensorDataFullRecordBody
{
    uint8_t entity_id;
    uint8_t entity_instance;
    uint8_t sensor_initialization;
    uint8_t sensor_capabilities; // no macro support
    uint8_t sensor_type;
    uint8_t event_reading_type;
    uint8_t supported_assertions[2];          // no macro support
    uint8_t supported_deassertions[2];        // no macro support
    uint8_t discrete_reading_setting_mask[2]; // no macro support
    uint8_t sensor_units_1;
    uint8_t sensor_units_2_base;
    uint8_t sensor_units_3_modifier;
    uint8_t linearization;
    uint8_t m_lsb;
    uint8_t m_msb_and_tolerance;
    uint8_t b_lsb;
    uint8_t b_msb_and_accuracy_lsb;
    uint8_t accuracy_and_sensor_direction;
    uint8_t r_b_exponents;
    uint8_t analog_characteristic_flags; // no macro support
    uint8_t nominal_reading;
    uint8_t normal_max;
    uint8_t normal_min;
    uint8_t sensor_max;
    uint8_t sensor_min;
    uint8_t upper_nonrecoverable_threshold;
    uint8_t upper_critical_threshold;
    uint8_t upper_noncritical_threshold;
    uint8_t lower_nonrecoverable_threshold;
    uint8_t lower_critical_threshold;
    uint8_t lower_noncritical_threshold;
    uint8_t positive_threshold_hysteresis;
    uint8_t negative_threshold_hysteresis;
    uint16_t reserved;
    uint8_t oem_reserved;
    uint8_t id_string_info;
    char id_string[FULL_RECORD_ID_STR_MAX_LENGTH];
} __attribute__((packed));

/** @struct SensorDataFruRecordBody
 *
 *  FRU Device Locator Record(body) - SDR Type 11
 */
struct SensorDataFruRecordBody
{
    uint8_t reserved;
    uint8_t deviceType;
    uint8_t deviceTypeModifier;
    uint8_t entityID;
    uint8_t entityInstance;
    uint8_t oem;
    uint8_t deviceIDLen;
    char deviceID[FRU_RECORD_DEVICE_ID_MAX_LENGTH];
} __attribute__((packed));

struct SensorDataFullRecord
{
    SensorDataRecordHeader header;
    SensorDataRecordKey key;
    SensorDataFullRecordBody body;
} __attribute__((packed));

/** @struct SensorDataFruRecord
 *
 *  FRU Device Locator Record - SDR Type 11
 */
struct SensorDataFruRecord
{
    SensorDataRecordHeader header;
    SensorDataFruRecordKey key;
    SensorDataFruRecordBody body;
} __attribute__((packed));

} // namespace get_sdr
