
#define SIZE_IANA_ID 3
#define DATA_BYTE_IDX 6

#define INTERFACE_IDX 3
#define NETFN_IDX 4
#define CMD_IDX 5
#define SHIFT_TWO 2

#define ZERO_IDX 0
#define ONE_IDX 1

// IPMI Command for a Net Function number as specified by IPMI V2.0 spec.
using Cmd = uint8_t;

constexpr Cmd cmdOemBicInfo = 0x01;
