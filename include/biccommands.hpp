
enum fb_bic_cmds
{
    CMD_OEM_BIC_INFO = 0x01,
    CMD_OEM_GET_BIC_GPIO_STATE = 0x03,
    CMD_OEM_SEND_POST_BUFFER_TO_BMC = 0x08,
};

const char* dbusObj = "/xyz/openbmc_project/state/boot/raw";

const char* dbusService = "xyz.openbmc_project.State.Boot.Raw";

static constexpr auto iana =
    std::array<uint8_t, 3>{0x15, 0xA0, 0x0}; // Meta's IANA
