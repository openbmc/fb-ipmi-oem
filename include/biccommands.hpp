
enum fb_bic_cmds
{
    CMD_OEM_BIC_INFO = 0x01,
    CMD_OEM_GET_BIC_GPIO_STATE = 0x03,
    CMD_OEM_SEND_POST_BUFFER_TO_BMC = 0x08,
    CMD_OEM_SET_HOST_POWER_STATE = 0x0C,
};

const char* dbusObj = "/xyz/openbmc_project/state/boot/raw";

const char* dbusService = "xyz.openbmc_project.State.Boot.Raw";

constexpr auto systemdService = "org.freedesktop.systemd1";
constexpr auto systemdObjPath = "/org/freedesktop/systemd1";
constexpr auto systemdInterface = "org.freedesktop.systemd1.Manager";

static constexpr auto iana =
    std::array<uint8_t, 3>{0x15, 0xA0, 0x0}; // Meta's IANA

enum host_power_state
{
    HOST_POWER_OFF = 0x0,
    HOST_POWER_ON = 0x1,
};
