
enum class fb_bic_cmds : uint8_t
{
    CMD_OEM_BIC_INFO = 0x1,
    CMD_OEM_GET_BIC_GPIO_STATE = 0x3,
    CMD_OEM_SEND_POST_BUFFER_TO_BMC = 0x8,
    CMD_OEM_SET_HOST_POWER_STATE = 0x0C,
    CMD_OEM_CLEAR_CMOS = 0x25,
};

// Command for clear CMOS
constexpr uint8_t cmdOemClearCMOS = 0x25;

const char* dbusObj = "/xyz/openbmc_project/state/boot/raw";

const char* dbusService = "xyz.openbmc_project.State.Boot.Raw";

constexpr auto systemdService = "org.freedesktop.systemd1";
constexpr auto systemdObjPath = "/org/freedesktop/systemd1";
constexpr auto systemdInterface = "org.freedesktop.systemd1.Manager";

enum class HostPowerState : uint8_t
{
    HOST_POWER_OFF = 0x0,
    HOST_POWER_ON = 0x1,
};
