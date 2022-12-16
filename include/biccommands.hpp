
enum class fb_bic_cmds : uint8_t
{
    CMD_OEM_BIC_INFO = 0x1,
    CMD_OEM_GET_BIC_GPIO_STATE = 0x3,
    CMD_OEM_SEND_POST_BUFFER_TO_BMC = 0x8,
};

const char* dbusObj = "/xyz/openbmc_project/state/boot/raw";

const char* dbusService = "xyz.openbmc_project.State.Boot.Raw";
