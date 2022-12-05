
// Command for getting device id
constexpr uint8_t cmdOemBicInfo = 0x01;

// Command for getting post code
constexpr uint8_t cmdOemSendPostBufferToBMC = 0x08;

// Command for clear CMOS
constexpr uint8_t cmdOemClearCMOS = 0x25;

const char* dbusObj = "/xyz/openbmc_project/state/boot/raw";

const char* dbusService = "xyz.openbmc_project.State.Boot.Raw";
