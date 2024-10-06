#include <commandutils.hpp>
#include <groupextcommands.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <phosphor-logging/lg2.hpp>

namespace ipmi
{

PHOSPHOR_LOG2_USING;

uint64_t bigEndianToHost(uint64_t bigEndianValue)
{
    if (std::endian::native == std::endian::little)
    {
        return std::byteswap(bigEndianValue);
    }

    return bigEndianValue;
}

void registerSBMRFunctions() __attribute__((constructor));

ipmi::RspType<> ipmiSBMRSendBootProgress(ipmi::Context::ptr ctx,
                                         std::vector<uint8_t> data)
{
    using postcode_t = std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>;

    std::optional<size_t> hostId = findHost(ctx->hostIdx);

    if (!hostId)
    {
        error("Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }

    if (data.size() != 9)
    {
        error("Invalid request of boot progress length received: {LENGTH}",
              "LENGTH", data.size());
        return ipmi::responseReqDataLenInvalid();
    }

    try
    {
        postcode_t postCode(std::move(data), {});
        auto conn = getSdBus();
        auto hostbootRawObj =
            std::string(bootRawObjPrefix) + std::to_string(*hostId);
        auto method =
            conn->new_method_call(bootRawBusName, hostbootRawObj.data(),
                                  "org.freedesktop.DBus.Properties", "Set");

        method.append(bootRawIntf, "Value",
                      std::variant<postcode_t>(std::move(postCode)));

        conn->call_noreply(method);
    }
    catch (std::exception& e)
    {
        error("postcode handler error: {ERROR}", "ERROR", e);
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

void registerSBMRFunctions()
{
    ipmi::registerGroupHandler(
        ipmi::prioOemBase, ipmi::groupSBMR, ipmi::sbmr::cmdSendBootProgress,
        ipmi::Privilege::Admin, ipmiSBMRSendBootProgress);
    return;
}

} // end of namespace ipmi
