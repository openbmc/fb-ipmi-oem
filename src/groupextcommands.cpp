#include <commandutils.hpp>
#include <groupextcommands.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <phosphor-logging/lg2.hpp>

namespace ipmi
{

void registerSBMRFunctions() __attribute__((constructor));

ipmi::RspType<> ipmiSBMRSendBootProgress(ipmi::Context::ptr ctx,
                                         std::vector<uint8_t> data)
{
    using postcode_t = std::tuple<uint64_t, std::vector<uint8_t>>;

    std::optional<size_t> hostId = findHost(ctx->hostIdx);

    if (!hostId)
    {
        lg2::error("Invalid Host Id received");
        return ipmi::responseInvalidCommand();
    }

    if (data.size() != 9)
    {
        lg2::error("Invalid request of boot progress length received: {LENGTH}",
                   "LENGTH", data.size());
        return ipmi::responseReqDataLenInvalid();
    }

    try
    {
        auto primaryPostCode = reinterpret_cast<const uint64_t*>(data.data());
        auto postCode = postcode_t(*primaryPostCode, data);
        auto conn = getSdBus();
        auto hostbootRawObj = std::string(bootRawObjPrefix) +
                              std::to_string(*hostId);
        auto method =
            conn->new_method_call(bootRawBusName, hostbootRawObj.data(),
                                  "org.freedesktop.DBus.Properties", "Set");

        method.append(bootRawIntf, "Value", std::variant<postcode_t>(postCode));

        conn->call_noreply(method);
    }
    catch (std::exception& e)
    {
        lg2::error("postcode handler error: {WHAT}", "WHAT", e.what());
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
