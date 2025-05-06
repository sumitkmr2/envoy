#include "source/extensions/filters/http/proto_api_scrubber/filter_config.h"

// #include "envoy/api/api.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProtoApiScrubber {
namespace {

using ::envoy::extensions::filters::http::proto_api_scrubber::v3::
    ProtoApiScrubberConfig;
// using ::google::grpc::transcoding::TypeHelper;
} // namespace

FilterConfig::FilterConfig(const ProtoApiScrubberConfig& proto_config/*, Api::Api& api*/){
    this->proto_config_ = proto_config;
  // api_ = api;
}

} // namespace ProtoApiScrubber
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
