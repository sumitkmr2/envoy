#pragma once

#include "envoy/extensions/filters/http/proto_api_scrubber/v3/config.pb.h"
#include "envoy/extensions/filters/http/proto_api_scrubber/v3/config.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProtoApiScrubber {

// The config for Proto Message Extraction filter. As a thread-safe class, it
// should be constructed only once and shared among filters for better
// performance.
class FilterConfig {
public:
  explicit FilterConfig(const envoy::extensions::filters::http::proto_api_scrubber::v3::
                            ProtoApiScrubberConfig& proto_config/*, Api::Api& api*/);

  ProtoApiScrubberConfig proto_config_;
  // Api::Api& api_;

};

using FilterConfigSharedPtr = std::shared_ptr<const FilterConfig>;

} // namespace ProtoApiScrubber
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
