#include "source/extensions/filters/http/proto_api_scrubber/config.h"

#include <memory>
#include <string>

#include "envoy/http/filter.h"
#include "envoy/registry/registry.h"

#include "source/common/http/codes.h"
#include "source/common/http/header_utility.h"
#include "source/extensions/filters/http/proto_api_scrubber/filter.h"

#include "proto_field_extraction/message_data/cord_message_data.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProtoApiScrubber {

FilterFactoryCreator::FilterFactoryCreator() : FactoryBase(kFilterName) {}

Envoy::Http::FilterFactoryCb FilterFactoryCreator::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::proto_api_scrubber::v3::
        ProtoApiScrubberConfig& proto_config,
    const std::string&, Envoy::Server::Configuration::FactoryContext& context) {
  // TODO: Might need to update this to remove ExtractorFactoryImpl.
  auto filter_config = std::make_shared<FilterConfig>(
      proto_config/*, context.serverFactoryContext().api()*/);
  return [filter_config](Envoy::Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<Filter>(*filter_config));
  };
}

REGISTER_FACTORY(FilterFactoryCreator, Envoy::Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace ProtoApiScrubber
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
