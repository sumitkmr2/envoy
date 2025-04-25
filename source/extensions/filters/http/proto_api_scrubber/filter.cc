#include "envoy/source/extensions/filters/http/proto_api_scrubber/filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProtoApiScrubber {

Envoy::Http::FilterHeadersStatus Filter::decodeHeaders(Envoy::Http::RequestHeaderMap& headers, bool) {
  ENVOY_STREAM_LOG(debug, "Called ProtoApiScrubber::DecodeHeaders : {}", *decoder_callbacks_, __func__);
  return Envoy::Http::FilterHeadersStatus::Continue;
}

Envoy::Http::FilterDataStatus Filter::decodeData(Envoy::Buffer::Instance& data, bool end_stream) {
  ENVOY_STREAM_LOG(debug, "Called ProtoApiScrubber::decodeData: data size={} end_stream={}", *decoder_callbacks_, data.length(), end_stream);
  return Envoy::Http::FilterDataStatus::Continue;
}

Envoy::Http::FilterHeadersStatus Filter::encodeHeaders(Envoy::Http::ResponseHeaderMap& headers,
                                                       bool end_stream) {
  ENVOY_STREAM_LOG(debug, "Called ProtoApiScrubber::encodeHeaders: {}", *encoder_callbacks_,
                   __func__);
  return Envoy::Http::FilterHeadersStatus::Continue;
}

Envoy::Http::FilterDataStatus Filter::encodeData(Envoy::Buffer::Instance& data, bool end_stream) {
  ENVOY_STREAM_LOG(debug, "Called ProtoApiScrubber::encodeData: data size={} end_stream={}", *encoder_callbacks_,
                   data.length(), end_stream);
  return Envoy::Http::FilterDataStatus::Continue;
}
}
}
}
}
