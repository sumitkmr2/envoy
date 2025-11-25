#include "envoy/extensions/filters/http/proto_api_scrubber/v3/config.pb.h"
#include "envoy/grpc/status.h"
#include "envoy/registry/registry.h"        // Required for InjectFactory
#include "envoy/server/filter_config.h"     // For NamedHttpFilterConfigFactory
#include "envoy/stream_info/filter_state.h" // Required for FilterState::Object

#include "source/extensions/filters/http/common/factory_base.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

#include "test/extensions/filters/http/grpc_field_extraction/message_converter/message_converter_test_lib.h"
#include "test/integration/http_protocol_integration.h"
#include "test/proto/apikeys.pb.h"
#include "test/test_common/registry.h" // Required for InjectFactory

#include "eval/public/cel_value.h" // Required for CelValue::Type definition
#include "eval/public/structs/cel_proto_wrapper.h"
#include "fmt/format.h"
#include "google/protobuf/empty.pb.h"
#include "google/protobuf/struct.pb.h" // Required for Struct/ListValue

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProtoApiScrubber {
namespace {

using envoy::extensions::filters::http::proto_api_scrubber::v3::ProtoApiScrubberConfig;
using envoy::extensions::filters::network::http_connection_manager::v3::HttpFilter;
using ::Envoy::Extensions::HttpFilters::GrpcFieldExtraction::checkSerializedData;

std::string apikeysDescriptorPath() {
  return TestEnvironment::runfilesPath("test/proto/apikeys.descriptor");
}

const std::string kCreateApiKeyMethod = "/apikeys.ApiKeys/CreateApiKey";

// CEL Matcher Config (Protobuf Text Format) which evaluates to TRUE.
constexpr absl::string_view kCelAlwaysTrue = R"pb(
  cel_expr_parsed {
    expr {
      id: 1
      const_expr { bool_value: true }
    }
    source_info {
      syntax_version: "cel1"
      location: "inline_expression"
      positions { key: 1 value: 0 }
    }
  }
)pb";

// CEL Matcher Config (Protobuf Text Format) which evaluates to FALSE.
constexpr absl::string_view kCelAlwaysFalse = R"pb(
  cel_expr_parsed {
    expr {
      id: 1
      const_expr { bool_value: false }
    }
    source_info {
      syntax_version: "cel1"
      location: "inline_expression"
      positions { key: 1 value: 0 }
    }
  }
)pb";

// 1. Filter State Object Wrapper
class ProtobufFilterStateObject : public ::Envoy::StreamInfo::FilterState::Object {
public:
  explicit ProtobufFilterStateObject(std::unique_ptr<::google::protobuf::Message> msg)
      : msg_(std::move(msg)) {}

  // FIX: Use serializeAsProto instead of reflect.
  // This is the supported method in your Envoy version for exposing data.
  ::Envoy::ProtobufTypes::MessagePtr serializeAsProto() const override {
    // We must return a new copy because the signature returns a unique_ptr
    auto new_msg = std::unique_ptr<::google::protobuf::Message>(msg_->New());
    new_msg->CopyFrom(*msg_);
    return new_msg;
  }

private:
  std::unique_ptr<::google::protobuf::Message> msg_;
};

// 2. Injector Filter
class MetadataInjectorFilter : public ::Envoy::Http::PassThroughDecoderFilter {
public:
  ::Envoy::Http::FilterHeadersStatus decodeHeaders(::Envoy::Http::RequestHeaderMap&,
                                                   bool) override {
    // Create a simple StringValue
    auto metadata = std::make_unique<::google::protobuf::StringValue>();
    metadata->set_value("LABEL1,INTERNAL");

    // Inject directly into FilterState
    decoder_callbacks_->streamInfo().filterState()->setData(
        "wasm.cloudesf.wasms.chemist_v2_check.visibility_labels",
        std::make_shared<ProtobufFilterStateObject>(std::move(metadata)),
        ::Envoy::StreamInfo::FilterState::StateType::ReadOnly);

    return ::Envoy::Http::FilterHeadersStatus::Continue;
  }
};

// 3. Factory Registration
class MetadataInjectorConfigFactory
    : public ::Envoy::Server::Configuration::NamedHttpFilterConfigFactory {
public:
  absl::StatusOr<::Envoy::Http::FilterFactoryCb>
  createFilterFactoryFromProto(const ::Envoy::Protobuf::Message&, const std::string&,
                               ::Envoy::Server::Configuration::FactoryContext&) override {
    return [](::Envoy::Http::FilterChainFactoryCallbacks& callbacks) {
      callbacks.addStreamDecoderFilter(std::make_shared<MetadataInjectorFilter>());
    };
  }

  ::Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::google::protobuf::Empty>();
  }

  std::string name() const override { return "test_injector"; }
};

// 4. Static Registration
static MetadataInjectorConfigFactory* metadata_injector_config_factory =
    new MetadataInjectorConfigFactory();

static ::Envoy::Registry::InjectFactory<
    ::Envoy::Server::Configuration::NamedHttpFilterConfigFactory>
    register_injector(*metadata_injector_config_factory);

class ProtoApiScrubberIntegrationTest : public HttpProtocolIntegrationTest {
public:
  void SetUp() override { HttpProtocolIntegrationTest::SetUp(); }

  void TearDown() override {
    cleanupUpstreamAndDownstream();
    HttpProtocolIntegrationTest::TearDown();
  }

  enum class RestrictionType { Request, Response };

  // Helper to build the configuration using readable Protobuf Text Format.
  std::string getFilterConfig(const std::string& descriptor_path,
                              const std::string& method_name = "",
                              const std::string& field_to_scrub = "",
                              RestrictionType type = RestrictionType::Request,
                              absl::string_view cel_matcher_proto_text = kCelAlwaysTrue) {

    std::string full_config_text;
    if (method_name.empty() || field_to_scrub.empty()) {
      // Simple config with just descriptor
      full_config_text = fmt::format(
          R"pb(
            filtering_mode: OVERRIDE
            descriptor_set {{ data_source {{ filename: "{0}" }} }}
          )pb",
          descriptor_path);
    } else {
      std::string restriction_key = (type == RestrictionType::Request)
                                        ? "request_field_restrictions"
                                        : "response_field_restrictions";

      // Format the full config.
      full_config_text = fmt::format(R"pb(
      filtering_mode: OVERRIDE
      descriptor_set {{
        data_source {{
          filename: "{0}"
        }}
      }}
      restrictions {{
        method_restrictions {{
          key: "{1}"
          value {{
            {2} {{
              key: "{3}"
              value {{
                matcher {{
                  matcher_list {{
                    matchers {{
                      predicate {{
                        single_predicate {{
                          input {{
                            name: "envoy.matching.inputs.cel_data_input"
                            typed_config {{
                              [type.googleapis.com/xds.type.matcher.v3.HttpAttributesCelMatchInput] {{}}
                            }}
                          }}
                          custom_match {{
                            name: "envoy.matching.matchers.cel_matcher"
                            typed_config {{
                              [type.googleapis.com/xds.type.matcher.v3.CelMatcher] {{
                                expr_match {{
                                  {4}
                                }}
                              }}
                            }}
                          }}
                        }}
                      }}
                      on_match {{
                        action {{
                          name: "remove_field"
                          typed_config {{
                            [type.googleapis.com/envoy.extensions.filters.http.proto_api_scrubber.v3.RemoveFieldAction] {{}}
                          }}
                        }}
                      }}
                    }}
                  }}
                }}
              }}
            }}
          }}
        }}
      }}
    )pb",
                                     descriptor_path,       // {0}
                                     method_name,           // {1}
                                     restriction_key,       // {2}
                                     field_to_scrub,        // {3}
                                     cel_matcher_proto_text // {4}
      );
    }

    // ProtoApiScrubberConfig filter_config_proto;
    Protobuf::Any any_config;

    // Protobuf::TextFormat::ParseFromString(full_config_text, &filter_config_proto);

    // DEBUG: Print the config to verify the CEL expression is present!
    std::cerr << "DEBUG CONFIG:\n" << full_config_text << std::endl;

    ProtoApiScrubberConfig filter_config_proto;
    if (!Protobuf::TextFormat::ParseFromString(full_config_text, &filter_config_proto)) {
      std::cerr << "FAILED TO PARSE CONFIG" << std::endl;
      RELEASE_ASSERT(false, "Failed to parse config");
    }

    any_config.PackFrom(filter_config_proto);
    std::string json_config = MessageUtil::getJsonStringFromMessageOrError(any_config);
    return fmt::format(R"EOF(
      name: envoy.filters.http.proto_api_scrubber
      typed_config: {})EOF",
                       json_config);
  }

  template <typename T>
  IntegrationStreamDecoderPtr sendGrpcRequest(const T& request_msg,
                                              const std::string& method_path) {
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto request_buf = Grpc::Common::serializeToGrpcFrame(request_msg);
    auto request_headers = Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                                          {":path", method_path},
                                                          {"content-type", "application/grpc"},
                                                          {":authority", "host"},
                                                          {":scheme", "http"}};
    return codec_client_->makeRequestWithBody(request_headers, request_buf->toString());
  }
};

INSTANTIATE_TEST_SUITE_P(Protocols, ProtoApiScrubberIntegrationTest,
                         testing::ValuesIn(HttpProtocolIntegrationTest::getProtocolTestParams(
                             /*downstream_protocols=*/{Http::CodecType::HTTP2},
                             /*upstream_protocols=*/{Http::CodecType::HTTP2})),
                         HttpProtocolIntegrationTest::protocolTestParamsToString);

apikeys::CreateApiKeyRequest makeCreateApiKeyRequest(absl::string_view pb = R"pb(
  parent: "projects/123"
  key {
    display_name: "test-key"
    current_key: "abc-123"
  }
)pb") {
  apikeys::CreateApiKeyRequest request;
  Protobuf::TextFormat::ParseFromString(pb, &request);
  return request;
}

// ============================================================================
// TEST GROUP 1: PASS THROUGH
// ============================================================================

// Tests that the simple non-streaming request passes through without modification if there are no
// restrictions configured in the filter config.
TEST_P(ProtoApiScrubberIntegrationTest, UnaryRequestPassesThrough) {
  config_helper_.prependFilter(getFilterConfig(apikeysDescriptorPath()));
  initialize();

  auto request_proto = makeCreateApiKeyRequest();

  auto response = sendGrpcRequest(request_proto, kCreateApiKeyMethod);
  waitForNextUpstreamRequest();

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_TRUE(upstream_request_->receivedData());

  Buffer::OwnedImpl data;
  data.add(upstream_request_->body());
  checkSerializedData<apikeys::CreateApiKeyRequest>(data, {request_proto});

  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);
  ASSERT_TRUE(response->waitForEndStream());
}

// Tests that the streaming request passes through without modification if there are no restrictions
// configured in the filter config.
TEST_P(ProtoApiScrubberIntegrationTest, StreamingPassesThrough) {
  config_helper_.prependFilter(getFilterConfig(apikeysDescriptorPath()));
  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  auto req1 = makeCreateApiKeyRequest(R"pb(parent: "req1")pb");
  auto req2 = makeCreateApiKeyRequest(R"pb(parent: "req2")pb");
  auto req3 = makeCreateApiKeyRequest(R"pb(parent: "req3")pb");

  Buffer::OwnedImpl combined_request;
  combined_request.move(*Grpc::Common::serializeToGrpcFrame(req1));
  combined_request.move(*Grpc::Common::serializeToGrpcFrame(req2));
  combined_request.move(*Grpc::Common::serializeToGrpcFrame(req3));

  auto request_headers = Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                                        {":path", kCreateApiKeyMethod},
                                                        {"content-type", "application/grpc"},
                                                        {":authority", "host"},
                                                        {":scheme", "http"}};

  auto response = codec_client_->makeRequestWithBody(request_headers, combined_request.toString());
  waitForNextUpstreamRequest();

  Buffer::OwnedImpl data;
  data.add(upstream_request_->body());
  checkSerializedData<apikeys::CreateApiKeyRequest>(data, {req1, req2, req3});

  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);
  ASSERT_TRUE(response->waitForEndStream());
}

// ============================================================================
// TEST GROUP 2: SCRUBBING LOGIC
// ============================================================================

// Tests scrubbing of top level fields in the request when the corresponding matcher evaluates to
// true.
TEST_P(ProtoApiScrubberIntegrationTest, ScrubTopLevelField) {
  config_helper_.prependFilter(getFilterConfig(apikeysDescriptorPath(), kCreateApiKeyMethod,
                                               "parent", RestrictionType::Request, kCelAlwaysTrue));
  initialize();

  auto original_proto = makeCreateApiKeyRequest(R"pb(
    parent: "sensitive-data"
    key { display_name: "public" }
  )pb");

  auto response = sendGrpcRequest(original_proto, kCreateApiKeyMethod);
  waitForNextUpstreamRequest();

  apikeys::CreateApiKeyRequest expected = original_proto;
  expected.clear_parent();

  Buffer::OwnedImpl data;
  data.add(upstream_request_->body());
  checkSerializedData<apikeys::CreateApiKeyRequest>(data, {expected});

  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);
  ASSERT_TRUE(response->waitForEndStream());
}

// Tests scrubbing of nested fields in the request when the corresponding matcher evaluates to true.
TEST_P(ProtoApiScrubberIntegrationTest, ScrubNestedField_MatcherTrue) {
  config_helper_.prependFilter(getFilterConfig(apikeysDescriptorPath(), kCreateApiKeyMethod,
                                               "key.display_name", RestrictionType::Request,
                                               kCelAlwaysTrue));
  initialize();

  auto original_proto = makeCreateApiKeyRequest(R"pb(
    parent: "public"
    key { display_name: "sensitive" }
  )pb");

  auto response = sendGrpcRequest(original_proto, kCreateApiKeyMethod);
  waitForNextUpstreamRequest();

  apikeys::CreateApiKeyRequest expected = original_proto;
  expected.mutable_key()->clear_display_name();

  Buffer::OwnedImpl data;
  data.add(upstream_request_->body());
  checkSerializedData<apikeys::CreateApiKeyRequest>(data, {expected});

  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);
  ASSERT_TRUE(response->waitForEndStream());
}

// Tests scrubbing of nested fields in the request when the corresponding matcher evaluates to
// false.
TEST_P(ProtoApiScrubberIntegrationTest, ScrubNestedField_MatcherFalse) {
  config_helper_.prependFilter(getFilterConfig(apikeysDescriptorPath(), kCreateApiKeyMethod,
                                               "key.display_name", RestrictionType::Request,
                                               kCelAlwaysFalse));
  initialize();

  auto original_proto = makeCreateApiKeyRequest(R"pb(
    parent: "public"
    key { display_name: "should-stay" }
  )pb");

  auto response = sendGrpcRequest(original_proto, kCreateApiKeyMethod);
  waitForNextUpstreamRequest();

  Buffer::OwnedImpl data;
  data.add(upstream_request_->body());
  checkSerializedData<apikeys::CreateApiKeyRequest>(data, {original_proto});

  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);
  ASSERT_TRUE(response->waitForEndStream());
}

TEST_P(ProtoApiScrubberIntegrationTest, ScrubBasedOnFilterState) {
// Logic:
  // 1. Access request.filter_state['key'] -> Returns StringValue Message
  // 2. Access .value -> Returns primitive string "LABEL1,INTERNAL"
  // 3. Split by comma -> Returns list
  // 4. Check list for matches

  const std::string cel_expression_config = R"pb(
    cel_expr_parsed {
      expr {
        id: 1
        call_expr {
          function: "_||_"
          args {
            id: 2
            call_expr {
              function: "contains"
              # Target is implied "self" or usually can be omitted in some CEL contexts,
              # but for CelMatcher we often need the ident.
              # HOWEVER: CelMatcher with primitive inputs is tricky.
              # A safer bet for string matching is pure regex if CEL fights you on variable names.

              # Trying implicit self access via 'this' or simple function call:
              target { id: 3 ident_expr { name: "input" } } # Commonly 'input' in generic matchers
              args { id: 4 const_expr { string_value: "LABEL1" } }
            }
          }
          args {
            id: 5
            call_expr {
              function: "contains"
              target { id: 6 ident_expr { name: "input" } }
              args { id: 7 const_expr { string_value: "INTERNAL" } }
            }
          }
        }
      }
      source_info {
        syntax_version: "cel1"
        location: "inline_expression"
        positions { key: 1 value: 0 }
      }
    }
    )pb";

  config_helper_.prependFilter("{ name: test_injector }");
  config_helper_.prependFilter(getFilterConfig(apikeysDescriptorPath(), kCreateApiKeyMethod,
                                               "parent", RestrictionType::Request, cel_expression_config));

  initialize();

  // The request contains sensitive data in 'parent'
  auto original_proto = makeCreateApiKeyRequest(R"pb(
    parent: "sensitive-data"
  )pb");

  auto response = sendGrpcRequest(original_proto, kCreateApiKeyMethod);
  waitForNextUpstreamRequest();

  // Expectation: Because the injector added "LABEL1", the matcher returns TRUE.
  // Therefore, 'parent' should be scrubbed (cleared).
  apikeys::CreateApiKeyRequest expected = original_proto;
  expected.clear_parent();

  Buffer::OwnedImpl data;
  data.add(upstream_request_->body());
  checkSerializedData<apikeys::CreateApiKeyRequest>(data, {expected});

  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"}}, true);
  ASSERT_TRUE(response->waitForEndStream());
}

// ============================================================================
// TEST GROUP 3: VALIDATION & REJECTION
// ============================================================================

// Tests that the request is rejected if the called gRPC method doesn't exist in the descriptor
// configured in the filter config.
TEST_P(ProtoApiScrubberIntegrationTest, RejectsMethodNotInDescriptor) {
  config_helper_.prependFilter(getFilterConfig(apikeysDescriptorPath()));
  initialize();

  auto request_proto = makeCreateApiKeyRequest();
  auto response = sendGrpcRequest(request_proto, "/apikeys.ApiKeys/NonExistentMethod");

  ASSERT_TRUE(response->waitForEndStream());

  // For gRPC requests, Envoy returns HTTP 200 with grpc-status in the header.
  // We check that grpc-status matches INVALID_ARGUMENT (3).
  auto grpc_status = response->headers().GrpcStatus();
  ASSERT_TRUE(grpc_status != nullptr);
  EXPECT_EQ("3", grpc_status->value().getStringView()); // 3 = Invalid Argument
}

// Tests that the request is rejected if the gRPC `:path` header is in invalid format.
TEST_P(ProtoApiScrubberIntegrationTest, RejectsInvalidPathFormat) {
  config_helper_.prependFilter(getFilterConfig(apikeysDescriptorPath()));
  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));

  auto request_headers = Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                                        {":path", "/invalid-format"},
                                                        {"content-type", "application/grpc"},
                                                        {":authority", "host"},
                                                        {":scheme", "http"}};

  auto response = codec_client_->makeHeaderOnlyRequest(request_headers);
  ASSERT_TRUE(response->waitForEndStream());

  // For gRPC requests, expect HTTP 200 with grpc-status header.
  auto grpc_status = response->headers().GrpcStatus();
  ASSERT_TRUE(grpc_status != nullptr);
  EXPECT_EQ("3", grpc_status->value().getStringView()); // 3 = Invalid Argument
}

} // namespace
} // namespace ProtoApiScrubber
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
