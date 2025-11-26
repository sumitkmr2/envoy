#include "envoy/extensions/filters/http/proto_api_scrubber/v3/config.pb.h"
#include "envoy/extensions/filters/http/proto_api_scrubber/v3/matcher_actions.pb.h"
#include "envoy/grpc/status.h"
#include "envoy/matcher/matcher.h"
#include "envoy/registry/registry.h"        // Required for InjectFactory
#include "envoy/server/filter_config.h"     // For NamedHttpFilterConfigFactory
#include "envoy/stream_info/filter_state.h" // Required for FilterState::Object

#include "source/extensions/filters/http/common/factory_base.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"
#include "source/common/router/string_accessor_impl.h"

#include "test/extensions/filters/http/grpc_field_extraction/message_converter/message_converter_test_lib.h"
#include "test/integration/http_protocol_integration.h"
#include "test/proto/apikeys.pb.h"
#include "test/test_common/registry.h" // Required for InjectFactory

#include "eval/public/cel_value.h" // Required for CelValue::Type definition
#include "eval/public/structs/cel_proto_wrapper.h"
#include "fmt/format.h"
#include "google/protobuf/empty.pb.h"
#include "google/protobuf/struct.pb.h" // Required for Struct/ListValue

#include <google/api/expr/v1alpha1/checked.pb.h>

#include "parser/parser.h"
#include "google/api/expr/v1alpha1/syntax.pb.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ProtoApiScrubber {
namespace {

using envoy::extensions::filters::http::proto_api_scrubber::v3::ProtoApiScrubberConfig;
using envoy::extensions::filters::network::http_connection_manager::v3::HttpFilter;
using ::Envoy::Extensions::HttpFilters::GrpcFieldExtraction::checkSerializedData;

// --- ADD THIS BLOCK TO integration_test.cc ---

// --- PASTE THIS INTO integration_test.cc ---

// 1. Define the Action Class
class TestRemoveFieldAction
    : public Envoy::Matcher::ActionBase<envoy::extensions::filters::http::proto_api_scrubber::v3::RemoveFieldAction> {
public:
  absl::string_view typeUrl() const override {
    return "type.googleapis.com/envoy.extensions.filters.http.proto_api_scrubber.v3.RemoveFieldAction";
  }
};

// 2. Define the Factory
class TestRemoveFilterActionFactory
    : public Envoy::Matcher::ActionFactory<envoy::extensions::filters::http::proto_api_scrubber::v3::RemoveFieldAction> {
public:
  std::string name() const override { return "remove_field"; }

  // FIX: Matches filter_config.h signature exactly
  Envoy::Matcher::ActionConstSharedPtr createAction(
      const Envoy::Protobuf::Message&,
      envoy::extensions::filters::http::proto_api_scrubber::v3::RemoveFieldAction&,
      Envoy::ProtobufMessage::ValidationVisitor&) override {
    return std::make_shared<TestRemoveFieldAction>();
  }

  Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<envoy::extensions::filters::http::proto_api_scrubber::v3::RemoveFieldAction>();
  }
};

// 3. Register the Factory
static TestRemoveFilterActionFactory* test_action_factory = new TestRemoveFilterActionFactory();
static Envoy::Registry::InjectFactory<Envoy::Matcher::ActionFactory<envoy::extensions::filters::http::proto_api_scrubber::v3::RemoveFieldAction>>
    register_test_action_factory(*test_action_factory);

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


// Injector: Writes to StreamInfo::FilterState
class MetadataInjectorFilter : public ::Envoy::Http::PassThroughDecoderFilter {
public:
  ::Envoy::Http::FilterHeadersStatus decodeHeaders(::Envoy::Http::RequestHeaderMap&,
                                                   bool) override {
    const std::string key = "wasm.cloudesf.wasms.chemist_v2_check.visibility_labels";
    const std::string value = "LABEL1,INTERNAL";

    std::cerr << ">>> TEST INJECTOR: Writing to FilterState..." << std::endl;

    // Use the built-in Router::StringAccessorImpl
    // This implements serializeAsString() automatically, so your Regex Matcher will work.
    decoder_callbacks_->streamInfo().filterState()->setData(
        key,
        std::make_shared<::Envoy::Router::StringAccessorImpl>(value),
        ::Envoy::StreamInfo::FilterState::StateType::ReadOnly);

    return ::Envoy::Http::FilterHeadersStatus::Continue;
  }
};

class MetadataInjectorConfigFactory
    : public ::Envoy::Server::Configuration::NamedHttpFilterConfigFactory {
public:
  // Change 1: Update the config type in the validation signature
  absl::StatusOr<::Envoy::Http::FilterFactoryCb>
  createFilterFactoryFromProto(const ::Envoy::Protobuf::Message&, const std::string&,
                               ::Envoy::Server::Configuration::FactoryContext&) override {
    return [](::Envoy::Http::FilterChainFactoryCallbacks& callbacks) {
      callbacks.addStreamDecoderFilter(std::make_shared<MetadataInjectorFilter>());
    };
  }

  // Change 2: Return 'Struct' instead of 'Empty' to satisfy the assertion
  ::Envoy::ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::google::protobuf::Struct>();
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

  // Helper to build config using FilterStateInput instead of HttpAttributes
// Helper to build config using FilterStateInput
std::string getFilterConfigWithFilterStateInput(const std::string& descriptor_path,
                                                const std::string& filter_state_key,
                                                const std::string& cel_matcher_proto_text) {
  // We use fmt::format to inject the FilterStateInput typed_config
  return fmt::format(R"pb(
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
          request_field_restrictions {{
            key: "parent"
            value {{
              matcher {{
                matcher_list {{
                  matchers {{
                    predicate {{
                      single_predicate {{
                        input {{
                          name: "envoy.matching.inputs.filter_state"
                          typed_config {{
                            [type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.FilterStateInput] {{
                              key: "wasm.cloudesf.wasms.chemist_v2_check.visibility_labels"
                            }}
                          }}
                        }}
                        # USE SIMPLE CONTAINS FOR DEBUGGING
                        value_match {{
                          contains: "LABEL1"
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
  descriptor_path,      // {0}
  kCreateApiKeyMethod,  // {1}
  filter_state_key,     // {2}
  cel_matcher_proto_text // {3}
  );
}

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

  void printAst(std::string expr_str = "request.headers['user-agent'].contains('curl')") {
    // 1. Invoke the CEL Parser
    // Returns a google::api::expr::parser::ParseStatus
    auto parse_status = google::api::expr::parser::Parse(expr_str);

    if (!parse_status.ok()) {
      // Handle error: parse_status.status() contains the error message
      return;
    }

    // 2. Get the ParsedExpr Protobuf
    // This object contains the AST and source info.
    const auto& parsed_expr = parse_status.value();

    std::cout << "Parsed AST: " << std::endl;
    std::cout << parsed_expr.DebugString() << std::endl;
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


TEST_P(ProtoApiScrubberIntegrationTest, Ast) {
  printAst("request.headers['user-agent'].contains('curl')");
  printAst("filter_state['visibility.labels'].contains('INTERNAL')");
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

TEST_P(ProtoApiScrubberIntegrationTest, ScrubBasedOnMultipleLabelsRegex) {
  // LOGIC:
  // 1. Injector writes "LABEL1,INTERNAL"
  // 2. Regex matches "LABEL1" -> Returns TRUE.
  // 3. Action: Remove "key.display_name" (Nested field)

  // 1. Config
  std::string config_pb_text = fmt::format(R"pb(
    filtering_mode: OVERRIDE
    descriptor_set {{ data_source {{ filename: "{0}" }} }}
    restrictions {{
      method_restrictions {{
        key: "{1}"
        value {{
          request_field_restrictions {{
            key: "key.display_name"
            value {{
              matcher {{
                matcher_list {{
                  matchers {{
                    predicate {{
                      single_predicate {{
                        input {{
                          name: "envoy.matching.inputs.filter_state"
                          typed_config {{
                            [type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.FilterStateInput] {{
                              key: "wasm.cloudesf.wasms.chemist_v2_check.visibility_labels"
                            }}
                          }}
                        }}
                        value_match {{
                          contains: "LABEL1"
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
  )pb", apikeysDescriptorPath(), kCreateApiKeyMethod);

  ProtoApiScrubberConfig proto_config;
  ASSERT_TRUE(Protobuf::TextFormat::ParseFromString(config_pb_text, &proto_config));
  Protobuf::Any any_config;
  any_config.PackFrom(proto_config);

  // 2. Setup Chain
  config_helper_.prependFilter(fmt::format(R"EOF(
      name: envoy.filters.http.proto_api_scrubber
      typed_config: {})EOF", MessageUtil::getJsonStringFromMessageOrError(any_config)));
  config_helper_.prependFilter("{ name: test_injector }");

  initialize();

  // 3. Request with Nested Data
  auto original_proto = makeCreateApiKeyRequest(R"pb(
    parent: "should-stay"
    key { display_name: "sensitive-name" }
  )pb");

  auto response = sendGrpcRequest(original_proto, kCreateApiKeyMethod);
  waitForNextUpstreamRequest();

  // 4. Verify Nested Scrubbing
  apikeys::CreateApiKeyRequest expected = original_proto;
  expected.mutable_key()->clear_display_name(); // Expect this to be cleared

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
