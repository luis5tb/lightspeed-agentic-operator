package configuration

const (
	// ConfigMapName is the well-known name of the ConfigMap created by the
	// lightspeed-operator with agentic sandbox and Collector connectivity details.
	ConfigMapName                = "lightspeed-agentic-configuration"
	DefaultTerminalTTLDays int32 = 14

	// ConfigMap keys (lightspeed-agentic-configuration)
	KeySandboxMode                 = "sandbox-mode"
	KeyTerminalTTLDays             = "terminal-ttl-days"
	KeySandboxPodSpec              = "sandbox-pod-spec"
	KeySandboxCredentialMode       = "sandbox-credential-mode"
	KeyGatewayServerURLTemplate    = "gateway-server-url-template"
	KeyGatewayCASecret             = "gateway-ca-secret"
	KeyToolOutputInspectionEnabled = "tool-output-inspection-enabled"
	KeyTLSProfile                  = "tls-profile"
	KeyTLSMinVersion               = "tls-min-version"
	KeyTLSCipherSuites             = "tls-cipher-suites"
	KeyAdditionalCAConfigMap       = "additional-ca-configmap"
	KeyOtelCollectorEndpoint       = "otel-collector-endpoint"
	KeyOtelAdminEndpoint           = "otel-admin-endpoint"
	KeyOtelCASecret                = "otel-ca-secret"
	KeyOtelCredentialsSecret       = "otel-credentials-secret"
	KeyMCPEndpoint                 = "mcp-endpoint"
	KeyMCPCASecret                 = "mcp-ca-secret"
	KeyRHOKPEndpoint               = "rhokp-endpoint"
	KeyRHOKPCASecret               = "rhokp-ca-secret"

	// Error constants
	ErrReadConfigMap         = "read configuration ConfigMap"
	ErrInvalidConfig         = "invalid configuration ConfigMap"
	ErrParseSandboxPodSpec   = "parse sandbox-pod-spec from ConfigMap"
	ErrReadCASecret          = "read OTEL CA Secret"
	ErrParseCACert           = "parse CA certificate"
	ErrReadCredentialsSecret = "read credentials Secret"
	ErrParseClientCert       = "parse client TLS certificate"
	ErrCreateTraceExporter   = "create OTLP trace exporter"
	ErrCreateLogExporter     = "create OTLP log exporter"
	ErrCreateDeleteRequest   = "create delete request"
	ErrDeleteLogs            = "delete logs"
	ErrInvalidCredentialMode = "invalid sandbox-credential-mode"
	ErrMissingGatewayConfig  = "gateway credential mode is missing required configuration"

	// Sandbox credential modes (sandbox-credential-mode key).
	// CredentialModeSpokeSA is the default: the operator requests a per-step
	// spoke SA token and embeds it in the sandbox kubeconfig.
	CredentialModeSpokeSA = "spoke-sa"
	// CredentialModeGateway routes sandbox spoke traffic through a hub-local
	// policy gateway performing an RFC 8693 token exchange per call.
	CredentialModeGateway = "gateway"
)
