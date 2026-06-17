package api

// AuditChannel identifies the client surface a write action came through. It
// is self-reported by the client via the HeaderChannel request header and is
// informational metadata, not a security boundary — the actor remains
// authoritative.
type AuditChannel string

const (
	AuditChannelAPI     AuditChannel = "api"
	AuditChannelConsole AuditChannel = "console"
	AuditChannelMCP     AuditChannel = "mcp"
	AuditChannelCLI     AuditChannel = "cli"
)

// HeaderChannel is the HTTP header clients set to declare their channel.
const HeaderChannel = "X-Deploys-Channel"

// NormalizeAuditChannel maps an arbitrary client-supplied value to a known
// channel, falling back to AuditChannelAPI for empty or unrecognized input
// (e.g. direct API callers that send no header).
func NormalizeAuditChannel(s string) AuditChannel {
	switch AuditChannel(s) {
	case AuditChannelConsole:
		return AuditChannelConsole
	case AuditChannelMCP:
		return AuditChannelMCP
	case AuditChannelCLI:
		return AuditChannelCLI
	default:
		return AuditChannelAPI
	}
}
