package api

import (
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/moonrhythm/validator"
)

type ValidateError struct {
	err *validator.Error
}

func (err *ValidateError) Error() string {
	return err.err.Error()
}

func (err *ValidateError) OKError() {}

func (err *ValidateError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Message string   `json:"message"`
		Items   []string `json:"items"`
	}{"api: validate error", err.err.Strings()})
}

func (err *ValidateError) Items() []error {
	return err.err.Errors()
}

func WrapValidate(v *validator.Validator) error {
	if err := v.Error(); err != nil {
		return &ValidateError{err.(*validator.Error)}
	}
	return nil
}

func IsValidateError(err error) bool {
	var e *ValidateError
	return errors.As(err, &e)
}

// helper

var reEnvName = regexp.MustCompile(`^[-._a-zA-Z][-._a-zA-Z0-9]*$`)

func validEnvName(env map[string]string) bool {
	for k := range env {
		if !reEnvName.MatchString(k) {
			return false
		}
	}
	return true
}

func validImage(image string) bool {
	if strings.HasSuffix(image, "@") {
		return false
	}

	return true
}

func validRouteTarget(target string) bool {
	for _, x := range routeTargetPrefix {
		if strings.HasPrefix(target, x) {
			return true
		}
	}
	return false
}

func validURL(url string) bool {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return govalidator.IsURL(url)
	}
	return false
}

// validExternalTarget reports whether target is a phase-1 external upstream
// route: http://<ip>[:port] pointing at a customer-owned server. Only IP
// literals are accepted (no hostnames yet), and the IP must be globally
// routable — the guard blocks SSRF into loopback/private/link-local space
// (incl. the cloud metadata endpoint at 169.254.169.254) and the
// unspecified/multicast/CGNAT ranges. https:// is intentionally not accepted
// yet; phase 1 is HTTP-only.
func validExternalTarget(target string) bool {
	hostport, ok := strings.CutPrefix(target, "http://")
	if !ok || hostport == "" {
		return false
	}

	host, ok := splitHostPort(hostport)
	if !ok {
		return false
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return isPublicIP(ip)
}

// splitHostPort extracts the host from an "ip" or "ip:port" string, validating
// the port if present. A bare IPv6 literal may be bracketed ("[::1]") or not
// ("::1"). The port is optional (the caller supplies the default).
func splitHostPort(hostport string) (host string, ok bool) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		return h, true
	}
	// No port present. Strip brackets from a bare IPv6 literal.
	host = hostport
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return host, true
}

// isPublicIP reports whether ip is a globally routable unicast address — i.e.
// not in any range that could be turned into a request against internal
// infrastructure. IsPrivate covers 10/8, 172.16/12, 192.168/16 and fc00::/7;
// IsLinkLocalUnicast covers 169.254/16 (cloud metadata) and fe80::/10.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 0: // 0.0.0.0/8
			return false
		case ip4[0] == 100 && ip4[1]&0xc0 == 64: // 100.64.0.0/10 carrier-grade NAT
			return false
		}
	}
	return true
}
