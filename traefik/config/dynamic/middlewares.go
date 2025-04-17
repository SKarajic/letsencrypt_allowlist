package dynamic

import (
	"fmt"
	"github.com/skarajic/letsencrypt_allowlist/traefik/ip"
)

// IPAllowList holds the IP allowlist middleware configuration.
// This middleware limits allowed requests based on the client IP.
// More info: https://doc.traefik.io/traefik/v3.4/middlewares/http/ipallowlist/
type IPAllowList struct {
	// SourceRange defines the set of allowed IPs (or ranges of allowed IPs by using CIDR notation).
	SourceRange []string    `json:"sourceRange,omitempty" toml:"sourceRange,omitempty" yaml:"sourceRange,omitempty"`
	IPStrategy  *IPStrategy `json:"ipStrategy,omitempty" toml:"ipStrategy,omitempty" yaml:"ipStrategy,omitempty" label:"allowEmpty" file:"allowEmpty" kv:"allowEmpty" export:"true"`
	// RejectStatusCode defines the HTTP status code used for refused requests.
	// If not set, the default is 403 (Forbidden).
	RejectStatusCode int `json:"rejectStatusCode,omitempty" toml:"rejectStatusCode,omitempty" yaml:"rejectStatusCode,omitempty" label:"allowEmpty" file:"allowEmpty" kv:"allowEmpty" export:"true"`
}

// IPStrategy holds the IP strategy configuration used by Traefik to determine the client IP.
// More info: https://doc.traefik.io/traefik/v3.4/middlewares/http/ipallowlist/#ipstrategy
type IPStrategy struct {
	// Depth tells Traefik to use the X-Forwarded-For header and take the IP located at the depth position (starting from the right).
	// +kubebuilder:validation:Minimum=0
	Depth int `json:"depth,omitempty" toml:"depth,omitempty" yaml:"depth,omitempty" export:"true"`
	// ExcludedIPs configures Traefik to scan the X-Forwarded-For header and select the first IP not in the list.
	ExcludedIPs []string `json:"excludedIPs,omitempty" toml:"excludedIPs,omitempty" yaml:"excludedIPs,omitempty"`
	// IPv6Subnet configures Traefik to consider all IPv6 addresses from the defined subnet as originating from the same IP. Applies to RemoteAddrStrategy and DepthStrategy.
	IPv6Subnet *int `json:"ipv6Subnet,omitempty" toml:"ipv6Subnet,omitempty" yaml:"ipv6Subnet,omitempty"`
	// TODO(mpl): I think we should make RemoteAddr an explicit field. For one thing, it would yield better documentation.
}

// Get an IP selection strategy.
// If nil return the RemoteAddr strategy
// else return a strategy based on the configuration using the X-Forwarded-For Header.
// Depth override the ExcludedIPs.
func (s *IPStrategy) Get() (ip.Strategy, error) {
	if s == nil {
		return &ip.RemoteAddrStrategy{}, nil
	}

	if s.Depth > 0 {
		if s.IPv6Subnet != nil && (*s.IPv6Subnet <= 0 || *s.IPv6Subnet > 128) {
			return nil, fmt.Errorf("invalid IPv6 subnet %d value, should be greater to 0 and lower or equal to 128", *s.IPv6Subnet)
		}

		return &ip.DepthStrategy{
			Depth:      s.Depth,
			IPv6Subnet: s.IPv6Subnet,
		}, nil
	}

	if len(s.ExcludedIPs) > 0 {
		checker, err := ip.NewChecker(s.ExcludedIPs)
		if err != nil {
			return nil, err
		}
		return &ip.PoolStrategy{
			Checker: checker,
		}, nil
	}

	if s.IPv6Subnet != nil && (*s.IPv6Subnet <= 0 || *s.IPv6Subnet > 128) {
		return nil, fmt.Errorf("invalid IPv6 subnet %d value, should be greater to 0 and lower or equal to 128", *s.IPv6Subnet)
	}

	return &ip.RemoteAddrStrategy{
		IPv6Subnet: s.IPv6Subnet,
	}, nil
}
