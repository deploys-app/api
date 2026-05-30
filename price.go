package api

const (
	PriceCPUUsage       = 0.0006   // s
	PriceCPU            = 0.00025  // s
	PriceMemory         = 0.00007  // GiB/s
	PriceEgress         = 4        // GiB
	PriceRegistryEgress = 1        // GiB
	PriceDropboxEgress  = 1        // GiB
	PriceDisk           = 0.000004 // GiB/s
	PriceReplica        = 0.000004 // replica/s
	PriceDomainCDN      = 0.00038  // domain/s

	// External HTTP routes ("bring your own server" + WAF). The customer brings
	// the compute, so we only bill edge work: a flat per-route fee for the edge
	// (cert + WAF zone + load-balancer slot) and egress served from the edge.
	// Defaults anchor to the CDN-domain and egress rates; both are overridable
	// per account/location via *_skus and pending finance sign-off.
	PriceWAFRoute  = 0.00038 // route/s (anchor: PriceDomainCDN)
	PriceWAFEgress = 4       // GiB     (anchor: PriceEgress)
)
