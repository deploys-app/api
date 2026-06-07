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

	// External HTTP routes ("bring your own server" + WAF). The customer brings
	// the compute, so we bill only edge egress served from the edge — no flat
	// per-route fee. Default anchors to the egress rate and is overridable per
	// account/location via *_skus; pending finance sign-off.
	PriceWAFEgress = 4 // GiB (anchor: PriceEgress)
)
