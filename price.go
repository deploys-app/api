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

	// PriceStaticStorage is the static-web object-storage rate in THB per
	// GiB-month. The billing cron applies it to a once-daily byte gauge with
	// Unit = unitGiB * 30, so a month is realized as ~30 daily snapshots.
	PriceStaticStorage = 1 // GiB-month

	// PriceDropboxStorage is the dropbox object-storage rate in THB per
	// GiB-month. Same as SSD Disk: PriceDisk * 60*60*24*30. Billed as a
	// once-daily byte gauge with Unit = unitGiB * unitMonth, mirroring
	// PriceStaticStorage.
	PriceDropboxStorage = 10.368 // GiB-month (same as SSD Disk: PriceDisk * 60*60*24*30)

	// External HTTP routes ("bring your own server" + WAF). The customer brings
	// the compute, so we bill only edge egress served from the edge — no flat
	// per-route fee. Default anchors to the egress rate and is overridable per
	// account/location via *_skus; pending finance sign-off.
	PriceWAFEgress = 4 // GiB (anchor: PriceEgress)

	// PriceStaticEgress is the origin egress rate for Static deployments in THB
	// per GiB — the body bytes the static-gateway streams, summed per project
	// from static_gateway_response_bytes_total. Static has no pod, so the
	// pod-based PriceEgress metric never sees it. Anchored to the egress rate and
	// overridable per account/location via *_skus; pending finance sign-off.
	PriceStaticEgress = 4 // GiB (anchor: PriceEgress)
)
