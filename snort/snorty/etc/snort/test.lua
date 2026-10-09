profiler = { }
perf_monitor =
{
    base          = true,
    flow          = false,   -- set true if you also want per-flow CSV
    flow_ip       = false,   -- per-IP-pair breakdowns (high-volume in a lab)

    seconds       = 30,

    max_file_size = 10485760,
}


alert_json = {
	file = true,
	limit = 100,
	fields = 'seconds timestamp gid sid rev msg priority class ' ..
             'proto src_addr src_port dst_addr dst_port ' ..
             'dir action service pkt_len iface'
}
