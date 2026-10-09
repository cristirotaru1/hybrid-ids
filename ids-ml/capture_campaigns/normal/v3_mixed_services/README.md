# Normal mixed-services campaign V3

This campaign contains normal mixed TCP, UDP, and ICMP traffic for model fitting
and threshold calibration. Some captures also use multiple destination services.

- `normal_v3_fit_001_mixed_low_rate.pcap`: low-rate mixed fitting traffic.
- `normal_v3_fit_002_mixed_grouped.pcap`: fitting traffic arranged in groups.
- `normal_v3_fit_003_mixed_bounded_burst.pcap`: bounded mixed fitting burst.
- `normal_v3_fit_004_mixed_multi_service.pcap`: failed multi-service attempt.
- `normal_v3_fit_004_retry1_mixed_multi_service.pcap`: accepted multi-service retry.
- `normal_v3_fit_005_mixed_operational_variation.pcap`: mixed traffic with isolated TCP refusals.
- `normal_v3_cal_001_mixed_low_moderate.pcap`: empty failed calibration attempt.
- `normal_v3_cal_001_retry1_mixed_low_moderate.pcap`: accepted low/moderate calibration retry.
- `normal_v3_cal_002_mixed_grouped.pcap`: grouped calibration traffic.
- `normal_v3_cal_003_mixed_multi_service.pcap`: multi-service calibration traffic.
- `normal_v3_cal_004_mixed_operational_variation.pcap`: calibration traffic with isolated TCP refusals.
