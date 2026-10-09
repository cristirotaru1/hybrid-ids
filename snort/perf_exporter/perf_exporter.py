import csv
import time
import os
from prometheus_client import start_http_server, Gauge

CSV_PATH = "/var/log/snort/perf_monitor_base.csv"

FIELDS = [
    "daq.received", "daq.analyzed", "daq.dropped",
    "daq.filtered", "daq.outstanding", "daq.rx_bytes",
]

gauges = {
    f: Gauge(
        "snort_" + f.replace(".", "_"),
        f"Snort perf_monitor field {f}"
    )
    for f in FIELDS
}

def read_latest_row():
    if not os.path.exists(CSV_PATH):
        return
    with open(CSV_PATH, "r") as fh:
        reader = csv.DictReader(fh)  # Uses the commented CSV header.
        last = None
        for row in reader:
            last = row
    if last:
        for f in FIELDS:
            try:
                gauges[f].set(float(last[f]))
            except (KeyError, ValueError):
                pass

if __name__ == "__main__":
    start_http_server(9101)
    while True:
        read_latest_row()
        time.sleep(15)
