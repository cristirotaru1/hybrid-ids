# EVE-NG topology export

`NIDS.unl` is the sanitized EVE-NG lab definition used by this project. It contains five QEMU nodes, their links, resource allocations, and EVE image-folder references. It does not contain EVE-NG itself or any node disk image.

The export contains no embedded startup configurations. Guest IP addresses and operating-system settings must therefore be configured using `nodes.csv` and the reconstruction guide.

## Included topology

| EVE node | Image folder | vCPU | RAM | EVE links |
| --- | --- | ---: | ---: | --- |
| Kali | `linux-kali` | 1 | 1024 MB | `e0` to OVS, `e1` to `pnet0` |
| Debian | `linux-debian` | 1 | 512 MB | `e0` to OVS, `e1` to `pnet0` |
| IDS-Snort | `linux-debian12` | 2 | 8192 MB | `e0` to OVS mirror port, `e1` to `pnet0` |
| Floodlight | `linux-debian12` | 1 | 2048 MB | `e0` to `pnet0`, `e1` to OVS |
| OVS-Switch | `linux-debian12` | 2 | 512 MB | Floodlight, Kali, Debian, and IDS-facing ports |

The two visible `pnet0` network objects refer to the EVE management/external network. The four bridge objects provide the point-to-point links through the OVS VM.

## Importing the raw lab file

Copy `NIDS.unl` into an appropriate directory below `/opt/unetlab/labs/` on the evaluator's EVE-NG host, then repair EVE permissions:

```bash
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions
```

Alternatively, place the file into an EVE-compatible ZIP archive and use the web interface's Import action.

## Sanitization result

The committed file was checked as XML and reviewed for embedded passwords, private keys, API-token terms, SNMP community strings, email addresses, and public IP addresses. None were found. The author metadata, internal UUIDs, and laboratory MAC addresses are retained because they are not authentication secrets.

## Export checklist

1. Shut down or stop all lab nodes so the topology has a consistent state.
2. Export the lab from the EVE-NG web interface, including node startup configurations when available.
3. Name the export descriptively, for example `hybrid-ids-lab.unl` or `hybrid-ids-lab.zip`.
4. Inspect the export as text/archive content before committing it.
5. Remove passwords, password hashes, SSH private keys, API tokens, SNMP communities, personal email addresses, and unrelated command history.
6. Ensure the node template/image names agree with `images.csv`.
7. Verify the interface order and addressing against `nodes.csv`.
8. Import the sanitized export into a clean EVE-NG installation and perform the checks in `../docs/reproduction.md`.

The repository `.gitignore` rejects common VM disk and installation-media formats as an additional guardrail.
