# EVE-NG topology export

Place the sanitized EVE-NG lab export in this directory before publishing the final reconstruction package. Commit only the topology definition and startup configurations—not EVE-NG itself or any node disk image.

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
