# FortiManager VPN Manager Tunnel IP Assignment Tool

**Python:** 3.10 or later  
**Dependency:** `requests`

## Overview

This tool assigns numbered IP addresses to route-based IPsec tunnel interfaces created by a FortiManager VPN Manager community.

The tool:

1. Connects to FortiManager with an API token.
2. Lists FortiGate-compatible ADOMs.
3. Lists managed devices and Device Manager groups.
4. Lists VPN Manager communities.
5. Resolves the selected community's device/VDOM members.
6. Finds Phase 1 interfaces matching the community tunnel naming pattern.
7. Correlates tunnel endpoints using reciprocal underlay gateway information.
8. Allocates one `/30` network per confirmed tunnel pair.
9. Assigns a local `/32` address and the peer address as `remote-ip /30`.
10. Shows a dry-run plan.
11. With `--apply`, updates the FortiManager Device Database.
12. Creates an API rollback file before making changes.

The tool **does not install configuration to FortiGate devices**. Installation must be reviewed and performed separately from FortiManager.

---

## Addressing model

Each confirmed tunnel pair receives one `/30` allocation.

Example:

```text
Allocated subnet: 10.240.0.0/30
Endpoint A:       10.240.0.1
Endpoint B:       10.240.0.2
```

Endpoint A receives:

```text
ip        = 10.240.0.1/32
remote-ip = 10.240.0.2/32
```

Endpoint B receives:

```text
ip        = 10.240.0.2/32
remote-ip = 10.240.0.1/32
```

The next tunnel pair receives the next available `/30`, such as `10.240.0.4/30`.

---

## Important safety behavior

- The default mode is **dry run**.
- No change is made unless `--apply` is supplied.
- The script asks for the exact confirmation word `APPLY` unless `--yes` is used.
- Existing partial or conflicting tunnel addressing blocks apply by default.
- `--overwrite-existing` is available but should be used only after reviewing existing values.
- Unresolved tunnel endpoints block apply unless `--allow-unresolved` is explicitly supplied.
- The tool updates only `ip` and `remote-ip` on the matched tunnel interfaces.
- The tool does not use ADOM workspace lock, commit, or unlock API calls.
- A `rollback.json` file is saved before interface updates begin.
- Rollback revalidates the device, VDOM, interface type, and currently assigned values before restoring anything.

---

## Requirements

### Software

- Python 3.10 or later
- Python package: `requests`
- Network access from the workstation to FortiManager HTTPS

Install the dependency:

```powershell
py -m pip install requests
```

Verify Python:

```powershell
py --version
```

### FortiManager API administrator

Use a FortiManager REST API administrator with access to:

- System status, when available
- ADOM inventory
- Device Manager devices and groups
- VPN Manager communities and nodes
- Managed-device Phase 1 interface configuration
- Managed-device `system/interface` configuration
- Write access to managed-device configuration when using `--apply` or `--rollback`

Use a dedicated API administrator and protect its token.

---

## Files

Minimum files:

```text
fmg_vpn_tunnel_ip_final.py
config.ini
```

Optional files:

```text
gateway_map.json
```

Generated output directory example:

```text
fmg_vpn_tunnel_ip_Test_Com_20260722_164852\
```

Depending on the operation, it may contain:

```text
plan.json
plan.csv
unresolved.csv
rollback.json
ROLLBACK_INSTRUCTIONS.txt
```

A combined FortiGate CLI rollback file is intentionally not generated. The supported rollback method is `rollback.json` through the FortiManager API.

---

## Configuration

Create `config.ini` in the same folder as the script:

```ini
[fortimanager]
host = https://192.0.2.10
api_key = REPLACE_WITH_FMG_API_TOKEN
verify_ssl = false
timeout = 30
```

The script automatically checks these filenames:

```text
config.ini
fmg_vpn_tunnel_ip.ini
```

A different file can be specified with:

```powershell
py fmg_vpn_tunnel_ip_final.py --config customer_fmg.ini
```

### TLS verification

Use:

```ini
verify_ssl = true
```

when FortiManager uses a certificate trusted by the workstation.

For a lab with a self-signed certificate:

```ini
verify_ssl = false
```

The command-line alternative is:

```powershell
--no-verify-ssl
```

---

## Quick start

### Interactive dry run

```powershell
py fmg_vpn_tunnel_ip_final.py
```

The script asks you to select:

1. ADOM
2. VPN Manager community
3. Tunnel IP pool

A dry run ends with:

```text
[DRY RUN] No FortiManager configuration was changed.
```

### Non-interactive dry run

```powershell
py fmg_vpn_tunnel_ip_final.py ^
  --adom root ^
  --community "ABC" ^
  --pool 10.240.0.0/24
```

### Dry run with exported files

```powershell
py fmg_vpn_tunnel_ip_final_.py ^
  --adom root ^
  --community "ABC" ^
  --pool 10.240.0.0/24 ^
  --export
```

### Apply to the FortiManager Device Database

```powershell
py fmg_vpn_tunnel_ip_final.py ^
  --adom root ^
  --community "ABC" ^
  --pool 10.240.0.0/24 ^
  --apply
```

At the confirmation prompt, type:

```text
APPLY
```

The script updates only the FortiManager Device Database. It does not install to FortiGate devices.

### Apply with API debugging

```powershell
py fmg_vpn_tunnel_ip_final.py ^
  --adom root ^
  --community "ABC" ^
  --pool 10.240.0.0/24 ^
  --apply ^
  --debug
```

`--debug` prints JSON API requests and responses. Debug output may contain environment details, so store or share it carefully.

---

## ADOM filtering

Version 7 retrieves `/dvmdb/adom` with `verbose: 1` and filters ADOMs by the FortiGate-compatible `restricted_prds` product code.

Supported product codes are:

```text
fos
foc
ffw
fwc
fpx
```

`rootp` is excluded.

---

## Tunnel discovery and pairing

The default Phase 1 name pattern is:

```text
^<community-name>_[0-9]+$
```

For community `Test_Com`, the default pattern becomes:

```text
^Test_Com_[0-9]+$
```

The numeric suffix is not used to identify the peer. Tunnel endpoints are paired by reciprocal underlay information:

```text
A.remote-gw == B.local-gateway
B.remote-gw == A.local-gateway
```

The script reads the complete managed-device `system/interface` table with:

```json
{
  "url": "/pm/config/device/<device>/global/system/interface",
  "verbose": 1
}
```

It then selects the interface by name and VDOM locally. This same table-read method is used for discovery, pre-apply validation, read-back verification, and rollback validation.

---

## Custom tunnel naming pattern

Use `--tunnel-regex` when tunnel names do not follow `<community>_<number>`.

Example:

```powershell
py fmg_vpn_tunnel_ip_final_v7.py ^
  --adom root ^
  --community "MESH" ^
  --tunnel-regex "^MESH-VPN-[0-9]+$" ^
  --pool 10.240.0.0/24 ^
  --export
```

The expression must be a valid Python regular expression.

---

## Gateway override file

A gateway override is normally unnecessary. Use it only when the local public VPN gateway cannot be derived reliably from Phase 1 `local-gw` or the outgoing-interface address.

Typical cases:

- FortiGate behind NAT
- DHCP or PPPoE WAN
- Private outgoing-interface address with a public translated address
- Ambiguous local gateway information

Create `gateway_map.json`:

```json
{
  "FGT-A|root|Test_Com_1": "203.0.113.10",
  "FGT-B|root|wan1": "198.51.100.20",
  "FGT-C|root": "192.0.2.30",
  "FGT-D": "192.0.2.40"
}
```

The lookup order is:

```text
DEVICE|VDOM|PHASE1
DEVICE|VDOM|OUTGOING_INTERFACE
DEVICE|VDOM
DEVICE
```

Run with:

```powershell
py fmg_vpn_tunnel_ip_final.py ^
  --adom root ^
  --community "ABC" ^
  --pool 10.240.0.0/24 ^
  --gateway-map gateway_map.json ^
  --export
```

---

## Pair status meanings

### `eligible`

Neither endpoint has tunnel-interface addressing that conflicts with the plan. The pair can receive a new `/30`.

### `configured`

Both endpoints already have a complete, internally consistent tunnel-interface IP configuration. The pair is skipped.

### `partial`

Only part of the expected configuration exists. Examples:

```text
Endpoint A ip is set, but remote-ip is unset.
Endpoint A is configured, but Endpoint B is unset.
```

Apply stops by default.

### `conflict`

Both endpoints contain addressing, but the values are not a valid reciprocal pair or do not belong to the same `/30` allocation. Apply stops by default.

### Overwriting existing values

After reviewing the existing configuration, use:

```powershell
--overwrite-existing
```

Example:

```powershell
py fmg_vpn_tunnel_ip_final.py ^
  --adom root ^
  --community "ABC" ^
  --pool 10.240.0.0/24 ^
  --overwrite-existing ^
  --apply
```

This is intentionally marked dangerous because it replaces partial or conflicting existing values.

---

## Unresolved endpoints

An endpoint may be unresolved when:

- `remote-gw` is missing
- The tunnel is dynamic or dial-up
- The peer uses DDNS rather than a resolvable IPv4 gateway
- Multiple members match the same gateway
- Reciprocal matching fails
- The corresponding tunnel interface cannot be found
- NAT hides the correct public endpoint and no gateway override is supplied

By default, unresolved endpoints block `--apply`.

To apply only confirmed pairs while leaving unrelated unresolved endpoints untouched:

```powershell
--allow-unresolved
```

Review `unresolved.csv` before using this option.

---

## Pool validation and overlap handling

The supplied pool must be an IPv4 network broad enough to contain the required number of `/30` allocations.

Examples:

```text
/24 = 64 /30 networks
/20 = 1,024 /30 networks
/19 = 2,048 /30 networks
/16 = 16,384 /30 networks
```

The script compares candidate `/30` networks with interface networks discovered from managed devices. Overlapping `/30` networks are skipped before allocation.

Example output:

```text
Required /30 networks: 3
Overlapping /30 networks skipped before completing allocation: 0
```

FortiManager cannot prove that a range is unused in an external system or network that is not represented in its Device Database. The operator must reserve and validate the pool before use.

---

## Exported plan files

Use `--export` to generate plan files during a dry run.

### `plan.json`

Structured plan containing the selected ADOM, community, regex, pool, pair status, and allocations.

### `plan.csv`

One row per planned tunnel interface, including:

```text
pair_id
subnet
device
vdom
interface
local_ip
remote_ip
```

### `unresolved.csv`

Endpoints that could not be safely correlated, with the reason for each unresolved result.

### Custom output directory

```powershell
py fmg_vpn_tunnel_ip_final.py ^
  --adom root ^
  --community "ABC" ^
  --pool 10.240.0.0/24 ^
  --export ^
  --export-dir C:\FMG-Plans\ABC
```

When `--apply` is used, an output directory is created even without `--export` because rollback data must be saved.

---

## Rollback

Before apply, the script saves:

```text
rollback.json
ROLLBACK_INSTRUCTIONS.txt
```

The rollback file records:

```text
Device
VDOM
Interface
Old ip
Old remote-ip
New ip
New remote-ip
```

Run rollback:

```powershell
py fmg_vpn_tunnel_ip_final.py ^
  --rollback "fmg_vpn_tunnel_ip_ABC_20260722_164852\rollback.json"
```

Type:

```text
ROLLBACK
```

Rollback performs these checks before restoring values:

1. The correct managed device exists.
2. The expected interface exists in the expected VDOM.
3. The object is still a tunnel interface.
4. The current `ip` and `remote-ip` still match the values written by the saved plan.

It then restores the previous values and performs read-back verification.

Rollback changes only the FortiManager Device Database. If the original changes were installed to FortiGate devices, install the restored Device Database configuration from FortiManager afterward.

---

## Post-apply workflow

After a successful apply:

1. Open FortiManager Device Manager.
2. Review the modified devices.
3. Run an installation preview.
4. Confirm that only the expected tunnel-interface `ip` and `remote-ip` changes appear.
5. Install to a small test set or one tunnel pair first.
6. Verify routing and tunnel reachability.
7. Continue with the remaining devices.

Example FortiGate verification:

```cli
show system interface ABC_1
```

Expected fields resemble:

```cli
set ip 10.240.0.2 255.255.255.255
set remote-ip 10.240.0.1 255.255.255.252
```

---

## Common commands

### Show command-line help

```powershell
py fmg_vpn_tunnel_ip_final.py --help
```

### Interactive dry run

```powershell
py fmg_vpn_tunnel_ip_final.py
```

### Fully specified dry run

```powershell
py fmg_vpn_tunnel_ip_final.py --adom root --community "ABC" --pool 10.240.0.0/24
```

### Export plan

```powershell
py fmg_vpn_tunnel_ip_final.py --adom root --community "ABC" --pool 10.240.0.0/24 --export
```

### Apply

```powershell
py fmg_vpn_tunnel_ip_final.py --adom root --community "ABC" --pool 10.240.0.0/24 --apply
```

### Apply without confirmation prompt

```powershell
py fmg_vpn_tunnel_ip_final.py --adom root --community "ABC" --pool 10.240.0.0/24 --apply --yes
```

Use `--yes` only in a controlled workflow after reviewing an equivalent dry run.

### Rollback

```powershell
py fmg_vpn_tunnel_ip_final.py --rollback ".\output_folder\rollback.json"
```

### Debug

```powershell
py fmg_vpn_tunnel_ip_final.py --adom root --community "ABC" --pool 10.240.0.0/24 --debug
```

---

## Command-line options

| Option | Purpose |
|---|---|
| `--config FILE` | Use a specific INI configuration file. |
| `--host HOST` | Override the FortiManager URL or IP. |
| `--api-key TOKEN` | Supply the API token on the command line. Prefer `config.ini` or the secure prompt. |
| `--no-verify-ssl` | Disable TLS certificate verification. |
| `--timeout SECONDS` | Set the HTTPS timeout. |
| `--adom NAME` | Preselect an ADOM. |
| `--community NAME` | Preselect a VPN Manager community. |
| `--tunnel-regex REGEX` | Override the default Phase 1 naming regex. |
| `--gateway-map FILE` | Load public/local gateway overrides from JSON. |
| `--pool CIDR` | Supply the IPv4 pool to divide into `/30` allocations. |
| `--apply` | Update the FortiManager Device Database. |
| `--overwrite-existing` | Replace partial or conflicting existing addressing. Use carefully. |
| `--yes` | Skip the `APPLY` or `ROLLBACK` confirmation prompt. |
| `--export-dir DIRECTORY` | Select the output directory. |
| `--export` | Export dry-run plan files. |
| `--batch-size NUMBER` | Maximum interface updates per API request. Valid range: 1–500. |
| `--workspace auto|on|off` | Deprecated compatibility option; ignored for device-level changes. |
| `--rollback FILE` | Restore values from `rollback.json`. |
| `--allow-unresolved` | Apply confirmed pairs even when unrelated endpoints remain unresolved. |
| `--debug` | Print API requests and responses. |

---

## Troubleshooting

### `Partial or conflicting tunnel addressing exists`

At least one matched pair already contains incomplete or inconsistent `ip`/`remote-ip` values.

Actions:

1. Review the listed interfaces in the FMG Device Database.
2. Use the previous run's `rollback.json` when the values came from this tool.
3. Remove unwanted test values manually in FMG.
4. Use `--overwrite-existing` only after confirming replacement is safe.

### `Unable to retrieve interface DEVICE/VDOM/INTERFACE`

The full `system/interface` table did not contain the expected name and VDOM.

Check:

- Device name
- VDOM
- Tunnel interface name
- Whether the interface was deleted or renamed after discovery
- API administrator permissions
- `--debug` response from the table GET

### `Unresolved endpoints exist`

The script could not establish a safe reciprocal peer match.

Check:

- Phase 1 `remote-gw`
- Phase 1 `local-gw`
- Outgoing-interface address
- NAT/public address
- Gateway override file
- Dynamic or DDNS peer type

### `Invalid IPv4 pool`

Supply a valid network in CIDR form:

```text
10.240.0.0/24
```

Do not submit a blank value.

### ADOM list includes unrelated products

Use v7 or later. V7 retrieves ADOMs with `verbose: 1` and filters by `restricted_prds`.

### Certificate warning

Use a trusted FortiManager certificate and `verify_ssl = true` for production. `verify_ssl = false` or `--no-verify-ssl` should be limited to controlled environments.

---

## Current scope and limitations

The tool is intended for:

- FortiManager 7.6.x JSON API
- Static IPv4 route-based IPsec tunnels
- VPN Manager communities with resolvable device/VDOM members
- Tunnel interfaces represented in the FMG Device Database

The following may require manual handling or gateway overrides:

- Dynamic or dial-up peers
- DDNS peers
- Ambiguous NAT
- Multiple members sharing a public IP
- Unsupported or unusual VPN Manager node structures
- Tunnel naming that does not match the default pattern

The script does not:

- Create VPN Manager communities
- Create Phase 1 or Phase 2 objects
- Add static routes or dynamic-routing neighbors
- Install configurations to FortiGate devices
- Validate address use in external IPAM systems
- Lock the ADOM workspace

---

## Security recommendations

- Store the API token in `config.ini` rather than command history.
- Restrict filesystem permissions on `config.ini` and generated rollback files.
- Use a dedicated API administrator with only the required permissions.
- Enable TLS certificate verification in production.
- Review dry-run output before every apply.
- Protect debug logs because they may expose device names, IP addresses, configuration details, and API responses.
- Preserve `rollback.json` until the change is installed and verified.
