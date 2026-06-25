# FortiManager Device Refresh Tool

This version reads the FortiManager address and API key from `config.ini`.
It does not prompt for the FortiManager IP address and does not create a
username/password session.

## Files

- `fmg_refresh_devices.py` — the Python tool
- `config.ini.example` — safe configuration template
- `config.ini` — local configuration containing the API key; ignored by Git
- `.gitignore` — prevents `config.ini` from being committed

## Setup

Install the dependency:

```powershell
py -m pip install requests
```

Copy the configuration template:

```powershell
Copy-Item config.ini.example config.ini
```

Edit `config.ini`:

```ini
[fortimanager]
host = 10.128.210.118
api_key = YOUR_FORTIMANAGER_API_KEY
verify_ssl = false
timeout = 30
poll_interval = 2
max_polls = 150
```

`verify_ssl = false` is needed when FortiManager uses a self-signed
certificate. Use `verify_ssl = true` when the certificate is trusted.

Run:

```powershell
py fmg_refresh_devices.py
```

Use a different configuration file:

```powershell
py fmg_refresh_devices.py --config C:\secure\fmg-config.ini
```

Optionally skip interactive ADOM selection:

```powershell
py fmg_refresh_devices.py --adom root
```

## Device selection

- `1` — one device
- `1,3,7` — multiple devices
- `2-5` — a range
- `1,4-6,9` — combined selection
- `all` — all listed devices
