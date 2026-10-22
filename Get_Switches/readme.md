# FortiManager FortiSwitch Lookup

Sample Python script (`get_switches.py`) to retrieve FortiSwitch data from a FortiManager ADOM and filter the results for a selected FortiGate.

## Purpose and background

The default FortiManager API endpoint for retrieving FortiSwitches is:

```text
/pm/config/adom/{ADOM}/obj/fsp/managed-switch
```

Replace `{ADOM}` with the target ADOM name. In the reported issue, a bug causes the switch `status` returned by this endpoint to show incorrect information.

An alternate approach uses the following controller status endpoint:

```text
/pm/config/adom/{ADOM}/_controller/status/fsw
```

However, the following behavior has been observed in the affected production environment:

- Setting the scope member `name` to a specific FortiGate sometimes returns no results.
- Using an API-side `filter` on either `sn` or `dev` can also return no results.
- Using `"name": "All_FortiGate"` successfully returns switch data for the ADOM.

Specific-FortiGate queries and API-side filtering worked in a separate FortiManager v7.6.7 lab, but did not behave consistently in the affected production environment.

The workaround is to retrieve all FortiSwitch records, prompt the user to select a FortiGate, and display only the records whose `dev` field matches that FortiGate. Filtering is performed locally in Python.

## How it works

1. Connects to FortiManager using an API key stored in a configuration file.
2. Retrieves switch data for all FortiGates in the configured ADOM using `"name": "All_FortiGate"`.
3. Presents the FortiGate selection prompt.
4. Uses the `dev` field to filter the retrieved records for the selected FortiGate.
5. Shows only the switches associated with that FortiGate.

The FortiGate is selected interactively; it does not need to be specified in the configuration file.

## Requirements

- Python 3.
- The Python `requests` package.
- HTTPS connectivity from the computer running the script to FortiManager.
- A valid FortiManager API key with permissions to read the relevant ADOM and device information.
- The script and its matching configuration file.

## Setup

Install the dependency on Windows:

```powershell
py -m pip install requests
```

On Linux or macOS:

```bash
python3 -m pip install requests
```

Update the configuration file used by your copy of the script with the FortiManager address, API key, and target ADOM. Preserve the configuration filename, format, and field names expected by the script.

Keep the API key private. Do not include the populated configuration file in public repositories or share it with the README.

> This README is based on the described script workflow. The script source and configuration schema were not available for verification, so exact configuration keys, selection syntax, and output formatting are not specified here.

## Usage

Open a terminal in the directory containing the script and its configuration file.

Windows:

```powershell
py get_switches.py
```

Linux or macOS:

```bash
python3 get_switches.py
```

Follow the on-screen prompt to select a FortiGate from the returned list. The script filters the switch records for that FortiGate using the `dev` field.

## Alternate switch API request

The switch query uses the following endpoint, with `root` replaced by the target ADOM as appropriate:

```text
/pm/config/adom/root/_controller/status/fsw
```

Example JSON-RPC request body:

```json
{
  "id": 1,
  "method": "get",
  "params": [
    {
      "url": "/pm/config/adom/root/_controller/status/fsw",
      "scope member": [
        {
          "name": "All_FortiGate"
        }
      ]
    }
  ]
}
```

The script performs the FortiGate-specific filtering locally after receiving the response. The request above does not include authentication details.

## Troubleshooting

| Symptom | Suggested check |
| --- | --- |
| `No module named 'requests'` | Install `requests` using the same Python interpreter used to run the script. |
| Configuration file cannot be found | Check the filename and location expected by the script, and run it from its directory. |
| `CERTIFICATE_VERIFY_FAILED` | Ensure FortiManager presents a certificate trusted by the Python client and that the address matches the certificate. For a private CA, configure the client to trust the appropriate CA certificate. |
| Authentication or permission error | Verify the API key, its permissions, and access to the target ADOM. |
| Connection timeout or connection refused | Verify the FortiManager address, HTTPS port, routing, and intervening firewall rules. |
| No FortiGates listed | Confirm the ADOM name and API account access. |
| No switches returned for the selected FortiGate | Check the unfiltered response and confirm how the selected FortiGate is represented in the `dev` field. |

## Limitations and support scope

- The alternate `_controller/status/fsw` API endpoint is undocumented; its availability, response fields, and behavior may vary between FortiManager versions.
- This is a workaround for retrieving and filtering data. It does not resolve the underlying API behavior or correct status discrepancies in the returned data.
- Successful behavior in the v7.6.7 lab does not establish that a fix is available for every environment. Confirm the applicable fixed release separately.
- Developing, modifying, and maintaining custom scripts is outside the scope of Fortinet TAC support. This sample is provided as a reference example to demonstrate the workaround.
- Review and test the script in your environment before use.
