############################################
# Created by Farhan Ahmed - www.farhan.ch  #
############################################

import json
from pathlib import Path

import requests


def main():
    config_path = Path(__file__).resolve().parent / "config.json"
    with config_path.open(encoding="utf-8") as file:
        config = json.load(file)

    payload = {
        "id": 1,
        "method": "get",
        "params": [
            {
                "url": (
                    f"/pm/config/adom/{config['adom']}"
                    "/_controller/status/fsw"
                ),
                "scope member": [{"name": "All_FortiGate"}]
            }
        ]
    }

    response = requests.post(
        config["fmg_url"],
        headers={"Authorization": f"Bearer {config['api_key']}"},
        json=payload,
        timeout=60,
        verify=config.get("verify_ssl", True)
    )
    response.raise_for_status()
    body = response.json()

    if body.get("error"):
        raise RuntimeError(f"API error: {body['error']}")

    if "result" not in body:
        raise RuntimeError("Unexpected API response: missing 'result'")

    all_switches = []

    for result in body["result"]:
        status = result.get("status", {})
        if status.get("code", 0) != 0:
            raise RuntimeError(f"FortiManager API error: {status}")

        all_switches.extend(result.get("data", []))

    fortigates = sorted({
        switch["dev"]
        for switch in all_switches
        if switch.get("dev")
    })

    if not fortigates:
        print("No FortiGates found in the switch-status response.")
        return

    print("\nAvailable FortiGates:")
    for number, name in enumerate(fortigates, start=1):
        count = sum(s.get("dev") == name for s in all_switches)
        print(f"  {number}. {name} ({count} switches)")

    while True:
        choice = input("\nSelect FortiGate number (q to quit): ").strip()

        if choice.lower() == "q":
            return

        try:
            index = int(choice) - 1
            if 0 <= index < len(fortigates):
                selected = fortigates[index]
                break
        except ValueError:
            pass

        print(f"Enter a number from 1 to {len(fortigates)}, or q.")

    switches = [
        switch
        for switch in all_switches
        if switch.get("dev") == selected
    ]

    print(f"\nSwitches for {selected}:")
    print(json.dumps(switches, indent=4))


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
    except (OSError, ValueError, KeyError, RuntimeError,
            requests.RequestException) as error:
        print(f"Error: {error}")
