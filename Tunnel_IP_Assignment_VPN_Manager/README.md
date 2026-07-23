FortiManager VPN Tunnel IP Allocator
====================================

Files
-----
fmg_vpn_tunnel_ip.py
fmg_vpn_tunnel_ip.ini.example
fmg_vpn_tunnel_ip_gateway_map.json.example

Requirements
------------
Python 3.10 or later
requests module:

    py -m pip install requests

Configuration
-------------
Copy fmg_vpn_tunnel_ip.ini.example to config.ini and update the FMG host and API token.
The API administrator requires read access to Device Manager and VPN Manager, and write access to device configuration for --apply.

Dry run
-------

    py fmg_vpn_tunnel_ip.py

Non-interactive selection with plan export:

    py fmg_vpn_tunnel_ip.py --adom root --community MESH --pool 10.240.0.0/24 --export

Apply to the FMG Device Database only:

    py fmg_vpn_tunnel_ip.py --adom root --community MESH --pool 10.240.0.0/24 --apply

The script does not install configuration to FortiGate devices.

Tunnel matching
---------------
The default Phase 1 regex is:

    ^<community-name>_[0-9]+$

Override it where required:

    py fmg_vpn_tunnel_ip.py --tunnel-regex "^MY-MESH_[0-9]+$"

DHCP, PPPoE, or NAT gateways
----------------------------
Use a gateway-map JSON file when the local external address cannot be read from Phase 1 local-gw or the outgoing interface.
Supported keys, from most specific to least specific:

    DEVICE|VDOM|PHASE1
    DEVICE|VDOM|OUTGOING_INTERFACE
    DEVICE|VDOM
    DEVICE

Example:

    py fmg_vpn_tunnel_ip.py --gateway-map gateway_map.json

Rollback
--------
Every --apply run creates rollback.json.
To restore the previous values in the FMG Device Database:

    py fmg_vpn_tunnel_ip.py --rollback <output-directory>/rollback.json

The rollback CLI file uses exact unset commands where the original value was absent.
