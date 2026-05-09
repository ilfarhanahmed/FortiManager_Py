#!/usr/bin/env python3
"""
FortiManager ADOM Object Extractor & Restorer

Connects to a FortiManager via JSON-RPC API and lets you:
  - Extract all ADOM-level objects to JSON/CSV files
  - Restore objects from a previously extracted file into any target ADOM

Supports FMG 7.6.6, 288 object types (ADOM + Controller Config).

Usage:
    python3 fmg_adom_extractor.py
    python3 fmg_adom_extractor.py --adom root            # pre-select ADOM
    python3 fmg_adom_extractor.py --category firewall    # extract one category
    python3 fmg_adom_extractor.py --out backup.json      # custom output path
    python3 fmg_adom_extractor.py --list-categories      # show all categories
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import ssl
from datetime import datetime, timezone

# Terminal colour helpers — disabled automatically on Windows or non-TTY output
USE_COLOUR = sys.stdout.isatty() and os.name != "nt"

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOUR else text

def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def red(t):    return _c("31", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)


# ── ADOM-level root table definitions (228 entries from FMG 7.6.6 docs) ────────
#
# Base URL pattern for every entry:
#   /pm/config/adom/{adom}/obj/<path>
#
# Sections mirror the top-level namespace under /obj/:
#   antivirus · application · authentication · casb · certificate · cli
#   cloud · diameter-filter · dlp · dnsfilter · dynamic · emailfilter
#   endpoint-control · extender-controller · extension-controller
#   file-filter · firewall · fmg · global · gtp · icap · ips · log
#   router · sctp-filter · ssh-filter · switch-controller · system
#   telemetry-controller · ums · user · videofilter · virtual-patch
#   voip · vpn · vpnmgr · waf · wanopt · web-proxy · webfilter · ztna
#
ADOM_TABLES = [

    # ──────────────────────────────────────────────────────────────────────────
    # ANTIVIRUS  —  /pm/config/adom/{adom}/obj/antivirus/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "antivirus/profile",                          "url": "/pm/config/adom/{adom}/obj/antivirus/profile",                          "description": "Configure AntiVirus profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # APPLICATION CONTROL  —  /pm/config/adom/{adom}/obj/application/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "application/categories",                     "url": "/pm/config/adom/{adom}/obj/application/categories",                     "description": "Built-in application categories."},
    {"name": "application/custom",                         "url": "/pm/config/adom/{adom}/obj/application/custom",                         "description": "Configure custom application signatures."},
    {"name": "application/group",                          "url": "/pm/config/adom/{adom}/obj/application/group",                          "description": "Configure firewall application groups."},
    {"name": "application/list",                           "url": "/pm/config/adom/{adom}/obj/application/list",                           "description": "Configure application control lists."},

    # ──────────────────────────────────────────────────────────────────────────
    # AUTHENTICATION  —  /pm/config/adom/{adom}/obj/authentication/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "authentication/scheme",                      "url": "/pm/config/adom/{adom}/obj/authentication/scheme",                      "description": "Configure Authentication Schemes."},

    # ──────────────────────────────────────────────────────────────────────────
    # CASB (Cloud Access Security Broker)  —  /pm/config/adom/{adom}/obj/casb/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "casb/profile",                               "url": "/pm/config/adom/{adom}/obj/casb/profile",                               "description": "Configure CASB profile."},
    {"name": "casb/saas-application",                      "url": "/pm/config/adom/{adom}/obj/casb/saas-application",                      "description": "Configure CASB SaaS application."},
    {"name": "casb/user-activity",                         "url": "/pm/config/adom/{adom}/obj/casb/user-activity",                         "description": "Configure CASB user activity."},

    # ──────────────────────────────────────────────────────────────────────────
    # CERTIFICATE  —  /pm/config/adom/{adom}/obj/certificate/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "certificate/template",                       "url": "/pm/config/adom/{adom}/obj/certificate/template",                       "description": "Configure certificate templates."},

    # ──────────────────────────────────────────────────────────────────────────
    # CLI TEMPLATES  —  /pm/config/adom/{adom}/obj/cli/
    # Used to push arbitrary CLI commands to managed devices via FMG.
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "cli/template",                               "url": "/pm/config/adom/{adom}/obj/cli/template",                               "description": "CLI template — requires device/vdom scope member for assignment."},
    {"name": "cli/template-group",                         "url": "/pm/config/adom/{adom}/obj/cli/template-group",                         "description": "CLI template group — requires device/vdom scope member for assignment."},

    # ──────────────────────────────────────────────────────────────────────────
    # CLOUD ORCHESTRATION (AWS)  —  /pm/config/adom/{adom}/obj/cloud/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "cloud/orchest-aws",                          "url": "/pm/config/adom/{adom}/obj/cloud/orchest-aws",                          "description": "AWS cloud orchestration settings."},
    {"name": "cloud/orchest-awsconnector",                 "url": "/pm/config/adom/{adom}/obj/cloud/orchest-awsconnector",                 "description": "AWS connector settings for cloud orchestration."},
    {"name": "cloud/orchest-awstemplate/autoscale-existing-vpc", "url": "/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-existing-vpc", "description": "AWS auto-scale template — existing VPC."},
    {"name": "cloud/orchest-awstemplate/autoscale-new-vpc",      "url": "/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-new-vpc",      "description": "AWS auto-scale template — new VPC."},
    {"name": "cloud/orchest-awstemplate/autoscale-tgw-new-vpc",  "url": "/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-tgw-new-vpc",  "description": "AWS auto-scale template — Transit Gateway, new VPC."},
    {"name": "cloud/orchestration",                        "url": "/pm/config/adom/{adom}/obj/cloud/orchestration",                        "description": "Generic cloud orchestration settings."},

    # ──────────────────────────────────────────────────────────────────────────
    # DIAMETER FILTER  —  /pm/config/adom/{adom}/obj/diameter-filter/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "diameter-filter/profile",                    "url": "/pm/config/adom/{adom}/obj/diameter-filter/profile",                    "description": "Configure Diameter filter profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # DLP (Data Loss Prevention)  —  /pm/config/adom/{adom}/obj/dlp/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "dlp/data-type",                              "url": "/pm/config/adom/{adom}/obj/dlp/data-type",                              "description": "Configure predefined data types used by DLP blocking."},
    {"name": "dlp/dictionary",                             "url": "/pm/config/adom/{adom}/obj/dlp/dictionary",                             "description": "Configure DLP dictionaries."},
    {"name": "dlp/filepattern",                            "url": "/pm/config/adom/{adom}/obj/dlp/filepattern",                            "description": "Configure file patterns used by DLP blocking."},
    {"name": "dlp/fp-doc-source",                          "url": "/pm/config/adom/{adom}/obj/dlp/fp-doc-source",                          "description": "Create a DLP fingerprint database from a designated document source file server."},
    {"name": "dlp/profile",                                "url": "/pm/config/adom/{adom}/obj/dlp/profile",                                "description": "Configure DLP profiles."},
    {"name": "dlp/sensitivity",                            "url": "/pm/config/adom/{adom}/obj/dlp/sensitivity",                            "description": "Configure DLP sensitivity levels (used with fp-doc-source)."},
    {"name": "dlp/sensor",                                 "url": "/pm/config/adom/{adom}/obj/dlp/sensor",                                 "description": "Configure DLP sensors."},

    # ──────────────────────────────────────────────────────────────────────────
    # DNS FILTER  —  /pm/config/adom/{adom}/obj/dnsfilter/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "dnsfilter/domain-filter",                    "url": "/pm/config/adom/{adom}/obj/dnsfilter/domain-filter",                    "description": "Configure DNS domain filters."},
    {"name": "dnsfilter/profile",                          "url": "/pm/config/adom/{adom}/obj/dnsfilter/profile",                          "description": "Configure DNS domain filter profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # DYNAMIC OBJECTS  —  /pm/config/adom/{adom}/obj/dynamic/
    # Dynamic mappings let a single policy object resolve to different
    # per-device values at install time (interface, VIP, IP pool, etc.).
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "dynamic/address",                            "url": "/pm/config/adom/{adom}/obj/dynamic/address",                            "description": "Dynamic address mapping (per-device resolution)."},
    {"name": "dynamic/certificate/local",                  "url": "/pm/config/adom/{adom}/obj/dynamic/certificate/local",                  "description": "Dynamic local certificate mapping."},
    {"name": "dynamic/input-interface",                    "url": "/pm/config/adom/{adom}/obj/dynamic/input-interface",                    "description": "Dynamic input interface mapping."},
    {"name": "dynamic/interface",                          "url": "/pm/config/adom/{adom}/obj/dynamic/interface",                          "description": "Dynamic interface mapping (per-device resolution)."},
    {"name": "dynamic/ippool",                             "url": "/pm/config/adom/{adom}/obj/dynamic/ippool",                             "description": "Dynamic IP pool mapping."},
    {"name": "dynamic/multicast-interface",                "url": "/pm/config/adom/{adom}/obj/dynamic/multicast-interface",                "description": "Dynamic multicast interface mapping."},
    {"name": "dynamic/vip",                                "url": "/pm/config/adom/{adom}/obj/dynamic/vip",                                "description": "Dynamic VIP mapping."},
    {"name": "dynamic/vpntunnel",                          "url": "/pm/config/adom/{adom}/obj/dynamic/vpntunnel",                          "description": "Dynamic VPN tunnel mapping."},

    # ──────────────────────────────────────────────────────────────────────────
    # EMAIL FILTER (Anti-Spam)  —  /pm/config/adom/{adom}/obj/emailfilter/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "emailfilter/block-allow-list",               "url": "/pm/config/adom/{adom}/obj/emailfilter/block-allow-list",               "description": "Configure anti-spam block/allow list."},
    {"name": "emailfilter/bwl",                            "url": "/pm/config/adom/{adom}/obj/emailfilter/bwl",                            "description": "Configure anti-spam black/white list (legacy)."},
    {"name": "emailfilter/bword",                          "url": "/pm/config/adom/{adom}/obj/emailfilter/bword",                          "description": "Configure AntiSpam banned word list."},
    {"name": "emailfilter/dnsbl",                          "url": "/pm/config/adom/{adom}/obj/emailfilter/dnsbl",                          "description": "Configure AntiSpam DNSBL/ORBL."},
    {"name": "emailfilter/iptrust",                        "url": "/pm/config/adom/{adom}/obj/emailfilter/iptrust",                        "description": "Configure AntiSpam IP trust."},
    {"name": "emailfilter/mheader",                        "url": "/pm/config/adom/{adom}/obj/emailfilter/mheader",                        "description": "Configure AntiSpam MIME header."},
    {"name": "emailfilter/profile",                        "url": "/pm/config/adom/{adom}/obj/emailfilter/profile",                        "description": "Configure Email Filter profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # ENDPOINT CONTROL (FortiClient EMS)  —  /pm/config/adom/{adom}/obj/endpoint-control/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "endpoint-control/fctems",                    "url": "/pm/config/adom/{adom}/obj/endpoint-control/fctems",                    "description": "Configure FortiClient EMS server entries."},

    # ──────────────────────────────────────────────────────────────────────────
    # EXTENDER CONTROLLER (FortiExtender / LTE)  —  /pm/config/adom/{adom}/obj/extender-controller/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "extender-controller/dataplan",               "url": "/pm/config/adom/{adom}/obj/extender-controller/dataplan",               "description": "FortiExtender data plan configuration."},
    {"name": "extender-controller/extender-profile",       "url": "/pm/config/adom/{adom}/obj/extender-controller/extender-profile",       "description": "FortiExtender extender profile configuration."},
    {"name": "extender-controller/sim_profile",            "url": "/pm/config/adom/{adom}/obj/extender-controller/sim_profile",            "description": "FortiExtender SIM profile configuration."},

    # ──────────────────────────────────────────────────────────────────────────
    # EXTENSION CONTROLLER (FortiSwitch/FortiAP extensions)  —  /pm/config/adom/{adom}/obj/extension-controller/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "extension-controller/extender-profile",      "url": "/pm/config/adom/{adom}/obj/extension-controller/extender-profile",      "description": "FortiExtender profile (extension-controller)."},
    {"name": "extension-controller/fortigate-profile",     "url": "/pm/config/adom/{adom}/obj/extension-controller/fortigate-profile",     "description": "FortiGate extension profile."},

    # ──────────────────────────────────────────────────────────────────────────
    # FILE FILTER  —  /pm/config/adom/{adom}/obj/file-filter/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "file-filter/profile",                        "url": "/pm/config/adom/{adom}/obj/file-filter/profile",                        "description": "Configure file-filter profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # FIREWALL OBJECTS  —  /pm/config/adom/{adom}/obj/firewall/
    #
    # Sub-groups within firewall/:
    #   Access Proxy     — access-proxy, access-proxy6, access-proxy-ssh-client-cert, access-proxy-virtual-host
    #   Addresses (IPv4) — address, addrgrp
    #   Addresses (IPv6) — address6, address6-template, addrgrp6
    #   Addresses (Multicast) — multicast-address, multicast-address6
    #   Addresses (Proxy) — proxy-address, proxy-addrgrp
    #   Addresses (Wildcard FQDN) — wildcard-fqdn/custom, wildcard-fqdn/group
    #   Addresses (Region) — region
    #   Internet Service (ISDB) — internet-service-addition, internet-service-custom,
    #                             internet-service-custom-group, internet-service-group,
    #                             internet-service-name, network-service-dynamic
    #   IP Pools & NAT   — ippool, ippool6
    #   Virtual IPs      — vip, vip6, vip46, vip64, vipgrp, vipgrp6, vipgrp46, vipgrp64
    #   Services         — service/category, service/custom, service/group
    #   Schedules        — schedule/onetime, schedule/recurring, schedule/group
    #   Traffic Shaping  — shaper/traffic-shaper, shaper/per-ip-shaper, shaping-profile, traffic-class
    #   Security Profiles — profile-group, profile-protocol-options, ssl-ssh-profile, mms-profile
    #   SSH Proxy        — ssh/local-ca, ssh/local-key
    #   Load Balancing   — ldb-monitor
    #   Identity Routing — identity-based-route
    #   Carrier / GTP    — carrier-endpoint-bwl, gtp
    # ──────────────────────────────────────────────────────────────────────────

    # Access Proxy (ZTNA / SSL-VPN reverse proxy)
    {"name": "firewall/access-proxy",                      "url": "/pm/config/adom/{adom}/obj/firewall/access-proxy",                      "description": "Configure IPv4 access proxy."},
    {"name": "firewall/access-proxy6",                     "url": "/pm/config/adom/{adom}/obj/firewall/access-proxy6",                     "description": "Configure IPv6 access proxy."},
    {"name": "firewall/access-proxy-ssh-client-cert",      "url": "/pm/config/adom/{adom}/obj/firewall/access-proxy-ssh-client-cert",      "description": "Configure Access Proxy SSH client certificate."},
    {"name": "firewall/access-proxy-virtual-host",         "url": "/pm/config/adom/{adom}/obj/firewall/access-proxy-virtual-host",         "description": "Configure Access Proxy virtual hosts."},

    # Addresses — IPv4
    {"name": "firewall/address",                           "url": "/pm/config/adom/{adom}/obj/firewall/address",                           "description": "Configure IPv4 addresses."},
    {"name": "firewall/addrgrp",                           "url": "/pm/config/adom/{adom}/obj/firewall/addrgrp",                           "description": "Configure IPv4 address groups."},

    # Addresses — IPv6
    {"name": "firewall/address6",                          "url": "/pm/config/adom/{adom}/obj/firewall/address6",                          "description": "Configure IPv6 firewall addresses."},
    {"name": "firewall/address6-template",                 "url": "/pm/config/adom/{adom}/obj/firewall/address6-template",                 "description": "Configure IPv6 address templates."},
    {"name": "firewall/addrgrp6",                          "url": "/pm/config/adom/{adom}/obj/firewall/addrgrp6",                          "description": "Configure IPv6 address groups."},

    # Addresses — Multicast
    {"name": "firewall/multicast-address",                 "url": "/pm/config/adom/{adom}/obj/firewall/multicast-address",                 "description": "Configure multicast addresses."},
    {"name": "firewall/multicast-address6",                "url": "/pm/config/adom/{adom}/obj/firewall/multicast-address6",                "description": "Configure IPv6 multicast addresses."},

    # Addresses — Web Proxy
    {"name": "firewall/proxy-address",                     "url": "/pm/config/adom/{adom}/obj/firewall/proxy-address",                     "description": "Configure web proxy address."},
    {"name": "firewall/proxy-addrgrp",                     "url": "/pm/config/adom/{adom}/obj/firewall/proxy-addrgrp",                     "description": "Configure web proxy address group."},

    # Addresses — Wildcard FQDN
    {"name": "firewall/wildcard-fqdn/custom",              "url": "/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/custom",              "description": "Configure global Wildcard FQDN addresses."},
    {"name": "firewall/wildcard-fqdn/group",               "url": "/pm/config/adom/{adom}/obj/firewall/wildcard-fqdn/group",               "description": "Configure global Wildcard FQDN address groups."},

    # Addresses — Region / Geography
    {"name": "firewall/region",                            "url": "/pm/config/adom/{adom}/obj/firewall/region",                            "description": "Geographic region objects."},

    # Internet Service Database (ISDB)
    {"name": "firewall/internet-service-addition",         "url": "/pm/config/adom/{adom}/obj/firewall/internet-service-addition",         "description": "Configure Internet Services additions."},
    {"name": "firewall/internet-service-custom",           "url": "/pm/config/adom/{adom}/obj/firewall/internet-service-custom",           "description": "Configure custom Internet Services."},
    {"name": "firewall/internet-service-custom-group",     "url": "/pm/config/adom/{adom}/obj/firewall/internet-service-custom-group",     "description": "Configure custom Internet Service groups."},
    {"name": "firewall/internet-service-group",            "url": "/pm/config/adom/{adom}/obj/firewall/internet-service-group",            "description": "Configure groups of Internet Services."},
    {"name": "firewall/internet-service-name",             "url": "/pm/config/adom/{adom}/obj/firewall/internet-service-name",             "description": "Define Internet Service names."},
    {"name": "firewall/network-service-dynamic",           "url": "/pm/config/adom/{adom}/obj/firewall/network-service-dynamic",           "description": "Configure dynamic network services."},

    # IP Pools & NAT
    {"name": "firewall/ippool",                            "url": "/pm/config/adom/{adom}/obj/firewall/ippool",                            "description": "Configure IPv4 IP pools (NAT overload / fixed-port)."},
    {"name": "firewall/ippool6",                           "url": "/pm/config/adom/{adom}/obj/firewall/ippool6",                           "description": "Configure IPv6 IP pools."},

    # Virtual IPs (DNAT / Port-forwarding)
    {"name": "firewall/vip",                               "url": "/pm/config/adom/{adom}/obj/firewall/vip",                               "description": "Configure virtual IPs (IPv4 DNAT)."},
    {"name": "firewall/vip6",                              "url": "/pm/config/adom/{adom}/obj/firewall/vip6",                              "description": "Configure virtual IPs (IPv6 DNAT)."},
    {"name": "firewall/vip46",                             "url": "/pm/config/adom/{adom}/obj/firewall/vip46",                             "description": "Configure IPv4-to-IPv6 virtual IPs."},
    {"name": "firewall/vip64",                             "url": "/pm/config/adom/{adom}/obj/firewall/vip64",                             "description": "Configure IPv6-to-IPv4 virtual IPs."},
    {"name": "firewall/vipgrp",                            "url": "/pm/config/adom/{adom}/obj/firewall/vipgrp",                            "description": "Configure IPv4 VIP groups."},
    {"name": "firewall/vipgrp6",                           "url": "/pm/config/adom/{adom}/obj/firewall/vipgrp6",                           "description": "Configure IPv6 VIP groups."},
    {"name": "firewall/vipgrp46",                          "url": "/pm/config/adom/{adom}/obj/firewall/vipgrp46",                          "description": "Configure IPv4-to-IPv6 VIP groups."},
    {"name": "firewall/vipgrp64",                          "url": "/pm/config/adom/{adom}/obj/firewall/vipgrp64",                          "description": "Configure IPv6-to-IPv4 VIP groups."},

    # Services
    {"name": "firewall/service/category",                  "url": "/pm/config/adom/{adom}/obj/firewall/service/category",                  "description": "Configure service categories."},
    {"name": "firewall/service/custom",                    "url": "/pm/config/adom/{adom}/obj/firewall/service/custom",                    "description": "Configure custom services (TCP/UDP/ICMP ports)."},
    {"name": "firewall/service/group",                     "url": "/pm/config/adom/{adom}/obj/firewall/service/group",                     "description": "Configure service groups."},

    # Schedules
    {"name": "firewall/schedule/onetime",                  "url": "/pm/config/adom/{adom}/obj/firewall/schedule/onetime",                  "description": "Configure one-time schedules."},
    {"name": "firewall/schedule/recurring",                "url": "/pm/config/adom/{adom}/obj/firewall/schedule/recurring",                "description": "Configure recurring schedules."},
    {"name": "firewall/schedule/group",                    "url": "/pm/config/adom/{adom}/obj/firewall/schedule/group",                    "description": "Configure schedule groups."},

    # Traffic Shaping
    {"name": "firewall/shaper/traffic-shaper",             "url": "/pm/config/adom/{adom}/obj/firewall/shaper/traffic-shaper",             "description": "Configure shared traffic shapers."},
    {"name": "firewall/shaper/per-ip-shaper",              "url": "/pm/config/adom/{adom}/obj/firewall/shaper/per-ip-shaper",              "description": "Configure per-IP traffic shapers."},
    {"name": "firewall/shaping-profile",                   "url": "/pm/config/adom/{adom}/obj/firewall/shaping-profile",                   "description": "Configure shaping profiles."},
    {"name": "firewall/traffic-class",                     "url": "/pm/config/adom/{adom}/obj/firewall/traffic-class",                     "description": "Configure traffic class names for shaping."},

    # Security Profiles — grouping & protocol options
    {"name": "firewall/profile-group",                     "url": "/pm/config/adom/{adom}/obj/firewall/profile-group",                     "description": "Configure profile groups (bundle security profiles)."},
    {"name": "firewall/profile-protocol-options",          "url": "/pm/config/adom/{adom}/obj/firewall/profile-protocol-options",          "description": "Configure protocol options profiles (deep inspection helpers)."},
    {"name": "firewall/ssl-ssh-profile",                   "url": "/pm/config/adom/{adom}/obj/firewall/ssl-ssh-profile",                   "description": "Configure SSL/SSH inspection profiles."},
    {"name": "firewall/mms-profile",                       "url": "/pm/config/adom/{adom}/obj/firewall/mms-profile",                       "description": "Configure MMS (Multimedia Messaging Service) profiles."},

    # SSH Proxy
    {"name": "firewall/ssh/local-ca",                      "url": "/pm/config/adom/{adom}/obj/firewall/ssh/local-ca",                      "description": "SSH proxy local CA certificates."},
    {"name": "firewall/ssh/local-key",                     "url": "/pm/config/adom/{adom}/obj/firewall/ssh/local-key",                     "description": "SSH proxy local host keys."},

    # Load Balancing
    {"name": "firewall/ldb-monitor",                       "url": "/pm/config/adom/{adom}/obj/firewall/ldb-monitor",                       "description": "Configure server load-balancing health monitors."},

    # Identity-based Routing
    {"name": "firewall/identity-based-route",              "url": "/pm/config/adom/{adom}/obj/firewall/identity-based-route",              "description": "Configure identity-based routing rules."},

    # Carrier / GTP (mobile networks)
    {"name": "firewall/carrier-endpoint-bwl",              "url": "/pm/config/adom/{adom}/obj/firewall/carrier-endpoint-bwl",              "description": "Carrier endpoint black/white list."},
    {"name": "firewall/gtp",                               "url": "/pm/config/adom/{adom}/obj/firewall/gtp",                               "description": "Configure GTP (GPRS Tunnelling Protocol) objects."},

    # ──────────────────────────────────────────────────────────────────────────
    # FMG (FortiManager-specific objects)  —  /pm/config/adom/{adom}/obj/fmg/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "fmg/device/blueprint",                       "url": "/pm/config/adom/{adom}/obj/fmg/device/blueprint",                       "description": "FMG device provisioning blueprints."},
    {"name": "fmg/fabric/authorization-template",          "url": "/pm/config/adom/{adom}/obj/fmg/fabric/authorization-template",          "description": "Fabric authorization templates."},
    {"name": "fmg/variable",                               "url": "/pm/config/adom/{adom}/obj/fmg/variable",                               "description": "FMG ADOM-level variables (used in CLI templates and scripts)."},

    # ──────────────────────────────────────────────────────────────────────────
    # GLOBAL IPS (shared IPS objects across ADOMs)  —  /pm/config/adom/{adom}/obj/global/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "global/ips/sensor",                          "url": "/pm/config/adom/{adom}/obj/global/ips/sensor",                          "description": "Global IPS sensor definitions."},
    {"name": "global/ips/trigger",                         "url": "/pm/config/adom/{adom}/obj/global/ips/trigger",                         "description": "Global IPS trigger definitions."},

    # ──────────────────────────────────────────────────────────────────────────
    # GTP (GPRS Tunnelling Protocol — mobile/carrier)  —  /pm/config/adom/{adom}/obj/gtp/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "gtp/apn",                                    "url": "/pm/config/adom/{adom}/obj/gtp/apn",                                    "description": "Configure APNs (Access Point Names) for GTP."},
    {"name": "gtp/apngrp",                                 "url": "/pm/config/adom/{adom}/obj/gtp/apngrp",                                 "description": "Configure APN groups for GTP."},
    {"name": "gtp/ie-allow-list",                          "url": "/pm/config/adom/{adom}/obj/gtp/ie-allow-list",                          "description": "Configure GTP Information Element (IE) allow lists."},
    {"name": "gtp/ie-white-list",                          "url": "/pm/config/adom/{adom}/obj/gtp/ie-white-list",                          "description": "Configure GTP IE white lists (legacy)."},
    {"name": "gtp/message-filter-v0v1",                    "url": "/pm/config/adom/{adom}/obj/gtp/message-filter-v0v1",                    "description": "Message filter for GTPv0/v1."},
    {"name": "gtp/message-filter-v2",                      "url": "/pm/config/adom/{adom}/obj/gtp/message-filter-v2",                      "description": "Message filter for GTPv2."},
    {"name": "gtp/rat-timeout-profile",                    "url": "/pm/config/adom/{adom}/obj/gtp/rat-timeout-profile",                    "description": "GTP Radio Access Technology (RAT) timeout profiles."},
    {"name": "gtp/tunnel-limit",                           "url": "/pm/config/adom/{adom}/obj/gtp/tunnel-limit",                           "description": "Configure GTP tunnel limits."},

    # ──────────────────────────────────────────────────────────────────────────
    # ICAP (Internet Content Adaptation Protocol)  —  /pm/config/adom/{adom}/obj/icap/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "icap/profile",                               "url": "/pm/config/adom/{adom}/obj/icap/profile",                               "description": "Configure ICAP profiles."},
    {"name": "icap/server",                                "url": "/pm/config/adom/{adom}/obj/icap/server",                                "description": "Configure ICAP servers."},
    {"name": "icap/server-group",                          "url": "/pm/config/adom/{adom}/obj/icap/server-group",                          "description": "Configure ICAP server groups (supports failover and load balancing)."},

    # ──────────────────────────────────────────────────────────────────────────
    # IPS (Intrusion Prevention System)  —  /pm/config/adom/{adom}/obj/ips/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "ips/custom",                                 "url": "/pm/config/adom/{adom}/obj/ips/custom",                                 "description": "Configure custom IPS signatures."},
    {"name": "ips/sensor",                                 "url": "/pm/config/adom/{adom}/obj/ips/sensor",                                 "description": "Configure IPS sensors."},

    # ──────────────────────────────────────────────────────────────────────────
    # LOGGING  —  /pm/config/adom/{adom}/obj/log/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "log/custom-field",                           "url": "/pm/config/adom/{adom}/obj/log/custom-field",                           "description": "Configure custom log fields."},

    # ──────────────────────────────────────────────────────────────────────────
    # ROUTER POLICY OBJECTS  —  /pm/config/adom/{adom}/obj/router/
    # Used in route-map / redistribution / BGP policy on managed devices.
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "router/access-list",                         "url": "/pm/config/adom/{adom}/obj/router/access-list",                         "description": "Configure IPv4 access lists."},
    {"name": "router/access-list6",                        "url": "/pm/config/adom/{adom}/obj/router/access-list6",                        "description": "Configure IPv6 access lists."},
    {"name": "router/aspath-list",                         "url": "/pm/config/adom/{adom}/obj/router/aspath-list",                         "description": "Configure BGP AS-path lists."},
    {"name": "router/community-list",                      "url": "/pm/config/adom/{adom}/obj/router/community-list",                      "description": "Configure BGP community lists."},
    {"name": "router/prefix-list",                         "url": "/pm/config/adom/{adom}/obj/router/prefix-list",                         "description": "Configure IPv4 prefix lists."},
    {"name": "router/prefix-list6",                        "url": "/pm/config/adom/{adom}/obj/router/prefix-list6",                        "description": "Configure IPv6 prefix lists."},
    {"name": "router/route-map",                           "url": "/pm/config/adom/{adom}/obj/router/route-map",                           "description": "Configure route maps (match/set for routing policy)."},

    # ──────────────────────────────────────────────────────────────────────────
    # SCTP FILTER  —  /pm/config/adom/{adom}/obj/sctp-filter/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "sctp-filter/profile",                        "url": "/pm/config/adom/{adom}/obj/sctp-filter/profile",                        "description": "Configure SCTP filter profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # SSH FILTER  —  /pm/config/adom/{adom}/obj/ssh-filter/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "ssh-filter/profile",                         "url": "/pm/config/adom/{adom}/obj/ssh-filter/profile",                         "description": "Configure SSH filter profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # SWITCH CONTROLLER (FortiSwitch)  —  /pm/config/adom/{adom}/obj/switch-controller/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "switch-controller/auto-config/policy",       "url": "/pm/config/adom/{adom}/obj/switch-controller/auto-config/policy",       "description": "Configure FortiSwitch Auto-Config policies."},
    {"name": "switch-controller/auto-config/default",      "url": "/pm/config/adom/{adom}/obj/switch-controller/auto-config/default",      "description": "Configure FortiSwitch Auto-Config defaults (QoS policy and dynamic VLAN)."},

    # ──────────────────────────────────────────────────────────────────────────
    # SYSTEM  —  /pm/config/adom/{adom}/obj/system/
    #
    # Sub-groups:
    #   General / Misc      — custom-language, object-tag, sms-server
    #   DHCP                — dhcp/server
    #   External Resources  — externalresource  (URL/IP threat feeds)
    #   FSSO / SSO          — fsso-polling
    #   GeoIP               — geoip-country, geoip-override
    #   Meta Fields         — meta-fields/{devicelist,grouplist,policylist}
    #   NPU                 — npu/npu-tcam  (NP6/NP7 hardware offload)
    #   Replacement Msgs    — replacemsg-group, replacemsg-image
    #   SD-WAN (current)    — sdwan/{duplication,health-check,members,neighbor,service,zone}
    #   Virtual WAN Link    — virtual-wan-link/{health-check,members,neighbor,service}  (legacy pre-6.4)
    # ──────────────────────────────────────────────────────────────────────────

    # System — General / Miscellaneous
    {"name": "system/custom-language",                     "url": "/pm/config/adom/{adom}/obj/system/custom-language",                     "description": "Configure custom language packs."},
    {"name": "system/object-tag",                          "url": "/pm/config/adom/{adom}/obj/system/object-tag",                          "description": "Configure object tags (for labelling policy objects)."},
    {"name": "system/sms-server",                          "url": "/pm/config/adom/{adom}/obj/system/sms-server",                          "description": "Configure SMS servers (for OTP / user authentication)."},

    # System — DHCP
    {"name": "system/dhcp/server",                         "url": "/pm/config/adom/{adom}/obj/system/dhcp/server",                         "description": "Configure DHCP servers."},

    # System — External Resources (threat feeds, blocklists)
    {"name": "system/externalresource",                    "url": "/pm/config/adom/{adom}/obj/system/externalresource",                    "description": "Configure external resources (URL/IP threat feeds)."},

    # System — FSSO / Single Sign-On
    {"name": "system/fsso-polling",                        "url": "/pm/config/adom/{adom}/obj/system/fsso-polling",                        "description": "Configure FSSO polling (Active Directory SSO)."},

    # System — GeoIP
    {"name": "system/geoip-country",                       "url": "/pm/config/adom/{adom}/obj/system/geoip-country",                       "description": "Geographic country objects (built-in FortiGuard GeoIP database)."},
    {"name": "system/geoip-override",                      "url": "/pm/config/adom/{adom}/obj/system/geoip-override",                      "description": "Override FortiGuard GeoIP mappings for specific IP addresses."},

    # System — Meta Fields (FMG object metadata)
    {"name": "system/meta-fields/devicelist",              "url": "/pm/config/adom/{adom}/obj/system/meta-fields/devicelist",              "description": "Custom meta-field definitions for devices."},
    {"name": "system/meta-fields/grouplist",               "url": "/pm/config/adom/{adom}/obj/system/meta-fields/grouplist",               "description": "Custom meta-field definitions for device groups."},
    {"name": "system/meta-fields/policylist",              "url": "/pm/config/adom/{adom}/obj/system/meta-fields/policylist",              "description": "Custom meta-field definitions for policies."},

    # System — NPU (NP6/NP7 hardware acceleration)
    {"name": "system/npu/npu-tcam",                        "url": "/pm/config/adom/{adom}/obj/system/npu/npu-tcam",                        "description": "Configure NPU TCAM offload policies."},

    # System — Replacement Messages (block pages)
    {"name": "system/replacemsg-group",                    "url": "/pm/config/adom/{adom}/obj/system/replacemsg-group",                    "description": "Configure replacement message groups (block page text/HTML)."},
    {"name": "system/replacemsg-image",                    "url": "/pm/config/adom/{adom}/obj/system/replacemsg-image",                    "description": "Configure replacement message images (logos on block pages)."},

    # System — SD-WAN (current, 6.4+)
    {"name": "system/sdwan/duplication",                   "url": "/pm/config/adom/{adom}/obj/system/sdwan/duplication",                   "description": "Configure SD-WAN packet duplication rules."},
    {"name": "system/sdwan/health-check",                  "url": "/pm/config/adom/{adom}/obj/system/sdwan/health-check",                  "description": "Configure SD-WAN health-check probes."},
    {"name": "system/sdwan/members",                       "url": "/pm/config/adom/{adom}/obj/system/sdwan/members",                       "description": "Configure SD-WAN member interfaces."},
    {"name": "system/sdwan/neighbor",                      "url": "/pm/config/adom/{adom}/obj/system/sdwan/neighbor",                      "description": "Configure SD-WAN BGP neighbors (SLA-driven route advertisement)."},
    {"name": "system/sdwan/service",                       "url": "/pm/config/adom/{adom}/obj/system/sdwan/service",                       "description": "Configure SD-WAN rules / services (session steering)."},
    {"name": "system/sdwan/zone",                          "url": "/pm/config/adom/{adom}/obj/system/sdwan/zone",                          "description": "Configure SD-WAN zones."},

    # System — Virtual WAN Link (legacy SD-WAN, pre-6.4)
    {"name": "system/virtual-wan-link/health-check",       "url": "/pm/config/adom/{adom}/obj/system/virtual-wan-link/health-check",       "description": "Legacy SD-WAN health-check probes (virtual-wan-link)."},
    {"name": "system/virtual-wan-link/members",            "url": "/pm/config/adom/{adom}/obj/system/virtual-wan-link/members",            "description": "Legacy SD-WAN member interfaces (virtual-wan-link)."},
    {"name": "system/virtual-wan-link/neighbor",           "url": "/pm/config/adom/{adom}/obj/system/virtual-wan-link/neighbor",           "description": "Legacy SD-WAN BGP neighbors (virtual-wan-link)."},
    {"name": "system/virtual-wan-link/service",            "url": "/pm/config/adom/{adom}/obj/system/virtual-wan-link/service",            "description": "Legacy SD-WAN service rules (virtual-wan-link)."},

    # ──────────────────────────────────────────────────────────────────────────
    # TELEMETRY CONTROLLER  —  /pm/config/adom/{adom}/obj/telemetry-controller/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "telemetry-controller/integration",           "url": "/pm/config/adom/{adom}/obj/telemetry-controller/integration",           "description": "Configure telemetry integrations."},
    {"name": "telemetry-controller/profile",               "url": "/pm/config/adom/{adom}/obj/telemetry-controller/profile",               "description": "Configure telemetry profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # UMS (Unified Management Service)  —  /pm/config/adom/{adom}/obj/ums/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "ums/profile",                                "url": "/pm/config/adom/{adom}/obj/ums/profile",                                "description": "Configure UMS profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # USER & AUTHENTICATION  —  /pm/config/adom/{adom}/obj/user/
    #
    # Sub-groups:
    #   Local users & groups       — local, group
    #   Remote auth servers        — ldap, radius, tacacs+, saml, pop3, exchange, krbkeytab, domaincontroller
    #   FSSO / SSO                 — fsso, fsso-polling, adgrp
    #   Certificates & MFA         — certificate, fortitoken
    #   Device identity            — device, device-category, device-group, device-access-list
    #   NAC                        — nac-policy
    #   Peer auth                  — peer, peergrp
    #   Security exemptions        — security-exempt-list
    # ──────────────────────────────────────────────────────────────────────────

    # Local users & groups
    {"name": "user/local",                                 "url": "/pm/config/adom/{adom}/obj/user/local",                                 "description": "Configure local user accounts."},
    {"name": "user/group",                                 "url": "/pm/config/adom/{adom}/obj/user/group",                                 "description": "Configure user groups."},

    # Remote authentication servers
    {"name": "user/ldap",                                  "url": "/pm/config/adom/{adom}/obj/user/ldap",                                  "description": "Configure LDAP server entries."},
    {"name": "user/radius",                                "url": "/pm/config/adom/{adom}/obj/user/radius",                                "description": "Configure RADIUS server entries."},
    {"name": "user/tacacs+",                               "url": "/pm/config/adom/{adom}/obj/user/tacacs+",                               "description": "Configure TACACS+ server entries."},
    {"name": "user/saml",                                  "url": "/pm/config/adom/{adom}/obj/user/saml",                                  "description": "Configure SAML IdP server entries."},
    {"name": "user/pop3",                                  "url": "/pm/config/adom/{adom}/obj/user/pop3",                                  "description": "Configure POP3 server entries (mail-based auth)."},
    {"name": "user/exchange",                              "url": "/pm/config/adom/{adom}/obj/user/exchange",                              "description": "Configure MS Exchange server entries."},
    {"name": "user/krbkeytab",                             "url": "/pm/config/adom/{adom}/obj/user/krbkeytab",                             "description": "Configure Kerberos keytab entries (for Kerberos SSO)."},
    {"name": "user/domaincontroller",                      "url": "/pm/config/adom/{adom}/obj/user/domaincontroller",                      "description": "Configure Windows domain controller entries (LDAP federation)."},

    # FSSO (Fortinet Single Sign-On)
    {"name": "user/fsso",                                  "url": "/pm/config/adom/{adom}/obj/user/fsso",                                  "description": "Configure FSSO collector agent entries."},
    {"name": "user/fsso-polling",                          "url": "/pm/config/adom/{adom}/obj/user/fsso-polling",                          "description": "Configure FSSO AD polling mode servers."},
    {"name": "user/adgrp",                                 "url": "/pm/config/adom/{adom}/obj/user/adgrp",                                 "description": "Configure FSSO AD groups."},

    # Certificates & MFA
    {"name": "user/certificate",                           "url": "/pm/config/adom/{adom}/obj/user/certificate",                           "description": "Configure user certificate authentication."},
    {"name": "user/fortitoken",                            "url": "/pm/config/adom/{adom}/obj/user/fortitoken",                            "description": "Configure FortiToken MFA token seeds."},

    # Device identity
    {"name": "user/device",                                "url": "/pm/config/adom/{adom}/obj/user/device",                                "description": "Configure device identity objects."},
    {"name": "user/device-category",                       "url": "/pm/config/adom/{adom}/obj/user/device-category",                       "description": "Configure device categories."},
    {"name": "user/device-group",                          "url": "/pm/config/adom/{adom}/obj/user/device-group",                          "description": "Configure device groups."},
    {"name": "user/device-access-list",                    "url": "/pm/config/adom/{adom}/obj/user/device-access-list",                    "description": "Configure device access control lists."},

    # NAC, Peer auth, Exemptions
    {"name": "user/nac-policy",                            "url": "/pm/config/adom/{adom}/obj/user/nac-policy",                            "description": "Configure NAC policies (device fingerprint matching)."},
    {"name": "user/peer",                                  "url": "/pm/config/adom/{adom}/obj/user/peer",                                  "description": "Configure peer user objects (certificate-based peer auth)."},
    {"name": "user/peergrp",                               "url": "/pm/config/adom/{adom}/obj/user/peergrp",                               "description": "Configure peer user groups."},
    {"name": "user/security-exempt-list",                  "url": "/pm/config/adom/{adom}/obj/user/security-exempt-list",                  "description": "Configure security exemption lists."},

    # ──────────────────────────────────────────────────────────────────────────
    # VIDEO FILTER  —  /pm/config/adom/{adom}/obj/videofilter/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "videofilter/keyword",                        "url": "/pm/config/adom/{adom}/obj/videofilter/keyword",                        "description": "Configure video filter keyword lists."},
    {"name": "videofilter/profile",                        "url": "/pm/config/adom/{adom}/obj/videofilter/profile",                        "description": "Configure VideoFilter profiles."},
    {"name": "videofilter/youtube-channel-filter",         "url": "/pm/config/adom/{adom}/obj/videofilter/youtube-channel-filter",         "description": "Configure YouTube channel filter lists."},

    # ──────────────────────────────────────────────────────────────────────────
    # VIRTUAL PATCH  —  /pm/config/adom/{adom}/obj/virtual-patch/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "virtual-patch/profile",                      "url": "/pm/config/adom/{adom}/obj/virtual-patch/profile",                      "description": "Configure virtual patch profiles (agentless vulnerability shielding)."},

    # ──────────────────────────────────────────────────────────────────────────
    # VOIP  —  /pm/config/adom/{adom}/obj/voip/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "voip/profile",                               "url": "/pm/config/adom/{adom}/obj/voip/profile",                               "description": "Configure VoIP profiles (SIP/SCCP inspection)."},

    # ──────────────────────────────────────────────────────────────────────────
    # VPN  —  /pm/config/adom/{adom}/obj/vpn/
    #
    # Sub-groups:
    #   Certificates  — certificate/{ca, ocsp-server, remote}
    #   IPsec         — ipsec/{fec, manualkey, manualkey-interface,
    #                          phase1, phase1-interface, phase2, phase2-interface}
    #   KMIP          — kmip-server  (external key management)
    #   OCVPN         — ocvpn  (Overlay Controller VPN / SD-WAN overlay mesh)
    #   SSL-VPN       — ssl/web/{host-check-software, portal, realm}
    # ──────────────────────────────────────────────────────────────────────────

    # VPN — Certificates
    {"name": "vpn/certificate/ca",                         "url": "/pm/config/adom/{adom}/obj/vpn/certificate/ca",                         "description": "CA certificates for VPN PKI."},
    {"name": "vpn/certificate/ocsp-server",                "url": "/pm/config/adom/{adom}/obj/vpn/certificate/ocsp-server",                "description": "OCSP server configuration for certificate revocation."},
    {"name": "vpn/certificate/remote",                     "url": "/pm/config/adom/{adom}/obj/vpn/certificate/remote",                     "description": "Remote peer certificates (PEM)."},

    # VPN — IPsec
    {"name": "vpn/ipsec/fec",                              "url": "/pm/config/adom/{adom}/obj/vpn/ipsec/fec",                              "description": "Configure IPsec Forward Error Correction (FEC) profiles."},
    {"name": "vpn/ipsec/manualkey",                        "url": "/pm/config/adom/{adom}/obj/vpn/ipsec/manualkey",                        "description": "Configure IPsec manual key SAs (policy-based)."},
    {"name": "vpn/ipsec/manualkey-interface",              "url": "/pm/config/adom/{adom}/obj/vpn/ipsec/manualkey-interface",              "description": "Configure IPsec manual key SAs (interface-based)."},
    {"name": "vpn/ipsec/phase1",                           "url": "/pm/config/adom/{adom}/obj/vpn/ipsec/phase1",                           "description": "Configure IPsec Phase 1 (IKEv1/IKEv2 — policy-based)."},
    {"name": "vpn/ipsec/phase1-interface",                 "url": "/pm/config/adom/{adom}/obj/vpn/ipsec/phase1-interface",                 "description": "Configure IPsec Phase 1 (IKEv1/IKEv2 — interface/route-based)."},
    {"name": "vpn/ipsec/phase2",                           "url": "/pm/config/adom/{adom}/obj/vpn/ipsec/phase2",                           "description": "Configure IPsec Phase 2 / child SA (policy-based)."},
    {"name": "vpn/ipsec/phase2-interface",                 "url": "/pm/config/adom/{adom}/obj/vpn/ipsec/phase2-interface",                 "description": "Configure IPsec Phase 2 / child SA (interface-based)."},

    # VPN — KMIP (external key management)
    {"name": "vpn/kmip-server",                            "url": "/pm/config/adom/{adom}/obj/vpn/kmip-server",                            "description": "Configure KMIP key management server entries."},

    # VPN — OCVPN / Overlay Controller
    {"name": "vpn/ocvpn",                                  "url": "/pm/config/adom/{adom}/obj/vpn/ocvpn",                                  "description": "Configure Overlay Controller VPN (OCVPN) settings."},

    # VPN — SSL-VPN
    {"name": "vpn/ssl/web/host-check-software",            "url": "/pm/config/adom/{adom}/obj/vpn/ssl/web/host-check-software",            "description": "Configure SSL-VPN host-check software entries."},
    {"name": "vpn/ssl/web/portal",                         "url": "/pm/config/adom/{adom}/obj/vpn/ssl/web/portal",                         "description": "Configure SSL-VPN web portals."},
    {"name": "vpn/ssl/web/realm",                          "url": "/pm/config/adom/{adom}/obj/vpn/ssl/web/realm",                          "description": "Configure SSL-VPN realms (per-realm portal mapping)."},

    # ──────────────────────────────────────────────────────────────────────────
    # VPN MANAGER  —  /pm/config/adom/{adom}/obj/vpnmgr/
    # FMG VPN Manager topology objects (hub-spoke / full-mesh wizards).
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "vpnmgr/node",                                "url": "/pm/config/adom/{adom}/obj/vpnmgr/node",                                "description": "Configure VPN Manager nodes (hub or spoke devices)."},
    {"name": "vpnmgr/vpntable",                            "url": "/pm/config/adom/{adom}/obj/vpnmgr/vpntable",                            "description": "Configure VPN Manager topology tables."},

    # ──────────────────────────────────────────────────────────────────────────
    # WAF (Web Application Firewall)  —  /pm/config/adom/{adom}/obj/waf/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "waf/main-class",                             "url": "/pm/config/adom/{adom}/obj/waf/main-class",                             "description": "WAF main signature class table (tracks user-updated signatures)."},
    {"name": "waf/profile",                                "url": "/pm/config/adom/{adom}/obj/waf/profile",                                "description": "Configure WAF profiles."},
    {"name": "waf/signature",                              "url": "/pm/config/adom/{adom}/obj/waf/signature",                              "description": "WAF signature table (tracks signature updates)."},
    {"name": "waf/sub-class",                              "url": "/pm/config/adom/{adom}/obj/waf/sub-class",                              "description": "WAF sub-class signature table."},

    # ──────────────────────────────────────────────────────────────────────────
    # WAN OPTIMIZATION  —  /pm/config/adom/{adom}/obj/wanopt/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "wanopt/auth-group",                          "url": "/pm/config/adom/{adom}/obj/wanopt/auth-group",                          "description": "Configure WAN optimization authentication groups."},
    {"name": "wanopt/peer",                                "url": "/pm/config/adom/{adom}/obj/wanopt/peer",                                "description": "Configure WAN optimization peer devices."},
    {"name": "wanopt/profile",                             "url": "/pm/config/adom/{adom}/obj/wanopt/profile",                             "description": "Configure WAN optimization profiles."},

    # ──────────────────────────────────────────────────────────────────────────
    # WEB PROXY  —  /pm/config/adom/{adom}/obj/web-proxy/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "web-proxy/forward-server",                   "url": "/pm/config/adom/{adom}/obj/web-proxy/forward-server",                   "description": "Configure explicit proxy forward server addresses."},
    {"name": "web-proxy/forward-server-group",             "url": "/pm/config/adom/{adom}/obj/web-proxy/forward-server-group",             "description": "Configure forward server groups (failover and load balancing)."},
    {"name": "web-proxy/isolator-server",                  "url": "/pm/config/adom/{adom}/obj/web-proxy/isolator-server",                  "description": "Configure web isolator server addresses."},
    {"name": "web-proxy/profile",                          "url": "/pm/config/adom/{adom}/obj/web-proxy/profile",                          "description": "Configure web proxy profiles."},
    {"name": "web-proxy/wisp",                             "url": "/pm/config/adom/{adom}/obj/web-proxy/wisp",                             "description": "Configure WISP (Websense Integrated Services Protocol) servers."},

    # ──────────────────────────────────────────────────────────────────────────
    # WEB FILTER  —  /pm/config/adom/{adom}/obj/webfilter/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "webfilter/categories",                       "url": "/pm/config/adom/{adom}/obj/webfilter/categories",                       "description": "Built-in FortiGuard web filter categories."},
    {"name": "webfilter/content",                          "url": "/pm/config/adom/{adom}/obj/webfilter/content",                          "description": "Configure web filter banned word tables."},
    {"name": "webfilter/content-header",                   "url": "/pm/config/adom/{adom}/obj/webfilter/content-header",                   "description": "Configure content-type headers for web filtering."},
    {"name": "webfilter/ftgd-local-cat",                   "url": "/pm/config/adom/{adom}/obj/webfilter/ftgd-local-cat",                   "description": "Configure FortiGuard local web filter categories."},
    {"name": "webfilter/ftgd-local-rating",                "url": "/pm/config/adom/{adom}/obj/webfilter/ftgd-local-rating",                "description": "Configure local URL ratings (override FortiGuard ratings)."},
    {"name": "webfilter/ftgd-risk-level",                  "url": "/pm/config/adom/{adom}/obj/webfilter/ftgd-risk-level",                  "description": "Configure FortiGuard web filter risk levels."},
    {"name": "webfilter/profile",                          "url": "/pm/config/adom/{adom}/obj/webfilter/profile",                          "description": "Configure web filter profiles."},
    {"name": "webfilter/urlfilter",                        "url": "/pm/config/adom/{adom}/obj/webfilter/urlfilter",                        "description": "Configure URL filter lists (static allow/block by URL)."},

    # ──────────────────────────────────────────────────────────────────────────
    # ZTNA (Zero Trust Network Access)  —  /pm/config/adom/{adom}/obj/ztna/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "ztna/traffic-forward-proxy",                 "url": "/pm/config/adom/{adom}/obj/ztna/traffic-forward-proxy",                 "description": "Configure ZTNA traffic forward proxy."},
    {"name": "ztna/web-portal",                            "url": "/pm/config/adom/{adom}/obj/ztna/web-portal",                            "description": "Configure ZTNA web portals."},
    {"name": "ztna/web-portal-bookmark",                   "url": "/pm/config/adom/{adom}/obj/ztna/web-portal-bookmark",                   "description": "Configure ZTNA web portal bookmarks."},
    {"name": "ztna/web-proxy",                             "url": "/pm/config/adom/{adom}/obj/ztna/web-proxy",                             "description": "Configure ZTNA web proxy settings."},
]
CATEGORIES = sorted(set(t["name"].split("/")[0] for t in ADOM_TABLES))

# ── ADOM Controller Config table definitions (60 entries from FMG 7.6.6 docs) ──────
#
# Base URL pattern:  /pm/config/adom/{adom}/obj/<path>
# Covers FortiSwitch, FortiAP, FortiExtender, FSP VLAN,
# and Hotspot 2.0 controller objects.
#
CONTROLLER_TABLES = [

    # ──────────────────────────────────────────────────────────────────────────
    # EXTENSION CONTROLLER (FortiExtender)  —  /pm/config/adom/{adom}/obj/extension-controller/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "extension-controller/extender", "url": "/pm/config/adom/{adom}/obj/extension-controller/extender", "description": "Extender controller configuration."},

    # ──────────────────────────────────────────────────────────────────────────
    # FSP (FortiSwitch Ports — VLANs, packet capture)  —  /pm/config/adom/{adom}/obj/fsp/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "fsp/managed-switch", "url": "/pm/config/adom/{adom}/obj/fsp/managed-switch", "description": "Require device/vdom scope member."},
    {"name": "fsp/packet-capture", "url": "/pm/config/adom/{adom}/obj/fsp/packet-capture", "description": "Require device/vdom scope member."},
    {"name": "fsp/vdom-settings/interface-settings", "url": "/pm/config/adom/{adom}/obj/fsp/vdom-settings/interface-settings", "description": "Require device/vdom scope member."},
    {"name": "fsp/vlan", "url": "/pm/config/adom/{adom}/obj/fsp/vlan", "description": "FortiSwitch VLAN template."},

    # ──────────────────────────────────────────────────────────────────────────
    # SWITCH CONTROLLER (FortiSwitch)  —  /pm/config/adom/{adom}/obj/switch-controller/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "switch-controller/acl/group", "url": "/pm/config/adom/{adom}/obj/switch-controller/acl/group", "description": "Configure ACL groups to be applied on managed FortiSwitch ports."},
    {"name": "switch-controller/acl/ingress", "url": "/pm/config/adom/{adom}/obj/switch-controller/acl/ingress", "description": "Configure ingress ACL policies to be applied on managed FortiSwitch ports."},
    {"name": "switch-controller/custom-command", "url": "/pm/config/adom/{adom}/obj/switch-controller/custom-command", "description": "Configure the FortiGate switch controller to send custom commands to managed FortiSwitch devices."},
    {"name": "switch-controller/dsl/policy", "url": "/pm/config/adom/{adom}/obj/switch-controller/dsl/policy", "description": "DSL policy."},
    {"name": "switch-controller/dynamic-port-policy", "url": "/pm/config/adom/{adom}/obj/switch-controller/dynamic-port-policy", "description": "Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device."},
    {"name": "switch-controller/fortilink-settings", "url": "/pm/config/adom/{adom}/obj/switch-controller/fortilink-settings", "description": "Configure integrated FortiLink settings for FortiSwitch."},
    {"name": "switch-controller/lldp-profile", "url": "/pm/config/adom/{adom}/obj/switch-controller/lldp-profile", "description": "Configure FortiSwitch LLDP profiles."},
    {"name": "switch-controller/mac-policy", "url": "/pm/config/adom/{adom}/obj/switch-controller/mac-policy", "description": "Configure MAC policy to be applied on the managed FortiSwitch devices through NAC device."},
    {"name": "switch-controller/managed-switch", "url": "/pm/config/adom/{adom}/obj/switch-controller/managed-switch", "description": "FortiSwitch Template."},
    {"name": "switch-controller/ptp/profile", "url": "/pm/config/adom/{adom}/obj/switch-controller/ptp/profile", "description": "Global PTP profile."},
    {"name": "switch-controller/qos/dot1p-map", "url": "/pm/config/adom/{adom}/obj/switch-controller/qos/dot1p-map", "description": "Configure FortiSwitch QoS 802.1p."},
    {"name": "switch-controller/qos/ip-dscp-map", "url": "/pm/config/adom/{adom}/obj/switch-controller/qos/ip-dscp-map", "description": "Configure FortiSwitch QoS IP precedence/DSCP."},
    {"name": "switch-controller/qos/qos-policy", "url": "/pm/config/adom/{adom}/obj/switch-controller/qos/qos-policy", "description": "Configure FortiSwitch QoS policy."},
    {"name": "switch-controller/qos/queue-policy", "url": "/pm/config/adom/{adom}/obj/switch-controller/qos/queue-policy", "description": "Configure FortiSwitch QoS egress queue policy."},
    {"name": "switch-controller/security-policy/802-1X", "url": "/pm/config/adom/{adom}/obj/switch-controller/security-policy/802-1X", "description": "Configure 802.1x MAC Authentication Bypass (MAB) policies."},
    {"name": "switch-controller/switch-group", "url": "/pm/config/adom/{adom}/obj/switch-controller/switch-group", "description": "Configure FortiSwitch switch groups."},
    {"name": "switch-controller/switch-interface-tag", "url": "/pm/config/adom/{adom}/obj/switch-controller/switch-interface-tag", "description": "Configure switch object tags."},
    {"name": "switch-controller/traffic-policy", "url": "/pm/config/adom/{adom}/obj/switch-controller/traffic-policy", "description": "Configure FortiSwitch traffic policy."},
    {"name": "switch-controller/vlan-policy", "url": "/pm/config/adom/{adom}/obj/switch-controller/vlan-policy", "description": "Configure VLAN policy to be applied on the managed FortiSwitch ports through dynamic-port-policy."},

    # ──────────────────────────────────────────────────────────────────────────
    # WIRELESS CONTROLLER (FortiAP / Wi-Fi)  —  /pm/config/adom/{adom}/obj/wireless-controller/
    # ──────────────────────────────────────────────────────────────────────────
    {"name": "wireless-controller/access-control-list", "url": "/pm/config/adom/{adom}/obj/wireless-controller/access-control-list", "description": "Configure WiFi bridge access control list."},
    {"name": "wireless-controller/apcfg-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/apcfg-profile", "description": "Configure AP local configuration profiles."},
    {"name": "wireless-controller/arrp-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/arrp-profile", "description": "Configure WiFi Automatic Radio Resource Provisioning (ARRP) profiles."},
    {"name": "wireless-controller/ble-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/ble-profile", "description": "Configure Bluetooth Low Energy profile."},
    {"name": "wireless-controller/bonjour-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/bonjour-profile", "description": "Configure Bonjour profiles. Bonjour is Apple's zero configuration networking protocol. Bonjour profiles allow APs and FortiAPs to connect to networks using Bonjour."},
    {"name": "wireless-controller/hotspot20/anqp-3gpp-cellular", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-3gpp-cellular", "description": "Configure 3GPP public land mobile network (PLMN)."},
    {"name": "wireless-controller/hotspot20/anqp-ip-address-type", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-ip-address-type", "description": "Configure IP address type availability."},
    {"name": "wireless-controller/hotspot20/anqp-nai-realm", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-nai-realm", "description": "Configure network access identifier (NAI) realm."},
    {"name": "wireless-controller/hotspot20/anqp-network-auth-type", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-network-auth-type", "description": "Configure network authentication type."},
    {"name": "wireless-controller/hotspot20/anqp-roaming-consortium", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-roaming-consortium", "description": "Configure roaming consortium."},
    {"name": "wireless-controller/hotspot20/anqp-venue-name", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-name", "description": "Configure venue name duple."},
    {"name": "wireless-controller/hotspot20/anqp-venue-url", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/anqp-venue-url", "description": "Configure venue URL."},
    {"name": "wireless-controller/hotspot20/h2qp-advice-of-charge", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-advice-of-charge", "description": "Configure advice of charge."},
    {"name": "wireless-controller/hotspot20/h2qp-conn-capability", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-conn-capability", "description": "Configure connection capability."},
    {"name": "wireless-controller/hotspot20/h2qp-operator-name", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-operator-name", "description": "Configure operator friendly name."},
    {"name": "wireless-controller/hotspot20/h2qp-osu-provider", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider", "description": "Configure online sign up (OSU) provider list."},
    {"name": "wireless-controller/hotspot20/h2qp-osu-provider-nai", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-osu-provider-nai", "description": "Configure online sign up (OSU) provider NAI list."},
    {"name": "wireless-controller/hotspot20/h2qp-terms-and-conditions", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-terms-and-conditions", "description": "Configure terms and conditions."},
    {"name": "wireless-controller/hotspot20/h2qp-wan-metric", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/h2qp-wan-metric", "description": "Configure WAN metrics."},
    {"name": "wireless-controller/hotspot20/hs-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/hs-profile", "description": "Configure hotspot profile."},
    {"name": "wireless-controller/hotspot20/icon", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/icon", "description": "Configure OSU provider icon."},
    {"name": "wireless-controller/hotspot20/qos-map", "url": "/pm/config/adom/{adom}/obj/wireless-controller/hotspot20/qos-map", "description": "Configure QoS map set."},
    {"name": "wireless-controller/mpsk-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/mpsk-profile", "description": "Configure MPSK profile."},
    {"name": "wireless-controller/nac-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/nac-profile", "description": "Configure WiFi network access control (NAC) profiles."},
    {"name": "wireless-controller/qos-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/qos-profile", "description": "Configure WiFi quality of service (QoS) profiles."},
    {"name": "wireless-controller/region", "url": "/pm/config/adom/{adom}/obj/wireless-controller/region", "description": "Configure FortiAP regions (for floor plans and maps)."},
    {"name": "wireless-controller/ssid-policy", "url": "/pm/config/adom/{adom}/obj/wireless-controller/ssid-policy", "description": "Configure WiFi SSID policies."},
    {"name": "wireless-controller/syslog-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/syslog-profile", "description": "Configure Wireless Termination Points (WTP) system log server profile."},
    {"name": "wireless-controller/utm-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/utm-profile", "description": "Configure UTM (Unified Threat Management) profile."},
    {"name": "wireless-controller/vap", "url": "/pm/config/adom/{adom}/obj/wireless-controller/vap", "description": "Configure Virtual Access Points (VAPs)."},
    {"name": "wireless-controller/vap-group", "url": "/pm/config/adom/{adom}/obj/wireless-controller/vap-group", "description": "Configure virtual Access Point (VAP) groups."},
    {"name": "wireless-controller/wag-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/wag-profile", "description": "Configure wireless access gateway (WAG) profiles used for tunnels on AP."},
    {"name": "wireless-controller/wids-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/wids-profile", "description": "Configure wireless intrusion detection system (WIDS) profiles."},
    {"name": "wireless-controller/wtp", "url": "/pm/config/adom/{adom}/obj/wireless-controller/wtp", "description": "Configure Wireless Termination Points (WTPs), that is, FortiAPs or APs to be managed by FortiGate."},
    {"name": "wireless-controller/wtp-group", "url": "/pm/config/adom/{adom}/obj/wireless-controller/wtp-group", "description": "Configure WTP groups."},
    {"name": "wireless-controller/wtp-profile", "url": "/pm/config/adom/{adom}/obj/wireless-controller/wtp-profile", "description": "Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms."},
]


CONTROLLER_CATEGORIES = sorted(set(t['name'].split('/')[0] for t in CONTROLLER_TABLES))

# Policy package table definitions — 24 policy types from FMG 7.6.6
# URL pattern: /pm/config/adom/{adom}/pkg/{pkg}/<policy_type>
POLICY_TABLES = [
    # Main firewall policies
    {"name": "firewall/policy",               "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy",               "description": "IPv4/IPv6 firewall policies."},
    {"name": "firewall/security-policy",      "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy",      "description": "NGFW security policies."},
    {"name": "firewall/proxy-policy",         "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/proxy-policy",         "description": "Explicit proxy policies."},

    # DoS policies — anomaly sub-tables are fetched automatically per policy
    {"name": "firewall/DoS-policy",           "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy",           "description": "IPv4 DoS policies (includes anomaly rules)."},
    {"name": "firewall/DoS-policy6",          "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy6",          "description": "IPv6 DoS policies (includes anomaly rules)."},

    # ACL and interface policies
    {"name": "firewall/acl",                  "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl",                  "description": "IPv4 interface ACL policies."},
    {"name": "firewall/acl6",                 "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/acl6",                 "description": "IPv6 interface ACL policies."},
    {"name": "firewall/interface-policy",     "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy",     "description": "IPv4 interface-based policies."},
    {"name": "firewall/interface-policy6",    "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy6",    "description": "IPv6 interface-based policies."},

    # NAT and routing
    {"name": "firewall/central-snat-map",     "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/central-snat-map",     "description": "Central SNAT rules."},
    {"name": "central/dnat",                  "url": "/pm/config/adom/{adom}/pkg/{pkg}/central/dnat",                  "description": "Central DNAT rules."},
    {"name": "central/dnat6",                 "url": "/pm/config/adom/{adom}/pkg/{pkg}/central/dnat6",                 "description": "Central IPv6 DNAT rules."},

    # Local-in and multicast
    {"name": "firewall/local-in-policy",      "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy",      "description": "IPv4 local-in policies."},
    {"name": "firewall/local-in-policy6",     "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/local-in-policy6",     "description": "IPv6 local-in policies."},
    {"name": "firewall/multicast-policy",     "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy",     "description": "IPv4 multicast policies."},
    {"name": "firewall/multicast-policy6",    "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/multicast-policy6",    "description": "IPv6 multicast policies."},

    # Traffic shaping
    {"name": "firewall/shaping-policy",       "url": "/pm/config/adom/{adom}/pkg/{pkg}/firewall/shaping-policy",       "description": "Traffic shaping policies."},

    # Authentication
    {"name": "authentication/rule",           "url": "/pm/config/adom/{adom}/pkg/{pkg}/authentication/rule",           "description": "Authentication rules."},

    # Other
    {"name": "user/nac-policy",               "url": "/pm/config/adom/{adom}/pkg/{pkg}/user/nac-policy",               "description": "NAC policies."},
    {"name": "videofilter/youtube-key",       "url": "/pm/config/adom/{adom}/pkg/{pkg}/videofilter/youtube-key",       "description": "YouTube filter keys."},

    # Global header/footer policies (prepended/appended across all devices)
    {"name": "global/header/policy",          "url": "/pm/config/adom/{adom}/pkg/{pkg}/global/header/policy",          "description": "Global header policies."},
    {"name": "global/header/shaping-policy",  "url": "/pm/config/adom/{adom}/pkg/{pkg}/global/header/shaping-policy",  "description": "Global header shaping policies."},
    {"name": "global/footer/policy",          "url": "/pm/config/adom/{adom}/pkg/{pkg}/global/footer/policy",          "description": "Global footer policies."},
    {"name": "global/footer/shaping-policy",  "url": "/pm/config/adom/{adom}/pkg/{pkg}/global/footer/shaping-policy",  "description": "Global footer shaping policies."},
]

# Per-package single objects (not tables — fetched as one object per package)
# authentication/setting and schedule are objects, not lists of entries
POLICY_OBJECTS = [
    {"name": "authentication/setting", "url": "/pm/config/adom/{adom}/pkg/{pkg}/authentication/setting",
     "description": "Authentication settings for the package."},
]

# Policy types supported inside policy blocks
PBLOCK_POLICY_TYPES = [
    {"name": "firewall/policy",          "description": "IPv4/IPv6 firewall policies."},
    {"name": "firewall/proxy-policy",    "description": "Explicit proxy policies."},
    {"name": "firewall/security-policy", "description": "NGFW security policies."},
]

# Fields stripped when pushing policies to target.
# "obj seq" is an internal sequence field FMG rejects on write.
# Everything else (including _ prefixed stats fields) is accepted and ignored by FMG.
_POLICY_STRIP = {"oid", "obj-ver", "uuid", "_image-base64", "obj seq", "obj flags"}




# FortiManager JSON-RPC client

class FMGClient:
    """Minimal FortiManager JSON-RPC over HTTPS client."""

    def __init__(self, host: str, port: int = 443, verify_ssl: bool = False):
        self.base_url = f"https://{host}:{port}/jsonrpc"
        self.session = None
        self._req_id = 1
        self._ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # HTTP transport

    def _post(self, payload: dict) -> dict:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise ConnectionError(f"Cannot reach FortiManager: {exc.reason}") from exc

    def _call(self, method: str, params: list) -> dict:
        payload = {
            "method": method,
            "params": params,
            "session": self.session,
            "id": self._req_id,
            "verbose": 1,
        }
        self._req_id += 1
        resp = self._post(payload)
        return resp

    # Authentication

    def login(self, username: str, password: str) -> None:
        resp = self._call("exec", [{"url": "/sys/login/user",
                                    "data": {"user": username, "passwd": password}}])
        result = resp.get("result", [{}])
        status = result[0].get("status", {}) if result else {}
        if status.get("code", -1) != 0:
            raise PermissionError(f"Login failed: {status.get('message', 'unknown error')}")
        self.session = resp.get("session")

    def logout(self) -> None:
        if self.session:
            self._call("exec", [{"url": "/sys/logout"}])
            self.session = None

    # API queries

    def get_adoms(self) -> list[dict]:
        """
        Return ADOM names that are relevant for firewall object extraction.

        Only ADOMs whose restricted_prds includes at least one FortiOS-family
        product are returned:
            fos  — FortiOS (FortiGate)
            foc  — FortiOS Carrier
            ffw  — FortiFirewall
            fwc  — FortiFirewall Carrier
            fpx  — FortiProxy

        ADOMs for FortiAnalyzer, FortiMail, FortiSandbox, etc. are excluded
        because they do not carry firewall/address, service, VIP, etc. objects.
        rootp (Global Policy ADOM) is always included when present.
        """
        FORTIOS_PRDS = {"fos", "foc", "ffw", "fwc", "fpx"}

        resp = self._call("get", [{
            "url":    "/dvmdb/adom",
            "fields": ["name", "restricted_prds", "os_ver", "mr"],
        }])
        result = resp.get("result", [{}])
        status = result[0].get("status", {})
        if status.get("code", -1) != 0:
            raise RuntimeError(f"Failed to list ADOMs: {status.get('message')}")
        data = result[0].get("data", [])

        filtered = []
        for a in data:
            name = a.get("name")
            if not name:
                continue

            # os_ver = "7.0" means major version 7; mr = 2 means minor 2 → v7.2
            # Extract just the major number from os_ver and combine with mr
            os_ver  = str(a.get("os_ver", "")).strip()
            mr      = a.get("mr", "")
            major   = os_ver.split(".")[0] if "." in os_ver else os_ver
            version = f"{major}.{mr}" if major and mr != "" else major

            entry = {"name": name, "version": version}

            # rootp (Global Policy ADOM) is always relevant
            if name == "rootp":
                filtered.append(entry)
                continue

            # restricted_prds may be returned as:
            #   list  e.g. ["fos", "fpx"]   — newer FMG versions
            #   str   e.g. "fos"            — single-product ADOMs on some versions
            #   int   e.g. 0x0001           — bitmask on older FMG versions
            #   []  / missing               — "all products" ADOM
            prds = a.get("restricted_prds", [])
            if isinstance(prds, int):
                BITMASK = {0x0001: "fos", 0x0008: "ffw", 0x0010: "fwc",
                           0x0020: "foc", 0x0200: "fpx"}
                prds = [v for k, v in BITMASK.items() if prds & k]
            elif isinstance(prds, str):
                prds = [prds] if prds else []
            # prds is now always a list
            if not prds or set(prds) & FORTIOS_PRDS:
                filtered.append(entry)

        return filtered

    def get_table(self, url: str, with_scope: bool = False) -> tuple[list, int]:
        """
        Fetch all entries from a table URL (paginates automatically).
        Returns (entries, status_code).

        loadsub is intentionally omitted (defaults to 1) so that
        sub-objects such as dynamic_mapping are included in the response.

        with_scope=True: also fetches per-entry scope member (install targets).
        Use this for policy tables like central/dnat that support per-entry
        installation targets.
        """
        all_entries = []
        offset = 0
        page_size = 500

        while True:
            params = {"url": url}
            if with_scope:
                # scope member option — no range, fetch all at once
                params["option"] = "scope member"
            else:
                params["range"] = [offset, page_size]

            resp = self._call("get", [params])
            result = resp.get("result", [{}])
            status = result[0].get("status", {})
            code = status.get("code", -1)

            if code != 0:
                return [], code

            data = result[0].get("data", [])
            if not data:
                break
            if not isinstance(data, list):
                # Single object returned (shouldn't happen for tables)
                all_entries.append(data)
                break

            all_entries.extend(data)
            # No pagination when using scope member option
            if with_scope or len(data) < page_size:
                break
            offset += page_size

        return all_entries, 0

    def get_pblocks(self, adom: str) -> list[dict]:
        """Return all policy blocks in an ADOM."""
        url  = f"/pm/pblock/adom/{adom}"
        resp = self._call("get", [{"url": url, "fields": ["name"]}])
        data = resp.get("result", [{}])[0].get("data", [])
        if not isinstance(data, list):
            data = [data] if data else []
        return [{"name": p.get("name", ""), "path": p.get("name", "")}
                for p in data if p.get("name")]

    def get_packages(self, adom: str) -> list[dict]:
        """
        Return all policy packages in an ADOM as a flat list.
        Each entry has: name, path (full pkg_name_path), type, subpkgs.
        Folders are traversed recursively so nested packages are included.
        """
        def _traverse(url: str, parent_path: str = "") -> list[dict]:
            resp   = self._call("get", [{"url": url}])  # no fields filter — get everything
            result = resp.get("result", [{}])
            data   = result[0].get("data", [])
            if not isinstance(data, list):
                data = [data] if data else []
            pkgs = []
            for p in data:
                name      = p.get("name", "")
                pkg_type  = p.get("type", "pkg")
                full_path = f"{parent_path}/{name}" if parent_path else name
                pkgs.append({
                    "name":             name,
                    "path":             full_path,
                    "type":             pkg_type,
                    "package settings": p.get("package settings", {}),
                    "scope member":     p.get("scope member", []),
                })
                # Recurse into folders
                if pkg_type == "folder":
                    sub_url = f"{url}/{name}"
                    pkgs.extend(_traverse(sub_url, full_path))
            return pkgs

        if adom == "rootp":
            base_url = "/pm/pkg/global"
        else:
            base_url = f"/pm/pkg/adom/{adom}"
        return _traverse(base_url)

    def get_sys_status(self) -> tuple[str, bool]:
        """
        Returns (version_string, adom_enabled).
        adom_enabled is False when 'Admin Domain Configuration' == 'Disabled'.
        """
        resp = self._call("get", [{"url": "/sys/status"}])
        result = resp.get("result", [{}])
        data = result[0].get("data", {})
        version = data.get("Version", "unknown")
        adom_cfg = data.get("Admin Domain Configuration", "Enabled")
        adom_enabled = adom_cfg.strip().lower() != "disabled"
        return version, adom_enabled


# Progress bar shown during extraction and restore

class Progress:
    def __init__(self, total: int):
        self.total = total
        self.done = 0
        self.ok = 0
        self.skipped = 0
        self.errors = 0
        self._start = time.time()

    def tick(self, name: str, count: int, code: int) -> None:
        self.done += 1
        if code == 0:
            self.ok += 1
        elif code in (-3, -6, -10):  # object does not exist / not found / not licensed
            self.skipped += 1
        else:
            self.errors += 1

        bar_width = 30
        filled = int(bar_width * self.done / self.total)
        bar = "█" * filled + "░" * (bar_width - filled)
        pct = 100 * self.done // self.total

        if code == 0:
            status = green(f"{count:>5} entries")
        elif code in (-3, -6, -10):
            status = dim("  N/A")
        else:
            status = red(f"  err {code}")

        name_col = name[:42].ljust(42)
        print(f"\r  [{bar}] {pct:>3}%  {cyan(name_col)} {status}   ", end="", flush=True)

    def summary(self) -> None:
        elapsed = time.time() - self._start
        print()  # newline after progress bar
        print(f"\n  Completed in {elapsed:.1f}s  |  "
              f"{green(str(self.ok))} fetched  "
              f"{dim(str(self.skipped))} N/A  "
              f"{red(str(self.errors))} errors")


# Extraction logic

def build_url(tbl: dict, adom: str) -> str:
    """
    Build the API URL for a given table and ADOM.
    'rootp' (Global Policy ADOM) uses /pm/config/global/obj/ instead of
    /pm/config/adom/rootp/obj/ — this matches what FortiManager itself sends.
    """
    if adom == "rootp":
        return tbl["url"].replace("/pm/config/adom/{adom}/obj/", "/pm/config/global/obj/")
    return tbl["url"].format(adom=adom)


def extract_adom(client: FMGClient, adom: str, tables: list[dict],
                 progress: Progress) -> dict:
    """Fetch all tables for one ADOM. Returns {table_name: [entries]}."""
    result = {}
    for tbl in tables:
        url = build_url(tbl, adom)
        entries, code = client.get_table(url)
        progress.tick(f"[{display_name(adom)}] {tbl['name']}", len(entries), code)
        if code == 0:
            result[tbl["name"]] = entries
    return result


def run_extraction(client: FMGClient, adoms: list[str],
                   tables: list[dict], fmg_version: str = "") -> dict:
    """Extract all tables for all ADOMs."""
    total_ops = len(adoms) * len(tables)
    prog = Progress(total_ops)

    print(f"\n  Extracting {bold(str(len(tables)))} object types "
          f"across {bold(str(len(adoms)))} ADOM(s) "
          f"({bold(str(total_ops))} requests)\n")

    output = {
        "metadata": {
            "extracted_at":      datetime.now(timezone.utc).isoformat(),
            "fmg_version":       fmg_version,
            "adoms":             adoms,
            "tables_queried":    len(tables),
            "adom_tables":       len([t for t in tables if t in ADOM_TABLES]),
            "controller_tables": len([t for t in tables if t in CONTROLLER_TABLES]),
        },
        "data": {}
    }

    for adom in adoms:
        output["data"][adom] = extract_adom(client, adom, tables, prog)

    prog.summary()
    return output


# Output file writers

def _sanitize_filename(name: str) -> str:
    """Replace characters that are unsafe in filenames."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def write_json_per_adom(data: dict, out_stem: str, no_csv: bool) -> None:
    """Write one JSON (and optionally one CSV) file per ADOM."""
    import csv
    for adom, tables in data["data"].items():
        safe = _sanitize_filename(display_name(adom))

        # Build a self-contained payload for this ADOM
        adom_payload = {
            "metadata": {
                **{k: v for k, v in data["metadata"].items() if k != "adoms"},
                "adom": adom,
                "fmg_version": data.get("metadata", {}).get("fmg_version", ""),
            },
            "data": {adom: tables},
        }

        # JSON
        json_path = f"{out_stem}_{safe}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(adom_payload, f, indent=2, default=str)
        size_kb = os.path.getsize(json_path) / 1024
        print(f"  {green('✓')} JSON  → {bold(json_path)}  ({size_kb:.0f} KB)")

        # CSV
        if not no_csv:
            rows = []
            for table_name, entries in tables.items():
                for entry in entries:
                    rows.append({
                        "adom": adom,
                        "table": table_name,
                        "name": entry.get("name", entry.get("id", "")),
                        "data": json.dumps(entry, default=str),
                    })
            csv_path = f"{out_stem}_{safe}.csv"
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["adom", "table", "name", "data"])
                writer.writeheader()
                writer.writerows(rows)
            size_kb = os.path.getsize(csv_path) / 1024
            print(f"  {green('✓')} CSV   → {bold(csv_path)}  ({size_kb:.0f} KB)  "
                  f"({len(rows)} rows)")


def write_summary(data: dict) -> None:
    """Print a quick count summary to stdout."""
    print(f"\n  {'ADOM':<20} {'Table':<45} {'Count':>6}")
    print("  " + "─" * 75)
    for adom, tables in data["data"].items():
        label = display_name(adom)
        for tbl, entries in sorted(tables.items()):
            if entries:
                print(f"  {label:<20} {tbl:<45} {green(str(len(entries))):>6}")
    print()


# CLI prompt helpers

def prompt(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"  {label}{suffix}: ").strip()
    return val or default


def prompt_password(label: str = "Password") -> str:
    """
    Read a password with masking.
    - Real terminals: uses getpass.getpass() — no echo at all.
    - PyCharm / non-TTY on Windows: uses msvcrt to echo '*' per character.
    - PyCharm / non-TTY on other OS: falls back to plain input() with warning.
    """
    import getpass
    prompt = f"  {label}: "

    in_pycharm = (
        "PYCHARM_HOSTED" in os.environ
        or "PYDEV_CONSOLE_EXECUTE_HOOK" in os.environ
    )

    # Try standard getpass first (works on real TTY everywhere)
    if not in_pycharm:
        try:
            return getpass.getpass(prompt)
        except Exception:
            pass  # fall through to platform-specific fallback

    # PyCharm / non-TTY: use msvcrt on Windows for star-masked input
    if os.name == "nt":
        try:
            import msvcrt
            sys.stdout.write(prompt)
            sys.stdout.flush()
            chars = []
            while True:
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):   # Enter
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    break
                elif ch == "\x08":       # Backspace
                    if chars:
                        chars.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                elif ch == "\x03":       # Ctrl-C
                    raise KeyboardInterrupt
                elif ch >= " ":          # printable character
                    chars.append(ch)
                    sys.stdout.write("*")
                    sys.stdout.flush()
            return "".join(chars)
        except Exception:
            pass  # fall through to plain input

    # Last resort: plain input with warning
    print(f"  {yellow('⚠  Masked input not available in this terminal.')}")
    print(f"  {dim('Use PyCharm Terminal tab (Alt+F12) for hidden input.')}")
    return input(prompt)


def print_banner() -> None:
    print()
    print(bold("  ╔══════════════════════════════════════════════════╗"))
    print(bold("  ║   FortiManager ADOM Object Extractor v1.0        ║"))
    print(bold("  ║   FMG 7.6.6 · 288 object types · JSON-RPC API    ║"))
    print(bold("  ╚══════════════════════════════════════════════════╝"))
    print()
    print()


ALL_TABLES = ADOM_TABLES + CONTROLLER_TABLES
ALL_CATEGORIES = sorted(set(t["name"].split("/")[0] for t in ALL_TABLES))


def select_tables(category_filter: str | None) -> list[dict]:
    if category_filter:
        selected = [t for t in ALL_TABLES
                    if t["name"].split("/")[0] == category_filter]
        if not selected:
            print(red(f"  Unknown category '{category_filter}'."))
            print(f"  Available: {', '.join(ALL_CATEGORIES)}")
            sys.exit(1)
        return selected
    return ALL_TABLES


def display_name(adom: str) -> str:
    """Map internal ADOM names to user-friendly display names."""
    return "Global" if adom == "rootp" else adom


def select_adoms(client: FMGClient, adom_filter: str | None,
                 adom_enabled: bool) -> list[str]:
    """
    Always presents a numbered picker so the user confirms their selection.
    - When ADOMs are disabled, the list contains only ['root'].
    - 'rootp' is shown as 'Global (Global Policy)' but kept as 'rootp' internally.
    - Only FortiOS-family ADOMs are listed (filtered in get_adoms).
    """
    print(f"  {dim('Fetching ADOM list...')}", end=" ", flush=True)

    if adom_enabled:
        raw_adoms = client.get_adoms()
        names     = [a["name"] for a in raw_adoms]
        if "root" not in names:
            raw_adoms = [{"name": "root", "version": ""}] + raw_adoms
    else:
        raw_adoms = [{"name": "root", "version": ""}]

    all_adoms = [a["name"]    for a in raw_adoms]
    adom_vers = [a["version"] for a in raw_adoms]

    print(green(f"{len(all_adoms)} found"))

    if not adom_enabled:
        print(f"  {dim('Admin Domain Configuration: Disabled')}")

    # --adom CLI flag: validate and return immediately without showing picker
    if adom_filter:
        if adom_filter not in all_adoms:
            print(red(f"  ADOM '{adom_filter}' not found on this FortiManager."))
            print(f"  Available: {', '.join(display_name(a) for a in all_adoms)}")
            sys.exit(1)
        print(f"  Selected: {cyan(display_name(adom_filter))}")
        return [adom_filter]

    # Always show the picker — never auto-select
    labels = [display_name(n) for n in all_adoms]
    notes  = []
    for n, ver in zip(all_adoms, adom_vers):
        parts = []
        if n == "rootp":
            parts.append("Global Policy")
        if not adom_enabled:
            parts.append("ADOMs disabled")
        if ver:
            parts.append(f"v{ver}")
        notes.append("  ".join(parts))
    col_idx  = max(len(str(len(all_adoms))), 1)
    col_name = max(len("ADOM Name"), max(len(l) for l in labels))
    col_note = max((len(nt) for nt in notes if nt), default=0)
    col_note = max(len("Note"), col_note)
    sep      = "  "
    divider  = "─" * (col_idx + len(sep) + col_name + len(sep) + col_note)
    print()
    print(f"  {'#':<{col_idx}}{sep}{'ADOM Name':<{col_name}}{sep}Note")
    print("  " + divider)
    for i, (name, label, note) in enumerate(zip(all_adoms, labels, notes), 1):
        idx_col  = cyan(str(i).ljust(col_idx))
        name_col = label.ljust(col_name)
        note_col = dim(note) if note else ""
        print(f"  {idx_col}{sep}{name_col}{sep}{note_col}")
    print()
    print(f"  Enter numbers or names  (e.g. {dim('1,3')} or {dim('root,FortiFirewall')})")
    print(f"  Press {dim('Enter')} or type {dim('all')} to select all.")
    print(f"  Type {dim('back')} to return to the main menu.")
    print()

    while True:
        raw = input("  Selection > ").strip()

        if raw.lower() in ("back", "b", "q"):
            return None  # caller should treat None as "go back"

        if raw == "" or raw.lower() == "all":
            print(f"  Selected: {cyan('all ' + str(len(all_adoms)) + ' ADOM(s)')}")
            return all_adoms

        # Parse tokens: real ADOM name checked first (handles numeric ADOM names
        # like "72" or "74" that would otherwise be misread as index numbers),
        # then friendly aliases, then fall back to treating as a row index.
        selected = []
        invalid = []
        for token in (t.strip() for t in raw.split(",") if t.strip()):
            if token in all_adoms:                                # exact name match (first!)
                selected.append(token)
            elif token.lower() == "global" and "rootp" in all_adoms:  # friendly alias
                selected.append("rootp")
            elif token.isdigit():                                 # row index fallback
                idx = int(token) - 1
                if 0 <= idx < len(all_adoms):
                    selected.append(all_adoms[idx])
                else:
                    invalid.append(token)
            else:
                invalid.append(token)

        if invalid:
            print(red(f"  Unknown selection(s): {', '.join(invalid)} — try again."))
            continue
        if not selected:
            print(red("  Nothing selected — try again."))
            continue

        # Deduplicate while preserving order
        seen: set = set()
        selected = [x for x in selected if not (x in seen or seen.add(x))]
        print(f"  Selected: {cyan(', '.join(display_name(a) for a in selected))}")
        return selected


def _print_divider(label: str = "") -> None:
    if label:
        pad = "─" * 2
        print(f"  {dim(pad + ' ' + label + ' ' + '─' * max(0, 52 - len(label)))}")
    else:
        print("  " + dim("─" * 56))


def _show_category_list() -> None:
    """Print the two-section category list (ADOM Objects / Controller Config)."""
    adom_cats = sorted(set(t["name"].split("/")[0] for t in ADOM_TABLES))
    ctrl_cats = sorted(set(t["name"].split("/")[0] for t in CONTROLLER_TABLES))
    all_cats  = adom_cats + ctrl_cats

    col_idx  = len(str(len(all_cats)))
    col_name = max(len(c) for c in all_cats)
    sep      = "  "

    _print_divider("ADOM Objects")
    for i, cat in enumerate(adom_cats, 1):
        count = sum(1 for t in ADOM_TABLES if t["name"].split("/")[0] == cat)
        print(f"  {cyan(str(i).ljust(col_idx))}{sep}{cat.ljust(col_name)}{sep}"
              f"{dim(str(count) + (' table' if count == 1 else ' tables'))}")

    print()
    _print_divider("Controller Config")
    for i, cat in enumerate(ctrl_cats, len(adom_cats) + 1):
        count = sum(1 for t in CONTROLLER_TABLES if t["name"].split("/")[0] == cat)
        print(f"  {cyan(str(i).ljust(col_idx))}{sep}{cat.ljust(col_name)}{sep}"
              f"{dim(str(count) + (' table' if count == 1 else ' tables'))}")

    return adom_cats + ctrl_cats


def _show_table_list(cat: str) -> list[dict]:
    """Print all tables in a category and return them."""
    tables = [t for t in ALL_TABLES if t["name"].split("/")[0] == cat]
    col_idx = len(str(len(tables)))
    col_name = max(len(t["name"]) for t in tables)
    print()
    _print_divider(f"{cat}  ({len(tables)} tables)")
    for i, t in enumerate(tables, 1):
        desc = dim("  " + t["description"][:55]) if t["description"] else ""
        print(f"  {cyan(str(i).ljust(col_idx))}  {t['name'].ljust(col_name)}{desc}")
    print()
    return tables


def select_tables_interactive(_unused: list[dict] | None = None) -> list[dict] | None:
    """
    Multi-step interactive table picker:
      Step 1 — All objects  OR  Selective
      Step 2 — Category list  (if selective)
      Step 3 — All tables in category  OR  pick specific table(s) / range
    At every step typing 'back' goes up one level; 'back' at step 1 returns None.
    """
    adom_cats = sorted(set(t["name"].split("/")[0] for t in ADOM_TABLES))
    ctrl_cats = sorted(set(t["name"].split("/")[0] for t in CONTROLLER_TABLES))
    all_cats  = adom_cats + ctrl_cats

    # ── Step 1: All or Selective ───────────────────────────────────────────────
    while True:
        print()
        print(bold("  Export scope"))
        print()
        print(f"  {cyan('1')}  All objects      {dim(str(len(ALL_TABLES)) + ' tables across ' + str(len(all_cats)) + ' categories')}")
        print(f"  {cyan('2')}  Selective export {dim('choose category then tables')}")
        print()
        print(f"  Type {dim('back')} to return to the main menu.")
        print()
        raw = input("  Selection > ").strip().lower()

        if raw in ("back", "b", "q"):
            return None

        if raw in ("1", "all"):
            print(f"  Scope: {cyan('all')}  ({len(ALL_TABLES)} tables)")
            return ALL_TABLES

        if raw in ("2", "selective", "s"):
            break   # proceed to category picker

        print(red("  Please enter 1 or 2."))

    # ── Step 2: Category picker ────────────────────────────────────────────────
    while True:
        print()
        print(bold("  Select category"))
        print()
        all_cats = _show_category_list()  # returns the full list
        print()
        print(f"  Enter a {dim('number')} to pick a category.")
        print(f"  Type {dim('back')} to go back.")
        print()

        raw = input("  Selection > ").strip()

        if raw.lower() in ("back", "b", "q"):
            break   # back to step 1

        # Resolve to a category
        cat = None
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(all_cats):
                cat = all_cats[idx]
            else:
                print(red(f"  Number out of range (1–{len(all_cats)})."))
                continue
        elif raw in all_cats:
            cat = raw
        else:
            print(red(f"  Unknown category '{raw}' — try again."))
            continue

        # ── Step 3: Table picker within category ──────────────────────────────
        while True:
            cat_tables = _show_table_list(cat)
            n = len(cat_tables)

            print(f"  {cyan('0')}  All {n} tables in {bold(cat)}")
            print()
            print(f"  Enter {dim('0')} for all, a {dim('number')}, or a {dim('range')} like {dim('1-5')}.")
            print(f"  You can also combine: {dim('1,3,5-8')}")
            print(f"  Type {dim('back')} to go back to categories.")
            print()

            raw2 = input("  Selection > ").strip()

            if raw2.lower() in ("back", "b", "q"):
                break   # back to category picker

            if raw2 == "0" or raw2.lower() == "all" or raw2 == "":
                print(f"  Scope: {cyan(cat)}  (all {n} tables)")
                return cat_tables

            # Parse numbers and ranges e.g. "1,3,5-8"
            selected: list[dict] = []
            invalid:  list[str]  = []
            seen_idx: set        = set()

            for token in (t.strip() for t in raw2.split(",") if t.strip()):
                # Range e.g. "2-5"
                if "-" in token:
                    parts = token.split("-", 1)
                    if parts[0].isdigit() and parts[1].isdigit():
                        lo, hi = int(parts[0]) - 1, int(parts[1]) - 1
                        if 0 <= lo <= hi < n:
                            for idx in range(lo, hi + 1):
                                if idx not in seen_idx:
                                    seen_idx.add(idx)
                                    selected.append(cat_tables[idx])
                        else:
                            invalid.append(token)
                    else:
                        invalid.append(token)
                elif token.isdigit():
                    idx = int(token) - 1
                    if 0 <= idx < n:
                        if idx not in seen_idx:
                            seen_idx.add(idx)
                            selected.append(cat_tables[idx])
                    else:
                        invalid.append(token)
                else:
                    # Try exact table name
                    match = [t for t in cat_tables if t["name"] == token]
                    if match:
                        for t in match:
                            if id(t) not in seen_idx:
                                seen_idx.add(id(t))
                                selected.append(t)
                    else:
                        invalid.append(token)

            if invalid:
                print(red(f"  Unknown: {', '.join(invalid)} — try again."))
                continue
            if not selected:
                print(red("  Nothing selected — try again."))
                continue

            names = ", ".join(t["name"] for t in selected)
            print(f"  Scope: {cyan(names)}  ({len(selected)} table(s))")
            return selected

    # User went back from category step — loop back to step 1
    return select_tables_interactive()


# Entry point

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract all ADOM-level objects from FortiManager via JSON-RPC API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Categories available:
  {', '.join(CATEGORIES)}

Examples:
  python3 fmg_adom_extractor.py
  python3 fmg_adom_extractor.py --host 10.0.0.1 --user admin
  python3 fmg_adom_extractor.py --adom root --category firewall
  python3 fmg_adom_extractor.py --out /tmp/backup.json --no-csv
  python3 fmg_adom_extractor.py --list-categories
        """
    )
    p.add_argument("--host",     help="FortiManager IP or hostname")
    p.add_argument("--port",     type=int, default=443, help="HTTPS port (default: 443)")
    p.add_argument("--user",     help="API username")
    p.add_argument("--password", help="Password (omit to prompt securely)")
    p.add_argument("--adom",     help="Extract only this ADOM (default: all)")
    p.add_argument("--category", help="Extract only this category (e.g. firewall, wireless-controller). Covers both ADOM and Controller tables.")
    p.add_argument("--out",      default="", help="Output JSON filename (default: auto-generated)")
    p.add_argument("--no-csv",   action="store_true", help="Skip CSV export")
    p.add_argument("--no-summary", action="store_true", help="Skip count summary")
    p.add_argument("--verify-ssl", action="store_true", help="Verify TLS certificate")
    p.add_argument("--list-categories", action="store_true",
                   help="Print all available categories and exit")
    return p.parse_args()


def run_once(client: FMGClient, adoms: list[str], tables: list[dict],
             args: argparse.Namespace) -> bool:
    """
    Extract the given adoms/tables and save output.
    Returns True on completion, False on error.
    """

    # Run extraction
    fmg_version, _ = client.get_sys_status()
    result = run_extraction(client, adoms, tables, fmg_version)

    # Save one file per ADOM
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_stem = args.out.rstrip(".json") if args.out else f"fmg_adom_objects_{timestamp}"

    print(f"\n  {bold('Saving output...')}")
    write_json_per_adom(result, out_stem, no_csv=args.no_csv)

    if not args.no_summary:
        write_summary(result)

    print(green("  Done.\n"))
    return True


# Restore helpers (push objects to a target ADOM)

# Fields stripped from both the top-level object and each dynamic_mapping entry.
_PUSH_STRIP = {"oid", "obj-ver", "uuid", "_image-base64"}


def _push_clean(obj: dict) -> dict:
    """Strip server-generated fields from object and its dynamic_mapping entries."""
    cleaned = {k: v for k, v in obj.items() if k not in _PUSH_STRIP}
    if "dynamic_mapping" in cleaned and isinstance(cleaned["dynamic_mapping"], list):
        cleaned["dynamic_mapping"] = [
            {k: v for k, v in dm.items() if k not in _PUSH_STRIP}
            for dm in cleaned["dynamic_mapping"]
        ]
    return cleaned


# Maximum objects per set call.
# Higher = faster (fewer round trips) but FMG may reject very large payloads.
# 500 works well in practice; drop to 100 if you see errors.
_PUSH_CHUNK_SIZE = 500


def _push_table(client: FMGClient, table_name: str, entries: list,
                target_adom: str, dry_run: bool,
                progress_cb=None) -> tuple[int, int, list]:
    """
    Push all entries for one table using chunked set calls.
    Sends up to _PUSH_CHUNK_SIZE objects per request.
    If a chunk fails, falls back to one-by-one for that chunk only.
    progress_cb(pushed, errors, total) is called after each chunk.
    Returns (pushed, errors, failed_objects) where failed_objects is a list of
    {"name": ..., "code": ..., "message": ...} for each failed object.
    """
    if not entries:
        return 0, 0, []

    url      = build_url({"url": f"/pm/config/adom/{{adom}}/obj/{table_name}"}, target_adom)
    batch    = [_push_clean(e) for e in entries]
    failed   = []

    if dry_run:
        if progress_cb:
            progress_cb(len(batch), 0, len(batch))
        return len(batch), 0, []

    pushed = errors = 0

    # Send in chunks using set (creates if missing, overwrites if exists)
    for i in range(0, len(batch), _PUSH_CHUNK_SIZE):
        chunk = batch[i:i + _PUSH_CHUNK_SIZE]

        resp   = client._call("set", [{"url": url, "data": chunk}])
        result = resp.get("result", [{}])[0]
        code   = result.get("status", {}).get("code", -1)

        if code == 0:
            pushed += len(chunk)
        else:
            # Chunk failed — retry one-by-one to salvage what we can
            for obj in chunk:
                r    = client._call("set", [{"url": url, "data": [obj]}])
                res  = r.get("result", [{}])[0]
                code = res.get("status", {}).get("code", -1)
                if code == 0:
                    pushed += 1
                else:
                    errors += 1
                    failed.append({
                        "name":    obj.get("name", obj.get("id", "?")),
                        "code":    code,
                        "message": res.get("status", {}).get("message", ""),
                    })

        if progress_cb:
            progress_cb(pushed, errors, len(batch))

    return pushed, errors, failed


def _pick_restore_file() -> str:
    """List available extractor JSON files and let the user pick one."""
    candidates = sorted(
        f for f in os.listdir(".")
        if f.startswith("fmg_adom_objects") and f.endswith(".json")
    )
    if candidates:
        print()
        print(f"  Available extractor files in current directory:\n")
        for i, f in enumerate(candidates, 1):
            size_kb = os.path.getsize(f) / 1024
            print(f"    {cyan(str(i))}  {f}  {dim(f'({size_kb:.0f} KB)')}")
        print()
        raw = input("  Select file (number or full path): ").strip()
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(candidates):
                return candidates[idx]
        return raw
    return input("  Path to extractor JSON file: ").strip()


def _pick_source_adom_from_file(file_data: dict) -> str:
    """Pick which ADOM from the loaded JSON to use as source."""
    adoms = list(file_data.keys())
    if not adoms:
        print(red("  No ADOM data found in the JSON file."))
        sys.exit(1)
    if len(adoms) == 1:
        adom = adoms[0]
        print(f"  Source ADOM : {cyan(display_name(adom))} (only one in file)")
        return adom
    print(f"\n  ADOMs in file:")
    for i, a in enumerate(adoms, 1):
        print(f"    {cyan(str(i))}  {display_name(a)}")
    print()
    while True:
        raw = input("  Select source ADOM > ").strip()
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(adoms):
                return adoms[idx]
        if raw in adoms:
            return raw
        if raw.lower() == "global" and "rootp" in adoms:
            return "rootp"
        print(red("  Invalid selection — try again."))


def _pick_target_adom(client: FMGClient, source_version: str = "",
                      adom_enabled: bool = True) -> str:
    """Numbered ADOM picker for restore target; allows typing a new ADOM name."""
    if adom_enabled:
        raw_adoms = client.get_adoms()
        names     = [a["name"] for a in raw_adoms]
        if "root" not in names:
            raw_adoms = [{"name": "root", "version": ""}] + raw_adoms
    else:
        raw_adoms = [{"name": "root", "version": ""}]

    all_adoms = [a["name"]    for a in raw_adoms]
    adom_vers = [a["version"] for a in raw_adoms]

    labels = [display_name(a) for a in all_adoms]
    notes  = []
    for a, ver in zip(all_adoms, adom_vers):
        parts = []
        if a == "rootp":
            parts.append("Global Policy")
        if ver:
            parts.append(f"v{ver}")
        notes.append("  ".join(parts))

    col_idx  = max(len(str(len(all_adoms))), 1)
    col_name = max(len("ADOM Name"), max(len(l) for l in labels))
    col_note = max(len("Note"), max((len(n) for n in notes if n), default=0))
    sep      = "  "
    divider  = "─" * (col_idx + len(sep) + col_name + len(sep) + col_note)

    print()
    if source_version:
        import re as _re
        m     = _re.search(r'v(\d+\.\d+)', source_version)
        short = f"v{m.group(1)}" if m else source_version.split('-')[0]
        print(f"  {yellow('ℹ')}  Export was from FortiManager {cyan(short)}.")
        print(f"  {dim('Recommended: restore to a ' + short + ' ADOM.')}")
        print(f"  {dim('Other versions may work but could have schema compatibility issues.')}")
        print()
    print(f"  Select target ADOM  {dim('(or type a new name to create it)')}")
    print(f"  {'#':<{col_idx}}{sep}{'ADOM Name':<{col_name}}{sep}Note")
    print("  " + divider)
    for i, (name, lbl, note) in enumerate(zip(all_adoms, labels, notes), 1):
        print(f"  {cyan(str(i).ljust(col_idx))}{sep}{lbl:<{col_name}}{sep}{dim(note) if note else ''}")
    print()

    print(f"  Type {dim('back')} to go back.")
    print()
    while True:
        raw = input("  Selection > ").strip()
        if not raw:
            print(red("  Please enter a number or ADOM name."))
            continue
        if raw.lower() in ("back", "b", "q"):
            return None
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(all_adoms):
                chosen = all_adoms[idx]
                print(f"  Selected: {cyan(display_name(chosen))}")
                return chosen
            print(red(f"  Number out of range (1–{len(all_adoms)})."))
            continue
        if raw.lower() == "global" and "rootp" in all_adoms:
            print(f"  Selected: {cyan('Global')}")
            return "rootp"
        if raw in all_adoms:
            print(f"  Selected: {cyan(display_name(raw))}")
            return raw
        # New ADOM
        print(f"  ADOM {cyan(raw)} not found.")
        confirm = input(f"  Create new ADOM '{raw}'? [y/N]: ").strip().lower()
        if confirm in ("y", "yes"):
            return raw


def _ensure_adom(client: FMGClient, adom: str) -> None:
    """Create the ADOM if it does not already exist."""
    resp = client._call("get", [{"url": f"/dvmdb/adom/{adom}"}])
    code = resp.get("result", [{}])[0].get("status", {}).get("code", -1)
    if code == 0:
        return  # already exists
    print(f"  Creating ADOM {cyan(adom)} ...", end=" ", flush=True)
    resp = client._call("add", [{
        "url":  "/dvmdb/adom",
        "data": {
            "name":            adom,
            "restricted_prds": ["fos"],
            "desc":            f"Created by fmg_adom_extractor on "
                               f"{datetime.now(timezone.utc).isoformat()}",
        },
    }])
    code = resp.get("result", [{}])[0].get("status", {}).get("code", -1)
    if code == 0:
        print(green("OK"))
    else:
        print(red(f"failed (code {code})"))
        sys.exit(1)


def _write_push_report(results: dict, source_adom: str,
                       target_adom: str, dry_run: bool) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname     = f"fmg_push_report_{timestamp}.json"
    failed_tables = {k: v["failed"] for k, v in results.items()
                     if v.get("failed")}
    report    = {
        "metadata": {
            "pushed_at":   datetime.now(timezone.utc).isoformat(),
            "source_adom": source_adom,
            "target_adom": target_adom,
            "dry_run":     dry_run,
        },
        "summary": {
            "tables":        len(results),
            "total_objects": sum(v["total"]  for v in results.values()),
            "pushed":        sum(v["pushed"] for v in results.values()),
            "errors":        sum(v["errors"] for v in results.values()),
        },
        "results": {k: {kk: vv for kk, vv in v.items() if kk != "failed"}
                    for k, v in results.items()},
        "failed_objects": failed_tables,
    }
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    size_kb = os.path.getsize(fname) / 1024
    print(f"  {green('✓')} Report → {bold(fname)}  ({size_kb:.0f} KB)")


def _print_obj_config(entry: dict) -> None:
    """Pretty-print a single FMG object config with colour and indentation."""
    _SKIP = {"oid", "obj-ver", "dirty", "_image-base64"}

    def _fmt_val(v, indent=4) -> str:
        """Recursively format a value with indentation."""
        pad = " " * indent
        if isinstance(v, list):
            if not v:
                return dim("[]")
            if all(isinstance(i, (str, int, float, bool)) for i in v):
                return dim(", ".join(str(i) for i in v))
            # Complex list — each item indented as a block
            lines = []
            for item in v:
                if isinstance(item, dict):
                    item_lines = _fmt_dict(item, indent)
                    lines.append(item_lines)
                else:
                    lines.append(pad + dim(str(item)))
            return "\n" + "\n".join(lines)
        elif isinstance(v, dict):
            if not v:
                return dim("{}")
            return "\n" + _fmt_dict(v, indent)
        elif v is None:
            return dim("null")
        else:
            return str(v)

    def _fmt_dict(d: dict, indent: int) -> str:
        """Format a dict as indented key-value lines, skipping read-only fields."""
        pad  = " " * indent
        keys = [k for k in d if k not in _SKIP and d[k] not in (None, [], "")]
        if not keys:
            return ""
        col  = max(len(k) for k in keys)
        lines = []
        for k in keys:
            v = d[k]
            lines.append(f"{pad}{cyan(k.ljust(col))}  {_fmt_val(v, indent + 4)}")
        return "\n".join(lines)

    # Top-level: skip read-only and empty, align by longest key
    keys = [k for k in entry if k not in _SKIP and entry[k] not in (None, [], "")]
    col  = max((len(k) for k in keys), default=10)
    for k in keys:
        formatted = _fmt_val(entry[k])
        print(f"    {cyan(k.ljust(col))}  {formatted}")


def _pick_objects(adom_data: dict, tables_selected: list[dict]) -> dict:
    """
    After table selection, ask whether to restore all objects in those tables
    or pick specific objects by name.

    Returns tables_to_push: {table_name: [entries]} ready to push.
    Never lists all objects unless user explicitly asks.
    """
    selected_names = {t["name"] for t in tables_selected}
    # Pre-filter to only tables that have data in the file
    available = {k: v for k, v in adom_data.items()
                 if v and k in selected_names}

    if not available:
        print(red("  No data found for selected tables in this file."))
        return {}

    total = sum(len(v) for v in available.values())

    # If multiple tables selected, skip individual object picker — ambiguous names
    if len(available) > 1:
        print()
        print(bold("  Object selection"))
        print()
        print(f"  {dim(f'{len(available)} tables selected — restoring all {total} objects.')}")
        print(f"  {dim('(Individual object selection is only available when a single table is selected.)')}")
        print()
        confirm = input(f"  Proceed with all objects? [{green('Y')}/back]: ").strip().lower()
        if confirm in ("back", "b", "q", "n", "no"):
            return None
        return available

    # Single table — offer individual object selection
    print()
    print(bold("  Object selection"))
    print()
    print(f"  {cyan('1')}  All objects in selected table  "
          f"{dim(f'({total} objects)')}")
    print(f"  {cyan('2')}  Specific objects by name  {dim('or list all objects')}")
    print()

    while True:
        raw = input("  Selection [1/2]: ").strip()
        if raw in ("back", "b", "q"):
            return None  # signal back
        if raw in ("1", "all", ""):
            return available
        if raw in ("2", "specific", "s"):
            break
        print(red("  Please enter 1 or 2."))

    # ── Specific object picker ────────────────────────────────────────────────
    print()
    print(f"  Enter object name(s) to restore, comma-separated.")
    print(f"  e.g. {dim('VLAN-226-10.246.215.0, test_address, admin')}")
    print(f"  Type {dim('list')} to list all objects  —  then {dim('view <number>')} to inspect config.")
    print(f"  Type {dim('back')} to go back.")
    print()

    result: dict[str, list] = {}   # {table_name: [filtered entries]}

    while True:
        raw = input("  Objects > ").strip()

        if raw.lower() in ("back", "b", "q"):
            return None

        # Handle "list" or "list <table>" command
        if raw.lower() == "list" or raw.lower().startswith("list "):
            tbl_filter = raw[5:].strip() if raw.lower().startswith("list ") else None
            tables_to_list = ({tbl_filter: available[tbl_filter]}
                              if tbl_filter and tbl_filter in available
                              else available if not tbl_filter
                              else None)
            if tables_to_list is None:
                print(red(f"  Table '{tbl_filter}' not in selection. "
                          f"Available: {', '.join(sorted(available))}"))
            else:
                # Build a flat index: number → (table, entry) for view command
                _listed: list[tuple[str, dict]] = []
                for tbl, entries in tables_to_list.items():
                    print(f"\n  {bold(tbl)}  ({len(entries)} objects)\n")
                    col = max((len(e.get("name", e.get("id", "?")))
                               for e in entries), default=4)
                    for i, e in enumerate(entries, 1):
                        name = e.get("name", e.get("id", "?"))
                        desc = e.get("comment", e.get("description", ""))[:55]
                        idx  = len(_listed) + 1
                        print(f"    {dim(str(idx).rjust(4))}  {name.ljust(col)}  {dim(desc)}")
                        _listed.append((tbl, e))
                print()
                print(f"  Type {dim('view <number>')} to see full config of an object.")
                print(f"  e.g. {dim('view 3')}")
                print()
                # Inner loop to handle view commands without re-prompting full Objects >
                while True:
                    view_raw = input("  view / Enter to continue > ").strip()
                    if view_raw == "":
                        break  # back to main Objects > prompt
                    if view_raw.lower().startswith("view "):
                        token = view_raw[5:].strip()
                        # Accept number or name
                        entry_to_view = None
                        if token.isdigit():
                            idx = int(token) - 1
                            if 0 <= idx < len(_listed):
                                entry_to_view = _listed[idx][1]
                            else:
                                print(red(f"  Number out of range (1–{len(_listed)})."))
                                continue
                        else:
                            # Search by name
                            for _, e in _listed:
                                if str(e.get("name", e.get("id", ""))) == token or                                    str(e.get("name", e.get("id", ""))).lower() == token.lower():
                                    entry_to_view = e
                                    break
                            if not entry_to_view:
                                print(red(f"  '{token}' not found in listed objects."))
                                continue
                        # Pretty-print the config
                        name = entry_to_view.get("name", entry_to_view.get("id", "?"))
                        print(f"\n  {bold(name)} — full config\n")
                        _print_obj_config(entry_to_view)
                        print()
                    else:
                        print(red("  Type 'view <number>' or press Enter to continue."))
            continue

        # Parse comma-separated object names.
        # Only search within the tables the user already selected.
        tokens = [t.strip() for t in raw.split(",") if t.strip()]

        for token in tokens:
            # Search for the object
            found_entry = None
            found_tbl   = None
            for tbl, entries in available.items():
                for e in entries:
                    obj_name = str(e.get("name", e.get("id", "")))
                    if obj_name == token or obj_name.lower() == token.lower():
                        found_entry = e
                        found_tbl   = tbl
                        break
                if found_entry:
                    break

            if not found_entry:
                print(red(f"  '{token}' not found in selected table. "
                          f"Type 'list' to browse objects."))
                continue

            obj_name = str(found_entry.get("name", found_entry.get("id", "?")))

            # ── Found — offer view or proceed ────────────────────────────────
            print(f"  Found: {cyan(obj_name)}")
            print()
            print(f"    {cyan('v')}  View config")
            print(f"    {cyan('r')}  Add to restore selection")
            print(f"    {cyan('s')}  Skip this object")
            print()

            while True:
                action = input(f"  Action [v/r/s]: ").strip().lower()

                if action in ("v", "view"):
                    # Pretty-print config
                    print(f"\n  {bold(obj_name)} — full config\n")
                    _print_obj_config(found_entry)
                    print()
                    # After viewing, ask again
                    print(f"    {cyan('r')}  Add to restore selection")
                    print(f"    {cyan('s')}  Skip this object")
                    print()
                    continue

                elif action in ("r", "restore", "y", ""):
                    if found_tbl not in result:
                        result[found_tbl] = []
                    existing = {str(x.get("name", x.get("id")))
                                for x in result[found_tbl]}
                    if obj_name not in existing:
                        result[found_tbl].append(found_entry)
                        print(green(f"  ✓ {obj_name} added to restore selection."))
                    else:
                        print(dim(f"  {obj_name} already in selection."))
                    break

                elif action in ("s", "skip", "n"):
                    print(dim(f"  Skipped {obj_name}."))
                    break

                else:
                    print(red("  Please enter v, r, or s."))

            print()

        if not result:
            continue  # loop back — user will enter another name

        # Show current selection summary
        total_sel = sum(len(v) for v in result.values())
        print(f"  Current selection: {cyan(str(total_sel))} object(s)")
        for tbl, objs in result.items():
            names = ", ".join(e.get("name", e.get("id", "?")) for e in objs)
            print(f"    {cyan(tbl)}: {dim(names)}")
        print()

        nxt = input(f"  [{green('Enter')} to continue adding  /  "
                    f"{cyan('done')} to proceed with restore  /  "
                    f"{dim('back')} to clear & restart]: ").strip().lower()

        if nxt in ("done", "d", "proceed", "p"):
            return result
        if nxt in ("back", "b"):
            result = {}
            continue
        # Enter or anything else — keep adding


def mode_restore(client: FMGClient, adom_enabled: bool = True,
                 dry_run: bool = False) -> None:
    """Interactive restore-from-file flow using the live client session."""

    # Select the JSON file to restore from
    json_file = _pick_restore_file()
    if not os.path.isfile(json_file):
        print(red(f"  File not found: {json_file}"))
        return

    print(f"\n  Loading {cyan(json_file)} ...", end=" ", flush=True)
    try:
        with open(json_file, encoding="utf-8") as f:
            payload = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(red(f"\n  ✗ {exc}"))
        return

    file_data = payload.get("data", {})
    if not file_data:
        print(red("\n  ✗ JSON file has no 'data' key or is empty."))
        return

    total_objs = sum(len(v) for tables in file_data.values()
                     for v in tables.values() if isinstance(v, list))
    print(green(f"OK  ({len(file_data)} ADOM(s), {total_objs} objects)"))

    # Pick which ADOM from the file to restore
    source_adom = _pick_source_adom_from_file(file_data)
    adom_data   = file_data[source_adom]

    # Pick target ADOM on the connected FMG
    source_version = payload.get("metadata", {}).get("fmg_version", "")
    target_adom    = _pick_target_adom(client, source_version, adom_enabled)
    if target_adom is None:
        return  # user went back
    _ensure_adom(client, target_adom)

    # Navigation loop — "back" at any step goes up one level
    step = 1  # 1=table scope, 2=object scope
    tables_selected = None
    tables_to_push  = None

    while True:
        print()
        print(bold("  " + "─" * 48))

        if step == 1:
            tables_selected = select_tables_interactive()
            if tables_selected is None:
                return  # back from table scope → exit restore entirely
            step = 2

        if step == 2:
            tables_to_push = _pick_objects(adom_data, tables_selected)
            if tables_to_push is None:
                # back from object scope → go back to table scope
                step = 1
                continue
            break  # both steps done

    # Show a summary and ask the user to confirm before pushing
    total_entries = sum(len(v) for v in tables_to_push.values())

    print()
    print(bold("  " + "─" * 48))
    print(f"  Source ADOM : {cyan(display_name(source_adom))}")
    print(f"  Target ADOM : {cyan(display_name(target_adom))}")
    print(f"  Tables      : {len(tables_to_push)}")
    print(f"  Objects     : {total_entries}")
    print()

    confirm = input(f"  Proceed with restore? [{green('Y')}/n/back]: ").strip().lower()
    if confirm in ("back", "b"):
        # back from confirm → go back to object scope
        step = 2
        while True:
            print()
            print(bold("  " + "─" * 48))
            if step == 2:
                tables_to_push = _pick_objects(adom_data, tables_selected)
                if tables_to_push is None:
                    step = 1
                    tables_selected = select_tables_interactive()
                    if tables_selected is None:
                        return
                    step = 2
                    continue
                break
        total_entries = sum(len(v) for v in tables_to_push.values())
        print()
        print(bold("  " + "─" * 48))
        print(f"  Source ADOM : {cyan(display_name(source_adom))}")
        print(f"  Target ADOM : {cyan(display_name(target_adom))}")
        print(f"  Tables      : {len(tables_to_push)}")
        print(f"  Objects     : {total_entries}")
        print()
        confirm = input(f"  Proceed with restore? [{green('Y')}/n]: ").strip().lower()

    if confirm in ("n", "no"):
        print(dim("  Cancelled."))
        return

    # Push objects to target ADOM
    total_tables  = len(tables_to_push)
    total_objects = sum(len(v) for v in tables_to_push.values())
    results       = {}
    done          = 0
    obj_done      = 0
    t_start       = time.time()
    bar_width     = 28

    def _render(t_done, t_total, o_pushed, o_errors, o_total, name, final=False):
        """Render one progress line. Clamps bar to 100%."""
        # Clamp so bar never exceeds 100%
        total_done_objs = min(obj_done + o_pushed + o_errors, total_objects)
        filled  = int(bar_width * total_done_objs / max(total_objects, 1))
        filled  = min(filled, bar_width)
        bar     = "█" * filled + "░" * (bar_width - filled)
        pct     = min(100, 100 * total_done_objs // max(total_objects, 1))

        elapsed_so_far = time.time() - t_start
        rate      = total_done_objs / elapsed_so_far if elapsed_so_far > 0 else 0
        remaining = max(0, total_objects - total_done_objs)
        eta_str   = f"ETA {remaining/rate:.0f}s" if rate > 1 and remaining > 0 else ""

        name_col = name[:36].ljust(36)
        if final:
            status = (green(f"{o_pushed:>4} pushed") if o_errors == 0
                      else f"{green(str(o_pushed))} ok {red(str(o_errors))} err")
            suffix = f"{status}  {dim(eta_str)}"
        else:
            chunk_pct = int(100 * (o_pushed + o_errors) / max(o_total, 1))
            suffix    = dim(f"{o_pushed+o_errors}/{o_total} ({chunk_pct}%)  {eta_str}")

        print(f"\r  [{bar}] {pct:>3}%  {cyan(name_col)} {suffix:<30}",
              end="", flush=True)

    print()
    for table_name, entries in tables_to_push.items():
        n = len(entries)

        # Show initial line before any requests fire
        _render(done, total_tables, 0, 0, max(n, 1), table_name)

        def make_cb(tname, n_entries):
            def cb(p, e, total):
                _render(done, total_tables, p, e, total, tname)
            return cb

        pushed, errors, failed = _push_table(client, table_name, entries, target_adom,
                                             False, progress_cb=make_cb(table_name, n))
        results[table_name] = {
            "pushed": pushed, "errors": errors, "total": n,
            "failed": failed,
        }
        obj_done += n
        done     += 1

        # Final line for this table — newline so each table stays visible
        _render(done, total_tables, pushed, errors, n, table_name, final=True)
        print()  # keep each table on its own line

    elapsed      = time.time() - t_start
    total_pushed = sum(v["pushed"] for v in results.values())
    total_errors = sum(v["errors"] for v in results.values())
    all_failed   = [(tbl, f) for tbl, v in results.items() for f in v.get("failed", [])]

    print(f"\n  Completed in {elapsed:.1f}s  |  "
          f"{green(str(total_pushed))} pushed  "
          f"{(red(str(total_errors)) if total_errors else dim('0'))} errors")

    # ── print error details on terminal if any ────────────────────────────────
    if all_failed:
        print()
        print(bold(f"  {red('✗')} Failed objects ({len(all_failed)}):"))
        print()

        # Group by table for readability
        by_table: dict = {}
        for tbl, f in all_failed:
            by_table.setdefault(tbl, []).append(f)

        for tbl, failures in by_table.items():
            print(f"  {cyan(tbl)}  ({len(failures)} error(s))")
            col = max((len(f['name']) for f in failures), default=4)
            for f in failures:
                msg = f.get('message', '') or f"code {f.get('code', '?')}"
                print(f"    {red('✗')}  {f['name'].ljust(col)}  {dim(msg)}")
            print()

    # Save push report
    print(f"  {bold('Saving report...')}")
    _write_push_report(results, source_adom, target_adom, False)
    print(green("  Done.\n"))



def _pick_packages(client: FMGClient, adom: str,
                   label: str = "Select policy package(s)") -> list[dict] | None:
    """
    Show all policy packages in the ADOM and let the user pick one, many, or all.
    Returns a list of package dicts, or None if the user goes back.
    Folders are shown but cannot be selected directly (their children can be).
    """
    print(f"  {dim('Fetching policy packages...')}", end=" ", flush=True)
    pkgs = client.get_packages(adom)
    actual = [p for p in pkgs if p["type"] != "folder"]

    if not actual:
        print(red("none found."))
        print(red(f"  No policy packages found in ADOM '{display_name(adom)}'."))
        return None

    print(green(f"{len(actual)} found"))
    print()
    print(bold(f"  {label}"))
    print()

    col = max(len(p["path"]) for p in actual)
    for i, p in enumerate(actual, 1):
        indent = "  " * p["path"].count("/")
        print(f"  {cyan(str(i).ljust(3))}  {indent}{p['path'].ljust(col)}")

    print()
    print(f"  Enter number(s), e.g. {dim('1')} or {dim('1,3')} — or press {dim('Enter')} for all.")
    print(f"  Type {dim('back')} to go back.")
    print()

    while True:
        raw = input("  Selection > ").strip()

        if raw.lower() in ("back", "b", "q"):
            return None

        if raw == "" or raw.lower() == "all":
            print(f"  Selected: {cyan('all')} ({len(actual)} packages)")
            return actual

        selected = []
        invalid  = []
        seen     = set()
        for token in (t.strip() for t in raw.split(",") if t.strip()):
            if token.isdigit():
                idx = int(token) - 1
                if 0 <= idx < len(actual):
                    if idx not in seen:
                        seen.add(idx)
                        selected.append(actual[idx])
                else:
                    invalid.append(token)
            elif token in [p["path"] for p in actual]:
                match = next(p for p in actual if p["path"] == token)
                if match["path"] not in seen:
                    seen.add(match["path"])
                    selected.append(match)
            else:
                invalid.append(token)

        if invalid:
            print(red(f"  Unknown: {', '.join(invalid)} — try again."))
            continue
        if not selected:
            print(red("  Nothing selected — try again."))
            continue

        names = ", ".join(p["path"] for p in selected)
        print(f"  Selected: {cyan(names)}")
        return selected


def _fetch_dos_anomalies(client: FMGClient, base_url: str,
                         dos_policies: list) -> list:
    """
    Fetch anomaly sub-tables for each DoS policy and embed them inline.
    FMG stores DoS anomaly rules at:
      /pm/config/adom/{adom}/pkg/{pkg}/firewall/DoS-policy/{policyid}/anomaly
    We embed them as "anomaly" inside each DoS policy entry so the full
    config is preserved and can be restored as a single unit.
    """
    enriched = []
    for pol in dos_policies:
        pid  = pol.get("policyid", pol.get("oid"))
        pol  = dict(pol)  # copy
        if pid is not None:
            anom_url             = f"{base_url}/{pid}/anomaly"
            anomalies, code      = client.get_table(anom_url)
            if code == 0 and anomalies:
                pol["_anomaly"] = anomalies
        enriched.append(pol)
    return enriched


def _fetch_package(client: FMGClient, adom: str, pkg: dict,
                   tables: list[dict]) -> dict:
    """
    Fetch all policy types for one package.
    Also fetches:
      - authentication/setting (single object, not a list)
      - DoS anomaly sub-tables embedded inside each DoS policy
    Returns {policy_type: entries_or_object}.
    """
    result = {}

    for tbl in tables:
        url = tbl["url"].format(adom=adom, pkg=pkg["path"])
        # Always fetch with scope member — captures per-policy install targets
        entries, code = client.get_table(url, with_scope=True)
        if code == 0 and entries:
            # Embed anomaly sub-tables into DoS policy entries
            if tbl["name"] in ("firewall/DoS-policy", "firewall/DoS-policy6"):
                base = url
                entries = _fetch_dos_anomalies(client, base, entries)
            result[tbl["name"]] = entries

    # Fetch per-package single objects (e.g. authentication/setting)
    # authentication/setting is only valid in profile-based ngfw-mode
    ngfw_mode = pkg.get("package settings", {}).get("ngfw-mode", "profile-based")
    for obj in POLICY_OBJECTS:
        if obj["name"] == "authentication/setting" and ngfw_mode == "policy-based":
            continue
        url  = obj["url"].format(adom=adom, pkg=pkg["path"])
        resp = client._call("get", [{"url": url}])
        data = resp.get("result", [{}])[0].get("data")
        if data and isinstance(data, dict):
            result[obj["name"]] = data  # single object, stored as dict not list

    return result


def mode_policy(client: FMGClient, adom_enabled: bool) -> None:
    """Mode 3 — Policy Package export / import."""

    while True:
        print()
        print(bold("  Policy Package"))
        print()
        print(f"  {cyan('1')}  Export policy packages  {dim('(save to JSON)')}")
        print(f"  {cyan('2')}  Import policy packages  {dim('(restore from JSON)')}")
        print()
        print(f"  Type {dim('back')} to return to the main menu.")
        print()

        raw = input("  Selection [1/2]: ").strip().lower()
        if raw in ("back", "b", "q"):
            return
        if raw in ("1", "export", "e"):
            _policy_export(client, adom_enabled)
        elif raw in ("2", "import", "i"):
            _policy_import(client, adom_enabled)
        else:
            print(red("  Please enter 1 or 2."))

        print("  " + "─" * 48)
        again = input(f"  Policy Package menu again? [{green('Y')}/n]: ").strip().lower()
        if again in ("n", "no", "q"):
            return


def _fetch_pblock_policies(client: FMGClient, adom: str, pblock_name: str) -> dict:
    """Fetch all supported policy types from a policy block."""
    result = {}
    for ptype in PBLOCK_POLICY_TYPES:
        url = f"/pm/config/adom/{adom}/pblock/{pblock_name}/{ptype['name']}"
        entries, code = client.get_table(url)
        if code == 0 and entries:
            result[ptype["name"]] = entries
    return result


def _policy_export(client: FMGClient, adom_enabled: bool) -> None:
    """Export policy packages and policy blocks from a source ADOM to JSON."""

    # Pick source ADOM
    print()
    print(bold("  " + "─" * 48))
    adoms = select_adoms(client, None, adom_enabled)
    if adoms is None or not adoms:
        return
    if len(adoms) > 1:
        print(yellow("  Policy export works one ADOM at a time. Using first selection."))
    adom = adoms[0]

    # Pick packages
    print()
    print(bold("  " + "─" * 48))
    packages = _pick_packages(client, adom, "Select packages to export")
    if packages is None:
        return

    # Pick policy types
    print()
    print(bold("  " + "─" * 48))
    tables = _pick_policy_types()
    if tables is None:
        return

    # Fetch policy blocks too
    print(f"  {dim('Fetching policy blocks...')}", end=" ", flush=True)
    pblocks = client.get_pblocks(adom)
    print(green(f"{len(pblocks)} found") if pblocks else dim("none"))

    print()
    total_pkgs = len(packages)
    print(f"  Exporting {bold(str(total_pkgs))} package(s) "
          f"x {bold(str(len(tables)))} policy type(s) "
          f"+ {bold(str(len(pblocks)))} policy block(s) "
          f"from ADOM {cyan(display_name(adom))}")
    print()

    output = {
        "metadata": {
            "exported_at":  datetime.now(timezone.utc).isoformat(),
            "fmg_version":  client.get_sys_status()[0],
            "source_adom":  adom,
            "packages":     [p["path"] for p in packages],
            "policy_types": [t["name"] for t in tables],
            "pblocks":      [p["name"] for p in pblocks],
        },
        "packages": packages,   # full metadata: name, path, type, package settings, scope member
        "data":    {},
        "pblocks": {},
    }

    bar_width = 30
    t_start   = time.time()
    total_pol = 0

    for i, pkg in enumerate(packages, 1):
        filled = int(bar_width * i / total_pkgs)
        bar    = "█" * filled + "░" * (bar_width - filled)
        pct    = 100 * i // total_pkgs
        print(f"\r  [{bar}] {pct:>3}%  {cyan(pkg['path'][:40].ljust(40))}",
              end="", flush=True)
        pkg_data = _fetch_package(client, adom, pkg, tables)
        output["data"][pkg["path"]] = pkg_data
        total_pol += sum(len(v) for v in pkg_data.values())

    if pblocks:
        print(f"\n  Exporting policy blocks...")
        for pb in pblocks:
            pb_data = _fetch_pblock_policies(client, adom, pb["name"])
            output["pblocks"][pb["name"]] = pb_data
            pb_count = sum(len(v) for v in pb_data.values())
            total_pol += pb_count
            print(f"    {cyan(pb['name']):<30} {pb_count} policies")

    elapsed = time.time() - t_start
    print(f"\n  Fetched {green(str(total_pol))} policies total in {elapsed:.1f}s")
    # Save file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_adom = _sanitize_filename(display_name(adom))
    fname     = f"fmg_policy_{timestamp}_{safe_adom}.json"

    with open(fname, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    size_kb = os.path.getsize(fname) / 1024
    print(f"  {green('✓')} Saved → {bold(fname)}  ({size_kb:.0f} KB)")


def _policy_import(client: FMGClient, adom_enabled: bool) -> None:
    """Import policy packages from a JSON file into a target ADOM."""

    # Dependency warning
    print()
    print(f"  {yellow('⚠  Important — dependency order')}")
    print(f"  {dim('Policy packages reference ADOM objects (addresses, VIPs, services, users, etc.)')}")
    print(f"  {dim('Make sure you have already imported ADOM objects into the target ADOM')}")
    print(f"  {dim('(Import → ADOM objects) before importing policies.')}")
    print(f"  {dim('If referenced objects are missing, policies will fail with "data not exist" errors.')}")
    print()
    confirm = input(f"  ADOM objects already imported? [{green('Y')} to continue / {dim('n')} to cancel]: ").strip().lower()
    if confirm in ("n", "no"):
        print(dim("  Cancelled. Please import ADOM objects first."))
        return
    print()

    # Pick file
    candidates = sorted(
        f for f in os.listdir(".")
        if f.startswith("fmg_policy") and f.endswith(".json")
    )
    if candidates:
        print()
        print(f"  Available policy export files:")
        for i, f in enumerate(candidates, 1):
            size_kb = os.path.getsize(f) / 1024
            print(f"    {cyan(str(i))}  {f}  {dim(f'({size_kb:.0f} KB)')}")
        print()
        raw = input("  Select file (number or path): ").strip()
        if raw.lower() in ("back", "b", "q"):
            return
        if raw.isdigit() and 1 <= int(raw) <= len(candidates):
            fname = candidates[int(raw) - 1]
        else:
            fname = raw
    else:
        fname = input("  Path to policy JSON file: ").strip()
        if not fname:
            return

    if not os.path.isfile(fname):
        print(red(f"  File not found: {fname}"))
        return

    print(f"  Loading {cyan(fname)} ...", end=" ", flush=True)
    with open(fname, encoding="utf-8") as f:
        payload = json.load(f)

    file_data = payload.get("data", {})
    meta      = payload.get("metadata", {})
    if not file_data:
        print(red("  No policy data found in file."))
        return

    total_pol = sum(len(v) for pkg in file_data.values()
                    for v in pkg.values() if isinstance(v, list))
    print(green(f"OK  ({len(file_data)} package(s), {total_pol} policies)"))

    src_version = meta.get("fmg_version", "")
    src_adom    = meta.get("source_adom", "")
    print(f"  Source ADOM : {cyan(display_name(src_adom))}")
    if src_version:
        print(f"  Source FMG  : {cyan(src_version)}")
    print()

    # Pick target ADOM
    print(bold("  " + "─" * 48))
    target_adom = _pick_target_adom(client, src_version, adom_enabled)
    if target_adom is None:
        return
    _ensure_adom(client, target_adom)

    # Pick target package (must exist or will be created)
    print()
    print(bold("  " + "─" * 48))
    print(f"  Packages in the export file:")
    pkg_paths = list(file_data.keys())
    for i, path in enumerate(pkg_paths, 1):
        pol_count = sum(len(v) for v in file_data[path].values()
                        if isinstance(v, list))
        print(f"    {cyan(str(i))}  {path}  {dim(str(pol_count) + ' policies')}")

    print()
    print(f"  {dim('All packages will be imported. Press Enter to confirm or type back.')}")
    raw = input("  > ").strip().lower()
    if raw in ("back", "b", "q"):
        return

    # Ensure each target package exists, then push policies
    print()
    bar_width   = 30
    total_pkgs  = len(pkg_paths)
    t_start     = time.time()
    pushed_all  = 0
    errors_all  = 0
    all_failed  = []

    def _push_policy_list(url, policies, context, tbl_name="", with_scope=True):
        nonlocal pushed_all, errors_all
        batch = []
        for p in policies:
            clean = {k: v for k, v in p.items() if k not in _POLICY_STRIP}
            if not with_scope:
                clean.pop("scope member", None)
            batch.append(clean)
        if not batch:
            return
        resp = client._call("set", [{"url": url, "data": batch}])
        code = resp.get("result", [{}])[0].get("status", {}).get("code", -1)
        if code == 0:
            pushed_all += len(batch)
        else:
            for pol in batch:
                r    = client._call("set", [{"url": url, "data": [pol]}])
                res  = r.get("result", [{}])[0]
                code = res.get("status", {}).get("code", -1)
                if code == 0:
                    pushed_all += 1
                else:
                    errors_all += 1
                    all_failed.append({
                        "context":  context,
                        "policyid": pol.get("policyid", pol.get("name", "?")),
                        "code":     code,
                        "message":  res.get("status", {}).get("message", ""),
                    })

    # Build a lookup: pkg_path -> pkg_meta (settings + scope member)
    pkg_meta_map = {p["path"]: p for p in payload.get("packages", [])}

    for pi, pkg_path in enumerate(pkg_paths, 1):
        pkg_data = file_data[pkg_path]
        pkg_meta = pkg_meta_map.get(pkg_path)

        # Try creating the package with full settings + scope member
        code = _ensure_policy_package(client, target_adom, pkg_path, pkg_meta,
                                      with_scope=True)

        # If it failed and there are scope members, the device probably doesn't
        # exist in the target ADOM. Ask if user wants to retry without scope.
        if code not in (0, None):
            scope_names = ([s.get("name", "?") for s in pkg_meta["scope member"]]
                           if pkg_meta and pkg_meta.get("scope member") else [])
            print()
            print(red(f"  ✗ Failed to create package '{pkg_path}' "
                      f"(code {code})."))
            if scope_names:
                print(yellow(f"  ⚠  This is likely because the installation "
                             f"target(s) {scope_names} don't exist in "
                             f"ADOM '{display_name(target_adom)}'."))
            choice = input(
                f"  Retry without installation target (scope member)? [{green('Y')}/n]: "
            ).strip().lower()
            if choice not in ("n", "no"):
                code = _ensure_policy_package(client, target_adom, pkg_path,
                                              pkg_meta, with_scope=False)
                if code not in (0, None):
                    print(red(f"  ✗ Still failed (code {code}). Skipping package."))
                    continue
            else:
                print(dim(f"  Skipping package '{pkg_path}' and its policies."))
                continue
            print()

        for tbl_name, data in pkg_data.items():
            if not data:
                continue

            url   = f"/pm/config/adom/{target_adom}/pkg/{pkg_path}/{tbl_name}"
            label = f"{pkg_path}/{tbl_name}"[:40].ljust(40)
            filled = int(bar_width * pi / total_pkgs)
            bar    = "█" * filled + "░" * (bar_width - filled)
            pct    = 100 * pi // total_pkgs

            # Single object (e.g. authentication/setting) — use set directly
            if isinstance(data, dict):
                # Strip read-only fields AND empty/null values — FMG rejects
                # some empty list fields on single-object endpoints
                clean = {k: v for k, v in data.items()
                         if k not in _POLICY_STRIP
                         and v is not None
                         and v != []}
                print(f"\r  [{bar}] {pct:>3}%  {cyan(label)}  {dim('(object)')}  ",
                      end="", flush=True)
                resp = client._call("set", [{"url": url, "data": clean}])
                code = resp.get("result", [{}])[0].get("status", {}).get("code", -1)
                msg  = resp.get("result", [{}])[0].get("status", {}).get("message", "")
                if code == 0:
                    pushed_all += 1
                elif code == -6 and "invalid url" in msg.lower():
                    # Target package doesn't support this object (e.g. authentication/setting
                    # not applicable for this ngfw-mode) — skip silently
                    pass
                else:
                    errors_all += 1
                    all_failed.append({
                        "context":  f"{pkg_path}/{tbl_name}",
                        "policyid": tbl_name,
                        "code":     code,
                        "message":  msg,
                    })
                continue

            # Table of policies
            print(f"\r  [{bar}] {pct:>3}%  {cyan(label)}  "
                  f"{dim(str(len(data)) + ' policies')}  ",
                  end="", flush=True)

            # For DoS policies, push anomaly sub-tables after the main policy
            if tbl_name in ("firewall/DoS-policy", "firewall/DoS-policy6"):
                for pol in data:
                    anomalies = pol.pop("_anomaly", None)
                    clean     = {k: v for k, v in pol.items() if k not in _POLICY_STRIP}
                    pid       = clean.get("policyid")
                    r    = client._call("set", [{"url": url, "data": [clean]}])
                    code = r.get("result", [{}])[0].get("status", {}).get("code", -1)
                    if code == 0:
                        pushed_all += 1
                    else:
                        errors_all += 1
                        all_failed.append({
                            "context":  f"{pkg_path}/{tbl_name}",
                            "policyid": pid or "?",
                            "code":     code,
                            "message":  r.get("result", [{}])[0].get("status", {}).get("message", ""),
                        })
                    if anomalies and pid is not None:
                        anom_url   = f"{url}/{pid}/anomaly"
                        anom_batch = [{k: v for k, v in a.items()
                                       if k not in _POLICY_STRIP} for a in anomalies]
                        client._call("set", [{"url": anom_url, "data": anom_batch}])
                continue

            # Push with scope member first
            prev_errors = errors_all
            _push_policy_list(url, data, f"{pkg_path}/{tbl_name}", tbl_name,
                              with_scope=True)
            new_errors = errors_all - prev_errors

            # If any failed and scope members are present in the data, offer retry
            if new_errors > 0 and any(p.get("scope member") for p in data):
                print()
                print(yellow(f"  ⚠  {new_errors} policy/ies failed in '{pkg_path}/{tbl_name}'."))
                print(f"  {dim('This may be because the installation target devices do not exist in the target ADOM.')}")
                retry = input(
                    f"  Retry without installation targets (scope member)? [{green('Y')}/n]: "
                ).strip().lower()
                if retry not in ("n", "no"):
                    # Reset the errors from failed scope attempt
                    errors_all  -= new_errors
                    pushed_all  -= (len(data) - new_errors)  # remove partial successes
                    all_failed   = [f for f in all_failed
                                    if f.get("context") != f"{pkg_path}/{tbl_name}"]
                    _push_policy_list(url, data, f"{pkg_path}/{tbl_name}", tbl_name,
                                      with_scope=False)

    # Restore policy blocks
    pblock_data = payload.get("pblocks", {})
    if pblock_data:
        print(f"\n  Importing {bold(str(len(pblock_data)))} policy block(s)...")
        for pb_name, pb_policies in pblock_data.items():
            pb_base = f"/pm/pblock/adom/{target_adom}"
            chk     = client._call("get", [{"url": f"{pb_base}/{pb_name}",
                                            "fields": ["name"]}])
            if chk.get("result", [{}])[0].get("status", {}).get("code", -1) != 0:
                client._call("add", [{"url": pb_base,
                                      "data": {"name": pb_name, "type": "pblock"}}])
            for tbl_name, policies in pb_policies.items():
                if not policies:
                    continue
                url = f"/pm/config/adom/{target_adom}/pblock/{pb_name}/{tbl_name}"
                print(f"    {cyan(pb_name)}/{tbl_name}  "
                      f"{dim(str(len(policies)) + ' policies')}")
                _push_policy_list(url, policies, f"pblock:{pb_name}/{tbl_name}", tbl_name)

    elapsed = time.time() - t_start
    print()
    print(f"\n  Completed in {elapsed:.1f}s  |  "
          f"{green(str(pushed_all))} pushed  "
          f"{(red(str(errors_all)) if errors_all else dim('0'))} errors")

    if all_failed:
        print()
        print(bold(f"  {red('x')} Failed policies ({len(all_failed)}):"))
        print()
        for f in all_failed:
            print(f"    {red('x')}  {f.get('context', '?')}  "
                  f"policyid={f['policyid']}  {dim(f['message'])}")
        print()

    print(green("  Done.\n"))



def _ensure_policy_package(client: FMGClient, adom: str, pkg_path: str,
                           pkg_meta: dict | None = None,
                           with_scope: bool = True) -> int:
    """
    Create a policy package (and any parent folders) if it doesn't exist.
    pkg_meta: the exported package dict containing 'package settings' and 'scope member'.
    with_scope: if False, scope member is omitted (used as fallback when device not found).
    Returns the status code of the final add call (0 = success).
    """
    if adom == "rootp":
        base = "/pm/pkg/global"
    else:
        base = f"/pm/pkg/adom/{adom}"

    # Strip read-only fields from package settings
    _PKG_STRIP = {"hitc-taskid", "hitc-timestamp"}
    pkg_settings = {}
    if pkg_meta and pkg_meta.get("package settings"):
        pkg_settings = {k: v for k, v in pkg_meta["package settings"].items()
                        if k not in _PKG_STRIP}

    parts  = pkg_path.split("/")
    built  = ""
    last_code = 0
    for i, part in enumerate(parts):
        built     = f"{built}/{part}" if built else part
        check_url = f"{base}/{built}"
        resp      = client._call("get", [{"url": check_url, "fields": ["name", "type"]}])
        code      = resp.get("result", [{}])[0].get("status", {}).get("code", -1)
        if code != 0:
            is_last    = (i == len(parts) - 1)
            parent_url = f"{base}/{'/'.join(parts[:i])}" if i > 0 else base
            data = {
                "name": part,
                "type": "folder" if not is_last else "pkg",
            }
            if is_last:
                if pkg_settings:
                    data["package settings"] = pkg_settings
                if with_scope and pkg_meta and pkg_meta.get("scope member"):
                    data["scope member"] = pkg_meta["scope member"]
            r = client._call("add", [{"url": parent_url, "data": data}])
            last_code = r.get("result", [{}])[0].get("status", {}).get("code", -1)
    return last_code


def _pick_policy_types() -> list[dict] | None:
    """Let the user choose which policy types to export."""
    print()
    print(bold("  Policy types to export"))
    print()
    print(f"  {cyan('0')}  All policy types  {dim(f'({len(POLICY_TABLES)} types)')}")
    print()

    # Group by category
    categories: dict[str, list] = {}
    for t in POLICY_TABLES:
        cat = t["name"].split("/")[0]
        categories.setdefault(cat, []).append(t)

    idx = 1
    cat_map: dict[str, list] = {}
    for cat, tables in categories.items():
        print(f"  {dim('── ' + cat + ' ──────────────────────────────────────────────')}")
        for t in tables:
            print(f"  {cyan(str(idx).ljust(3))}  {t['name']:<40}  {dim(t['description'][:50])}")
            cat_map[str(idx)] = [t]
            idx += 1
        print()

    print(f"  Enter {dim('0')} for all, or number(s) e.g. {dim('1,3,5')}.")
    print(f"  Type {dim('back')} to go back.")
    print()

    while True:
        raw = input("  Selection > ").strip()
        if raw.lower() in ("back", "b", "q"):
            return None
        if raw == "0" or raw.lower() == "all" or raw == "":
            print(f"  Scope: {cyan('all')} ({len(POLICY_TABLES)} policy types)")
            return POLICY_TABLES

        selected = []
        invalid  = []
        seen     = set()
        for token in (t.strip() for t in raw.split(",") if t.strip()):
            if token in cat_map and token not in seen:
                seen.add(token)
                selected.extend(cat_map[token])
            else:
                invalid.append(token)

        if invalid:
            print(red(f"  Unknown: {', '.join(invalid)} — try again."))
            continue
        if not selected:
            print(red("  Nothing selected — try again."))
            continue

        names = ", ".join(t["name"] for t in selected)
        print(f"  Scope: {cyan(names)}")
        return selected

# Mode selector shown after login


# IPsec template export uses action-list which contains everything nested
# under value["vpn ipsec phase1-interface"], value["system interface"], etc.
# On IMPORT however, FMG requires separate URLs for phase1 and phase2.
# The _push_template function handles this split automatically.
IPSEC_TEMPLATE_SUBS = [
    {"name": "action-list", "url": "action-list"},
]

# Secret fields nested inside action-list/value — masked by FMG as ["ENC","..."]
# Must be re-entered manually on the target FMG after import.
_IPSEC_SECRET_PATHS = [
    ("vpn ipsec phase1-interface", "psksecret"),
    ("vpn ipsec phase1-interface", "ppk-secret"),
    ("vpn ipsec phase1-interface", "group-authentication-secret"),
]

# SD-WAN overlay template sub-object
# URL: /pm/config/adom/{adom}/template/_sdwan_overlay/{name}/sdwan/overlay
SDWAN_OVERLAY_SUBS = [
    {"name": "sdwan/overlay", "url": "sdwan/overlay"},
]

_TMPL_STRIP = {"oid", "obj-ver", "uuid", "_image-base64"}


def _get_templates(client: FMGClient, adom: str, stype: str) -> list[dict]:
    """List all templates of a given stype (_ipsec or _sdwan_overlay)."""
    url  = f"/pm/template/{stype}/adom/{adom}"
    resp = client._call("get", [{"url": url}])
    data = resp.get("result", [{}])[0].get("data", [])
    if not isinstance(data, list):
        data = [data] if data else []
    return [t for t in data if t.get("name")]


def _fetch_template(client: FMGClient, adom: str, stype: str,
                    name: str, subs: list[dict]) -> dict:
    """
    Fetch a template and all its sub-objects.
    For IPsec templates, PSK and other secrets are masked by FMG as
    ["ENC", "..."] — these are flagged in metadata and must be
    re-entered manually after import.
    """
    result = {"name": name, "stype": stype, "subs": {}, "masked_secrets": []}
    for sub in subs:
        url = f"/pm/config/adom/{adom}/template/{stype}/{name}/{sub['url']}"
        entries, code = client.get_table(url)
        if code == 0 and entries:
            # For IPsec templates: secrets are nested inside entry["value"]
            if stype == "_ipsec" and sub["name"] == "action-list":
                for entry in entries:
                    val = entry.get("value", {}) or {}
                    for nested_key, secret_field in _IPSEC_SECRET_PATHS:
                        nested = val.get(nested_key, {}) or {}
                        v = nested.get(secret_field)
                        if isinstance(v, list) and v and v[0] == "ENC":
                            tunnel = val.get("name", "?")
                            result["masked_secrets"].append(
                                f"{sub['name']}/{tunnel}/{secret_field}"
                            )
            result["subs"][sub["name"]] = entries
    return result


def _push_template(client: FMGClient, adom: str, tmpl: dict,
                   subs: list[dict]) -> tuple[int, list]:
    """
    Create a template shell then push all sub-objects.

    For IPsec templates the import URL structure differs from export:
      Export: GET action-list returns everything nested in value
      Import: must push action-list, phase1, and phase2 via separate URLs
        - action-list  (tunnel basics + system interface)
        - vpn/ipsec/phase1-interface  (from value["vpn ipsec phase1-interface"])
        - vpn/ipsec/phase2-interface  (from value["vpn ipsec phase2-interface"])

    Masked PSK/secret fields are stripped — user must re-enter them manually.
    Returns (errors_count, failed_list).
    """
    stype  = tmpl["stype"]
    name   = tmpl["name"]
    errors = 0
    failed = []

    # Warn about masked secrets
    masked = tmpl.get("masked_secrets", [])
    if masked:
        print()
        print(yellow(f"  ⚠  Template '{name}' has masked secret field(s):"))
        for m in masked:
            print(f"     {dim(m)}")
        print(f"  {dim('Set them manually on the target FMG after import.')}")
        print()

    # Create the template shell (with widgets for IPsec)
    base_url = f"/pm/template/{stype}/adom/{adom}"
    shell_setting = {"stype": stype}
    if stype == "_ipsec":
        shell_setting["widgets"] = [stype]
    shell = {"name": name, "type": "template", "template setting": shell_setting}
    resp = client._call("set", [{"url": base_url, "data": shell}])
    code = resp.get("result", [{}])[0].get("status", {}).get("code", -1)
    if code not in (0,):
        msg = resp.get("result", [{}])[0].get("status", {}).get("message", "")
        failed.append({"name": name, "sub": "(shell)", "code": code, "message": msg})
        errors += 1
        return errors, failed

    def _do_set(url, data_list, sub_label):
        nonlocal errors
        r    = client._call("set", [{"url": url, "data": data_list}])
        code = r.get("result", [{}])[0].get("status", {}).get("code", -1)
        if code == 0:
            return
        # fallback one-by-one
        for item in data_list:
            r2   = client._call("set", [{"url": url, "data": [item]}])
            code = r2.get("result", [{}])[0].get("status", {}).get("code", -1)
            if code != 0:
                msg = r2.get("result", [{}])[0].get("status", {}).get("message", "")
                failed.append({"name": name, "sub": sub_label,
                               "code": code, "message": msg})
                errors += 1

    # IPsec: split action-list entries into separate push calls
    if stype == "_ipsec":
        action_entries = tmpl["subs"].get("action-list", [])
        al_batch  = []  # tunnel basics for action-list URL
        ph1_batch = []  # phase1 entries
        ph2_batch = []  # phase2 entries

        for entry in action_entries:
            val = entry.get("value", {}) or {}

            # Build action-list entry (tunnel basics + system interface only)
            al_entry = {k: v for k, v in entry.items()
                        if k not in _TMPL_STRIP | {"oid"}}
            # Keep value but only with tunnel-level keys
            al_val = {k: v for k, v in val.items()
                      if k not in ("vpn ipsec phase1-interface",
                                   "vpn ipsec phase2-interface")}
            al_entry["value"] = al_val
            al_batch.append(al_entry)

            # Extract phase1 from nested value
            ph1 = val.get("vpn ipsec phase1-interface")
            if isinstance(ph1, dict):
                clean_ph1 = {k: v for k, v in ph1.items() if k not in _TMPL_STRIP}
                # Handle masked secrets — prompt user to enter PSK
                for _, secret_field in _IPSEC_SECRET_PATHS:
                    v = clean_ph1.get(secret_field)
                    if isinstance(v, list) and v and v[0] == "ENC":
                        tunnel_name = val.get("name", "?")
                        print()
                        print(yellow(f"  ⚠  '{tunnel_name}' — encrypted field: {secret_field}"))

                        # Show field-specific guidance
                        if secret_field == "psksecret":
                            print(f"  {dim('Pre-shared key for IKE authentication. Required.')}")
                            required = True
                        elif secret_field == "ppk-secret":
                            print(f"  {dim('IKEv2 Post-quantum Preshared Key (ASCII or hex with leading 0x).')}")
                            print(f"  {dim('Not required — only enter if you use post-quantum protection.')}")
                            required = False
                        elif secret_field == "group-authentication-secret":
                            print(f"  {dim('Password for IKEv2 ID group authentication (ASCII or hex with leading 0x).')}")
                            print(f"  {dim('Not required — only enter if you use IKEv2 group authentication.')}")
                            required = False
                        else:
                            print(f"  {dim('Encrypted credential — enter if applicable.')}")
                            required = False

                        label = f"  Enter {secret_field} for '{tunnel_name}'"
                        label += " (required)" if required else " (or leave blank to skip)"
                        psk = prompt_password(label)
                        if psk:
                            clean_ph1[secret_field] = psk
                        else:
                            clean_ph1.pop(secret_field, None)
                            if required:
                                print(yellow(f"  ⚠  Skipped — phase1 may fail without {secret_field}."))
                            else:
                                print(dim(f"  Skipped — set {secret_field} in FMG GUI if needed."))
                ph1_batch.append(clean_ph1)

            # Extract phase2 from nested value
            ph2 = val.get("vpn ipsec phase2-interface")
            if isinstance(ph2, dict):
                clean_ph2 = {k: v for k, v in ph2.items() if k not in _TMPL_STRIP}
                ph2_batch.append(clean_ph2)

        base = f"/pm/config/adom/{adom}/template/_ipsec/{name}"
        if al_batch:
            _do_set(f"{base}/action-list/",              al_batch,  "action-list")
        if ph1_batch:
            _do_set(f"{base}/vpn/ipsec/phase1-interface/", ph1_batch, "phase1-interface")
        if ph2_batch:
            _do_set(f"{base}/vpn/ipsec/phase2-interface/", ph2_batch, "phase2-interface")

    else:
        # Non-IPsec templates: push each sub-object as-is
        for sub in subs:
            sub_name = sub["name"]
            entries  = tmpl["subs"].get(sub_name, [])
            if not entries:
                continue
            url   = f"/pm/config/adom/{adom}/template/{stype}/{name}/{sub['url']}"
            batch = [{k: v for k, v in e.items() if k not in _TMPL_STRIP}
                     for e in entries]
            _do_set(url, batch, sub_name)

    return errors, failed


def _pick_templates(templates: list[dict], label: str) -> list[dict] | None:
    """Numbered picker for templates. Returns selected list or None for back."""
    if not templates:
        print(dim("  No templates found."))
        return []

    col = max(len(t["name"]) for t in templates)
    print()
    for i, t in enumerate(templates, 1):
        print(f"  {cyan(str(i).ljust(3))}  {t['name'].ljust(col)}")
    print()
    print(f"  Press {dim('Enter')} for all, or enter numbers e.g. {dim('1,3')}.")
    print(f"  Type {dim('back')} to go back.")
    print()

    while True:
        raw = input("  Selection > ").strip()
        if raw.lower() in ("back", "b", "q"):
            return None
        if raw == "" or raw.lower() == "all":
            return templates
        selected = []
        invalid  = []
        seen     = set()
        for token in (t.strip() for t in raw.split(",") if t.strip()):
            if token.isdigit():
                idx = int(token) - 1
                if 0 <= idx < len(templates) and idx not in seen:
                    seen.add(idx)
                    selected.append(templates[idx])
                else:
                    invalid.append(token)
            else:
                invalid.append(token)
        if invalid:
            print(red(f"  Unknown: {', '.join(invalid)} — try again."))
            continue
        if not selected:
            print(red("  Nothing selected — try again."))
            continue
        return selected


def mode_template_export(client: FMGClient, adom_enabled: bool) -> None:
    """Export IPsec and SD-WAN Overlay templates from an ADOM."""

    # Pick ADOM
    print()
    print(bold("  " + "─" * 48))
    adoms = select_adoms(client, None, adom_enabled)
    if adoms is None:
        return
    if len(adoms) > 1:
        print(yellow("  Template export works one ADOM at a time. Using first."))
    adom = adoms[0]

    output = {
        "metadata": {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "fmg_version": client.get_sys_status()[0],
            "source_adom": adom,
        },
        "ipsec_templates":        [],
        "sdwan_overlay_templates": [],
    }

    # IPsec templates
    print(f"  {dim('Fetching IPsec templates...')}", end=" ", flush=True)
    ipsec_list = _get_templates(client, adom, "_ipsec")
    print(green(f"{len(ipsec_list)} found") if ipsec_list else dim("none"))

    if ipsec_list:
        selected = _pick_templates(ipsec_list, "Select IPsec templates to export")
        if selected is None:
            return
        for t in selected:
            print(f"  Fetching {cyan(t['name'])} ...", end=" ", flush=True)
            tmpl = _fetch_template(client, adom, "_ipsec", t["name"],
                                   IPSEC_TEMPLATE_SUBS)
            tmpl["meta"] = t
            output["ipsec_templates"].append(tmpl)
            total   = sum(len(v) for v in tmpl["subs"].values())
            masked  = tmpl.get("masked_secrets", [])
            suffix  = f"  {yellow(f'{len(masked)} secret(s) masked')}" if masked else ""
            print(green(f"{total} sub-objects") + suffix)

    # SD-WAN Overlay templates
    print(f"  {dim('Fetching SD-WAN Overlay templates...')}", end=" ", flush=True)
    sdwan_list = _get_templates(client, adom, "_sdwan_overlay")
    print(green(f"{len(sdwan_list)} found") if sdwan_list else dim("none"))

    if sdwan_list:
        selected = _pick_templates(sdwan_list, "Select SD-WAN Overlay templates")
        if selected is None:
            return
        for t in selected:
            print(f"  Fetching {cyan(t['name'])} ...", end=" ", flush=True)
            tmpl = _fetch_template(client, adom, "_sdwan_overlay", t["name"],
                                   SDWAN_OVERLAY_SUBS)
            tmpl["meta"] = t
            output["sdwan_overlay_templates"].append(tmpl)
            total = sum(len(v) for v in tmpl["subs"].values())
            print(green(f"{total} sub-objects"))

    # Save
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_adom = _sanitize_filename(display_name(adom))
    fname     = f"fmg_templates_{timestamp}_{safe_adom}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)
    size_kb = os.path.getsize(fname) / 1024
    print(f"  {green(chr(10003))} Saved -> {bold(fname)}  ({size_kb:.0f} KB)\n")




def mode_template_import(client: FMGClient, adom_enabled: bool) -> None:
    """Import IPsec and SD-WAN Overlay templates from a JSON file."""

    # Pick file
    candidates = sorted(
        f for f in os.listdir(".")
        if f.startswith("fmg_templates") and f.endswith(".json")
    )
    if candidates:
        print()
        print("  Available template export files:\n")

        for i, f in enumerate(candidates, 1):
            size_kb = os.path.getsize(f) / 1024
            print(f"    {cyan(str(i))}  {f}  {dim(f'({size_kb:.0f} KB)')}")
        print()
        raw = input("  Select file (number or path): ").strip()
        if raw.lower() in ("back", "b", "q"):
            return
        fname = candidates[int(raw) - 1] if raw.isdigit() and 1 <= int(raw) <= len(candidates) else raw
    else:
        fname = input("  Path to template JSON file: ").strip()
        if not fname:
            return

    if not os.path.isfile(fname):
        print(red(f"  File not found: {fname}"))
        return

    print(f"  Loading {cyan(fname)} ...", end=" ", flush=True)
    with open(fname, encoding="utf-8") as f:
        payload = json.load(f)

    ipsec_tmpls = payload.get("ipsec_templates", [])
    sdwan_tmpls = payload.get("sdwan_overlay_templates", [])
    src_version = payload.get("metadata", {}).get("fmg_version", "")
    src_adom    = payload.get("metadata", {}).get("source_adom", "")
    print(green(f"OK  ({len(ipsec_tmpls)} IPsec, {len(sdwan_tmpls)} SD-WAN Overlay)"))
    print(f"  Source ADOM : {cyan(display_name(src_adom))}")
    if src_version:
        print(f"  Source FMG  : {cyan(src_version)}")

    # Pick target ADOM
    print()
    print(bold("  " + "─" * 48))
    target_adom = _pick_target_adom(client, src_version, adom_enabled)
    if target_adom is None:
        return
    _ensure_adom(client, target_adom)

    total_errors = 0
    all_failed   = []

    # Import IPsec templates
    if ipsec_tmpls:
        print(f"Importing {bold(str(len(ipsec_tmpls)))} IPsec template(s)...")

        for tmpl in ipsec_tmpls:
            print(f"  {cyan(tmpl['name'])} ...", end=" ", flush=True)
            errs, failed = _push_template(client, target_adom, tmpl,
                                          IPSEC_TEMPLATE_SUBS)
            total_errors += errs
            all_failed.extend(failed)
            print(green("OK") if errs == 0 else red(f"{errs} error(s)"))

    # Import SD-WAN Overlay templates
    if sdwan_tmpls:
        print(f"Importing {bold(str(len(sdwan_tmpls)))} SD-WAN Overlay template(s)...")

        for tmpl in sdwan_tmpls:
            print(f"  {cyan(tmpl['name'])} ...", end=" ", flush=True)
            errs, failed = _push_template(client, target_adom, tmpl,
                                          SDWAN_OVERLAY_SUBS)
            total_errors += errs
            all_failed.extend(failed)
            print(green("OK") if errs == 0 else red(f"{errs} error(s)"))

    # Show errors
    if all_failed:
        print()
        print(bold(f"  {red('✗')} Failed ({len(all_failed)}):"))
        for f in all_failed:
            print(f"    {red('✗')}  {f['name']}/{f['sub']}  {dim(f['message'])}")

    print(green(f"\n  Done.  {total_errors} error(s)\n"))




def pick_direction() -> str:
    """Top-level menu: Export or Import."""
    print()
    print(bold("  What would you like to do?"))
    print()
    print(f"    {cyan('1')}  Export  {dim('(extract data from FMG to file)')}")
    print(f"    {cyan('2')}  Import  {dim('(push data from file into FMG)')}")
    print()
    while True:
        raw = input("  Select [1/2]: ").strip().lower()
        if raw in ("1", "export", "e"):
            return "export"
        if raw in ("2", "import", "i"):
            return "import"
        print(red("  Please enter 1 or 2."))


def pick_data_type(direction: str) -> str:
    """Ask what type of data to export or import."""
    verb = "Export" if direction == "export" else "Import"
    print()
    print(bold(f"  {verb} — what data?"))
    print()
    print(f"    {cyan('1')}  ADOM objects       {dim('(firewall addresses, services, users, etc.)')}")
    print(f"    {cyan('2')}  Policy packages    {dim('(firewall policies, DoS, NAT, etc.)')}")
    print(f"    {cyan('3')}  Templates          {dim('(IPsec + SD-WAN Overlay templates)')}")
    print()
    print(f"  Type {dim('back')} to go back.")
    print()
    while True:
        raw = input("  Select [1/2/3]: ").strip().lower()
        if raw in ("back", "b", "q"):
            return "back"
        if raw in ("1", "objects", "o"):
            return "objects"
        if raw in ("2", "policy", "p", "policies"):
            return "policy"
        if raw in ("3", "templates", "t"):
            return "templates"
        print(red("  Please enter 1, 2, or 3."))


def main() -> None:
    args = parse_args()

    if args.list_categories:
        print("\nADOM Object categories:\n")
        for cat in CATEGORIES:
            count = sum(1 for t in ADOM_TABLES if t["name"].split("/")[0] == cat)
            print(f"  {cat:<40} {count} table(s)")
        print("\nADOM Controller Config categories:\n")
        for cat in CONTROLLER_CATEGORIES:
            count = sum(1 for t in CONTROLLER_TABLES if t["name"].split("/")[0] == cat)
            print(f"  {cat:<40} {count} table(s)")
        print(f"\n  Total: {len(ALL_TABLES)} tables across {len(ALL_CATEGORIES)} categories\n")
        return

    print_banner()

    # Get connection details from CLI args or prompt
    print(bold("  Connection details"))
    print("  " + "─" * 48)
    host     = args.host     or prompt("FortiManager IP / hostname")
    port     = args.port
    username = args.user     or prompt("Username", "admin")
    password = args.password or prompt_password()

    if not host or not password:
        print(red("  Host and password are required."))
        sys.exit(1)

    # Connect to FMG
    print(f"\n  Connecting to {cyan(f'https://{host}:{port}')} ...", end="", flush=True)
    client = FMGClient(host, port, verify_ssl=args.verify_ssl)

    try:
        client.login(username, password)
    except (ConnectionError, PermissionError) as exc:
        print(f"\n  {red('✗')} {exc}")
        sys.exit(1)

    print(green("  connected"))

    try:
        version, adom_enabled = client.get_sys_status()
        print(f"  FortiManager version: {cyan(version)}")
        if not adom_enabled:
            print(f"  {dim('Admin Domain Configuration:')} {yellow('Disabled')}")

        # Main menu loop — runs until user chooses to exit
        while True:
            direction = pick_direction()

            while True:
                data_type = pick_data_type(direction)
                if data_type == "back":
                    break  # go back to direction picker

                print()
                print(bold("  " + "─" * 48))

                if direction == "export":
                    if data_type == "objects":
                        # Step 1: ADOM selection
                        adoms = select_adoms(client, args.adom, adom_enabled)
                        if adoms is None:
                            continue

                        # Step 2: Object scope
                        if args.category:
                            tables = select_tables(args.category)
                            print(f"  Category filter: {cyan(args.category)} ({len(tables)} table(s))")
                        else:
                            tables = select_tables_interactive(ALL_TABLES)
                            if tables is None:
                                continue

                        # Step 3: Extract loop
                        while True:
                            completed = run_once(client, adoms, tables, args)
                            if not completed:
                                break
                            print("  " + "─" * 48)
                            choice = input(
                                f"  Extract again? [{green('Y')} same scope / "
                                f"{cyan('a')} change ADOM / "
                                f"{cyan('o')} change objects / "
                                f"{dim('n')} back to menu]: "
                            ).strip().lower()
                            if choice in ("n", "no", "q", "quit", "exit"):
                                break
                            elif choice in ("a", "adom"):
                                adoms = select_adoms(client, None, adom_enabled)
                                if adoms is None:
                                    break
                            elif choice in ("o", "obj", "objects"):
                                tables = select_tables_interactive(ALL_TABLES)
                                if tables is None:
                                    break

                    elif data_type == "policy":
                        _policy_export(client, adom_enabled)

                    else:  # templates
                        mode_template_export(client, adom_enabled)

                else:  # import
                    if data_type == "objects":
                        while True:
                            mode_restore(client, adom_enabled)
                            print("  " + "─" * 48)
                            again = input(
                                f"  Restore to another ADOM? [{green('Y')}/n]: "
                            ).strip().lower()
                            if again in ("n", "no", "q", "quit", "exit"):
                                break

                    elif data_type == "policy":
                        _policy_import(client, adom_enabled)

                    else:  # templates
                        mode_template_import(client, adom_enabled)

                print("  " + "─" * 48)
                again = input(
                    f"  Back to {bold(direction.capitalize())} menu? [{green('Y')}/n]: "
                ).strip().lower()
                if again in ("n", "no", "q", "quit", "exit"):
                    break

            print("  " + "─" * 48)
            again = input(
                f"  Return to main menu? [{green('Y')}/n]: "
            ).strip().lower()
            if again in ("n", "no", "q", "quit", "exit"):
                break

    finally:
        client.logout()
        print(f"  {dim('Session closed.')}")

    print(green("  Goodbye.\n"))


if __name__ == "__main__":
    main()