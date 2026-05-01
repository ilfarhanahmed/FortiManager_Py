#!/usr/bin/env python3
"""
FortiManager ADOM Object Extractor
Connects to a FortiManager via JSON-RPC API and extracts all ADOM-level objects
across every ADOM, based on the 228 root-level table endpoints from FMG 7.6.6.

Usage:
    python3 fmg_adom_extractor.py
    python3 fmg_adom_extractor.py --adom root        # single ADOM
    python3 fmg_adom_extractor.py --category firewall # single category
    python3 fmg_adom_extractor.py --out results.json  # custom output file
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

# ── colours (disabled on Windows or non-TTY) ──────────────────────────────────
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


# ── FortiManager JSON-RPC client ───────────────────────────────────────────────

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

    # ── low-level ──────────────────────────────────────────────────────────────

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

    # ── auth ───────────────────────────────────────────────────────────────────

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

    # ── queries ────────────────────────────────────────────────────────────────

    def get_adoms(self) -> list[str]:
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
            "url":     "/dvmdb/adom",
            "option":  "name",
            "fields":  ["name", "restricted_prds"],
            "verbose": 1,
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
            # rootp (Global) is always relevant
            if name == "rootp":
                filtered.append(name)
                continue
            # restricted_prds may be returned as:
            #   list  e.g. ["fos", "fpx"]   — newer FMG versions
            #   str   e.g. "fos"            — single-product ADOMs on some versions
            #   int   e.g. 0x0001           — bitmask on older FMG versions
            #   []  / missing               — "all products" ADOM
            prds = a.get("restricted_prds", [])
            if isinstance(prds, int):
                # bitmask: fos=0x0001, ffw=0x0008, fwc=0x0010, foc=0x0020, fpx=0x0200
                BITMASK = {0x0001: "fos", 0x0008: "ffw", 0x0010: "fwc",
                           0x0020: "foc", 0x0200: "fpx"}
                prds = [v for k, v in BITMASK.items() if prds & k]
            elif isinstance(prds, str):
                # single product returned as a bare string — wrap in a list
                prds = [prds] if prds else []
            # prds is now always a list
            if not prds or set(prds) & FORTIOS_PRDS:
                # empty restricted_prds means "all products" — include it
                filtered.append(name)

        return filtered

    def get_table(self, url: str) -> tuple[list, int]:
        """
        Fetch all entries from a table URL (paginates automatically).
        Returns (entries, status_code).

        loadsub is intentionally omitted (defaults to 1) so that
        sub-objects such as dynamic_mapping are included in the response.
        """
        all_entries = []
        offset = 0
        page_size = 500

        while True:
            resp = self._call("get", [{
                "url": url,
                "range": [offset, page_size],
            }])
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
            if len(data) < page_size:
                break
            offset += page_size

        return all_entries, 0

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


# ── progress printer ───────────────────────────────────────────────────────────

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


# ── core extraction ────────────────────────────────────────────────────────────

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
                   tables: list[dict]) -> dict:
    """Extract all tables for all ADOMs."""
    total_ops = len(adoms) * len(tables)
    prog = Progress(total_ops)

    print(f"\n  Extracting {bold(str(len(tables)))} object types "
          f"across {bold(str(len(adoms)))} ADOM(s) "
          f"({bold(str(total_ops))} requests)\n")

    output = {
        "metadata": {
            "extracted_at": datetime.now(timezone.utc).isoformat(),
            "adoms": adoms,
            "tables_queried": len(tables),
                "adom_tables": len([t for t in tables if t in ADOM_TABLES]),
                "controller_tables": len([t for t in tables if t in CONTROLLER_TABLES]),
        },
        "data": {}
    }

    for adom in adoms:
        output["data"][adom] = extract_adom(client, adom, tables, prog)

    prog.summary()
    return output


# ── output writers ─────────────────────────────────────────────────────────────

def _sanitize_filename(name: str) -> str:
    """Replace characters that are unsafe in filenames."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def write_json_per_adom(data: dict, out_stem: str, no_csv: bool) -> None:
    """Write one JSON (and optionally one CSV) file per ADOM."""
    import csv
    for adom, tables in data["data"].items():
        safe = _sanitize_filename(display_name(adom))

        # ── per-ADOM payload ──────────────────────────────────────────────────
        adom_payload = {
            "metadata": {
                **{k: v for k, v in data["metadata"].items() if k != "adoms"},
                "adom": adom,
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


# ── CLI prompt helpers ─────────────────────────────────────────────────────────

def prompt(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"  {label}{suffix}: ").strip()
    return val or default


def prompt_password(label: str = "Password") -> str:
    import getpass
    prompt = f"  {label}: "
    # PyCharm's embedded terminal doesn't support getpass (no raw TTY),
    # so fall back to plain input() when running inside the IDE.
    in_pycharm = (
        "PYCHARM_HOSTED" in os.environ
        or "PYDEV_CONSOLE_EXECUTE_HOOK" in os.environ
    )
    if in_pycharm:
        return input(prompt)
    try:
        return getpass.getpass(prompt)
    except Exception:
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
        all_adoms = client.get_adoms()
    else:
        # ADOMs disabled — only root exists
        all_adoms = ["root"]

    # Ensure root is always in the list (sometimes not returned by API)
    if "root" not in all_adoms and adom_enabled:
        all_adoms = ["root"] + all_adoms

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
    # Derive column widths from actual data so nothing is ever clipped or over-padded.
    labels   = [display_name(n) for n in all_adoms]
    notes    = ["Global Policy"  if n == "rootp"      else
                "ADOMs disabled" if not adom_enabled  else ""
                for n in all_adoms]
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


# ── main ───────────────────────────────────────────────────────────────────────

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

    # ── extract ───────────────────────────────────────────────────────────────
    result = run_extraction(client, adoms, tables)

    # ── write output — one file per ADOM ─────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_stem = args.out.rstrip(".json") if args.out else f"fmg_adom_objects_{timestamp}"

    print(f"\n  {bold('Saving output...')}")
    write_json_per_adom(result, out_stem, no_csv=args.no_csv)

    if not args.no_summary:
        write_summary(result)

    print(green("  Done.\n"))
    return True


# ── Restore (push) helpers ────────────────────────────────────────────────────
# Inlined from fmg_adom_pusher.py so both modes share the live FMG session.

_PUSH_STRIP = {"oid", "obj-ver", "dirty", "_image-base64"}


def _push_clean(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in _PUSH_STRIP}


# Maximum objects per set call. FMG can reject very large payloads;
# 100 is a safe chunk size that balances speed vs. reliability.
_PUSH_CHUNK_SIZE = 100


def _push_table(client: FMGClient, table_name: str, entries: list,
                target_adom: str, dry_run: bool,
                progress_cb=None) -> tuple[int, int]:
    """
    Push all entries for one table using chunked set calls.
    Sends up to _PUSH_CHUNK_SIZE objects per request.
    If a chunk fails, falls back to one-by-one for that chunk only.
    progress_cb(pushed, errors, total) is called after each chunk.
    """
    if not entries:
        return 0, 0

    url   = build_url({"url": f"/pm/config/adom/{{adom}}/obj/{table_name}"}, target_adom)
    batch = [_push_clean(e) for e in entries]

    if dry_run:
        if progress_cb:
            progress_cb(len(batch), 0, len(batch))
        return len(batch), 0

    pushed = errors = 0

    # Send in chunks of _PUSH_CHUNK_SIZE
    for i in range(0, len(batch), _PUSH_CHUNK_SIZE):
        chunk = batch[i:i + _PUSH_CHUNK_SIZE]

        resp = client._call("set", [{"url": url, "data": chunk}])
        code = resp.get("result", [{}])[0].get("status", {}).get("code", -1)

        if code == 0:
            pushed += len(chunk)
        else:
            # Chunk failed — retry one-by-one to salvage what we can
            for obj in chunk:
                r    = client._call("set", [{"url": url, "data": [obj]}])
                code = r.get("result", [{}])[0].get("status", {}).get("code", -1)
                if code == 0:
                    pushed += 1
                else:
                    errors += 1

        if progress_cb:
            progress_cb(pushed, errors, len(batch))

    return pushed, errors


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


def _pick_target_adom(client: FMGClient) -> str:
    """Numbered ADOM picker for restore target; allows typing a new ADOM name."""
    all_adoms = client.get_adoms()
    if "root" not in all_adoms:
        all_adoms = ["root"] + all_adoms

    labels = [display_name(a) for a in all_adoms]
    notes  = ["Global Policy" if a == "rootp" else "" for a in all_adoms]

    col_idx  = max(len(str(len(all_adoms))), 1)
    col_name = max(len("ADOM Name"), max(len(l) for l in labels))
    col_note = max(len("Note"), max((len(n) for n in notes if n), default=0))
    sep      = "  "
    divider  = "─" * (col_idx + len(sep) + col_name + len(sep) + col_note)

    print()
    print(f"  Select target ADOM  {dim('(or type a new name to create it)')}")
    print(f"  {'#':<{col_idx}}{sep}{'ADOM Name':<{col_name}}{sep}Note")
    print("  " + divider)
    for i, (name, lbl, note) in enumerate(zip(all_adoms, labels, notes), 1):
        print(f"  {cyan(str(i).ljust(col_idx))}{sep}{lbl:<{col_name}}{sep}{dim(note) if note else ''}")
    print()

    while True:
        raw = input("  Selection > ").strip()
        if not raw:
            print(red("  Please enter a number or ADOM name."))
            continue
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
    report    = {
        "metadata": {
            "pushed_at":   datetime.now(timezone.utc).isoformat(),
            "source_adom": source_adom,
            "target_adom": target_adom,
            "dry_run":     dry_run,
        },
        "results": results,
        "summary": {
            "tables":         len(results),
            "total_objects":  sum(v["total"]  for v in results.values()),
            "pushed":         sum(v["pushed"] for v in results.values()),
            "errors":         sum(v["errors"] for v in results.values()),
        },
    }
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    size_kb = os.path.getsize(fname) / 1024
    print(f"  {green('✓')} Report → {bold(fname)}  ({size_kb:.0f} KB)")


def mode_restore(client: FMGClient, dry_run: bool = False) -> None:
    """Interactive restore-from-file flow using the live client session."""

    # ── pick file ─────────────────────────────────────────────────────────────
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

    # ── pick source ADOM from file ────────────────────────────────────────────
    source_adom = _pick_source_adom_from_file(file_data)
    adom_data   = file_data[source_adom]

    # ── pick target ADOM on the live FMG ─────────────────────────────────────
    target_adom = _pick_target_adom(client)
    _ensure_adom(client, target_adom)

    # ── object scope selection (reuse the same interactive picker as extract) ──
    print()
    print(bold("  " + "─" * 48))
    tables_selected = select_tables_interactive()
    if tables_selected is None:
        return  # user went back

    selected_names = {t["name"] for t in tables_selected}

    # ── summary before push ───────────────────────────────────────────────────
    tables_to_push = {k: v for k, v in adom_data.items()
                      if v and k in selected_names}
    total_entries  = sum(len(v) for v in tables_to_push.values())

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

    # ── push ──────────────────────────────────────────────────────────────────
    total_tables  = len(tables_to_push)
    total_objects = sum(len(v) for v in tables_to_push.values())
    results       = {}
    done          = 0
    obj_done      = 0
    t_start       = time.time()
    bar_width     = 28

    def _render(t_done, t_total, o_pushed, o_errors, o_total, name, final=False):
        """Render one progress line. Uses object-level progress within a table."""
        # Overall bar based on objects completed across all tables
        total_done_objs = obj_done + o_pushed + o_errors
        filled  = int(bar_width * total_done_objs / max(total_objects, 1))
        bar     = "█" * filled + "░" * (bar_width - filled)
        pct     = 100 * total_done_objs // max(total_objects, 1)

        elapsed_so_far = time.time() - t_start
        rate      = total_done_objs / elapsed_so_far if elapsed_so_far > 0 else 0
        remaining = total_objects - total_done_objs
        eta_str   = f"ETA {remaining/rate:.0f}s" if rate > 1 else ""

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
        n        = len(entries)
        name_col = table_name[:36].ljust(36)

        # Show initial line before any requests fire
        _render(done, total_tables, 0, 0, max(n, 1), table_name)

        def make_cb(tname, n_entries):
            def cb(p, e, total):
                _render(done, total_tables, p, e, total, tname)
            return cb

        pushed, errors = _push_table(client, table_name, entries, target_adom,
                                     False, progress_cb=make_cb(table_name, n))
        results[table_name] = {"pushed": pushed, "errors": errors, "total": n}
        obj_done += n
        done     += 1

        # Final line for this table
        _render(done, total_tables, pushed, errors, n, table_name, final=True)

    elapsed      = time.time() - t_start
    total_pushed = sum(v["pushed"] for v in results.values())
    total_errors = sum(v["errors"] for v in results.values())
    print()
    print(f"\n  Completed in {elapsed:.1f}s  |  "
          f"{green(str(total_pushed))} pushed  "
          f"{(red(str(total_errors)) if total_errors else dim('0'))} errors")

    # ── report ────────────────────────────────────────────────────────────────
    print(f"\n  {bold('Saving report...')}")
    _write_push_report(results, source_adom, target_adom, False)
    print(green("  Done.\n"))


# ── mode selector ─────────────────────────────────────────────────────────────

def pick_mode() -> str:
    """Ask the user what they want to do after login."""
    print()
    print(bold("  What would you like to do?"))
    print()
    print(f"    {cyan('1')}  Extract ADOM objects  {dim('(save to JSON/CSV)')}")
    print(f"    {cyan('2')}  Restore from file     {dim('(push objects to a target ADOM)')}")
    print()
    while True:
        raw = input("  Select mode [1/2]: ").strip()
        if raw in ("1", "extract", "e"):
            return "extract"
        if raw in ("2", "restore", "r"):
            return "restore"
        print(red("  Please enter 1 or 2."))


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

    # ── gather connection details ──────────────────────────────────────────────
    print(bold("  Connection details"))
    print("  " + "─" * 48)
    host     = args.host     or prompt("FortiManager IP / hostname")
    port     = args.port
    username = args.user     or prompt("Username", "admin")
    password = args.password or prompt_password()

    if not host or not password:
        print(red("  Host and password are required."))
        sys.exit(1)

    # ── connect ────────────────────────────────────────────────────────────────
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

        # ── mode loop ─────────────────────────────────────────────────────────
        while True:
            mode = pick_mode()

            print()
            print(bold("  " + "─" * 48))

            if mode == "extract":
                # ── Step 1: ADOM selection ────────────────────────────────────
                adoms = select_adoms(client, args.adom, adom_enabled)
                if adoms is None:
                    continue  # user went back to mode menu

                # ── Step 2: Object scope selection ───────────────────────────
                if args.category:
                    tables = select_tables(args.category)
                    print(f"  Category filter: {cyan(args.category)} ({len(tables)} table(s))")
                else:
                    tables = select_tables_interactive(ALL_TABLES)
                    if tables is None:
                        continue  # user went back to mode menu

                # ── Step 3: Extract ───────────────────────────────────────────
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
                        # re-pick ADOM, keep same object scope
                        adoms = select_adoms(client, None, adom_enabled)
                        if adoms is None:
                            break
                    elif choice in ("o", "obj", "objects"):
                        # re-pick object scope, keep same ADOMs
                        tables = select_tables_interactive(ALL_TABLES)
                        if tables is None:
                            break
                    # default (Y/Enter): re-run with same adoms + tables

            else:  # restore
                while True:
                    mode_restore(client)
                    print("  " + "─" * 48)
                    again = input(
                        f"  Restore to another ADOM? [{green('Y')}/n]: "
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