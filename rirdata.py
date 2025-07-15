#!/usr/bin/env python3
"""
Print RIR data for a given IP prefix.
"""

import sys
import json
from ipwhois import IPWhois


def main():
    """Main function."""

    ip = sys.argv[1]
    obj = IPWhois(ip)
    result = obj.lookup_rdap()

    print(ip)
    print("asn:", result['asn'])
    print("rir:", result['asn_registry'])
    print("country:", result['asn_country_code'])
    print("description:", result['asn_description'])

    print("network->handle:", result['network']['handle'])
    print("network->cidr:", result['network']['cidr'])
    print("network->ip_version:", result['network']['ip_version'])
    print("network->type:", result['network']['type'])
    print("network->name:", result['network']['name'])
    print("network->country:", result['network']['country'])
    print("network->parent_handle:", result['network']['parent_handle'])


if __name__ == "__main__":
    main()
