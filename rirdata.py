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
    print(json.dumps(result))

if __name__ == "__main__":
    main()
