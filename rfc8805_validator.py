#!/usr/bin/env python3
"""
RFC 8805 Geo IP Feed Validator and Analyzer

Usage: python rfc8805_validator.py <filename_or_url>
"""

import sys
import re
import ipaddress
from typing import List, Tuple, Dict
import argparse
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass
from ipwhois import IPWhois


@dataclass
class Config:
    """Configuration for RFC 8805 validation."""
    insecure: bool = False
    ipv4_only: bool = False
    ipv6_only: bool = False
    no_overlap_check: bool = False
    stats: bool = False
    verbose: bool = False
    show_rir: bool = False


class RFC8805Validator:
    """Validator for RFC 8805 formatted geo IP feed files."""

    def __init__(self):
        # ISO 3166-1 alpha-2 country codes (common ones)
        self.valid_countries = {
            'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR',
            'AS', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD', 'BE',
            'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ',
            'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD',
            'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR',
            'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM',
            'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI',
            'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF',
            'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS',
            'GT', 'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR', 'HT', 'HU',
            'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT',
            'JE', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN',
            'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK',
            'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME',
            'MF', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ',
            'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA',
            'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU',
            'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM',
            'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS',
            'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI',
            'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS', 'ST', 'SV',
            'SX', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK',
            'TL', 'TM', 'TN', 'TO', 'TR', 'TT', 'TV', 'TW', 'TZ', 'UA',
            'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI',
            'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW'
        }

        # Common region code patterns (ISO 3166-2 format: CC-SS where CC is country, SS is subdivision)
        self.region_pattern = re.compile(r'^[A-Z]{2}-[A-Z0-9]+$')

        self.errors = []
        self.warnings = []
        self.stats = {
            'total_lines': 0,
            'comment_lines': 0,
            'data_lines': 0,
            'valid_lines': 0,
            'invalid_lines': 0
        }
        # For --stats
        self.prefix_lengths = {}  # {prefix_length: count}
        self.total_prefixes = 0
        self.total_addresses = 0  # Sum of all IP addresses in all prefixes
        self.country_counts = {}  # {country_code: count}
        self.distinct_countries = set()  # Set of unique country codes
        # Separate IPv4/IPv6 tracking
        self.ipv4_prefix_lengths = {}  # {prefix_length: count}
        self.ipv6_prefix_lengths = {}  # {prefix_length: count}
        self.ipv4_total_prefixes = 0
        self.ipv6_total_prefixes = 0
        self.ipv4_total_addresses = 0
        self.ipv6_total_addresses = 0
        # For overlap detection
        self._all_networks = []  # List of (ip_network, line_num, line)

    def validate_ip_range(self, ip_range: str, ipv4_only: bool = False,
                         ipv6_only: bool = False, line_num: int = None, line: str = None) -> bool:
        """Validate IP range in CIDR notation."""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)

            # Check if it's a valid network
            if network.network_address != network[0]:
                self.errors.append(f"Line {line_num}: Invalid network address: {ip_range}")
                if line:
                    self.errors.append(f"  Full line: {line}")
                return False

            # For --stats: count prefix lengths (only if not filtered out)
            if (not (ipv4_only and network.version != 4) and
                not (ipv6_only and network.version != 6)):
                prefixlen = network.prefixlen
                self.prefix_lengths[prefixlen] = self.prefix_lengths.get(prefixlen, 0) + 1
                self.total_prefixes += 1
                # Calculate total addresses in this prefix
                self.total_addresses += network.num_addresses

                # Separate IPv4/IPv6 tracking
                if network.version == 4:
                    self.ipv4_prefix_lengths[prefixlen] = (
                        self.ipv4_prefix_lengths.get(prefixlen, 0) + 1
                    )
                    self.ipv4_total_prefixes += 1
                    self.ipv4_total_addresses += network.num_addresses
                else:  # IPv6
                    self.ipv6_prefix_lengths[prefixlen] = (
                        self.ipv6_prefix_lengths.get(prefixlen, 0) + 1
                    )
                    self.ipv6_total_prefixes += 1
                    self.ipv6_total_addresses += network.num_addresses

            # For overlap detection, store all valid networks
            if line_num is not None and line is not None:
                self._all_networks.append((network, line_num, line))

            return True
        except ValueError as e:
            self.errors.append(f"Line {line_num}: Invalid IP range {ip_range}: {e}")
            if line:
                self.errors.append(f"  Full line: {line}")
            return False

    def validate_country_code(self, country_code: str, line_num: int = None, line: str = None) -> bool:
        """Validate country code (ISO 3166-1 alpha-2)."""
        if not country_code or len(country_code) != 2:
            self.errors.append(f"Line {line_num}: Invalid country code format: {country_code}")
            if line:
                self.errors.append(f"  Full line: {line}")
            return False

        if country_code not in self.valid_countries:
            self.warnings.append(f"Line {line_num}: Unknown country code: {country_code}")
            return False

        # For --stats: track country statistics
        self.country_counts[country_code] = (
            self.country_counts.get(country_code, 0) + 1
        )
        self.distinct_countries.add(country_code)

        return True

    def validate_region_code(self, region_code: str, line_num: int = None, line: str = None) -> bool:
        """Validate region code (ISO 3166-2 format)."""
        if not region_code:
            return True  # Region codes can be empty according to RFC

        if not self.region_pattern.match(region_code):
            self.errors.append(f"Line {line_num}: Invalid region code format: {region_code}")
            if line:
                self.errors.append(f"  Full line: {line}")
            return False

        return True

    def validate_city_name(self, city_name: str, line_num: int = None, line: str = None) -> bool:
        """Validate city name."""
        if not city_name:
            return True  # City names can be empty according to RFC

        # Basic validation - should not contain control characters
        if any(ord(c) < 32 for c in city_name):
            self.errors.append(f"Line {line_num}: City name contains control characters: {city_name}")
            if line:
                self.errors.append(f"  Full line: {line}")
            return False

        return True

    def get_rir_data(self, ip_range: str) -> Dict:
        """Get RIR data for a given IP range."""
        try:
            # Extract the first IP address from the range for whois lookup
            network = ipaddress.ip_network(ip_range, strict=False)
            first_ip = str(network.network_address)
            
            obj = IPWhois(first_ip)
            result = obj.lookup_rdap()
            
            # Extract the required fields
            asn = result.get('asn', 'N/A')
            asn_cidr = result.get('asn_cidr', 'N/A')
            asn_country_code = result.get('asn_country_code', 'N/A')
            asn_registry = result.get('asn_registry', 'N/A')
            
                        # Check the relationship between this prefix and the ASN CIDR
            relationship_indicator = ""
            if asn_cidr != 'N/A' and asn_cidr != 'Error':
                try:
                    asn_network = ipaddress.ip_network(asn_cidr, strict=False)
                    if network.version == asn_network.version and network != asn_network:
                        if network.subnet_of(asn_network):
                            relationship_indicator = " (Subnet)"
                        elif asn_network.subnet_of(network):
                            relationship_indicator = " (Supernet)"
                except ValueError:
                    pass  # Invalid ASN CIDR, skip relationship check

            network_info = result.get('network', {})
            network_cidr = network_info.get('cidr', 'N/A')
            network_handle = network_info.get('handle', 'N/A')
            network_name = network_info.get('name', 'N/A')
            network_parent_handle = network_info.get('parent_handle', 'N/A')
            network_type = network_info.get('type', 'N/A')
            network_country = network_info.get('country', 'N/A')
            
            return {
                'asn': asn,
                'asn_cidr': asn_cidr + relationship_indicator,
                'asn_country_code': asn_country_code,
                'asn_registry': asn_registry,
                'network_cidr': network_cidr,
                'network_handle': network_handle,
                'network_name': network_name,
                'network_parent_handle': network_parent_handle,
                'network_type': network_type,
                'network_country': network_country
            }
        except Exception as e:
            return {
                'asn': 'Error',
                'asn_cidr': 'Error',
                'asn_country_code': 'Error',
                'asn_registry': 'Error',
                'network_cidr': 'Error',
                'network_handle': 'Error',
                'network_name': f'Error: {str(e)}',
                'network_parent_handle': 'Error',
                'network_type': 'Error',
                'network_country': 'Error'
            }

    def validate_entry(self, line: str, line_num: int, config: Config) -> bool:
        """Validate a single data line."""
        # Remove trailing comma and split
        line = line.rstrip(',')
        fields = line.split(',')

        if len(fields) < 2:
            self.errors.append(f"Line {line_num}: Expected at least 2 fields (IP range, country code), got {len(fields)}")
            self.errors.append(f"  Full line: {line}")
            return False

        # Extract fields, handling optional region, city, and postal code
        ip_range = fields[0]
        country_code = fields[1]
        region_code = fields[2] if len(fields) > 2 else ""
        city_name = fields[3] if len(fields) > 3 else ""
        # Note: postal code (field 5) is also optional but not currently validated

        # Validate each field
        ip_valid = self.validate_ip_range(ip_range.strip(), config.ipv4_only, config.ipv6_only, line_num, line)
        country_valid = self.validate_country_code(country_code.strip(), line_num, line)
        region_valid = self.validate_region_code(region_code.strip(), line_num, line)
        city_valid = self.validate_city_name(city_name.strip(), line_num, line)

        # Show RIR data if requested
        if config.show_rir and ip_valid:
            print(f"{ip_range.strip()},{country_code.strip()},{region_code.strip()},{city_name.strip()}")
            rir_data = self.get_rir_data(ip_range.strip())
            print(f"    asn: {rir_data['asn']}")
            print(f"    asn_cidr: {rir_data['asn_cidr']}")
            print(f"    asn_country_code: {rir_data['asn_country_code']}")
            print(f"    asn_registry: {rir_data['asn_registry']}")
            print(f"    network->cidr: {rir_data['network_cidr']}")
            print(f"    network->handle: {rir_data['network_handle']}")
            print(f"    network->name: {rir_data['network_name']}")
            print(f"    network->parent_handle: {rir_data['network_parent_handle']}")
            print(f"    network->type: {rir_data['network_type']}")
            print(f"    network->country: {rir_data['network_country']}")

        # Filter by address family if requested
        if config.ipv4_only or config.ipv6_only:
            try:
                network = ipaddress.ip_network(ip_range.strip(), strict=False)
                if config.ipv4_only and network.version != 4:
                    self.warnings.append(
                        f"Line {line_num}: Skipping IPv6 address (IPv4 only mode): "
                        f"{ip_range.strip()}"
                    )
                    return False
                if config.ipv6_only and network.version != 6:
                    self.warnings.append(
                        f"Line {line_num}: Skipping IPv4 address (IPv6 only mode): "
                        f"{ip_range.strip()}"
                    )
                    return False
            except ValueError:
                pass  # Let the normal validation handle invalid IPs

        return all([ip_valid, country_valid, region_valid, city_valid])

    def validate_file(self, filename: str, config: Config) -> bool:
        """Validate entire file according to RFC 8805."""
        self.errors = []
        self.warnings = []
        self.stats = {
            'total_lines': 0,
            'comment_lines': 0,
            'data_lines': 0,
            'valid_lines': 0,
            'invalid_lines': 0
        }

        # Reset statistics if filtering is applied
        if config.ipv4_only or config.ipv6_only:
            self.prefix_lengths = {}
            self.total_prefixes = 0
            self.total_addresses = 0
            self.country_counts = {}
            self.distinct_countries = set()
            self.ipv4_prefix_lengths = {}
            self.ipv6_prefix_lengths = {}
            self.ipv4_total_prefixes = 0
            self.ipv6_total_prefixes = 0
            self.ipv4_total_addresses = 0
            self.ipv6_total_addresses = 0
            self._all_networks = [] # Clear overlap detection list

        try:
            # Get the appropriate file-like object
            if filename.startswith(('http://', 'https://')):
                # Handle SSL certificate verification
                if config.insecure:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                else:
                    context = None

                file_obj = urllib.request.urlopen(filename, context=context)
                decode_lines = True
            else:
                file_obj = open(filename, 'r', encoding='utf-8')
                decode_lines = False

            # Process lines from either source
            with file_obj:
                for line_num, line in enumerate(file_obj, 1):
                    self.stats['total_lines'] += 1

                    # Decode if needed (for URL responses)
                    if decode_lines:
                        line = line.decode('utf-8').strip()
                    else:
                        line = line.strip()

                    # Skip empty lines
                    if not line:
                        continue

                    # Handle comments
                    if line.startswith('#'):
                        self.stats['comment_lines'] += 1
                        continue

                    # Validate data line
                    self.stats['data_lines'] += 1
                    if self.validate_entry(line, line_num, config):
                        self.stats['valid_lines'] += 1
                    else:
                        self.stats['invalid_lines'] += 1

        except urllib.error.URLError as e:
            print(f"Error accessing URL: {e}")
            return False
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            return False
        except Exception as e:
            print(f"Error reading file: {e}")
            return False

        # Check for overlapping IP ranges (separate by IP version)
        if self._all_networks and not config.no_overlap_check:
            # Separate IPv4 and IPv6 networks
            ipv4_networks = [(net, line, _) for net, line, _ in self._all_networks if net.version == 4]
            ipv6_networks = [(net, line, _) for net, line, _ in self._all_networks if net.version == 6]

            # Check IPv4 overlaps
            if ipv4_networks:
                sorted_ipv4 = sorted(ipv4_networks, key=lambda x: x[0])
                for i in range(len(sorted_ipv4) - 1):
                    current_net, current_line, current_line_str = sorted_ipv4[i]
                    next_net, next_line, next_line_str = sorted_ipv4[i + 1]
                    if current_net.overlaps(next_net):
                        self.warnings.append(
                            f"Warning: Overlapping IPv4 ranges found at lines {current_line} and {next_line}: "
                            f"{current_net} overlaps {next_net}"
                        )
                        self.warnings.append(f"  Line {current_line}: {current_line_str}")
                        self.warnings.append(f"  Line {next_line}: {next_line_str}")

            # Check IPv6 overlaps
            if ipv6_networks:
                sorted_ipv6 = sorted(ipv6_networks, key=lambda x: x[0])
                for i in range(len(sorted_ipv6) - 1):
                    current_net, current_line, current_line_str = sorted_ipv6[i]
                    next_net, next_line, next_line_str = sorted_ipv6[i + 1]
                    if current_net.overlaps(next_net):
                        self.warnings.append(
                            f"Warning: Overlapping IPv6 ranges found at lines {current_line} and {next_line}: "
                            f"{current_net} overlaps {next_net}"
                        )
                        self.warnings.append(f"  Line {current_line}: {current_line_str}")
                        self.warnings.append(f"  Line {next_line}: {next_line_str}")

        return len(self.errors) == 0

    def print_results(self):
        """Print validation results."""
        print("\n=== RFC 8805 Validation Results ===")
        print(f"Total lines: {self.stats['total_lines']}")
        print(f"Comment lines: {self.stats['comment_lines']}")
        print(f"Data lines: {self.stats['data_lines']}")
        print(f"Valid lines: {self.stats['valid_lines']}")
        print(f"Invalid lines: {self.stats['invalid_lines']}")

        if self.warnings:
            print(f"\n=== Warnings ({len(self.warnings)}) ===")
            for warning in self.warnings:
                print(f"  WARNING: {warning}")

        if self.errors:
            print(f"\n=== Errors ({len(self.errors)}) ===")
            for error in self.errors:
                if error.startswith("  Full line:"):
                    print(f"  {error}")
                else:
                    print(f"  ERROR: {error}")
            print(f"\n❌ Validation FAILED with {len(self.errors)} errors")
        else:
            print(f"\n✅ Validation PASSED - All {self.stats['valid_lines']} data lines are valid")

    def print_stats(self):
        """Print statistics about the IP prefixes."""
        print("\n=== Statistics ===")
        print(f"Total IP prefixes processed: {self.total_prefixes}")

        # Only show IPv4/IPv6 breakdown if both are present or no filtering
        if self.ipv4_total_prefixes > 0 and self.ipv6_total_prefixes > 0:
            print(f"  IPv4 prefixes: {self.ipv4_total_prefixes}")
            print(f"  IPv6 prefixes: {self.ipv6_total_prefixes}")
        elif self.ipv4_total_prefixes > 0:
            print(f"  IPv4 prefixes: {self.ipv4_total_prefixes}")
        elif self.ipv6_total_prefixes > 0:
            print(f"  IPv6 prefixes: {self.ipv6_total_prefixes}")

        # Format total addresses appropriately for IPv6
        if self.total_addresses > 1e12:  # Very large numbers (IPv6)
            print(f"Total IP addresses: {self.total_addresses:.2e}")
        else:
            print(f"Total IP addresses: {self.total_addresses:,}")

        # Only show IPv4/IPv6 address breakdown if both are present or no filtering
        if self.ipv4_total_addresses > 0 and self.ipv6_total_addresses > 0:
            print(f"  IPv4 addresses: {self.ipv4_total_addresses:,}")
            if self.ipv6_total_addresses > 1e12:
                print(f"  IPv6 addresses: {self.ipv6_total_addresses:.2e}")
            else:
                print(f"  IPv6 addresses: {self.ipv6_total_addresses:,}")
        elif self.ipv4_total_addresses > 0:
            print(f"  IPv4 addresses: {self.ipv4_total_addresses:,}")
        elif self.ipv6_total_addresses > 0:
            if self.ipv6_total_addresses > 1e12:
                print(f"  IPv6 addresses: {self.ipv6_total_addresses:.2e}")
            else:
                print(f"  IPv6 addresses: {self.ipv6_total_addresses:,}")

        if self.country_counts:
            print(f"Distinct countries: {len(self.distinct_countries)}")
            print("Country breakdown:")
            for country in sorted(self.country_counts):
                print(f"  {country}: {self.country_counts[country]} prefixes")

        if self.ipv4_prefix_lengths:
            print("IPv4 Prefix length breakdown:")
            for plen in sorted(self.ipv4_prefix_lengths):
                count = self.ipv4_prefix_lengths[plen]
                addresses_per_prefix = 2 ** (32 - plen)
                total_addresses = count * addresses_per_prefix
                print(f"  /{plen}: {count} entries ({addresses_per_prefix:,} addresses each, "
                      f"{total_addresses:,} total)")

        if self.ipv6_prefix_lengths:
            print("IPv6 Prefix length breakdown:")
            for plen in sorted(self.ipv6_prefix_lengths):
                count = self.ipv6_prefix_lengths[plen]
                addresses_per_prefix = 2 ** (128 - plen)
                total_addresses = count * addresses_per_prefix
                if total_addresses > 1e12:
                    print(f"  /{plen}: {count} entries ({addresses_per_prefix:.2e} addresses each, "
                          f"{total_addresses:.2e} total)")
                else:
                    print(f"  /{plen}: {count} entries ({addresses_per_prefix:,} addresses each, "
                          f"{total_addresses:,} total)")

        if not self.prefix_lengths and not self.country_counts:
            print("No valid prefixes found.")


def get_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate RFC 8805 formatted geo IP feed files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rfc8805_validator.py hf-ipam-ranges.csv
  python rfc8805_validator.py --verbose my-geofeed.csv
  python rfc8805_validator.py https://example.com/geofeed.csv --stats
        """
    )
    parser.add_argument('filename',
                       help='Path to the RFC 8805 formatted file or HTTP(S) URL')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed validation information')
    parser.add_argument('--stats', action='store_true',
                       help='Show prefix length statistics')
    parser.add_argument('--insecure', action='store_true',
                       help='Skip SSL certificate verification (use with caution)')
    parser.add_argument('--no-overlap-check', action='store_true',
                       help='Skip checking for overlapping IP ranges')
    parser.add_argument('--show-rir', action='store_true',
                       help='Show RIR (Regional Internet Registry) data for each prefix')

    # Mutually exclusive address family options
    address_group = parser.add_mutually_exclusive_group()
    address_group.add_argument('-4', '--ipv4-only', action='store_true',
                              help='Only validate IPv4 addresses')
    address_group.add_argument('-6', '--ipv6-only', action='store_true',
                              help='Only validate IPv6 addresses')

    args = parser.parse_args()
    config = Config(
        insecure=args.insecure,
        ipv4_only=args.ipv4_only,
        ipv6_only=args.ipv6_only,
        no_overlap_check=args.no_overlap_check,
        stats=args.stats,
        verbose=args.verbose,
        show_rir=args.show_rir
    )
    return args.filename, config


def main():
    """Main function."""

    filename, config = get_args()

    validator = RFC8805Validator()
    success = validator.validate_file(filename, config)

    validator.print_results()

    if config.stats:
        validator.print_stats()

    if config.verbose and success:
        print(f"\n📋 File '{filename}' is a valid RFC 8805 geo IP feed")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
