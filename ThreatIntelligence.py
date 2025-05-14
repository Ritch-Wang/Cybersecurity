"""
Enhanced Indicator Checker

A script that checks indicators (IP addresses or CVE identifiers) against a list of known malicious entries,
supports single or batch mode, CLI arguments, and optional logging to a file.

Usage:
  python indicator_checker.py -i 192.168.1.100
  python indicator_checker.py -f indicators.txt -o results.log
  python indicator_checker.py --show-list

Options:
  -i, --indicator   Single indicator to check
  -f, --file        Path to a file containing indicators (one per line)
  -l, --show-list   Display the current malicious IPs and CVEs
  -o, --output      Log results to the specified output file
"""
import argparse
import logging
import re
import sys

# Predefined malicious indicators
BAD_IPS = [
    '192.168.1.100',
    '203.0.113.45',
    '198.51.100.23'
]
BAD_CVES = [
    'CVE-2021-34527',
    'CVE-2020-1472',
    'CVE-2019-0708'
]

# Compile regex patterns
global_ip_pattern = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
global_cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Setup logger
logger = logging.getLogger('IndicatorChecker')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Optional file handler added in main if output file is specified


def detect_type(indicator: str) -> str:
    """Determine if the indicator is an IP, CVE, or Unknown"""
    if global_ip_pattern.match(indicator):
        return 'IP'
    if global_cve_pattern.match(indicator):
        return 'CVE'
    return 'UNKNOWN'


def is_malicious(indicator: str, ind_type: str) -> bool:
    """Check if an indicator is in the malicious lists based on its type"""
    if ind_type == 'IP':
        return indicator in BAD_IPS
    if ind_type == 'CVE':
        return indicator.upper() in (c.upper() for c in BAD_CVES)
    return False


def process_indicator(indicator: str, output_file=None):
    """Process and report a single indicator."""
    ind = indicator.strip()
    ind_type = detect_type(ind)
    mal = is_malicious(ind, ind_type)
    result = f"{ind} ({ind_type}): {'MALICIOUS' if mal else 'Clean'}"
    logger.info(result)
    if output_file:
        output_file.write(result + '\n')


def main():
    parser = argparse.ArgumentParser(description='Enhanced Indicator Checker')
    parser.add_argument('-i', '--indicator', help='Single indicator to check')
    parser.add_argument('-f', '--file', help='File path for batch indicators')
    parser.add_argument('-l', '--show-list', action='store_true', help='Show malicious IPs and CVEs')
    parser.add_argument('-o', '--output', help='Output log file for results')
    args = parser.parse_args()

    # Show current lists
    if args.show_list:
        print('Malicious IPs:')
        for ip in BAD_IPS:
            print('  -', ip)
        print('Malicious CVEs:')
        for cve in BAD_CVES:
            print('  -', cve)
        sys.exit(0)

    # Prepare output file if needed
    file_handle = None
    if args.output:
        try:
            file_handle = open(args.output, 'w')
        except Exception as e:
            logger.error(f"Failed to open output file: {e}")
            sys.exit(1)

    # Single indicator mode
    if args.indicator:
        process_indicator(args.indicator, file_handle)
    # Batch file mode
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    if line.strip():
                        process_indicator(line, file_handle)
        except FileNotFoundError:
            logger.error(f"Indicator file not found: {args.file}")
            sys.exit(1)
    else:
        logger.error('No indicator or file provided. Use -h for help.')
        sys.exit(1)

    if file_handle:
        file_handle.close()


if __name__ == '__main__':
    main()
