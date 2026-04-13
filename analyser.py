import re
import sys
import gzip
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
from colorama import Fore, Style, init

ATTACK_PATHS = {
    '/wp-admin', '/wp-login.php', '/.env', '/.git/config', '/etc/passwd',
    '/etc/shadow', '/phpmyadmin', '/phpMyAdmin', '/admin', '/xmlrpc.php',
    '/wp-json/wp/v2/users', '/.htaccess', '/config.php', '/backup',
    '/shell.php', '/cmd.php', '/eval', '/server-status', '/manager/html',
    '/.git/HEAD', '/config/database.php', '/actuator', '/console',
    '/api/v1/users', '/.DS_Store',
}

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

TIME_FORMAT = '%d/%b/%Y:%H:%M:%S %z'


def parse_line(line):
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group('time'), TIME_FORMAT)
    except ValueError:
        ts = None
    return {
        'ip': m.group('ip'),
        'time': ts,
        'method': m.group('method'),
        'path': m.group('path').split('?')[0],
        'status': int(m.group('status')),
        'bytes': m.group('bytes'),
        'ua': m.group('ua') or '',
    }


def open_log(filepath):
    if filepath.endswith('.gz'):
        return gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
    return open(filepath, 'r', encoding='utf-8', errors='ignore')


def analyse(filepath):
    ip_data = defaultdict(lambda: {
        'total': 0, 'errors': 0, 'attack_paths': set(),
        'post_login_times': [], 'requests': [],
    })

    total_requests = 0
    error_requests = 0
    hour_buckets = defaultdict(int)
    malformed = 0

    with open_log(filepath) as f:
        for line in f:
            parsed = parse_line(line)
            if not parsed:
                malformed += 1
                continue

            total_requests += 1
            ip = parsed['ip']
            path = parsed['path'].lower()
            status = parsed['status']
            ts = parsed['time']

            ip_data[ip]['total'] += 1
            ip_data[ip]['requests'].append(parsed)

            if status >= 400:
                ip_data[ip]['errors'] += 1
                error_requests += 1

            for ap in ATTACK_PATHS:
                if path == ap.lower() or path.startswith(ap.lower()):
                    ip_data[ip]['attack_paths'].add(ap)

            if parsed['method'] == 'POST' and any(
                p in path for p in ['/login', '/wp-login', '/signin', '/auth']
            ):
                if ts:
                    ip_data[ip]['post_login_times'].append(ts)

            if ts:
                hour_buckets[ts.strftime('%Y-%m-%d %H:00')] += 1

    return ip_data, total_requests, error_requests, hour_buckets, malformed


def detect_brute_force(post_times, window_minutes=20, threshold=50):
    if len(post_times) < threshold:
        return False
    sorted_times = sorted(post_times)
    window = timedelta(minutes=window_minutes)
    for i in range(len(sorted_times)):
        count = sum(1 for t in sorted_times[i:] if t - sorted_times[i] <= window)
        if count >= threshold:
            return True
    return False


def classify_ip(data):
    threats = []
    attack_count = len(data['attack_paths'])
    total = data['total']
    errors = data['errors']
    error_pct = (errors / total * 100) if total else 0

    if detect_brute_force(data['post_login_times']):
        threats.append('BRUTE_FORCE')
    if attack_count >= 3:
        threats.append('SCANNER')
    if error_pct >= 30 and total >= 20:
        threats.append('HIGH_ERROR_RATE')

    return threats, error_pct


def peak_window(hour_buckets):
    if not hour_buckets:
        return 'Unknown'
    return max(hour_buckets, key=hour_buckets.get)


def print_report(ip_data, total, errors, hour_buckets, malformed, filepath):
    init(autoreset=True)
    error_rate = (errors / total * 100) if total else 0

    print(Fore.CYAN + Style.BRIGHT + "\n  Apache / Nginx Log Security Analyser")
    print(Fore.CYAN + "  by Phil Atkins — phillipatkins.co.uk")
    print(Fore.CYAN + f"\n  File: {filepath}")
    print("  " + "─" * 54)
    print(f"  Total requests : {total:,}")
    print(f"  Unique IPs     : {len(ip_data):,}")
    print(f"  Error rate     : {Fore.RED if error_rate > 10 else Fore.GREEN}{error_rate:.1f}%{Style.RESET_ALL}")
    print(f"  Peak window    : {peak_window(hour_buckets)}")
    if malformed:
        print(f"  {Fore.YELLOW}Malformed lines : {malformed}{Style.RESET_ALL}")
    print("  " + "─" * 54)

    # Suspicious IPs
    flagged = []
    for ip, data in ip_data.items():
        threats, error_pct = classify_ip(data)
        if threats:
            flagged.append((ip, data, threats, error_pct))

    flagged.sort(key=lambda x: (-len(x[2]), -x[1]['total']))

    if not flagged:
        print(f"\n  {Fore.GREEN}No suspicious IPs detected.{Style.RESET_ALL}\n")
    else:
        print(f"\n  {Fore.RED}{Style.BRIGHT}Suspicious IPs ({len(flagged)} found):{Style.RESET_ALL}\n")
        for ip, data, threats, error_pct in flagged:
            threat_str = ' | '.join(threats)
            print(f"  {Fore.RED}{ip:<18}{Style.RESET_ALL}  {Fore.YELLOW}{threat_str}{Style.RESET_ALL}")
            print(f"    Requests: {data['total']}  Errors: {data['errors']} ({error_pct:.0f}%)")
            if data['attack_paths']:
                paths_str = ', '.join(sorted(data['attack_paths'])[:5])
                if len(data['attack_paths']) > 5:
                    paths_str += f" (+{len(data['attack_paths']) - 5} more)"
                print(f"    Attack paths: {Fore.RED}{paths_str}{Style.RESET_ALL}")
            if 'BRUTE_FORCE' in threats:
                print(f"    {Fore.RED}↳ {len(data['post_login_times'])} login POST requests detected{Style.RESET_ALL}")
            print()

    # Recommendations
    print("  " + "─" * 54)
    print(f"  {Style.BRIGHT}Recommendations:{Style.RESET_ALL}\n")

    rec_num = 1
    if flagged:
        ips = [ip for ip, _, _, _ in flagged]
        print(f"  {rec_num}. {Fore.RED}Block these IPs immediately:{Style.RESET_ALL}")
        for ip in ips[:10]:
            print(f"     iptables -A INPUT -s {ip} -j DROP")
        rec_num += 1
        print()

    if any('BRUTE_FORCE' in t for _, _, t, _ in flagged):
        print(f"  {rec_num}. {Fore.YELLOW}Enable login rate limiting (fail2ban or WAF rule){Style.RESET_ALL}")
        rec_num += 1

    if error_rate > 10:
        print(f"  {rec_num}. {Fore.YELLOW}Investigate high error rate ({error_rate:.1f}%) — possible server instability{Style.RESET_ALL}")
        rec_num += 1

    print(f"  {rec_num}. Add IPs to abuseipdb.com for cross-referencing")
    rec_num += 1
    print(f"  {rec_num}. Consider Cloudflare or similar WAF for ongoing protection")
    print()

    return flagged


def export_report(filepath, ip_data, flagged, total, error_rate):
    out_path = filepath + '_report.txt'
    with open(out_path, 'w') as f:
        f.write("Apache Log Security Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Log file: {filepath}\n\n")
        f.write(f"Total requests: {total:,}\n")
        f.write(f"Unique IPs: {len(ip_data):,}\n")
        f.write(f"Error rate: {error_rate:.1f}%\n\n")
        f.write("Suspicious IPs:\n")
        for ip, data, threats, error_pct in flagged:
            f.write(f"\n  {ip}\n")
            f.write(f"    Threats: {', '.join(threats)}\n")
            f.write(f"    Requests: {data['total']} | Errors: {data['errors']} ({error_pct:.0f}%)\n")
            if data['attack_paths']:
                f.write(f"    Attack paths: {', '.join(sorted(data['attack_paths']))}\n")
        f.write("\n--- End of report ---\n")
    return out_path


def output_json(ip_data, total, errors, hour_buckets, malformed, flagged):
    import json
    error_rate = (errors / total * 100) if total else 0
    results = []
    for ip, data, threats, error_pct in flagged:
        results.append({
            'ip': ip,
            'threats': threats,
            'total_requests': data['total'],
            'error_count': data['errors'],
            'error_pct': round(error_pct, 1),
            'attack_paths': sorted(data['attack_paths']),
            'brute_force_attempts': len(data['post_login_times']) if 'BRUTE_FORCE' in threats else 0,
        })
    print(json.dumps({
        'total_requests': total,
        'unique_ips': len(ip_data),
        'error_rate': round(error_rate, 1),
        'peak_window': peak_window(hour_buckets),
        'malformed_lines': malformed,
        'suspicious_ips': results,
    }))


def main():
    parser = argparse.ArgumentParser(description='Apache/Nginx log security analyser')
    parser.add_argument('logfile', nargs='?', help='Path to log file (.log or .log.gz)')
    parser.add_argument('--format', choices=['terminal', 'json'], default='terminal')
    args = parser.parse_args()

    filepath = args.logfile
    if not filepath:
        filepath = input("Log file path: ").strip()
    if not filepath:
        print("No file provided.")
        sys.exit(1)

    try:
        ip_data, total, errors, hour_buckets, malformed = analyse(filepath)
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        sys.exit(1)

    if args.format == 'json':
        # Need to classify all IPs first
        flagged = []
        for ip, data in ip_data.items():
            threats, error_pct = classify_ip(data)
            if threats:
                flagged.append((ip, data, threats, error_pct))
        flagged.sort(key=lambda x: (-len(x[2]), -x[1]['total']))
        output_json(ip_data, total, errors, hour_buckets, malformed, flagged)
        return

    flagged = print_report(ip_data, total, errors, hour_buckets, malformed, filepath)

    error_rate = (errors / total * 100) if total else 0
    out_path = export_report(filepath, ip_data, flagged, total, error_rate)
    print(f"  Full report saved → {out_path}\n")


if __name__ == '__main__':
    main()
