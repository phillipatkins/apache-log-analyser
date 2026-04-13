# Apache Log Security Analyser

Built by [Phil Atkins](https://phillipatkins.co.uk)

---

A client called me because their website had been "running slow" for a week. Their hosting company kept saying everything looked fine.

First thing I did: download the Apache access logs.

5,000 lines. Inside 30 seconds I had the picture — one IP hammering known attack paths, another brute-forcing the login page, error rate 3x normal, all of it happening between 3:30 and 4am. The "slow website" was a server under active attack that nobody was watching.

I built a parser that turns a raw log file into a prioritised report in seconds.

---

## What it detects

- **Scanners** — IPs hitting 3+ known attack paths (`/.env`, `/wp-admin`, `/.git/config`, `/etc/passwd`, `/phpMyAdmin` etc.)
- **Brute force** — IPs firing 50+ POST requests to login endpoints in any 20-minute window
- **High error rate** — IPs with 30%+ 4xx/5xx response rate across significant request volume
- **Peak attack window** — the hour with the most suspicious activity
- **Overall error rate** — flags if the server is under strain

Works with Apache and Nginx combined log format. Handles gzipped logs too (`.log.gz`).

---

## Setup

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Run against the included sample log
python analyser.py sample.log

# Run against your own log
python analyser.py /var/log/apache2/access.log
python analyser.py /var/log/nginx/access.log.gz
```

---

## Output

Colour-coded terminal report showing:
- Summary stats (total requests, unique IPs, error rate, peak attack window)
- Each suspicious IP with its threat classification and attack paths
- `iptables` block commands ready to copy-paste
- Prioritised recommendations

A plain text report is saved alongside the log file.

---

## Sample log

The included `sample.log` has ~900 lines with:
- Normal browsing traffic throughout the day
- A scanner hitting known attack paths over 6 hours
- A brute force attack on `/wp-login.php`
- A couple of other suspicious IPs

Run `python analyser.py sample.log` to see the tool in action.

---

MIT License — Phil Atkins 2026 — [phillipatkins.co.uk](https://phillipatkins.co.uk)
