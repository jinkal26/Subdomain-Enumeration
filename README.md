# Subdomain-Enumeration
# Threaded Subdomain Enumerator

A safe, threaded subdomain enumeration tool written in Python.  
This project checks potential subdomains of a given domain and records the discovered active subdomains into an output file.  

---

## Features

- Load subdomain candidates from a wordlist (`subdomains.txt` by default)
- Multi-threaded scanning for faster enumeration
- Checks each subdomain via HTTP(S) request
- Stores discovered subdomains with URL and HTTP status code in an output file
- Queue + Lock ensures thread-safe operations
- Safe defaults prevent accidental scanning of third-party domains
- Minimal unit tests included (mocked requests, no network required)

---

## Installation

1. Clone the repository:

git clone https://github.com/jinkal26/subdomain-enumerator.git
cd subdomain-enumerator

2.Install dependencies:
pip install -r requirements.txt

3.Usage:
python subdomain_enumeration.py --domain example.com

| Option       | Description                                   | Default                     |
| ------------ | --------------------------------------------- | --------------------------- |
| `--domain`   | Target domain (must be in safe list)          | `example.com`               |
| `--wordlist` | Path to subdomain wordlist                    | `subdomains.txt`            |
| `--out`      | Output file for discovered subdomains         | `discovered_subdomains.txt` |
| `--threads`  | Number of worker threads                      | `20`                        |
| `--timeout`  | HTTP request timeout in seconds               | `3.0`                       |
| `--scheme`   | HTTP scheme (`http` or `https`)               | `http`                      |
| `--insecure` | Disable SSL certificate verification          | False                       |
| `--selftest` | Run built-in unit tests (no network required) | False                       |

Example
python subdomain_enumeration.py --domain example.com --threads 10 --scheme https

#Safe Defaults

To prevent accidental scanning of external domains, only a predefined set of "safe" domains are allowed by default:

example.com

example.org

example.net

localhost

127.0.0.1

localtest.me

Development / Testing-

Run the built-in tests:

python subdomain_enumeration.py --selftest

Tests use mocked HTTP responses, so no network connection is required.


OUTPUT:

<img width="1920" height="1080" alt="Image" src="https://github.com/user-attachments/assets/d52f7c45-17b1-4598-aa33-ac4c44c94e4a" />
