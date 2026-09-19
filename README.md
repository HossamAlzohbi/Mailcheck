# Mailcheck

Checks whether a domain is protected against email spoofing, and
produces a report a non-technical business owner can act on.

## The problem

Email has no built-in sender verification. Anyone can put
`faktura@yourcompany.no` in the From field and send mail that looks
like it came from you. This is how invoice fraud works: a message
that appears to come from a supplier, asking for payment to a new
account number.

Three DNS records exist to stop this:

- **SPF** lists which servers may send mail for the domain
- **DKIM** signs outgoing mail so the recipient can verify it
- **DMARC** decides what happens when SPF or DKIM fails

The last one is where most domains fall short. A DMARC policy set to
`p=none` records forgery attempts and delivers them anyway. The
mechanism is there, but it enforces nothing.

## What it does

For each domain, Mailcheck queries public DNS and classifies the
result:

- SPF: missing, weak (`~all`), enforcing (`-all`), or broken
- DMARC: missing, weak (`p=none`), partial, or enforcing
- DKIM: probes 16 common selectors

It then generates a PDF report in Norwegian explaining what is wrong
and which DNS values to change, staged so the fix does not block the
company's own mail.

## Usage
 
Install the dependencies:
```
pip install dnspython reportlab
```
 
Scan a single domain:
 
```
python main.py example.no
```
 
Scan a single domain and write a PDF report:
 
```
python main.py example.no --report
```
Scan every domain listed in a file:
 
```
python main.py domains.txt --report
```

Batch mode writes a CSV to `results/` and one PDF per domain to
`reports/`.

## Limitations

**DKIM cannot be enumerated.** Selector names are chosen by whoever
configured the domain and cannot be listed from DNS. A negative
result means none of the 16 probed selectors responded, not that
DKIM is absent. The report states this explicitly.

**Third-party reporting is flagged, not judged.** A `rua` address
pointing elsewhere may be a DMARC vendor the company pays for, or a
hosting provider that set it up for itself. DNS cannot distinguish
these, so the report asks rather than asserts.

**SPF lookup limits are not checked yet.** SPF permits at most 10
DNS lookups; exceeding it makes the whole record fail silently.
Following `include:` chains recursively is not implemented.

## Scope

All checks are passive DNS queries against publicly published
records. No connection is made to any scanned organisation's systems.