"""DKIM selector discovery."""

import dns.resolver
resolver = dns.resolver.Resolver()
resolver.timeout = 5
resolver.lifetime = 10

# DKIM keys live at <selector>._domainkey.<domain>, and the selector
# name is chosen by whoever set it up. There is no way to list them,
# so we probe the ones used by common mail providers.
COMMON_SELECTORS = [
    ("google", "Google Workspace"),
    ("selector1", "Microsoft 365"),
    ("selector2", "Microsoft 365"),
    ("k1", "Mailchimp / Klaviyo"),
    ("mandrill", "Mailchimp Transactional"),
    ("dkim", "generic"),
    ("default", "generic"),
    ("mail", "generic"),
    ("smtp", "generic"),
    ("s1", "generic"),
    ("s2", "generic"),
    ("zoho", "Zoho Mail"),
    ("fd", "Sendgrid"),
    ("mailjet", "Mailjet"),
    ("pm", "Postmark"),
    ("resend", "Resend"),
]


def probe_selector(domain, selector):
    """
    Check whether a DKIM key exists at this selector.
    Returns the record text, or None.
    """
    try:
        answers = resolver.resolve(
            f"{selector}._domainkey.{domain}", "TXT"
        )
    except Exception:
        # Any failure here means "not found at this selector".
        # We probe many, so we do not care which error it was.
        return None

    for record in answers:
        text = b"".join(record.strings).decode()
        if "p=" in text:          # p= holds the public key
            return text

    return None


def evaluate_dkim(domain):
    """
    Probe common DKIM selectors for a domain.

    Note: a negative result does NOT prove DKIM is absent. It only
    means none of the selectors we know about were found. This is a
    limitation of DNS: selectors cannot be enumerated.

    Returns a dict with:
        status    - "found" | "not_found"
        selectors - list of (selector, provider) tuples that responded
        detail    - short human-readable explanation
    """
    found = []

    for selector, provider in COMMON_SELECTORS:
        if probe_selector(domain, selector):
            found.append((selector, provider))

    if found:
        names = ", ".join(s for s, _ in found)
        return {
            "status": "found",
            "selectors": found,
            "detail": f"DKIM keys published at: {names}",
        }

    return {
        "status": "not_found",
        "selectors": [],
        "detail": (
            "No DKIM key found at any common selector. "
            "Mail from this domain may not be signed."
        ),
    }