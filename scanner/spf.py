"""SPF record lookup and evaluation."""

import dns.resolver

resolver = dns.resolver.Resolver()
resolver.timeout = 5
resolver.lifetime = 10

# What the trailing "all" mechanism means for unlisted senders.
# The qualifier is the character immediately before "all".
ALL_QUALIFIERS = {
    "-": ("reject", "enforcing"),
    "~": ("softfail", "weak"),
    "?": ("neutral", "weak"),
    "+": ("pass", "broken"),
}


def get_spf(domain):
    """
    Look up the SPF record for a domain.

    Returns:
        str  - the raw SPF record, if found
        None - domain resolves but has no SPF record
        dict - {"error": "..."} if the lookup failed
    """
    try:
        answers = resolver.resolve(domain, "TXT")
    except dns.resolver.NXDOMAIN:
        return {"error": "domain does not exist"}
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NoNameservers:
        return {"error": "no nameservers responded"}
    except dns.resolver.LifetimeTimeout:
        return {"error": "lookup timed out"}

    for record in answers:
        # DNS splits long strings into chunks of max 255 chars,
        # so we join them back together before decoding.
        text = b"".join(record.strings).decode()

        if text.lower().startswith("v=spf1"):
            return text

    return None


def evaluate_spf(domain):
    """
    Look up and evaluate a domain's SPF record.

    Returns a dict with:
        status   - "missing" | "enforcing" | "weak" | "broken" | "error"
        record   - the raw SPF string, or None
        policy   - "reject" | "softfail" | "neutral" | "pass" | None
        detail   - short human-readable explanation
    """
    result = get_spf(domain)

    if result is None:
        return {
            "status": "missing",
            "record": None,
            "policy": None,
            "detail": "No SPF record. Anyone can send mail as this domain.",
        }

    if isinstance(result, dict):
        return {
            "status": "error",
            "record": None,
            "policy": None,
            "detail": result["error"],
        }

    # Find the trailing all-mechanism, e.g. "~all" or "-all".
    # It is normally last, but we scan all terms to be safe.
    qualifier = None
    for term in result.split():
        if term.lower().endswith("all") and len(term) <= 4:
            qualifier = term[0] if term[0] in ALL_QUALIFIERS else "+"

    if qualifier is None:
        return {
            "status": "broken",
            "record": result,
            "policy": None,
            "detail": "SPF record has no 'all' mechanism, so it enforces nothing.",
        }

    policy, status = ALL_QUALIFIERS[qualifier]

    details = {
        "reject": "SPF rejects mail from unlisted senders.",
        "softfail": "SPF marks unlisted senders as suspect but still delivers them.",
        "neutral": "SPF takes no position on unlisted senders.",
        "pass": "SPF allows any sender. This is the same as having no protection.",
    }

    return {
        "status": status,
        "record": result,
        "policy": policy,
        "detail": details[policy],
    }