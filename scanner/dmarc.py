"""DMARC record lookup and evaluation."""

import dns.resolver

resolver = dns.resolver.Resolver()
resolver.timeout = 5
resolver.lifetime = 10

# What each DMARC policy actually does to failing mail.
POLICIES = {
    "reject": (
        "enforcing",
        "Forged mail claiming to be from this domain is rejected.",
    ),
    "quarantine": (
        "partial",
        "Forged mail is sent to spam, but still reaches the recipient.",
    ),
    "none": (
        "weak",
        "Forged mail is delivered normally. The policy only monitors.",
    ),
}


def get_dmarc(domain):
    """
    Look up the DMARC record for a domain.

    DMARC always lives on the _dmarc subdomain, not the domain itself.

    Returns:
        str  - the raw DMARC record, if found
        None - no DMARC record
        dict - {"error": "..."} if the lookup failed
    """
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # No _dmarc subdomain at all means no DMARC.
        return None
    except dns.resolver.NoNameservers:
        return {"error": "no nameservers responded"}
    except dns.resolver.LifetimeTimeout:
        return {"error": "lookup timed out"}

    for record in answers:
        text = b"".join(record.strings).decode()
        if text.lower().startswith("v=dmarc1"):
            return text

    return None


def parse_tags(record):
    """
    Turn 'v=DMARC1; p=none; rua=mailto:x@y.no' into a dict.
    Tag names are lowercased, values are kept as-is.
    """
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def evaluate_dmarc(domain):
    """
    Look up and evaluate a domain's DMARC record.

    Returns a dict with:
        status            - "missing" | "enforcing" | "partial" | "weak"
                            | "broken" | "error"
        record            - the raw DMARC string, or None
        policy            - "reject" | "quarantine" | "none" | None
        subdomain_policy  - the sp tag, if present
        pct               - percentage of mail the policy applies to
        reporting         - True if the domain collects reports
        rua_domain        - where aggregate reports are sent
        detail            - short human-readable explanation
    """
    result = get_dmarc(domain)

    if result is None:
        return {
            "status": "missing",
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "pct": None,
            "reporting": False,
            "rua_domain": "",
            "detail": "No DMARC record. Nothing stops anyone from forging this domain.",
        }

    if isinstance(result, dict):
        return {
            "status": "error",
            "record": None,
            "policy": None,
            "subdomain_policy": None,
            "pct": None,
            "reporting": False,
            "rua_domain": "",
            "detail": result["error"],
        }

    tags = parse_tags(result)
    policy = tags.get("p", "").lower()

    # rua is where aggregate reports get sent. No rua means the
    # domain owner never sees who is forging them.
    reporting = "rua" in tags

    # Reports may be sent to a third party rather than the domain
    # owner, so we keep the destination domain for later evaluation.
    rua_domain = ""
    if "rua" in tags and "@" in tags["rua"]:
        rua_domain = tags["rua"].split("@")[-1].split(",")[0].strip()

    # sp sets the policy for subdomains. If the main policy enforces
    # but sp=none, an attacker can simply forge mail.domain.no instead.
    subdomain_policy = tags.get("sp", "").lower() or None

    # pct limits how much mail the policy applies to. Default is 100.
    try:
        pct = int(tags.get("pct", "100"))
    except ValueError:
        pct = 100

    if policy not in POLICIES:
        return {
            "status": "broken",
            "record": result,
            "policy": policy or None,
            "subdomain_policy": subdomain_policy,
            "pct": pct,
            "reporting": reporting,
            "rua_domain": rua_domain,
            "detail": "DMARC record exists but has no valid policy tag.",
        }

    status, detail = POLICIES[policy]

    # A policy applied to only part of the mail flow is not real enforcement.
    if pct < 100 and status == "enforcing":
        status = "partial"
        detail = f"Policy is reject, but only applied to {pct}% of mail."

    # A subdomain gap undermines an otherwise strong policy.
    if policy == "reject" and subdomain_policy == "none":
        status = "partial"
        detail = (
            "The domain itself is protected, but subdomains are not. "
            "An attacker can forge mail from any subdomain."
        )

    return {
        "status": status,
        "record": result,
        "policy": policy,
        "subdomain_policy": subdomain_policy,
        "pct": pct,
        "reporting": reporting,
        "rua_domain": rua_domain,
        "detail": detail,
    }