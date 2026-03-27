import ipaddress
import socket


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except Exception:
        return False


def _try_import_whois():
    try:
        import whois  # type: ignore
        return whois, None
    except Exception as e:
        return None, str(e)


def _try_import_dns():
    try:
        import dns.resolver  # type: ignore
        return dns.resolver, None
    except Exception as e:
        return None, str(e)


def _normalize_field(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value)
    return str(value)


def lookup_whois(target: str):
    whois_mod, err = _try_import_whois()
    if err:
        return None, f"whois import failed: {err}"

    try:
        result = whois_mod.whois(target)
    except Exception as e:
        return None, f"whois lookup failed: {e}"

    data = {
        "domain_name": _normalize_field(getattr(result, "domain_name", None)),
        "registrar": _normalize_field(getattr(result, "registrar", None)),
        "creation_date": _normalize_field(getattr(result, "creation_date", None)),
        "expiration_date": _normalize_field(getattr(result, "expiration_date", None)),
        "updated_date": _normalize_field(getattr(result, "updated_date", None)),
        "name_servers": _normalize_field(getattr(result, "name_servers", None)),
        "status": _normalize_field(getattr(result, "status", None)),
        "emails": _normalize_field(getattr(result, "emails", None)),
        "org": _normalize_field(getattr(result, "org", None)),
        "country": _normalize_field(getattr(result, "country", None)),
    }
    return data, None


def _resolve_records(resolver, target: str, rtype: str):
    try:
        answers = resolver.resolve(target, rtype)
        return [str(r).rstrip(".") for r in answers], None
    except Exception as e:
        return [], str(e)


def lookup_dns(target: str):
    if _is_ip(target):
        return None, "DNS record lookup expects a domain, not an IP address"

    resolver, err = _try_import_dns()
    if err:
        # fallback only for A/AAAA via socket
        a_records = set()
        aaaa_records = set()
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(target, None):
                if fam == socket.AF_INET:
                    a_records.add(sockaddr[0])
                elif fam == socket.AF_INET6:
                    aaaa_records.add(sockaddr[0])
        except Exception as e:
            return {
                "A": [],
                "AAAA": [],
                "MX": [],
                "NS": [],
                "errors": [f"dns import failed: {err}", f"socket fallback failed: {e}"],
            }, None

        return {
            "A": sorted(a_records),
            "AAAA": sorted(aaaa_records),
            "MX": [],
            "NS": [],
            "errors": [f"dns import failed: {err}", "MX/NS requires dnspython"],
        }, None

    a_records, a_err = _resolve_records(resolver, target, "A")
    aaaa_records, aaaa_err = _resolve_records(resolver, target, "AAAA")
    mx_records, mx_err = _resolve_records(resolver, target, "MX")
    ns_records, ns_err = _resolve_records(resolver, target, "NS")

    errors = []
    for e in (a_err, aaaa_err, mx_err, ns_err):
        if e:
            errors.append(e)

    return {
        "A": a_records,
        "AAAA": aaaa_records,
        "MX": mx_records,
        "NS": ns_records,
        "errors": errors,
    }, None


def run_passive_recon(target: str):
    results = {
        "whois": None,
        "dns": None,
        "errors": [],
    }

    whois_data, whois_err = lookup_whois(target)
    if whois_err:
        results["errors"].append(whois_err)
    else:
        results["whois"] = whois_data

    dns_data, dns_err = lookup_dns(target)
    if dns_err:
        results["errors"].append(dns_err)
    else:
        results["dns"] = dns_data

    return results
