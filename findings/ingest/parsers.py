"""
Each scanner exports findings in its own shape. Real tools (Nessus, Snyk,
Burp, Qualys...) don't agree on field names, severity scales, or how they
identify an asset. The job of a parser is to normalize one scanner's raw
export into a single common dict shape so the rest of the pipeline never
has to know which scanner a finding came from.

Common normalized shape:
{
    "source": "nessus",
    "cve_id": "CVE-2023-1234" | None,
    "title": str,
    "description": str,
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "cvss_score": float,
    "asset_identifier": str,
    "asset_name": str,
    "asset_type": "host" | "web_app" | "repo" | "api" | "cloud_resource",
}
"""

# Nessus reports severity as an integer 0-4 rather than a word.
NESSUS_SEVERITY_MAP = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def parse_nessus(raw: dict) -> dict:
    return {
        "source": "nessus",
        "cve_id": raw.get("cve"),
        "title": raw["plugin_name"],
        "description": raw.get("synopsis", ""),
        "severity": NESSUS_SEVERITY_MAP.get(raw.get("severity", 0), "info"),
        "cvss_score": float(raw.get("cvss_base_score", 0.0)),
        "asset_identifier": raw["host"],
        "asset_name": raw["host"],
        "asset_type": "host",
    }


def parse_snyk(raw: dict) -> dict:
    # Snyk nests CVSS under a scoring object and uses its own severity words
    # that happen to match ours, but that's not guaranteed for every source.
    return {
        "source": "snyk",
        "cve_id": (raw.get("identifiers", {}).get("CVE") or [None])[0],
        "title": raw["title"],
        "description": raw.get("description", ""),
        "severity": raw.get("severity", "low"),
        "cvss_score": float(raw.get("cvssScore", 0.0)),
        "asset_identifier": raw["projectName"],
        "asset_name": raw["projectName"],
        "asset_type": "repo",
    }


def parse_generic_dast(raw: dict) -> dict:
    # A stand-in for something like Burp or a custom DAST tool: severity is
    # a free-text label with different casing/wording than our schema.
    severity_map = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Info": "info",
    }
    return {
        "source": "generic_dast",
        "cve_id": raw.get("cve_reference"),
        "title": raw["vulnerability_name"],
        "description": raw.get("details", ""),
        "severity": severity_map.get(raw.get("risk_level", "Info"), "info"),
        "cvss_score": float(raw.get("cvss", 0.0)),
        "asset_identifier": raw["endpoint_url"],
        "asset_name": raw["endpoint_url"],
        "asset_type": "api",
    }


PARSERS = {
    "nessus": parse_nessus,
    "snyk": parse_snyk,
    "generic_dast": parse_generic_dast,
}


def parse_file(source: str, records: list) -> list:
    """Run the right parser over a list of raw records from one scanner."""
    if source not in PARSERS:
        raise ValueError(f"No parser registered for source '{source}'")
    parser = PARSERS[source]
    return [parser(r) for r in records]
