from findings.models import Asset, Finding


def ingest_records(normalized_records: list) -> dict:
    """
    Take a list of normalized finding dicts (see parsers.py) and write them
    into the DB, deduplicating along the way.

    Dedup rule: same CVE on the same asset is the same underlying finding,
    regardless of which scanner reported it. If two scanners both flag
    CVE-2023-1234 on host web-01, that's one Finding with two sources
    attached, not two separate findings.

    Findings without a CVE (common for DAST-style logic bugs like IDOR)
    fall back to matching on (asset, title) instead, since there's no
    universal ID to dedup against.
    """
    created_count = 0
    merged_count = 0

    for record in normalized_records:
        asset, _ = Asset.objects.get_or_create(
            identifier=record["asset_identifier"],
            defaults={
                "name": record["asset_name"],
                "asset_type": record["asset_type"],
            },
        )

        existing = None
        if record["cve_id"]:
            existing = Finding.objects.filter(
                asset=asset, cve_id=record["cve_id"]
            ).first()
        else:
            existing = Finding.objects.filter(
                asset=asset, title=record["title"], cve_id__isnull=True
            ).first()

        if existing:
            sources = set(existing.sources.split(",")) if existing.sources else set()
            sources.add(record["source"])
            existing.sources = ",".join(sorted(sources))
            # A second scanner's score for the same bug is worth keeping if
            # it's more severe than what we already had on file.
            existing.cvss_score = max(existing.cvss_score, record["cvss_score"])
            existing.save(update_fields=["sources", "cvss_score", "last_seen"])
            merged_count += 1
        else:
            Finding.objects.create(
                asset=asset,
                cve_id=record["cve_id"],
                title=record["title"],
                description=record["description"],
                severity=record["severity"],
                cvss_score=record["cvss_score"],
                sources=record["source"],
            )
            created_count += 1

    return {"created": created_count, "merged": merged_count}
