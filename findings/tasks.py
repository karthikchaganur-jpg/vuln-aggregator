import random
import time

from celery import shared_task

from .models import Finding


@shared_task
def validate_finding(finding_id: int):
    """
    Simulates what Strobes' exploit agents actually do: take a raw finding
    and attempt to prove it's exploitable in an isolated environment.

    Here we fake the "attempt" with a short delay and a weighted random
    outcome (higher CVSS = more likely to be a real, validated exploit,
    which loosely mirrors how easier-to-exploit bugs tend to score higher).
    Swap this function's body for a real exploit harness and the rest of
    the system doesn't have to change.
    """
    try:
        finding = Finding.objects.get(id=finding_id)
    except Finding.DoesNotExist:
        return f"Finding {finding_id} no longer exists"

    finding.status = "validating"
    finding.save(update_fields=["status"])

    # Simulate the time a real exploit attempt would take.
    time.sleep(3)

    exploit_probability = min(finding.cvss_score / 10, 0.95)
    is_exploitable = random.random() < exploit_probability

    finding.status = "validated" if is_exploitable else "false_positive"
    finding.save(update_fields=["status"])

    return f"Finding {finding_id} -> {finding.status}"


@shared_task
def validate_findings_bulk(finding_ids: list):
    """Fan out validation across many findings, e.g. after a fresh ingest."""
    for fid in finding_ids:
        validate_finding.delay(fid)
    return f"Queued validation for {len(finding_ids)} findings"
