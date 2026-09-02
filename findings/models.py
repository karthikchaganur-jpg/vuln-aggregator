from django.db import models


class Asset(models.Model):
    """Something that can have vulnerabilities: a host, repo, API, etc."""

    ASSET_TYPES = [
        ("host", "Host"),
        ("web_app", "Web Application"),
        ("repo", "Code Repository"),
        ("api", "API Endpoint"),
        ("cloud_resource", "Cloud Resource"),
    ]

    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=32, choices=ASSET_TYPES)
    identifier = models.CharField(
        max_length=255,
        unique=True,
        help_text="Unique handle, e.g. hostname, repo URL, or ARN",
    )
    # A rough 1-10 business-criticality score, set by whoever owns the asset.
    # This is what turns "CVSS 9.1" into "CVSS 9.1 on our payments API",
    # which is the whole point of risk-based prioritization.
    criticality = models.PositiveSmallIntegerField(default=5)

    def __str__(self):
        return f"{self.name} ({self.asset_type})"


class Finding(models.Model):
    """A normalized vulnerability finding, deduplicated across scanners."""

    SEVERITY_CHOICES = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("info", "Informational"),
    ]

    STATUS_CHOICES = [
        ("new", "New"),
        ("validating", "Validating"),
        ("validated", "Validated - Exploitable"),
        ("false_positive", "False Positive"),
        ("fixed", "Fixed"),
    ]

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="findings")
    cve_id = models.CharField(max_length=32, blank=True, null=True, db_index=True)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES)
    cvss_score = models.FloatField(default=0.0)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="new")

    # Every scanner that reported this same underlying issue. Stored as a
    # comma-separated list of source names for simplicity; a real system
    # would use a related model, but this keeps the dedup logic readable.
    sources = models.CharField(max_length=255, default="")

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-cvss_score"]

    def __str__(self):
        return f"{self.title} [{self.severity}] on {self.asset.name}"

    @property
    def priority_score(self):
        """
        Combine exploit severity with business impact.
        CVSS is capped at 10, criticality is 1-10, so this stays in a
        readable 0-100-ish range without needing external normalization.
        """
        return round(self.cvss_score * self.asset.criticality, 2)
