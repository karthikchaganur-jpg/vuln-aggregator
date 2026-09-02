from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .filters import FindingFilter
from .models import Asset, Finding
from .serializers import AssetSerializer, FindingSerializer
from .tasks import validate_finding, validate_findings_bulk


class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer


class FindingViewSet(viewsets.ModelViewSet):
    queryset = Finding.objects.select_related("asset").all()
    serializer_class = FindingSerializer
    filterset_class = FindingFilter
    ordering_fields = ["cvss_score", "first_seen", "last_seen"]

    def filter_queryset(self, queryset):
        # Run the normal DRF/django-filter filtering first, which needs a
        # real QuerySet (it inspects .model). Only after that do we drop
        # to a plain list to sort by priority_score, since that's a Python
        # property rather than a database column.
        queryset = super().filter_queryset(queryset)
        ordering = self.request.query_params.get("ordering")
        if ordering in ("priority_score", "-priority_score"):
            reverse = ordering.startswith("-")
            queryset = sorted(queryset, key=lambda f: f.priority_score, reverse=reverse)
        return queryset

    @action(detail=True, methods=["post"])
    def validate(self, request, pk=None):
        """Kick off async exploit validation for a single finding."""
        finding = self.get_object()
        task = validate_finding.delay(finding.id)
        return Response(
            {"finding_id": finding.id, "task_id": task.id, "status": "queued"},
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=False, methods=["post"])
    def validate_bulk(self, request):
        """
        Kick off async validation for every 'new' finding, e.g. right after
        an ingest run. Mirrors triggering the exploit agents on a fresh
        batch of scanner results.
        """
        ids = list(
            self.get_queryset().filter(status="new").values_list("id", flat=True)
        )
        if not ids:
            return Response({"detail": "No new findings to validate."})
        task = validate_findings_bulk.delay(ids)
        return Response(
            {"queued_count": len(ids), "task_id": task.id},
            status=status.HTTP_202_ACCEPTED,
        )
