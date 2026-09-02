import json

from django.core.management.base import BaseCommand, CommandError

from findings.ingest.parsers import parse_file
from findings.ingest.service import ingest_records


class Command(BaseCommand):
    help = "Ingest a scanner export file and merge it into the findings database."

    def add_arguments(self, parser):
        parser.add_argument(
            "source",
            choices=["nessus", "snyk", "generic_dast"],
            help="Which scanner format the file is in.",
        )
        parser.add_argument("filepath", help="Path to the JSON export file.")

    def handle(self, *args, **options):
        source = options["source"]
        filepath = options["filepath"]

        try:
            with open(filepath) as f:
                raw_records = json.load(f)
        except FileNotFoundError:
            raise CommandError(f"File not found: {filepath}")
        except json.JSONDecodeError as e:
            raise CommandError(f"Invalid JSON in {filepath}: {e}")

        normalized = parse_file(source, raw_records)
        result = ingest_records(normalized)

        self.stdout.write(
            self.style.SUCCESS(
                f"Ingested {source}: {result['created']} new findings, "
                f"{result['merged']} merged into existing findings."
            )
        )
