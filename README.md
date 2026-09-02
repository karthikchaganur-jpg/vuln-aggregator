# Vulnerability Aggregator and Prioritizer

A backend-only Django/DRF/Celery project that ingests findings from multiple
security scanners, deduplicates them, prioritizes by business risk, and
runs an async "exploit validation" step against them. It's a small-scale
version of what an exposure-validation platform like Strobes does.

## What it does

- Normalizes findings from three different mock scanner formats (Nessus,
  Snyk, and a generic DAST tool) into one common schema
- Deduplicates findings that multiple scanners report on the same asset,
  merging them into one record with a combined `sources` list
- Computes a `priority_score` from CVSS score x asset business criticality
- Exposes a filterable, sortable REST API over findings and assets
- Runs an async Celery task per finding that simulates an exploit-agent
  proving (or disproving) that a finding is actually exploitable

## Stack

Python, Django, Django REST Framework, django-filter, Celery, Redis.

## Setup

### 1. Install Redis

Celery needs a message broker. Redis is the simplest option locally.

```bash
# macOS
brew install redis
brew services start redis

# Ubuntu/Debian
sudo apt install redis-server
sudo systemctl start redis-server
```

Confirm it's running: `redis-cli ping` should return `PONG`.

### 2. Install Python dependencies

```bash
python -m venv venv
source venv/bin/activate   # venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### 3. Set up the database

```bash
python manage.py migrate
python manage.py createsuperuser   # optional, for the admin panel
```

### 4. Run everything (three terminals)

Terminal 1, Django dev server:
```bash
python manage.py runserver
```

Terminal 2, Celery worker:
```bash
celery -A config worker --loglevel=info
```

Terminal 3, use it:
```bash
# Ingest the sample data from all three scanners
python manage.py ingest_findings nessus sample_data/nessus_export.json
python manage.py ingest_findings snyk sample_data/snyk_export.json
python manage.py ingest_findings generic_dast sample_data/generic_dast_export.json
```

You should see output like:

```
Ingested nessus: 3 new findings, 0 merged into existing findings.
Ingested snyk: 2 new findings, 1 merged into existing findings.
Ingested generic_dast: 3 new findings, 0 merged into existing findings.
```

The "1 merged" happens because the sample Nessus and Snyk files both
report the same Heartbleed CVE on the same host. That's the dedup logic
working as intended.

## API

Browsable API root: `http://localhost:8000/api/findings/`
Admin panel: `http://localhost:8000/admin/`

### List and filter findings

```
GET /api/findings/
GET /api/findings/?severity=critical
GET /api/findings/?min_cvss=8
GET /api/findings/?max_cvss=9
GET /api/findings/?status=new
GET /api/findings/?source=nessus
GET /api/findings/?ordering=-cvss_score
GET /api/findings/?ordering=-priority_score
```

### Trigger validation

```
POST /api/findings/<id>/validate/
```
Kicks off async validation for one finding. Returns immediately with a
task ID while the Celery worker processes it in the background. Poll
`GET /api/findings/<id>/` afterward to watch the status move through
`new` -> `validating` -> `validated` or `false_positive`.

```
POST /api/findings/validate_bulk/
```
Same thing, but for every finding currently in `new` status. Good to run
right after an ingest.

## Design notes worth knowing for an interview

- **Why dedup on (asset, CVE) and not just CVE**: the same CVE can exist
  on ten different hosts. Deduping globally by CVE would incorrectly
  merge unrelated instances. Dedup has to be scoped to "same bug on the
  same thing."
- **Why findings without a CVE fall back to (asset, title) matching**:
  a lot of real findings, especially from DAST tools, are logic bugs
  like IDOR that don't have a CVE at all. The dedup logic can't assume
  every finding has one.
- **Why `priority_score` is a Python property, not a DB column**: it's
  a derived value (`cvss_score * asset.criticality`). Keeping it as a
  property avoids data getting out of sync if criticality changes later.
  The trade-off, visible in `views.py`, is that sorting by it can't use
  the database and falls back to an in-memory sort. Fine at this scale;
  at real scale you'd denormalize it into an indexed column.
- **Why Celery instead of doing validation synchronously**: a real
  exploit attempt takes real time (the code simulates this with
  `time.sleep`). Doing that inside a request/response cycle would block
  the API and time out on any bulk operation. Async lets `validate_bulk`
  fan out to dozens of findings without blocking.

## Sample data

`sample_data/` has three files, one per scanner format, designed so
that ingesting all three produces one intentional duplicate (Heartbleed,
reported by both Nessus and Snyk on the same host) so you can see the
dedup logic do its job.
