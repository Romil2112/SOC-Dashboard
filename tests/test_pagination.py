"""Tests for server-side pagination on GET /api/alerts and /api/alerts/all."""
import psycopg2
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _delete_all_alerts(db_url):
    """Clear the alerts table so pagination-at-zero can be tested."""
    with psycopg2.connect(db_url) as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM alerts")
    conn.commit()


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------

def test_open_alerts_returns_paginated_envelope(client):
    r = client.get("/api/alerts")
    assert r.status_code == 200
    d = r.get_json()
    assert set(d.keys()) >= {"alerts", "page", "per_page", "total", "total_pages"}
    assert isinstance(d["alerts"], list)
    assert isinstance(d["total"], int)


def test_all_alerts_returns_paginated_envelope(client):
    r = client.get("/api/alerts/all")
    assert r.status_code == 200
    d = r.get_json()
    assert set(d.keys()) >= {"alerts", "page", "per_page", "total", "total_pages"}


def test_default_page_and_per_page(client):
    d = client.get("/api/alerts").get_json()
    assert d["page"] == 1
    assert d["per_page"] == 100


def test_total_pages_matches_total_and_per_page(client):
    d = client.get("/api/alerts/all?per_page=2").get_json()
    expected = (d["total"] + d["per_page"] - 1) // d["per_page"] if d["total"] else 0
    assert d["total_pages"] == expected


# ---------------------------------------------------------------------------
# Pagination mechanics
# ---------------------------------------------------------------------------

def test_per_page_limits_returned_rows(client):
    d = client.get("/api/alerts/all?per_page=2").get_json()
    assert len(d["alerts"]) <= 2


def test_page_two_offset_is_applied(client):
    d1 = client.get("/api/alerts/all?per_page=2&page=1").get_json()
    d2 = client.get("/api/alerts/all?per_page=2&page=2").get_json()
    ids_p1 = {a["id"] for a in d1["alerts"]}
    ids_p2 = {a["id"] for a in d2["alerts"]}
    assert ids_p1.isdisjoint(ids_p2), "page 1 and page 2 should not share alerts"


def test_page_beyond_last_returns_empty_alerts(client):
    d = client.get("/api/alerts/all?page=9999&per_page=100").get_json()
    assert d["alerts"] == []
    assert d["total"] > 0          # total still reflects the real count
    assert d["page"] == 9999


def test_total_is_stable_across_pages(client):
    d1 = client.get("/api/alerts/all?page=1&per_page=2").get_json()
    d2 = client.get("/api/alerts/all?page=2&per_page=2").get_json()
    assert d1["total"] == d2["total"]


# ---------------------------------------------------------------------------
# Filters + pagination: total reflects the filtered set
# ---------------------------------------------------------------------------

def test_severity_filter_total_is_filtered_not_full_table(client):
    d_all = client.get("/api/alerts/all").get_json()
    d_crit = client.get("/api/alerts/all?severity=CRITICAL").get_json()
    assert d_crit["total"] < d_all["total"]
    for a in d_crit["alerts"]:
        assert a["severity"] == "CRITICAL"


def test_filter_combined_with_explicit_page(client):
    d = client.get("/api/alerts/all?severity=CRITICAL&page=1&per_page=50").get_json()
    assert d["page"] == 1
    for a in d["alerts"]:
        assert a["severity"] == "CRITICAL"


def test_open_queue_total_excludes_closed_alerts(client):
    d_open = client.get("/api/alerts").get_json()
    d_all = client.get("/api/alerts/all").get_json()
    # fixture has 2 closed (true_positive + escalated) and 2 open
    assert d_open["total"] < d_all["total"]


# ---------------------------------------------------------------------------
# Empty table
# ---------------------------------------------------------------------------

def test_empty_table_returns_zeros(client):
    import os
    _delete_all_alerts(os.environ["DATABASE_URL"])
    d = client.get("/api/alerts/all").get_json()
    assert d["alerts"] == []
    assert d["total"] == 0
    assert d["total_pages"] == 0


def test_empty_table_open_queue_also_zero(client):
    import os
    _delete_all_alerts(os.environ["DATABASE_URL"])
    d = client.get("/api/alerts").get_json()
    assert d["total"] == 0 and d["alerts"] == []


# ---------------------------------------------------------------------------
# Validation — invalid inputs return 400
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("qs", ["page=0", "page=-1", "page=-100"])
def test_invalid_page_returns_400(client, qs):
    r = client.get(f"/api/alerts?{qs}")
    assert r.status_code == 400


@pytest.mark.parametrize("qs", ["per_page=0", "per_page=-1", "per_page=501", "per_page=9999"])
def test_invalid_per_page_returns_400(client, qs):
    r = client.get(f"/api/alerts?{qs}")
    assert r.status_code == 400


def test_non_integer_page_returns_400(client):
    assert client.get("/api/alerts?page=abc").status_code == 400


def test_non_integer_per_page_returns_400(client):
    assert client.get("/api/alerts?per_page=abc").status_code == 400


def test_per_page_500_is_allowed(client):
    assert client.get("/api/alerts?per_page=500").status_code == 200


def test_400_response_has_json_error_body(client):
    d = client.get("/api/alerts?page=0").get_json()
    assert "error" in d


# ---------------------------------------------------------------------------
# Both endpoints accept same pagination params
# ---------------------------------------------------------------------------

def test_all_alerts_endpoint_also_validates_page(client):
    assert client.get("/api/alerts/all?page=-1").status_code == 400


def test_all_alerts_endpoint_also_validates_per_page(client):
    assert client.get("/api/alerts/all?per_page=0").status_code == 400
