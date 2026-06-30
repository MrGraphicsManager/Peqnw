"""Backend tests for pean GFX v2 - launch toggle, discount, admin pack CRUD."""
import os
import uuid
import pytest
import requests

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") + "/api"
ADMIN_EMAIL = "admin@pean.com"
ADMIN_PASS = "Pean@2026"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture(scope="module")
def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def _slug():
    return f"test-{uuid.uuid4().hex[:8]}"


# Public packs expose new fields, never drive_link
def test_public_packs_fields():
    r = requests.get(f"{BASE}/packs")
    assert r.status_code == 200
    data = r.json()
    assert len(data) >= 2
    for p in data:
        for f in ("id", "slug", "price", "original_price", "discount_percent", "is_launched"):
            assert f in p, f"missing {f}"
        assert "drive_link" not in p


def test_no_discount_price_equals_original():
    r = requests.get(f"{BASE}/packs")
    for p in r.json():
        if p["discount_percent"] == 0:
            assert p["price"] == p["original_price"]


# Admin pack create / duplicate slug / auth gate
def test_admin_create_pack_and_duplicate_and_unauth(auth_headers):
    # unauth
    r = requests.post(f"{BASE}/admin/packs", json={"slug": _slug(), "name": "X", "version": "1", "price": 49})
    assert r.status_code == 401

    slug = _slug()
    payload = {"slug": slug, "name": "TEST Pack", "version": "9.9", "price": 49,
               "tagline": "t", "description": "d", "discount_percent": 20, "is_launched": False}
    r = requests.post(f"{BASE}/admin/packs", json=payload, headers=auth_headers)
    assert r.status_code == 200, r.text
    pid = r.json()["id"]

    # duplicate
    r2 = requests.post(f"{BASE}/admin/packs", json=payload, headers=auth_headers)
    assert r2.status_code == 400

    # discount math: 49 * 0.8 = 39.2 -> 39
    pub = requests.get(f"{BASE}/packs/{slug}").json()
    assert pub["original_price"] == 49
    assert pub["price"] == 39
    assert pub["discount_percent"] == 20
    assert pub["is_launched"] is False

    # order blocked when not launched
    o = requests.post(f"{BASE}/orders", json={"pack_id": pid, "email": "t@e.com", "utr": "123456789"})
    assert o.status_code == 400

    # toggle launch
    u = requests.put(f"{BASE}/admin/packs/{pid}", json={"is_launched": True}, headers=auth_headers)
    assert u.status_code == 200 and u.json()["is_launched"] is True

    # order uses discounted price
    o2 = requests.post(f"{BASE}/orders", json={"pack_id": pid, "email": "TEST_t@e.com", "utr": "987654321"})
    assert o2.status_code == 200, o2.text
    assert o2.json()["pack_price"] == 39

    # update discount independently
    u2 = requests.put(f"{BASE}/admin/packs/{pid}", json={"discount_percent": 0}, headers=auth_headers)
    assert u2.status_code == 200 and u2.json()["discount_percent"] == 0
    pub2 = requests.get(f"{BASE}/packs/{slug}").json()
    assert pub2["price"] == pub2["original_price"] == 49

    # delete
    d_unauth = requests.delete(f"{BASE}/admin/packs/{pid}")
    assert d_unauth.status_code == 401
    d = requests.delete(f"{BASE}/admin/packs/{pid}", headers=auth_headers)
    assert d.status_code == 200
    # verify gone
    assert requests.get(f"{BASE}/packs/{slug}").status_code == 404


def test_legacy_packs_default_fields():
    # existing seed packs should have is_launched=true & discount=0
    r = requests.get(f"{BASE}/packs/bgmi-4-4")
    assert r.status_code == 200
    d = r.json()
    assert d["is_launched"] is True
    assert d["discount_percent"] == 0
    assert d["price"] == d["original_price"]
