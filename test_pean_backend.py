"""Backend tests for pean GFX store."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://bgmi-design-assets.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@pean.com"
ADMIN_PASSWORD = "Pean@2026"


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


@pytest.fixture(scope="module")
def admin_token(session):
    r = session.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    data = r.json()
    assert "token" in data
    # cookie should also be set
    assert "access_token" in session.cookies
    return data["token"]


@pytest.fixture(scope="module")
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ---------------- Public ----------------
class TestPublic:
    def test_config(self, session):
        r = session.get(f"{API}/config")
        assert r.status_code == 200
        d = r.json()
        assert d["upi_id"] == "priyennaik@okhdfcbank"
        assert d.get("payee_name")

    def test_list_packs(self, session):
        r = session.get(f"{API}/packs")
        assert r.status_code == 200
        packs = r.json()
        assert len(packs) >= 2
        slugs = {p["slug"]: p for p in packs}
        assert "bgmi-4-4" in slugs and slugs["bgmi-4-4"]["price"] == 49
        assert "bgmi-4-5" in slugs and slugs["bgmi-4-5"]["price"] == 79
        for p in packs:
            assert "drive_link" not in p

    def test_get_pack_bgmi44(self, session):
        r = session.get(f"{API}/packs/bgmi-4-4")
        assert r.status_code == 200
        d = r.json()
        assert d["slug"] == "bgmi-4-4"
        assert d["price"] == 49
        assert "drive_link" not in d

    def test_get_pack_bgmi45(self, session):
        r = session.get(f"{API}/packs/bgmi-4-5")
        assert r.status_code == 200
        d = r.json()
        assert d["price"] == 79
        assert "drive_link" not in d

    def test_get_pack_404(self, session):
        r = session.get(f"{API}/packs/does-not-exist")
        assert r.status_code == 404


# ---------------- Orders ----------------
class TestOrders:
    def test_create_order_invalid_pack(self, session):
        r = session.post(f"{API}/orders", json={"pack_id": "bad-id", "email": "x@y.com", "utr": "123456789012"})
        assert r.status_code == 404

    def test_create_order_invalid_email(self, session):
        # fetch a valid pack id
        pack = session.get(f"{API}/packs").json()[0]
        r = session.post(f"{API}/orders", json={"pack_id": pack["id"], "email": "not-an-email", "utr": "123456789012"})
        assert r.status_code == 422

    def test_create_order_short_utr(self, session):
        pack = session.get(f"{API}/packs").json()[0]
        r = session.post(f"{API}/orders", json={"pack_id": pack["id"], "email": "TEST_a@x.com", "utr": "12"})
        assert r.status_code == 422

    def test_create_order_and_pending_status_hides_drive(self, session):
        pack = next(p for p in session.get(f"{API}/packs").json() if p["slug"] == "bgmi-4-4")
        r = session.post(f"{API}/orders", json={
            "pack_id": pack["id"],
            "email": "TEST_buyer@example.com",
            "utr": "401234567890",
        })
        assert r.status_code == 200, r.text
        order = r.json()
        assert order["status"] == "pending"
        assert order["drive_link"] is None
        assert order["pack_price"] == 49

        # GET order
        g = session.get(f"{API}/orders/{order['id']}")
        assert g.status_code == 200
        gd = g.json()
        assert gd["status"] == "pending"
        assert gd["drive_link"] is None

    def test_get_order_404(self, session):
        r = session.get(f"{API}/orders/nonexistent-id")
        assert r.status_code == 404


# ---------------- Auth ----------------
class TestAuth:
    def test_login_wrong(self, session):
        s = requests.Session()
        r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong"})
        assert r.status_code == 401

    def test_login_ok_sets_cookie(self, session):
        s = requests.Session()
        r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert r.status_code == 200
        assert "token" in r.json()
        assert "access_token" in s.cookies

    def test_me_without_token(self):
        r = requests.get(f"{API}/auth/me")
        assert r.status_code == 401

    def test_me_with_token(self, auth_headers):
        r = requests.get(f"{API}/auth/me", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["email"] == ADMIN_EMAIL


# ---------------- Admin ----------------
class TestAdmin:
    def test_admin_orders_protected(self):
        r = requests.get(f"{API}/admin/orders")
        assert r.status_code == 401

    def test_admin_packs_protected(self):
        r = requests.get(f"{API}/admin/packs")
        assert r.status_code == 401

    def test_admin_list_orders(self, auth_headers):
        r = requests.get(f"{API}/admin/orders", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_admin_list_packs_includes_drive(self, auth_headers):
        r = requests.get(f"{API}/admin/packs", headers=auth_headers)
        assert r.status_code == 200
        packs = r.json()
        assert len(packs) >= 2
        for p in packs:
            assert "drive_link" in p

    def test_approve_unlocks_drive_link(self, session, auth_headers):
        # create order
        pack = next(p for p in session.get(f"{API}/packs").json() if p["slug"] == "bgmi-4-5")
        order = session.post(f"{API}/orders", json={
            "pack_id": pack["id"], "email": "TEST_approve@x.com", "utr": "999888777666"
        }).json()
        oid = order["id"]

        # approve
        r = requests.post(f"{API}/admin/orders/{oid}/approve", headers=auth_headers)
        assert r.status_code == 200

        # verify drive_link now exposed
        g = requests.get(f"{API}/orders/{oid}").json()
        assert g["status"] == "approved"
        assert g["drive_link"] and "drive.google.com" in g["drive_link"]

    def test_reject_order(self, session, auth_headers):
        pack = session.get(f"{API}/packs").json()[0]
        order = session.post(f"{API}/orders", json={
            "pack_id": pack["id"], "email": "TEST_reject@x.com", "utr": "111222333444"
        }).json()
        oid = order["id"]
        r = requests.post(f"{API}/admin/orders/{oid}/reject", headers=auth_headers)
        assert r.status_code == 200
        g = requests.get(f"{API}/orders/{oid}").json()
        assert g["status"] == "rejected"
        assert g["drive_link"] is None

    def test_approve_nonexistent(self, auth_headers):
        r = requests.post(f"{API}/admin/orders/nonexistent/approve", headers=auth_headers)
        assert r.status_code == 404

    def test_update_pack(self, session, auth_headers):
        pack = next(p for p in session.get(f"{API}/packs").json() if p["slug"] == "bgmi-4-4")
        new_tagline = "Updated tagline TEST"
        r = requests.put(f"{API}/admin/packs/{pack['id']}",
                         headers={**auth_headers, "Content-Type": "application/json"},
                         json={"tagline": new_tagline, "price": 49})
        assert r.status_code == 200
        assert r.json()["tagline"] == new_tagline

        # restore
        requests.put(f"{API}/admin/packs/{pack['id']}",
                     headers={**auth_headers, "Content-Type": "application/json"},
                     json={"tagline": "Cinematic edits, ready in seconds."})
