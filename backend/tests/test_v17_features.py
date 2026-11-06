"""v1.7 features: tracker detection, cleaned URLs, redirect tracing,
email tracking pixels / hidden text, and the public trends aggregate."""

from app.modules import redirect_tracer
from app.modules.email_analyzer import analyze_email
from app.modules.url_analyzer import analyze_url, impersonated_brand, registrable_domain

# ── URL trackers ─────────────────────────────────────────────────────

def test_tracking_params_detected_and_cleaned():
    url = "https://example.com/offer?utm_source=news&utm_medium=email&fbclid=ABC123&keep=1"
    report = analyze_url(url)
    codes = [f["code"] for f in report.findings]
    assert "tracking-params" in codes
    names = {t["name"] for t in report.trackers if t["type"] == "parameter"}
    assert {"utm_source", "utm_medium", "fbclid"} <= names
    assert report.cleaned_url == "https://example.com/offer?keep=1"


def test_clean_url_has_no_trackers_or_cleaned_variant():
    report = analyze_url("https://www.google.com/search?q=test")
    assert report.trackers == []
    assert report.cleaned_url is None


def test_tracking_wrapper_detected():
    report = analyze_url("https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.org%2Fpromo")
    codes = [f["code"] for f in report.findings]
    assert "tracking-wrapper" in codes
    assert any(t["type"] == "wrapped-destination" and t["name"] == "example.org" for t in report.trackers)


def test_impersonated_brand_helper():
    assert impersonated_brand("http://paypa1-secure.xyz/login") == "paypal"
    assert impersonated_brand("https://www.paypal.com/signin") is None
    assert impersonated_brand("https://www.google.com") is None
    assert registrable_domain("https://login.example.com/path") == "example.com"
    assert registrable_domain("http://paypa1-secure-login.xyz/verify") == "paypa1-secure-login.xyz"


# ── Email tracking & hidden text ─────────────────────────────────────

def test_tracking_pixel_detected():
    body = '<p>Hello</p><img src="https://t.mailtrack.io/pixel/abc" width="1" height="1" alt="">'
    result = analyze_email("", body)
    assert "tracking-pixel" in [f["code"] for f in result["findings"]]


def test_invisible_image_detected_without_known_tracker():
    body = '<img src="https://cdn.example.net/o.gif" width="1" height="1">'
    result = analyze_email("", body)
    assert "tracking-pixel" in [f["code"] for f in result["findings"]]


def test_hidden_text_detected():
    body = '<div style="display:none">cheap medicines discount pharmacy bonus words galore here</div><p>Hi</p>'
    result = analyze_email("", body)
    assert "hidden-text" in [f["code"] for f in result["findings"]]


def test_plain_email_has_no_tracking_findings():
    result = analyze_email("", "<p>Meeting moved to 3 pm tomorrow.</p>")
    codes = [f["code"] for f in result["findings"]]
    assert "tracking-pixel" not in codes and "hidden-text" not in codes


# ── Redirect tracer (network fully mocked) ───────────────────────────

def test_redirect_chain_followed_and_scored(monkeypatch):
    hops = {
        "https://sho.rt/abc": (302, "https://tracker.example.net/clk?id=9"),
        "https://tracker.example.net/clk?id=9": (302, "https://paypa1-secure.xyz/login"),
        "https://paypa1-secure.xyz/login": (200, None),
    }
    monkeypatch.setattr(redirect_tracer, "_probe", lambda u: hops[u])
    monkeypatch.setattr(redirect_tracer, "assert_public_host", lambda host: None)
    out = redirect_tracer.trace_redirects("https://sho.rt/abc")
    assert out["hops"] == 2
    assert out["final_url"] == "https://paypa1-secure.xyz/login"
    assert out["crossed_domains"] is True
    assert out["final_risk_score"] >= 40  # brand impersonation at the destination


def test_redirect_to_private_target_blocked(monkeypatch):
    from app.modules.web_audit import UnsafeUrlError

    def guard(host):
        if host == "169.254.169.254":
            raise UnsafeUrlError("private")

    monkeypatch.setattr(redirect_tracer, "assert_public_host", guard)
    monkeypatch.setattr(redirect_tracer, "_probe", lambda u: (302, "http://169.254.169.254/latest/meta-data"))
    try:
        redirect_tracer.trace_redirects("https://sho.rt/x")
        raise AssertionError("expected UnsafeUrlError")
    except UnsafeUrlError:
        pass


def test_resolve_endpoint_rejects_non_web_scheme(client):
    r = client.post("/api/tools/url/resolve", json={"url": "ftp://example.com/file"})
    assert r.status_code == 400


# ── Trends aggregate ─────────────────────────────────────────────────

def test_trending_reflects_recorded_scans(client):
    phish = {"url": "http://paypa1-secure-login.xyz/verify?account=suspended"}
    client.post("/api/tools/url", json=phish)
    client.post("/api/tools/url", json=phish)
    client.post("/api/tools/url", json={"url": "https://www.google.com"})
    out = client.get("/api/public/trending").json()
    assert out["total_scans"] == 3
    assert out["flagged"] == 2
    assert out["top_impersonated_brands"][0] == {"name": "paypal", "count": 2}
    assert out["top_flagged_domains"][0]["domain"] == "paypa1-secure-login.xyz"
    labels = {p["label"] for p in out["top_patterns"]}
    assert "Fake brand login pages" in labels


def test_trending_empty_state_is_honest(client):
    out = client.get("/api/public/trending").json()
    assert out["total_scans"] == 0
    assert out["flagged_pct"] == 0.0
    assert out["top_flagged_domains"] == []
