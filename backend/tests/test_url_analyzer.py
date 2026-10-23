from app.modules.url_analyzer import analyze_url


def test_official_paypal_is_safe():
    r = analyze_url("https://www.paypal.com/signin")
    assert r.verdict in ("safe", "low-risk")
    assert r.risk_score < 40


def test_ip_host_phishing_is_flagged():
    r = analyze_url("http://192.168.10.5/paypal/login/verify")
    assert r.risk_score >= 50
    codes = {f["code"] for f in r.findings}
    assert "ip-host" in codes and "no-https" in codes


def test_typosquat_detected():
    r = analyze_url("https://paypa1-secure-login.xyz/verify")
    assert r.risk_score >= 40
    assert any(f["code"] in ("typosquat", "brand-in-host", "suspicious-tld") for f in r.findings)


def test_brand_in_unrelated_host():
    r = analyze_url("https://free-offer-top.click/amazon-prize")
    assert r.risk_score >= 30


def test_shortener_and_userinfo_trick():
    assert analyze_url("https://bit.ly/3abcXYZ").risk_score >= 20
    r = analyze_url("https://google.com@evil.example.com/login")
    assert any(f["code"] == "userinfo-trick" for f in r.findings)


def test_punycode_flagged():
    r = analyze_url("https://xn--pypal-4ve.com/login")
    assert any(f["code"] in ("punycode", "brand-in-host", "typosquat") for f in r.findings)
