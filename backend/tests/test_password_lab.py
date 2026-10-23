from app.modules import password_lab as pl


def test_common_password_scores_terribly():
    r = pl.assess_password("password")
    assert r["is_common_password"] is True
    assert r["score"] < 30


def test_strong_password_scores_well():
    r = pl.assess_password("Tr7!mango-BICYCLE-92#quartz")
    assert r["score"] >= 70
    assert r["entropy_bits"] > 80


def test_offline_breach_check():
    assert pl.breach_check_local("123456")["breached"] is True
    assert pl.breach_check_local("xK9!unique-phrase-zz42")["breached"] is False


def test_generator_meets_policy():
    for _ in range(25):
        pw = pl.generate_password(20, symbols=True)
        assert len(pw) == 20
        assert any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)


def test_passphrase_format():
    phrase = pl.generate_passphrase(5)
    assert phrase.count("-") >= 4
