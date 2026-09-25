import socket
import pytest
from url_guard.core import AnalizadorURL, InvalidURL, extract, parse_url, reference_info, decide


@pytest.mark.parametrize("url,brand", [
    ("https://facebook.com", "Facebook"),
    ("https://www.facebook.com/login", "Facebook"),
    ("https://m.facebook.com", "Facebook"),
    ("https://www.instagram.com", "Instagram"),
    ("https://instagram.com/p/demo", "Instagram"),
    ("https://www.bancoestado.cl", "BancoEstado"),
    ("https://bancoestado.cl", "BancoEstado"),
    ("https://BANCOESTADO.CL", "BancoEstado"),
    ("https://www.bancoestado.cl.", "BancoEstado"),
    ("https://bancoestado.cl.ejemplo.test", None),
    ("https://facebook.com.ejemplo.test", None),
    ("https://instagram.com.ejemplo.test", None),
    ("https://falsofacebook.com", None),
    ("https://bancoestado.cl@ejemplo.test", None),
    ("https://ejemplo.test/facebook.com", None),
    ("https://ejemplo.test/?next=https://bancoestado.cl", None),
    ("https://facebook-com.test", None),
    ("https://instagrarn.test", None),
    ("https://example.com", None),
    ("https://127.0.0.1", None),
    ("https://[::1]", None),
    ("https://bancoestado.cl:443/", "BancoEstado"),
])
def test_reference_is_hostname_boundary(url, brand):
    parsed = parse_url(url)
    actual = reference_info(parsed, url)["hostname_matches"]
    assert actual == ([brand] if brand else [])


@pytest.mark.parametrize("url", ["", "facebook.com", "javascript:alert(1)", "file:///etc/passwd",
    "ftp://example.com", "https://", "https://a.test:99999", "https://a.test\\@b.test",
    "https://a.test/\n", "https://a.test/%zz", "https://a..com", "https://-bad.com",
    "https://[::1", "https://a.test/" + "x" * 4096])
def test_invalid_input(url):
    with pytest.raises(InvalidURL):
        parse_url(url)


def test_suffix_grouping():
    assert parse_url("https://a.example.co.uk")["group"] == "example.co.uk"
    assert parse_url("https://b.example.co.uk")["group"] == "example.co.uk"
    assert parse_url("https://one.github.io")["group"] != parse_url("https://two.github.io")["group"]


def test_no_model_no_probability(tmp_path):
    result = AnalizadorURL(tmp_path / "missing.joblib").analizar("https://www.facebook.com")
    assert result["p_phishing"] is None
    assert result["level"] is None
    assert result["state"] == "NO_CONCLUYENTE"
    states = {r["id"]: r["state"] for r in result["criteria"]}
    assert states["redirecciones"] == "NO_EVALUABLE"
    assert states["solicitud_credenciales"] == "NO_EVALUABLE"


def test_extraction_never_resolves_or_fetches(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No se permite red durante el análisis")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    f, parsed = extract("https://bancoestado.cl.ejemplo.test/a?password=demo")
    assert f["keyword_count"] > 0
    assert parsed["host"] == "bancoestado.cl.ejemplo.test"


def test_threshold_boundaries():
    policy = {"low": .2, "high": .8}
    assert decide(.19, policy) == "likely_legitimate"
    assert decide(.2, policy) == "caution"
    assert decide(.799, policy) == "caution"
    assert decide(.8, policy) == "likely_suspicious"
    assert decide(.01, {"low": None, "high": None}) == "caution"


def test_features_count_and_types():
    f, _ = extract("https://usuario@127.0.0.1:443/a/b?x=1&y=2")
    assert f["is_ip"] == 1 and f["has_userinfo"] == 1
    assert f["parameters"] == 2 and f["path_segments"] == 2
    assert f["https_declared"] == 1
