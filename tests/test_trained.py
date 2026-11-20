from pathlib import Path
import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from url_guard.core import AnalizadorURL, FEATURES, extract, probabilities

pytestmark = pytest.mark.skipif(not Path("artifacts/selected.joblib").exists(), reason="Entrene primero")


def test_api_cli_probability_agree(monkeypatch):
    from app import app
    monkeypatch.setenv("MODEL_PATH", str(Path("artifacts/selected.joblib").resolve()))
    app.middleware_stack = None
    a = AnalizadorURL("artifacts/selected.joblib")
    url = "https://www.bancoestado.cl"
    with TestClient(app) as client:
        data = client.post("/api/analyze", json={"url": url}).json()
    assert data["p_phishing"] == a.analizar(url)["p_phishing"]
    f, _ = extract(url)
    direct = float(probabilities(a.bundle, np.array([[f[k] for k in FEATURES]]))[0])
    assert abs(data["p_phishing"] - direct) < 1e-6


def test_brand_conflict_does_not_produce_low_risk():
    a = AnalizadorURL("artifacts/selected.joblib")
    r = a.analizar("https://bancoestado.cl.ejemplo.test")
    assert r["classification"] != "likely_legitimate"
    assert r["reference"]["hostname_matches"] == []
    assert r["p_phishing"] is not None
    assert r["precaution_reasons"]


def test_model_integrity(tmp_path):
    import shutil
    p = tmp_path / "selected.joblib"
    shutil.copyfile("artifacts/selected.joblib", p)
    shutil.copyfile("artifacts/selected.manifest.json", p.with_suffix(".manifest.json"))
    with p.open("ab") as f:
        f.write(b"changed")
    with pytest.raises(RuntimeError, match="Checksum"):
        AnalizadorURL(p)


def test_actual_split_domains_do_not_overlap():
    df = pd.read_csv("artifacts/splits.csv")
    assert df.groupby("group").fold.nunique().max() == 1
    assert df.row_sha256.is_unique
