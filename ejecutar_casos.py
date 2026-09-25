"""CU-02: evidencia de 24 casos FUNCIONALES. No son un dataset ni métricas ML.

python ejecutar_casos.py --salida evidencias/casos.json
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from url_guard.core import AnalizadorURL, InvalidURL

CASES = [
    ("https://facebook.com", "Facebook", False),
    ("https://www.facebook.com", "Facebook", False),
    ("https://m.facebook.com", "Facebook", False),
    ("https://instagram.com", "Instagram", False),
    ("https://www.instagram.com", "Instagram", False),
    ("https://bancoestado.cl", "BancoEstado", False),
    ("https://www.bancoestado.cl", "BancoEstado", False),
    ("https://BANCOESTADO.CL", "BancoEstado", False),
    ("https://bancoestado.cl.", "BancoEstado", False),
    ("https://bancoestado.cl:443", "BancoEstado", False),
    ("https://bancoestado.cl.ejemplo.test", None, False),
    ("https://facebook.com.ejemplo.test", None, False),
    ("https://instagram.com.ejemplo.test", None, False),
    ("https://bancoestado.cl@ejemplo.test", None, False),
    ("https://ejemplo.test/facebook.com", None, False),
    ("https://ejemplo.test/?next=https://instagram.com", None, False),
    ("https://example.com", None, False),
    ("http://example.com", None, False),
    ("https://127.0.0.1", None, False),
    ("https://[::1]", None, False),
    ("", None, True),
    ("facebook.com", None, True),
    ("javascript:alert(1)", None, True),
    ("https://example.com:99999", None, True),
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--modelo", default="artifacts/selected.joblib")
    p.add_argument("--salida", default="evidencias/casos.json")
    args = p.parse_args()
    engine = AnalizadorURL(args.modelo)
    rows = []
    for i, (url, brand, invalid) in enumerate(CASES, 1):
        try:
            result = engine.analizar(url)
            ok = not invalid and result["reference"]["hostname_matches"] == ([brand] if brand else [])
            if brand is None and any(s in url for s in ("bancoestado", "facebook", "instagram")) and engine.bundle:
                ok = ok and result["classification"] != "likely_legitimate"
            row = {"result": result, "matches_functional_expectation": bool(ok)}
        except InvalidURL as exc:
            row = {"error": str(exc), "matches_functional_expectation": invalid}
        rows.append({"case_id": f"CU02-{i:02}", "url_controlled": url,
                     "expected_reference": brand, "expected_invalid": invalid, **row})
    output = Path(args.salida)
    output.parent.mkdir(exist_ok=True, parents=True)
    if output.exists():
        p.error("Use otro archivo para preservar la evidencia anterior.")
    report = {"date": datetime.now(timezone.utc).isoformat(),
              "purpose": "Pruebas funcionales; no prueban seguridad real ni exactitud ML.",
              "total": len(rows), "passed": sum(r["matches_functional_expectation"] for r in rows), "cases": rows}
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{report['passed']}/{report['total']} verificaciones funcionales. Evidencia: {output}")
    raise SystemExit(0 if report["passed"] == report["total"] else 1)


if __name__ == "__main__":
    main()
