"""Análisis estático. No realiza DNS, HTTP ni navegación de la URL recibida."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import joblib
import numpy as np
import tldextract

FEATURE_VERSION = "static-v1"
MAX_URL_LENGTH = 4096
# Instantánea incluida en la versión fijada de tldextract; no descarga en inferencia.
PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                          include_psl_private_domains=True)
REFERENCES = {"Facebook": "facebook.com", "Instagram": "instagram.com",
              "BancoEstado": "bancoestado.cl"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly"}
WORDS = ("login", "verify", "secure", "account", "password", "update",
         "urgente", "bloqueo", "clave", "verificar", "premio")
LIMITATION = ("Estimación académica basada solo en el texto de la URL. "
              "No se visitó el sitio ni se verificaron contenido, TLS, redirecciones "
              "o reputación actual. No garantiza seguridad ni confirma phishing.")


class InvalidURL(ValueError):
    pass


def parse_url(value: str) -> dict:
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        raise InvalidURL("Ingrese una URL de entre 1 y 4096 caracteres.")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise InvalidURL("No se admiten espacios, controles ni barras invertidas.")
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise InvalidURL("Codificación porcentual inválida.")
    try:
        p = urlsplit(value)
        if p.scheme.lower() not in ("http", "https") or not p.netloc or not p.hostname:
            raise InvalidURL("Use una URL completa que comience con http:// o https://.")
        port = p.port  # Valida también rango y formato del puerto.
        host = p.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if not host or "%" in host:
            raise InvalidURL("Hostname no admitido.")
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
            if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s)
                                      for s in host.split(".")):
                raise InvalidURL("Hostname no admitido.")
        ext = PSL(host) if not is_ip else None
        registered = (ext.top_domain_under_public_suffix or host) if ext else host
        subdomains = len(ext.subdomain.split(".")) if ext and ext.subdomain else 0
        # Clave de deduplicación conservadora: preserva consulta, ruta y fragmento.
        authority = ("[" + host + "]") if ":" in host else host
        if port is not None:
            authority += ":" + str(port)
        if "@" in p.netloc:
            authority = p.netloc.rsplit("@", 1)[0] + "@" + authority
        key = p.scheme.lower() + "://" + authority + p.path
        if "?" in value.split("#", 1)[0]:
            key += "?" + p.query
        if "#" in value:
            key += "#" + p.fragment
        return {"parts": p, "host": host, "group": registered, "is_ip": is_ip,
                "subdomains": subdomains, "port": port, "key": key,
                "known_suffix": bool(ext and ext.suffix)}
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, InvalidURL):
            raise
        raise InvalidURL("La URL tiene una estructura no admitida.") from exc


def entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((n / len(value)) * math.log2(n / len(value))
                for n in Counter(value).values())


def extract(value: str) -> tuple[dict, dict]:
    parsed = parse_url(value)
    p, h = parsed["parts"], parsed["host"]
    digits = sum(c.isdigit() for c in value)
    f = {
        "url_length": len(value), "host_length": len(h),
        "path_length": len(p.path), "query_length": len(p.query),
        "subdomains": parsed["subdomains"],
        "path_segments": len([s for s in p.path.split("/") if s]),
        "parameters": len([s for s in p.query.split("&") if s]),
        "digits": digits, "digit_ratio": digits / len(value),
        "hyphens": value.count("-"), "host_hyphens": h.count("-"),
        "dots": value.count("."), "at_signs": value.count("@"),
        "percent_signs": value.count("%"), "equals": value.count("="),
        "special_ratio": sum(not c.isalnum() for c in value) / len(value),
        "is_ip": int(parsed["is_ip"]), "https_declared": int(p.scheme == "https"),
        "explicit_port": int(parsed["port"] is not None),
        "has_userinfo": int("@" in p.netloc),
        "punycode": int(any(s.startswith("xn--") for s in h.split("."))),
        "host_entropy": entropy(h), "path_entropy": entropy(p.path),
        "keyword_count": sum(value.lower().count(w) for w in WORDS),
        "has_fragment": int(bool(p.fragment)),
    }
    return f, parsed


FEATURES = tuple(extract("https://example.com")[0])


def reference_info(parsed: dict, url: str) -> dict:
    host = parsed["host"]
    matches = [name for name, root in REFERENCES.items()
               if host == root or host.endswith("." + root)]
    # Coincidencia textual informativa; no prueba suplantación ni propiedad.
    mentions = [name for name in REFERENCES if name.lower() in url.lower()
                and name not in matches]
    return {"hostname_matches": matches, "brand_mentions_elsewhere": mentions,
            "note": "Catálogo parcial de referencia. Coincidir no garantiza seguridad; "
                    "no coincidir tampoco demuestra fraude."}


def criteria(url: str, f: dict, parsed: dict) -> list[dict]:
    refs = reference_info(parsed, url)
    checks = [
        ("url_extensa", f["url_length"] > 200, f"Longitud: {f['url_length']}; umbral descriptivo: 200."),
        ("multiples_subdominios", f["subdomains"] >= 3, f"Subdominios: {f['subdomains']}."),
        ("ip_en_hostname", bool(f["is_ip"]), "Hostname expresado como IP literal."),
        ("userinfo", bool(f["has_userinfo"]), "Presencia de información antes de @ en la autoridad."),
        ("palabras_referencia", f["keyword_count"] > 0, f"Coincidencias léxicas: {f['keyword_count']}."),
        ("acortador", parsed["host"] in SHORTENERS, "Comparación exacta con catálogo parcial de acortadores."),
        ("marca_fuera_dominio_referencia", bool(refs["brand_mentions_elsewhere"]),
         "Mención textual fuera del hostname de referencia: " + ", ".join(refs["brand_mentions_elsewhere"])),
    ]
    result = [{"id": name, "state": "DETECTADO" if yes else "NO_DETECTADO", "evidence": evidence}
              for name, yes, evidence in checks]
    result.extend({"id": name, "state": "NO_EVALUABLE", "evidence": "No se obtiene contenido ni se visita el sitio."}
                  for name in ("solicitud_credenciales", "redirecciones", "inconsistencia_visual"))
    return result


def logit_features(p):
    p = np.clip(np.asarray(p), 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p)).reshape(-1, 1)


def probabilities(bundle: dict, X):
    raw = bundle["pipeline"].predict_proba(X)[:, 1]
    return bundle["calibrator"].predict_proba(logit_features(raw))[:, 1]


def decide(p: float, policy: dict) -> str:
    if policy["low"] is not None and p < policy["low"]:
        return "likely_legitimate"
    if policy["high"] is not None and p >= policy["high"]:
        return "likely_suspicious"
    return "caution"


class AnalizadorURL:
    def __init__(self, model_path: str | Path):
        path = Path(model_path)
        self.bundle = None
        if path.exists():
            # joblib solo debe cargar artefactos propios: nunca archivos del usuario.
            manifest = json.loads(path.with_suffix(".manifest.json").read_text())
            if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["sha256"]:
                raise RuntimeError("Checksum del modelo incorrecto.")
            self.bundle = joblib.load(path)
            if self.bundle["features"] != list(FEATURES) or self.bundle["feature_version"] != FEATURE_VERSION:
                raise RuntimeError("El modelo y el extractor no son compatibles.")

    def analizar(self, url: str) -> dict:
        f, parsed = extract(url)
        result = {"analysis_id": str(uuid4()), "analyzed_at": datetime.now(timezone.utc).isoformat(),
                  "state": "NO_CONCLUYENTE", "classification": "unavailable", "level": None,
                  "p_phishing": None, "coverage": "PARCIAL", "analysis_mode": "static_url",
                  "observed_features": f, "criteria": criteria(url, f, parsed),
                  "reference": reference_info(parsed, url), "hostname": parsed["host"],
                  "model_version": None, "feature_version": FEATURE_VERSION,
                  "model_explanation": None, "limitations": LIMITATION,
                  "message": "Modelo no disponible. Hay observaciones, pero no una predicción."}
        if self.bundle is None:
            return result
        b = self.bundle
        X = np.array([[f[name] for name in FEATURES]], dtype=float)
        p = float(probabilities(b, X)[0])
        model_decision = decide(p, b["policy"])
        decision = model_decision
        # Capa preventiva explícita, posterior al modelo. Nunca declara legítimo
        # por reconocer una marca. Mantiene visible la predicción sin modificarla.
        precaution_reasons = []
        if result["reference"]["brand_mentions_elsewhere"]:
            precaution_reasons.append("La URL menciona una marca, pero el hostname no coincide con su referencia.")
        if f["has_userinfo"]:
            precaution_reasons.append("La autoridad contiene información antes de @; el destino está después de @.")
        if not parsed["known_suffix"] or parsed["is_ip"]:
            precaution_reasons.append("IP literal o sufijo fuera de la lista pública: cobertura limitada para este caso.")
        if decision == "likely_legitimate" and precaution_reasons:
            decision = "caution"
        labels = {"likely_legitimate": ("BAJO", "Probablemente legítima"),
                  "caution": ("MEDIO", "Requiere precaución"),
                  "likely_suspicious": ("ALTO", "Probablemente sospechosa")}
        level, message = labels[decision]
        result.update(state="CLASIFICADA", classification=decision, level=level,
                      p_phishing=round(p, 6), model_version=b["version"],
                      model_name=b["name"], message=message,
                      model_classification=model_decision,
                      precaution_reasons=precaution_reasons,
                      precaution_policy_version="precaution-v1",
                      precaution_override=decision != model_decision,
                      decision_policy=b["policy"], calibration="sigmoid_holdout",
                      model_explanation_note="Las observaciones no son atribuciones causales ni SHAP.")
        return result
