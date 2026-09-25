"""Mensajes públicos. Escala orientativa, no nuevos umbrales validados del modelo."""
import math

BANDS = [
    {"id": "minimal", "label": "Muy pocas señales", "range": "Menos de 1 %", "action": "Confirma que esperabas recibir este enlace."},
    {"id": "low", "label": "Pocas señales", "range": "De 1 a 5 %", "action": "Comprueba la dirección antes de ingresar datos."},
    {"id": "moderate", "label": "Algunas señales", "range": "Más de 5 a 20 %", "action": "Revisa el enlace con atención."},
    {"id": "high", "label": "Varias señales", "range": "Más de 20 a 50 %", "action": "Evita ingresar claves o hacer pagos desde este enlace."},
    {"id": "very_high", "label": "Muchas señales", "range": "Más de 50 %", "action": "No ingreses datos. Accede al servicio por tu cuenta."}
]


def band_for(p):
    if p < .01: return 0
    if p <= .05: return 1
    if p <= .20: return 2
    if p <= .50: return 3
    return 4


def format_percent(p):
    # Evita redondear 0.999% a 1% y cruzar visualmente un límite de rango.
    if p < .0001: return "Menos de 0,01 %"
    if p > .9999: return "Más de 99,99 %"
    for boundary in (.05, .20, .50):
        if boundary < p < boundary + .0001:
            return f"Más de {int(boundary * 100)} %"
    return (f"{math.floor(p * 10000) / 100:.2f}".rstrip("0").rstrip(".").replace(".", ",") + " %")


def public_result(result):
    out = {"version": "public-v2", "status": "unavailable", "band": None,
           "title": "No pudimos analizar el enlace", "percent": None,
           "explanation": "El análisis no está disponible en este momento. Inténtalo más tarde.",
           "recommendation": "Si tienes dudas, abre la aplicación del servicio o escribe su dirección por tu cuenta.",
           "site": result["hostname"], "reference_note": "",
           "notice": "Este análisis puede equivocarse. Una puntuación baja no garantiza que el sitio sea seguro."}
    if result["p_phishing"] is None: return out
    refs = result["reference"]["hostname_matches"]
    if refs:
        out["reference_note"] = "La dirección coincide con el dominio de referencia de " + ", ".join(refs) + "."
    if result.get("reference_conflict"):
        out.update(status="uncertain", title="Conviene comprobar este enlace",
                   explanation="Reconocemos el dominio, pero el análisis del enlace completo no es concluyente. "
                               "Que la dirección sea larga no demuestra que sea una estafa.",
                   recommendation="Abre la aplicación del servicio o escribe su dirección principal por tu cuenta.")
        return out
    if result.get("precaution_reasons"):
        if result["observed_features"]["has_userinfo"]:
            reason = "El enlace usa un símbolo @ que puede confundir sobre la página a la que lleva."
        elif result["reference"]["brand_mentions_elsewhere"]:
            reason = "El enlace menciona " + ", ".join(result["reference"]["brand_mentions_elsewhere"]) + ", pero dirige a otro dominio."
        else:
            reason = "No tenemos suficiente información para interpretar esta dirección con confianza."
        out.update(status="uncertain", title="Revisa el enlace antes de continuar", explanation=reason)
        return out
    if any(c["id"] == "acortador" and c["state"] == "DETECTADO" for c in result["criteria"]):
        out.update(status="uncertain", title="El destino del enlace no está a la vista",
                   explanation="Es un enlace acortado. Este análisis no sigue el enlace para comprobar a dónde lleva.")
        return out
    p = result["p_phishing"]
    index = band_for(p)
    # Si el umbral estadístico ordenó cautela, no presentar una señal verde.
    if result["model_classification"] == "caution" and index < 2:
        out.update(status="uncertain", title="El resultado necesita una comprobación",
                   explanation="El análisis no ofrece una conclusión suficientemente clara para este enlace.")
        return out
    out.update(status="scored", band=index, title=BANDS[index]["label"],
               percent=format_percent(p), recommendation=BANDS[index]["action"],
               explanation="La puntuación indica cuánto se parece la dirección a enlaces usados para engañar y robar datos. "
                           "No verifica el contenido de la página.")
    return out
