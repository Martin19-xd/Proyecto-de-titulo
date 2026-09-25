"""Descarga solo un dataset público fijo. Nunca visita las URLs de sus filas."""
import hashlib
import io
import json
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile

SOURCE = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"

def main():
    target = Path("data")
    target.mkdir(exist_ok=True)
    with urlopen(SOURCE, timeout=90) as r:
        data = r.read(30 * 1024 * 1024 + 1)
    if len(data) > 30 * 1024 * 1024:
        raise ValueError("Archivo mayor que el límite permitido.")
    with ZipFile(io.BytesIO(data)) as z:
        content = z.read("PhiUSIIL_Phishing_URL_Dataset.csv")
    (target / "phiusiil.csv").write_bytes(content)
    (target / "source.json").write_text(json.dumps({
        "source": SOURCE, "license": "CC BY 4.0", "authors": "Arvind Prasad y Shalini Chandra (2024)",
        "original_labels": {"1": "legitimate", "0": "phishing"},
        "sha256": hashlib.sha256(content).hexdigest()
    }, indent=2), encoding="utf-8")
    print("Guardado data/phiusiil.csv. Etiqueta original: 0 phishing, 1 legítima.")

if __name__ == "__main__":
    main()
