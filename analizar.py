"""Uso: python analizar.py 'https://www.bancoestado.cl' [--modelo artifacts/mlp.joblib]"""
import argparse
import json
from url_guard.core import AnalizadorURL, InvalidURL

def main():
    p = argparse.ArgumentParser()
    p.add_argument("url")
    p.add_argument("--modelo", default="artifacts/selected.joblib")
    args = p.parse_args()
    try:
        result = AnalizadorURL(args.modelo).analizar(args.url)
    except InvalidURL as exc:
        p.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
