"""Experimento reproducible: cinco modelos, calibración y test separado por dominio.

PhiUSIIL: python entrenar.py --csv data/phiusiil.csv --etiqueta-phishing 0
CSV propio: columnas URL,label y declarar explícitamente cuál etiqueta significa phishing.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, brier_score_loss,
    confusion_matrix, f1_score, log_loss, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from threadpoolctl import threadpool_limits

from url_guard.core import FEATURES, FEATURE_VERSION, InvalidURL, extract, logit_features, probabilities


def metrics(y, p):
    pred = p >= .5
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    fraction, predicted = calibration_curve(y, p, n_bins=10, strategy="quantile")
    return {"accuracy": float(accuracy_score(y, pred)),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y, p)),
            "average_precision": float(average_precision_score(y, p)),
            "brier": float(brier_score_loss(y, p)), "log_loss": float(log_loss(y, p)),
            "fpr": float(fp / (fp + tn)), "fnr": float(fn / (fn + tp)),
            "confusion_matrix_labels_0_1": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "binary_threshold": .5,
            "calibration_curve": {"mean_prediction": predicted.tolist(), "fraction_phishing": fraction.tolist()}}


def choose_policy(y, p, max_error=.05, min_cases=30):
    # Presupuesto empírico de errores de 5% por clase en policy; no garantía estadística.
    lows, highs = [], []
    for threshold in np.linspace(.001, .999, 999):
        lo, hi = p < threshold, p >= threshold
        if threshold <= .5 and lo.sum() >= min_cases and lo[y == 1].mean() <= max_error:
            lows.append(float(threshold))
        if threshold >= .5 and hi.sum() >= min_cases and hi[y == 0].mean() <= max_error:
            highs.append(float(threshold))
    return {"low": max(lows) if lows else None, "high": min(highs) if highs else None,
            "version": "policy-v1", "empirical_class_error_budget": max_error,
            "min_validation_cases": min_cases,
            "note": "Umbrales elegidos en validación independiente. No garantizan tasas futuras."}


def policy_metrics(y, p, policy):
    low = p < policy["low"] if policy["low"] is not None else np.zeros(len(p), dtype=bool)
    high = p >= policy["high"] if policy["high"] is not None else np.zeros(len(p), dtype=bool)
    mid = ~(low | high)
    return {"coverage": float((low | high).mean()), "abstention_rate": float(mid.mean()),
            "phishing_marked_legitimate_rate": float(low[y == 1].mean()),
            "legitimate_marked_suspicious_rate": float(high[y == 0].mean()),
            "rows_truth_legitimate_phishing_columns_low_caution_high": [
                [int((mask & (y == truth)).sum()) for mask in (low, mid, high)] for truth in (0, 1)]}


def group_bootstrap(y, p, groups, seed, repeats=200):
    rng = np.random.default_rng(seed)
    unique = np.unique(groups)
    indices = {g: np.flatnonzero(groups == g) for g in unique}
    values = []
    for _ in range(repeats):
        idx = np.concatenate([indices[g] for g in rng.choice(unique, len(unique), replace=True)])
        if len(np.unique(y[idx])) == 2:
            values.append(average_precision_score(y[idx], p[idx]))
    return {"metric": "average_precision", "method": "percentile_bootstrap_by_domain",
            "replicates": len(values), "confidence": .95,
            "interval": np.quantile(values, [.025, .975]).tolist()}


def prepare(csv_path, phishing_label, max_rows, seed):
    raw = pd.read_csv(csv_path, usecols=["URL", "label"], dtype=str)
    if set(raw["label"].dropna().unique()) != {"0", "1"}:
        raise ValueError("El CSV debe contener ambas clases 0 y 1; declare --etiqueta-phishing.")
    audit = {"input_rows": len(raw), "missing_rows": int(raw.isna().any(axis=1).sum())}
    records = []
    invalid = 0
    for url, label in raw.dropna().itertuples(index=False, name=None):
        try:
            f, parsed = extract(url)
        except InvalidURL:
            invalid += 1
            continue
        records.append({"key": parsed["key"], "group": parsed["group"],
                        "label": int(label == phishing_label), **f})
    df = pd.DataFrame(records)
    if df.empty:
        raise ValueError("No hay URLs analizables.")
    conflicts = df.groupby("key")["label"].nunique()
    bad_keys = conflicts[conflicts > 1].index
    audit.update(invalid_rows=invalid, conflicting_keys=len(bad_keys))
    df = df[~df["key"].isin(bad_keys)]
    before = len(df)
    df = df.drop_duplicates("key")
    audit["duplicate_rows_removed"] = before - len(df)
    audit["clean_rows_before_sampling"] = len(df)
    if max_rows and len(df) > max_rows:
        fraction = max_rows / len(df)
        df = pd.concat([g.sample(n=max(1, int(round(len(g) * fraction))), random_state=seed)
                        for _, g in df.groupby("label")])
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    if len(df) < 1000 or df.groupby("label")["group"].nunique().min() < 20:
        raise ValueError("Se requieren al menos 1000 filas y 20 dominios por clase para este protocolo.")
    audit.update(used_rows=len(df), unique_groups=int(df.group.nunique()),
                 phishing_rows=int(df.label.sum()), legitimate_rows=int((df.label == 0).sum()))
    return df, audit


def split_groups(df, seed):
    assignments = np.full(len(df), -1)
    cv = StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=seed)
    for fold, (_, idx) in enumerate(cv.split(df, df.label, groups=df.group)):
        assignments[idx] = fold
    masks = {"train": assignments < 5,
             "validation": (assignments == 5) | (assignments == 6),
             "calibration": assignments == 7, "policy": assignments == 8,
             "test": assignments == 9}
    seen = set()
    for name, mask in masks.items():
        groups = set(df.loc[mask, "group"])
        assert not seen.intersection(groups), "Fuga por dominio"
        seen |= groups
        if df.loc[mask, "label"].nunique() != 2:
            raise ValueError(f"{name} no contiene ambas clases. Necesita más datos o revisar grupos.")
    return masks, assignments


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True)
    parser.add_argument("--etiqueta-phishing", choices=["0", "1"], required=True)
    parser.add_argument("--max-filas", type=int, default=50000, help="0 usa todo; por defecto piloto de 50000")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--salida", default="artifacts")
    args = parser.parse_args()
    if args.max_filas < 0 or args.epochs < 1:
        parser.error("max-filas debe ser >= 0 y epochs >= 1")
    output = Path(args.salida)
    if output.exists() and any(output.iterdir()):
        parser.error("La carpeta de salida debe estar vacía; use otra para conservar experimentos.")
    output.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    print("Preparando URLs sin visitar sitios...", flush=True)
    df, audit = prepare(args.csv, args.etiqueta_phishing, args.max_filas, args.seed)
    masks, folds = split_groups(df, args.seed)
    X = df[list(FEATURES)].to_numpy(dtype=float)
    y = df.label.to_numpy()
    train, val, cal, pol, test = [masks[k] for k in ("train", "validation", "calibration", "policy", "test")]
    candidates = {
        "dummy": DummyClassifier(strategy="prior"),
        "logistic": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=args.seed)),
        "tree": DecisionTreeClassifier(max_depth=12, min_samples_leaf=10, random_state=args.seed),
        "forest": RandomForestClassifier(n_estimators=150, max_depth=18, min_samples_leaf=3,
                                         random_state=args.seed, n_jobs=2),
        "boosting": HistGradientBoostingClassifier(max_iter=150, max_leaf_nodes=15,
                                                  early_stopping=False, random_state=args.seed),
        # Red densa de dos capas ocultas: ReLU, Adam, retropropagación y penalización L2.
        # Sin early_stopping interno: evitar una validación aleatoria que mezcle dominios.
        "mlp": make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(64, 32),
            activation="relu", solver="adam", alpha=.001, batch_size=256,
            max_iter=args.epochs, early_stopping=False, random_state=args.seed)),
    }
    report = {"protocol": "pilot-group-holdout-v1", "seed": args.seed,
              "dataset_sha256": hashlib.sha256(Path(args.csv).read_bytes()).hexdigest(),
              "original_phishing_label": args.etiqueta_phishing,
              "audit": audit, "features": list(FEATURES), "feature_version": FEATURE_VERSION,
              "splits": {k: {"n": int(m.sum()), "phishing": int(y[m].sum()),
                              "domains": int(df.loc[m, "group"].nunique())} for k, m in masks.items()},
              "selection_metric": "validation average_precision before calibration",
              "models": {}, "python": platform.python_version(),
              "dependencies": {n: importlib.metadata.version(n) for n in ("scikit-learn", "numpy", "pandas", "tldextract", "joblib")},
              "limitations": ["Una sola fuente; no validación temporal ni externa.",
                "Separación por dominio no elimina todo sesgo de campaña o fuente.",
                "Configuraciones fijas; no búsqueda exhaustiva ni validación cruzada repetida.",
                "Los ejemplos locales no son etiquetas de entrenamiento ni pruebas de seguridad."]}
    for name, model in candidates.items():
        print("Entrenando", name, flush=True)
        tick = time.perf_counter()
        with warnings.catch_warnings(record=True) as caught, threadpool_limits(limits=2):
            warnings.simplefilter("always")
            model.fit(X[train], y[train])
        report["models"][name] = {"training_seconds": time.perf_counter() - tick,
            "parameters": {k: str(v) for k, v in model.get_params().items()},
            "warnings": [str(w.message) for w in caught],
            "train": metrics(y[train], model.predict_proba(X[train])[:, 1]),
            "validation": metrics(y[val], model.predict_proba(X[val])[:, 1])}
    selected = max((n for n in candidates if n != "dummy"),
                   key=lambda n: report["models"][n]["validation"]["average_precision"])
    report["selected"] = selected  # Elección fijada ANTES de consultar el test.
    report["selected_at"] = datetime.now(timezone.utc).isoformat()
    print("Seleccionado en validación:", selected, flush=True)
    bundles = {}
    for name, model in candidates.items():
        raw_cal = model.predict_proba(X[cal])[:, 1]
        calibrator = LogisticRegression(C=1000, max_iter=1000)
        calibrator.fit(logit_features(raw_cal), y[cal])
        bundle = {"name": name, "pipeline": model, "calibrator": calibrator,
                  "version": f"{name}-{report['dataset_sha256'][:8]}-s{args.seed}-{report['selected_at']}",
                  "feature_version": FEATURE_VERSION, "features": list(FEATURES)}
        bundle["policy"] = choose_policy(y[pol], probabilities(bundle, X[pol]))
        bundles[name] = bundle
    # Importancia global calculada en validación, no una explicación local.
    with threadpool_limits(limits=2):
        importance = permutation_importance(candidates[selected], X[val], y[val],
            scoring="average_precision", n_repeats=3, random_state=args.seed, n_jobs=1)
    report["global_permutation_importance_validation"] = sorted([
        {"feature": f, "mean": float(m), "std": float(s)}
        for f, m, s in zip(FEATURES, importance.importances_mean, importance.importances_std)
    ], key=lambda v: v["mean"], reverse=True)
    prediction_table = pd.DataFrame({"row_sha256": [hashlib.sha256(s.encode()).hexdigest() for s in df.loc[test, "key"]],
                                     "group": df.loc[test, "group"].to_numpy(), "label": y[test]})
    for name, bundle in bundles.items():
        p = probabilities(bundle, X[test])
        entry = report["models"][name]
        entry["test_uncalibrated"] = metrics(y[test], candidates[name].predict_proba(X[test])[:, 1])
        entry["test_calibrated"] = metrics(y[test], p)
        entry["decision_policy"] = bundle["policy"]
        entry["test_policy"] = policy_metrics(y[test], p, bundle["policy"])
        prediction_table[name] = p
        path = output / f"{name}.joblib"
        joblib.dump(bundle, path, compress=3)
        path.with_suffix(".manifest.json").write_text(json.dumps({"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "feature_version": FEATURE_VERSION, "name": name}, indent=2))
    report["selected_test_ap_interval"] = group_bootstrap(y[test], prediction_table[selected].to_numpy(),
                                                          prediction_table.group.to_numpy(), args.seed)
    report["mlp_loss_curve"] = candidates["mlp"][-1].loss_curve_
    report["elapsed_seconds"] = time.perf_counter() - start
    for suffix in (".joblib", ".manifest.json"):
        shutil.copyfile(output / (selected + suffix), output / ("selected" + suffix))
    prediction_table.to_csv(output / "test_predictions.csv", index=False)
    pd.DataFrame({"row_sha256": [hashlib.sha256(s.encode()).hexdigest() for s in df.key],
                  "group": df.group, "fold": folds}).to_csv(output / "splits.csv", index=False)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"selected": selected, "test": report['models'][selected]['test_calibrated'],
                      "saved": str(output)}, indent=2), flush=True)


if __name__ == "__main__":
    # Evita sobreasignar hilos durante predicción y calibración.
    with threadpool_limits(limits=2):
        main()
