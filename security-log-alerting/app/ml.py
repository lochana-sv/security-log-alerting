"""Optional ML anomaly detection (IsolationForest) - the 'future work' item of the report."""
from . import database as db


def detect_anomalies(contamination=0.05, top=15):
    try:
        import pandas as pd
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return {"available": False, "message": "Install scikit-learn and pandas to enable ML detection."}
    rows = db.fetch("SELECT ts, ip, username, event_type, status FROM events WHERE ip IS NOT NULL")
    if len(rows) < 30:
        return {"available": True, "anomalies": [], "message": "Not enough data yet (need 30+ events)."}
    df = pd.DataFrame(rows)
    df["bucket"] = pd.to_datetime(df["ts"]).dt.floor("5min")
    df["failed"] = df["event_type"].isin(["login_failed", "invalid_user"]).astype(int)
    df["err"] = (df["status"].fillna(0) >= 400).astype(int)
    g = df.groupby(["ip", "bucket"]).agg(total=("event_type", "size"), failed=("failed", "sum"),
                                         errors=("err", "sum"), users=("username", "nunique")).reset_index()
    X = g[["total", "failed", "errors", "users"]]
    model = IsolationForest(contamination=contamination, random_state=42).fit(X)
    g["score"] = -model.score_samples(X)           # higher = more anomalous
    g["anomaly"] = model.predict(X) == -1
    g["bucket"] = g["bucket"].astype(str)
    res = g[g["anomaly"]].sort_values("score", ascending=False).head(top)
    return {"available": True, "anomalies": res.round(3).to_dict("records")}
