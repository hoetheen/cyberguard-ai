import os

import threading

import time

import random

import sys

import queue

from pathlib import Path

import tkinter as tk

from tkinter import ttk, messagebox



# --- third-party libs ---

try:

    import numpy as np

    import pandas as pd

    from sklearn.ensemble import IsolationForest

    import joblib

except Exception as e:

    print("Missing packages. Install with:\n pip install numpy pandas scikit-learn joblib")

    raise e



# ----------------------------

# Config / Paths

# ----------------------------

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "model_iforest.pkl"

DATA_PATH = BASE_DIR / "sample_network.csv"



# GUI Colors (dark-modern)

ACCENT_BG = "#0f172a"   # slate-900

CARD_BG   = "#111827"   # gray-900

ACCENT    = "#22d3ee"   # cyan-400

TEXT      = "#e5e7eb"   # gray-200

DANGER    = "#ef4444"   # red-500

SUCCESS   = "#16a34a"   # green-600

WARN      = "#f59e0b"   # amber-500


# ----------------------------

# Feature helpers (inline)

# ----------------------------

PROTO_MAP = {"tcp": 0, "udp": 1, "icmp": 2}



NUM_FEATURES = [

    "duration",

    "src_bytes",

    "dst_bytes",

    "pkts",

    "conn_rate",

    "failed_logins"

]



ALL_FEATURES = ["protocol"] + NUM_FEATURES



def encode_protocol(proto: str) -> int:

    return PROTO_MAP.get(str(proto).lower(), 0)



def row_to_features(row: dict) -> np.ndarray:

    proto = encode_protocol(row.get("protocol", "tcp"))

    vals = [

        float(row.get("duration", 0)),

        float(row.get("src_bytes", 0)),

        float(row.get("dst_bytes", 0)),

        float(row.get("pkts", 0)),

        float(row.get("conn_rate", 0)),

        float(row.get("failed_logins", 0)),

    ]

    return np.array([proto] + vals, dtype=float).reshape(1, -1)



# ----------------------------

# Synthetic data generator

# ----------------------------

def random_packet(anomalous=False):

    proto = random.choice(list(PROTO_MAP.keys()))

    if not anomalous:

        return {

            "protocol": proto,

            "duration": max(0.0, random.gauss(0.8, 0.5)),

            "src_bytes": abs(int(random.gauss(4000, 1200))),

            "dst_bytes": abs(int(random.gauss(3800, 1100))),

            "pkts": max(1, int(random.gauss(8, 3))),

            "conn_rate": max(0.01, random.gauss(2.5, 0.7)),

            "failed_logins": max(0, int(abs(random.gauss(0.1, 0.4))))

        }

    else:

        # anomaly: unusual large values or repeated failed logins

        return {

            "protocol": proto,

            "duration": max(0.0, random.gauss(12, 6)),

            "src_bytes": abs(int(random.gauss(120000, 50000))),

            "dst_bytes": abs(int(random.gauss(150000, 60000))),

            "pkts": max(1, int(random.gauss(250, 80))),

            "conn_rate": max(0.01, random.gauss(25, 10)),

            "failed_logins": max(1, int(abs(random.gauss(8, 4))))

        }



def generate_synthetic_csv(path: Path, n_normal=3000, n_anom=300):

    rows = []

    for _ in range(n_normal):

        rows.append(random_packet(anomalous=False))

    for _ in range(n_anom):

        rows.append(random_packet(anomalous=True))

    random.shuffle(rows)

    df = pd.DataFrame(rows)

    path.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(path, index=False)

    print(f"Synthetic dataset saved to {path}")



# ----------------------------

# Train model

# ----------------------------

def train_and_save_model(data_path: Path, model_path: Path):

    print("Training model...")

    if not data_path.exists():

        print("Data missing – generating synthetic data...")

        generate_synthetic_csv(data_path)



    df = pd.read_csv(data_path)

    # preprocess: ensure columns exist

    for col in ALL_FEATURES:

        if col not in df.columns:

            # fill missing numeric columns with zeros and protocol with 'tcp'

            if col == "protocol":

                df[col] = "tcp"

            else:

                df[col] = 0.0

    # map protocol and fillna

    df["protocol"] = df["protocol"].astype(str).str.lower().map(PROTO_MAP).fillna(0).astype(int)

    for col in NUM_FEATURES:

        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)



    X = df[["protocol"] + NUM_FEATURES].values



    model = IsolationForest(

        n_estimators=200,

        max_samples="auto",

        contamination=0.08,

        random_state=42,

        n_jobs=-1

    )

    model.fit(X)

    joblib.dump(model, model_path)

    print("Model trained and saved to", model_path)

    return model


# ----------------------------

# Tkinter GUI App

# ----------------------------

class IDSApp(tk.Tk):

    def __init__(self, model):

        super().__init__()

        self.title("IDS Monitor — Python ML + Tkinter")

        self.geometry("1000x640")

        self.minsize(900, 600)

        self.configure(bg=ACCENT_BG)

        self.model = model



        # stats

        self.running = False

        self.total_count = 0

        self.anomaly_count = 0



        # packet queue for thread-safe GUI updates

        self.q = queue.Queue(maxsize=200)



        self._build_ui()



        # start periodic GUI updater

        self.after(200, self._consume_queue)



    def _build_ui(self):

        # Header

        header = tk.Frame(self, bg=ACCENT_BG)

        header.pack(fill="x", padx=16, pady=(12,6))

        title = tk.Label(header, text="Intrusion Detection System (ML + GUI)",

                         bg=ACCENT_BG, fg=TEXT, font=("Segoe UI", 18, "bold"))

        title.pack(side="left")

        badge = tk.Label(header, text="Live", bg=ACCENT, fg="#000", font=("Segoe UI", 10, "bold"), padx=10, pady=4)

        badge.pack(side="right")



        # Control panel

        panel = tk.Frame(self, bg=CARD_BG)

        panel.pack(fill="x", padx=16, pady=(0,12))

        panel.columnconfigure(5, weight=1)



        self.start_btn = tk.Button(panel, text="Start", command=self.start_monitor,

                                   bg=SUCCESS, fg="#000", font=("Segoe UI", 11, "bold"))

        self.stop_btn  = tk.Button(panel, text="Stop", command=self.stop_monitor,

                                   bg=DANGER, fg="#000", font=("Segoe UI", 11, "bold"))

        self.clear_btn = tk.Button(panel, text="Clear", command=self.clear_table,

                                   bg=WARN, fg="#000", font=("Segoe UI", 11, "bold"))



        self.start_btn.grid(row=0, column=0, padx=8, pady=8, sticky="w")

        self.stop_btn.grid(row=0, column=1, padx=8, pady=8, sticky="w")

        self.clear_btn.grid(row=0, column=2, padx=8, pady=8, sticky="w")



        self.stat_total = tk.Label(panel, text="Total: 0", bg=CARD_BG, fg=TEXT, font=("Segoe UI", 11))

        self.stat_anom  = tk.Label(panel, text="Anomalies: 0", bg=CARD_BG, fg=TEXT, font=("Segoe UI", 11, "bold"))

        self.stat_rate  = tk.Label(panel, text="Anomaly Rate: 0.00%", bg=CARD_BG, fg=TEXT, font=("Segoe UI", 11))



        self.stat_total.grid(row=0, column=3, padx=8, sticky="e")

        self.stat_anom.grid(row=0, column=4, padx=8, sticky="e")

        self.stat_rate.grid(row=0, column=5, padx=8, sticky="e")



        # Treeview area

        container = tk.Frame(self, bg=ACCENT_BG)

        container.pack(fill="both", expand=True, padx=16, pady=(0,16))



        style = ttk.Style(self)

        style.theme_use("default")

        style.configure("Treeview", background=CARD_BG, fieldbackground=CARD_BG,

                        foreground=TEXT, rowheight=26, borderwidth=0)

        style.configure("Treeview.Heading", background="#0b1220", foreground=TEXT, font=("Segoe UI", 10, "bold"))

        style.map("Treeview", background=[("selected", "#1f2937")])



        cols = ("protocol", "duration", "src_bytes", "dst_bytes", "pkts", "conn_rate", "failed_logins", "score", "label")

        self.tree = ttk.Treeview(container, columns=cols, show="headings", selectmode="none")

        for c in cols:

            self.tree.heading(c, text=c.upper())

            self.tree.column(c, anchor="center", width=110)

        self.tree.column("protocol", width=90)

        self.tree.column("label", width=100)



        vsb = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)

        self.tree.configure(yscroll=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")

        vsb.grid(row=0, column=1, sticky="ns")



        # Statusbar

        sb = tk.Frame(self, bg=ACCENT_BG)

        sb.pack(fill="x", padx=16, pady=(0,12))

        self.status = tk.Label(sb, text="Ready", bg=ACCENT_BG, fg="#9ca3af", font=("Segoe UI", 10))

        self.status.pack(side="left")



    def start_monitor(self):

        if self.model is None:

            messagebox.showerror("Error", "Model missing. Train model first.")

            return

        if self.running:

            return

        self.running = True

        self.status.config(text="Monitoring…")

        self.thread = threading.Thread(target=self._producer_loop, daemon=True)

        self.thread.start()



    def stop_monitor(self):

        self.running = False

        self.status.config(text="Stopped")



    def clear_table(self):

        for i in self.tree.get_children():

            self.tree.delete(i)

        self.total_count = 0

        self.anomaly_count = 0

        self._update_stats()



    def _update_stats(self):

        self.stat_total.config(text=f"Total: {self.total_count}")

        self.stat_anom.config(text=f"Anomalies: {self.anomaly_count}")

        rate = 0 if self.total_count == 0 else (self.anomaly_count / self.total_count) * 100

        self.stat_rate.config(text=f"Anomaly Rate: {rate:.2f}%")



    def _producer_loop(self):

        # produce packets into queue; simulate some anomalies occasionally

        while self.running:

            # make anomalies rarer; but sometimes burst

            is_anom = (random.random() < 0.12)  # ~12% anomalies

            pkt = random_packet(anomalous=is_anom)

            features = row_to_features(pkt)

            try:

                score = float(self.model.decision_function(features)[0])

                pred = int(self.model.predict(features)[0])  # -1 anomaly, 1 normal

            except Exception as e:

                score = 0.0

                pred = 1

            label = "ANOMALY" if pred == -1 else "OK"

            self.q.put((pkt, score, label))

            time.sleep(0.6)



    def _consume_queue(self):

        # called in mainloop periodically

        try:

            while True:

                pkt, score, label = self.q.get_nowait()

                self._insert_row(pkt, score, label)

        except queue.Empty:

            pass

        finally:

            # schedule next

            self.after(200, self._consume_queue)



    def _insert_row(self, pkt, score, label):

        self.total_count += 1

        if label == "ANOMALY":

            self.anomaly_count += 1



        values = (

            pkt["protocol"],

            f"{pkt['duration']:.2f}",

            pkt["src_bytes"],

            pkt["dst_bytes"],

            pkt["pkts"],

            f"{pkt['conn_rate']:.2f}",

            pkt["failed_logins"],

            f"{score:.3f}",

            label

        )

        iid = self.tree.insert("", "end", values=values)

        # keep last N rows (avoid memory growth)

        max_rows = 200

        if len(self.tree.get_children()) > max_rows:

            first = self.tree.get_children()[0]

            self.tree.delete(first)

        # color tag

        self.tree.tag_configure("anom", foreground=DANGER)

        self.tree.tag_configure("ok", foreground=SUCCESS)

        self.tree.item(iid, tags=("anom" if label == "ANOMALY" else "ok"))

        self._update_stats()



# ----------------------------

# Main runner

# ----------------------------

def main():

    # load or train model

    model = None

    if MODEL_PATH.exists():

        try:

            model = joblib.load(MODEL_PATH)

            print("Loaded model from", MODEL_PATH)

        except Exception as e:

            print("Failed to load model (will retrain):", e)

            model = train_and_save_model(DATA_PATH, MODEL_PATH)

    else:

        # train and save

        model = train_and_save_model(DATA_PATH, MODEL_PATH)



    # start GUI

    app = IDSApp(model)

    app.mainloop()



if __name__ == "__main__":

    main()