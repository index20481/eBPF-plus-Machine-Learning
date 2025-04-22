import signal
import socket
import struct
import sys
import csv
import os
import time
from bcc import BPF
import numpy as np
from joblib import load
from xgboost import XGBClassifier

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack('I', ip_int))


MODEL_PATH = "/home/zze/project/ebpfml/model/xgboost_model.pkl"
SCALER_PATH = "/home/zze/project/ebpfml/model/scalerxg.pkl"
LABEL_ENCODER_PATH = "/home/zze/project/ebpfml/model/label_encoderxg.pkl"

#load model
model: XGBClassifier = load(MODEL_PATH)
scaler = load(SCALER_PATH)
label_encoder = load(LABEL_ENCODER_PATH)

#load ebpf
b = BPF(src_file="xdp3.c")
interface = "enp5s0"  
xdp_func = b.load_func("xdp_process", BPF.XDP)
b.attach_xdp(interface, xdp_func)


FEATURES_FILE = "/home/zze/project/flow_features.csv"

last_processed_line = 0

# init csv
if not os.path.exists(FEATURES_FILE):
    with open(FEATURES_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        headers = [
            'src_ip', 'dst_ip', 'sport', 'dport', 'protocol',
            'duration', 'packets_per_sec', 'bytes_per_sec',
            'avg_fwd_size', 'max_fwd_len', 'init_win_fwd'
        ]
        writer.writerow(headers)

def export_flow_features():
    global last_processed_line
    flow_table = b["flow_table"]

    #write csv
    with open(FEATURES_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        for key, value in flow_table.items():
            try:
                duration = (value.last_seen - value.start_ts) / 1e9 if value.start_ts != 0 else 0
                packets_per_sec = value.total_packets / duration if duration > 0 else 0
                bytes_per_sec = value.total_bytes / duration if duration > 0 else 0
                avg_fwd_size = value.fwd_bytes / value.fwd_packets if value.fwd_packets > 0 else 0
                init_win_fwd = value.init_win_fwd if key.protocol == socket.IPPROTO_TCP else -1
                src_ip = int_to_ip(value.src_ip)
                dst_ip = int_to_ip(value.dst_ip)
                proto = 'TCP' if key.protocol == socket.IPPROTO_TCP else 'UDP'
                
                writer.writerow([
                    src_ip, dst_ip, key.sport, key.dport, proto,
                    duration, packets_per_sec, bytes_per_sec,
                    avg_fwd_size, value.max_fwd_len, init_win_fwd
                ])
            except Exception as e:
                print(f"writer data err: {e}")

    #read csv
    with open(FEATURES_FILE, 'r') as f:
        reader = csv.reader(f)
        headers = next(reader)  #
        for _ in range(last_processed_line):
            next(reader, None)
        new_rows = list(reader)
        last_processed_line += len(new_rows)

        for row in new_rows:
            try:
                src_ip, dst_ip, sport, dport, proto, duration, pkt_sec, byte_sec, avg_fwd, max_fwd, init_win = row
                
                features = np.array([float(duration), float(pkt_sec), float(byte_sec),
                                     float(avg_fwd), float(max_fwd), int(sport), float(init_win)]).reshape(1, -1)
                
                features_scaled = scaler.transform(features)
                # predit
                pred = label_encoder.inverse_transform(model.predict(features_scaled))[0]
                if pred in ['MSSQL']:
                    pred = 'BENIGN'
                print(f"INF:{src_ip}:{sport} -> {dst_ip}:{dport} {proto} | Type:{pred}")

                # drop BENIGN
                if pred == 'BENIGN':
                    src_ip_int = struct.unpack('!I', socket.inet_aton(src_ip))[0]
                    dst_ip_int = struct.unpack('!I', socket.inet_aton(dst_ip))[0]
                    protocol_num = 6 if proto == 'TCP' else 17
                    key = flow_table.Key(
                        src_ip=src_ip_int,
                        dst_ip=dst_ip_int,
                        sport=int(sport),
                        dport=int(dport),
                        protocol=protocol_num
                    )
                    if key in flow_table:
                        del flow_table[key]
            except Exception as e:
                print(f"model err: {e}")


def signal_handler(sig, frame):
    print("\nuninstall XDP...")
    b.remove_xdp(interface, 0)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

while True:
    time.sleep(1)
    export_flow_features()