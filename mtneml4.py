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
import warnings


warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')



# IP转换
def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack('I', ip_int))

# 模型和预处理工具路径
MODEL_PATH = "/home/zze/project/ebpfml/model/xgboost_model.pkl"
SCALER_PATH = "/home/zze/project/ebpfml/model/scalerxg.pkl"
LABEL_ENCODER_PATH = "/home/zze/project/ebpfml/model/label_encoderxg.pkl"

# 加载模型和预处理工具
model: XGBClassifier = load(MODEL_PATH)
scaler = load(SCALER_PATH)
label_encoder = load(LABEL_ENCODER_PATH)

# 加载eBPF程序
b = BPF(src_file="xdp3_1.c")
interface = "enp5s0"  
xdp_func = b.load_func("xdp_process", BPF.XDP)
b.attach_xdp(interface, xdp_func)

# 定义数据文件和行追踪
FEATURES_FILE = "/home/zze/project/flow_features.csv"
last_processed_line = 0
processed_keys = set()

# 初始化CSV文件（写入表头）
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

    # 写入流数据到CSV
    new_entries = []
    for key, value in flow_table.items():
        tuple_key = (key.saddr, key.daddr, key.sport, key.dport, key.protocol)
        if tuple_key in processed_keys:
            continue
        processed_keys.add(tuple_key)
        new_entries.append((key, value))

    # 将新条目追加写入 CSV 并预测
    with open(FEATURES_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        for key, value in new_entries:
            try:
                duration = (value.last_seen - value.start_ts) / 1e9 if value.start_ts else 0
                pkt_per_sec = value.total_packets / duration if duration > 0 else 0
                byte_per_sec = value.total_bytes / duration if duration > 0 else 0
                avg_fwd = value.fwd_bytes / value.fwd_packets if value.fwd_packets > 0 else 0
                init_win = value.init_win_fwd if key.protocol == socket.IPPROTO_TCP else -1
                src_ip = int_to_ip(value.src_ip)
                dst_ip = int_to_ip(value.dst_ip)
                proto = 'TCP' if key.protocol == socket.IPPROTO_TCP else 'UDP'

                writer.writerow([
                    src_ip, dst_ip, key.sport, key.dport, proto,
                    duration, pkt_per_sec, byte_per_sec,
                    avg_fwd, value.max_fwd_len, init_win
                ])
            except Exception as e:
                print(f"writer data err: {e}")

    # 对新增条目做模型预测并可选删除 BENIGN 流
    for key, value in new_entries:
        try:
            duration = (value.last_seen - value.start_ts) / 1e9 if value.start_ts else 0
            pkt_per_sec = value.total_packets / duration if duration > 0 else 0
            byte_per_sec = value.total_bytes / duration if duration > 0 else 0
            avg_fwd = value.fwd_bytes / value.fwd_packets if value.fwd_packets > 0 else 0
            init_win = value.init_win_fwd if key.protocol == socket.IPPROTO_TCP else -1
            features = np.array([duration, pkt_per_sec, byte_per_sec, avg_fwd, value.max_fwd_len, key.sport, init_win]).reshape(1, -1)
            pred = label_encoder.inverse_transform(model.predict(scaler.transform(features)))[0]
            if pred == 'MSSQL':
                pred = 'BENIGN'
            if pred == 'NetBIOS':
                pred = 'BENIGN' 
            src_ip = int_to_ip(value.src_ip)
            dst_ip = int_to_ip(value.dst_ip)
            print(f"INF:{src_ip}:{key.sport} -> {dst_ip}:{key.dport} Proto={proto} | Type:{pred}")

            if pred == 'BENIGN':
                bf_key = flow_table.Key(
                    src_ip=struct.unpack('!I', socket.inet_aton(src_ip))[0],
                    dst_ip=struct.unpack('!I', socket.inet_aton(dst_ip))[0],
                    sport=key.sport, dport=key.dport,
                    protocol=(6 if proto=='TCP' else 17)
                )
                if bf_key in flow_table:
                    del flow_table[bf_key]
        except Exception as e:
            print(f"model err: {e}")    

# 信号处理和主循环
def signal_handler(sig, frame):
    print("\n unload XDP...")
    b.remove_xdp(interface, 0)
    # 删除此次记录
    try:
        if os.path.exists(FEATURES_FILE):
            os.remove(FEATURES_FILE)
            print(f"Deleated: {FEATURES_FILE}")
    except Exception as e:
        print(f"删除CSV文件时出错: {e}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

while True:
    time.sleep(1)
    export_flow_features()