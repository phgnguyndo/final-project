# app/services/realtime_service.py
import threading
import asyncio
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import numpy as np
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import pickle
from flask_socketio import SocketIO, emit
from ..config.settings import Config
import pandas as pd
from datetime import datetime
from collections import deque
import os

class RealtimeService:
    def __init__(self, app):
        self.app = app
        self.socketio = SocketIO(app, cors_allowed_origins=["http://localhost:3000"])  # Cho phép origin frontend
        self.model = load_model(os.path.join('models', 'lstm_ae_be_model.h5'),
                              custom_objects={'mse': 'mse'}, compile=False)
        with open(os.path.join('models', 'scaler_be.pkl'), 'rb') as f:
            self.scaler = pickle.load(f)
        self.train_columns = [
            'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts',
            'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean', 'bwd_pkt_len_max', 'bwd_pkt_len_min',
            'bwd_pkt_len_mean', 'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 'flow_iat_max',
            'fwd_iat_tot', 'fwd_iat_max', 'fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt'
        ]
        self.window_size = 10
        self.n_features = len(self.train_columns)
        self.interface = 'wlp5s0'  # Thay đổi theo giao diện mạng của bạn
        self.abnormal_history = deque(maxlen=3)  # Lưu 3 window (30 giây)
        self.packet_buffer = deque(maxlen=self.window_size)  # Lưu 10 gói gần nhất
        self.history_buffer = deque(maxlen=10)  # Lưu lịch sử 10 window
        self.lock = threading.Lock()
        self.current_flow = None  # Khởi tạo để tránh lỗi

    def process_packet(self, pkt):
        if IP in pkt:
            with self.lock:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                timestamp = pkt.time
                flow_key = (src_ip, dst_ip, pkt[IP].proto)
                
                if not hasattr(self, 'current_flow') or self.current_flow['key'] != flow_key:
                    if hasattr(self, 'current_flow'):
                        self._finalize_flow(timestamp)
                    self.current_flow = {'key': flow_key, 'src_ip': src_ip, 'dst_ip': dst_ip,
                                      'total_packets': 0, 'total_bytes': 0, 'fwd_pkts': 0, 'bwd_pkts': 0,
                                      'fwd_bytes': 0, 'bwd_bytes': 0, 'syn_flag_cnt': 0, 'fin_flag_cnt': 0,
                                      'rst_flag_cnt': 0, 'psh_flag_cnt': 0, 'ack_flag_cnt': 0,
                                      'total_iat': 0, 'iat_values': [], 'fwd_iat_values': [], 'bwd_iat_values': [],
                                      'last_time': timestamp, 'start_time': timestamp}
                
                self.current_flow['total_packets'] += 1
                self.current_flow['total_bytes'] += len(pkt)
                if TCP in pkt:
                    if pkt[TCP].flags.S: self.current_flow['syn_flag_cnt'] += 1
                    if pkt[TCP].flags.F: self.current_flow['fin_flag_cnt'] += 1
                    if pkt[TCP].flags.R: self.current_flow['rst_flag_cnt'] += 1
                    if pkt[TCP].flags.P: self.current_flow['psh_flag_cnt'] += 1
                    if pkt[TCP].flags.A: self.current_flow['ack_flag_cnt'] += 1
                if src_ip == self.current_flow['src_ip']:
                    self.current_flow['fwd_pkts'] += 1
                    self.current_flow['fwd_bytes'] += len(pkt)
                else:
                    self.current_flow['bwd_pkts'] += 1
                    self.current_flow['bwd_bytes'] += len(pkt)
                if self.current_flow['total_packets'] > 1:
                    iat = timestamp - self.current_flow['last_time']
                    self.current_flow['total_iat'] += iat
                    self.current_flow['iat_values'].append(iat)
                    if src_ip == self.current_flow['src_ip']:
                        self.current_flow['fwd_iat_values'].append(iat)
                    else:
                        self.current_flow['bwd_iat_values'].append(iat)
                self.current_flow['last_time'] = timestamp

    def _finalize_flow(self, timestamp):
        flow_duration = timestamp - self.current_flow['start_time']
        if flow_duration > 0 and self.current_flow['total_packets'] >= self.window_size:
            flow_byts_s = self.current_flow['total_bytes'] / flow_duration
            flow_pkts_s = self.current_flow['total_packets'] / flow_duration
            flow_iat_mean = self.current_flow['total_iat'] / (self.current_flow['total_packets'] - 1) if self.current_flow['total_packets'] > 1 else 0
            flow_iat_max = max(self.current_flow['iat_values']) if self.current_flow['iat_values'] and len(self.current_flow['iat_values']) > 0 else 0
            flow_iat_min = min(self.current_flow['iat_values']) if self.current_flow['iat_values'] and len(self.current_flow['iat_values']) > 0 else 0
            flow_iat_std = np.std(self.current_flow['iat_values']) if len(self.current_flow['iat_values']) > 1 else 0
            fwd_iat_tot = sum(self.current_flow['fwd_iat_values'])
            fwd_iat_max = max(self.current_flow['fwd_iat_values']) if self.current_flow['fwd_iat_values'] and len(self.current_flow['fwd_iat_values']) > 0 else 0
            fwd_iat_min = min(self.current_flow['fwd_iat_values']) if self.current_flow['fwd_iat_values'] and len(self.current_flow['fwd_iat_values']) > 0 else 0
            fwd_iat_mean = np.mean(self.current_flow['fwd_iat_values']) if self.current_flow['fwd_iat_values'] and len(self.current_flow['fwd_iat_values']) > 0 else 0
            fwd_iat_std = np.std(self.current_flow['fwd_iat_values']) if len(self.current_flow['fwd_iat_values']) > 1 else 0
            bwd_iat_tot = sum(self.current_flow['bwd_iat_values'])
            bwd_iat_max = max(self.current_flow['bwd_iat_values']) if self.current_flow['bwd_iat_values'] and len(self.current_flow['bwd_iat_values']) > 0 else 0
            bwd_iat_min = min(self.current_flow['bwd_iat_values']) if self.current_flow['bwd_iat_values'] and len(self.current_flow['bwd_iat_values']) > 0 else 0
            bwd_iat_mean = np.mean(self.current_flow['bwd_iat_values']) if self.current_flow['bwd_iat_values'] and len(self.current_flow['bwd_iat_values']) > 0 else 0
            bwd_iat_std = np.std(self.current_flow['bwd_iat_values']) if len(self.current_flow['bwd_iat_values']) > 1 else 0

            # Tạo DataFrame tạm
            flow_data = {
                'flow_duration': flow_duration,
                'tot_fwd_pkts': self.current_flow['fwd_pkts'],
                'tot_bwd_pkts': self.current_flow['bwd_pkts'],
                'totlen_fwd_pkts': self.current_flow['fwd_bytes'],
                'totlen_bwd_pkts': self.current_flow['bwd_bytes'],
                'flow_byts_s': flow_byts_s,
                'flow_pkts_s': flow_pkts_s,
                'flow_iat_mean': flow_iat_mean,
                'flow_iat_max': flow_iat_max,
                'flow_iat_min': flow_iat_min,
                'flow_iat_std': flow_iat_std,
                'fwd_iat_tot': fwd_iat_tot,
                'fwd_iat_max': fwd_iat_max,
                'fwd_iat_min': fwd_iat_min,
                'fwd_iat_mean': fwd_iat_mean,
                'fwd_iat_std': fwd_iat_std,
                'bwd_iat_tot': bwd_iat_tot,
                'bwd_iat_max': bwd_iat_max,
                'bwd_iat_min': bwd_iat_min,
                'bwd_iat_mean': bwd_iat_mean,
                'bwd_iat_std': bwd_iat_std,
                'fin_flag_cnt': self.current_flow['fin_flag_cnt'],
                'syn_flag_cnt': self.current_flow['syn_flag_cnt'],
                'rst_flag_cnt': self.current_flow['rst_flag_cnt'],
                'psh_flag_cnt': self.current_flow['psh_flag_cnt'],
                'ack_flag_cnt': self.current_flow['ack_flag_cnt']
            }
            df = pd.DataFrame([flow_data])
            for col in self.train_columns:
                if col not in df.columns:
                    df[col] = 0
            df = df[self.train_columns]

            # Chuẩn hóa và dự đoán
            scaled_data = self.scaler.transform(df)
            self.packet_buffer.append(scaled_data[0])
            if len(self.packet_buffer) >= self.window_size:
                X_test = np.array(self.packet_buffer).reshape((1, self.window_size, self.n_features))
                mse = np.mean(np.power(X_test - self.model.predict(X_test, verbose=0), 2), axis=(1, 2))[0]
                threshold = np.percentile(mse, 95) if len(mse) > 0 else 0
                y_pred = (mse > threshold).astype(int)
                abnormal_percentage = (np.sum(y_pred) / len(y_pred)) * 100 if len(y_pred) > 0 else 0
                max_mse = np.max(mse) if len(mse) > 0 else 0

                # Lưu lịch sử và gửi dữ liệu realtime
                self.history_buffer.append({'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                         'flow_pkts_s': flow_pkts_s, 'flow_byts_s': flow_byts_s,
                                         'tot_fwd_pkts': self.current_flow['fwd_pkts'],
                                         'tot_bwd_pkts': self.current_flow['bwd_pkts'],
                                         'max_mse': max_mse, 'abnormal_percentage': abnormal_percentage})
                self.socketio.emit('realtime_data', {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'flow_pkts_s': flow_pkts_s,
                    'flow_byts_s': flow_byts_s,
                    'tot_fwd_pkts': self.current_flow['fwd_pkts'],
                    'tot_bwd_pkts': self.current_flow['bwd_pkts'],
                    'max_mse': max_mse,
                    'abnormal_percentage': abnormal_percentage,
                    'status': 'Normal',
                    'mse_values': mse.tolist() if len(mse) > 0 else [],
                    'flow_pkts_s_history': [h['flow_pkts_s'] for h in self.history_buffer],
                    'flow_byts_s_history': [h['flow_byts_s'] for h in self.history_buffer]
                })

                # Xác nhận bất thường
                self.abnormal_history.append({'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                           'max_mse': max_mse, 'abnormal_percentage': abnormal_percentage})
                if len(self.abnormal_history) > 3:
                    self.abnormal_history.pop(0)
                if len(self.abnormal_history) == 3:
                    abnormal_count = sum(1 for h in self.abnormal_history if h['abnormal_percentage'] > 90 or 
                                       (h['max_mse'] > 0.0005 and h['abnormal_percentage'] > 20))
                    if abnormal_count >= 2:  # Xác nhận bất thường sau 30 giây
                        self.socketio.emit('alert', {
                            'timestamp': self.abnormal_history[0]['timestamp'],
                            'prediction': 'Attack detected',
                            'max_mse': max(self.abnormal_history, key=lambda x: x['max_mse'])['max_mse'],
                            'abnormal_percentage': max(self.abnormal_history, key=lambda x: x['abnormal_percentage'])['abnormal_percentage'],
                            'duration_confirmed': 30
                        })
                        self.abnormal_history = []  # Reset sau khi báo

    def start_realtime_monitoring(self):
        self.packet_buffer = deque(maxlen=self.window_size)
        sniff(iface=self.interface, prn=self.process_packet, store=0)

    def run(self):
        monitor_thread = threading.Thread(target=self.start_realtime_monitoring, daemon=True)
        monitor_thread.start()