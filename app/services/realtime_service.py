import threading
import time
from flask_socketio import SocketIO, emit
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import pickle
import os
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime
from collections import deque
from flask import request
import logging
from concurrent.futures import ThreadPoolExecutor
import gc

# Configure logging for better debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealtimeService:
    def __init__(self, app):
        self.app = app
        self.socketio = SocketIO(
            app, 
            cors_allowed_origins=["http://localhost:3000", "http://192.168.11.132:5000"], 
            async_mode='threading',
            ping_timeout=30,
            ping_interval=10
        )
        
        # Load model and scaler
        try:
            self.model = load_model(
                os.path.join('models', 'lstm_ae_retrain_add_column.h5'),
                custom_objects={'mse': 'mse'}, compile=False
            )
            with open(os.path.join('models', 'scaler_retrain_add_column.pkl'), 'rb') as f:
                self.scaler = pickle.load(f)
            
            # Define feature names (29 columns) - KHÔNG THAY ĐỔI
            self.train_columns = [
                'protocol', 'flow_duration', 'flow_byts_s', 'flow_pkts_s', 'fwd_pkts_s', 'bwd_pkts_s',
                'tot_fwd_pkts', 'tot_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_mean', 'fwd_pkt_len_std',
                'pkt_len_max', 'pkt_len_mean', 'pkt_len_std', 'flow_iat_mean', 'flow_iat_max', 'flow_iat_std',
                'fwd_iat_tot', 'bwd_iat_tot', 'syn_flag_cnt', 'ack_flag_cnt', 'fin_flag_cnt', 'rst_flag_cnt',
                'down_up_ratio', 'pkt_size_avg', 'init_fwd_win_byts', 'init_bwd_win_byts', 
                'subflow_fwd_pkts', 'subflow_bwd_pkts'
            ]
            print(f"Using feature names: {self.train_columns}")
            print("Model and scaler loaded successfully")
        except Exception as e:
            print(f"Error loading model/scaler: {e}")
            raise
        
        # GIỮ NGUYÊN CÁC THAM SỐ GỐC
        self.window_size = 10  # Giữ nguyên
        self.n_features = len(self.train_columns)
        self.interface = 'ens33'
        self.packet_buffer = deque(maxlen=self.window_size)
        self.history_buffer = deque(maxlen=50)
        self.attack_history = deque(maxlen=100)
        self.abnormal_history = deque(maxlen=10)
        self.normal_confirmation_history = deque(maxlen=1000)
        self.previous_status = "Normal"
        self.flows = {}
        self.flow_timeout = 10  # Giữ nguyên
        self.buffer_cleanup_interval = 60  # Giữ nguyên
        self.anomaly_window = 10  # Giữ nguyên
        self.anomaly_threshold = 80  # Giữ nguyên
        self.normal_confirmation_window = 5  # Giữ nguyên
        self.state_change_threshold = 0.8  # Giữ nguyên
        self.mse_threshold = 2  # Giữ nguyên
        
        # Tối ưu threading và performance
        self.lock = threading.RLock()  # Sử dụng RLock thay vì Lock
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="rt")
        
        # Tracking variables cho tối ưu
        self.packet_count = 0
        self.last_cleanup_time = time.time()
        self.last_emit_time = 0
        self.emit_interval = 0.05  # Giới hạn emit rate
        
        # Pre-compile regex patterns và cache
        self._feature_cache = {}
        self._flow_keys_cache = set()

    def process_packet(self, pkt):
        """Tối ưu packet processing với early returns"""
        try:
            # Quick validation với early returns
            if not pkt.haslayer(IP):
                return
                
            ip_layer = pkt.getlayer(IP)
            if ip_layer is None:
                return
                
            # Extract thông tin cần thiết một lần
            try:
                packet_info = {
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'timestamp': float(pkt.time) if hasattr(pkt, 'time') else time.time(),
                    'packet_size': len(pkt),
                    'src_port': 0,
                    'dst_port': 0
                }
                
                # Extract ports efficiently
                if pkt.haslayer(TCP):
                    tcp_layer = pkt.getlayer(TCP)
                    packet_info['src_port'] = tcp_layer.sport
                    packet_info['dst_port'] = tcp_layer.dport
                elif pkt.haslayer(UDP):
                    udp_layer = pkt.getlayer(UDP)
                    packet_info['src_port'] = udp_layer.sport
                    packet_info['dst_port'] = udp_layer.dport
                    
            except (AttributeError, TypeError) as e:
                return
                
            if not packet_info['src_ip'] or not packet_info['dst_ip']:
                return
                
            # Sử dụng non-blocking processing
            self.executor.submit(self._process_packet_threaded, pkt, packet_info)
            
            # Periodic cleanup (không block)
            self.packet_count += 1
            if self.packet_count % 200 == 0:
                self.executor.submit(self._periodic_maintenance)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _process_packet_threaded(self, pkt, packet_info):
        """Xử lý packet trong thread riêng"""
        try:
            with self.lock:
                flow_key = (packet_info['src_ip'], packet_info['dst_ip'], packet_info['protocol'], 
                           packet_info['src_port'], packet_info['dst_port'])
                reverse_flow_key = (packet_info['dst_ip'], packet_info['src_ip'], packet_info['protocol'], 
                                   packet_info['dst_port'], packet_info['src_port'])
                
                # Tìm flow hiệu quả hơn
                if flow_key in self.flows:
                    flow = self.flows[flow_key]
                    flow['direction'] = 'forward'
                elif reverse_flow_key in self.flows:
                    flow = self.flows[reverse_flow_key]
                    flow['direction'] = 'backward'
                else:
                    flow = self._create_new_flow(flow_key, packet_info)
                    self.flows[flow_key] = flow
                    self._flow_keys_cache.add(flow_key)
                    flow['direction'] = 'forward'
                
                self._update_flow_stats(flow, pkt, packet_info)
                
                # Check finalization conditions
                if (packet_info['timestamp'] - flow['start_time'] > self.flow_timeout or 
                    flow['total_packets'] >= 50):
                    self._finalize_flow(flow, packet_info['timestamp'])
                    
                    # Cleanup flows
                    if flow_key in self.flows:
                        del self.flows[flow_key]
                        self._flow_keys_cache.discard(flow_key)
                    if reverse_flow_key in self.flows:
                        del self.flows[reverse_flow_key]
                        self._flow_keys_cache.discard(reverse_flow_key)
                        
        except Exception as e:
            logger.error(f"Error in threaded packet processing: {e}")

    def _create_new_flow(self, flow_key, packet_info):
        """Tạo flow mới với initialization tối ưu"""
        return {
            'key': flow_key,
            'src_ip': packet_info['src_ip'],
            'dst_ip': packet_info['dst_ip'],
            'start_time': packet_info['timestamp'],
            'last_time': packet_info['timestamp'],
            'total_packets': 0,
            'total_bytes': 0,
            'fwd_pkts': 0,
            'bwd_pkts': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'fwd_pkt_lengths': [],
            'bwd_pkt_lengths': [],
            'syn_flag_cnt': 0,
            'fin_flag_cnt': 0,
            'rst_flag_cnt': 0,
            'ack_flag_cnt': 0,
            'iat_values': [],
            'fwd_iat_values': [],
            'bwd_iat_values': [],
            'direction': 'forward',
            'protocol': packet_info['protocol'],
            'src_port': packet_info['src_port'],
            'dst_port': packet_info['dst_port'],
            'init_fwd_win_byts': 0,
            'init_bwd_win_byts': 0
        }

    def _update_flow_stats(self, flow, pkt, packet_info):
        """Cập nhật thống kê flow với optimization"""
        flow['total_packets'] += 1
        flow['total_bytes'] += packet_info['packet_size']
        
        # Tính IAT hiệu quả hơn
        if flow['total_packets'] > 1:
            iat = packet_info['timestamp'] - flow['last_time']
            flow['iat_values'].append(iat)
            if flow['direction'] == 'forward':
                flow['fwd_iat_values'].append(iat)
            else:
                flow['bwd_iat_values'].append(iat)
                
        flow['last_time'] = packet_info['timestamp']
        
        # Cập nhật theo hướng
        if flow['direction'] == 'forward':
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += packet_info['packet_size']
            flow['fwd_pkt_lengths'].append(packet_info['packet_size'])
            if pkt.haslayer(TCP) and flow['init_fwd_win_byts'] == 0:
                flow['init_fwd_win_byts'] = pkt[TCP].window
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += packet_info['packet_size']
            flow['bwd_pkt_lengths'].append(packet_info['packet_size'])
            if pkt.haslayer(TCP) and flow['init_bwd_win_byts'] == 0:
                flow['init_bwd_win_byts'] = pkt[TCP].window
        
        # Xử lý TCP flags hiệu quả hơn
        if pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer and hasattr(tcp_layer, 'flags'):
                try:
                    flags = tcp_layer.flags
                    flow['syn_flag_cnt'] += bool(flags & 0x02)
                    flow['fin_flag_cnt'] += bool(flags & 0x01)
                    flow['rst_flag_cnt'] += bool(flags & 0x04)
                    flow['ack_flag_cnt'] += bool(flags & 0x10)
                except (AttributeError, TypeError):
                    pass

    def _calculate_flow_features(self, flow, flow_duration):
        """Tính toán features với numpy optimization"""
        # Sử dụng numpy cho tính toán nhanh hơn
        fwd_lens = np.array(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else np.array([0])
        bwd_lens = np.array(flow['bwd_pkt_lengths']) if flow['bwd_pkt_lengths'] else np.array([0])
        all_lens = np.concatenate([fwd_lens, bwd_lens]) if (len(fwd_lens) > 0 and len(bwd_lens) > 0) else fwd_lens
        iat_vals = np.array(flow['iat_values']) if flow['iat_values'] else np.array([0])
        
        features = {
            'protocol': flow['protocol'],
            'flow_duration': flow_duration,
            'tot_fwd_pkts': flow['fwd_pkts'],
            'tot_bwd_pkts': flow['bwd_pkts'],
            'fwd_pkt_len_max': np.max(fwd_lens),
            'fwd_pkt_len_mean': np.mean(fwd_lens),
            'fwd_pkt_len_std': np.std(fwd_lens),
            'pkt_len_max': np.max(all_lens),
            'pkt_len_mean': np.mean(all_lens),
            'pkt_len_std': np.std(all_lens),
            'flow_byts_s': flow['total_bytes'] / flow_duration if flow_duration > 0 else 0,
            'flow_pkts_s': flow['total_packets'] / flow_duration if flow_duration > 0 else 0,
            'fwd_pkts_s': flow['fwd_pkts'] / flow_duration if flow_duration > 0 else 0,
            'bwd_pkts_s': flow['bwd_pkts'] / flow_duration if flow_duration > 0 else 0,
            'flow_iat_mean': np.mean(iat_vals),
            'flow_iat_max': np.max(iat_vals),
            'flow_iat_std': np.std(iat_vals),
            'fwd_iat_tot': np.sum(flow['fwd_iat_values']) if flow['fwd_iat_values'] else 0,
            'bwd_iat_tot': np.sum(flow['bwd_iat_values']) if flow['bwd_iat_values'] else 0,
            'syn_flag_cnt': flow['syn_flag_cnt'],
            'ack_flag_cnt': flow['ack_flag_cnt'],
            'fin_flag_cnt': flow['fin_flag_cnt'],
            'rst_flag_cnt': flow['rst_flag_cnt'],
            'down_up_ratio': flow['fwd_pkts'] / flow['bwd_pkts'] if flow['bwd_pkts'] > 0 else 1000,
            'pkt_size_avg': flow['total_bytes'] / flow['total_packets'] if flow['total_packets'] > 0 else 0,
            'init_fwd_win_byts': flow['init_fwd_win_byts'],
            'init_bwd_win_byts': flow['init_bwd_win_byts'],
            'subflow_fwd_pkts': flow['fwd_pkts'],
            'subflow_bwd_pkts': flow['bwd_pkts']
        }
        
        return features

    def _finalize_flow(self, flow, timestamp):
        """Finalize flow với caching và optimization"""
        try:
            flow_duration = timestamp - flow['start_time']
            
            if flow_duration <= 0 or flow['total_packets'] < 2:
                return
                
            flow_features = self._calculate_flow_features(flow, flow_duration)
            
            # Tạo DataFrame hiệu quả hơn
            df = pd.DataFrame([flow_features])
            df = df.reindex(columns=self.train_columns, fill_value=0)
            df = df.replace([np.inf, -np.inf], 0).fillna(0)
            
            try:
                scaled_data = self.scaler.transform(df)
                self.packet_buffer.append(scaled_data[0])
                
                # Emit real-time data với rate limiting
                current_time = time.time()
                if current_time - self.last_emit_time >= self.emit_interval:
                    self._emit_realtime_data(flow_features, flow_duration, timestamp)
                    self.last_emit_time = current_time
                
                if len(self.packet_buffer) >= self.window_size:
                    self._perform_anomaly_detection(flow_features, flow_duration, timestamp)
                    
            except ValueError as e:
                logger.error(f"Error in scaling/transform: {e}")
            except Exception as e:
                logger.error(f"Error in prediction: {e}")
                
        except Exception as e:
            logger.error(f"Error finalizing flow: {e}")

    def _emit_realtime_data(self, flow_features, flow_duration, timestamp):
        """Emit realtime data với optimization"""
        try:
            current_time = time.time()
            current_time_str = datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S')
            
            max_mse = 0.0
            is_anomaly = False
            if len(self.packet_buffer) >= self.window_size:
                X_test = np.array(self.packet_buffer).reshape((1, self.window_size, self.n_features))
                prediction = self.model.predict(X_test, verbose=0)
                mse = np.mean(np.power(X_test - prediction, 2), axis=(1, 2))
                max_mse = float(mse[0])
                is_anomaly = bool(mse[0] > self.mse_threshold)
                
                self.normal_confirmation_history.append({
                    'timestamp': current_time,
                    'is_anomaly': is_anomaly
                })

            history_entry = {
                'timestamp': current_time_str,
                'flow_pkts_s': flow_features['flow_pkts_s'],
                'flow_byts_s': flow_features['flow_byts_s'],
                'tot_fwd_pkts': flow_features['tot_fwd_pkts'],
                'tot_bwd_pkts': flow_features['tot_bwd_pkts'],
                'max_mse': max_mse,
                'is_anomaly': is_anomaly
            }
            
            self.history_buffer.append(history_entry)
            
            # Tính toán anomaly percentage hiệu quả hơn
            recent_entries = [h for h in self.history_buffer 
                             if (current_time - datetime.strptime(h['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp()) <= self.anomaly_window]
            
            if recent_entries:
                recent_anomalies = sum(1 for h in recent_entries if h['is_anomaly'])
                abnormal_percentage = (recent_anomalies / len(recent_entries) * 100)
            else:
                abnormal_percentage = 0
            
            # Emit data
            self.socketio.emit('realtime_data', {
                'timestamp': current_time_str,
                'flow_pkts_s': flow_features['flow_pkts_s'],
                'flow_byts_s': flow_features['flow_byts_s'],
                'tot_fwd_pkts': flow_features['tot_fwd_pkts'],
                'tot_bwd_pkts': flow_features['tot_bwd_pkts'],
                'max_mse': max_mse,
                'mse_values': [h['max_mse'] for h in list(self.history_buffer)[-20:]],  # Chỉ lấy 20 recent
                'abnormal_percentage': abnormal_percentage,
                'is_anomaly': is_anomaly,
                'status': self.previous_status,
                'flow_pkts_s_history': [h['flow_pkts_s'] for h in list(self.history_buffer)[-20:]],
                'flow_byts_s_history': [h['flow_byts_s'] for h in list(self.history_buffer)[-20:]],
                'attack_history': list(self.attack_history)[-10:]  # Chỉ lấy 10 recent
            })
                
        except Exception as e:
            logger.error(f"Error emitting realtime data: {e}")

    def _perform_anomaly_detection(self, flow_features, flow_duration, timestamp):
        """Perform anomaly detection với optimization"""
        try:
            X_test = np.array(self.packet_buffer).reshape((1, self.window_size, self.n_features))
            prediction = self.model.predict(X_test, verbose=0)
            mse = np.mean(np.power(X_test - prediction, 2), axis=(1, 2))
            max_mse = float(mse[0])
            
            is_anomaly = bool(mse[0] > self.mse_threshold)
            
            self.normal_confirmation_history.append({
                'timestamp': timestamp,
                'is_anomaly': is_anomaly
            })
            
            # Cập nhật status
            status = self.previous_status
            current_time = time.time()
            recent_entries = [entry for entry in self.normal_confirmation_history 
                             if (current_time - entry['timestamp']) <= self.normal_confirmation_window]
            
            if recent_entries:
                anomaly_count = sum(1 for entry in recent_entries if entry['is_anomaly'])
                anomaly_ratio = anomaly_count / len(recent_entries)
                
                if self.previous_status == "Normal" and anomaly_ratio > self.state_change_threshold:
                    status = "Anomaly Detected"
                    self.previous_status = status
                elif self.previous_status == "Anomaly Detected" and anomaly_ratio < (1 - self.state_change_threshold):
                    status = "Normal"
                    self.previous_status = status
            
            history_entry = {
                'timestamp': datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S'),
                'flow_pkts_s': flow_features['flow_pkts_s'],
                'flow_byts_s': flow_features['flow_byts_s'],
                'tot_fwd_pkts': flow_features['tot_fwd_pkts'],
                'tot_bwd_pkts': flow_features['tot_bwd_pkts'],
                'max_mse': max_mse,
                'is_anomaly': is_anomaly
            }
            
            self.history_buffer.append(history_entry)
            
            # Tính anomaly percentage
            recent_entries = [h for h in self.history_buffer 
                             if (current_time - datetime.strptime(h['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp()) <= self.anomaly_window]
            
            if recent_entries:
                recent_anomalies = sum(1 for h in recent_entries if h['is_anomaly'])
                abnormal_percentage = (recent_anomalies / len(recent_entries) * 100)
            else:
                abnormal_percentage = 0
            
            # Emit data với rate limiting
            if current_time - self.last_emit_time >= self.emit_interval:
                self.socketio.emit('realtime_data', {
                    'timestamp': history_entry['timestamp'],
                    'flow_pkts_s': flow_features['flow_pkts_s'],
                    'flow_byts_s': flow_features['flow_byts_s'],
                    'tot_fwd_pkts': flow_features['tot_fwd_pkts'],
                    'tot_bwd_pkts': flow_features['tot_bwd_pkts'],
                    'max_mse': max_mse,
                    'mse_values': [h['max_mse'] for h in list(self.history_buffer)[-20:]],
                    'abnormal_percentage': abnormal_percentage,
                    'is_anomaly': is_anomaly,
                    'status': status,
                    'flow_pkts_s_history': [h['flow_pkts_s'] for h in list(self.history_buffer)[-20:]],
                    'flow_byts_s_history': [h['flow_byts_s'] for h in list(self.history_buffer)[-20:]],
                    'attack_history': list(self.attack_history)[-10:]
                })
                self.last_emit_time = current_time
            
            # Handle alerts
            if is_anomaly:
                self.abnormal_history.append(history_entry)
                if len(recent_entries) >= 3 and abnormal_percentage >= self.anomaly_threshold:
                    attack_entry = {
                        'timestamp': history_entry['timestamp'],
                        'prediction': 'Sustained Anomaly Detected',
                        'max_mse': max_mse,
                        'abnormal_percentage': abnormal_percentage,
                        'duration_confirmed': self.anomaly_window,
                        'details': f'Anomaly detected with {abnormal_percentage:.2f}% anomalies in {self.anomaly_window} seconds'
                    }
                    self.attack_history.append(attack_entry)
                    self.socketio.emit('alert', attack_entry)
            else:
                if status == "Normal":
                    self.abnormal_history.clear()
                
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")

    def _periodic_maintenance(self):
        """Maintenance định kỳ với optimization"""
        try:
            current_time = time.time()
            
            # Skip nếu cleanup quá gần
            if current_time - self.last_cleanup_time < 30:  # 30 giây
                return
                
            self.last_cleanup_time = current_time
            
            with self.lock:
                # Clean expired flows
                expired_flows = []
                for flow_key, flow in self.flows.items():
                    if current_time - flow['last_time'] > self.flow_timeout:
                        expired_flows.append(flow_key)
                
                for flow_key in expired_flows:
                    if flow_key in self.flows:
                        del self.flows[flow_key]
                    self._flow_keys_cache.discard(flow_key)
                
                # Clean history buffers
                cutoff_time = current_time - self.buffer_cleanup_interval
                
                # Clean normal confirmation history
                self.normal_confirmation_history = deque(
                    [n for n in self.normal_confirmation_history 
                     if n['timestamp'] > current_time - self.normal_confirmation_window],
                    maxlen=1000
                )
                
                logger.info(f"Maintenance: removed {len(expired_flows)} flows, active flows: {len(self.flows)}")
                
                # Garbage collection định kỳ
                if self.packet_count % 1000 == 0:
                    gc.collect()
                    
        except Exception as e:
            logger.error(f"Error in periodic maintenance: {e}")

    def start_realtime_monitoring(self):
        """Start packet capture với optimization"""
        try:
            print(f"Starting packet capture on interface: {self.interface}")
            packet_filter = "ip and (tcp or udp or icmp)"
            
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=0,
                filter=packet_filter,
                stop_filter=lambda pkt: False
            )
        except Exception as e:
            logger.error(f"Error starting packet capture: {e}")
            raise

    def run(self):
        """Start the monitoring service"""
        try:
            monitor_thread = threading.Thread(
                target=self.start_realtime_monitoring,
                daemon=True
            )
            monitor_thread.start()
            print("Realtime monitoring started successfully")
            self.socketio.run(self.app, host='192.168.11.132', port=5000, allow_unsafe_werkzeug=True)
        except Exception as e:
            logger.error(f"Error starting realtime monitoring: {e}")
            raise
        finally:
            self.executor.shutdown(wait=True)

    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)