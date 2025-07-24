
import threading
import asyncio
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import numpy as np
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import pickle
from flask_socketio import SocketIO, emit
import pandas as pd
from datetime import datetime
from collections import deque
import os
import tensorflow as tf
import tensorflow.keras.backend as K

class RealtimeService:
    def __init__(self, app):
        self.app = app
        self.socketio = SocketIO(app, cors_allowed_origins=["http://localhost:3000"])
        
        try:
            # Load the weights from the pickle file
            with open(os.path.join('models', 'weights_mse_pretrain.pkl'), 'rb') as f:
                self.weights = pickle.load(f)
            self.weights = tf.constant(self.weights, dtype=tf.float32)

            # Define weighted sum loss function
            def weighted_sum_loss(weights):
                def loss(y_true, y_pred):
                    error = K.square(y_true - y_pred)
                    weighted_error = error * weights
                    return K.mean(K.sum(weighted_error, axis=-1), axis=-1)
                return loss

            # Create specific loss function with weights
            custom_loss = weighted_sum_loss(self.weights)

            # Load the new model with the custom loss function
            self.model = load_model(
                os.path.join('models', 'lstm_ae_mse_weighted_sum_pretrain.keras'),
                custom_objects={'loss': custom_loss},
                compile=True
            )

            # Load the scaler
            with open(os.path.join('models', 'scaler_mse_weighted_sum_pretrain.pkl'), 'rb') as f:
                self.scaler = pickle.load(f)
            
            if hasattr(self.scaler, 'feature_names_in_'):
                self.train_columns = list(self.scaler.feature_names_in_)
            else:
                self.train_columns = [
                    'protocol', 'flow_duration', 'flow_byts_s', 'flow_pkts_s', 'fwd_pkts_s', 'bwd_pkts_s',
                    'tot_fwd_pkts', 'tot_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_mean', 'fwd_pkt_len_std',
                    'pkt_len_max', 'pkt_len_mean', 'pkt_len_std', 'flow_iat_mean', 'flow_iat_max', 'flow_iat_std',
                    'fwd_iat_tot', 'bwd_iat_tot', 'syn_flag_cnt', 'ack_flag_cnt', 'fin_flag_cnt', 'rst_flag_cnt',
                    'down_up_ratio', 'pkt_size_avg', 'init_fwd_win_byts', 'init_bwd_win_byts',
                    'subflow_fwd_pkts', 'subflow_bwd_pkts'
                ]
            
            print("Model, scaler, and weights loaded successfully")
        except Exception as e:
            print(f"Error loading model/scaler/weights: {e}")
            import traceback
            traceback.print_exc()
            raise
        
        self.window_size = 10
        self.n_features = len(self.train_columns)
        self.interface = 'ens33'
        self.abnormal_history = deque(maxlen=10)
        self.packet_buffer = deque(maxlen=self.window_size)
        self.history_buffer = deque(maxlen=50)
        self.attack_history = deque(maxlen=100)
        self.lock = threading.Lock()
        self.flows = {}
        self.flow_timeout = 60
        self.buffer_cleanup_interval = 300
        self.anomaly_window = 10
        self.anomaly_threshold = 80
        self.mse_threshold = 2  # Adjusted based on percentile 95 from test results

    def process_packet(self, pkt):
        try:
            if not pkt.haslayer(IP):
                return
                
            ip_layer = pkt.getlayer(IP)
            if ip_layer is None:
                return
                
            try:
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.proto
            except (AttributeError, TypeError) as e:
                print(f"Error extracting IP info: {e} - {pkt.summary() if pkt else 'None'}")
                return
                
            if not src_ip or not dst_ip:
                print(f"Skipping packet: No valid src/dst IP - {pkt.summary()}")
                return
                
            with self.lock:
                timestamp = float(pkt.time) if hasattr(pkt, 'time') else datetime.now().timestamp()
                packet_size = len(pkt)
                
                flow_key = (src_ip, dst_ip, protocol)
                reverse_flow_key = (dst_ip, src_ip, protocol)
                
                if flow_key in self.flows:
                    flow = self.flows[flow_key]
                    flow['direction'] = 'forward'
                elif reverse_flow_key in self.flows:
                    flow = self.flows[reverse_flow_key]
                    flow['direction'] = 'backward'
                else:
                    flow = self._create_new_flow(flow_key, src_ip, dst_ip, protocol, timestamp)
                    self.flows[flow_key] = flow
                    flow['direction'] = 'forward'
                
                self._update_flow_stats(flow, pkt, packet_size, timestamp)
                
                if (timestamp - flow['start_time'] > self.flow_timeout or 
                    flow['total_packets'] >= 100):
                    self._finalize_flow(flow, timestamp)
                    if flow_key in self.flows:
                        del self.flows[flow_key]
                    if reverse_flow_key in self.flows:
                        del self.flows[reverse_flow_key]
                        
        except Exception as e:
            print(f"Error processing packet: {e} - {pkt.summary() if pkt else 'None'}")

    def _create_new_flow(self, flow_key, src_ip, dst_ip, protocol, timestamp):
        return {
            'key': flow_key,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'start_time': timestamp,
            'last_time': timestamp,
            'total_packets': 0,
            'total_bytes': 0,
            'fwd_pkts': 0,
            'bwd_pkts': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'fwd_pkt_lengths': [],
            'bwd_pkt_lengths': [],
            'all_pkt_lengths': [],
            'syn_flag_cnt': 0,
            'fin_flag_cnt': 0,
            'rst_flag_cnt': 0,
            'ack_flag_cnt': 0,
            'psh_flag_cnt': 0,
            'iat_values': [],
            'fwd_iat_values': [],
            'bwd_iat_values': [],
            'init_fwd_win_byts': -1,
            'init_bwd_win_byts': -1,
            'direction': 'forward'
        }

    def _update_flow_stats(self, flow, pkt, packet_size, timestamp):
        flow['total_packets'] += 1
        flow['total_bytes'] += packet_size
        flow['all_pkt_lengths'].append(packet_size)
        
        if flow['total_packets'] > 1:
            iat = timestamp - flow['last_time']
            flow['iat_values'].append(iat)
            if flow['direction'] == 'forward':
                flow['fwd_iat_values'].append(iat)
            else:
                flow['bwd_iat_values'].append(iat)
                
        flow['last_time'] = timestamp
        
        if flow['direction'] == 'forward':
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += packet_size
            flow['fwd_pkt_lengths'].append(packet_size)
            if flow['total_packets'] == 1 and pkt.haslayer(TCP):
                tcp_layer = pkt.getlayer(TCP)
                if tcp_layer and hasattr(tcp_layer, 'window'):
                    flow['init_fwd_win_byts'] = tcp_layer.window
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += packet_size
            flow['bwd_pkt_lengths'].append(packet_size)
            if flow['total_packets'] == 1 and pkt.haslayer(TCP):
                tcp_layer = pkt.getlayer(TCP)
                if tcp_layer and hasattr(tcp_layer, 'window'):
                    flow['init_bwd_win_byts'] = tcp_layer.window
        
        if pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            if tcp_layer and hasattr(tcp_layer, 'flags'):
                try:
                    if tcp_layer.flags & 0x02:  # SYN
                        flow['syn_flag_cnt'] += 1
                    if tcp_layer.flags & 0x01:  # FIN
                        flow['fin_flag_cnt'] += 1
                    if tcp_layer.flags & 0x04:  # RST
                        flow['rst_flag_cnt'] += 1
                    if tcp_layer.flags & 0x10:  # ACK
                        flow['ack_flag_cnt'] += 1
                    if tcp_layer.flags & 0x08:  # PSH
                        flow['psh_flag_cnt'] += 1
                except (AttributeError, TypeError):
                    pass

    def _calculate_flow_features(self, flow, flow_duration):
        features = {}
        
        features['protocol'] = float(flow['protocol'])
        features['flow_duration'] = flow_duration
        features['tot_fwd_pkts'] = flow['fwd_pkts']
        features['tot_bwd_pkts'] = flow['bwd_pkts']
        features['flow_byts_s'] = flow['total_bytes'] / flow_duration if flow_duration > 0 else 0
        features['flow_pkts_s'] = flow['total_packets'] / flow_duration if flow_duration > 0 else 0
        features['fwd_pkts_s'] = flow['fwd_pkts'] / flow_duration if flow_duration > 0 else 0
        features['bwd_pkts_s'] = flow['bwd_pkts'] / flow_duration if flow_duration > 0 else 0
        
        features['fwd_pkt_len_max'] = max(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0
        features['fwd_pkt_len_mean'] = np.mean(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0
        features['fwd_pkt_len_std'] = np.std(flow['fwd_pkt_lengths']) if flow['fwd_pkt_lengths'] else 0
        
        features['pkt_len_max'] = max(flow['all_pkt_lengths']) if flow['all_pkt_lengths'] else 0
        features['pkt_len_mean'] = np.mean(flow['all_pkt_lengths']) if flow['all_pkt_lengths'] else 0
        features['pkt_len_std'] = np.std(flow['all_pkt_lengths']) if flow['all_pkt_lengths'] else 0
        
        features['flow_iat_mean'] = np.mean(flow['iat_values']) if flow['iat_values'] else 0
        features['flow_iat_max'] = max(flow['iat_values']) if flow['iat_values'] else 0
        features['flow_iat_std'] = np.std(flow['iat_values']) if flow['iat_values'] else 0
        
        features['fwd_iat_tot'] = sum(flow['fwd_iat_values']) if flow['fwd_iat_values'] else 0
        features['bwd_iat_tot'] = sum(flow['bwd_iat_values']) if flow['bwd_iat_values'] else 0
        
        features['syn_flag_cnt'] = flow['syn_flag_cnt']
        features['ack_flag_cnt'] = flow['ack_flag_cnt']
        features['fin_flag_cnt'] = flow['fin_flag_cnt']
        features['rst_flag_cnt'] = flow['rst_flag_cnt']
        
        total_pkts = flow['fwd_pkts'] + flow['bwd_pkts']
        features['down_up_ratio'] = flow['bwd_bytes'] / flow['fwd_bytes'] if flow['fwd_bytes'] > 0 else 0
        features['pkt_size_avg'] = flow['total_bytes'] / total_pkts if total_pkts > 0 else 0
        
        features['init_fwd_win_byts'] = flow['init_fwd_win_byts']
        features['init_bwd_win_byts'] = flow['init_bwd_win_byts']
        
        features['subflow_fwd_pkts'] = flow['fwd_pkts']
        features['subflow_bwd_pkts'] = flow['bwd_pkts']
        
        return features

    def _finalize_flow(self, flow, timestamp):
        try:
            flow_duration = timestamp - flow['start_time']
            
            if flow_duration <= 0 or flow['total_packets'] < 2:
                return
                
            flow_features = self._calculate_flow_features(flow, flow_duration)
            
            df = pd.DataFrame([flow_features])
            df = df.reindex(columns=self.train_columns, fill_value=0)
            df = df.replace([np.inf, -np.inf], np.nan)
            df = df.fillna(df.max() if not df.max().isna().all() else 0)
            
            try:
                scaled_data = self.scaler.transform(df)
                self.packet_buffer.append(scaled_data[0])
                
                self._emit_realtime_data(flow_features, flow_duration, timestamp, scaled_data)
                
                if len(self.packet_buffer) >= self.window_size:
                    self._perform_anomaly_detection(flow_features, flow_duration, timestamp)
                    
            except ValueError as e:
                print(f"Error in scaling/transform: {e} - Features in df: {df.columns.tolist()}, Expected: {self.train_columns}")
            except Exception as e:
                print(f"Error in prediction: {e}")
                
        except Exception as e:
            print(f"Error finalizing flow: {e}")

    def _emit_realtime_data(self, flow_features, flow_duration, timestamp, scaled_data):
        try:
            current_time = datetime.now().timestamp()
            current_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            max_mse = 0.0
            is_anomaly = False
            abnormal_percentage = 0.0
            status = "Normal"
            
            if len(self.packet_buffer) >= self.window_size:
                X_test = np.array(self.packet_buffer).reshape((1, self.window_size, self.n_features))
                prediction = self.model.predict(X_test, verbose=0)
                
                # Compute weighted MSE for anomaly detection
                error = np.square(X_test - prediction)
                weighted_error = error * self.weights.numpy()  # Apply weights
                mse = np.mean(np.sum(weighted_error, axis=-1), axis=-1)
                max_mse = float(mse[0])
                is_anomaly = bool(mse[0] > self.mse_threshold)
                
                for entry in self.history_buffer:
                    entry['is_anomaly'] = bool(entry['max_mse'] > self.mse_threshold)
                
                recent_anomalies = sum(
                    1 for h in self.history_buffer 
                    if h['is_anomaly'] and (current_time - datetime.strptime(h['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp()) <= self.anomaly_window
                )
                total_recent = sum(
                    1 for h in self.history_buffer 
                    if (current_time - datetime.strptime(h['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp()) <= self.anomaly_window
                )
                abnormal_percentage = (recent_anomalies / total_recent * 100) if total_recent > 0 else 0
                status = "Anomaly Detected" if is_anomaly else "Normal"
            
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
            
            self.socketio.emit('realtime_data', {
                'timestamp': current_time_str,
                'flow_pkts_s': flow_features['flow_pkts_s'],
                'flow_byts_s': flow_features['flow_byts_s'],
                'tot_fwd_pkts': flow_features['tot_fwd_pkts'],
                'tot_bwd_pkts': flow_features['tot_bwd_pkts'],
                'max_mse': max_mse,
                'mse_values': [h['max_mse'] for h in self.history_buffer],
                'abnormal_percentage': abnormal_percentage,
                'is_anomaly': is_anomaly,
                'status': status,
                'flow_pkts_s_history': [h['flow_pkts_s'] for h in self.history_buffer],
                'flow_byts_s_history': [h['flow_byts_s'] for h in self.history_buffer],
                'attack_history': list(self.attack_history)
            })
            
            self._cleanup_buffer(current_time)
                
        except Exception as e:
            print(f"Error emitting realtime data: {e}")

    def _perform_anomaly_detection(self, flow_features, flow_duration, timestamp):
        try:
            X_test = np.array(self.packet_buffer).reshape((1, self.window_size, self.n_features))
            
            prediction = self.model.predict(X_test, verbose=0)
            
            # Compute weighted MSE for anomaly detection
            error = np.square(X_test - prediction)
            weighted_error = error * self.weights.numpy()  # Apply weights
            mse = np.mean(np.sum(weighted_error, axis=-1), axis=-1)
            
            max_mse = float(mse[0])
            is_anomaly = bool(mse[0] > self.mse_threshold)
            
            for entry in self.history_buffer:
                entry['is_anomaly'] = bool(entry['max_mse'] > self.mse_threshold)
            
            current_time = datetime.now().timestamp()
            recent_anomalies = sum(
                1 for h in self.history_buffer 
                if h['is_anomaly'] and (current_time - datetime.strptime(h['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp()) <= self.anomaly_window
            )
            total_recent = sum(
                1 for h in self.history_buffer 
                if (current_time - datetime.strptime(h['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp()) <= self.anomaly_window
            )
            abnormal_percentage = (recent_anomalies / total_recent * 100) if total_recent > 0 else 0
            
            history_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'flow_pkts_s': flow_features['flow_pkts_s'],
                'flow_byts_s': flow_features['flow_byts_s'],
                'tot_fwd_pkts': flow_features['tot_fwd_pkts'],
                'tot_bwd_pkts': flow_features['tot_bwd_pkts'],
                'max_mse': max_mse,
                'is_anomaly': is_anomaly
            }
            
            self.history_buffer.append(history_entry)
            
            self.socketio.emit('realtime_data', {
                'timestamp': history_entry['timestamp'],
                'flow_pkts_s': flow_features['flow_pkts_s'],
                'flow_byts_s': flow_features['flow_byts_s'],
                'tot_fwd_pkts': flow_features['tot_fwd_pkts'],
                'tot_bwd_pkts': flow_features['tot_bwd_pkts'],
                'max_mse': max_mse,
                'mse_values': [h['max_mse'] for h in self.history_buffer],
                'abnormal_percentage': abnormal_percentage,
                'is_anomaly': is_anomaly,
                'status': 'Anomaly Detected' if is_anomaly else 'Normal',
                'flow_pkts_s_history': [h['flow_pkts_s'] for h in self.history_buffer],
                'flow_byts_s_history': [h['flow_byts_s'] for h in self.history_buffer],
                'attack_history': list(self.attack_history)
            })
            
            if is_anomaly:
                self.abnormal_history.append(history_entry)
                if total_recent >= 3 and abnormal_percentage >= self.anomaly_threshold:
                    attack_entry = {
                        'timestamp': history_entry['timestamp'],
                        'prediction': 'Sustained Attack Detected',
                        'max_mse': max_mse,
                        'abnormal_percentage': abnormal_percentage,
                        'duration_confirmed': self.anomaly_window,
                        'details': f'Attack detected with {abnormal_percentage:.2f}% anomalies in {self.anomaly_window} seconds'
                    }
                    self.attack_history.append(attack_entry)
                    self.socketio.emit('alert', attack_entry)
            else:
                self.abnormal_history.clear()
                
            self._cleanup_buffer(current_time)
                
        except Exception as e:
            print(f"Error in anomaly detection: {e}")

    def _cleanup_buffer(self, current_time):
        try:
            cutoff_time = current_time - self.buffer_cleanup_interval
            self.history_buffer = deque(
                [h for h in self.history_buffer 
                 if datetime.strptime(h['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp() > cutoff_time],
                maxlen=50
            )
            print(f"Cleaned up history_buffer, remaining entries: {len(self.history_buffer)}")
        except Exception as e:
            print(f"Error cleaning up buffer: {e}")

    def start_realtime_monitoring(self):
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
            print(f"Error starting packet capture: {e}")
            raise

    def run(self):
        try:
            monitor_thread = threading.Thread(
                target=self.start_realtime_monitoring,
                daemon=True
            )
            monitor_thread.start()
            print("Realtime monitoring started successfully")
        except Exception as e:
            print(f"Error starting realtime monitoring: {e}")
            raise

    def cleanup_old_flows(self):
        current_time = datetime.now().timestamp()
        expired_flows = []
        
        for flow_key, flow in self.flows.items():
            if current_time - flow['last_time'] > self.flow_timeout:
                expired_flows.append(flow_key)
        
        for flow_key in expired_flows:
            if flow_key in self.flows:
                del self.flows[flow_key]
        
        if expired_flows:
            print(f"Cleaned up {len(expired_flows)} expired flows")

    def get_status(self):
        return {
            'active_flows': len(self.flows),
            'buffer_size': len(self.packet_buffer),
            'history_size': len(self.history_buffer),
            'attack_history_size': len(self.attack_history),
            'interface': self.interface
        }