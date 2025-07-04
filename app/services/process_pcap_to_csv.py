# app/services/process_pcap_to_csv.py
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import pandas as pd
import os
from datetime import datetime
import numpy as np

def process_pcap(pcap_path, csv_path):
    # Đọc file PCAP
    packets = rdpcap(pcap_path)
    
    # Khởi tạo danh sách để lưu flow
    flows = []
    current_flow = None
    flow_start_time = None
    timestamp = None  # Initialize timestamp
    
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            timestamp = float(pkt.time)
            flow_key = (src_ip, dst_ip, pkt[IP].proto)  # Nhận diện flow bằng cặp IP và giao thức
            
            if current_flow is None or current_flow['key'] != flow_key:
                if current_flow and flow_start_time is not None:
                    # Kết thúc flow trước
                    flow_duration = timestamp - flow_start_time
                    if flow_duration > 0:
                        flow_byts_s = current_flow['total_bytes'] / flow_duration
                        flow_pkts_s = current_flow['total_packets'] / flow_duration
                        flow_iat_mean = current_flow['total_iat'] / (current_flow['total_packets'] - 1) if current_flow['total_packets'] > 1 else 0
                        flow_iat_max = max(current_flow['iat_values']) if current_flow['iat_values'] else 0
                        flow_iat_min = min(current_flow['iat_values']) if current_flow['iat_values'] else 0
                        flow_iat_std = np.std(current_flow['iat_values']) if len(current_flow['iat_values']) > 1 else 0
                        fwd_iat_tot = sum(current_flow['fwd_iat_values'])
                        fwd_iat_max = max(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0
                        fwd_iat_min = min(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0
                        fwd_iat_mean = np.mean(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0
                        fwd_iat_std = np.std(current_flow['fwd_iat_values']) if len(current_flow['fwd_iat_values']) > 1 else 0
                        bwd_iat_tot = sum(current_flow['bwd_iat_values'])
                        bwd_iat_max = max(current_flow['bwd_iat_values']) if current_flow['bwd_iat_values'] else 0
                        bwd_iat_min = min(current_flow['bwd_iat_values']) if current_flow['bwd_iat_values'] else 0
                        bwd_iat_mean = np.mean(current_flow['bwd_iat_values']) if current_flow['bwd_iat_values'] else 0
                        bwd_iat_std = np.std(current_flow['bwd_iat_values']) if len(current_flow['bwd_iat_values']) > 1 else 0
                        fin_flag_cnt = current_flow['fin_flag_cnt']
                        rst_flag_cnt = current_flow['rst_flag_cnt']

                        flows.append({
                            'src_ip': current_flow['src_ip'],
                            'dst_ip': current_flow['dst_ip'],
                            'timestamp': datetime.fromtimestamp(flow_start_time).strftime('%Y-%m-%d %H:%M:%S'),
                            'flow_duration': flow_duration,
                            'tot_fwd_pkts': current_flow['fwd_pkts'],
                            'tot_bwd_pkts': current_flow['bwd_pkts'],
                            'totlen_fwd_pkts': current_flow['fwd_bytes'],
                            'totlen_bwd_pkts': current_flow['bwd_bytes'],
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
                            'fin_flag_cnt': fin_flag_cnt,
                            'syn_flag_cnt': current_flow['syn_flag_cnt'],
                            'rst_flag_cnt': rst_flag_cnt,
                            'psh_flag_cnt': current_flow['psh_flag_cnt'],
                            'ack_flag_cnt': current_flow['ack_flag_cnt']
                        })
                # Bắt đầu flow mới
                current_flow = {'key': flow_key, 'src_ip': src_ip, 'dst_ip': dst_ip, 'total_packets': 0, 
                              'total_bytes': 0, 'fwd_pkts': 0, 'bwd_pkts': 0, 'fwd_bytes': 0, 'bwd_bytes': 0,
                              'syn_flag_cnt': 0, 'fin_flag_cnt': 0, 'rst_flag_cnt': 0, 'psh_flag_cnt': 0, 'ack_flag_cnt': 0,
                              'total_iat': 0, 'iat_values': [], 'fwd_iat_values': [], 'bwd_iat_values': [], 'last_time': timestamp}
                flow_start_time = timestamp
            
            current_flow['total_packets'] += 1
            current_flow['total_bytes'] += len(pkt)
            if TCP in pkt:
                if pkt[TCP].flags.S:
                    current_flow['syn_flag_cnt'] += 1
                if pkt[TCP].flags.F:
                    current_flow['fin_flag_cnt'] += 1
                if pkt[TCP].flags.R:
                    current_flow['rst_flag_cnt'] += 1
                if pkt[TCP].flags.P:
                    current_flow['psh_flag_cnt'] += 1
                if pkt[TCP].flags.A:
                    current_flow['ack_flag_cnt'] += 1
            if UDP in pkt or ICMP in pkt:
                # Với UDP/ICMP, không có flag, nhưng vẫn đếm gói
                pass
            if src_ip == current_flow['src_ip']:
                current_flow['fwd_pkts'] += 1
                current_flow['fwd_bytes'] += len(pkt)
            else:
                current_flow['bwd_pkts'] += 1
                current_flow['bwd_bytes'] += len(pkt)
            if current_flow['total_packets'] > 1:
                iat = timestamp - current_flow['last_time']
                current_flow['total_iat'] += iat
                current_flow['iat_values'].append(iat)
                if src_ip == current_flow['src_ip']:
                    current_flow['fwd_iat_values'].append(iat)
                else:
                    current_flow['bwd_iat_values'].append(iat)
            current_flow['last_time'] = timestamp
    
    # Kết thúc flow cuối cùng
    if current_flow and flow_start_time is not None and timestamp is not None:
        flow_duration = timestamp - flow_start_time
        if flow_duration > 0:
            flow_byts_s = current_flow['total_bytes'] / flow_duration
            flow_pkts_s = current_flow['total_packets'] / flow_duration
            flow_iat_mean = current_flow['total_iat'] / (current_flow['total_packets'] - 1) if current_flow['total_packets'] > 1 else 0
            flow_iat_max = max(current_flow['iat_values']) if current_flow['iat_values'] else 0
            flow_iat_min = min(current_flow['iat_values']) if current_flow['iat_values'] else 0
            flow_iat_std = np.std(current_flow['iat_values']) if len(current_flow['iat_values']) > 1 else 0
            fwd_iat_tot = sum(current_flow['fwd_iat_values'])
            fwd_iat_max = max(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0
            fwd_iat_min = min(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0
            fwd_iat_mean = np.mean(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0
            fwd_iat_std = np.std(current_flow['fwd_iat_values']) if len(current_flow['fwd_iat_values']) > 1 else 0
            bwd_iat_tot = sum(current_flow['bwd_iat_values'])
            bwd_iat_max = max(current_flow['bwd_iat_values']) if current_flow['bwd_iat_values'] else 0
            bwd_iat_min = min(current_flow['bwd_iat_values']) if current_flow['bwd_iat_values'] else 0
            bwd_iat_mean = np.mean(current_flow['bwd_iat_values']) if current_flow['bwd_iat_values'] else 0
            bwd_iat_std = np.std(current_flow['bwd_iat_values']) if len(current_flow['bwd_iat_values']) > 1 else 0
            fin_flag_cnt = current_flow['fin_flag_cnt']
            rst_flag_cnt = current_flow['rst_flag_cnt']

            flows.append({
                'src_ip': current_flow['src_ip'],
                'dst_ip': current_flow['dst_ip'],
                'timestamp': datetime.fromtimestamp(flow_start_time).strftime('%Y-%m-%d %H:%M:%S'),
                'flow_duration': flow_duration,
                'tot_fwd_pkts': current_flow['fwd_pkts'],
                'tot_bwd_pkts': current_flow['bwd_pkts'],
                'totlen_fwd_pkts': current_flow['fwd_bytes'],
                'totlen_bwd_pkts': current_flow['bwd_bytes'],
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
                'fin_flag_cnt': fin_flag_cnt,
                'syn_flag_cnt': current_flow['syn_flag_cnt'],
                'rst_flag_cnt': rst_flag_cnt,
                'psh_flag_cnt': current_flow['psh_flag_cnt'],
                'ack_flag_cnt': current_flow['ack_flag_cnt']
            })

    # Lưu thành CSV
    df = pd.DataFrame(flows)
    # Điền giá trị mặc định cho các cột còn thiếu (nếu có)
    for col in ['flow_iat_mean', 'flow_iat_max', 'flow_iat_min', 'flow_iat_std', 'fwd_iat_tot', 
                'fwd_iat_max', 'fwd_iat_min', 'fwd_iat_mean', 'fwd_iat_std', 'bwd_iat_tot', 
                'bwd_iat_max', 'bwd_iat_min', 'bwd_iat_mean', 'bwd_iat_std', 'fin_flag_cnt', 
                'syn_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt']:
        if col not in df.columns:
            df[col] = 0
    df.to_csv(csv_path, index=False)
    print(f"Processed PCAP to CSV: {csv_path}")

# Ví dụ gọi hàm
if __name__ == "__main__":
    process_pcap("/path/to/attack.pcap", "/path/to/output.csv")