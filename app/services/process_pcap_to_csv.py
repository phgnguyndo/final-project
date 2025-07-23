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
            protocol = pkt[IP].proto
            timestamp = float(pkt.time)
            flow_key = (src_ip, dst_ip, protocol)  # Nhận diện flow bằng cặp IP và giao thức
            
            if current_flow is None or current_flow['key'] != flow_key:
                if current_flow and flow_start_time is not None:
                    # Kết thúc flow trước
                    flow_duration = timestamp - flow_start_time
                    if flow_duration > 0 and current_flow['total_packets'] >= 2:  # Chỉ lưu flow có ít nhất 2 packets
                        flow_byts_s = current_flow['total_bytes'] / flow_duration if flow_duration > 0 else 0
                        flow_pkts_s = current_flow['total_packets'] / flow_duration if flow_duration > 0 else 0
                        flow_iat_mean = np.mean(current_flow['iat_values']) if current_flow['iat_values'] else 0
                        flow_iat_max = max(current_flow['iat_values']) if current_flow['iat_values'] else 0
                        fwd_iat_tot = sum(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0
                        fwd_iat_max = max(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0

                        # Tính pkt_len stats (bây giờ đã lưu lengths)
                        fwd_pkt_len_max = max(current_flow['fwd_pkt_lengths']) if current_flow['fwd_pkt_lengths'] else 0
                        fwd_pkt_len_min = min(current_flow['fwd_pkt_lengths']) if current_flow['fwd_pkt_lengths'] else 0
                        fwd_pkt_len_mean = np.mean(current_flow['fwd_pkt_lengths']) if current_flow['fwd_pkt_lengths'] else 0
                        bwd_pkt_len_max = max(current_flow['bwd_pkt_lengths']) if current_flow['bwd_pkt_lengths'] else 0
                        bwd_pkt_len_min = min(current_flow['bwd_pkt_lengths']) if current_flow['bwd_pkt_lengths'] else 0
                        bwd_pkt_len_mean = np.mean(current_flow['bwd_pkt_lengths']) if current_flow['bwd_pkt_lengths'] else 0

                        flows.append({
                            'src_ip': current_flow['src_ip'],  # Logging
                            'dst_ip': current_flow['dst_ip'],  # Logging
                            'timestamp': datetime.fromtimestamp(flow_start_time).strftime('%Y-%m-%d %H:%M:%S'),  # Logging
                            'flow_duration': flow_duration,
                            'tot_fwd_pkts': current_flow['fwd_pkts'],
                            'tot_bwd_pkts': current_flow['bwd_pkts'],
                            'totlen_fwd_pkts': current_flow['fwd_bytes'],
                            'totlen_bwd_pkts': current_flow['bwd_bytes'],
                            'fwd_pkt_len_max': fwd_pkt_len_max,
                            'fwd_pkt_len_min': fwd_pkt_len_min,
                            'fwd_pkt_len_mean': fwd_pkt_len_mean,
                            'bwd_pkt_len_max': bwd_pkt_len_max,
                            'bwd_pkt_len_min': bwd_pkt_len_min,
                            'bwd_pkt_len_mean': bwd_pkt_len_mean,
                            'flow_byts_s': flow_byts_s,
                            'flow_pkts_s': flow_pkts_s,
                            'flow_iat_mean': flow_iat_mean,
                            'flow_iat_max': flow_iat_max,
                            'fwd_iat_tot': fwd_iat_tot,
                            'fwd_iat_max': fwd_iat_max,
                            'fin_flag_cnt': current_flow['fin_flag_cnt'],
                            'syn_flag_cnt': current_flow['syn_flag_cnt'],
                            'rst_flag_cnt': current_flow['rst_flag_cnt'],
                            'protocol': current_flow['protocol'],
                            'src_port': current_flow['src_port'],
                            'dst_port': current_flow['dst_port']
                        })
                # Bắt đầu flow mới
                current_flow = {
                    'key': flow_key, 
                    'src_ip': src_ip, 
                    'dst_ip': dst_ip, 
                    'protocol': protocol,
                    'src_port': 0,  # Sẽ cập nhật sau
                    'dst_port': 0,  # Sẽ cập nhật sau
                    'total_packets': 0, 
                    'total_bytes': 0, 
                    'fwd_pkts': 0, 
                    'bwd_pkts': 0, 
                    'fwd_bytes': 0, 
                    'bwd_bytes': 0,
                    'fwd_pkt_lengths': [],  # Thêm để tính max/min/mean
                    'bwd_pkt_lengths': [],  # Thêm
                    'syn_flag_cnt': 0, 
                    'fin_flag_cnt': 0, 
                    'rst_flag_cnt': 0,
                    'iat_values': [], 
                    'fwd_iat_values': [], 
                    'bwd_iat_values': [], 
                    'last_time': timestamp
                }
                flow_start_time = timestamp
            
            packet_size = len(pkt)
            current_flow['total_packets'] += 1
            current_flow['total_bytes'] += packet_size
            
            # Cập nhật ports (lấy từ packet đầu tiên của flow, hoặc cập nhật nếu thay đổi)
            if TCP in pkt:
                current_flow['src_port'] = pkt[TCP].sport
                current_flow['dst_port'] = pkt[TCP].dport
                if pkt[TCP].flags & 0x02:  # SYN
                    current_flow['syn_flag_cnt'] += 1
                if pkt[TCP].flags & 0x01:  # FIN
                    current_flow['fin_flag_cnt'] += 1
                if pkt[TCP].flags & 0x04:  # RST
                    current_flow['rst_flag_cnt'] += 1
            elif UDP in pkt:
                current_flow['src_port'] = pkt[UDP].sport
                current_flow['dst_port'] = pkt[UDP].dport
            elif ICMP in pkt:
                current_flow['src_port'] = 0
                current_flow['dst_port'] = 0
            
            # Phân biệt fwd/bwd
            if src_ip == current_flow['src_ip']:
                current_flow['fwd_pkts'] += 1
                current_flow['fwd_bytes'] += packet_size
                current_flow['fwd_pkt_lengths'].append(packet_size)
            else:
                current_flow['bwd_pkts'] += 1
                current_flow['bwd_bytes'] += packet_size
                current_flow['bwd_pkt_lengths'].append(packet_size)
            
            if current_flow['total_packets'] > 1:
                iat = timestamp - current_flow['last_time']
                current_flow['iat_values'].append(iat)
                if src_ip == current_flow['src_ip']:
                    current_flow['fwd_iat_values'].append(iat)
                else:
                    current_flow['bwd_iat_values'].append(iat)
            
            current_flow['last_time'] = timestamp
    
    # Kết thúc flow cuối cùng (tương tự)
    if current_flow and flow_start_time is not None and timestamp is not None:
        flow_duration = timestamp - flow_start_time
        if flow_duration > 0 and current_flow['total_packets'] >= 2:
            # Tính tương tự như trên
            flow_byts_s = current_flow['total_bytes'] / flow_duration if flow_duration > 0 else 0
            flow_pkts_s = current_flow['total_packets'] / flow_duration if flow_duration > 0 else 0
            flow_iat_mean = np.mean(current_flow['iat_values']) if current_flow['iat_values'] else 0
            flow_iat_max = max(current_flow['iat_values']) if current_flow['iat_values'] else 0
            fwd_iat_tot = sum(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0
            fwd_iat_max = max(current_flow['fwd_iat_values']) if current_flow['fwd_iat_values'] else 0

            fwd_pkt_len_max = max(current_flow['fwd_pkt_lengths']) if current_flow['fwd_pkt_lengths'] else 0
            fwd_pkt_len_min = min(current_flow['fwd_pkt_lengths']) if current_flow['fwd_pkt_lengths'] else 0
            fwd_pkt_len_mean = np.mean(current_flow['fwd_pkt_lengths']) if current_flow['fwd_pkt_lengths'] else 0
            bwd_pkt_len_max = max(current_flow['bwd_pkt_lengths']) if current_flow['bwd_pkt_lengths'] else 0
            bwd_pkt_len_min = min(current_flow['bwd_pkt_lengths']) if current_flow['bwd_pkt_lengths'] else 0
            bwd_pkt_len_mean = np.mean(current_flow['bwd_pkt_lengths']) if current_flow['bwd_pkt_lengths'] else 0

            flows.append({
                'src_ip': current_flow['src_ip'],
                'dst_ip': current_flow['dst_ip'],
                'timestamp': datetime.fromtimestamp(flow_start_time).strftime('%Y-%m-%d %H:%M:%S'),
                'flow_duration': flow_duration,
                'tot_fwd_pkts': current_flow['fwd_pkts'],
                'tot_bwd_pkts': current_flow['bwd_pkts'],
                'totlen_fwd_pkts': current_flow['fwd_bytes'],
                'totlen_bwd_pkts': current_flow['bwd_bytes'],
                'fwd_pkt_len_max': fwd_pkt_len_max,
                'fwd_pkt_len_min': fwd_pkt_len_min,
                'fwd_pkt_len_mean': fwd_pkt_len_mean,
                'bwd_pkt_len_max': bwd_pkt_len_max,
                'bwd_pkt_len_min': bwd_pkt_len_min,
                'bwd_pkt_len_mean': bwd_pkt_len_mean,
                'flow_byts_s': flow_byts_s,
                'flow_pkts_s': flow_pkts_s,
                'flow_iat_mean': flow_iat_mean,
                'flow_iat_max': flow_iat_max,
                'fwd_iat_tot': fwd_iat_tot,
                'fwd_iat_max': fwd_iat_max,
                'fin_flag_cnt': current_flow['fin_flag_cnt'],
                'syn_flag_cnt': current_flow['syn_flag_cnt'],
                'rst_flag_cnt': current_flow['rst_flag_cnt'],
                'protocol': current_flow['protocol'],
                'src_port': current_flow['src_port'],
                'dst_port': current_flow['dst_port']
            })

    # Lưu thành CSV
    df = pd.DataFrame(flows)
    df = df.replace([np.inf, -np.inf], 0).fillna(0)
    df.to_csv(csv_path, index=False)
    print(f"Processed PCAP to CSV: {csv_path}")

# Ví dụ gọi hàm
if __name__ == "__main__":
    process_pcap("/path/to/attack.pcap", "/path/to/output.csv")