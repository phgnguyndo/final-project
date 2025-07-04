from scapy.all import rdpcap, wrpcap

packets = rdpcap("attk2.pcap", count=10000)  # Đọc 10.000 gói đầu
wrpcap("chunk_0.pcap", packets)              # Ghi ra file mới
