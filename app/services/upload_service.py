import os
import subprocess
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import pickle
from tensorflow.keras.losses import MeanSquaredError
from ..repositories.upload_repository import UploadRepository
from ..config.settings import Config

class UploadService:
    def __init__(self):
        self.repository = UploadRepository()
        # Load model và scaler đã huấn luyện
        self.model = load_model(
            os.path.join('models', 'lstm_ae_retrain_add_column.h5'),
            custom_objects={'mse': MeanSquaredError()}, compile=False
        )
        with open(os.path.join('models', 'scaler_retrain_add_column.pkl'), 'rb') as f:
            self.scaler = pickle.load(f)
        # Định nghĩa cột từ huấn luyện, 29 cột khớp với mô hình mới
        self.train_columns = [
            'protocol', 'flow_duration', 'flow_byts_s', 'flow_pkts_s', 'fwd_pkts_s', 'bwd_pkts_s',
            'tot_fwd_pkts', 'tot_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_mean', 'fwd_pkt_len_std',
            'pkt_len_max', 'pkt_len_mean', 'pkt_len_std', 'flow_iat_mean', 'flow_iat_max', 'flow_iat_std',
            'fwd_iat_tot', 'bwd_iat_tot', 'syn_flag_cnt', 'ack_flag_cnt', 'fin_flag_cnt', 'rst_flag_cnt',
            'down_up_ratio', 'pkt_size_avg', 'init_fwd_win_byts', 'init_bwd_win_byts', 
            'subflow_fwd_pkts', 'subflow_bwd_pkts'
        ]
        self.window_size = 10
        self.n_features = len(self.train_columns)
        # Ngưỡng bất thường (80th percentile từ dữ liệu benign, sẽ được tính động trong process_pcap)
        self.mse_threshold = None

    def process_pcap(self, file, filename):
        if file.content_length > Config.MAX_UPLOAD_SIZE:
            raise ValueError("File size exceeds limit")
        
        pcap_path = self.repository.save_file(file, filename, Config.UPLOAD_DIR)
        
        csv_filename = f"{os.path.splitext(filename)[0]}.csv"
        csv_path = os.path.join(Config.CSV_OUTPUT_DIR, csv_filename)
        
        os.makedirs(Config.CSV_OUTPUT_DIR, exist_ok=True)
        
        # Gọi cicflowmeter CLI để xử lý PCAP thành CSV
        cmd = ['/home/phuong/Desktop/final-project/venv/bin/cicflowmeter', '-f', pcap_path, '-c', csv_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if result.returncode != 0:
            raise RuntimeError(f"CICFlowMeter failed: {result.stderr}")
        
        # Dự đoán từ CSV
        df = pd.read_csv(csv_path)
        # Đảm bảo tất cả cột cần thiết có mặt, điền giá trị mặc định nếu thiếu
        for col in self.train_columns:
            if col not in df.columns:
                df[col] = 0
        df_processed = df[self.train_columns].copy()
        df_processed = df_processed.replace([np.inf, -np.inf], 0).fillna(0)

        scaled_data = self.scaler.transform(df_processed)
        
        def create_sequences(data, window_size):
            X = []
            for i in range(len(data) - window_size + 1):
                X.append(data[i:i + window_size])
            return np.array(X)

        test_sequences = create_sequences(scaled_data, self.window_size)
        if test_sequences.shape[0] == 0:
            raise ValueError("Not enough data for sequence creation")
        X_test = test_sequences.reshape((test_sequences.shape[0], self.window_size, self.n_features))

        X_test_pred = self.model.predict(X_test, verbose=0)
        mse = np.mean(np.power(X_test - X_test_pred, 2), axis=(1, 2))
        mean_mse = np.mean(mse)
        std_mse = np.std(mse)
        max_mse = np.max(mse)
        
        # Tính ngưỡng động (80th percentile của MSE)
        self.mse_threshold = 0.01  # Giả định dữ liệu PCAP có phần lớn là benign
        
        y_pred = (mse > self.mse_threshold).astype(int)

        normal_percentage = (np.sum(y_pred == 0) / len(y_pred)) * 100 if len(y_pred) > 0 else 100
        abnormal_percentage = (np.sum(y_pred == 1) / len(y_pred)) * 100 if len(y_pred) > 0 else 0

        print(f"MSE values: {mse}")
        print(f"Mean MSE: {mean_mse}, Std MSE: {std_mse}, Max MSE: {max_mse}, Threshold: {self.mse_threshold}")

        # Logic prediction nhất quán với real-time (dựa trên abnormal_percentage)
        if abnormal_percentage >= 80:  # Khớp anomaly_threshold trong real-time
            prediction = "Attack detected"
        else:
            prediction = "No attack detected"

        return {
            "pcap_path": pcap_path,
            "csv_path": csv_path,
            "prediction": prediction,
            "mse_threshold": self.mse_threshold,
            "mse_values": mse.tolist(),
            "normal_percentage": normal_percentage,
            "abnormal_percentage": abnormal_percentage,
            "max_mse": max_mse,
            "mean_mse": mean_mse
        }