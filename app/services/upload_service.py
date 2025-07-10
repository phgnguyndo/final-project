# app/services/upload_service.py
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
from .process_pcap_to_csv import process_pcap

class UploadService:
    def __init__(self):
        self.repository = UploadRepository()
        # Load model và scaler đã huấn luyện
        self.model = load_model(os.path.join('models', 'lstm_ae_be_model.h5'), 
                              custom_objects={'mse': MeanSquaredError()}, compile=False)
        with open(os.path.join('models', 'scaler_be.pkl'), 'rb') as f:
            self.scaler = pickle.load(f)
        # Định nghĩa cột từ huấn luyện (Colab), khớp với CSV từ script mới
        self.train_columns = [
            'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'totlen_fwd_pkts', 'totlen_bwd_pkts',
            'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean', 'bwd_pkt_len_max', 'bwd_pkt_len_min',
            'bwd_pkt_len_mean', 'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 'flow_iat_max',
            'fwd_iat_tot', 'fwd_iat_max', 'fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt'
        ]
        self.window_size = 10
        self.n_features = len(self.train_columns)

    def process_pcap(self, file, filename):
        if file.content_length > Config.MAX_UPLOAD_SIZE:
            raise ValueError("File size exceeds limit")
        
        pcap_path = self.repository.save_file(file, filename, Config.UPLOAD_DIR)
        
        csv_filename = f"{os.path.splitext(filename)[0]}.csv"
        csv_path = os.path.join(Config.CSV_OUTPUT_DIR, csv_filename)
        
        os.makedirs(Config.CSV_OUTPUT_DIR, exist_ok=True)
        
        # Gọi script để xử lý PCAP thành CSV
        process_pcap(pcap_path, csv_path)
        
        # Dự đoán từ CSV
        df = pd.read_csv(csv_path)
        # Đảm bảo tất cả cột cần thiết có mặt, điền giá trị mặc định nếu thiếu
        for col in self.train_columns:
            if col not in df.columns:
                df[col] = 0
        df_processed = df[self.train_columns].copy()
        for col in self.train_columns:
            df_processed.loc[:, col] = df_processed[col].replace([np.inf, -np.inf], np.nan)
            df_processed.loc[:, col] = df_processed[col].fillna(df_processed[col].max() if not np.isnan(df_processed[col].max()) else 0)
        df_processed = df_processed.dropna()

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
        
        # Ngưỡng động dựa trên percentile 95%
        threshold = 0.004
        y_pred = (mse > threshold).astype(int)

        normal_percentage = (np.sum(y_pred == 0) / len(y_pred)) * 100
        abnormal_percentage = (np.sum(y_pred == 1) / len(y_pred)) * 100

        print(f"MSE values: {mse}")
        print(f"Mean MSE: {mean_mse}, Std MSE: {std_mse}, Max MSE: {max_mse}, Threshold: {threshold}")

        if abnormal_percentage > 90 or (max_mse > 0.0005 and abnormal_percentage > 20):
            prediction = "Attack detected"
        elif normal_percentage > 95:
            prediction = "No attack detected"
        else:
            prediction = "Uncertain"

        return {
            "pcap_path": pcap_path,
            "csv_path": csv_path,
            "prediction": prediction,
            "mse_threshold": threshold,
            "mse_values": mse.tolist(),
            "normal_percentage": normal_percentage,
            "abnormal_percentage": abnormal_percentage,
            "max_mse": max_mse,
            "mean_mse": mean_mse
        }