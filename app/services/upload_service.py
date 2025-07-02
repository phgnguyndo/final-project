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

class UploadService:
    def __init__(self):
        self.repository = UploadRepository()
        # Load model và scaler khi khởi tạo
        self.model = load_model(os.path.join('models', 'lstm_ae_model_new.h5'), 
                              custom_objects={'mse': MeanSquaredError()})
        with open(os.path.join('models', 'scaler_new.pkl'), 'rb') as f:
            self.scaler = pickle.load(f)
        # Định nghĩa cột từ huấn luyện (Colab) và ánh xạ sang CSV
        self.train_columns = [
            'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
            'Total Length of Fwd Packet', 'Total Length of Bwd Packet',
            'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Max',
            'Fwd IAT Total', 'Fwd IAT Max', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count'
        ]
        self.csv_columns = [
            'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts',
            'totlen_fwd_pkts', 'totlen_bwd_pkts',
            'fwd_pkt_len_max', 'fwd_pkt_len_min', 'fwd_pkt_len_mean',
            'bwd_pkt_len_max', 'bwd_pkt_len_min', 'bwd_pkt_len_mean',
            'flow_byts_s', 'flow_pkts_s', 'flow_iat_mean', 'flow_iat_max',
            'fwd_iat_tot', 'fwd_iat_max', 'fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt'
        ]
        self.column_mapping = dict(zip(self.csv_columns, self.train_columns))
        self.window_size = 10
        self.n_features = len(self.train_columns)

    def process_pcap(self, file, filename):
        if file.content_length > Config.MAX_UPLOAD_SIZE:
            raise ValueError("File size exceeds limit")
        
        pcap_path = self.repository.save_file(file, filename, Config.UPLOAD_DIR)
        
        csv_filename = f"{os.path.splitext(filename)[0]}.csv"
        csv_path = os.path.join(Config.CSV_OUTPUT_DIR, csv_filename)
        
        os.makedirs(Config.CSV_OUTPUT_DIR, exist_ok=True)
        
        cmd = ['cicflowmeter', '-f', pcap_path, '-c', csv_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            with open(csv_path, 'r') as f:
                content = f.read()
                if not content.strip():
                    raise RuntimeError(f"CSV empty. Debug: {result.stderr} | {result.stdout}")
            print(f"CSV content preview: {content[:200]}...")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"CICFlowMeter failed: {e.stderr}")
        
        # Dự đoán
        df = pd.read_csv(csv_path)
        # Ánh xạ cột từ CSV sang tên huấn luyện
        mapped_df = df.rename(columns=self.column_mapping)
        df_processed = mapped_df[self.train_columns]
        for col in self.train_columns:
            df_processed[col] = df_processed[col].replace([np.inf, -np.inf], np.nan)
            df_processed[col] = df_processed[col].fillna(df_processed[col].max() if not np.isnan(df_processed[col].max()) else 0)
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

        X_test_pred = self.model.predict(X_test)
        mse = np.mean(np.power(X_test - X_test_pred, 2), axis=(1, 2))
        mean_mse = np.mean(mse)
        std_mse = np.std(mse)
        max_mse = np.max(mse)
        
        # Tính ngưỡng ban đầu
        initial_threshold = max(0.00001, mean_mse + 0.1 * std_mse)
        initial_y_pred = (mse > initial_threshold).astype(int)
        initial_abnormal_percentage = (np.sum(initial_y_pred == 1) / len(initial_y_pred)) * 100

        # Ngưỡng động với điều chỉnh dựa trên abnormal_percentage ban đầu
        adjustment = 0.3 if initial_abnormal_percentage > 50 else 1.0  # Giảm ngưỡng nếu abnormal_percentage cao
        threshold = max(0.00001, 0.4 * mean_mse + 1 * std_mse)
        y_pred = (mse > threshold).astype(int)

        # Tinh chỉnh logic dự đoán
        normal_percentage = (np.sum(y_pred == 0) / len(y_pred)) * 100
        abnormal_percentage = (np.sum(y_pred == 1) / len(y_pred)) * 100

        # # Log mse để debug
        # print(f"MSE values: {mse}")
        # print(f"Mean MSE: {mean_mse}, Std MSE: {std_mse}, Max MSE: {max_mse}, Threshold: {threshold}")

        if abnormal_percentage > 40:  # Ưu tiên max_mse cao và abnormal_percentage đáng kể
            prediction = "Attack detected"
        elif normal_percentage > 90:
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