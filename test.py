import pandas as pd
import os

# Đường dẫn đến file CSV trong csv_outputs
csv_path = os.path.join('csv_outputs', 'file2.csv')  # Thay 'file1.csv' bằng tên file thực tế

# Đọc file CSV
df = pd.read_csv(csv_path)

# In danh sách các cột
print("Các cột trong file CSV:")
for column in df.columns:
    print(column)