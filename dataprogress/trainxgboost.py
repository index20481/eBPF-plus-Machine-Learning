import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier
import joblib
import os
import numpy as np


# save_dir = r'/home/zze/project/ebpfml/model' 
# os.makedirs(save_dir, exist_ok=True) 
data_path = 'D:\project\combined_data_customdf.csv'

# load

df = pd.read_csv(data_path) 
df = df.dropna()
features = [' Flow Duration',
    ' Flow Packets/s', 
    'Flow Bytes/s', 
    ' Avg Fwd Segment Size',
    ' Fwd Packet Length Max',
    ' Source Port',
    'Init_Win_bytes_forward'
    ]


X = df[features]
y = df[' Label']

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)  # encode

X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(X.mean(), inplace=True)


X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42
)

# standard
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# train
model = XGBClassifier(use_label_encoder=False, eval_metric='logloss')
model.fit(X_train_scaled, y_train)

# # save
# model_path = os.path.join(save_dir, 'xgboost_model.pkl')
# joblib.dump(model, model_path)

# scaler_path = os.path.join(save_dir, 'scalerxg.pkl')
# encoder_path = os.path.join(save_dir, 'label_encoderxg.pkl')
# joblib.dump(scaler, scaler_path)
# joblib.dump(label_encoder, encoder_path)

# result
y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)
print(f"测试集准确率: {accuracy:.8f}")
print("分类报告:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))