import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report
import numpy as np
import joblib
import os

save_dir = r'D:\project'
os.makedirs(save_dir, exist_ok=True) 
# data_path = 'D:\Programs\combined_1data45w.csv'
data_path = 'D:\project\combined_data_customdf.csv'



df = pd.read_csv(data_path)


# features = [' Flow Duration',
#     ' Flow Packets/s', 
#     'Flow Bytes/s', 
#     ' Avg Fwd Segment Size',
#     ' Fwd Packet Length Max',
#     ' Source Port',
#     'Init_Win_bytes_forward'
#     ]


X = df.drop(' Label', axis=1)
#X = df[features]
y = df[' Label']

label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(X.mean(), inplace=True)

scaler = StandardScaler()
X = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


models = [
    ('Support Vector Machine', SVC(kernel='rbf', C=1.0)),
    ('Random Forest', RandomForestClassifier(random_state=42)),
    ('Logistic Regression', LogisticRegression(multi_class='multinomial', solver='lbfgs', max_iter=1000)),
    ('Decision Tree', DecisionTreeClassifier(random_state=42)),
    ('K-Nearest Neighbors', KNeighborsClassifier()),
    ('XGBoost', XGBClassifier(use_label_encoder=False, eval_metric='mlogloss'))
]


for name, model in models:
    print(f"\nTraining {name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"{name} Accuracy: {accuracy:.8f}")
    print(f"Classification Report for {name}:\n{classification_report(y_test, y_pred, target_names=label_encoder.classes_)}")
    


