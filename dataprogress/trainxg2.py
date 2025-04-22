import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
from joblib import Parallel, delayed


data_path = 'D:\project\combined_data_customdf.csv'
df = pd.read_csv(data_path)

df = df.drop(['Unnamed: 0'], axis=1)

features = df.columns.drop(' Label')
y = df[' Label']

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# conbine
best_feature_1 = ' Average Packet Size'
best_feature_2 = 'Init_Win_bytes_forward'
best_feature_3 = ' Source Port'
best_feature_4 = ' min_seg_size_forward'
best_feature_5 = ' Fwd Packet Length Mean'
best_feature_6 = 'Fwd Packets/s'
remaining_features = [feature for feature in features if feature not in [best_feature_1, best_feature_2, best_feature_3, best_feature_4, best_feature_5,best_feature_6]]
feature_combinations = [(best_feature_1, best_feature_2, best_feature_3, best_feature_4, best_feature_5,best_feature_6, feature) for feature in remaining_features]


def process_combination(features_comb, X_all, y_encoded):
    try:
        print(f"处理特征组合: {features_comb}")
        X = X_all[list(features_comb)].copy()
        
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(X.mean(skipna=True), inplace=True)
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_encoded, test_size=0.2, random_state=42
        )
        
        # XGBoost
        model = XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, verbosity=0)
        model.fit(X_train, y_train)
        
        # predit
        y_pred = model.predict(X_test)
        return (', '.join(features_comb), accuracy_score(y_test, y_pred))
    except Exception as e:
        print(f"feature combination [{', '.join(features_comb)}] err: {str(e)}")
        return (', '.join(features_comb), 0.0)

#parallel deal
accuracies = Parallel(n_jobs=8, verbose=10)(  
    delayed(process_combination)(comb, df, y_encoded) for comb in feature_combinations
)

#sort
sorted_acc = sorted(accuracies, key=lambda x: x[1], reverse=True)


results_df = pd.DataFrame(
    sorted_acc,
    columns=['Feature', 'Accuracy']
)
results_df['Accuracy'] = results_df['Accuracy'].round(8)

csv_path = r'D:\Programs\feature7_accuracies.csv'
results_df.to_csv(csv_path, index=False, float_format='%.8f')
print(f"\nsave to: {csv_path}")

# 可视化结果
plt.figure(figsize=(12, len(feature_combinations)*0.5))
plt.barh(
    [item[0] for item in sorted_acc],
    [item[1] for item in sorted_acc],
    color='mediumseagreen'
)
plt.xlabel('Accuracy')
plt.title('Feature Combination Accuracy Ranking')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig(r'D:\Programs\xgboost_feature_combination_accuracy_rank7.png', dpi=300)
plt.show()
