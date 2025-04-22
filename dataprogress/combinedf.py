import os
import pandas as pd

# 创建保存目录
save_dir = r'/home/mpuc/henry/SVM_train/03-11'
os.makedirs(save_dir, exist_ok=True)

# 文件路径列表
file_paths = [
    '/home/mpuc/henry/SVM_train/03-11/UDP.csv',
    '/home/mpuc/henry/SVM_train/03-11/Syn.csv',
    '/home/mpuc/henry/SVM_train/03-11/MSSQL.csv',
    '/home/mpuc/henry/SVM_train/03-11/LDAP.csv',
    '/home/mpuc/henry/SVM_train/03-11/NetBIOS.csv'
]

# 读取并合并CSV文件
df_list = []
for file_path in file_paths:
    df = pd.read_csv(file_path)
    df_list.append(df)
df = pd.concat(df_list, ignore_index=True)

# 删除不需要的列
df = df.drop(['Flow ID', ' Source IP', ' Destination IP', ' Timestamp', 'SimillarHTTP'], axis=1)

# 定义每个类别要抽取的样本数量
sample_dict = {
    'LDAP': 170000,
    'NetBIOS': 170000,
    'BENIGN': 170000,
    'MSSQL': 170000,
    'Syn': 170000,
    'UDP': 170000
}

# 筛选感兴趣的标签（自动匹配sample_dict中的键）
selected_labels = list(sample_dict.keys())
df_selected = df[df[' Label'].isin(selected_labels)]

# 对每个类别按指定数量抽样，自动处理样本不足的情况
samples = []
for label, n_sample in sample_dict.items():
    df_label = df_selected[df_selected[' Label'] == label]
    # 如果当前类别的样本数量不足，则抽取全部
    n_sample_adj = min(n_sample, len(df_label))
    if n_sample_adj < n_sample:
        print(f"注意: 类别 {label} 仅包含 {len(df_label)} 个样本，将全部抽取。")
    samples.append(df_label.sample(n=n_sample_adj, random_state=42))

df_samples = pd.concat(samples).reset_index(drop=True)

# 保存抽样后的数据到新的CSV文件
output_file = os.path.join(save_dir, 'combined_data_customdf1.csv')
df_samples.to_csv(output_file, index=False)

print(f"抽样后的数据已保存到 {output_file}")
print("各类别抽样数量统计:")
print(df_samples[' Label'].value_counts())