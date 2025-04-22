import pandas as pd

data_path = '/home/zze/project/ebpfml/dataset/combined_data_customdf.csv'

df = pd.read_csv(data_path)
print(df.columns)
print(df.head())
print(df.columns)
print(df[' Label'].value_counts())
print(df.dtypes)# 查找数据类型

# 筛选出非数值列
non_numeric_columns = df.select_dtypes(include=['object']).columns
print("非数值列:", non_numeric_columns)