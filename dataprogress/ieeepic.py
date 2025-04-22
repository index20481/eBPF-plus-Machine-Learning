import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# IEEE 格式预设
plt.rcParams.update({
    'font.family': 'Times New Roman',  # IEEE推荐字体
    'font.size': 8,                   # 正文字号8-10pt
    'axes.labelsize': 9,              # 轴标签稍大
    'axes.titlesize': 9,
    'axes.linewidth': 0.5,            # 坐标轴线宽
    'lines.linewidth': 1,             # 图形线宽
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 8,
    'figure.dpi': 600                 # 输出分辨率
})

# 读取数据
csv_path = r'D:\Programs\feature1_accuracies.csv'
results_df = pd.read_csv(csv_path).sort_values('Accuracy', ascending=False)

feature_abbreviations = {
    # 原始特征列表
    'Average Packet Size': 'APS',
    'Fwd Packet Length Mean': 'FPLM',
    'Avg Fwd Segment Size': 'AFSS',
    'Packet Length Mean': 'PLM',
    'Fwd Packet Length Min': 'FPLMn',
    'Max Packet Length': 'MxPL',
    'Fwd Packet Length Max': 'FPLMx',
    'Min Packet Length': 'MiPL',
    'Total Length of Fwd Packets': 'TLoFP',
    'Subflow Fwd Bytes': 'SFB',
    'Flow Bytes/s': 'FBs',
    'Source Port': 'SP',
    'Fwd Header Length': 'FHL',
    'Fwd Header Length.1': 'FHL1',
    'Init_Win_bytes_forward': 'IWBF',
    'Flow IAT Max': 'FIATx',
    'Flow IAT Mean': 'FIATM',
    'Flow Packets/s': 'FPs',
    'Flow Duration': 'FDur',
    'Fwd Packets/s': 'FwdPs',
    'min_seg_size_forward': 'mSSF',
    'Flow IAT Std': 'FIATS',
    'Protocol': 'Proto',
    'ACK Flag Count': 'AFC',
    'Fwd IAT Max': 'FIATx',
    'Fwd IAT Mean': 'FIATm',
    'Fwd IAT Total': 'FIATt',
    'Packet Length Std': 'PLs',
    'Packet Length Variance': 'PLv',
    'act_data_pkt_fwd': 'ADPF',
    'Bwd Packets/s': 'BPs',
    'Total Fwd Packets': 'TFP',
    'Subflow Fwd Packets': 'SFP',
    'Total Length of Bwd Packets': 'TLoBP',
    'Subflow Bwd Bytes': 'SBB',
    'Fwd Packet Length Std': 'FPLs',
    'Bwd Packet Length Max': 'BPLx',
    'Bwd Packet Length Mean': 'BPLm',
    'Avg Bwd Segment Size': 'ABSS',
    'Fwd IAT Std': 'FIATs',
    'Init_Win_bytes_backward': 'IWBB',
    'Bwd Header Length': 'BHL',
    'Bwd IAT Max': 'BIATx',
    'Bwd IAT Total': 'BIATt',
    'Bwd Packet Length Min': 'BPLn',
    'Bwd IAT Mean': 'BIATm',
    'Total Backward Packets': 'TBP',
    'Subflow Bwd Packets': 'SBP',
    'Bwd IAT Min': 'BIATn',
    'Inbound': 'InBnd',
    'Destination Port': 'DP',
    'Flow IAT Min': 'FIATn',
    'Down/Up Ratio': 'DUR',
    'Fwd IAT Min': 'FwdIATn',
    'URG Flag Count': 'UFC',
    'CWE Flag Count': 'CWE',
    'Bwd Packet Length Std': 'BPLs',
    'Active Min': 'ActMn',
    'Fwd PSH Flags': 'FPSH',
    'RST Flag Count': 'RFC',
    'Idle Max': 'IdlMx',
    'Idle Mean': 'IdlMn',
    'Bwd IAT Std': 'BIATs',
    'Active Max': 'ActMx',
    'Active Mean': 'ActMn',
    'Idle Min': 'IdlMn',
    'Idle Std': 'IdlSd',
    'Active Std': 'ActSd',
    'SYN Flag Count': 'SYN',
    'Bwd PSH Flags': 'BPSH',
    'Fwd URG Flags': 'FURG',
    'Bwd URG Flags': 'BURG',
    'FIN Flag Count': 'FIN',
    'PSH Flag Count': 'PSH',
    'ECE Flag Count': 'ECE',
    'Fwd Avg Bytes/Bulk': 'FABB',
    'Fwd Avg Packets/Bulk': 'FAPB',
    'Fwd Avg Bulk Rate': 'FABR',
    'Bwd Avg Bytes/Bulk': 'BABB',
    'Bwd Avg Packets/Bulk': 'BAPB',
    'Bwd Avg Bulk Rate': 'BABR'
}
# 处理特征名称
def format_feature(feature_str):
    features = feature_str.split(', ')  # 根据实际分隔符调整
    last_feature = features[-1].strip()
    
    # 优先使用预定义的缩写
    if last_feature in feature_abbreviations:
        return feature_abbreviations[last_feature]
    
    # 自动生成首字母缩写（备选方案）
    words = last_feature.split()
    return ''.join([word[0].upper() for word in words])
    # return f"{features[-1].strip()}"

results_df = results_df.head(5)

results_df['DisplayName'] = results_df['Feature'].apply(format_feature)

# 动态计算x轴范围
def calculate_xlim(accuracies):
    min_acc = np.min(accuracies)
    max_acc = np.max(accuracies)
    range_acc = max_acc - min_acc
    
    # 根据数据分布动态调整显示范围
    if range_acc < 0.2:  # 数据集中时放大差异
        lower = max(0, min_acc - range_acc*0.3)
        upper = min(1, max_acc + range_acc*0.3)
    else:  # 数据分散时完整显示
        lower = 0
        upper = 1
    return lower, upper

x_min, x_max = calculate_xlim(results_df['Accuracy'])

# 创建画布（适应双栏排版宽度）
plt.figure(figsize=(3.5, 2.5), constrained_layout=True)  # IEEE双栏宽度3.5英寸
plt.xlim(x_min, x_max)
# 绘制条形图
bars = plt.barh(
    results_df['DisplayName'][::-1],
    results_df['Accuracy'][::-1],
    color='#404040',        # 柱颜色
    edgecolor='black',    # 边框色
    linewidth=0.5,
)
# bars = plt.barh(..., color='#404040', edgecolor='black', linewidth=0.5)

# 优化坐标轴
ax = plt.gca()
ax.spines['top'].set_visible(False)    # 移除顶部边框
ax.spines['right'].set_visible(False)  # 移除右侧边框

# 设置y轴细体字
for label in ax.get_yticklabels():
    label.set_fontweight('light')
    label.set_fontvariant('small-caps')  # 增强可读性

# 数据标签调整
for bar in bars:
    width = bar.get_width()
    plt.text(
        width * 0.9999999,  
        bar.get_y() + bar.get_height()/2,
        f'{width:.6f}',
        va='center',
        ha='right',  # 右对齐
        color='white',
        fontsize=7,
        fontweight='light'
        )

# 网格线优化
plt.grid(axis='x', linestyle='--', linewidth=0.5, alpha=0.6, color='gray')

plt.margins(y=0)  # 移除y轴方向的边距
plt.gca().set_ylim(-0.5, len(results_df)-0.5)  # 精确设置y轴范围

# 保存为TIFF格式（IEEE推荐）
plt.savefig(
    r'D:\resultpic\ieee\5_1.tiff',
    dpi=600,
    bbox_inches='tight',
    facecolor='white',
    format='tiff',
    pil_kwargs={"compression": "tiff_lzw"}
)