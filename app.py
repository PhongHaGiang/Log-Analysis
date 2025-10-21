import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from utils import parse_log_to_df, detect_bruteforce_windows

st.set_page_config(page_title="Login Analyzer", layout="wide")

st.title("Login Analyzer — Phát hiện brute-force & hành vi bất thường")
st.caption("Upload file log (auth.log, access.log, .txt). Ứng dụng hỗ trợ mẫu auth.log/SSH và access log cơ bản.")

uploaded_file = st.file_uploader("Chọn file log (text)", type=["log","txt"])

st.sidebar.header("Cấu hình phân tích")
window_minutes = st.sidebar.number_input("Window (phút) để tính brute-force", min_value=1, max_value=60, value=5)
threshold = st.sidebar.number_input("Ngưỡng số lần thất bại trong window để cảnh báo", min_value=1, max_value=1000, value=10)

if uploaded_file is not None:
    raw = uploaded_file.read().decode("utf-8", errors="ignore")
    st.subheader("Preview (10 dòng đầu)")
    st.code("\n".join(raw.splitlines()[:10]))

    df = parse_log_to_df(raw)

    if df.empty:
        st.warning("Không tìm thấy bản ghi hợp lệ trong file.")
    else:
        st.success(f"Đã parse được {len(df)} bản ghi.")

        counts = df['status'].value_counts().rename_axis('status').reset_index(name='counts')
        st.markdown("### Thống kê chung")
        st.table(counts)

        fail_df = df[df['status']=='FAIL']
        top_fail = fail_df.groupby('ip').size().sort_values(ascending=False).head(10).reset_index(name='fail_count')
        st.markdown("### Top IPs có nhiều login thất bại")
        st.table(top_fail)

        suspicious = detect_bruteforce_windows(fail_df, window_minutes=window_minutes, threshold=threshold)
        st.markdown("### IP nghi ngờ (brute-force windows)")
        if suspicious:
            st.table(pd.DataFrame(suspicious))
        else:
            st.info("Không phát hiện IP vượt ngưỡng.")

        ts = fail_df.set_index('timestamp').resample('1T').size()
        st.markdown("### Số lần login thất bại theo thời gian")
        fig, ax = plt.subplots(figsize=(10,3))
        ax.plot(ts.index, ts.values)
        ax.set_xlabel('Time')
        ax.set_ylabel('Failed attempts per minute')
        ax.set_title('Failed logins over time')
        st.pyplot(fig)
else:
    st.info("Upload file log để bắt đầu phân tích.")
