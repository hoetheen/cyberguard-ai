import streamlit as st
import pandas as pd
df = pd.read_csv("../data/cybersecurity_cleaned.csv")
st.title("CyberGuard AI Dashboard")
st.write("""
# Sales model
""")




# streamlit run streamlit_dashboard/app.py