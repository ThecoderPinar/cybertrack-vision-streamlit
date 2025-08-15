import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import matplotlib.pyplot as plt
import seaborn as sns
import folium
from streamlit_folium import st_folium
from datetime import datetime, timedelta
import pytz
from collections import Counter
import re
from wordcloud import WordCloud
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# Sayfa konfigürasyonu
st.set_page_config(
    page_title="🛡️ CyberTrack Vision - Siber Güvenlik Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS stilleri - Cybersecurity Dark Theme
st.markdown("""
<style>
/* Ana arkaplan ve konteynerler */
.main > div {
    padding-top: 2rem;
    background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
}

/* Sidebar styling - Advanced Cybersecurity */
.css-1d391kg {
    background: linear-gradient(180deg, #000000 0%, #0a0a0a 50%, #1a1a1a 100%);
    border-right: 3px solid #00ff41;
    box-shadow: 5px 0 25px rgba(0, 255, 65, 0.4);
    position: relative;
}

.css-1d391kg::before {
    content: '';
    position: absolute;
    top: 0;
    right: 0;
    width: 3px;
    height: 100%;
    background: linear-gradient(180deg, #00ff41 0%, #ff6600 50%, #ff0040 100%);
    animation: pulse 2s ease-in-out infinite;
}

/* Sidebar navigation items - Professional */
.css-17lntkn, .css-1l02zno, .css-1v0mbdj {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%) !important;
    border: 1px solid rgba(0, 255, 65, 0.3) !important;
    border-radius: 10px !important;
    margin: 8px 0 !important;
    padding: 15px !important;
    transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94) !important;
    position: relative !important;
    overflow: hidden !important;
    backdrop-filter: blur(5px) !important;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3) !important;
}

.css-17lntkn::before, .css-1l02zno::before, .css-1v0mbdj::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.2), transparent);
    transition: left 0.6s;
}

.css-17lntkn:hover::before, .css-1l02zno:hover::before, .css-1v0mbdj:hover::before {
    left: 100%;
}

.css-17lntkn:hover, .css-1l02zno:hover, .css-1v0mbdj:hover {
    background: linear-gradient(135deg, #00ff41 0%, #00cc33 100%) !important;
    border: 1px solid #ffffff !important;
    transform: translateX(8px) scale(1.02) !important;
    box-shadow: 0 8px 25px rgba(0, 255, 65, 0.6) !important;
}

.css-17lntkn:hover::after, .css-1l02zno:hover::after, .css-1v0mbdj:hover::after {
    content: '→';
    position: absolute;
    right: 15px;
    top: 50%;
    transform: translateY(-50%);
    color: #000000;
    font-weight: bold;
    font-size: 16px;
    animation: arrow-bounce 1s infinite;
}

/* Active state indicators */
.css-17lntkn[aria-selected="true"], .css-1l02zno[aria-selected="true"], .css-1v0mbdj[aria-selected="true"] {
    background: linear-gradient(135deg, #00ff41 0%, #00cc33 100%) !important;
    border: 2px solid #ffffff !important;
    box-shadow: 0 0 30px rgba(0, 255, 65, 0.8) !important;
    animation: active-glow 2s ease-in-out infinite alternate !important;
    transform: translateX(5px) !important;
}

/* Sidebar text styling - Enhanced */
.css-1d391kg p, .css-1d391kg div, .css-1d391kg span {
    color: #00ff41 !important;
    font-family: 'Courier New', monospace !important;
    font-weight: 600 !important;
    text-shadow: 0 0 8px rgba(0, 255, 65, 0.6) !important;
    transition: all 0.3s ease !important;
}

.css-17lntkn:hover p, .css-1l02zno:hover p, .css-1v0mbdj:hover p,
.css-17lntkn:hover div, .css-1l02zno:hover div, .css-1v0mbdj:hover div,
.css-17lntkn:hover span, .css-1l02zno:hover span, .css-1v0mbdj:hover span {
    color: #000000 !important;
    text-shadow: none !important;
    font-weight: 700 !important;
    letter-spacing: 0.5px !important;
}

/* Sidebar headers */
.css-1d391kg h1, .css-1d391kg h2, .css-1d391kg h3 {
    color: #00ff41 !important;
    text-shadow: 0 0 15px rgba(0, 255, 65, 0.8) !important;
    border-bottom: 2px solid #333 !important;
    padding-bottom: 10px !important;
    margin-bottom: 20px !important;
    font-family: 'Courier New', monospace !important;
    text-transform: uppercase !important;
    letter-spacing: 2px !important;
}

/* Filter widgets styling */
.css-1d391kg .stSelectbox, .css-1d391kg .stMultiSelect, .css-1d391kg .stDateInput {
    background: rgba(26, 26, 26, 0.8) !important;
    border: 1px solid #00ff41 !important;
    border-radius: 8px !important;
    margin: 10px 0 !important;
}

.css-1d391kg label {
    color: #00ff41 !important;
    font-family: 'Courier New', monospace !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
    text-shadow: 0 0 5px rgba(0, 255, 65, 0.5) !important;
}

/* Sidebar scrollbar */
.css-1d391kg::-webkit-scrollbar {
    width: 8px;
}

.css-1d391kg::-webkit-scrollbar-track {
    background: #0a0a0a;
    border-radius: 4px;
}

.css-1d391kg::-webkit-scrollbar-thumb {
    background: linear-gradient(180deg, #00ff41 0%, #00cc33 100%);
    border-radius: 4px;
    box-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
}

/* CSS Animations */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

@keyframes active-glow {
    0% { box-shadow: 0 0 30px rgba(0, 255, 65, 0.8); }
    100% { box-shadow: 0 0 40px rgba(0, 255, 65, 1); }
}

@keyframes arrow-bounce {
    0%, 100% { transform: translateY(-50%) translateX(0); }
    50% { transform: translateY(-50%) translateX(3px); }
}

/* Navigation icons enhancement - Professional */
.css-1629p8f, .css-14xtw13, .css-79elbk {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%) !important;
    border: 1px solid #00ff41 !important;
    border-radius: 10px !important;
    padding: 12px !important;
    margin: 8px 0 !important;
    transition: all 0.3s ease !important;
    position: relative !important;
    overflow: hidden !important;
}

.css-1629p8f:hover, .css-14xtw13:hover, .css-79elbk:hover {
    background: linear-gradient(135deg, #00ff41 0%, #00cc33 100%) !important;
    border: 1px solid #ffffff !important;
    transform: scale(1.05) !important;
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.6) !important;
}

/* Page navigation buttons */
.css-1v0mbdj button, .css-1d391kg button {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%) !important;
    border: 1px solid #00ff41 !important;
    color: #00ff41 !important;
    border-radius: 8px !important;
    padding: 10px 15px !important;
    font-family: 'Courier New', monospace !important;
    font-weight: 600 !important;
    transition: all 0.3s ease !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
}

.css-1v0mbdj button:hover, .css-1d391kg button:hover {
    background: linear-gradient(135deg, #00ff41 0%, #00cc33 100%) !important;
    color: #000000 !important;
    border: 1px solid #ffffff !important;
    box-shadow: 0 0 15px rgba(0, 255, 65, 0.5) !important;
    transform: scale(1.02) !important;
}

/* Metric containers */
.metric-container {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%) !important;
    border: 1px solid #00ff41 !important;
    border-radius: 10px !important;
    padding: 20px !important;
    margin: 10px 0 !important;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3) !important;
    transition: all 0.3s ease !important;
}

.metric-container:hover {
    transform: translateY(-3px) !important;
    box-shadow: 0 8px 25px rgba(0, 255, 65, 0.3) !important;
}
    padding: 10px !important;
    margin: 5px 0 !important;
    box-shadow: 0 0 10px rgba(0, 255, 65, 0.2) !important;
    transition: all 0.3s ease !important;
}

.css-1629p8f:hover {
    background: linear-gradient(135deg, #00ff41 0%, #2a2a2a 100%) !important;
    color: #000000 !important;
    transform: scale(1.05) !important;
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.5) !important;
}

/* Page navigation links */
.css-16idsys p {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%) !important;
    border: 1px solid #333 !important;
    border-radius: 8px !important;
    padding: 12px 15px !important;
    margin: 8px 0 !important;
    color: #00ff41 !important;
    font-family: 'Courier New', monospace !important;
    font-weight: bold !important;
    transition: all 0.3s ease !important;
    text-decoration: none !important;
    display: block !important;
    position: relative !important;
    overflow: hidden !important;
}

.css-16idsys p:hover {
    background: linear-gradient(135deg, #00ff41 0%, #1a1a1a 100%) !important;
    color: #000000 !important;
    border: 1px solid #00ff41 !important;
    transform: translateX(8px) !important;
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.4) !important;
}

.css-16idsys p::before {
    content: '▶' !important;
    margin-right: 10px !important;
    color: #00ff41 !important;
    transition: all 0.3s ease !important;
}

.css-16idsys p:hover::before {
    color: #000000 !important;
    transform: translateX(5px) !important;
}

/* Metrik kartları */
.metric-card {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
    border: 1px solid #00ff41;
    border-radius: 10px;
    padding: 20px;
    margin: 10px 0;
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
    transition: all 0.3s ease;
}

.metric-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 0 30px rgba(0, 255, 65, 0.5);
}

/* Başlıklar */
h1, h2, h3 {
    color: #00ff41 !important;
    text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
    font-family: 'Courier New', monospace;
}

/* Ana başlık özel stil */
.main-title {
    font-size: 3rem;
    color: #00ff41;
    text-align: center;
    text-shadow: 0 0 20px rgba(0, 255, 65, 0.8);
    margin-bottom: 30px;
    font-family: 'Courier New', monospace;
    font-weight: bold;
}

/* Kartlar ve paneller */
.stTabs [data-baseweb="tab-list"] {
    background: #1a1a1a;
    border: 1px solid #00ff41;
    border-radius: 10px;
}

.stTabs [data-baseweb="tab"] {
    color: #00ff41;
    background: #1a1a1a;
    border: 1px solid #333;
}

.stTabs [aria-selected="true"] {
    background: #00ff41 !important;
    color: #000000 !important;
}

/* Metrikleri özelleştir */
[data-testid="metric-container"] {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
    border: 1px solid #00ff41;
    border-radius: 10px;
    padding: 15px;
    box-shadow: 0 0 15px rgba(0, 255, 65, 0.3);
}

[data-testid="metric-container"] > div {
    color: #00ff41 !important;
}

/* Butonlar */
.stButton > button {
    background: linear-gradient(135deg, #1a1a1a 0%, #00ff41 100%);
    color: #000000;
    border: 2px solid #00ff41;
    border-radius: 10px;
    font-weight: bold;
    transition: all 0.3s ease;
}

.stButton > button:hover {
    background: #00ff41;
    color: #000000;
    box-shadow: 0 0 20px rgba(0, 255, 65, 0.8);
    transform: translateY(-2px);
}

/* Selectbox ve diğer input'lar */
.stSelectbox > div > div {
    background: #1a1a1a;
    border: 1px solid #00ff41;
    color: #00ff41;
}

/* Sidebar navigation styling */
.css-1544g2n {
    color: #00ff41 !important;
}

/* Plotly grafikleri için koyu tema */
.js-plotly-plot {
    background: #1a1a1a !important;
}

/* Dataframe styling */
.stDataFrame {
    background: #1a1a1a;
    border: 1px solid #00ff41;
    border-radius: 10px;
}

/* Alert ve bildirimler */
.stAlert {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
    border: 1px solid #00ff41;
    border-radius: 10px;
    color: #00ff41;
}

/* Matrix effect için ekstra */
.matrix-bg {
    background: 
        radial-gradient(ellipse at random, rgba(0, 255, 65, 0.1) 0%, transparent 50%),
        radial-gradient(ellipse at random, rgba(0, 255, 65, 0.1) 0%, transparent 50%);
    animation: matrix 20s linear infinite;
}

@keyframes matrix {
    0% { background-position: 0% 0%; }
    100% { background-position: 100% 100%; }
}

/* Glowing effect */
.glow {
    animation: glow 2s ease-in-out infinite alternate;
}

@keyframes glow {
    from { text-shadow: 0 0 5px #00ff41, 0 0 10px #00ff41, 0 0 15px #00ff41; }
    to { text-shadow: 0 0 10px #00ff41, 0 0 20px #00ff41, 0 0 30px #00ff41; }
}

/* Hacker terminal efekti */
.terminal-text {
    font-family: 'Courier New', monospace;
    color: #00ff41;
    background: #000000;
    padding: 10px;
    border-radius: 5px;
    border: 1px solid #00ff41;
    box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
}

/* Risk seviyesi renkleri */
.risk-critical { color: #ff0040 !important; text-shadow: 0 0 10px #ff0040; }
.risk-high { color: #ff6600 !important; text-shadow: 0 0 10px #ff6600; }
.risk-medium { color: #ffcc00 !important; text-shadow: 0 0 10px #ffcc00; }
.risk-low { color: #00ff41 !important; text-shadow: 0 0 10px #00ff41; }

</style>
""", unsafe_allow_html=True)

# Ana başlık - Cybersecurity temalı
st.markdown('<h1 class="main-title">🛡️ CyberTrack Vision</h1>', unsafe_allow_html=True)
st.markdown('<div class="terminal-text">/// CYBER DEFENSE OPERATIONS CENTER /// REAL-TIME THREAT MONITORING ///</div>', unsafe_allow_html=True)

@st.cache_data
def load_data():
    """Veri setini yükle ve ön işleme yap"""
    try:
        df = pd.read_csv('data/cybertrack_mock_dataset.csv')
        
        # Timestamp sütununu datetime'a çevir
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Risk kategorilerini düzenle
        risk_mapping = {
            'Düşük': 'Low',
            'Orta': 'Medium', 
            'Yüksek': 'High'
        }
        df['risk_category_en'] = df['risk_category'].map(risk_mapping)
        
        # Attack ports ve hours'ı parse et
        def parse_ports(port_str):
            if pd.isna(port_str) or port_str == '-':
                return []
            ports = []
            for item in port_str.split('|'):
                if ':' in item:
                    port = item.split(':')[0]
                    ports.append(port)
            return ports
        
        def parse_hours(hour_str):
            if pd.isna(hour_str) or hour_str == '-':
                return []
            hours = []
            for item in hour_str.split('|'):
                if ':' in item:
                    hour = item.split(':')[0]
                    hours.append(hour)
            return hours
        
        df['parsed_ports'] = df['attack_ports'].apply(parse_ports)
        df['parsed_hours'] = df['attack_hours'].apply(parse_hours)
        
        # Saat ve gün bilgilerini ekle
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.day_name()
        df['month'] = df['timestamp'].dt.month_name()
        
        return df
    except Exception as e:
        st.error(f"Veri yükleme hatası: {e}")
        return None

def create_header():
    """Ana başlığı oluştur"""
    st.markdown('<h1 class="main-header">🛡️ CyberTrack Vision</h1>', unsafe_allow_html=True)
    st.markdown('<h3 style="text-align: center; color: #666;">Gerçek Zamanlı Siber Güvenlik İzleme ve Analiz Platformu</h3>', unsafe_allow_html=True)

def sidebar_filters(df):
    """Enhanced Sidebar filtreleri"""
    
    # Cybersecurity Header
    st.sidebar.markdown("""
    <div style="
        background: linear-gradient(135deg, #1a1a1a 0%, #00ff41 100%);
        padding: 15px;
        border-radius: 10px;
        margin-bottom: 20px;
        text-align: center;
        border: 2px solid #00ff41;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
    ">
        <h2 style="color: #000000; margin: 0; font-family: 'Courier New', monospace; text-shadow: none;">
            🛡️ CYBERTRACK VISION
        </h2>
        <p style="color: #000000; margin: 5px 0 0 0; font-size: 12px; font-weight: bold;">
            /// THREAT ANALYSIS CONSOLE ///
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Navigation Categories
    st.sidebar.markdown("""
    <div style="
        background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
        border: 1px solid #00ff41;
        border-radius: 8px;
        padding: 10px;
        margin: 10px 0;
        box-shadow: 0 0 15px rgba(0, 255, 65, 0.2);
    ">
        <h3 style="color: #00ff41; margin: 0; font-size: 16px; text-align: center;">
            � CORE ANALYTICS
        </h3>
    </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.markdown("""
    <div style="
        background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
        border: 1px solid #ff6600;
        border-radius: 8px;
        padding: 10px;
        margin: 10px 0;
        box-shadow: 0 0 15px rgba(255, 102, 0, 0.2);
    ">
        <h3 style="color: #ff6600; margin: 0; font-size: 16px; text-align: center;">
            🎯 THREAT INTELLIGENCE
        </h3>
    </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.markdown("""
    <div style="
        background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
        border: 1px solid #ff0040;
        border-radius: 8px;
        padding: 10px;
        margin: 10px 0;
        box-shadow: 0 0 15px rgba(255, 0, 64, 0.2);
    ">
        <h3 style="color: #ff0040; margin: 0; font-size: 16px; text-align: center;">
            🔬 ADVANCED FORENSICS
        </h3>
    </div>
    """, unsafe_allow_html=True)
    
    # Filters Section
    st.sidebar.markdown("""
    <div style="
        background: linear-gradient(135deg, #2a2a2a 0%, #1a1a1a 100%);
        border: 2px solid #00ff41;
        border-radius: 10px;
        padding: 15px;
        margin: 20px 0;
        box-shadow: 0 0 25px rgba(0, 255, 65, 0.4);
    ">
        <h2 style="color: #00ff41; margin: 0 0 15px 0; text-align: center; font-family: 'Courier New', monospace;">
            🔍 THREAT FILTERS
        </h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Tarih aralığı filtresi
    date_range = st.sidebar.date_input(
        "📅 OPERATIONAL TIMEFRAME",
        value=[df['timestamp'].min().date(), df['timestamp'].max().date()],
        min_value=df['timestamp'].min().date(),
        max_value=df['timestamp'].max().date()
    )
    
    # Risk seviyesi filtresi
    risk_levels = st.sidebar.multiselect(
        "⚠️ THREAT SEVERITY LEVELS",
        options=['Low', 'Medium', 'High'],
        default=['Low', 'Medium', 'High']
    )
    
    # Ülke filtresi
    countries = st.sidebar.multiselect(
        "🌍 GEOGRAPHIC ORIGINS",
        options=sorted(df['country'].unique()),
        default=sorted(df['country'].unique())[:10]
    )
    
    # ISP filtresi
    isps = st.sidebar.multiselect(
        "🌐 ISP INTELLIGENCE",
        options=sorted(df['isp'].unique()),
        default=sorted(df['isp'].unique())[:5]
    )
    
    # System Status
    st.sidebar.markdown("""
    <div style="
        background: linear-gradient(135deg, #1a1a1a 0%, #0a0a0a 100%);
        border: 1px solid #00ff41;
        border-radius: 8px;
        padding: 15px;
        margin: 20px 0;
        text-align: center;
    ">
        <p style="color: #00ff41; margin: 0; font-family: 'Courier New', monospace; font-size: 12px;">
            🟢 SYSTEM STATUS: OPERATIONAL<br>
            🔄 LAST UPDATE: REAL-TIME<br>
            🛡️ SECURITY LEVEL: MAXIMUM
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    return date_range, risk_levels, countries, isps

def apply_filters(df, date_range, risk_levels, countries, isps):
    """Filtreleri uygula"""
    if len(date_range) == 2:
        start_date, end_date = date_range
        df = df[(df['timestamp'].dt.date >= start_date) & 
                (df['timestamp'].dt.date <= end_date)]
    
    if risk_levels:
        df = df[df['risk_category_en'].isin(risk_levels)]
    
    if countries:
        df = df[df['country'].isin(countries)]
    
    if isps:
        df = df[df['isp'].isin(isps)]
    
    return df

def display_metrics(df):
    """Ana metrikleri göster"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_attacks = len(df)
        st.markdown(f"""
        <div class="metric-container">
            <h3>🎯 Toplam Saldırı</h3>
            <h2>{total_attacks:,}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        unique_ips = df['ip'].nunique()
        st.markdown(f"""
        <div class="metric-container">
            <h3>🌐 Benzersiz IP</h3>
            <h2>{unique_ips:,}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        avg_risk = df['risk'].mean()
        st.markdown(f"""
        <div class="metric-container">
            <h3>📊 Ortalama Risk</h3>
            <h2>{avg_risk:.1f}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        unique_countries = df['country'].nunique()
        st.markdown(f"""
        <div class="metric-container">
            <h3>🏳️ Etkilenen Ülke</h3>
            <h2>{unique_countries}</h2>
        </div>
        """, unsafe_allow_html=True)

def risk_distribution_charts(df):
    """Risk dağılım grafikleri"""
    st.markdown("## 📊 Risk Analizi")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Risk kategorileri dağılımı
        risk_counts = df['risk_category_en'].value_counts()
        colors = {'High': '#ff0040', 'Medium': '#ff6600', 'Low': '#00ff41'}
        
        fig = px.pie(
            values=risk_counts.values,
            names=risk_counts.index,
            title="Risk Kategorileri Dağılımı",
            color=risk_counts.index,
            color_discrete_map=colors
        )
        fig.update_layout(
            height=400,
            plot_bgcolor='#1a1a1a',
            paper_bgcolor='#1a1a1a',
            font_color='#00ff41',
            title_font_color='#00ff41'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Risk skoru histogramı
        fig = px.histogram(
            df, 
            x='risk', 
            nbins=20,
            title="Risk Skoru Dağılımı",
            labels={'risk': 'Risk Skoru', 'count': 'Frekans'},
            color_discrete_sequence=['#00ff41']
        )
        fig.update_layout(
            height=400,
            plot_bgcolor='#1a1a1a',
            paper_bgcolor='#1a1a1a',
            font_color='#00ff41',
            title_font_color='#00ff41'
        )
        st.plotly_chart(fig, use_container_width=True)

def geographic_analysis(df):
    """Coğrafi analiz"""
    st.markdown("## 🌍 Coğrafi Analiz")
    
    tab1, tab2 = st.tabs(["🗺️ Harita Görünümü", "📍 Ülke Analizi"])
    
    with tab1:
        # Folium haritası
        m = folium.Map(location=[20, 0], zoom_start=2)
        
        # Risk seviyesine göre renk kodları
        def get_color(risk_level):
            if risk_level == 'High':
                return 'red'
            elif risk_level == 'Medium':
                return 'orange'
            else:
                return 'green'
        
        # Her ülke için bir marker ekle
        country_data = df.groupby(['country', 'latitude', 'longitude', 'risk_category_en']).size().reset_index(name='count')
        
        for _, row in country_data.iterrows():
            folium.CircleMarker(
                location=[row['latitude'], row['longitude']],
                radius=max(5, row['count'] / 10),
                popup=f"{row['country']}: {row['count']} saldırı",
                color=get_color(row['risk_category_en']),
                fill=True,
                weight=2
            ).add_to(m)
        
        st_folium(m, width=700, height=500)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            # Ülkeye göre saldırı sayısı
            country_attacks = df['country'].value_counts().head(10)
            fig = px.bar(
                x=country_attacks.index,
                y=country_attacks.values,
                title="En Çok Saldırı Alan Ülkeler",
                labels={'x': 'Ülke', 'y': 'Saldırı Sayısı'}
            )
            fig.update_layout(height=400, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Ülkeye göre ortalama risk
            country_risk = df.groupby('country')['risk'].mean().sort_values(ascending=False).head(10)
            fig = px.bar(
                x=country_risk.index,
                y=country_risk.values,
                title="En Yüksek Ortalama Risk",
                labels={'x': 'Ülke', 'y': 'Ortalama Risk Skoru'}
            )
            fig.update_layout(height=400, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)

def temporal_analysis(df):
    """Zamansal analiz"""
    st.markdown("## ⏰ Zamansal Analiz")
    
    tab1, tab2, tab3 = st.tabs(["📈 Zaman Serisi", "🕐 Saatlik Analiz", "📅 Günlük Analiz"])
    
    with tab1:
        # Günlük saldırı trendi
        daily_attacks = df.groupby(df['timestamp'].dt.date).size().reset_index(name='count')
        daily_attacks.columns = ['date', 'attacks']
        
        fig = px.line(
            daily_attacks,
            x='date',
            y='attacks',
            title="Günlük Saldırı Trendi",
            labels={'date': 'Tarih', 'attacks': 'Saldırı Sayısı'}
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Saatlik dağılım
        hourly_attacks = df['hour'].value_counts().sort_index()
        fig = px.bar(
            x=hourly_attacks.index,
            y=hourly_attacks.values,
            title="Saatlik Saldırı Dağılımı",
            labels={'x': 'Saat', 'y': 'Saldırı Sayısı'}
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Günlük dağılım
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        daily_attacks = df['day'].value_counts().reindex(day_order)
        
        fig = px.bar(
            x=daily_attacks.index,
            y=daily_attacks.values,
            title="Haftanın Günlerine Göre Saldırı Dağılımı",
            labels={'x': 'Gün', 'y': 'Saldırı Sayısı'}
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

def network_analysis(df):
    """Ağ analizi"""
    st.markdown("## 🌐 Ağ ve ISP Analizi")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # ISP analizi
        isp_attacks = df['isp'].value_counts().head(10)
        fig = px.bar(
            x=isp_attacks.values,
            y=isp_attacks.index,
            orientation='h',
            title="ISP'lere Göre Saldırı Dağılımı",
            labels={'x': 'Saldırı Sayısı', 'y': 'ISP'}
        )
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # ASN analizi
        asn_attacks = df['asn_name'].value_counts().head(10)
        fig = px.bar(
            x=asn_attacks.values,
            y=asn_attacks.index,
            orientation='h',
            title="ASN'lere Göre Saldırı Dağılımı",
            labels={'x': 'Saldırı Sayısı', 'y': 'ASN'}
        )
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)

def port_analysis(df):
    """Port analizi"""
    st.markdown("## 🔌 Port Analizi")
    
    # Tüm portları topla
    all_ports = []
    for ports in df['parsed_ports']:
        all_ports.extend(ports)
    
    if all_ports:
        port_counts = Counter(all_ports)
        top_ports = dict(port_counts.most_common(15))
        
        col1, col2 = st.columns(2)
        
        with col1:
            # En çok saldırıya uğrayan portlar
            fig = px.bar(
                x=list(top_ports.keys()),
                y=list(top_ports.values()),
                title="En Çok Hedef Alınan Portlar",
                labels={'x': 'Port Numarası', 'y': 'Saldırı Sayısı'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Port kategorileri
            common_ports = {
                '22': 'SSH', '23': 'Telnet', '25': 'SMTP', '53': 'DNS',
                '80': 'HTTP', '110': 'POP3', '143': 'IMAP', '443': 'HTTPS',
                '993': 'IMAPS', '995': 'POP3S'
            }
            
            port_categories = {}
            for port, count in top_ports.items():
                category = common_ports.get(port, 'Diğer')
                port_categories[category] = port_categories.get(category, 0) + count
            
            fig = px.pie(
                values=list(port_categories.values()),
                names=list(port_categories.keys()),
                title="Port Kategorileri"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

def advanced_analytics(df):
    """Gelişmiş analitik"""
    st.markdown("## 🧠 Gelişmiş Analitik")
    
    tab1, tab2, tab3 = st.tabs(["🎯 Risk Skorlama", "🔍 Anomali Tespiti", "📊 Korelasyon Analizi"])
    
    with tab1:
        # Risk skorlama modeli
        st.markdown("### Risk Skorlama Modeli")
        
        # Risk faktörleri
        col1, col2 = st.columns(2)
        
        with col1:
            # Ülkeye göre risk dağılımı
            country_risk = df.groupby('country').agg({
                'risk': ['mean', 'count']
            }).round(2)
            country_risk.columns = ['Ortalama Risk', 'Saldırı Sayısı']
            country_risk = country_risk.sort_values('Ortalama Risk', ascending=False).head(10)
            
            st.markdown("**En Riskli Ülkeler**")
            st.dataframe(country_risk)
        
        with col2:
            # ISP'ye göre risk
            isp_risk = df.groupby('isp').agg({
                'risk': ['mean', 'count']
            }).round(2)
            isp_risk.columns = ['Ortalama Risk', 'Saldırı Sayısı']
            isp_risk = isp_risk.sort_values('Ortalama Risk', ascending=False).head(10)
            
            st.markdown("**En Riskli ISP'ler**")
            st.dataframe(isp_risk)
    
    with tab2:
        # Anomali tespiti
        st.markdown("### Anomali Tespiti")
        
        # Günlük saldırı sayılarında anomali
        daily_counts = df.groupby(df['timestamp'].dt.date).size()
        
        # Z-score ile anomali tespiti
        mean_attacks = daily_counts.mean()
        std_attacks = daily_counts.std()
        threshold = 2
        
        anomalies = daily_counts[abs((daily_counts - mean_attacks) / std_attacks) > threshold]
        
        if len(anomalies) > 0:
            st.markdown(f"**{len(anomalies)} adet anormal gün tespit edildi:**")
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=daily_counts.index,
                y=daily_counts.values,
                mode='lines+markers',
                name='Günlük Saldırılar',
                line=dict(color='blue')
            ))
            
            fig.add_trace(go.Scatter(
                x=anomalies.index,
                y=anomalies.values,
                mode='markers',
                name='Anomaliler',
                marker=dict(color='red', size=10)
            ))
            
            fig.update_layout(
                title="Günlük Saldırı Anomalileri",
                xaxis_title="Tarih",
                yaxis_title="Saldırı Sayısı",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Anomali tespit edilmedi.")
    
    with tab3:
        # Korelasyon analizi
        st.markdown("### Korelasyon Analizi")
        
        # Sayısal değişkenler için korelasyon matrisi
        numeric_cols = ['risk', 'latitude', 'longitude']
        corr_matrix = df[numeric_cols].corr()
        
        fig = px.imshow(
            corr_matrix,
            text_auto=True,
            aspect="auto",
            title="Değişkenler Arası Korelasyon"
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

def data_export(df):
    """Veri dışa aktarma"""
    st.markdown("## 📤 Veri Dışa Aktarma")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Filtrelenmiş veriyi CSV olarak indir
        csv = df.to_csv(index=False)
        st.download_button(
            label="📊 CSV İndir",
            data=csv,
            file_name=f"cybertrack_filtered_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    with col2:
        # Özet rapor
        summary_report = f"""
CyberTrack Vision - Özet Rapor
===============================
Rapor Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Genel İstatistikler:
- Toplam Saldırı: {len(df):,}
- Benzersiz IP: {df['ip'].nunique():,}
- Ortalama Risk Skoru: {df['risk'].mean():.2f}
- Etkilenen Ülke Sayısı: {df['country'].nunique()}

Risk Dağılımı:
{df['risk_category_en'].value_counts().to_string()}

En Çok Saldırı Alan Ülkeler:
{df['country'].value_counts().head(5).to_string()}

En Riskli ISP'ler:
{df.groupby('isp')['risk'].mean().sort_values(ascending=False).head(5).to_string()}
        """
        
        st.download_button(
            label="📋 Rapor İndir",
            data=summary_report,
            file_name=f"cybertrack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )
    
    with col3:
        # JSON formatında indir
        json_data = df.to_json(orient='records', date_format='iso')
        st.download_button(
            label="🔧 JSON İndir",
            data=json_data,
            file_name=f"cybertrack_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

def main():
    """Ana uygulama"""
    create_header()
    
    # Veriyi yükle
    df = load_data()
    if df is None:
        st.error("Veri yüklenemedi. Lütfen veri dosyasını kontrol edin.")
        return
    
    # Sidebar filtreleri
    date_range, risk_levels, countries, isps = sidebar_filters(df)
    
    # Filtreleri uygula
    filtered_df = apply_filters(df, date_range, risk_levels, countries, isps)
    
    if len(filtered_df) == 0:
        st.warning("Seçilen filtrelere uygun veri bulunamadı.")
        return
    
    # Ana metrikler
    display_metrics(filtered_df)
    
    # Ana analiz bölümleri
    risk_distribution_charts(filtered_df)
    geographic_analysis(filtered_df)
    temporal_analysis(filtered_df)
    network_analysis(filtered_df)
    port_analysis(filtered_df)
    advanced_analytics(filtered_df)
    
    # Veri dışa aktarma
    data_export(filtered_df)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 20px;'>
        🛡️ CyberTrack Vision - Gelişmiş Siber Güvenlik Analiz Platformu<br>
        <small>Gerçek zamanlı tehdit izleme ve analiz sistemi</small>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
