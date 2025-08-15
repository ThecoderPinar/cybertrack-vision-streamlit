import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import random
import time
from datetime import datetime, timedelta
import numpy as np

st.set_page_config(
    page_title="🌐 Live Monitoring",
    page_icon="🌐",
    layout="wide"
)

# Cybersecurity Dark Theme CSS
st.markdown("""
<style>
.main > div { background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%); }
h1, h2, h3 { color: #00ff41 !important; text-shadow: 0 0 10px rgba(0, 255, 65, 0.5); }
[data-testid="metric-container"] {
    background: linear-gradient(135deg, #1a1a1a 0%, #2a2a2a 100%);
    border: 1px solid #00ff41;
    border-radius: 10px;
    padding: 15px;
    box-shadow: 0 0 15px rgba(0, 255, 65, 0.3);
}
</style>
""", unsafe_allow_html=True)

st.markdown("# 🌐 Live Monitoring System - Canlı İzleme Sistemi")

# Auto-refresh kontrolleri
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = True

if 'refresh_interval' not in st.session_state:
    st.session_state.refresh_interval = 5

@st.cache_data(ttl=5)  # 5 saniye cache
def load_data():
    df = pd.read_csv('data/cybertrack_mock_dataset.csv')
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

@st.cache_data(ttl=1)  # 1 saniye cache (gerçek zamanlı simülasyon)
def generate_live_attacks():
    """Gerçek zamanlı saldırı simülasyonu"""
    
    # Güncel zaman
    current_time = datetime.now()
    
    # Son 5 dakikadaki saldırılar
    live_attacks = []
    
    countries = ['United States', 'China', 'Russia', 'Iran', 'North Korea', 'India', 'Brazil', 'Germany', 'France', 'Turkey']
    cities = {
        'United States': ['New York', 'Los Angeles', 'Chicago', 'Washington'],
        'China': ['Beijing', 'Shanghai', 'Shenzhen', 'Guangzhou'],
        'Russia': ['Moscow', 'St. Petersburg', 'Novosibirsk', 'Kazan'],
        'Iran': ['Tehran', 'Isfahan', 'Mashhad', 'Shiraz'],
        'North Korea': ['Pyongyang', 'Hamhung', 'Chongjin', 'Wonsan'],
        'India': ['Mumbai', 'Delhi', 'Bangalore', 'Chennai'],
        'Brazil': ['São Paulo', 'Rio de Janeiro', 'Brasília', 'Belo Horizonte'],
        'Germany': ['Berlin', 'Munich', 'Hamburg', 'Frankfurt'],
        'France': ['Paris', 'Lyon', 'Marseille', 'Toulouse'],
        'Turkey': ['Istanbul', 'Ankara', 'Izmir', 'Bursa']
    }
    
    attack_types = [
        'SQL Injection', 'XSS Attack', 'DDoS', 'Port Scan', 'Brute Force',
        'Malware', 'Phishing', 'Ransomware', 'Zero-day Exploit', 'APT'
    ]
    
    target_types = [
        'Web Server', 'Database', 'Email Server', 'DNS Server', 'FTP Server',
        'SSH Server', 'API Endpoint', 'IoT Device', 'Mobile App', 'Cloud Service'
    ]
    
    severity_levels = ['Low', 'Medium', 'High', 'Critical']
    
    # 30 adet canlı saldırı oluştur
    for i in range(30):
        country = random.choice(countries)
        city = random.choice(cities[country])
        
        # Son 5 dakika içinde rastgele zaman
        attack_time = current_time - timedelta(minutes=random.randint(0, 5))
        
        live_attacks.append({
            'id': f"ATK-{random.randint(10000, 99999)}",
            'timestamp': attack_time,
            'source_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'target_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'source_country': country,
            'source_city': city,
            'attack_type': random.choice(attack_types),
            'target_type': random.choice(target_types),
            'severity': random.choice(severity_levels),
            'risk_score': random.randint(20, 100),
            'packets_count': random.randint(100, 10000),
            'data_size_mb': round(random.uniform(0.1, 100.0), 2),
            'blocked': random.choice([True, False]),
            'latitude': random.uniform(-60, 60),
            'longitude': random.uniform(-180, 180)
        })
    
    return pd.DataFrame(live_attacks)

def real_time_dashboard():
    """Gerçek Zamanlı Dashboard"""
    st.markdown("## 🚨 Gerçek Zamanlı Tehdit Dashboard")
    
    # Kontrol paneli
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown("### ⚡ Canlı Saldırı İzleme")
    
    with col2:
        auto_refresh = st.checkbox("🔄 Otomatik Yenileme", value=st.session_state.auto_refresh)
        st.session_state.auto_refresh = auto_refresh
    
    with col3:
        refresh_interval = st.selectbox("⏱️ Yenileme Aralığı", [1, 2, 5, 10], index=2)
        st.session_state.refresh_interval = refresh_interval
    
    # Canlı veri yükle
    live_df = generate_live_attacks()
    
    # Gerçek zamanlı metrikler
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        total_attacks = len(live_df)
        st.metric("🎯 Toplam Saldırı", total_attacks, delta=f"+{random.randint(5, 15)}")
    
    with col2:
        critical_attacks = len(live_df[live_df['severity'] == 'Critical'])
        st.metric("🚨 Kritik Saldırı", critical_attacks, delta=f"+{random.randint(0, 3)}")
    
    with col3:
        blocked_rate = (live_df['blocked'].sum() / len(live_df)) * 100
        st.metric("🛡️ Engelleme Oranı", f"{blocked_rate:.1f}%", delta=f"{random.uniform(-2, 2):.1f}%")
    
    with col4:
        avg_risk = live_df['risk_score'].mean()
        st.metric("⚠️ Ortalama Risk", f"{avg_risk:.1f}", delta=f"{random.uniform(-5, 5):.1f}")
    
    with col5:
        unique_countries = live_df['source_country'].nunique()
        st.metric("🌍 Aktif Ülke", unique_countries, delta=f"+{random.randint(0, 2)}")
    
    return live_df

def live_world_map(live_df):
    """Canlı Dünya Haritası"""
    st.markdown("## 🗺️ Canlı Saldırı Haritası")
    
    if live_df.empty:
        st.warning("Canlı veri bulunamadı.")
        return
    
    # Ülke bazlı saldırı sayısını hesapla
    country_attacks = live_df.groupby('source_country').agg({
        'risk_score': ['count', 'mean', 'max']
    }).round(2)
    country_attacks.columns = ['Attack Count', 'Avg Risk', 'Max Risk']
    country_attacks = country_attacks.reset_index()
    
    # Choropleth harita oluştur
    fig = px.choropleth(
        country_attacks,
        locations='source_country',
        color='Attack Count',
        hover_name='source_country',
        hover_data={'Avg Risk': True, 'Max Risk': True},
        color_continuous_scale='Reds',
        locationmode='country names',
        title='🌍 Canlı Saldırı Haritası - Ülke Bazlı'
    )
    
    fig.update_layout(
        height=600,
        plot_bgcolor='#1a1a1a',
        paper_bgcolor='#1a1a1a',
        font_color='#00ff41',
        title_font_color='#00ff41',
        geo=dict(
            showframe=False,
            showcoastlines=True,
            projection_type='equirectangular',
            bgcolor='#1a1a1a'
        )
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Ayrıca scatter plot da ekleyelim
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity dağılımı
        severity_counts = live_df['severity'].value_counts()
        colors = ['#00ff41', '#ffcc00', '#ff6600', '#ff0040']
        
        fig_pie = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            title="🚨 Severity Dağılımı",
            color_discrete_sequence=colors
        )
        fig_pie.update_layout(
            height=400,
            plot_bgcolor='#1a1a1a',
            paper_bgcolor='#1a1a1a',
            font_color='#00ff41',
            title_font_color='#00ff41'
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # En aktif ülkeler
        top_countries = live_df['source_country'].value_counts().head(8)
        
        fig_bar = px.bar(
            x=top_countries.values,
            y=top_countries.index,
            orientation='h',
            title="🌍 En Aktif Saldırgan Ülkeler",
            labels={'x': 'Saldırı Sayısı', 'y': 'Ülke'},
            color=top_countries.values,
            color_continuous_scale='Reds'
        )
        fig_bar.update_layout(
            height=400, 
            showlegend=False,
            plot_bgcolor='#1a1a1a',
            paper_bgcolor='#1a1a1a',
            font_color='#00ff41',
            title_font_color='#00ff41'
        )
        st.plotly_chart(fig_bar, use_container_width=True)

def attack_timeline(live_df):
    """Saldırı Zaman Çizelgesi"""
    st.markdown("## ⏰ Canlı Saldırı Zaman Çizelgesi")
    
    if live_df.empty:
        st.warning("Timeline verisi bulunamadı.")
        return
    
    # Timeline verisi hazırla
    timeline_df = live_df.sort_values('timestamp')
    
    # Severity'e göre renk
    color_map = {'Low': '#90EE90', 'Medium': '#FFD700', 'High': '#FF6347', 'Critical': '#FF0000'}
    
    fig = px.scatter(
        timeline_df,
        x='timestamp',
        y='attack_type',
        color='severity',
        size='risk_score',
        hover_data=['source_country', 'target_type', 'blocked'],
        title="⏰ Son 5 Dakikadaki Saldırılar",
        color_discrete_map=color_map
    )
    
    fig.update_layout(
        height=500,
        xaxis_title="Zaman",
        yaxis_title="Saldırı Türü"
    )
    
    st.plotly_chart(fig, use_container_width=True)

def threat_feed(live_df):
    """Canlı Tehdit Feed'i"""
    st.markdown("## 📡 Canlı Tehdit Feed'i")
    
    if live_df.empty:
        st.warning("Feed verisi bulunamadı.")
        return
    
    # En son saldırıları göster
    latest_attacks = live_df.sort_values('timestamp', ascending=False).head(10)
    
    for _, attack in latest_attacks.iterrows():
        severity_emoji = {
            'Low': '🟢',
            'Medium': '🟡', 
            'High': '🟠',
            'Critical': '🔴'
        }
        
        blocked_status = "🛡️ BLOCKED" if attack['blocked'] else "⚠️ ALLOWED"
        
        with st.container():
            col1, col2, col3, col4 = st.columns([1, 3, 2, 1])
            
            with col1:
                st.write(f"{severity_emoji[attack['severity']]} **{attack['severity']}**")
            
            with col2:
                st.write(f"**{attack['attack_type']}** from {attack['source_country']}")
                st.caption(f"Source: {attack['source_ip']} → Target: {attack['target_ip']}")
            
            with col3:
                st.write(f"🎯 Risk: **{attack['risk_score']}** | {blocked_status}")
                st.caption(f"⏰ {attack['timestamp'].strftime('%H:%M:%S')}")
            
            with col4:
                if attack['severity'] == 'Critical':
                    st.button("🚨", key=f"alert_{attack['id']}", help="Critical Alert!")
            
            st.divider()

def live_statistics(live_df):
    """Canlı İstatistikler"""
    st.markdown("## 📊 Canlı İstatistikler")
    
    if live_df.empty:
        st.warning("İstatistik verisi bulunamadı.")
        return
    
    tab1, tab2, tab3 = st.tabs(["🎯 Attack Types", "🌍 Geographic", "📈 Trends"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Attack type dağılımı
            attack_dist = live_df['attack_type'].value_counts()
            
            fig = px.pie(
                values=attack_dist.values,
                names=attack_dist.index,
                title="🎯 Saldırı Türü Dağılımı",
                hole=0.4
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Severity dağılımı
            severity_dist = live_df['severity'].value_counts()
            
            colors = ['#90EE90', '#FFD700', '#FF6347', '#FF0000']
            
            fig = px.bar(
                x=severity_dist.index,
                y=severity_dist.values,
                title="⚠️ Severity Dağılımı",
                labels={'x': 'Severity', 'y': 'Saldırı Sayısı'},
                color=severity_dist.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            # Ülke bazlı saldırılar
            country_attacks = live_df['source_country'].value_counts().head(10)
            
            fig = px.bar(
                x=country_attacks.values,
                y=country_attacks.index,
                orientation='h',
                title="🌍 Ülke Bazlı Saldırılar",
                labels={'x': 'Saldırı Sayısı', 'y': 'Ülke'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Target type analizi
            target_dist = live_df['target_type'].value_counts()
            
            fig = px.pie(
                values=target_dist.values,
                names=target_dist.index,
                title="🎯 Hedef Türü Dağılımı",
                hole=0.3
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Risk skoru trend
        risk_timeline = live_df.sort_values('timestamp')
        
        fig = px.line(
            risk_timeline,
            x='timestamp',
            y='risk_score',
            title="📈 Risk Skoru Trendi",
            labels={'timestamp': 'Zaman', 'risk_score': 'Risk Skoru'}
        )
        
        # Moving average ekle
        risk_timeline['risk_ma'] = risk_timeline['risk_score'].rolling(window=5).mean()
        
        fig.add_trace(
            go.Scatter(
                x=risk_timeline['timestamp'],
                y=risk_timeline['risk_ma'],
                mode='lines',
                name='5-Point Moving Average',
                line=dict(color='red', width=2)
            )
        )
        
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

def security_alerts():
    """Güvenlik Uyarıları"""
    st.markdown("## 🚨 Güvenlik Uyarıları ve Bildirimler")
    
    # Simüle edilmiş uyarılar
    alerts = [
        {
            'time': datetime.now() - timedelta(minutes=1),
            'level': 'Critical',
            'message': 'Multiple failed login attempts detected from China',
            'source': 'Brute Force Detection',
            'action': 'IP Blocked'
        },
        {
            'time': datetime.now() - timedelta(minutes=3),
            'level': 'High',
            'message': 'Suspicious SQL injection patterns detected',
            'source': 'Web Application Firewall',
            'action': 'Request Blocked'
        },
        {
            'time': datetime.now() - timedelta(minutes=5),
            'level': 'Medium',
            'message': 'Unusual outbound traffic pattern detected',
            'source': 'Network Monitor',
            'action': 'Under Investigation'
        },
        {
            'time': datetime.now() - timedelta(minutes=7),
            'level': 'High',
            'message': 'Zero-day exploit attempt blocked',
            'source': 'IPS System',
            'action': 'Threat Signature Updated'
        }
    ]
    
    for alert in alerts:
        level_emoji = {
            'Low': '🟢',
            'Medium': '🟡',
            'High': '🟠',
            'Critical': '🔴'
        }
        
        with st.container():
            col1, col2, col3 = st.columns([1, 6, 2])
            
            with col1:
                st.write(f"{level_emoji[alert['level']]} **{alert['level']}**")
            
            with col2:
                st.write(f"**{alert['message']}**")
                st.caption(f"Source: {alert['source']} | Action: {alert['action']}")
            
            with col3:
                st.caption(f"⏰ {alert['time'].strftime('%H:%M:%S')}")
            
            st.divider()

# Ana fonksiyon
def main():
    # Ana dashboard
    live_df = real_time_dashboard()
    
    # Ana içerik
    col1, col2 = st.columns([2, 1])
    
    with col1:
        live_world_map(live_df)
        attack_timeline(live_df)
    
    with col2:
        threat_feed(live_df)
        security_alerts()
    
    # Alt bölüm - detaylı istatistikler
    live_statistics(live_df)
    
    # Footer bilgi
    st.markdown("---")
    st.markdown(f"**🕐 Son Güncelleme:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | **🔄 Otomatik Yenileme:** {'Aktif' if st.session_state.auto_refresh else 'Pasif'}")
    
    # Auto-refresh logic (daha güvenli)
    if st.session_state.auto_refresh:
        placeholder = st.empty()
        with placeholder:
            st.info(f"⏱️ {st.session_state.refresh_interval} saniye sonra yenilenecek...")
            time.sleep(st.session_state.refresh_interval)
        placeholder.empty()
        st.rerun()

if __name__ == "__main__":
    main()
