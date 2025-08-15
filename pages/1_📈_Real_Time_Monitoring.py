import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

st.set_page_config(
    page_title="📈 Gerçek Zamanlı Monitoring",
    page_icon="📈",
    layout="wide"
)

st.markdown("# 📈 Gerçek Zamanlı İzleme")

@st.cache_data
def load_realtime_data():
    """Gerçek zamanlı veri simülasyonu"""
    df = pd.read_csv('data/cybertrack_mock_dataset.csv')
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Son 24 saatlik veri simülasyonu
    now = datetime.now()
    df['timestamp'] = pd.date_range(end=now, periods=len(df), freq='5min')
    
    return df.sort_values('timestamp', ascending=False)

def real_time_metrics(df):
    """Gerçek zamanlı metrikler"""
    # Son 1 saat, 24 saat ve 7 günlük veriler
    now = datetime.now()
    last_hour = df[df['timestamp'] >= now - timedelta(hours=1)]
    last_day = df[df['timestamp'] >= now - timedelta(days=1)]
    last_week = df[df['timestamp'] >= now - timedelta(days=7)]
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "🔥 Son 1 Saat",
            len(last_hour),
            delta=len(last_hour) - len(df[(df['timestamp'] >= now - timedelta(hours=2)) & 
                                         (df['timestamp'] < now - timedelta(hours=1))])
        )
    
    with col2:
        st.metric(
            "📊 Son 24 Saat", 
            len(last_day),
            delta=len(last_day) - len(df[(df['timestamp'] >= now - timedelta(days=2)) & 
                                        (df['timestamp'] < now - timedelta(days=1))])
        )
    
    with col3:
        high_risk_count = len(last_day[last_day['risk'] > 70])
        st.metric(
            "⚠️ Yüksek Risk (24h)",
            high_risk_count,
            delta=high_risk_count - len(df[(df['timestamp'] >= now - timedelta(days=2)) & 
                                          (df['timestamp'] < now - timedelta(days=1)) & 
                                          (df['risk'] > 70)])
        )
    
    with col4:
        unique_countries = last_day['country'].nunique()
        st.metric(
            "🌍 Etkilenen Ülke (24h)",
            unique_countries,
            delta=unique_countries - df[(df['timestamp'] >= now - timedelta(days=2)) & 
                                       (df['timestamp'] < now - timedelta(days=1))]['country'].nunique()
        )

def live_charts(df):
    """Canlı grafikler"""
    now = datetime.now()
    last_24h = df[df['timestamp'] >= now - timedelta(days=1)]
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Son 24 saatlik trend
        hourly_data = last_24h.groupby(last_24h['timestamp'].dt.floor('H')).size().reset_index(name='count')
        
        fig = px.line(
            hourly_data,
            x='timestamp',
            y='count',
            title="🕐 Son 24 Saat Saldırı Trendi",
            labels={'timestamp': 'Zaman', 'count': 'Saldırı Sayısı'}
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Risk seviyesi dağılımı (son 24 saat)
        risk_dist = last_24h['risk_category'].value_counts()
        
        fig = px.bar(
            x=risk_dist.index,
            y=risk_dist.values,
            title="⚠️ Risk Dağılımı (Son 24 Saat)",
            labels={'x': 'Risk Kategori', 'y': 'Saldırı Sayısı'},
            color=risk_dist.index,
            color_discrete_map={'Yüksek': '#ff6b6b', 'Orta': '#feca57', 'Düşük': '#48dbfb'}
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

def threat_alerts(df):
    """Tehdit uyarıları"""
    st.markdown("## 🚨 Aktif Tehdit Uyarıları")
    
    now = datetime.now()
    last_hour = df[df['timestamp'] >= now - timedelta(hours=1)]
    
    # Yüksek riskli IP'ler
    high_risk_ips = last_hour[last_hour['risk'] > 80].sort_values('risk', ascending=False)
    
    if not high_risk_ips.empty:
        st.markdown("### 🔴 Kritik Risk IP'leri (Son 1 Saat)")
        
        for _, row in high_risk_ips.head(5).iterrows():
            with st.expander(f"🚨 {row['ip']} - Risk: {row['risk']}", expanded=True):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"**Ülke:** {row['country']}")
                    st.write(f"**Şehir:** {row['city']}")
                with col2:
                    st.write(f"**ISP:** {row['isp']}")
                    st.write(f"**ASN:** {row['asn']}")
                with col3:
                    st.write(f"**Zaman:** {row['timestamp'].strftime('%H:%M:%S')}")
                    st.write(f"**Portlar:** {row['attack_ports']}")
    else:
        st.success("✅ Son 1 saatte kritik risk tespit edilmedi.")

def geographic_heatmap(df):
    """Coğrafi ısı haritası"""
    st.markdown("## 🌍 Coğrafi Tehdit Haritası")
    
    now = datetime.now()
    last_6h = df[df['timestamp'] >= now - timedelta(hours=6)]
    
    # Ülke bazında saldırı yoğunluğu
    country_attacks = last_6h.groupby('country').agg({
        'risk': 'mean',
        'ip': 'count'
    }).round(2)
    country_attacks.columns = ['Ortalama Risk', 'Saldırı Sayısı']
    country_attacks = country_attacks.sort_values('Saldırı Sayısı', ascending=False)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Dünya haritası üzerinde saldırı yoğunluğu
        fig = px.choropleth(
            locations=country_attacks.index,
            color=country_attacks['Saldırı Sayısı'],
            locationmode='country names',
            title="Son 6 Saat Saldırı Yoğunluğu",
            color_continuous_scale="Reds"
        )
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### 📊 Top 10 Ülke")
        st.dataframe(country_attacks.head(10))

# Ana sayfa
def main():
    df = load_realtime_data()
    
    # Auto-refresh butonu
    if st.button("🔄 Yenile", type="primary"):
        st.rerun()
    
    # Gerçek zamanlı metrikler
    real_time_metrics(df)
    
    # Canlı grafikler
    live_charts(df)
    
    # Tehdit uyarıları
    threat_alerts(df)
    
    # Coğrafi analiz
    geographic_heatmap(df)
    
    # Otomatik yenileme bildirimi
    st.info("🔄 Bu sayfa her 30 saniyede bir otomatik olarak güncellenir.")

if __name__ == "__main__":
    main()
