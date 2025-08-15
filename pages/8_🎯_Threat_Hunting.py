import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import re
from datetime import datetime, timedelta
import json

st.set_page_config(
    page_title="🎯 Threat Hunting",
    page_icon="🎯",
    layout="wide"
)

st.markdown("# 🎯 Threat Hunting - Tehdit Avcılığı")

@st.cache_data
def load_data():
    df = pd.read_csv('data/cybertrack_mock_dataset.csv')
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Risk kategorilerini düzenle
    risk_mapping = {
        'Düşük': 'Low',
        'Orta': 'Medium', 
        'Yüksek': 'High'
    }
    df['risk_category_en'] = df['risk_category'].map(risk_mapping)
    
    return df

def ioc_analysis(df):
    """IOC (Indicators of Compromise) Analizi"""
    st.markdown("## 🔍 IOC (Indicators of Compromise) Analizi")
    
    tab1, tab2, tab3 = st.tabs(["🌐 Suspicious IPs", "🔌 Malicious Ports", "📊 Attack Patterns"])
    
    with tab1:
        st.markdown("### 🚨 Şüpheli IP Adresleri")
        
        # Yüksek riskli IP'leri analiz et
        suspicious_ips = df[df['risk'] > 80].groupby('ip').agg({
            'risk': ['mean', 'max', 'count'],
            'country': 'first',
            'isp': 'first',
            'timestamp': ['min', 'max']
        }).round(2)
        
        suspicious_ips.columns = ['Ortalama Risk', 'Max Risk', 'Saldırı Sayısı', 'Ülke', 'ISP', 'İlk Görülme', 'Son Görülme']
        suspicious_ips = suspicious_ips.sort_values('Max Risk', ascending=False)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.dataframe(suspicious_ips.head(20), use_container_width=True)
        
        with col2:
            # IOC Score hesaplama
            st.markdown("### 🎯 IOC Risk Skoru")
            
            for ip in suspicious_ips.head(5).index:
                risk_score = suspicious_ips.loc[ip, 'Max Risk']
                attack_count = suspicious_ips.loc[ip, 'Saldırı Sayısı']
                country = suspicious_ips.loc[ip, 'Ülke']
                
                # IOC risk kategorisi
                if risk_score > 90:
                    risk_color = "🔴"
                    risk_level = "CRITICAL"
                elif risk_score > 70:
                    risk_color = "🟠"
                    risk_level = "HIGH"
                else:
                    risk_color = "🟡"
                    risk_level = "MEDIUM"
                
                st.markdown(f"""
                **{risk_color} {ip}**
                - Risk: {risk_score} ({risk_level})
                - Saldırı: {attack_count}
                - Ülke: {country}
                """)
    
    with tab2:
        st.markdown("### 🔌 Kötü Amaçlı Port Aktiviteleri")
        
        # Port analizini genişlet
        all_ports = []
        for index, row in df.iterrows():
            if pd.notna(row['attack_ports']) and row['attack_ports'] != '-':
                ports = []
                for item in row['attack_ports'].split('|'):
                    if ':' in item:
                        port = item.split(':')[0]
                        ports.append(port)
                        all_ports.append({
                            'port': port,
                            'ip': row['ip'],
                            'risk': row['risk'],
                            'country': row['country'],
                            'timestamp': row['timestamp']
                        })
        
        if all_ports:
            port_df = pd.DataFrame(all_ports)
            
            col1, col2 = st.columns(2)
            
            with col1:
                # En tehlikeli portlar
                dangerous_ports = port_df.groupby('port').agg({
                    'risk': 'mean',
                    'ip': 'nunique'
                }).sort_values('risk', ascending=False).head(10)
                dangerous_ports.columns = ['Ortalama Risk', 'Benzersiz IP']
                
                fig = px.bar(
                    x=dangerous_ports.index,
                    y=dangerous_ports['Ortalama Risk'],
                    title="En Tehlikeli Portlar",
                    labels={'x': 'Port', 'y': 'Ortalama Risk'},
                    color=dangerous_ports['Ortalama Risk'],
                    color_continuous_scale="Reds"
                )
                fig.update_layout(height=400, showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Port kategorileri
                port_categories = {
                    '22': 'SSH', '23': 'Telnet', '21': 'FTP', '25': 'SMTP',
                    '53': 'DNS', '80': 'HTTP', '443': 'HTTPS', '110': 'POP3',
                    '143': 'IMAP', '993': 'IMAPS', '995': 'POP3S'
                }
                
                port_risk_by_category = {}
                for port, risk in dangerous_ports['Ortalama Risk'].items():
                    category = port_categories.get(port, 'Other')
                    if category not in port_risk_by_category:
                        port_risk_by_category[category] = []
                    port_risk_by_category[category].append(risk)
                
                # Kategoriye göre ortalama risk
                category_avg_risk = {cat: sum(risks)/len(risks) for cat, risks in port_risk_by_category.items()}
                
                fig = px.pie(
                    values=list(category_avg_risk.values()),
                    names=list(category_avg_risk.keys()),
                    title="Servis Kategorilerinde Risk Dağılımı"
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        st.markdown("### 📊 Saldırı Desenleri")
        
        # Saldırı pattern'lerini analiz et
        col1, col2 = st.columns(2)
        
        with col1:
            # Zaman bazlı pattern
            df['hour'] = df['timestamp'].dt.hour
            hourly_risk = df.groupby('hour')['risk'].mean()
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=hourly_risk.index,
                y=hourly_risk.values,
                mode='lines+markers',
                name='Saatlik Risk Trendi',
                line=dict(color='red', width=3),
                marker=dict(size=8)
            ))
            
            # Anomali saatlerini vurgula
            anomaly_threshold = hourly_risk.mean() + hourly_risk.std()
            anomaly_hours = hourly_risk[hourly_risk > anomaly_threshold]
            
            if not anomaly_hours.empty:
                fig.add_trace(go.Scatter(
                    x=anomaly_hours.index,
                    y=anomaly_hours.values,
                    mode='markers',
                    name='Anomali Saatleri',
                    marker=dict(color='yellow', size=15, symbol='star')
                ))
            
            fig.update_layout(
                title="Saatlik Risk Pattern Analizi",
                xaxis_title="Saat",
                yaxis_title="Ortalama Risk",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Coğrafi pattern
            country_risk = df.groupby('country')['risk'].mean().sort_values(ascending=False).head(10)
            
            fig = px.bar(
                x=country_risk.values,
                y=country_risk.index,
                orientation='h',
                title="Ülkeye Göre Risk Pattern'leri",
                labels={'x': 'Ortalama Risk', 'y': 'Ülke'},
                color=country_risk.values,
                color_continuous_scale="Viridis"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

def behavioral_analysis(df):
    """Davranışsal Analiz"""
    st.markdown("## 🧠 Davranışsal Analiz")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔄 Tekrarlayan Saldırı Davranışları")
        
        # Aynı IP'den gelen tekrarlayan saldırıları analiz et
        repeated_attacks = df.groupby('ip').agg({
            'timestamp': ['count', 'min', 'max'],
            'risk': 'mean',
            'country': 'first'
        })
        repeated_attacks.columns = ['Saldırı Sayısı', 'İlk Saldırı', 'Son Saldırı', 'Ortalama Risk', 'Ülke']
        repeated_attacks = repeated_attacks[repeated_attacks['Saldırı Sayısı'] > 5].sort_values('Saldırı Sayısı', ascending=False)
        
        st.dataframe(repeated_attacks.head(15), use_container_width=True)
    
    with col2:
        st.markdown("### ⏱️ Saldırı Frekans Analizi")
        
        # Saldırı frekansına göre kategorize et
        attack_frequency = repeated_attacks['Saldırı Sayısı']
        
        frequency_categories = {
            'Düşük Frekans (5-10)': len(attack_frequency[(attack_frequency >= 5) & (attack_frequency <= 10)]),
            'Orta Frekans (11-20)': len(attack_frequency[(attack_frequency >= 11) & (attack_frequency <= 20)]),
            'Yüksek Frekans (21+)': len(attack_frequency[attack_frequency >= 21])
        }
        
        fig = px.pie(
            values=list(frequency_categories.values()),
            names=list(frequency_categories.keys()),
            title="Saldırı Frekans Dağılımı"
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

def threat_signatures(df):
    """Tehdit İmzaları"""
    st.markdown("## 🔐 Tehdit İmzaları ve Signature Analizi")
    
    # Bilinen saldırı imzalarını tanımla
    attack_signatures = {
        'Brute Force SSH': {'ports': ['22'], 'min_attempts': 10},
        'Web Server Attack': {'ports': ['80', '443'], 'min_attempts': 5},
        'Email Server Attack': {'ports': ['25', '110', '143'], 'min_attempts': 3},
        'DNS Attack': {'ports': ['53'], 'min_attempts': 15},
        'FTP Brute Force': {'ports': ['21'], 'min_attempts': 8}
    }
    
    # Port bilgilerini parse et
    def extract_ports(port_str):
        if pd.isna(port_str) or port_str == '-':
            return []
        ports = []
        for item in port_str.split('|'):
            if ':' in item:
                port = item.split(':')[0]
                ports.append(port)
        return ports
    
    df['extracted_ports'] = df['attack_ports'].apply(extract_ports)
    
    # Signature match'leri bul
    signature_matches = []
    
    for attack_type, signature in attack_signatures.items():
        target_ports = set(signature['ports'])
        min_attempts = signature['min_attempts']
        
        for _, row in df.iterrows():
            attack_ports = set(row['extracted_ports'])
            if target_ports.intersection(attack_ports):
                # Bu IP'nin bu port'larda kaç saldırısı var
                ip_attacks = df[(df['ip'] == row['ip'])].shape[0]
                if ip_attacks >= min_attempts:
                    signature_matches.append({
                        'attack_type': attack_type,
                        'ip': row['ip'],
                        'country': row['country'],
                        'risk': row['risk'],
                        'attempts': ip_attacks,
                        'ports': list(attack_ports.intersection(target_ports)),
                        'timestamp': row['timestamp']
                    })
    
    if signature_matches:
        signature_df = pd.DataFrame(signature_matches)
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Signature türlerine göre dağılım
            signature_counts = signature_df['attack_type'].value_counts()
            
            fig = px.bar(
                x=signature_counts.index,
                y=signature_counts.values,
                title="Tespit Edilen Tehdit İmzaları",
                labels={'x': 'Saldırı Türü', 'y': 'Tespit Sayısı'},
                color=signature_counts.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, xaxis_tickangle=-45, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # En tehlikeli signature match'ler
            top_threats = signature_df.nlargest(10, 'risk')[['attack_type', 'ip', 'country', 'risk', 'attempts']]
            
            st.markdown("### 🚨 En Tehlikeli Signature Match'ler")
            st.dataframe(top_threats, use_container_width=True)
    else:
        st.info("Herhangi bir bilinen tehdit imzası tespit edilmedi.")

def custom_hunt_queries(df):
    """Özel Arama Sorguları"""
    st.markdown("## 🔍 Özel Tehdit Avcılığı Sorguları")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.markdown("### 🎯 Hazır Sorgular")
        
        predefined_queries = {
            "Yüksek Risk IP'ler (>80)": "risk > 80",
            "Gece Saldırıları (00:00-06:00)": "hour >= 0 and hour <= 6",
            "Tekrarlayan Saldırılar": "ip_count > 5",
            "Çok Portlu Saldırılar": "port_count > 3",
            "Uzak Coğrafya Saldırıları": "country in ['China', 'Russia', 'Iran']"
        }
        
        selected_query = st.selectbox("Hazır sorgu seçin:", list(predefined_queries.keys()))
        
        if st.button("🚀 Sorguyu Çalıştır"):
            st.session_state.custom_query = predefined_queries[selected_query]
        
        st.markdown("### ✏️ Özel Sorgu")
        custom_query = st.text_area(
            "Kendi sorgunuzu yazın:",
            value=getattr(st.session_state, 'custom_query', ''),
            height=100,
            help="Örnek: risk > 70 and country == 'Russia'"
        )
        
        if st.button("🔍 Özel Sorguyu Çalıştır"):
            st.session_state.query_result = custom_query
    
    with col2:
        st.markdown("### 📊 Sorgu Sonuçları")
        
        # DataFrame'i hazırla
        hunt_df = df.copy()
        hunt_df['hour'] = hunt_df['timestamp'].dt.hour
        hunt_df['ip_count'] = hunt_df.groupby('ip')['ip'].transform('count')
        hunt_df['port_count'] = hunt_df['attack_ports'].apply(
            lambda x: len(x.split('|')) if pd.notna(x) and x != '-' else 0
        )
        
        query_to_run = getattr(st.session_state, 'query_result', 'risk > 70')
        
        try:
            # Güvenlik için eval yerine query kullan
            if query_to_run:
                result = hunt_df.query(query_to_run)
                
                if not result.empty:
                    st.success(f"✅ {len(result)} kayıt bulundu!")
                    
                    # Sonuçları göster
                    display_columns = ['timestamp', 'ip', 'country', 'risk', 'isp', 'attack_ports']
                    st.dataframe(result[display_columns].head(20), use_container_width=True)
                    
                    # İstatistikler
                    col_a, col_b, col_c = st.columns(3)
                    with col_a:
                        st.metric("Bulunan Kayıt", len(result))
                    with col_b:
                        st.metric("Ortalama Risk", f"{result['risk'].mean():.1f}")
                    with col_c:
                        st.metric("Benzersiz IP", result['ip'].nunique())
                else:
                    st.warning("⚠️ Sorgu sonucu bulunamadı.")
        except Exception as e:
            st.error(f"❌ Sorgu hatası: {str(e)}")
        
        # Örnek sorgular rehberi
        st.markdown("### 📝 Sorgu Örnekleri")
        st.code("""
# Yüksek riskli saldırılar
risk > 80

# Belirli ülkelerden saldırılar  
country in ['China', 'Russia', 'Iran']

# Gece saatlerinde saldırılar
hour >= 22 or hour <= 6

# Çoklu port saldırıları
port_count > 2

# Tekrarlayan IP'ler
ip_count > 5

# Kombinasyon sorguları
risk > 70 and country == 'Russia' and hour >= 22
        """)

# Ana fonksiyon
def main():
    df = load_data()
    
    # Threat Hunting Dashboard
    st.markdown("## 🎯 Threat Hunting Dashboard")
    
    # Genel istatistikler
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        high_risk_count = len(df[df['risk'] > 80])
        st.metric("🔴 Kritik Tehditler", high_risk_count)
    
    with col2:
        repeat_attackers = df.groupby('ip').size()
        repeat_count = len(repeat_attackers[repeat_attackers > 5])
        st.metric("🔄 Tekrarlayan Saldırganlar", repeat_count)
    
    with col3:
        unique_countries = df['country'].nunique()
        st.metric("🌍 Tehdit Ülkeleri", unique_countries)
    
    with col4:
        avg_risk = df['risk'].mean()
        st.metric("⚠️ Ortalama Risk", f"{avg_risk:.1f}")
    
    # Ana analiz bölümleri
    ioc_analysis(df)
    behavioral_analysis(df)
    threat_signatures(df)
    custom_hunt_queries(df)

if __name__ == "__main__":
    main()
