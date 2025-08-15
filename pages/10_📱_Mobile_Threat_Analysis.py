import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import random
from datetime import datetime, timedelta

st.set_page_config(
    page_title="📱 Mobile Threat Analysis",
    page_icon="📱",
    layout="wide"
)

st.markdown("# 📱 Mobile Threat Analysis - Mobil Tehdit Analizi")

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

@st.cache_data
def generate_mobile_data(df):
    """Mobil cihaz saldırı verisi oluştur"""
    
    # Mobil User-Agent'lar
    mobile_agents = [
        'Mobile Safari', 'Chrome Mobile', 'Android Browser', 'Samsung Browser',
        'Opera Mobile', 'Firefox Mobile', 'UC Browser', 'Edge Mobile',
        'Baidu Mobile', 'QQ Browser', 'WeChat Browser', 'Mobile App'
    ]
    
    # Mobil platformlar
    mobile_platforms = [
        'Android', 'iOS', 'Windows Mobile', 'BlackBerry', 
        'Symbian', 'Palm OS', 'Other Mobile'
    ]
    
    # Cihaz tipleri
    device_types = [
        'Smartphone', 'Tablet', 'Smart TV', 'IoT Device',
        'Wearable', 'Automotive', 'Industrial IoT'
    ]
    
    # App kategorileri
    app_categories = [
        'Social Media', 'Banking', 'E-commerce', 'Gaming',
        'Messaging', 'News', 'Productivity', 'Entertainment',
        'Health', 'Education', 'Travel', 'Unknown'
    ]
    
    # Mobil saldırı tipleri
    mobile_attack_types = [
        'App-based Malware', 'SMS Phishing', 'Rogue Apps', 'Man-in-the-Middle',
        'WiFi Hijacking', 'Bluetooth Attacks', 'SIM Swapping', 'Mobile Ransomware',
        'Banking Trojans', 'Adware', 'Spyware', 'Fake Apps'
    ]
    
    mobile_data = []
    
    for _, row in df.iterrows():
        # Mobil veri oluştur (tüm saldırıların %30'u mobil olsun)
        if random.random() < 0.3:
            mobile_data.append({
                'ip': row['ip'],
                'timestamp': row['timestamp'],
                'risk': row['risk'],
                'country': row['country'],
                'city': row['city'],
                'isp': row['isp'],
                'user_agent': random.choice(mobile_agents),
                'platform': random.choice(mobile_platforms),
                'device_type': random.choice(device_types),
                'app_category': random.choice(app_categories),
                'attack_type': random.choice(mobile_attack_types),
                'screen_resolution': random.choice([
                    '360x640', '375x667', '414x736', '360x780',
                    '375x812', '414x896', '768x1024', '1024x768'
                ]),
                'os_version': f"{random.choice(['12', '13', '14', '15', '16'])}.{random.randint(0, 9)}",
                'app_version': f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
                'jailbroken': random.choice([True, False]),
                'vpn_detected': random.choice([True, False])
            })
    
    return pd.DataFrame(mobile_data)

def mobile_device_analysis(mobile_df):
    """Mobil Cihaz Analizi"""
    st.markdown("## 📱 Mobil Cihaz Saldırı Analizi")
    
    if mobile_df.empty:
        st.warning("Mobil saldırı verisi bulunamadı.")
        return
    
    tab1, tab2, tab3 = st.tabs(["📊 Platform Analysis", "📱 Device Types", "🔧 Technical Details"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Platform dağılımı
            platform_dist = mobile_df['platform'].value_counts()
            
            fig = px.pie(
                values=platform_dist.values,
                names=platform_dist.index,
                title="Mobil Platform Dağılımı",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            # Platform risk analizi
            platform_risk = mobile_df.groupby('platform').agg({
                'risk': ['mean', 'max', 'count']
            }).round(2)
            platform_risk.columns = ['Avg Risk', 'Max Risk', 'Attack Count']
            platform_risk = platform_risk.sort_values('Avg Risk', ascending=False)
            
            st.markdown("#### 📊 Platform Risk Analizi")
            st.dataframe(platform_risk, use_container_width=True)
        
        with col2:
            # User Agent analizi
            ua_dist = mobile_df['user_agent'].value_counts().head(10)
            
            fig = px.bar(
                x=ua_dist.values,
                y=ua_dist.index,
                orientation='h',
                title="Top 10 Mobil User Agent",
                labels={'x': 'Saldırı Sayısı', 'y': 'User Agent'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            # OS Version analizi
            os_version_risk = mobile_df.groupby('os_version')['risk'].mean().sort_values(ascending=False).head(10)
            
            fig = px.bar(
                x=os_version_risk.index,
                y=os_version_risk.values,
                title="OS Version Risk Analizi",
                labels={'x': 'OS Version', 'y': 'Ortalama Risk'},
                color=os_version_risk.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            # Cihaz tipi analizi
            device_analysis = mobile_df.groupby('device_type').agg({
                'risk': ['mean', 'count'],
                'jailbroken': lambda x: (x == True).sum(),
                'vpn_detected': lambda x: (x == True).sum()
            }).round(2)
            device_analysis.columns = ['Avg Risk', 'Attack Count', 'Jailbroken', 'VPN Detected']
            
            st.markdown("#### 📱 Cihaz Tipi Analizi")
            st.dataframe(device_analysis, use_container_width=True)
            
            # Jailbroken vs Normal cihazlar
            jailbreak_comparison = mobile_df.groupby('jailbroken')['risk'].mean()
            
            fig = px.bar(
                x=['Normal Device', 'Jailbroken Device'],
                y=[jailbreak_comparison[False], jailbreak_comparison[True]],
                title="Jailbroken vs Normal Cihaz Risk Karşılaştırması",
                labels={'x': 'Cihaz Durumu', 'y': 'Ortalama Risk'},
                color=[jailbreak_comparison[False], jailbreak_comparison[True]],
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Ekran çözünürlüğü analizi
            resolution_dist = mobile_df['screen_resolution'].value_counts()
            
            fig = px.pie(
                values=resolution_dist.values,
                names=resolution_dist.index,
                title="Ekran Çözünürlüğü Dağılımı",
                hole=0.4
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            # VPN kullanımı analizi
            vpn_usage = mobile_df['vpn_detected'].value_counts()
            
            fig = px.bar(
                x=['VPN Yok', 'VPN Var'],
                y=[vpn_usage[False], vpn_usage[True]],
                title="VPN Kullanımı",
                labels={'x': 'VPN Durumu', 'y': 'Saldırı Sayısı'},
                color=['#2E86AB', '#A23B72']
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Teknik detaylar
        st.markdown("#### 🔧 Teknik Risk Faktörleri")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            jailbroken_count = mobile_df['jailbroken'].sum()
            st.metric("🔓 Jailbroken Cihazlar", jailbroken_count)
        
        with col2:
            vpn_count = mobile_df['vpn_detected'].sum()
            st.metric("🔒 VPN Kullanımı", vpn_count)
        
        with col3:
            high_risk_mobile = len(mobile_df[mobile_df['risk'] > 70])
            st.metric("⚠️ Yüksek Riskli Mobil", high_risk_mobile)
        
        # Detaylı teknik analiz tablosu
        technical_analysis = mobile_df[['platform', 'device_type', 'os_version', 'jailbroken', 'vpn_detected', 'risk']].copy()
        technical_analysis['risk_category'] = technical_analysis['risk'].apply(
            lambda x: 'High' if x > 70 else 'Medium' if x > 40 else 'Low'
        )
        
        st.markdown("#### 📋 Detaylı Teknik Analiz")
        st.dataframe(technical_analysis.head(20), use_container_width=True)

def app_based_threats(mobile_df):
    """Uygulama Bazlı Tehditler"""
    st.markdown("## 📱 Uygulama Bazlı Tehdit Analizi")
    
    if mobile_df.empty:
        st.warning("Mobil uygulama verisi bulunamadı.")
        return
    
    tab1, tab2, tab3 = st.tabs(["📊 App Categories", "🦠 Attack Types", "🔍 Threat Intelligence"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Uygulama kategorisi risk analizi
            app_risk = mobile_df.groupby('app_category').agg({
                'risk': ['mean', 'max', 'count']
            }).round(2)
            app_risk.columns = ['Avg Risk', 'Max Risk', 'Attack Count']
            app_risk = app_risk.sort_values('Avg Risk', ascending=False)
            
            st.markdown("#### 📱 Uygulama Kategorisi Risk Analizi")
            st.dataframe(app_risk, use_container_width=True)
            
            # En riskli kategoriler
            top_risky_apps = app_risk.head(6)
            
            fig = px.bar(
                x=top_risky_apps.index,
                y=top_risky_apps['Avg Risk'],
                title="En Riskli Uygulama Kategorileri",
                labels={'x': 'Kategori', 'y': 'Ortalama Risk'},
                color=top_risky_apps['Avg Risk'],
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, xaxis_tickangle=-45, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Uygulama sürümü analizi
            app_version_risk = mobile_df.groupby('app_version')['risk'].mean().sort_values(ascending=False).head(10)
            
            fig = px.scatter(
                x=app_version_risk.index,
                y=app_version_risk.values,
                size=[20] * len(app_version_risk),
                title="Uygulama Sürümü Risk Analizi",
                labels={'x': 'App Version', 'y': 'Ortalama Risk'},
                color=app_version_risk.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
            
            # Kategori dağılımı
            category_dist = mobile_df['app_category'].value_counts()
            
            fig = px.pie(
                values=category_dist.values,
                names=category_dist.index,
                title="Uygulama Kategorisi Dağılımı",
                hole=0.3
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            # Saldırı tipi analizi
            attack_analysis = mobile_df.groupby('attack_type').agg({
                'risk': ['mean', 'count'],
                'platform': lambda x: x.mode().iloc[0] if not x.empty else 'Unknown'
            }).round(2)
            attack_analysis.columns = ['Avg Risk', 'Attack Count', 'Primary Platform']
            attack_analysis = attack_analysis.sort_values('Avg Risk', ascending=False)
            
            st.markdown("#### 🦠 Mobil Saldırı Tipleri")
            st.dataframe(attack_analysis, use_container_width=True)
        
        with col2:
            # Saldırı tipi dağılımı
            attack_dist = mobile_df['attack_type'].value_counts().head(8)
            
            fig = px.bar(
                x=attack_dist.values,
                y=attack_dist.index,
                orientation='h',
                title="Mobil Saldırı Tipi Dağılımı",
                labels={'x': 'Saldırı Sayısı', 'y': 'Saldırı Tipi'},
                color=attack_dist.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Threat Intelligence
        st.markdown("#### 🔍 Mobil Tehdit İstihbaratı")
        
        # Tehdit özeti
        threat_summary = {
            'Toplam Mobil Saldırı': len(mobile_df),
            'Benzersiz Uygulama': mobile_df['app_category'].nunique(),
            'En Riskli Platform': mobile_df.groupby('platform')['risk'].mean().idxmax(),
            'En Tehlikeli Saldırı': mobile_df.groupby('attack_type')['risk'].mean().idxmax()
        }
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("📱 Toplam Mobil Saldırı", threat_summary['Toplam Mobil Saldırı'])
        with col2:
            st.metric("📊 Benzersiz Uygulama", threat_summary['Benzersiz Uygulama'])
        with col3:
            st.metric("⚠️ En Riskli Platform", threat_summary['En Riskli Platform'])
        with col4:
            st.metric("🎯 En Tehlikeli Saldırı", threat_summary['En Tehlikeli Saldırı'])
        
        # IOC'ler (Indicators of Compromise)
        st.markdown("#### 🚨 Mobil IOC'ler")
        
        mobile_iocs = []
        
        # Yüksek riskli kombinasyonlar
        high_risk_combinations = mobile_df[mobile_df['risk'] > 80].groupby(['platform', 'attack_type']).size().sort_values(ascending=False).head(10)
        
        for (platform, attack_type), count in high_risk_combinations.items():
            mobile_iocs.append({
                'IOC Type': 'Platform-Attack Combination',
                'Indicator': f"{platform} + {attack_type}",
                'Risk Level': 'High',
                'Occurrences': count,
                'Recommended Action': 'Block/Monitor'
            })
        
        # Jailbroken cihazlardan gelen saldırılar
        jailbroken_attacks = mobile_df[mobile_df['jailbroken'] == True]
        if not jailbroken_attacks.empty:
            for platform in jailbroken_attacks['platform'].unique():
                count = len(jailbroken_attacks[jailbroken_attacks['platform'] == platform])
                mobile_iocs.append({
                    'IOC Type': 'Jailbroken Device',
                    'Indicator': f"Jailbroken {platform}",
                    'Risk Level': 'High',
                    'Occurrences': count,
                    'Recommended Action': 'Enhanced Monitoring'
                })
        
        if mobile_iocs:
            ioc_df = pd.DataFrame(mobile_iocs)
            st.dataframe(ioc_df, use_container_width=True)

def location_based_analysis(mobile_df):
    """Konum Bazlı Mobil Analiz"""
    st.markdown("## 📍 Konum Bazlı Mobil Analiz")
    
    if mobile_df.empty:
        st.warning("Konum verisi bulunamadı.")
        return
    
    tab1, tab2 = st.tabs(["🌍 Geographic Distribution", "🏙️ City Analysis"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Ülke bazlı mobil saldırı analizi
            country_mobile = mobile_df.groupby('country').agg({
                'risk': ['mean', 'count'],
                'platform': lambda x: x.mode().iloc[0] if not x.empty else 'Unknown'
            }).round(2)
            country_mobile.columns = ['Avg Risk', 'Attack Count', 'Primary Platform']
            country_mobile = country_mobile.sort_values('Avg Risk', ascending=False)
            
            st.markdown("#### 🌍 Ülke Bazlı Mobil Saldırılar")
            st.dataframe(country_mobile.head(15), use_container_width=True)
        
        with col2:
            # Coğrafi risk dağılımı
            if not country_mobile.empty:
                fig = px.choropleth(
                    locations=country_mobile.index,
                    color=country_mobile['Avg Risk'],
                    locationmode='country names',
                    title="Mobil Saldırı Risk Haritası",
                    color_continuous_scale="Reds",
                    labels={'color': 'Avg Risk'}
                )
                fig.update_layout(height=500)
                st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Şehir bazlı analiz
        city_mobile = mobile_df.groupby(['country', 'city']).agg({
            'risk': ['mean', 'count']
        }).round(2)
        city_mobile.columns = ['Avg Risk', 'Attack Count']
        city_mobile = city_mobile.sort_values('Avg Risk', ascending=False)
        
        st.markdown("#### 🏙️ Şehir Bazlı Mobil Saldırılar")
        st.dataframe(city_mobile.head(20), use_container_width=True)

def mobile_security_recommendations(mobile_df):
    """Mobil Güvenlik Önerileri"""
    st.markdown("## 🛡️ Mobil Güvenlik Önerileri")
    
    if mobile_df.empty:
        st.warning("Öneri için yeterli veri bulunamadı.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📱 Platform Bazlı Öneriler")
        
        platform_recommendations = []
        
        for platform in mobile_df['platform'].unique():
            platform_data = mobile_df[mobile_df['platform'] == platform]
            avg_risk = platform_data['risk'].mean()
            attack_count = len(platform_data)
            jailbroken_count = platform_data['jailbroken'].sum()
            
            if avg_risk > 70:
                recommendation = "🔴 Yüksek Risk - Sıkı güvenlik kontrolü gerekli"
                priority = "High"
            elif avg_risk > 50:
                recommendation = "🟠 Orta Risk - Gelişmiş monitoring önerili"
                priority = "Medium"
            else:
                recommendation = "🟢 Düşük Risk - Standart güvenlik yeterli"
                priority = "Low"
            
            platform_recommendations.append({
                'Platform': platform,
                'Avg Risk': round(avg_risk, 2),
                'Attacks': attack_count,
                'Jailbroken': jailbroken_count,
                'Priority': priority,
                'Recommendation': recommendation
            })
        
        platform_rec_df = pd.DataFrame(platform_recommendations).sort_values('Avg Risk', ascending=False)
        st.dataframe(platform_rec_df, use_container_width=True)
    
    with col2:
        st.markdown("### 🔧 Teknik Öneriler")
        
        technical_recommendations = [
            "🔐 Jailbroken/Rooted cihazları engelle",
            "📱 Uygulama imza doğrulaması zorunlu kıl",
            "🔒 SSL Pinning uygula",
            "👤 Biyometrik kimlik doğrulama kullan",
            "🔄 Düzenli güvenlik güncellemeleri",
            "📊 Runtime Application Self-Protection (RASP)",
            "🚫 Sandbox kaçış koruması",
            "🔍 Davranışsal analiz sistemi"
        ]
        
        for i, recommendation in enumerate(technical_recommendations, 1):
            st.markdown(f"{i}. {recommendation}")
        
        # Güvenlik skoru hesapla
        total_attacks = len(mobile_df)
        high_risk_attacks = len(mobile_df[mobile_df['risk'] > 70])
        jailbroken_attacks = mobile_df['jailbroken'].sum()
        
        security_score = max(0, 100 - (high_risk_attacks / total_attacks * 50) - (jailbroken_attacks / total_attacks * 30))
        
        st.markdown("### 📊 Mobil Güvenlik Skoru")
        st.metric("🏆 Güvenlik Skoru", f"{security_score:.1f}/100")
        
        if security_score >= 80:
            st.success("✅ Mobil güvenlik durumu iyi")
        elif security_score >= 60:
            st.warning("⚠️ Mobil güvenlik iyileştirmesi gerekli")
        else:
            st.error("🚨 Kritik mobil güvenlik sorunları mevcut")

# Ana fonksiyon
def main():
    df = load_data()
    mobile_df = generate_mobile_data(df)
    
    # Genel mobil istatistikler
    if not mobile_df.empty:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("📱 Toplam Mobil Saldırı", len(mobile_df))
        
        with col2:
            avg_mobile_risk = mobile_df['risk'].mean()
            st.metric("⚠️ Ortalama Risk", f"{avg_mobile_risk:.1f}")
        
        with col3:
            unique_platforms = mobile_df['platform'].nunique()
            st.metric("📊 Platform Sayısı", unique_platforms)
        
        with col4:
            jailbroken_rate = (mobile_df['jailbroken'].sum() / len(mobile_df)) * 100
            st.metric("🔓 Jailbroken Oranı", f"{jailbroken_rate:.1f}%")
        
        # Ana analiz bölümleri
        mobile_device_analysis(mobile_df)
        app_based_threats(mobile_df)
        location_based_analysis(mobile_df)
        mobile_security_recommendations(mobile_df)
    else:
        st.warning("Mobil saldırı verisi oluşturulamadı.")

if __name__ == "__main__":
    main()
