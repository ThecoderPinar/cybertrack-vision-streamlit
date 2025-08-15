import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json

st.set_page_config(
    page_title="📊 Raporlar",
    page_icon="📊",
    layout="wide"
)

st.markdown("# 📊 Raporlar ve Dışa Aktarma")

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

def executive_summary(df):
    """Yönetici özeti"""
    st.markdown("## 👔 Yönetici Özeti")
    
    # Ana metrikler
    total_attacks = len(df)
    unique_ips = df['ip'].nunique()
    avg_risk = df['risk'].mean()
    high_risk_attacks = len(df[df['risk'] > 70])
    countries_affected = df['country'].nunique()
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Toplam Saldırı", f"{total_attacks:,}")
    with col2:
        st.metric("Benzersiz IP", f"{unique_ips:,}")
    with col3:
        st.metric("Ortalama Risk", f"{avg_risk:.1f}")
    with col4:
        st.metric("Yüksek Risk Saldırı", f"{high_risk_attacks:,}")
    with col5:
        st.metric("Etkilenen Ülke", countries_affected)
    
    # Özet değerlendirme
    st.markdown("### 📈 Durum Değerlendirmesi")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Risk seviyesi değerlendirmesi
        high_risk_percentage = (high_risk_attacks / total_attacks) * 100
        
        if high_risk_percentage > 20:
            risk_status = "🔴 Kritik"
            risk_message = f"Saldırıların %{high_risk_percentage:.1f}'si yüksek riskli. Acil müdahale gerekli."
        elif high_risk_percentage > 10:
            risk_status = "🟡 Orta"
            risk_message = f"Saldırıların %{high_risk_percentage:.1f}'si yüksek riskli. İzleme artırılmalı."
        else:
            risk_status = "🟢 Düşük"
            risk_message = f"Saldırıların %{high_risk_percentage:.1f}'si yüksek riskli. Durum kontrol altında."
        
        st.markdown(f"**Risk Durumu:** {risk_status}")
        st.markdown(risk_message)
    
    with col2:
        # Coğrafi dağılım değerlendirmesi
        top_country_attacks = df['country'].value_counts().iloc[0]
        top_country = df['country'].value_counts().index[0]
        country_concentration = (top_country_attacks / total_attacks) * 100
        
        if country_concentration > 30:
            geo_status = "🔴 Yoğunlaşmış"
            geo_message = f"Saldırıların %{country_concentration:.1f}'si {top_country}'den. Coğrafi filtreleme önerilir."
        else:
            geo_status = "🟢 Dağıtık"
            geo_message = f"Saldırılar {countries_affected} ülkeye dağılmış. Coğrafi çeşitlilik yüksek."
        
        st.markdown(f"**Coğrafi Durum:** {geo_status}")
        st.markdown(geo_message)

def detailed_analysis_report(df):
    """Detaylı analiz raporu"""
    st.markdown("## 📋 Detaylı Analiz Raporu")
    
    tab1, tab2, tab3, tab4 = st.tabs(["🌍 Coğrafi", "🕐 Zamansal", "🌐 Ağ", "⚠️ Risk"])
    
    with tab1:
        st.markdown("### 🌍 Coğrafi Analiz")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # En çok saldırı alan ülkeler
            top_countries = df['country'].value_counts().head(10)
            
            fig = px.bar(
                x=top_countries.values,
                y=top_countries.index,
                orientation='h',
                title="En Çok Saldırı Alan Ülkeler (Top 10)",
                labels={'x': 'Saldırı Sayısı', 'y': 'Ülke'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Risk haritası
            country_risk = df.groupby('country')['risk'].mean().head(10)
            
            fig = px.bar(
                x=country_risk.values,
                y=country_risk.index,
                orientation='h',
                title="En Yüksek Ortalama Risk (Top 10)",
                labels={'x': 'Ortalama Risk', 'y': 'Ülke'},
                color=country_risk.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        # Coğrafi istatistikler tablosu
        geo_stats = df.groupby('country').agg({
            'ip': ['count', 'nunique'],
            'risk': ['mean', 'max']
        }).round(2)
        geo_stats.columns = ['Toplam Saldırı', 'Benzersiz IP', 'Ortalama Risk', 'Max Risk']
        geo_stats = geo_stats.sort_values('Toplam Saldırı', ascending=False).head(15)
        
        st.markdown("#### 📊 Ülke Bazlı İstatistikler")
        st.dataframe(geo_stats, use_container_width=True)
    
    with tab2:
        st.markdown("### 🕐 Zamansal Analiz")
        
        # Saatlik ve günlük trendler
        col1, col2 = st.columns(2)
        
        with col1:
            hourly_attacks = df['timestamp'].dt.hour.value_counts().sort_index()
            
            fig = px.line(
                x=hourly_attacks.index,
                y=hourly_attacks.values,
                title="Saatlik Saldırı Dağılımı",
                labels={'x': 'Saat', 'y': 'Saldırı Sayısı'},
                markers=True
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            daily_attacks = df['timestamp'].dt.day_name().value_counts()
            day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            daily_attacks = daily_attacks.reindex(day_order)
            
            fig = px.bar(
                x=daily_attacks.index,
                y=daily_attacks.values,
                title="Günlük Saldırı Dağılımı",
                labels={'x': 'Gün', 'y': 'Saldırı Sayısı'}
            )
            fig.update_layout(height=400, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        # Zaman bazlı içgörüler
        peak_hour = hourly_attacks.idxmax()
        peak_day = daily_attacks.idxmax()
        
        st.markdown("#### ⏰ Zaman Bazlı İçgörüler")
        st.write(f"• **En yoğun saat:** {peak_hour}:00 ({hourly_attacks[peak_hour]} saldırı)")
        st.write(f"• **En yoğun gün:** {peak_day} ({daily_attacks[peak_day]} saldırı)")
        st.write(f"• **Gece saldırıları (00:00-06:00):** {hourly_attacks[0:6].sum()} saldırı")
        st.write(f"• **İş saatleri saldırıları (09:00-17:00):** {hourly_attacks[9:18].sum()} saldırı")
    
    with tab3:
        st.markdown("### 🌐 Ağ Analizi")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # ISP analizi
            top_isps = df['isp'].value_counts().head(10)
            
            fig = px.pie(
                values=top_isps.values,
                names=top_isps.index,
                title="ISP Dağılımı (Top 10)"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # ASN analizi
            top_asns = df['asn_name'].value_counts().head(8)
            
            fig = px.bar(
                x=top_asns.index,
                y=top_asns.values,
                title="En Aktif ASN'ler",
                labels={'x': 'ASN', 'y': 'Saldırı Sayısı'}
            )
            fig.update_layout(height=400, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        # Ağ istatistikleri
        network_stats = {
            'Toplam ISP': df['isp'].nunique(),
            'Toplam ASN': df['asn'].nunique(),
            'En aktif ISP': df['isp'].value_counts().index[0],
            'En aktif ASN': df['asn_name'].value_counts().index[0]
        }
        
        st.markdown("#### 🌐 Ağ İstatistikleri")
        for key, value in network_stats.items():
            st.write(f"• **{key}:** {value}")
    
    with tab4:
        st.markdown("### ⚠️ Risk Analizi")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk kategorisi dağılımı
            risk_dist = df['risk_category_en'].value_counts()
            
            fig = px.pie(
                values=risk_dist.values,
                names=risk_dist.index,
                title="Risk Kategorisi Dağılımı",
                color_discrete_map={'High': '#ff6b6b', 'Medium': '#feca57', 'Low': '#48dbfb'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Risk skoru dağılımı
            fig = px.histogram(
                df,
                x='risk',
                nbins=20,
                title="Risk Skoru Dağılımı",
                labels={'risk': 'Risk Skoru', 'count': 'Frekans'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        # Risk istatistikleri
        risk_stats = df['risk'].describe()
        
        st.markdown("#### 📊 Risk İstatistikleri")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Ortalama Risk", f"{risk_stats['mean']:.1f}")
        with col2:
            st.metric("Medyan Risk", f"{risk_stats['50%']:.1f}")
        with col3:
            st.metric("Maksimum Risk", f"{risk_stats['max']:.0f}")
        with col4:
            st.metric("Standart Sapma", f"{risk_stats['std']:.1f}")

def threat_intelligence_report(df):
    """Tehdit istihbaratı raporu"""
    st.markdown("## 🎯 Tehdit İstihbaratı Raporu")
    
    # En tehlikeli IP'ler
    st.markdown("### 🚨 En Tehlikeli IP Adresleri")
    
    dangerous_ips = df.nlargest(20, 'risk')[['ip', 'country', 'risk', 'isp', 'timestamp']]
    dangerous_ips['timestamp'] = dangerous_ips['timestamp'].dt.strftime('%Y-%m-%d %H:%M')
    
    st.dataframe(dangerous_ips, use_container_width=True)
    
    # Saldırı pattern'leri
    st.markdown("### 🔍 Saldırı Desenleri")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Port analizi
        all_ports = []
        for ports_str in df['attack_ports'].dropna():
            if ports_str != '-':
                for port_info in ports_str.split('|'):
                    if ':' in port_info:
                        port = port_info.split(':')[0]
                        all_ports.append(port)
        
        if all_ports:
            from collections import Counter
            port_counts = Counter(all_ports)
            top_ports = dict(port_counts.most_common(10))
            
            fig = px.bar(
                x=list(top_ports.keys()),
                y=list(top_ports.values()),
                title="En Çok Hedeflenen Portlar",
                labels={'x': 'Port', 'y': 'Saldırı Sayısı'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Saat bazlı saldırı yoğunluğu
        all_hours = []
        for hours_str in df['attack_hours'].dropna():
            if hours_str != '-':
                for hour_info in hours_str.split('|'):
                    if ':' in hour_info:
                        hour = hour_info.split(':')[0]
                        all_hours.append(hour)
        
        if all_hours:
            hour_counts = Counter(all_hours)
            top_hours = dict(hour_counts.most_common(10))
            
            fig = px.bar(
                x=list(top_hours.keys()),
                y=list(top_hours.values()),
                title="En Aktif Saldırı Saatleri",
                labels={'x': 'Saat', 'y': 'Saldırı Sayısı'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    # Öneriler
    st.markdown("### 💡 Güvenlik Önerileri")
    
    recommendations = [
        "🔥 Yüksek riskli IP adreslerini blacklist'e ekleyin",
        "🌍 Anormal yüksek saldırı alan ülkelerden trafik filtrelemesi uygulayın",
        "🔌 En çok hedeflenen portlarda ek güvenlik önlemleri alın",
        "⏰ Yoğun saldırı saatlerinde monitoring'i artırın",
        "🚨 Risk skoru 70'in üzerindeki aktiviteleri gerçek zamanlı izleyin"
    ]
    
    for rec in recommendations:
        st.write(rec)

def export_options(df):
    """Dışa aktarma seçenekleri"""
    st.markdown("## 📤 Veri Dışa Aktarma")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("### 📊 CSV Dışa Aktarma")
        
        # Filtreleme seçenekleri
        export_risk_filter = st.selectbox(
            "Risk seviyesi filtresi:",
            ['Tümü'] + list(df['risk_category_en'].unique())
        )
        
        if export_risk_filter != 'Tümü':
            filtered_df = df[df['risk_category_en'] == export_risk_filter]
        else:
            filtered_df = df
        
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="📊 CSV İndir",
            data=csv,
            file_name=f"cybertrack_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        
        st.info(f"İndirilecek kayıt sayısı: {len(filtered_df):,}")
    
    with col2:
        st.markdown("### 📋 Özet Rapor")
        
        # Özet rapor oluştur
        summary_report = f"""
CyberTrack Vision - Güvenlik Analiz Raporu
==========================================
Rapor Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

GENEL İSTATİSTİKLER
-------------------
• Toplam Saldırı: {len(df):,}
• Benzersiz IP: {df['ip'].nunique():,}
• Etkilenen Ülke: {df['country'].nunique()}
• Ortalama Risk Skoru: {df['risk'].mean():.2f}

RİSK DAĞILIMI
-------------
{df['risk_category_en'].value_counts().to_string()}

EN ÇOK SALDIRI ALAN ÜLKELER
---------------------------
{df['country'].value_counts().head(10).to_string()}

EN RİSKLİ ISP'LER
-----------------
{df.groupby('isp')['risk'].mean().sort_values(ascending=False).head(10).to_string()}

ZAMAN ANALİZİ
-------------
• En yoğun saat: {df['timestamp'].dt.hour.value_counts().index[0]}:00
• En yoğun gün: {df['timestamp'].dt.day_name().value_counts().index[0]}

ÖNERİLER
--------
• Risk skoru 70'in üzerindeki IP'leri izleyin
• Anormal yüksek aktivite gösteren ülkelerden filtreleme uygulayın
• Yoğun saatlerde ek güvenlik önlemleri alın
• Düzenli anomali tespiti yapın

Bu rapor CyberTrack Vision tarafından otomatik olarak oluşturulmuştur.
        """
        
        st.download_button(
            label="📋 Rapor İndir",
            data=summary_report,
            file_name=f"cybertrack_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )
    
    with col3:
        st.markdown("### 🔧 JSON Dışa Aktarma")
        
        # JSON formatında detaylı veri
        json_data = {
            "report_info": {
                "generated_at": datetime.now().isoformat(),
                "total_records": len(df),
                "date_range": {
                    "start": df['timestamp'].min().isoformat(),
                    "end": df['timestamp'].max().isoformat()
                }
            },
            "statistics": {
                "total_attacks": len(df),
                "unique_ips": df['ip'].nunique(),
                "countries_affected": df['country'].nunique(),
                "average_risk": round(df['risk'].mean(), 2),
                "risk_distribution": df['risk_category_en'].value_counts().to_dict()
            },
            "top_threats": {
                "countries": df['country'].value_counts().head(10).to_dict(),
                "isps": df['isp'].value_counts().head(10).to_dict(),
                "high_risk_ips": df[df['risk'] > 70]['ip'].tolist()
            }
        }
        
        json_str = json.dumps(json_data, indent=2, ensure_ascii=False)
        
        st.download_button(
            label="🔧 JSON İndir",
            data=json_str,
            file_name=f"cybertrack_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

def scheduled_reports():
    """Zamanlanmış raporlar"""
    st.markdown("## ⏰ Zamanlanmış Raporlar")
    
    st.markdown("""
    ### 📅 Otomatik Rapor Planlaması
    
    Sistem düzenli aralıklarla otomatik raporlar oluşturabilir:
    
    **Günlük Raporlar:**
    • Günlük saldırı özeti
    • Yeni tehditler
    • Risk değişimleri
    
    **Haftalık Raporlar:**
    • Haftalık trend analizi
    • ISP performans raporu
    • Coğrafi değişimler
    
    **Aylık Raporlar:**
    • Kapsamlı güvenlik değerlendirmesi
    • Strateji önerileri
    • ROI analizi
    """)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### ⚙️ Rapor Ayarları")
        
        report_frequency = st.selectbox(
            "Rapor sıklığı:",
            ["Günlük", "Haftalık", "Aylık"]
        )
        
        report_format = st.multiselect(
            "Rapor formatları:",
            ["PDF", "Excel", "CSV", "JSON"],
            default=["PDF"]
        )
        
        email_recipients = st.text_area(
            "E-posta alıcıları (virgülle ayırın):",
            placeholder="admin@company.com, security@company.com"
        )
        
        if st.button("📧 Rapor Planlamasını Etkinleştir"):
            st.success("✅ Rapor planlaması başarıyla etkinleştirildi!")
    
    with col2:
        st.markdown("#### 📊 Rapor Önizlemesi")
        
        st.info("""
        **Günlük Özet Raporu Örneği:**
        
        📅 Tarih: 2025-08-05
        🎯 Toplam Saldırı: 1,247
        ⚠️ Yüksek Risk: 127
        🌍 Yeni Ülke: 2
        📈 Risk Artışı: %12
        
        **En Kritik Tehditler:**
        • 192.168.1.100 (Risk: 95)
        • 10.0.0.50 (Risk: 87)
        
        **Önerilen Aksiyonlar:**
        • IP blacklist güncelleme
        • Firewall kuralları gözden geçirme
        """)

# Ana fonksiyon
def main():
    df = load_data()
    
    # Rapor türü seçimi
    st.sidebar.markdown("## 📊 Rapor Türü")
    report_type = st.sidebar.selectbox(
        "Rapor türünü seçin:",
        ["Yönetici Özeti", "Detaylı Analiz", "Tehdit İstihbaratı", "Veri Dışa Aktarma", "Zamanlanmış Raporlar"]
    )
    
    if report_type == "Yönetici Özeti":
        executive_summary(df)
    elif report_type == "Detaylı Analiz":
        detailed_analysis_report(df)
    elif report_type == "Tehdit İstihbaratı":
        threat_intelligence_report(df)
    elif report_type == "Veri Dışa Aktarma":
        export_options(df)
    else:
        scheduled_reports()

if __name__ == "__main__":
    main()
