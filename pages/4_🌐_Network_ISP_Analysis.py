import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from collections import Counter
import re

st.set_page_config(
    page_title="🌐 Ağ ve ISP Analizi",
    page_icon="🌐",
    layout="wide"
)

st.markdown("# 🌐 Ağ ve ISP Güvenlik Analizi")

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
    
    # Port bilgilerini parse et
    def parse_ports(port_str):
        if pd.isna(port_str) or port_str == '-':
            return []
        ports = []
        for item in port_str.split('|'):
            if ':' in item:
                port = item.split(':')[0]
                ports.append(port)
        return ports
    
    df['parsed_ports'] = df['attack_ports'].apply(parse_ports)
    
    return df

def isp_analysis(df):
    """ISP analizi"""
    st.markdown("## 🏢 İnternet Servis Sağlayıcıları (ISP) Analizi")
    
    tab1, tab2, tab3 = st.tabs(["📊 Genel ISP İstatistikleri", "⚠️ Risk Analizi", "🔍 Detaylı İnceleme"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # En çok saldırı yapan ISP'ler
            isp_attacks = df['isp'].value_counts().head(15)
            
            fig = px.bar(
                x=isp_attacks.values,
                y=isp_attacks.index,
                orientation='h',
                title="En Çok Saldırı Kaynaklı ISP'ler",
                labels={'x': 'Saldırı Sayısı', 'y': 'ISP'},
                color=isp_attacks.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # ISP'lere göre benzersiz IP sayısı
            isp_unique_ips = df.groupby('isp')['ip'].nunique().sort_values(ascending=False).head(15)
            
            fig = px.bar(
                x=isp_unique_ips.values,
                y=isp_unique_ips.index,
                orientation='h',
                title="ISP'lere Göre Benzersiz IP Sayısı",
                labels={'x': 'Benzersiz IP Sayısı', 'y': 'ISP'},
                color=isp_unique_ips.values,
                color_continuous_scale="Blues"
            )
            fig.update_layout(height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            # ISP'lere göre ortalama risk skoru
            isp_risk = df.groupby('isp')['risk'].mean().sort_values(ascending=False).head(15)
            
            fig = px.bar(
                x=isp_risk.values,
                y=isp_risk.index,
                orientation='h',
                title="En Yüksek Ortalama Risk Skoruna Sahip ISP'ler",
                labels={'x': 'Ortalama Risk Skoru', 'y': 'ISP'},
                color=isp_risk.values,
                color_continuous_scale="Oranges"
            )
            fig.update_layout(height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Risk kategorileri ve ISP ilişkisi
            risk_isp = df.groupby(['isp', 'risk_category_en']).size().unstack(fill_value=0)
            top_isps = df['isp'].value_counts().head(8).index
            risk_isp_top = risk_isp.loc[top_isps]
            
            fig = px.bar(
                risk_isp_top.reset_index(),
                x='isp',
                y=['Low', 'Medium', 'High'],
                title="Top ISP'lerde Risk Kategorisi Dağılımı",
                labels={'value': 'Saldırı Sayısı', 'variable': 'Risk Kategorisi'},
                color_discrete_map={'Low': '#48dbfb', 'Medium': '#feca57', 'High': '#ff6b6b'}
            )
            fig.update_layout(height=500, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # ISP seçimi
        selected_isp = st.selectbox(
            "Detaylı analiz için ISP seçin:",
            options=sorted(df['isp'].unique())
        )
        
        if selected_isp:
            isp_data = df[df['isp'] == selected_isp]
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Toplam Saldırı", len(isp_data))
                st.metric("Benzersiz IP", isp_data['ip'].nunique())
            
            with col2:
                st.metric("Ortalama Risk", f"{isp_data['risk'].mean():.1f}")
                st.metric("Maksimum Risk", isp_data['risk'].max())
            
            with col3:
                st.metric("Etkilenen Ülke", isp_data['country'].nunique())
                st.metric("ASN Sayısı", isp_data['asn'].nunique())
            
            # ISP'nin ülke dağılımı
            col1, col2 = st.columns(2)
            
            with col1:
                country_dist = isp_data['country'].value_counts().head(10)
                fig = px.pie(
                    values=country_dist.values,
                    names=country_dist.index,
                    title=f"{selected_isp} - Ülke Dağılımı"
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Zamansal trend
                daily_attacks = isp_data.groupby(isp_data['timestamp'].dt.date).size()
                fig = px.line(
                    x=daily_attacks.index,
                    y=daily_attacks.values,
                    title=f"{selected_isp} - Günlük Saldırı Trendi",
                    labels={'x': 'Tarih', 'y': 'Saldırı Sayısı'}
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)

def asn_analysis(df):
    """ASN analizi"""
    st.markdown("## 🔢 Otonom Sistem Numarası (ASN) Analizi")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # En çok saldırı yapan ASN'ler
        asn_attacks = df['asn_name'].value_counts().head(15)
        
        fig = px.bar(
            x=asn_attacks.values,
            y=asn_attacks.index,
            orientation='h',
            title="En Çok Saldırı Kaynaklı ASN'ler",
            labels={'x': 'Saldırı Sayısı', 'y': 'ASN'},
            color=asn_attacks.values,
            color_continuous_scale="Viridis"
        )
        fig.update_layout(height=500, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # ASN'lere göre ortalama risk
        asn_risk = df.groupby('asn_name')['risk'].mean().sort_values(ascending=False).head(15)
        
        fig = px.bar(
            x=asn_risk.values,
            y=asn_risk.index,
            orientation='h',
            title="En Yüksek Risk Skoruna Sahip ASN'ler",
            labels={'x': 'Ortalama Risk Skoru', 'y': 'ASN'},
            color=asn_risk.values,
            color_continuous_scale="Plasma"
        )
        fig.update_layout(height=500, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    # ASN detay tablosu
    st.markdown("### 📋 ASN Detay Tablosu")
    
    asn_details = df.groupby(['asn', 'asn_name']).agg({
        'ip': ['count', 'nunique'],
        'risk': ['mean', 'max'],
        'country': 'nunique'
    }).round(2)
    
    asn_details.columns = ['Toplam Saldırı', 'Benzersiz IP', 'Ortalama Risk', 'Max Risk', 'Ülke Sayısı']
    asn_details = asn_details.sort_values('Toplam Saldırı', ascending=False).head(20)
    
    st.dataframe(asn_details, use_container_width=True)

def port_analysis(df):
    """Port analizi"""
    st.markdown("## 🔌 Port ve Servis Analizi")
    
    # Tüm portları topla
    all_ports = []
    for ports in df['parsed_ports']:
        all_ports.extend(ports)
    
    if not all_ports:
        st.warning("Port bilgisi bulunamadı.")
        return
    
    port_counts = Counter(all_ports)
    
    tab1, tab2, tab3 = st.tabs(["📊 Port İstatistikleri", "🛡️ Servis Analizi", "⚠️ Risk Analizi"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # En çok hedef alınan portlar
            top_ports = dict(port_counts.most_common(20))
            
            fig = px.bar(
                x=list(top_ports.keys()),
                y=list(top_ports.values()),
                title="En Çok Hedef Alınan Portlar",
                labels={'x': 'Port Numarası', 'y': 'Saldırı Sayısı'},
                color=list(top_ports.values()),
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, showlegend=False, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Port dağılım pasta grafiği
            top_ports_pie = dict(port_counts.most_common(10))
            
            fig = px.pie(
                values=list(top_ports_pie.values()),
                names=list(top_ports_pie.keys()),
                title="Top 10 Port Dağılımı"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Port-servis eşleştirmesi
        common_ports = {
            '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP',
            '53': 'DNS', '80': 'HTTP', '110': 'POP3', '143': 'IMAP',
            '443': 'HTTPS', '993': 'IMAPS', '995': 'POP3S', '587': 'SMTP'
        }
        
        # Servis kategorilerine göre grupla
        service_attacks = {}
        for port, count in port_counts.items():
            service = common_ports.get(port, 'Diğer')
            service_attacks[service] = service_attacks.get(service, 0) + count
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Servis kategorilerine göre saldırı dağılımı
            fig = px.bar(
                x=list(service_attacks.keys()),
                y=list(service_attacks.values()),
                title="Servis Kategorilerine Göre Saldırı Dağılımı",
                labels={'x': 'Servis', 'y': 'Saldırı Sayısı'},
                color=list(service_attacks.values()),
                color_continuous_scale="Blues"
            )
            fig.update_layout(height=400, showlegend=False, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Kritik servisler uyarısı
            critical_services = ['SSH', 'FTP', 'Telnet', 'SMTP']
            critical_attacks = sum(service_attacks.get(service, 0) for service in critical_services)
            total_attacks = sum(service_attacks.values())
            critical_percentage = (critical_attacks / total_attacks) * 100
            
            st.markdown("### 🚨 Kritik Servis Uyarıları")
            st.metric(
                "Kritik Servislere Saldırı",
                f"{critical_attacks:,}",
                delta=f"{critical_percentage:.1f}% of total"
            )
            
            # Kritik servisler detayı
            st.markdown("**Kritik Servis Detayları:**")
            for service in critical_services:
                if service in service_attacks:
                    st.write(f"🔴 **{service}**: {service_attacks[service]:,} saldırı")
    
    with tab3:
        # Port bazlı risk analizi
        st.markdown("### ⚠️ Port Bazlı Risk Analizi")
        
        # Her port için ortalama risk hesapla
        port_risk_data = []
        for _, row in df.iterrows():
            if row['parsed_ports']:
                for port in row['parsed_ports']:
                    port_risk_data.append({'port': port, 'risk': row['risk']})
        
        if port_risk_data:
            port_risk_df = pd.DataFrame(port_risk_data)
            port_risk_avg = port_risk_df.groupby('port')['risk'].mean().sort_values(ascending=False)
            
            # Minimum 10 saldırı olan portları filtrele
            port_min_attacks = port_risk_df['port'].value_counts()
            qualified_ports = port_min_attacks[port_min_attacks >= 10].index
            port_risk_filtered = port_risk_avg[port_risk_avg.index.isin(qualified_ports)].head(15)
            
            col1, col2 = st.columns(2)
            
            with col1:
                fig = px.bar(
                    x=port_risk_filtered.index,
                    y=port_risk_filtered.values,
                    title="En Yüksek Risk Skoruna Sahip Portlar (Min 10 saldırı)",
                    labels={'x': 'Port', 'y': 'Ortalama Risk Skoru'},
                    color=port_risk_filtered.values,
                    color_continuous_scale="Oranges"
                )
                fig.update_layout(height=400, showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Yüksek riskli portlar tablosu
                st.markdown("**Yüksek Riskli Portlar:**")
                high_risk_ports = port_risk_filtered[port_risk_filtered > 50]
                
                for port, risk in high_risk_ports.items():
                    service = common_ports.get(port, 'Bilinmeyen')
                    attack_count = port_min_attacks.get(port, 0)
                    st.write(f"🔴 **Port {port}** ({service}): Risk {risk:.1f} - {attack_count} saldırı")

def network_topology(df):
    """Ağ topolojisi analizi"""
    st.markdown("## 🕸️ Ağ Topolojisi ve Bağlantı Analizi")
    
    # ISP-ASN ilişkileri
    isp_asn = df.groupby(['isp', 'asn_name']).size().reset_index(name='connections')
    
    # En çok bağlantısı olan ISP'ler
    top_connected_isps = isp_asn.groupby('isp')['connections'].sum().sort_values(ascending=False).head(10)
    
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.bar(
            x=top_connected_isps.values,
            y=top_connected_isps.index,
            orientation='h',
            title="En Çok Ağ Bağlantısına Sahip ISP'ler",
            labels={'x': 'Toplam Bağlantı', 'y': 'ISP'},
            color=top_connected_isps.values,
            color_continuous_scale="Greens"
        )
        fig.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Ülke-ISP çeşitliliği
        country_isp_diversity = df.groupby('country')['isp'].nunique().sort_values(ascending=False).head(10)
        
        fig = px.bar(
            x=country_isp_diversity.values,
            y=country_isp_diversity.index,
            orientation='h',
            title="Ülkelere Göre ISP Çeşitliliği",
            labels={'x': 'Benzersiz ISP Sayısı', 'y': 'Ülke'},
            color=country_isp_diversity.values,
            color_continuous_scale="Purples"
        )
        fig.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

def network_security_insights(df):
    """Ağ güvenliği içgörüleri"""
    st.markdown("## 🔍 Ağ Güvenliği İçgörüleri ve Öneriler")
    
    # Güvenlik metrikleri hesapla
    total_isps = df['isp'].nunique()
    high_risk_isps = df[df['risk'] > 70]['isp'].nunique()
    total_asns = df['asn'].nunique()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Toplam ISP", total_isps)
    
    with col2:
        st.metric(
            "Yüksek Riskli ISP", 
            high_risk_isps, 
            delta=f"{(high_risk_isps/total_isps)*100:.1f}% of total"
        )
    
    with col3:
        st.metric("Toplam ASN", total_asns)
    
    with col4:
        avg_risk_per_isp = df.groupby('isp')['risk'].mean().mean()
        st.metric("ISP Başına Ortalama Risk", f"{avg_risk_per_isp:.1f}")
    
    # Güvenlik önerileri
    st.markdown("### 🛡️ Güvenlik Önerileri")
    
    # En riskli ISP'leri belirle
    risky_isps = df.groupby('isp')['risk'].mean().sort_values(ascending=False).head(5)
    
    st.markdown("#### 🚨 Öncelikli İzleme Gerektiren ISP'ler:")
    for isp, risk in risky_isps.items():
        attack_count = len(df[df['isp'] == isp])
        st.write(f"🔴 **{isp}**: Ortalama risk {risk:.1f}, {attack_count} saldırı")
    
    # En çok saldırı alan portlar için öneriler
    if all_ports:
        top_5_ports = dict(Counter(all_ports).most_common(5))
        
        st.markdown("#### 🔌 Öncelikli Korunması Gereken Portlar:")
        for port, count in top_5_ports.items():
            service = common_ports.get(port, 'Bilinmeyen')
            st.write(f"🔒 **Port {port}** ({service}): {count} saldırı - Güvenlik duvarı kurallarını gözden geçirin")
    
    # Coğrafi güvenlik önerileri
    high_risk_countries = df.groupby('country')['risk'].mean().sort_values(ascending=False).head(3)
    
    st.markdown("#### 🌍 Coğrafi Güvenlik Önerileri:")
    for country, risk in high_risk_countries.items():
        attack_count = len(df[df['country'] == country])
        st.write(f"🚩 **{country}**: Ortalama risk {risk:.1f}, {attack_count} saldırı - Bölgesel güvenlik politikalarını güçlendirin")

# Ana fonksiyon
def main():
    df = load_data()
    
    # Genel ağ istatistikleri
    st.markdown("## 📈 Genel Ağ İstatistikleri")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Toplam ISP", df['isp'].nunique())
    with col2:
        st.metric("Toplam ASN", df['asn'].nunique())
    with col3:
        st.metric("Benzersiz Ağ", df['net_name'].nunique())
    with col4:
        st.metric("Etkilenen Port", len(set([port for ports in df['parsed_ports'] for port in ports])))
    
    # Tüm portları al (global değişken için)
    global all_ports, common_ports
    all_ports = []
    for ports in df['parsed_ports']:
        all_ports.extend(ports)
    
    common_ports = {
        '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP',
        '53': 'DNS', '80': 'HTTP', '110': 'POP3', '143': 'IMAP',
        '443': 'HTTPS', '993': 'IMAPS', '995': 'POP3S', '587': 'SMTP'
    }
    
    # Analiz bölümleri
    isp_analysis(df)
    asn_analysis(df)
    port_analysis(df)
    network_topology(df)
    network_security_insights(df)

if __name__ == "__main__":
    main()
