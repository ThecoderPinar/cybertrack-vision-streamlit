import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json

st.set_page_config(
    page_title="🔒 Security Policies",
    page_icon="🔒",
    layout="wide"
)

st.markdown("# 🔒 Security Policies - Güvenlik Politikaları")

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

def firewall_rules(df):
    """Firewall Kuralları Önerileri"""
    st.markdown("## 🛡️ Otomatik Firewall Kuralları")
    
    tab1, tab2, tab3 = st.tabs(["🚫 Blocking Rules", "🔄 Rate Limiting", "🌍 Geo-blocking"])
    
    with tab1:
        st.markdown("### 🚫 IP Blocking Önerileri")
        
        # Yüksek riskli IP'leri belirle
        high_risk_ips = df[df['risk'] > 85].groupby('ip').agg({
            'risk': ['mean', 'max', 'count'],
            'country': 'first',
            'isp': 'first'
        }).round(2)
        high_risk_ips.columns = ['Avg Risk', 'Max Risk', 'Attack Count', 'Country', 'ISP']
        high_risk_ips = high_risk_ips.sort_values('Max Risk', ascending=False)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("#### 📋 Önerilen IP Block Listesi")
            
            # Block listesi tablosu
            block_list = high_risk_ips.head(20).copy()
            block_list['Action'] = 'BLOCK'
            block_list['Rule Type'] = 'IP-based'
            
            st.dataframe(block_list, use_container_width=True)
            
            # Firewall rule export
            if st.button("📥 Firewall Rules Export"):
                rules_text = "# CyberTrack Vision - Automated Firewall Rules\n"
                rules_text += f"# Generated: {datetime.now()}\n\n"
                
                for ip in block_list.head(50).index:
                    risk = block_list.loc[ip, 'Max Risk']
                    country = block_list.loc[ip, 'Country']
                    rules_text += f"# Block {ip} - Risk: {risk} - Country: {country}\n"
                    rules_text += f"iptables -A INPUT -s {ip} -j DROP\n\n"
                
                st.download_button(
                    "💾 Download Firewall Rules",
                    rules_text,
                    file_name=f"firewall_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
        
        with col2:
            st.markdown("#### 🎯 Block Kategorileri")
            
            # Risk seviyesine göre kategorize
            risk_categories = {
                'Critical (90+)': len(high_risk_ips[high_risk_ips['Max Risk'] >= 90]),
                'High (80-89)': len(high_risk_ips[(high_risk_ips['Max Risk'] >= 80) & (high_risk_ips['Max Risk'] < 90)]),
                'Medium (70-79)': len(high_risk_ips[(high_risk_ips['Max Risk'] >= 70) & (high_risk_ips['Max Risk'] < 80)])
            }
            
            fig = px.pie(
                values=list(risk_categories.values()),
                names=list(risk_categories.keys()),
                title="Risk Seviyesine Göre Block Önerileri",
                color_discrete_map={
                    'Critical (90+)': '#ff4444',
                    'High (80-89)': '#ff8800',
                    'Medium (70-79)': '#ffaa00'
                }
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.markdown("### 🔄 Rate Limiting Önerileri")
        
        # Saldırı frekansını analiz et
        attack_frequency = df.groupby('ip').agg({
            'timestamp': 'count',
            'risk': 'mean'
        }).rename(columns={'timestamp': 'attack_count'})
        
        # Rate limiting kategorileri
        rate_limits = []
        for ip, data in attack_frequency.iterrows():
            count = data['attack_count']
            risk = data['risk']
            
            if count > 20:
                limit = "5 req/min"
                priority = "High"
            elif count > 10:
                limit = "10 req/min"
                priority = "Medium"
            elif count > 5:
                limit = "20 req/min"
                priority = "Low"
            else:
                continue
            
            rate_limits.append({
                'IP': ip,
                'Attack Count': count,
                'Avg Risk': round(risk, 2),
                'Suggested Limit': limit,
                'Priority': priority
            })
        
        if rate_limits:
            rate_df = pd.DataFrame(rate_limits).sort_values('Attack Count', ascending=False)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.dataframe(rate_df.head(20), use_container_width=True)
            
            with col2:
                # Priority dağılımı
                priority_dist = rate_df['Priority'].value_counts()
                
                fig = px.bar(
                    x=priority_dist.index,
                    y=priority_dist.values,
                    title="Rate Limiting Priority Dağılımı",
                    labels={'x': 'Priority', 'y': 'Count'},
                    color=priority_dist.index,
                    color_discrete_map={
                        'High': '#ff4444',
                        'Medium': '#ffaa00',
                        'Low': '#44ff44'
                    }
                )
                fig.update_layout(height=400, showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Rate limiting önerisi için yeterli veri bulunamadı.")
    
    with tab3:
        st.markdown("### 🌍 Coğrafi Blocking Önerileri")
        
        # Ülke bazlı risk analizi
        country_risk = df.groupby('country').agg({
            'risk': ['mean', 'max'],
            'ip': ['count', 'nunique']
        }).round(2)
        country_risk.columns = ['Avg Risk', 'Max Risk', 'Total Attacks', 'Unique IPs']
        country_risk = country_risk.sort_values('Avg Risk', ascending=False)
        
        # Geo-blocking önerileri
        geo_blocking_countries = country_risk[
            (country_risk['Avg Risk'] > 60) & 
            (country_risk['Total Attacks'] > 10)
        ]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🚫 Önerilen Geo-blocking Ülkeleri")
            
            if not geo_blocking_countries.empty:
                # Blocking önerileri
                blocking_recommendations = geo_blocking_countries.copy()
                blocking_recommendations['Action'] = blocking_recommendations.apply(
                    lambda row: 'BLOCK' if row['Avg Risk'] > 80 else 'MONITOR', axis=1
                )
                
                st.dataframe(blocking_recommendations.head(15), use_container_width=True)
                
                # Geo-blocking rules export
                if st.button("🌍 Export Geo-blocking Rules"):
                    geo_rules = "# CyberTrack Vision - Geo-blocking Rules\n"
                    geo_rules += f"# Generated: {datetime.now()}\n\n"
                    
                    for country in blocking_recommendations.head(10).index:
                        action = blocking_recommendations.loc[country, 'Action']
                        risk = blocking_recommendations.loc[country, 'Avg Risk']
                        geo_rules += f"# {action} {country} - Avg Risk: {risk}\n"
                        if action == 'BLOCK':
                            geo_rules += f"# iptables -A INPUT -m geoip --src-cc {country[:2]} -j DROP\n\n"
                    
                    st.download_button(
                        "💾 Download Geo-blocking Rules",
                        geo_rules,
                        file_name=f"geo_blocking_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain"
                    )
            else:
                st.info("Geo-blocking önerisi için kritik ülke bulunamadı.")
        
        with col2:
            # Risk haritası
            if not geo_blocking_countries.empty:
                fig = px.choropleth(
                    locations=geo_blocking_countries.index,
                    color=geo_blocking_countries['Avg Risk'],
                    locationmode='country names',
                    title="Geo-blocking Risk Haritası",
                    color_continuous_scale="Reds"
                )
                fig.update_layout(height=500)
                st.plotly_chart(fig, use_container_width=True)

def access_control_policies(df):
    """Erişim Kontrol Politikaları"""
    st.markdown("## 🔐 Erişim Kontrol Politikaları")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🕐 Zaman Bazlı Erişim Kontrolü")
        
        # Saatlik risk analizi
        df['hour'] = df['timestamp'].dt.hour
        hourly_risk = df.groupby('hour').agg({
            'risk': ['mean', 'count'],
            'ip': 'nunique'
        }).round(2)
        hourly_risk.columns = ['Avg Risk', 'Attack Count', 'Unique IPs']
        
        # Yüksek riskli saatleri belirle
        risk_threshold = hourly_risk['Avg Risk'].mean() + hourly_risk['Avg Risk'].std()
        high_risk_hours = hourly_risk[hourly_risk['Avg Risk'] > risk_threshold]
        
        # Zaman bazlı politika önerileri
        time_policies = []
        for hour in range(24):
            if hour in high_risk_hours.index:
                policy = "STRICT"
                description = "Enhanced monitoring, additional authentication"
            elif 22 <= hour <= 6:  # Gece saatleri
                policy = "MODERATE"
                description = "Standard monitoring, rate limiting"
            else:
                policy = "NORMAL"
                description = "Standard security policies"
            
            time_policies.append({
                'Hour': f"{hour:02d}:00",
                'Policy': policy,
                'Description': description,
                'Risk Level': hourly_risk.loc[hour, 'Avg Risk'] if hour in hourly_risk.index else 0
            })
        
        time_df = pd.DataFrame(time_policies)
        st.dataframe(time_df, use_container_width=True)
    
    with col2:
        st.markdown("### 🌐 Service-based Access Control")
        
        # Port bazlı erişim kontrolü
        port_services = {
            '22': 'SSH', '23': 'Telnet', '21': 'FTP', '25': 'SMTP',
            '53': 'DNS', '80': 'HTTP', '443': 'HTTPS', '110': 'POP3',
            '143': 'IMAP', '993': 'IMAPS', '995': 'POP3S'
        }
        
        # Port bazlı saldırı analizi
        port_attacks = []
        for _, row in df.iterrows():
            if pd.notna(row['attack_ports']) and row['attack_ports'] != '-':
                for port_info in row['attack_ports'].split('|'):
                    if ':' in port_info:
                        port = port_info.split(':')[0]
                        service = port_services.get(port, 'Unknown')
                        port_attacks.append({
                            'port': port,
                            'service': service,
                            'risk': row['risk']
                        })
        
        if port_attacks:
            port_df = pd.DataFrame(port_attacks)
            service_risk = port_df.groupby('service')['risk'].agg(['mean', 'count']).round(2)
            service_risk.columns = ['Avg Risk', 'Attack Count']
            service_risk = service_risk.sort_values('Avg Risk', ascending=False)
            
            # Service politikaları
            service_policies = []
            for service, data in service_risk.iterrows():
                avg_risk = data['Avg Risk']
                count = data['Attack Count']
                
                if avg_risk > 70:
                    policy = "BLOCK"
                    color = "🔴"
                elif avg_risk > 50:
                    policy = "RESTRICT"
                    color = "🟠"
                else:
                    policy = "MONITOR"
                    color = "🟡"
                
                service_policies.append({
                    'Service': service,
                    'Avg Risk': avg_risk,
                    'Attacks': count,
                    'Policy': f"{color} {policy}"
                })
            
            service_df = pd.DataFrame(service_policies)
            st.dataframe(service_df, use_container_width=True)

def automated_response_policies(df):
    """Otomatik Yanıt Politikaları"""
    st.markdown("## 🤖 Otomatik Yanıt Politikaları")
    
    # Risk seviyelerine göre otomatik eylemler
    response_rules = {
        'Critical (90+)': {
            'actions': ['Immediate IP Block', 'Alert Security Team', 'Log Incident'],
            'response_time': '< 1 minute',
            'escalation': 'High'
        },
        'High (70-89)': {
            'actions': ['Rate Limiting', 'Enhanced Monitoring', 'Notify Admin'],
            'response_time': '< 5 minutes',
            'escalation': 'Medium'
        },
        'Medium (50-69)': {
            'actions': ['Increased Logging', 'Monitor Pattern'],
            'response_time': '< 15 minutes',
            'escalation': 'Low'
        }
    }
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### ⚡ Otomatik Yanıt Matrisi")
        
        # Response matrix tablosu
        response_data = []
        for risk_level, config in response_rules.items():
            for action in config['actions']:
                response_data.append({
                    'Risk Level': risk_level,
                    'Action': action,
                    'Response Time': config['response_time'],
                    'Escalation': config['escalation']
                })
        
        response_df = pd.DataFrame(response_data)
        st.dataframe(response_df, use_container_width=True)
    
    with col2:
        st.markdown("### 📊 Politika Etki Analizi")
        
        # Mevcut veriye göre politika etkisini hesapla
        policy_impact = {}
        
        for risk_level in ['Critical (90+)', 'High (70-89)', 'Medium (50-69)']:
            if risk_level == 'Critical (90+)':
                affected = len(df[df['risk'] >= 90])
            elif risk_level == 'High (70-89)':
                affected = len(df[(df['risk'] >= 70) & (df['risk'] < 90)])
            else:
                affected = len(df[(df['risk'] >= 50) & (df['risk'] < 70)])
            
            policy_impact[risk_level] = affected
        
        fig = px.bar(
            x=list(policy_impact.keys()),
            y=list(policy_impact.values()),
            title="Politika Etki Alanı",
            labels={'x': 'Risk Seviyesi', 'y': 'Etkilenen Saldırı Sayısı'},
            color=list(policy_impact.values()),
            color_continuous_scale="Reds"
        )
        fig.update_layout(height=400, xaxis_tickangle=-45, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

def policy_compliance(df):
    """Politika Uyumluluk"""
    st.markdown("## 📋 Politika Uyumluluk ve Raporlama")
    
    # Compliance metrikleri
    total_attacks = len(df)
    blocked_recommended = len(df[df['risk'] > 85])  # Block önerilen saldırılar
    rate_limited_recommended = len(df[(df['risk'] >= 50) & (df['risk'] < 85)])
    
    compliance_metrics = {
        'Total Threats': total_attacks,
        'Recommended Blocks': blocked_recommended,
        'Recommended Rate Limits': rate_limited_recommended,
        'Policy Coverage': f"{((blocked_recommended + rate_limited_recommended) / total_attacks * 100):.1f}%"
    }
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Toplam Tehdit", compliance_metrics['Total Threats'])
    with col2:
        st.metric("Önerilen Block", compliance_metrics['Recommended Blocks'])
    with col3:
        st.metric("Rate Limit Önerisi", compliance_metrics['Recommended Rate Limits'])
    with col4:
        st.metric("Politika Kapsamı", compliance_metrics['Policy Coverage'])
    
    # Compliance raporu
    st.markdown("### 📊 Uyumluluk Raporu")
    
    compliance_report = f"""
    ## CyberTrack Vision - Güvenlik Politikası Uyumluluk Raporu
    
    **Rapor Tarihi:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    ### Özet
    - Toplam analiz edilen tehdit: {total_attacks:,}
    - Yüksek riskli tehdit (block önerisi): {blocked_recommended:,}
    - Orta riskli tehdit (rate limit önerisi): {rate_limited_recommended:,}
    - Politika kapsamı: {((blocked_recommended + rate_limited_recommended) / total_attacks * 100):.1f}%
    
    ### Öneriler
    1. **Immediate Actions**: {blocked_recommended} IP adresini derhal engelleyin
    2. **Rate Limiting**: {rate_limited_recommended} IP için rate limiting uygulayın
    3. **Monitoring**: Düşük riskli trafiği izlemeye devam edin
    
    ### Risk Dağılımı
    - Critical (90+): {len(df[df['risk'] >= 90])} saldırı
    - High (70-89): {len(df[(df['risk'] >= 70) & (df['risk'] < 90)])} saldırı
    - Medium (50-69): {len(df[(df['risk'] >= 50) & (df['risk'] < 70)])} saldırı
    
    Bu rapor CyberTrack Vision tarafından otomatik olarak oluşturulmuştur.
    """
    
    st.markdown(compliance_report)
    
    # Rapor indirme
    st.download_button(
        "📥 Compliance Raporu İndir",
        compliance_report,
        file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )

# Ana fonksiyon
def main():
    df = load_data()
    
    st.markdown("## 🔒 Güvenlik Politikaları Dashboard")
    
    # Genel istatistikler
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        block_candidates = len(df[df['risk'] > 85])
        st.metric("🚫 Block Önerisi", block_candidates)
    
    with col2:
        rate_limit_candidates = len(df[(df['risk'] >= 50) & (df['risk'] < 85)])
        st.metric("🔄 Rate Limit Önerisi", rate_limit_candidates)
    
    with col3:
        geo_block_countries = df[df['risk'] > 60].groupby('country')['risk'].mean()
        geo_candidates = len(geo_block_countries[geo_block_countries > 70])
        st.metric("🌍 Geo-block Önerisi", geo_candidates)
    
    with col4:
        policy_coverage = ((block_candidates + rate_limit_candidates) / len(df)) * 100
        st.metric("📊 Politika Kapsamı", f"{policy_coverage:.1f}%")
    
    # Ana analiz bölümleri
    firewall_rules(df)
    access_control_policies(df)
    automated_response_policies(df)
    policy_compliance(df)

if __name__ == "__main__":
    main()
