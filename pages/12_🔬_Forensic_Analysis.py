import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import random
from datetime import datetime, timedelta
import hashlib

st.set_page_config(
    page_title="🔬 Forensic Analysis",
    page_icon="🔬",
    layout="wide"
)

st.markdown("# 🔬 Forensic Analysis - Adli Analiz")

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
def generate_forensic_data(df):
    """Adli analiz verisi oluştur"""
    
    # Artifact türleri
    artifact_types = [
        'Network Logs', 'System Logs', 'Browser History', 'Registry Entries',
        'Memory Dumps', 'File System', 'Email Headers', 'Database Logs',
        'DNS Records', 'SSL Certificates', 'Process Lists', 'Network Packets'
    ]
    
    # Kanıt türleri
    evidence_types = [
        'Digital Signature', 'Hash Values', 'Timestamps', 'IP Traces',
        'User Activities', 'File Metadata', 'System Events', 'Network Traffic',
        'Malware Samples', 'Encryption Keys', 'Database Queries', 'API Calls'
    ]
    
    # Adli araçlar
    forensic_tools = [
        'Wireshark', 'Volatility', 'Autopsy', 'FTK', 'EnCase', 'YARA',
        'Sleuth Kit', 'Metasploit', 'Nmap', 'Hashcat', 'John the Ripper', 'Binwalk'
    ]
    
    # İnsident türleri
    incident_types = [
        'Data Breach', 'Malware Infection', 'Unauthorized Access', 'DDoS Attack',
        'Phishing Campaign', 'Insider Threat', 'Ransomware', 'APT Activity',
        'Account Compromise', 'System Compromise', 'Network Intrusion', 'Data Exfiltration'
    ]
    
    # Chain of Custody durumları
    custody_status = ['Collected', 'Analyzed', 'Preserved', 'Documented', 'Verified']
    
    forensic_data = []
    
    # Yüksek riskli saldırılar için forensic analiz oluştur
    high_risk_attacks = df[df['risk'] > 70].copy()
    
    for _, row in high_risk_attacks.iterrows():
        # Her saldırı için multiple artifacts oluştur
        num_artifacts = random.randint(2, 6)
        
        for i in range(num_artifacts):
            # Unique case ID oluştur
            case_id = f"CASE-{datetime.now().year}-{random.randint(1000, 9999)}"
            
            # Evidence hash oluştur
            evidence_hash = hashlib.sha256(f"{row['ip']}_{i}_{row['timestamp']}".encode()).hexdigest()[:32]
            
            forensic_data.append({
                'case_id': case_id,
                'ip': row['ip'],
                'timestamp': row['timestamp'],
                'risk': row['risk'],
                'country': row['country'],
                'city': row['city'],
                'isp': row['isp'],
                'artifact_type': random.choice(artifact_types),
                'evidence_type': random.choice(evidence_types),
                'forensic_tool': random.choice(forensic_tools),
                'incident_type': random.choice(incident_types),
                'evidence_hash': evidence_hash,
                'file_size_mb': random.randint(1, 1000),
                'custody_status': random.choice(custody_status),
                'analyst': f"Analyst_{random.randint(1, 10)}",
                'collection_date': row['timestamp'] - timedelta(hours=random.randint(1, 48)),
                'analysis_date': row['timestamp'] + timedelta(hours=random.randint(1, 24)),
                'integrity_verified': random.choice([True, False]),
                'admissible': random.choice([True, False]),
                'confidence_level': random.uniform(0.5, 1.0),
                'investigation_priority': random.choice(['Low', 'Medium', 'High', 'Critical'])
            })
    
    return pd.DataFrame(forensic_data)

def timeline_reconstruction(forensic_df):
    """Saldırı Zaman Çizelgesi Rekonstrüksiyonu"""
    st.markdown("## ⏰ Saldırı Zaman Çizelgesi Rekonstrüksiyonu")
    
    if forensic_df.empty:
        st.warning("Forensic veri bulunamadı.")
        return
    
    tab1, tab2, tab3 = st.tabs(["📅 Timeline Analysis", "🔍 Event Correlation", "📊 Pattern Analysis"])
    
    with tab1:
        st.markdown("### 🕐 Detaylı Zaman Çizelgesi")
        
        # Zaman çizelgesi için veri hazırla
        timeline_data = forensic_df[['timestamp', 'incident_type', 'ip', 'risk', 'evidence_type']].copy()
        timeline_data = timeline_data.sort_values('timestamp')
        
        # Interactive timeline
        fig = px.scatter(
            timeline_data,
            x='timestamp',
            y='incident_type',
            color='risk',
            size='risk',
            hover_data=['ip', 'evidence_type'],
            title="Incident Timeline Analizi",
            color_continuous_scale="Reds"
        )
        
        fig.update_layout(
            height=500,
            xaxis_title="Zaman",
            yaxis_title="Incident Türü"
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Timeline özeti
        col1, col2 = st.columns(2)
        
        with col1:
            # Saatlik dağılım
            hourly_incidents = timeline_data.groupby(timeline_data['timestamp'].dt.hour).size()
            
            fig = px.bar(
                x=hourly_incidents.index,
                y=hourly_incidents.values,
                title="Saatlik Incident Dağılımı",
                labels={'x': 'Saat', 'y': 'Incident Sayısı'}
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Günlük trend
            daily_incidents = timeline_data.groupby(timeline_data['timestamp'].dt.date).size()
            
            fig = px.line(
                x=daily_incidents.index,
                y=daily_incidents.values,
                title="Günlük Incident Trendi",
                labels={'x': 'Tarih', 'y': 'Incident Sayısı'}
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.markdown("### 🔗 Event Korelasyon Analizi")
        
        # IP bazlı korelasyon
        ip_correlation = forensic_df.groupby('ip').agg({
            'incident_type': ['count', lambda x: x.nunique()],
            'artifact_type': lambda x: x.nunique(),
            'risk': 'mean',
            'timestamp': ['min', 'max']
        }).round(2)
        ip_correlation.columns = ['Total Events', 'Unique Incidents', 'Unique Artifacts', 'Avg Risk', 'First Seen', 'Last Seen']
        ip_correlation = ip_correlation.sort_values('Total Events', ascending=False)
        
        st.markdown("#### 🌐 IP Bazlı Event Korelasyonu")
        st.dataframe(ip_correlation.head(20), use_container_width=True)
        
        # Incident türü korelasyonu
        incident_matrix = pd.crosstab(forensic_df['incident_type'], forensic_df['artifact_type'])
        
        fig = px.imshow(
            incident_matrix.values,
            x=incident_matrix.columns,
            y=incident_matrix.index,
            title="Incident-Artifact Korelasyon Matrisi",
            color_continuous_scale="Reds"
        )
        fig.update_layout(height=600)
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        st.markdown("### 📊 Davranışsal Pattern Analizi")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Attack pattern analizi
            attack_patterns = forensic_df.groupby(['incident_type', 'country']).size().reset_index()
            attack_patterns.columns = ['incident_type', 'country', 'count']
            attack_patterns = attack_patterns.sort_values('count', ascending=False).head(15)
            
            fig = px.bar(
                attack_patterns,
                x='count',
                y='incident_type',
                color='country',
                orientation='h',
                title="Incident-Ülke Pattern Analizi"
            )
            fig.update_layout(height=500)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Risk pattern analizi
            risk_patterns = forensic_df.groupby('investigation_priority')['risk'].describe().round(2)
            
            st.markdown("#### ⚠️ Risk Pattern Analizi")
            st.dataframe(risk_patterns, use_container_width=True)
            
            # Confidence level dağılımı
            fig = px.histogram(
                forensic_df,
                x='confidence_level',
                nbins=20,
                title="Analiz Güven Seviyesi Dağılımı",
                labels={'x': 'Güven Seviyesi', 'y': 'Analiz Sayısı'}
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)

def evidence_analysis(forensic_df):
    """Kanıt Analizi"""
    st.markdown("## 🔍 Dijital Kanıt Analizi")
    
    if forensic_df.empty:
        st.warning("Kanıt verisi bulunamadı.")
        return
    
    tab1, tab2, tab3 = st.tabs(["📁 Evidence Types", "🔒 Integrity Verification", "📋 Chain of Custody"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Evidence türü analizi
            evidence_analysis = forensic_df.groupby('evidence_type').agg({
                'file_size_mb': ['sum', 'mean'],
                'integrity_verified': lambda x: (x == True).sum(),
                'admissible': lambda x: (x == True).sum(),
                'confidence_level': 'mean'
            }).round(2)
            evidence_analysis.columns = ['Total Size (MB)', 'Avg Size (MB)', 'Verified', 'Admissible', 'Avg Confidence']
            evidence_analysis = evidence_analysis.sort_values('Total Size (MB)', ascending=False)
            
            st.markdown("#### 📊 Kanıt Türü Analizi")
            st.dataframe(evidence_analysis, use_container_width=True)
        
        with col2:
            # Artifact türü dağılımı
            artifact_dist = forensic_df['artifact_type'].value_counts()
            
            fig = px.pie(
                values=artifact_dist.values,
                names=artifact_dist.index,
                title="Digital Artifact Dağılımı",
                hole=0.4
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=500)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.markdown("### 🔒 Kanıt Bütünlüğü Doğrulaması")
        
        # Integrity verification analizi
        integrity_stats = {
            'Toplam Kanıt': len(forensic_df),
            'Doğrulanmış': forensic_df['integrity_verified'].sum(),
            'Kabul Edilebilir': forensic_df['admissible'].sum(),
            'Doğrulama Oranı': f"{(forensic_df['integrity_verified'].sum() / len(forensic_df) * 100):.1f}%"
        }
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("📁 Toplam Kanıt", integrity_stats['Toplam Kanıt'])
        with col2:
            st.metric("✅ Doğrulanmış", integrity_stats['Doğrulanmış'])
        with col3:
            st.metric("⚖️ Kabul Edilebilir", integrity_stats['Kabul Edilebilir'])
        with col4:
            st.metric("📊 Doğrulama Oranı", integrity_stats['Doğrulama Oranı'])
        
        # Hash verification details
        hash_verification = forensic_df[['evidence_hash', 'integrity_verified', 'file_size_mb', 'confidence_level']].copy()
        hash_verification['hash_prefix'] = hash_verification['evidence_hash'].str[:16] + '...'
        
        st.markdown("#### 🔐 Hash Doğrulama Detayları")
        st.dataframe(hash_verification[['hash_prefix', 'integrity_verified', 'file_size_mb', 'confidence_level']].head(20), use_container_width=True)
    
    with tab3:
        st.markdown("### 📋 Chain of Custody (Emanet Zinciri)")
        
        # Custody analizi
        custody_analysis = forensic_df.groupby('custody_status').agg({
            'case_id': 'count',
            'analyst': lambda x: x.nunique(),
            'file_size_mb': 'sum'
        }).round(2)
        custody_analysis.columns = ['Case Count', 'Unique Analysts', 'Total Size (MB)']
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.dataframe(custody_analysis, use_container_width=True)
            
            # Analyst workload
            analyst_workload = forensic_df['analyst'].value_counts()
            
            fig = px.bar(
                x=analyst_workload.index,
                y=analyst_workload.values,
                title="Analist İş Yükü Dağılımı",
                labels={'x': 'Analist', 'y': 'Case Sayısı'}
            )
            fig.update_layout(height=400, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Custody status dağılımı
            custody_dist = forensic_df['custody_status'].value_counts()
            
            fig = px.pie(
                values=custody_dist.values,
                names=custody_dist.index,
                title="Chain of Custody Durumu",
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        # Detaylı custody tracking
        st.markdown("#### 📝 Detaylı Emanet Takibi")
        
        custody_details = forensic_df[['case_id', 'evidence_hash', 'custody_status', 'analyst', 'collection_date', 'analysis_date']].copy()
        custody_details['evidence_hash'] = custody_details['evidence_hash'].str[:16] + '...'
        custody_details = custody_details.sort_values('collection_date', ascending=False)
        
        st.dataframe(custody_details.head(20), use_container_width=True)

def investigation_management(forensic_df):
    """Soruşturma Yönetimi"""
    st.markdown("## 📋 Soruşturma Yönetimi")
    
    if forensic_df.empty:
        st.warning("Soruşturma verisi bulunamadı.")
        return
    
    tab1, tab2 = st.tabs(["📊 Case Management", "🎯 Investigation Priorities"])
    
    with tab1:
        # Case management overview
        case_overview = forensic_df.groupby('case_id').agg({
            'incident_type': 'first',
            'investigation_priority': 'first',
            'ip': 'nunique',
            'artifact_type': 'nunique',
            'risk': 'mean',
            'confidence_level': 'mean',
            'integrity_verified': lambda x: (x == True).sum(),
            'admissible': lambda x: (x == True).sum()
        }).round(2)
        case_overview.columns = ['Incident Type', 'Priority', 'Unique IPs', 'Artifact Types', 'Avg Risk', 'Avg Confidence', 'Verified', 'Admissible']
        case_overview = case_overview.sort_values('Avg Risk', ascending=False)
        
        st.markdown("### 📁 Case Overview")
        
        # Case statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_cases = len(case_overview)
            st.metric("📋 Toplam Case", total_cases)
        
        with col2:
            critical_cases = len(case_overview[case_overview['Priority'] == 'Critical'])
            st.metric("🚨 Kritik Case", critical_cases)
        
        with col3:
            high_risk_cases = len(case_overview[case_overview['Avg Risk'] > 80])
            st.metric("⚠️ Yüksek Risk", high_risk_cases)
        
        with col4:
            avg_confidence = case_overview['Avg Confidence'].mean()
            st.metric("🎯 Ortalama Güven", f"{avg_confidence:.2f}")
        
        # Detailed case table
        st.dataframe(case_overview.head(20), use_container_width=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            # Priority dağılımı
            priority_analysis = forensic_df.groupby('investigation_priority').agg({
                'case_id': 'nunique',
                'risk': 'mean',
                'confidence_level': 'mean'
            }).round(2)
            priority_analysis.columns = ['Case Count', 'Avg Risk', 'Avg Confidence']
            
            st.markdown("#### 🎯 Öncelik Analizi")
            st.dataframe(priority_analysis, use_container_width=True)
            
            # Priority trend
            priority_dist = forensic_df['investigation_priority'].value_counts()
            
            fig = px.bar(
                x=priority_dist.index,
                y=priority_dist.values,
                title="Soruşturma Öncelik Dağılımı",
                labels={'x': 'Öncelik', 'y': 'Case Sayısı'},
                color=priority_dist.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Forensic tool kullanımı
            tool_usage = forensic_df['forensic_tool'].value_counts().head(10)
            
            fig = px.bar(
                x=tool_usage.values,
                y=tool_usage.index,
                orientation='h',
                title="En Çok Kullanılan Forensic Araçlar",
                labels={'x': 'Kullanım Sayısı', 'y': 'Araç'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

def forensic_reports(forensic_df):
    """Forensic Raporları"""
    st.markdown("## 📄 Forensic Analiz Raporları")
    
    if forensic_df.empty:
        st.warning("Rapor verisi bulunamadı.")
        return
    
    # Executive Summary
    st.markdown("### 📊 Executive Summary")
    
    summary_metrics = {
        'Toplam Soruşturma': forensic_df['case_id'].nunique(),
        'Toplam Kanıt': len(forensic_df),
        'Doğrulanmış Kanıt': forensic_df['integrity_verified'].sum(),
        'Ortalama Risk': forensic_df['risk'].mean(),
        'En Sık Incident': forensic_df['incident_type'].mode().iloc[0],
        'Toplam Veri (MB)': forensic_df['file_size_mb'].sum()
    }
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("📋 Toplam Soruşturma", summary_metrics['Toplam Soruşturma'])
        st.metric("📁 Toplam Kanıt", summary_metrics['Toplam Kanıt'])
    
    with col2:
        st.metric("✅ Doğrulanmış Kanıt", summary_metrics['Doğrulanmış Kanıt'])
        st.metric("⚠️ Ortalama Risk", f"{summary_metrics['Ortalama Risk']:.1f}")
    
    with col3:
        st.metric("🎯 En Sık Incident", summary_metrics['En Sık Incident'])
        st.metric("💾 Toplam Veri", f"{summary_metrics['Toplam Veri (MB)']:,.0f} MB")
    
    # Detailed findings
    st.markdown("### 🔍 Detaylı Bulgular")
    
    detailed_report = f"""
    ## 🔬 CyberTrack Vision - Forensic Analiz Raporu
    
    **Rapor Tarihi:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    **Analiz Dönemi:** {forensic_df['timestamp'].min()} - {forensic_df['timestamp'].max()}
    
    ### 📊 Soruşturma Özeti
    - **Toplam Case Sayısı:** {forensic_df['case_id'].nunique():,}
    - **Toplam Dijital Kanıt:** {len(forensic_df):,}
    - **Doğrulanmış Kanıt:** {forensic_df['integrity_verified'].sum():,} ({(forensic_df['integrity_verified'].sum() / len(forensic_df) * 100):.1f}%)
    - **Mahkemede Kabul Edilebilir:** {forensic_df['admissible'].sum():,} ({(forensic_df['admissible'].sum() / len(forensic_df) * 100):.1f}%)
    
    ### 🎯 Ana Bulgular
    1. **En Yaygın Incident Türü:** {forensic_df['incident_type'].mode().iloc[0]}
    2. **En Riskli Coğrafi Bölge:** {forensic_df.groupby('country')['risk'].mean().idxmax()}
    3. **En Etkili Forensic Araç:** {forensic_df['forensic_tool'].mode().iloc[0]}
    4. **Ortalama Analiz Güveni:** {forensic_df['confidence_level'].mean():.2f}
    
    ### ⚠️ Risk Değerlendirmesi
    - **Kritik Seviye Cases:** {len(forensic_df[forensic_df['investigation_priority'] == 'Critical'])}
    - **Yüksek Risk Incidents:** {len(forensic_df[forensic_df['risk'] > 80])}
    - **Bütünlük Sorunlu Kanıtlar:** {len(forensic_df[forensic_df['integrity_verified'] == False])}
    
    ### 📋 Öneriler
    1. Kanıt toplama süreçlerinin standardizasyonu
    2. Chain of custody protokollerinin güçlendirilmesi
    3. Forensic araç repertuarının genişletilmesi
    4. Analist eğitim programlarının artırılması
    
    **Bu rapor CyberTrack Vision Forensic Analysis modülü tarafından oluşturulmuştur.**
    """
    
    st.markdown(detailed_report)
    
    # Rapor indirme
    st.download_button(
        "📥 Forensic Analiz Raporu İndir",
        detailed_report,
        file_name=f"forensic_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown"
    )

# Ana fonksiyon
def main():
    df = load_data()
    forensic_df = generate_forensic_data(df)
    
    if not forensic_df.empty:
        st.markdown("## 🔬 Forensic Analysis Dashboard")
        
        # Genel forensic istatistikler
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_cases = forensic_df['case_id'].nunique()
            st.metric("📋 Aktif Cases", total_cases)
        
        with col2:
            total_evidence = len(forensic_df)
            st.metric("📁 Toplam Kanıt", total_evidence)
        
        with col3:
            verified_evidence = forensic_df['integrity_verified'].sum()
            st.metric("✅ Doğrulanmış", verified_evidence)
        
        with col4:
            avg_confidence = forensic_df['confidence_level'].mean()
            st.metric("🎯 Ortalama Güven", f"{avg_confidence:.2f}")
        
        # Ana analiz bölümleri
        timeline_reconstruction(forensic_df)
        evidence_analysis(forensic_df)
        investigation_management(forensic_df)
        forensic_reports(forensic_df)
    else:
        st.warning("Forensic analiz verisi oluşturulamadı.")

if __name__ == "__main__":
    main()
