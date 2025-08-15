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
    page_title="🕸️ Dark Web Intelligence",
    page_icon="🕸️",
    layout="wide"
)

st.markdown("# 🕸️ Dark Web Intelligence - Karanlık Ağ İstihbaratı")

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
def generate_darkweb_data(df):
    """Dark Web intelligence verisi oluştur"""
    
    # Dark Web marketplace'leri
    marketplaces = [
        'AlphaBay Revival', 'DarkMarket', 'Empire Market', 'White House Market',
        'Monopoly Market', 'Cannazon', 'Torrez Market', 'Dark0de Reborn',
        'World Market', 'Versus Market', 'Cartel Market', 'Genesis Market'
    ]
    
    # Sızıntı türleri
    breach_types = [
        'Credit Card Data', 'Personal Information', 'Login Credentials', 'Medical Records',
        'Financial Data', 'Government Documents', 'Corporate Secrets', 'Social Media Accounts',
        'Email Databases', 'Phone Numbers', 'Identity Documents', 'Cryptocurrency Wallets'
    ]
    
    # Kriminal aktivite türleri
    criminal_activities = [
        'Data Trading', 'Ransomware-as-a-Service', 'Malware Sales', 'Exploit Kits',
        'DDoS Services', 'Phishing Kits', 'Stolen Accounts', 'Fraud Services',
        'Money Laundering', 'Fake Documents', 'Botnet Access', 'Vulnerability Trading'
    ]
    
    # Forum kategorileri
    forum_categories = [
        'Hacking Tutorials', 'Malware Development', 'Social Engineering', 'Carding',
        'Cryptocurrency', 'Fraud Techniques', 'Market Discussion', 'Tool Sharing',
        'Zero-Day Exploits', 'Data Breaches', 'Ransomware Groups', 'APT Discussion'
    ]
    
    darkweb_data = []
    
    # IP'lere göre dark web aktivitesi oluştur
    for _, row in df.iterrows():
        # Yüksek riskli IP'ler için dark web verisi oluştur
        if row['risk'] > 60 and random.random() < 0.15:  # %15 ihtimal
            
            # Email hash oluştur (privacy için)
            email_hash = hashlib.md5(f"{row['ip']}_{random.randint(1, 1000)}".encode()).hexdigest()[:16]
            
            darkweb_data.append({
                'ip': row['ip'],
                'timestamp': row['timestamp'],
                'risk': row['risk'],
                'country': row['country'],
                'marketplace': random.choice(marketplaces),
                'breach_type': random.choice(breach_types),
                'criminal_activity': random.choice(criminal_activities),
                'forum_category': random.choice(forum_categories),
                'email_hash': email_hash,
                'price_usd': random.randint(1, 10000),
                'records_count': random.randint(100, 1000000),
                'breach_date': row['timestamp'] - timedelta(days=random.randint(1, 365)),
                'seller_reputation': random.uniform(1, 5),
                'verified_breach': random.choice([True, False]),
                'organization_type': random.choice([
                    'Financial Institution', 'Healthcare', 'E-commerce', 'Government',
                    'Education', 'Technology', 'Social Media', 'Retail'
                ]),
                'tor_node': f"onion{random.randint(100, 999)}.example",
                'cryptocurrency': random.choice(['Bitcoin', 'Monero', 'Ethereum', 'Litecoin'])
            })
    
    return pd.DataFrame(darkweb_data)

def breach_intelligence(darkweb_df):
    """Veri Sızıntısı İstihbaratı"""
    st.markdown("## 🔓 Veri Sızıntısı İstihbaratı")
    
    if darkweb_df.empty:
        st.warning("Dark Web verisi bulunamadı.")
        return
    
    tab1, tab2, tab3 = st.tabs(["📊 Breach Overview", "💰 Market Analysis", "🏢 Organization Impact"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Sızıntı türü analizi
            breach_analysis = darkweb_df.groupby('breach_type').agg({
                'records_count': ['sum', 'mean'],
                'price_usd': ['sum', 'mean'],
                'verified_breach': lambda x: (x == True).sum()
            }).round(2)
            breach_analysis.columns = ['Total Records', 'Avg Records', 'Total Price ($)', 'Avg Price ($)', 'Verified']
            breach_analysis = breach_analysis.sort_values('Total Records', ascending=False)
            
            st.markdown("#### 📋 Sızıntı Türü Analizi")
            st.dataframe(breach_analysis, use_container_width=True)
            
            # En değerli sızıntılar
            top_valuable = darkweb_df.nlargest(10, 'price_usd')[['breach_type', 'organization_type', 'price_usd', 'records_count', 'verified_breach']]
            
            st.markdown("#### 💎 En Değerli Sızıntılar")
            st.dataframe(top_valuable, use_container_width=True)
        
        with col2:
            # Sızıntı türü dağılımı
            breach_dist = darkweb_df['breach_type'].value_counts()
            
            fig = px.pie(
                values=breach_dist.values,
                names=breach_dist.index,
                title="Veri Sızıntısı Türü Dağılımı",
                hole=0.4
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            # Zaman serisi analizi
            daily_breaches = darkweb_df.groupby(darkweb_df['breach_date'].dt.date).size()
            
            fig = px.line(
                x=daily_breaches.index,
                y=daily_breaches.values,
                title="Günlük Sızıntı Aktivitesi",
                labels={'x': 'Tarih', 'y': 'Sızıntı Sayısı'}
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            # Marketplace analizi
            marketplace_analysis = darkweb_df.groupby('marketplace').agg({
                'price_usd': ['sum', 'mean', 'count'],
                'seller_reputation': 'mean',
                'verified_breach': lambda x: (x == True).sum()
            }).round(2)
            marketplace_analysis.columns = ['Total Revenue', 'Avg Price', 'Listings', 'Avg Reputation', 'Verified']
            marketplace_analysis = marketplace_analysis.sort_values('Total Revenue', ascending=False)
            
            st.markdown("#### 🏪 Marketplace Analizi")
            st.dataframe(marketplace_analysis, use_container_width=True)
        
        with col2:
            # Cryptocurrency kullanımı
            crypto_usage = darkweb_df['cryptocurrency'].value_counts()
            
            fig = px.bar(
                x=crypto_usage.index,
                y=crypto_usage.values,
                title="Cryptocurrency Kullanım Dağılımı",
                labels={'x': 'Cryptocurrency', 'y': 'Kullanım Sayısı'},
                color=crypto_usage.values,
                color_continuous_scale="Viridis"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
            
            # Fiyat vs kayıt sayısı korelasyonu
            fig = px.scatter(
                darkweb_df,
                x='records_count',
                y='price_usd',
                color='breach_type',
                size='seller_reputation',
                title="Kayıt Sayısı vs Fiyat Korelasyonu",
                labels={'records_count': 'Kayıt Sayısı', 'price_usd': 'Fiyat ($)'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Organizasyon türü analizi
        org_analysis = darkweb_df.groupby('organization_type').agg({
            'records_count': ['sum', 'count'],
            'price_usd': ['sum', 'mean'],
            'verified_breach': lambda x: (x == True).sum()
        }).round(2)
        org_analysis.columns = ['Total Records', 'Breach Count', 'Total Value ($)', 'Avg Price ($)', 'Verified']
        org_analysis = org_analysis.sort_values('Total Value ($)', ascending=False)
        
        st.markdown("#### 🏢 Organizasyon Türü Etki Analizi")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.dataframe(org_analysis, use_container_width=True)
        
        with col2:
            # En çok hedeflenen organizasyonlar
            fig = px.bar(
                x=org_analysis.index,
                y=org_analysis['Breach Count'],
                title="En Çok Hedeflenen Organizasyon Türleri",
                labels={'x': 'Organizasyon Türü', 'y': 'Sızıntı Sayısı'},
                color=org_analysis['Breach Count'],
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, xaxis_tickangle=-45, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

def criminal_marketplace_analysis(darkweb_df):
    """Kriminal Marketplace Analizi"""
    st.markdown("## 🏪 Kriminal Marketplace Analizi")
    
    if darkweb_df.empty:
        st.warning("Marketplace verisi bulunamadı.")
        return
    
    tab1, tab2, tab3 = st.tabs(["🛒 Activity Analysis", "👥 Seller Networks", "🔍 Threat Intelligence"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Kriminal aktivite analizi
            activity_analysis = darkweb_df.groupby('criminal_activity').agg({
                'price_usd': ['sum', 'mean', 'count'],
                'seller_reputation': 'mean'
            }).round(2)
            activity_analysis.columns = ['Total Revenue', 'Avg Price', 'Listings', 'Avg Reputation']
            activity_analysis = activity_analysis.sort_values('Total Revenue', ascending=False)
            
            st.markdown("#### 🎯 Kriminal Aktivite Analizi")
            st.dataframe(activity_analysis, use_container_width=True)
        
        with col2:
            # Aktivite dağılımı
            activity_dist = darkweb_df['criminal_activity'].value_counts().head(8)
            
            fig = px.bar(
                x=activity_dist.values,
                y=activity_dist.index,
                orientation='h',
                title="Kriminal Aktivite Dağılımı",
                labels={'x': 'Listing Sayısı', 'y': 'Aktivite Türü'},
                color=activity_dist.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Seller network analizi
        st.markdown("#### 👥 Seller Network Analizi")
        
        # Satıcı reputasyon analizi
        reputation_bins = pd.cut(darkweb_df['seller_reputation'], bins=[0, 2, 3, 4, 5], labels=['Low', 'Medium', 'High', 'Very High'])
        reputation_analysis = darkweb_df.groupby(reputation_bins).agg({
            'price_usd': ['sum', 'mean'],
            'criminal_activity': 'count'
        }).round(2)
        reputation_analysis.columns = ['Total Revenue', 'Avg Price', 'Listing Count']
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.dataframe(reputation_analysis, use_container_width=True)
            
            # En aktif ülkeler
            country_activity = darkweb_df['country'].value_counts().head(10)
            
            fig = px.bar(
                x=country_activity.index,
                y=country_activity.values,
                title="Dark Web Aktivitesi - Ülke Bazında",
                labels={'x': 'Ülke', 'y': 'Aktivite Sayısı'},
                color=country_activity.values,
                color_continuous_scale="Viridis"
            )
            fig.update_layout(height=400, xaxis_tickangle=-45, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Reputasyon dağılımı
            fig = px.histogram(
                darkweb_df,
                x='seller_reputation',
                nbins=20,
                title="Satıcı Reputasyon Dağılımı",
                labels={'x': 'Reputasyon Skoru', 'y': 'Satıcı Sayısı'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Threat Intelligence
        st.markdown("#### 🔍 Dark Web Threat Intelligence")
        
        # En tehlikeli kombinasyonlar
        threat_combinations = darkweb_df.groupby(['criminal_activity', 'breach_type']).agg({
            'price_usd': 'sum',
            'records_count': 'sum'
        }).sort_values('price_usd', ascending=False).head(10)
        
        st.markdown("##### 🚨 En Tehlikeli Kombinasyonlar")
        st.dataframe(threat_combinations, use_container_width=True)
        
        # IOC'ler (Indicators of Compromise)
        st.markdown("##### 🎯 Dark Web IOC'ler")
        
        ioc_data = []
        
        # Yüksek değerli sızıntılar
        high_value_breaches = darkweb_df[darkweb_df['price_usd'] > darkweb_df['price_usd'].quantile(0.9)]
        for _, breach in high_value_breaches.iterrows():
            ioc_data.append({
                'IOC Type': 'High-Value Breach',
                'Indicator': f"{breach['breach_type']} from {breach['organization_type']}",
                'Value': f"${breach['price_usd']:,}",
                'Risk Level': 'Critical',
                'Source': breach['marketplace']
            })
        
        # Büyük veri sızıntıları
        large_breaches = darkweb_df[darkweb_df['records_count'] > darkweb_df['records_count'].quantile(0.9)]
        for _, breach in large_breaches.iterrows():
            ioc_data.append({
                'IOC Type': 'Large Breach',
                'Indicator': f"{breach['records_count']:,} records - {breach['breach_type']}",
                'Value': f"{breach['records_count']:,} records",
                'Risk Level': 'High',
                'Source': breach['marketplace']
            })
        
        if ioc_data:
            ioc_df = pd.DataFrame(ioc_data)
            st.dataframe(ioc_df, use_container_width=True)

def forum_monitoring(darkweb_df):
    """Forum İzleme"""
    st.markdown("## 💬 Dark Web Forum İzleme")
    
    if darkweb_df.empty:
        st.warning("Forum verisi bulunamadı.")
        return
    
    tab1, tab2 = st.tabs(["📊 Forum Analysis", "🔍 Trend Monitoring"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Forum kategori analizi
            forum_analysis = darkweb_df.groupby('forum_category').agg({
                'criminal_activity': 'count',
                'seller_reputation': 'mean',
                'price_usd': 'mean'
            }).round(2)
            forum_analysis.columns = ['Post Count', 'Avg Reputation', 'Avg Price ($)']
            forum_analysis = forum_analysis.sort_values('Post Count', ascending=False)
            
            st.markdown("#### 💬 Forum Kategori Analizi")
            st.dataframe(forum_analysis, use_container_width=True)
        
        with col2:
            # Forum aktivite dağılımı
            forum_dist = darkweb_df['forum_category'].value_counts()
            
            fig = px.pie(
                values=forum_dist.values,
                names=forum_dist.index,
                title="Forum Aktivite Dağılımı",
                hole=0.3
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            fig.update_layout(height=500)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Trend monitoring
        st.markdown("#### 📈 Forum Trend Analizi")
        
        # Zaman bazlı forum aktivitesi
        forum_timeline = darkweb_df.groupby([darkweb_df['timestamp'].dt.date, 'forum_category']).size().reset_index()
        forum_timeline.columns = ['date', 'category', 'activity_count']
        
        # En aktif kategoriler için trend
        top_categories = darkweb_df['forum_category'].value_counts().head(5).index
        
        fig = go.Figure()
        
        for category in top_categories:
            category_data = forum_timeline[forum_timeline['category'] == category]
            fig.add_trace(go.Scatter(
                x=category_data['date'],
                y=category_data['activity_count'],
                mode='lines+markers',
                name=category,
                line=dict(width=2)
            ))
        
        fig.update_layout(
            title="Forum Kategori Trend Analizi",
            xaxis_title="Tarih",
            yaxis_title="Aktivite Sayısı",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)

def threat_attribution(darkweb_df):
    """Tehdit Atıfı"""
    st.markdown("## 🎯 Dark Web Tehdit Atıfı")
    
    if darkweb_df.empty:
        st.warning("Atıf verisi bulunamadı.")
        return
    
    # Genel istatistikler
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_value = darkweb_df['price_usd'].sum()
        st.metric("💰 Toplam Değer", f"${total_value:,}")
    
    with col2:
        total_records = darkweb_df['records_count'].sum()
        st.metric("📊 Toplam Kayıt", f"{total_records:,}")
    
    with col3:
        verified_rate = (darkweb_df['verified_breach'].sum() / len(darkweb_df)) * 100
        st.metric("✅ Doğrulama Oranı", f"{verified_rate:.1f}%")
    
    with col4:
        avg_reputation = darkweb_df['seller_reputation'].mean()
        st.metric("⭐ Ortalama Reputasyon", f"{avg_reputation:.2f}")
    
    # Atıf haritası
    st.markdown("### 🗺️ Coğrafi Tehdit Atıfı")
    
    country_attribution = darkweb_df.groupby('country').agg({
        'price_usd': 'sum',
        'records_count': 'sum',
        'criminal_activity': 'count'
    }).round(2)
    country_attribution.columns = ['Total Value ($)', 'Total Records', 'Activity Count']
    
    if not country_attribution.empty:
        fig = px.choropleth(
            locations=country_attribution.index,
            color=country_attribution['Total Value ($)'],
            locationmode='country names',
            title="Dark Web Aktivitesi - Coğrafi Dağılım",
            color_continuous_scale="Reds",
            labels={'color': 'Total Value ($)'}
        )
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)
    
    # Detaylı atıf tablosu
    st.markdown("### 📋 Detaylı Tehdit Atıfı")
    st.dataframe(country_attribution.sort_values('Total Value ($)', ascending=False), use_container_width=True)

# Ana fonksiyon
def main():
    df = load_data()
    darkweb_df = generate_darkweb_data(df)
    
    # Genel dark web istatistikleri
    if not darkweb_df.empty:
        st.markdown("## 🕸️ Dark Web Intelligence Dashboard")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("🔓 Toplam Sızıntı", len(darkweb_df))
        
        with col2:
            unique_marketplaces = darkweb_df['marketplace'].nunique()
            st.metric("🏪 Aktif Marketplace", unique_marketplaces)
        
        with col3:
            total_records = darkweb_df['records_count'].sum()
            st.metric("📊 Sızan Kayıt", f"{total_records:,}")
        
        with col4:
            total_value = darkweb_df['price_usd'].sum()
            st.metric("💰 Toplam Değer", f"${total_value:,}")
        
        # Ana analiz bölümleri
        breach_intelligence(darkweb_df)
        criminal_marketplace_analysis(darkweb_df)
        forum_monitoring(darkweb_df)
        threat_attribution(darkweb_df)
        
        # Özet rapor
        st.markdown("## 📋 Dark Web Intelligence Özeti")
        
        summary_report = f"""
        ### 🕸️ CyberTrack Vision - Dark Web Intelligence Raporu
        
        **Rapor Tarihi:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        #### 📊 Genel İstatistikler
        - **Toplam Veri Sızıntısı:** {len(darkweb_df):,}
        - **Aktif Marketplace Sayısı:** {darkweb_df['marketplace'].nunique()}
        - **Toplam Sızan Kayıt:** {darkweb_df['records_count'].sum():,}
        - **Toplam Piyasa Değeri:** ${darkweb_df['price_usd'].sum():,}
        - **Doğrulanmış Sızıntı Oranı:** {(darkweb_df['verified_breach'].sum() / len(darkweb_df) * 100):.1f}%
        
        #### 🎯 En Riskli Alanlar
        - **En Değerli Sızıntı Türü:** {darkweb_df.groupby('breach_type')['price_usd'].sum().idxmax()}
        - **En Aktif Marketplace:** {darkweb_df['marketplace'].mode().iloc[0]}
        - **En Çok Hedeflenen Sektör:** {darkweb_df['organization_type'].mode().iloc[0]}
        - **Dominant Cryptocurrency:** {darkweb_df['cryptocurrency'].mode().iloc[0]}
        
        #### ⚠️ Kritik Uyarılar
        - Yüksek değerli veri sızıntılarında artış gözlendi
        - Finansal veri ticaretinde yoğunlaşma var
        - Belirli marketplace'lerde aktivite artışı
        
        **Bu rapor CyberTrack Vision Dark Web Intelligence modülü tarafından oluşturulmuştur.**
        """
        
        st.markdown(summary_report)
        
        # Rapor indirme
        st.download_button(
            "📥 Dark Web Intelligence Raporu İndir",
            summary_report,
            file_name=f"darkweb_intelligence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown"
        )
    else:
        st.warning("Dark Web intelligence verisi oluşturulamadı.")

if __name__ == "__main__":
    main()
