import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from datetime import datetime, timedelta

st.set_page_config(
    page_title="🔍 Gelişmiş Analitik",
    page_icon="🔍",
    layout="wide"
)

st.markdown("# 🔍 Gelişmiş Analitik ve İstatistikler")

@st.cache_data
def load_data():
    df = pd.read_csv('data/cybertrack_mock_dataset.csv')
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df

def statistical_analysis(df):
    """İstatistiksel analiz"""
    st.markdown("## 📊 İstatistiksel Özet")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Risk skoru istatistikleri
        st.markdown("### Risk Skoru İstatistikleri")
        risk_stats = df['risk'].describe()
        
        stats_df = pd.DataFrame({
            'İstatistik': ['Ortalama', 'Medyan', 'Standart Sapma', 'Minimum', 'Maksimum', 'Q1', 'Q3'],
            'Değer': [
                risk_stats['mean'],
                risk_stats['50%'],
                risk_stats['std'],
                risk_stats['min'],
                risk_stats['max'],
                risk_stats['25%'],
                risk_stats['75%']
            ]
        })
        stats_df['Değer'] = stats_df['Değer'].round(2)
        st.dataframe(stats_df, use_container_width=True)
    
    with col2:
        # Risk dağılım grafiği
        fig = go.Figure()
        fig.add_trace(go.Histogram(
            x=df['risk'],
            nbinsx=30,
            name='Risk Dağılımı',
            opacity=0.7
        ))
        
        # Ortalama çizgisi
        fig.add_vline(
            x=df['risk'].mean(),
            line_dash="dash",
            line_color="red",
            annotation_text=f"Ortalama: {df['risk'].mean():.1f}"
        )
        
        fig.update_layout(
            title="Risk Skoru Dağılımı",
            xaxis_title="Risk Skoru",
            yaxis_title="Frekans",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)

def correlation_analysis(df):
    """Korelasyon analizi"""
    st.markdown("## 🔗 Korelasyon ve İlişki Analizi")
    
    # Kategorik değişkenleri sayısal hale getir
    df_encoded = df.copy()
    
    # Ülke kodlarını frekansa göre encode et
    country_freq = df['country'].value_counts()
    df_encoded['country_freq'] = df_encoded['country'].map(country_freq)
    
    # ISP'leri frekansa göre encode et
    isp_freq = df['isp'].value_counts()
    df_encoded['isp_freq'] = df_encoded['isp'].map(isp_freq)
    
    # Saat ve gün bilgilerini ekle
    df_encoded['hour'] = df_encoded['timestamp'].dt.hour
    df_encoded['day_of_week'] = df_encoded['timestamp'].dt.dayofweek
    
    # Korelasyon matrisi için sayısal sütunları seç
    numeric_cols = ['risk', 'latitude', 'longitude', 'country_freq', 'isp_freq', 'hour', 'day_of_week']
    corr_matrix = df_encoded[numeric_cols].corr()
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Korelasyon ısı haritası
        fig = px.imshow(
            corr_matrix,
            text_auto=True,
            aspect="auto",
            title="Değişkenler Arası Korelasyon Matrisi",
            color_continuous_scale="RdBu_r"
        )
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # En yüksek korelasyonlar
        st.markdown("### 🔝 En Yüksek Korelasyonlar")
        
        # Korelasyon değerlerini düzleştir ve sırala
        corr_pairs = []
        for i in range(len(corr_matrix.columns)):
            for j in range(i+1, len(corr_matrix.columns)):
                var1 = corr_matrix.columns[i]
                var2 = corr_matrix.columns[j]
                corr_val = corr_matrix.iloc[i, j]
                corr_pairs.append((var1, var2, abs(corr_val), corr_val))
        
        # En yüksek korelasyonları göster
        corr_pairs.sort(key=lambda x: x[2], reverse=True)
        for var1, var2, abs_corr, corr in corr_pairs[:5]:
            direction = "📈" if corr > 0 else "📉"
            st.write(f"{direction} **{var1}** - **{var2}**: {corr:.3f}")

def anomaly_detection(df):
    """Anomali tespiti"""
    st.markdown("## 🚨 Anomali Tespiti")
    
    tab1, tab2, tab3 = st.tabs(["📈 Zaman Serisi Anomali", "🎯 Risk Anomali", "🌍 Coğrafi Anomali"])
    
    with tab1:
        # Günlük saldırı sayısında anomali
        daily_attacks = df.groupby(df['timestamp'].dt.date).size()
        
        # Z-score hesaplama
        mean_attacks = daily_attacks.mean()
        std_attacks = daily_attacks.std()
        threshold = st.slider("Anomali Eşiği (Z-score)", 1.0, 3.0, 2.0, 0.1)
        
        z_scores = abs((daily_attacks - mean_attacks) / std_attacks)
        anomalies = daily_attacks[z_scores > threshold]
        
        # Grafik
        fig = go.Figure()
        
        # Normal günler
        normal_days = daily_attacks[z_scores <= threshold]
        fig.add_trace(go.Scatter(
            x=normal_days.index,
            y=normal_days.values,
            mode='lines+markers',
            name='Normal Günler',
            line=dict(color='blue'),
            marker=dict(size=6)
        ))
        
        # Anomali günleri
        if len(anomalies) > 0:
            fig.add_trace(go.Scatter(
                x=anomalies.index,
                y=anomalies.values,
                mode='markers',
                name='Anomali Günleri',
                marker=dict(color='red', size=12, symbol='x')
            ))
        
        # Ortalama çizgisi
        fig.add_hline(
            y=mean_attacks,
            line_dash="dash",
            line_color="green",
            annotation_text=f"Ortalama: {mean_attacks:.1f}"
        )
        
        # Eşik çizgileri
        fig.add_hline(
            y=mean_attacks + threshold * std_attacks,
            line_dash="dot",
            line_color="red",
            annotation_text=f"Üst Eşik"
        )
        
        fig.update_layout(
            title=f"Günlük Saldırı Anomalileri (Tespit Edilen: {len(anomalies)})",
            xaxis_title="Tarih",
            yaxis_title="Saldırı Sayısı",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)
        
        if len(anomalies) > 0:
            st.markdown("### 🚨 Anomali Günleri")
            for date, count in anomalies.items():
                st.write(f"📅 **{date}**: {count} saldırı (Z-score: {z_scores[date]:.2f})")
    
    with tab2:
        # Risk skoru anomalileri
        risk_mean = df['risk'].mean()
        risk_std = df['risk'].std()
        risk_threshold = st.slider("Risk Anomali Eşiği (Z-score)", 1.0, 3.0, 2.5, 0.1)
        
        risk_z_scores = abs((df['risk'] - risk_mean) / risk_std)
        risk_anomalies = df[risk_z_scores > risk_threshold]
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk anomali dağılımı
            fig = px.scatter(
                df,
                x=range(len(df)),
                y='risk',
                color=risk_z_scores > risk_threshold,
                title="Risk Skoru Anomalileri",
                labels={'x': 'Kayıt Sırası', 'y': 'Risk Skoru', 'color': 'Anomali'},
                color_discrete_map={True: 'red', False: 'blue'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Anomali özeti
            st.markdown(f"### 📊 Risk Anomali Özeti")
            st.metric("Toplam Anomali", len(risk_anomalies))
            st.metric("Anomali Oranı", f"{len(risk_anomalies)/len(df)*100:.1f}%")
            
            if len(risk_anomalies) > 0:
                st.markdown("**En Yüksek Risk Anomalileri:**")
                top_risk_anomalies = risk_anomalies.nlargest(5, 'risk')[['ip', 'country', 'risk']]
                st.dataframe(top_risk_anomalies, use_container_width=True)
    
    with tab3:
        # Coğrafi anomaliler
        st.markdown("### 🌍 Coğrafi Saldırı Yoğunluğu Anomalileri")
        
        # Ülke bazında saldırı yoğunluğu
        country_attacks = df['country'].value_counts()
        country_mean = country_attacks.mean()
        country_std = country_attacks.std()
        geo_threshold = st.slider("Coğrafi Anomali Eşiği (Z-score)", 1.0, 3.0, 2.0, 0.1)
        
        country_z_scores = abs((country_attacks - country_mean) / country_std)
        geo_anomalies = country_attacks[country_z_scores > geo_threshold]
        
        if len(geo_anomalies) > 0:
            col1, col2 = st.columns(2)
            
            with col1:
                # Anomali ülkelerin grafiği
                fig = px.bar(
                    x=geo_anomalies.index,
                    y=geo_anomalies.values,
                    title="Anormal Saldırı Yoğunluğuna Sahip Ülkeler",
                    labels={'x': 'Ülke', 'y': 'Saldırı Sayısı'},
                    color=geo_anomalies.values,
                    color_continuous_scale="Reds"
                )
                fig.update_layout(height=400, xaxis_tickangle=-45)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("**Anomali Ülkeleri:**")
                for country, count in geo_anomalies.items():
                    z_score = country_z_scores[country]
                    st.write(f"🚩 **{country}**: {count} saldırı (Z-score: {z_score:.2f})")
        else:
            st.info("Coğrafi anomali tespit edilmedi.")

def predictive_analysis(df):
    """Tahmin analizi"""
    st.markdown("## 🔮 Tahminsel Analiz")
    
    # Basit trend analizi
    daily_attacks = df.groupby(df['timestamp'].dt.date).size().reset_index(name='attacks')
    daily_attacks['date'] = pd.to_datetime(daily_attacks['timestamp'])
    daily_attacks['days_from_start'] = (daily_attacks['date'] - daily_attacks['date'].min()).dt.days
    
    # Linear regression for trend
    z = np.polyfit(daily_attacks['days_from_start'], daily_attacks['attacks'], 1)
    p = np.poly1d(z)
    
    # Gelecek 7 günlük tahmin
    future_days = np.arange(daily_attacks['days_from_start'].max() + 1, 
                           daily_attacks['days_from_start'].max() + 8)
    future_dates = [daily_attacks['date'].max() + timedelta(days=i) for i in range(1, 8)]
    future_predictions = p(future_days)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Trend grafiği
        fig = go.Figure()
        
        # Gerçek veriler
        fig.add_trace(go.Scatter(
            x=daily_attacks['date'],
            y=daily_attacks['attacks'],
            mode='lines+markers',
            name='Gerçek Veriler',
            line=dict(color='blue')
        ))
        
        # Trend çizgisi
        fig.add_trace(go.Scatter(
            x=daily_attacks['date'],
            y=p(daily_attacks['days_from_start']),
            mode='lines',
            name='Trend',
            line=dict(color='red', dash='dash')
        ))
        
        # Tahminler
        fig.add_trace(go.Scatter(
            x=future_dates,
            y=future_predictions,
            mode='lines+markers',
            name='7 Günlük Tahmin',
            line=dict(color='green', dash='dot'),
            marker=dict(symbol='diamond', size=8)
        ))
        
        fig.update_layout(
            title="Saldırı Trendi ve 7 Günlük Tahmin",
            xaxis_title="Tarih",
            yaxis_title="Günlük Saldırı Sayısı",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Tahmin metrikleri
        st.markdown("### 📈 Tahmin Metrikleri")
        
        current_avg = daily_attacks['attacks'].tail(7).mean()
        predicted_avg = np.mean(future_predictions)
        change_percent = ((predicted_avg - current_avg) / current_avg) * 100
        
        st.metric(
            "Mevcut 7 Günlük Ortalama",
            f"{current_avg:.1f}",
        )
        
        st.metric(
            "Tahmin Edilen 7 Günlük Ortalama",
            f"{predicted_avg:.1f}",
            delta=f"{change_percent:+.1f}%"
        )
        
        # Trend yönü
        trend_direction = "📈 Artış" if z[0] > 0 else "📉 Azalış" if z[0] < 0 else "➡️ Sabit"
        st.markdown(f"**Trend Yönü:** {trend_direction}")
        st.markdown(f"**Günlük Değişim Oranı:** {z[0]:.2f}")
        
        # Gelecek tahminleri tablosu
        st.markdown("### 📅 7 Günlük Detaylı Tahmin")
        future_df = pd.DataFrame({
            'Tarih': [d.strftime('%Y-%m-%d') for d in future_dates],
            'Tahmini Saldırı': [f"{p:.0f}" for p in future_predictions]
        })
        st.dataframe(future_df, use_container_width=True)

def clustering_analysis(df):
    """Kümeleme analizi"""
    st.markdown("## 🎯 Kümeleme Analizi")
    
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler
    
    # Kümeleme için özellik seçimi
    features = ['risk', 'latitude', 'longitude']
    
    # Veriyi hazırla
    X = df[features].dropna()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Optimal küme sayısını bul (Elbow method)
    inertias = []
    k_range = range(2, 11)
    
    for k in k_range:
        kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
        kmeans.fit(X_scaled)
        inertias.append(kmeans.inertia_)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Elbow curve
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=list(k_range),
            y=inertias,
            mode='lines+markers',
            name='Inertia'
        ))
        fig.update_layout(
            title="Optimal Küme Sayısı (Elbow Method)",
            xaxis_title="Küme Sayısı",
            yaxis_title="Inertia",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Küme sayısı seçimi
        n_clusters = st.selectbox("Küme Sayısını Seçin", options=list(k_range), index=2)
        
        # KMeans uygula
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        clusters = kmeans.fit_predict(X_scaled)
        
        # Küme dağılımı
        cluster_counts = pd.Series(clusters).value_counts().sort_index()
        
        fig = px.bar(
            x=[f"Küme {i}" for i in cluster_counts.index],
            y=cluster_counts.values,
            title="Küme Dağılımı",
            labels={'x': 'Küme', 'y': 'Kayıt Sayısı'}
        )
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    # Kümeleme sonuçlarını 3D göster
    df_clustered = X.copy()
    df_clustered['Cluster'] = clusters
    
    fig = px.scatter_3d(
        df_clustered,
        x='latitude',
        y='longitude',
        z='risk',
        color='Cluster',
        title="3D Kümeleme Sonuçları",
        labels={'latitude': 'Enlem', 'longitude': 'Boylam', 'risk': 'Risk Skoru'}
    )
    fig.update_layout(height=600)
    st.plotly_chart(fig, use_container_width=True)
    
    # Küme özellikleri
    st.markdown("### 📊 Küme Özellikleri")
    
    cluster_summary = df_clustered.groupby('Cluster').agg({
        'risk': ['mean', 'std', 'count'],
        'latitude': 'mean',
        'longitude': 'mean'
    }).round(2)
    
    cluster_summary.columns = ['Ortalama Risk', 'Risk Std', 'Kayıt Sayısı', 'Ortalama Enlem', 'Ortalama Boylam']
    st.dataframe(cluster_summary, use_container_width=True)

# Ana fonksiyon
def main():
    df = load_data()
    
    # İstatistiksel analiz
    statistical_analysis(df)
    
    # Korelasyon analizi
    correlation_analysis(df)
    
    # Anomali tespiti
    anomaly_detection(df)
    
    # Tahminsel analiz
    predictive_analysis(df)
    
    # Kümeleme analizi
    clustering_analysis(df)

if __name__ == "__main__":
    main()
