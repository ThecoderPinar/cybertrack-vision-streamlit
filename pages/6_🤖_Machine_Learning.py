import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt

st.set_page_config(
    page_title="🤖 Makine Öğrenmesi",
    page_icon="🤖",
    layout="wide"
)

st.markdown("# 🤖 Makine Öğrenmesi Modelleri")

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
    
    # Zaman özelliklerini ekle
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['month'] = df['timestamp'].dt.month
    
    return df

def prepare_features(df):
    """Makine öğrenmesi için özellik hazırlama"""
    # Kategorik değişkenleri encode et
    le_country = LabelEncoder()
    le_isp = LabelEncoder()
    
    df_encoded = df.copy()
    df_encoded['country_encoded'] = le_country.fit_transform(df['country'])
    df_encoded['isp_encoded'] = le_isp.fit_transform(df['isp'])
    
    # Özellik matrisi
    features = ['latitude', 'longitude', 'hour', 'day_of_week', 'month', 
                'country_encoded', 'isp_encoded']
    
    X = df_encoded[features]
    y_regression = df_encoded['risk']
    y_classification = df_encoded['risk_category_en']
    
    return X, y_regression, y_classification, le_country, le_isp

def risk_prediction_model(df):
    """Risk tahmin modeli"""
    st.markdown("## 🎯 Risk Skoru Tahmin Modeli")
    
    X, y_regression, y_classification, le_country, le_isp = prepare_features(df)
    
    tab1, tab2 = st.tabs(["📊 Regresyon Modeli", "🏷️ Sınıflandırma Modeli"])
    
    with tab1:
        st.markdown("### Regresyon - Risk Skoru Tahmini")
        
        # Model eğitimi
        X_train, X_test, y_train, y_test = train_test_split(X, y_regression, test_size=0.2, random_state=42)
        
        from sklearn.ensemble import RandomForestRegressor
        rf_regressor = RandomForestRegressor(n_estimators=100, random_state=42)
        rf_regressor.fit(X_train, y_train)
        
        # Tahminler
        y_pred = rf_regressor.predict(X_test)
        
        # Model performansı
        from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
        
        mae = mean_absolute_error(y_test, y_pred)
        mse = mean_squared_error(y_test, y_pred)
        r2 = r2_score(y_test, y_pred)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Ortalama Mutlak Hata (MAE)", f"{mae:.2f}")
        with col2:
            st.metric("R² Skoru", f"{r2:.3f}")
        with col3:
            st.metric("RMSE", f"{np.sqrt(mse):.2f}")
        
        # Gerçek vs Tahmin grafiği
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.scatter(
                x=y_test, 
                y=y_pred,
                title="Gerçek vs Tahmin Edilen Risk Skorları",
                labels={'x': 'Gerçek Risk', 'y': 'Tahmin Edilen Risk'},
                opacity=0.6
            )
            
            # Perfect prediction line
            min_val = min(y_test.min(), y_pred.min())
            max_val = max(y_test.max(), y_pred.max())
            fig.add_trace(go.Scatter(
                x=[min_val, max_val],
                y=[min_val, max_val],
                mode='lines',
                name='Mükemmel Tahmin',
                line=dict(dash='dash', color='red')
            ))
            
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Feature importance
            feature_importance = pd.DataFrame({
                'feature': X.columns,
                'importance': rf_regressor.feature_importances_
            }).sort_values('importance', ascending=False)
            
            fig = px.bar(
                feature_importance,
                x='importance',
                y='feature',
                orientation='h',
                title="Özellik Önem Sıralaması",
                labels={'importance': 'Önem Skoru', 'feature': 'Özellik'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        st.markdown("### Sınıflandırma - Risk Kategorisi Tahmini")
        
        # Model eğitimi
        X_train, X_test, y_train_class, y_test_class = train_test_split(X, y_classification, test_size=0.2, random_state=42)
        
        rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_classifier.fit(X_train, y_train_class)
        
        # Tahminler
        y_pred_class = rf_classifier.predict(X_test)
        
        # Model performansı
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support
        
        accuracy = accuracy_score(y_test_class, y_pred_class)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test_class, y_pred_class, average='weighted')
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Doğruluk (Accuracy)", f"{accuracy:.3f}")
        with col2:
            st.metric("Kesinlik (Precision)", f"{precision:.3f}")
        with col3:
            st.metric("Geri Çağırma (Recall)", f"{recall:.3f}")
        
        # Confusion Matrix
        col1, col2 = st.columns(2)
        
        with col1:
            cm = confusion_matrix(y_test_class, y_pred_class)
            
            fig = px.imshow(
                cm,
                text_auto=True,
                aspect="auto",
                title="Karışıklık Matrisi",
                labels={'x': 'Tahmin Edilen', 'y': 'Gerçek'},
                x=['High', 'Low', 'Medium'],
                y=['High', 'Low', 'Medium']
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Sınıf bazlı metrikler
            report = classification_report(y_test_class, y_pred_class, output_dict=True)
            
            classes = ['High', 'Low', 'Medium']
            metrics_df = pd.DataFrame({
                'Sınıf': classes,
                'Precision': [report[cls]['precision'] for cls in classes],
                'Recall': [report[cls]['recall'] for cls in classes],
                'F1-Score': [report[cls]['f1-score'] for cls in classes]
            })
            
            fig = px.bar(
                metrics_df.melt(id_vars='Sınıf', var_name='Metrik', value_name='Skor'),
                x='Sınıf',
                y='Skor',
                color='Metrik',
                title="Sınıf Bazlı Model Performansı",
                barmode='group'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

def anomaly_detection(df):
    """Anomali tespiti"""
    st.markdown("## 🚨 Anomali Tespit Modeli")
    
    # Özellik hazırlama
    X, _, _, _, _ = prepare_features(df)
    
    # Isolation Forest modeli
    isolation_forest = IsolationForest(contamination=0.1, random_state=42)
    anomaly_labels = isolation_forest.fit_predict(X)
    
    # Anomali skorları
    anomaly_scores = isolation_forest.decision_function(X)
    
    # Sonuçları DataFrame'e ekle
    df_anomaly = df.copy()
    df_anomaly['anomaly'] = anomaly_labels
    df_anomaly['anomaly_score'] = anomaly_scores
    df_anomaly['is_anomaly'] = df_anomaly['anomaly'] == -1
    
    # Anomali istatistikleri
    total_anomalies = (anomaly_labels == -1).sum()
    anomaly_percentage = (total_anomalies / len(df)) * 100
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Toplam Anomali", total_anomalies)
    with col2:
        st.metric("Anomali Oranı", f"{anomaly_percentage:.1f}%")
    with col3:
        avg_risk_anomaly = df_anomaly[df_anomaly['is_anomaly']]['risk'].mean()
        st.metric("Anomali Ortalama Risk", f"{avg_risk_anomaly:.1f}")
    
    tab1, tab2, tab3 = st.tabs(["📊 Anomali Dağılımı", "🗺️ Coğrafi Görünüm", "📋 Anomali Detayları"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Anomali vs Normal dağılımı
            fig = px.histogram(
                df_anomaly,
                x='risk',
                color='is_anomaly',
                nbins=30,
                title="Risk Dağılımı: Normal vs Anomali",
                labels={'is_anomaly': 'Anomali', 'risk': 'Risk Skoru'},
                color_discrete_map={True: 'red', False: 'blue'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Anomali skorları dağılımı
            fig = px.histogram(
                df_anomaly,
                x='anomaly_score',
                nbins=30,
                title="Anomali Skorları Dağılımı",
                labels={'anomaly_score': 'Anomali Skoru'}
            )
            fig.add_vline(
                x=df_anomaly[df_anomaly['is_anomaly']]['anomaly_score'].max(),
                line_dash="dash",
                line_color="red",
                annotation_text="Anomali Eşiği"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Coğrafi anomali haritası
        anomalies_geo = df_anomaly[df_anomaly['is_anomaly']]
        
        if not anomalies_geo.empty:
            fig = px.scatter_mapbox(
                anomalies_geo,
                lat='latitude',
                lon='longitude',
                size='risk',
                color='anomaly_score',
                hover_data=['country', 'risk', 'isp'],
                title="Coğrafi Anomali Dağılımı",
                mapbox_style='open-street-map',
                zoom=1,
                height=600
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Coğrafi anomali bulunamadı.")
    
    with tab3:
        # En yüksek anomali skorlarına sahip kayıtlar
        st.markdown("### 🔍 En Yüksek Anomali Skorları")
        
        top_anomalies = df_anomaly[df_anomaly['is_anomaly']].nsmallest(10, 'anomaly_score')[
            ['timestamp', 'ip', 'country', 'risk', 'isp', 'anomaly_score']
        ]
        
        if not top_anomalies.empty:
            st.dataframe(top_anomalies, use_container_width=True)
        else:
            st.info("Anomali bulunamadı.")

def clustering_analysis(df):
    """Kümeleme analizi"""
    st.markdown("## 🎯 Kümeleme Analizi")
    
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler
    
    # Özellik seçimi ve hazırlama
    features_for_clustering = ['risk', 'latitude', 'longitude']
    X_cluster = df[features_for_clustering].dropna()
    
    # Veriyi standartlaştır
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_cluster)
    
    # Optimal küme sayısını bul
    col1, col2 = st.columns(2)
    
    with col1:
        # Elbow method
        inertias = []
        k_range = range(2, 11)
        
        for k in k_range:
            kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
            kmeans.fit(X_scaled)
            inertias.append(kmeans.inertia_)
        
        fig = px.line(
            x=list(k_range),
            y=inertias,
            title="Optimal Küme Sayısı (Elbow Method)",
            labels={'x': 'Küme Sayısı', 'y': 'Inertia'},
            markers=True
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Küme sayısı seçimi
        n_clusters = st.selectbox("Küme Sayısını Seçin", options=list(k_range), index=2)
        
        # KMeans uygula
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        cluster_labels = kmeans.fit_predict(X_scaled)
        
        # Küme dağılımı
        cluster_counts = pd.Series(cluster_labels).value_counts().sort_index()
        
        fig = px.bar(
            x=[f"Küme {i}" for i in cluster_counts.index],
            y=cluster_counts.values,
            title="Küme Dağılımı",
            labels={'x': 'Küme', 'y': 'Kayıt Sayısı'}
        )
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    # Kümeleme sonuçlarını görselleştir
    X_cluster_with_labels = X_cluster.copy()
    X_cluster_with_labels['Cluster'] = cluster_labels
    
    tab1, tab2 = st.tabs(["🎨 3D Görünüm", "📊 Küme Analizi"])
    
    with tab1:
        # 3D scatter plot
        fig = px.scatter_3d(
            X_cluster_with_labels,
            x='latitude',
            y='longitude',
            z='risk',
            color='Cluster',
            title="3D Kümeleme Sonuçları",
            labels={'latitude': 'Enlem', 'longitude': 'Boylam', 'risk': 'Risk Skoru'}
        )
        fig.update_layout(height=600)
        st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Küme özellikleri
        cluster_summary = X_cluster_with_labels.groupby('Cluster').agg({
            'risk': ['mean', 'std', 'count'],
            'latitude': 'mean',
            'longitude': 'mean'
        }).round(2)
        
        cluster_summary.columns = ['Ortalama Risk', 'Risk Std', 'Kayıt Sayısı', 'Ortalama Enlem', 'Ortalama Boylam']
        st.dataframe(cluster_summary, use_container_width=True)
        
        # Her kümenin karakteristikleri
        st.markdown("### 🔍 Küme Karakteristikleri")
        
        for i in range(n_clusters):
            cluster_data = X_cluster_with_labels[X_cluster_with_labels['Cluster'] == i]
            avg_risk = cluster_data['risk'].mean()
            count = len(cluster_data)
            
            risk_level = "🔴 Yüksek" if avg_risk > 60 else "🟡 Orta" if avg_risk > 30 else "🟢 Düşük"
            
            st.write(f"**Küme {i}**: {count} kayıt, Ortalama Risk: {avg_risk:.1f} {risk_level}")

def predictive_modeling(df):
    """Tahminsel modelleme"""
    st.markdown("## 🔮 Tahminsel Modelleme")
    
    # Gelecek saldırı tahmini için zaman serisi analizi
    daily_attacks = df.groupby(df['timestamp'].dt.date).size().reset_index(name='attacks')
    daily_attacks['date'] = pd.to_datetime(daily_attacks['timestamp'])
    daily_attacks['days_from_start'] = (daily_attacks['date'] - daily_attacks['date'].min()).dt.days
    
    # Basit linear regression
    from sklearn.linear_model import LinearRegression
    
    X_time = daily_attacks[['days_from_start']]
    y_time = daily_attacks['attacks']
    
    lr_model = LinearRegression()
    lr_model.fit(X_time, y_time)
    
    # Gelecek 7 günlük tahmin
    future_days = np.arange(daily_attacks['days_from_start'].max() + 1, 
                           daily_attacks['days_from_start'].max() + 8).reshape(-1, 1)
    future_predictions = lr_model.predict(future_days)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Trend ve tahmin grafiği
        fig = go.Figure()
        
        # Gerçek veriler
        fig.add_trace(go.Scatter(
            x=daily_attacks['date'],
            y=daily_attacks['attacks'],
            mode='lines+markers',
            name='Gerçek Veriler',
            line=dict(color='blue')
        ))
        
        # Tahminler
        future_dates = [daily_attacks['date'].max() + pd.Timedelta(days=i) for i in range(1, 8)]
        fig.add_trace(go.Scatter(
            x=future_dates,
            y=future_predictions,
            mode='lines+markers',
            name='7 Günlük Tahmin',
            line=dict(color='red', dash='dash'),
            marker=dict(symbol='diamond', size=8)
        ))
        
        fig.update_layout(
            title="Saldırı Trendi ve Gelecek Tahmini",
            xaxis_title="Tarih",
            yaxis_title="Günlük Saldırı Sayısı",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Model performansı ve metrikler
        train_predictions = lr_model.predict(X_time)
        r2 = r2_score(y_time, train_predictions)
        
        st.markdown("### 📊 Model Performansı")
        st.metric("R² Skoru", f"{r2:.3f}")
        st.metric("Trend Katsayısı", f"{lr_model.coef_[0]:.3f}")
        
        # Gelecek tahminleri tablosu
        st.markdown("### 📅 7 Günlük Tahmin")
        future_df = pd.DataFrame({
            'Tarih': [d.strftime('%Y-%m-%d') for d in future_dates],
            'Tahmini Saldırı': [f"{p:.0f}" for p in future_predictions]
        })
        st.dataframe(future_df, use_container_width=True)

def model_insights(df):
    """Model içgörüleri"""
    st.markdown("## 💡 Model İçgörüleri ve Öneriler")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🎯 Risk Faktörleri")
        
        # En yüksek risk faktörlerini belirle
        high_risk_countries = df.groupby('country')['risk'].mean().sort_values(ascending=False).head(5)
        high_risk_isps = df.groupby('isp')['risk'].mean().sort_values(ascending=False).head(5)
        
        st.markdown("**En Riskli Ülkeler:**")
        for country, risk in high_risk_countries.items():
            st.write(f"🚩 {country}: {risk:.1f}")
        
        st.markdown("**En Riskli ISP'ler:**")
        for isp, risk in high_risk_isps.items():
            st.write(f"🌐 {isp}: {risk:.1f}")
    
    with col2:
        st.markdown("### 🛡️ Güvenlik Önerileri")
        
        # Zaman bazlı öneriler
        risky_hours = df.groupby('hour')['risk'].mean().sort_values(ascending=False).head(3)
        
        st.markdown("**Zaman Bazlı Öneriler:**")
        for hour, risk in risky_hours.items():
            st.write(f"⏰ Saat {hour}:00 - Yüksek risk ({risk:.1f})")
        
        st.markdown("**Genel Öneriler:**")
        st.write("🔍 Anomali tespit sistemini aktif tutun")
        st.write("📊 Risk skorları 70'in üzerindeki IP'leri izleyin")
        st.write("🌍 Coğrafi filtreleme uygulayın")
        st.write("🕐 Yoğun saatlerde ekstra güvenlik önlemleri alın")

# Ana fonksiyon
def main():
    df = load_data()
    
    # Model seçimi
    st.sidebar.markdown("## 🤖 Model Seçimi")
    model_type = st.sidebar.selectbox(
        "Analiz türünü seçin:",
        ["Risk Tahmin Modeli", "Anomali Tespiti", "Kümeleme Analizi", "Tahminsel Modelleme", "Model İçgörüleri"]
    )
    
    if model_type == "Risk Tahmin Modeli":
        risk_prediction_model(df)
    elif model_type == "Anomali Tespiti":
        anomaly_detection(df)
    elif model_type == "Kümeleme Analizi":
        clustering_analysis(df)
    elif model_type == "Tahminsel Modelleme":
        predictive_modeling(df)
    else:
        model_insights(df)

if __name__ == "__main__":
    main()
