import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import numpy as np

st.set_page_config(
    page_title="⏰ Zamansal Analiz",
    page_icon="⏰",
    layout="wide"
)

st.markdown("# ⏰ Zamansal Saldırı Analizi")

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
    
    # Zaman bileşenlerini ekle
    df['hour'] = df['timestamp'].dt.hour
    df['day'] = df['timestamp'].dt.day_name()
    df['month'] = df['timestamp'].dt.month_name()
    df['week'] = df['timestamp'].dt.isocalendar().week
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['is_weekend'] = df['day_of_week'].isin([5, 6])
    
    return df

def hourly_analysis(df):
    """Saatlik analiz"""
    st.markdown("## 🕐 Saatlik Saldırı Analizi")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # 24 saatlik dağılım
        hourly_attacks = df['hour'].value_counts().sort_index()
        
        fig = px.bar(
            x=hourly_attacks.index,
            y=hourly_attacks.values,
            title="24 Saatlik Saldırı Dağılımı",
            labels={'x': 'Saat', 'y': 'Saldırı Sayısı'},
            color=hourly_attacks.values,
            color_continuous_scale="Reds"
        )
        fig.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Saatlere göre ortalama risk
        hourly_risk = df.groupby('hour')['risk'].mean()
        
        fig = px.line(
            x=hourly_risk.index,
            y=hourly_risk.values,
            title="Saatlere Göre Ortalama Risk Skoru",
            labels={'x': 'Saat', 'y': 'Ortalama Risk'},
            markers=True
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    # En riskli saatler
    st.markdown("### 🚨 En Riskli Saatler")
    
    risky_hours = df.groupby('hour').agg({
        'ip': 'count',
        'risk': 'mean'
    }).sort_values('risk', ascending=False).head(5)
    risky_hours.columns = ['Saldırı Sayısı', 'Ortalama Risk']
    risky_hours.index.name = 'Saat'
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.dataframe(risky_hours.round(2), use_container_width=True)
    
    with col2:
        # Radar chart
        categories = [f"{hour}:00" for hour in risky_hours.index]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatterpolar(
            r=risky_hours['Ortalama Risk'].values,
            theta=categories,
            fill='toself',
            name='Risk Skoru'
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, risky_hours['Ortalama Risk'].max() * 1.1]
                )),
            title="En Riskli Saatler - Radar Görünümü",
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)

def daily_weekly_analysis(df):
    """Günlük ve haftalık analiz"""
    st.markdown("## 📅 Günlük ve Haftalık Analiz")
    
    tab1, tab2, tab3 = st.tabs(["📊 Haftanın Günleri", "📈 Haftalık Trendler", "🔄 Hafta Sonu vs Hafta İçi"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Haftanın günlerine göre saldırı dağılımı
            day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            day_attacks = df['day'].value_counts().reindex(day_order)
            
            fig = px.bar(
                x=day_attacks.index,
                y=day_attacks.values,
                title="Haftanın Günlerine Göre Saldırı Dağılımı",
                labels={'x': 'Gün', 'y': 'Saldırı Sayısı'},
                color=day_attacks.values,
                color_continuous_scale="Blues"
            )
            fig.update_layout(height=400, showlegend=False, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Günlere göre ortalama risk
            day_risk = df.groupby('day')['risk'].mean().reindex(day_order)
            
            fig = px.line(
                x=day_risk.index,
                y=day_risk.values,
                title="Günlere Göre Ortalama Risk Skoru",
                labels={'x': 'Gün', 'y': 'Ortalama Risk'},
                markers=True
            )
            fig.update_layout(height=400, xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Haftalık trendler
        weekly_data = df.groupby(df['timestamp'].dt.to_period('W')).agg({
            'ip': 'count',
            'risk': 'mean'
        }).reset_index()
        weekly_data['week_start'] = weekly_data['timestamp'].dt.start_time
        
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        
        fig.add_trace(
            go.Bar(
                x=weekly_data['week_start'],
                y=weekly_data['ip'],
                name="Haftalık Saldırı",
                marker_color='lightblue'
            ),
            secondary_y=False
        )
        
        fig.add_trace(
            go.Scatter(
                x=weekly_data['week_start'],
                y=weekly_data['risk'],
                mode='lines+markers',
                name="Ortalama Risk",
                marker_color='red'
            ),
            secondary_y=True
        )
        
        fig.update_xaxes(title_text="Hafta")
        fig.update_yaxes(title_text="Saldırı Sayısı", secondary_y=False)
        fig.update_yaxes(title_text="Ortalama Risk", secondary_y=True)
        fig.update_layout(title="Haftalık Saldırı ve Risk Trendi", height=500)
        
        st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        # Hafta sonu vs hafta içi karşılaştırması
        weekend_comparison = df.groupby('is_weekend').agg({
            'ip': 'count',
            'risk': ['mean', 'max'],
            'country': 'nunique'
        })
        weekend_comparison.columns = ['Saldırı Sayısı', 'Ortalama Risk', 'Max Risk', 'Ülke Sayısı']
        weekend_comparison.index = ['Hafta İçi', 'Hafta Sonu']
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📊 Hafta Sonu vs Hafta İçi Karşılaştırması")
            st.dataframe(weekend_comparison.round(2), use_container_width=True)
            
            # Yüzdelik hesaplamalar
            weekend_attacks = weekend_comparison.loc['Hafta Sonu', 'Saldırı Sayısı']
            weekday_attacks = weekend_comparison.loc['Hafta İçi', 'Saldırı Sayısı']
            weekend_percentage = (weekend_attacks / (weekend_attacks + weekday_attacks)) * 100
            
            st.metric(
                "Hafta Sonu Saldırı Oranı",
                f"{weekend_percentage:.1f}%",
                delta=f"{'Yüksek' if weekend_percentage > 50 else 'Düşük'} aktivite"
            )
        
        with col2:
            # Görsel karşılaştırma
            categories = ['Saldırı Sayısı', 'Ortalama Risk', 'Max Risk', 'Ülke Sayısı']
            weekday_values = weekend_comparison.loc['Hafta İçi'].values
            weekend_values = weekend_comparison.loc['Hafta Sonu'].values
            
            fig = go.Figure()
            
            fig.add_trace(go.Bar(
                name='Hafta İçi',
                x=categories,
                y=weekday_values,
                marker_color='lightblue'
            ))
            
            fig.add_trace(go.Bar(
                name='Hafta Sonu',
                x=categories,
                y=weekend_values,
                marker_color='lightcoral'
            ))
            
            fig.update_layout(
                title="Hafta İçi vs Hafta Sonu Karşılaştırması",
                barmode='group',
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)

def seasonal_analysis(df):
    """Mevsimsel analiz"""
    st.markdown("## 🌍 Mevsimsel ve Aylık Analiz")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Aylara göre saldırı dağılımı
        month_order = ['January', 'February', 'March', 'April', 'May', 'June',
                      'July', 'August', 'September', 'October', 'November', 'December']
        month_attacks = df['month'].value_counts().reindex([m for m in month_order if m in df['month'].values])
        
        fig = px.bar(
            x=month_attacks.index,
            y=month_attacks.values,
            title="Aylara Göre Saldırı Dağılımı",
            labels={'x': 'Ay', 'y': 'Saldırı Sayısı'},
            color=month_attacks.values,
            color_continuous_scale="Viridis"
        )
        fig.update_layout(height=400, showlegend=False, xaxis_tickangle=-45)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Aylara göre ortalama risk
        month_risk = df.groupby('month')['risk'].mean().reindex([m for m in month_order if m in df['month'].values])
        
        fig = px.line(
            x=month_risk.index,
            y=month_risk.values,
            title="Aylara Göre Ortalama Risk Skoru",
            labels={'x': 'Ay', 'y': 'Ortalama Risk'},
            markers=True
        )
        fig.update_layout(height=400, xaxis_tickangle=-45)
        st.plotly_chart(fig, use_container_width=True)

def time_series_trends(df):
    """Zaman serisi trendleri"""
    st.markdown("## 📈 Zaman Serisi Trend Analizi")
    
    # Günlük zaman serisi
    daily_stats = df.groupby(df['timestamp'].dt.date).agg({
        'ip': 'count',
        'risk': 'mean'
    }).reset_index()
    daily_stats.columns = ['date', 'attacks', 'avg_risk']
    
    # Hareketli ortalamalar
    daily_stats['attacks_ma7'] = daily_stats['attacks'].rolling(window=7, center=True).mean()
    daily_stats['risk_ma7'] = daily_stats['avg_risk'].rolling(window=7, center=True).mean()
    
    tab1, tab2 = st.tabs(["📊 Günlük Trendler", "📉 Hareketli Ortalamalar"])
    
    with tab1:
        # İkili eksen grafiği
        fig = make_subplots(specs=[[{"secondary_y": True}]])
        
        fig.add_trace(
            go.Bar(
                x=daily_stats['date'],
                y=daily_stats['attacks'],
                name="Günlük Saldırı",
                marker_color='lightblue',
                opacity=0.7
            ),
            secondary_y=False
        )
        
        fig.add_trace(
            go.Scatter(
                x=daily_stats['date'],
                y=daily_stats['avg_risk'],
                mode='lines',
                name="Günlük Ortalama Risk",
                line=dict(color='red', width=2)
            ),
            secondary_y=True
        )
        
        fig.update_xaxes(title_text="Tarih")
        fig.update_yaxes(title_text="Saldırı Sayısı", secondary_y=False)
        fig.update_yaxes(title_text="Ortalama Risk", secondary_y=True)
        fig.update_layout(title="Günlük Saldırı ve Risk Trendi", height=500)
        
        st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Hareketli ortalamalar
        col1, col2 = st.columns(2)
        
        with col1:
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=daily_stats['date'],
                y=daily_stats['attacks'],
                mode='lines',
                name='Günlük Saldırı',
                line=dict(color='lightblue', width=1),
                opacity=0.6
            ))
            
            fig.add_trace(go.Scatter(
                x=daily_stats['date'],
                y=daily_stats['attacks_ma7'],
                mode='lines',
                name='7 Günlük Hareketli Ortalama',
                line=dict(color='blue', width=3)
            ))
            
            fig.update_layout(
                title="Saldırı Sayısı - Hareketli Ortalama",
                xaxis_title="Tarih",
                yaxis_title="Saldırı Sayısı",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig = go.Figure()
            
            fig.add_trace(go.Scatter(
                x=daily_stats['date'],
                y=daily_stats['avg_risk'],
                mode='lines',
                name='Günlük Risk',
                line=dict(color='lightcoral', width=1),
                opacity=0.6
            ))
            
            fig.add_trace(go.Scatter(
                x=daily_stats['date'],
                y=daily_stats['risk_ma7'],
                mode='lines',
                name='7 Günlük Hareketli Ortalama',
                line=dict(color='red', width=3)
            ))
            
            fig.update_layout(
                title="Risk Skoru - Hareketli Ortalama",
                xaxis_title="Tarih",
                yaxis_title="Ortalama Risk",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)

def time_based_patterns(df):
    """Zaman bazlı desenler"""
    st.markdown("## 🔍 Zaman Bazlı Saldırı Desenleri")
    
    # Isı haritası - Gün vs Saat
    heatmap_data = df.groupby(['day_of_week', 'hour']).size().unstack(fill_value=0)
    day_names = ['Pazartesi', 'Salı', 'Çarşamba', 'Perşembe', 'Cuma', 'Cumartesi', 'Pazar']
    
    fig = px.imshow(
        heatmap_data.values,
        x=heatmap_data.columns,
        y=day_names,
        title="Gün-Saat Saldırı Yoğunluğu Isı Haritası",
        labels={'x': 'Saat', 'y': 'Gün', 'color': 'Saldırı Sayısı'},
        color_continuous_scale="Reds"
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)
    
    # En yoğun zaman dilimleri
    st.markdown("### ⏰ En Yoğun Zaman Dilimleri")
    
    # Saat dilimlerini grupla
    def categorize_time(hour):
        if 6 <= hour < 12:
            return 'Sabah (06:00-12:00)'
        elif 12 <= hour < 18:
            return 'Öğleden Sonra (12:00-18:00)'
        elif 18 <= hour < 24:
            return 'Akşam (18:00-24:00)'
        else:
            return 'Gece (00:00-06:00)'
    
    df['time_period'] = df['hour'].apply(categorize_time)
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Zaman dilimi dağılımı
        time_period_attacks = df['time_period'].value_counts()
        
        fig = px.pie(
            values=time_period_attacks.values,
            names=time_period_attacks.index,
            title="Zaman Dilimlerine Göre Saldırı Dağılımı"
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Zaman dilimine göre ortalama risk
        time_period_risk = df.groupby('time_period')['risk'].mean().sort_values(ascending=False)
        
        fig = px.bar(
            x=time_period_risk.index,
            y=time_period_risk.values,
            title="Zaman Dilimlerine Göre Ortalama Risk",
            labels={'x': 'Zaman Dilimi', 'y': 'Ortalama Risk'},
            color=time_period_risk.values,
            color_continuous_scale="Oranges"
        )
        fig.update_layout(height=400, showlegend=False, xaxis_tickangle=-45)
        st.plotly_chart(fig, use_container_width=True)

def temporal_correlations(df):
    """Zamansal korelasyonlar"""
    st.markdown("## 🔗 Zamansal Korelasyon Analizi")
    
    # Zaman bileşenleri ile risk arasındaki korelasyon
    time_features = ['hour', 'day_of_week', 'week']
    correlation_data = df[time_features + ['risk']].corr()['risk'].drop('risk')
    
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.bar(
            x=correlation_data.index,
            y=correlation_data.values,
            title="Zaman Bileşenleri ile Risk Korelasyonu",
            labels={'x': 'Zaman Bileşeni', 'y': 'Korelasyon'},
            color=correlation_data.values,
            color_continuous_scale="RdBu_r"
        )
        fig.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Saatlere göre ülke çeşitliliği
        hourly_diversity = df.groupby('hour')['country'].nunique()
        
        fig = px.line(
            x=hourly_diversity.index,
            y=hourly_diversity.values,
            title="Saatlere Göre Ülke Çeşitliliği",
            labels={'x': 'Saat', 'y': 'Benzersiz Ülke Sayısı'},
            markers=True
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    # Zamansal istatistikler tablosu
    st.markdown("### 📊 Zamansal İstatistikler Özeti")
    
    temporal_stats = df.groupby('hour').agg({
        'ip': 'count',
        'risk': ['mean', 'max'],
        'country': 'nunique',
        'isp': 'nunique'
    }).round(2)
    
    temporal_stats.columns = ['Saldırı Sayısı', 'Ortalama Risk', 'Max Risk', 'Ülke Sayısı', 'ISP Sayısı']
    
    # En yüksek değerleri vurgula
    styled_stats = temporal_stats.style.highlight_max(axis=0, color='lightgreen')
    st.dataframe(styled_stats, use_container_width=True)

# Ana fonksiyon
def main():
    df = load_data()
    
    # Genel zamansal istatistikler
    st.markdown("## 📊 Genel Zamansal İstatistikler")
    
    date_range = df['timestamp'].max() - df['timestamp'].min()
    peak_hour = df['hour'].value_counts().index[0]
    peak_day = df['day'].value_counts().index[0]
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Veri Aralığı", f"{date_range.days} gün")
    
    with col2:
        st.metric("En Yoğun Saat", f"{peak_hour}:00")
    
    with col3:
        st.metric("En Yoğun Gün", peak_day)
    
    with col4:
        avg_daily_attacks = len(df) / date_range.days if date_range.days > 0 else len(df)
        st.metric("Günlük Ortalama", f"{avg_daily_attacks:.1f}")
    
    # Analiz bölümleri
    hourly_analysis(df)
    daily_weekly_analysis(df)
    seasonal_analysis(df)
    time_series_trends(df)
    time_based_patterns(df)
    temporal_correlations(df)

if __name__ == "__main__":
    main()
