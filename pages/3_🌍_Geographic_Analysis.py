import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import folium
from streamlit_folium import st_folium
import numpy as np
from collections import Counter

st.set_page_config(
    page_title="🌍 Coğrafi Analiz",
    page_icon="🌍",
    layout="wide"
)

st.markdown("# 🌍 Coğrafi Tehdit Analizi")

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

def world_threat_map(df):
    """Dünya tehdit haritası"""
    st.markdown("## 🗺️ İnteraktif Dünya Tehdit Haritası")
    
    # Filtreleme seçenekleri
    col1, col2, col3 = st.columns(3)
    
    with col1:
        risk_filter = st.selectbox(
            "Risk Seviyesi Filtresi",
            options=['Tümü'] + list(df['risk_category_en'].unique()),
            index=0
        )
    
    with col2:
        top_n = st.slider("En Çok Saldırı Alan Ülke Sayısı", 5, 50, 20)
    
    with col3:
        map_style = st.selectbox(
            "Harita Stili",
            options=['OpenStreetMap', 'CartoDB positron', 'CartoDB dark_matter'],
            index=0
        )
    
    # Veriyi filtrele
    if risk_filter != 'Tümü':
        filtered_df = df[df['risk_category_en'] == risk_filter]
    else:
        filtered_df = df
    
    # Ülke bazında toplam saldırı ve ortalama risk
    country_stats = filtered_df.groupby(['country', 'latitude', 'longitude']).agg({
        'ip': 'count',
        'risk': 'mean'
    }).reset_index()
    country_stats.columns = ['country', 'latitude', 'longitude', 'attack_count', 'avg_risk']
    country_stats = country_stats.nlargest(top_n, 'attack_count')
    
    # Folium haritası oluştur
    m = folium.Map(
        location=[20, 0], 
        zoom_start=2,
        tiles=None
    )
    
    # Harita stilini ekle
    if map_style == 'OpenStreetMap':
        folium.TileLayer('OpenStreetMap').add_to(m)
    elif map_style == 'CartoDB positron':
        folium.TileLayer('CartoDB positron').add_to(m)
    else:
        folium.TileLayer('CartoDB dark_matter').add_to(m)
    
    # Risk seviyesine göre renk ve boyut
    def get_color_and_size(risk, count):
        if risk >= 70:
            return 'red', min(30, max(10, count / 2))
        elif risk >= 40:
            return 'orange', min(25, max(8, count / 3))
        else:
            return 'green', min(20, max(6, count / 4))
    
    # Ülkeler için marker'lar ekle
    for _, row in country_stats.iterrows():
        color, size = get_color_and_size(row['avg_risk'], row['attack_count'])
        
        # Popup içeriği
        popup_content = f"""
        <div style="width: 200px;">
            <h4>{row['country']}</h4>
            <hr>
            <b>Toplam Saldırı:</b> {row['attack_count']}<br>
            <b>Ortalama Risk:</b> {row['avg_risk']:.1f}<br>
            <b>Konum:</b> {row['latitude']:.2f}, {row['longitude']:.2f}
        </div>
        """
        
        folium.CircleMarker(
            location=[row['latitude'], row['longitude']],
            radius=size,
            popup=folium.Popup(popup_content, max_width=300),
            color='black',
            weight=2,
            fillColor=color,
            fillOpacity=0.7,
            tooltip=f"{row['country']}: {row['attack_count']} saldırı"
        ).add_to(m)
    
    # Harita legend'ını ekle
    legend_html = '''
    <div style="position: fixed; 
                bottom: 50px; left: 50px; width: 150px; height: 90px; 
                background-color: white; border:2px solid grey; z-index:9999; 
                font-size:14px; padding: 10px">
    <p><strong>Risk Seviyeleri</strong></p>
    <p><i class="fa fa-circle" style="color:red"></i> Yüksek (70+)</p>
    <p><i class="fa fa-circle" style="color:orange"></i> Orta (40-69)</p>
    <p><i class="fa fa-circle" style="color:green"></i> Düşük (<40)</p>
    </div>
    '''
    m.get_root().html.add_child(folium.Element(legend_html))
    
    # Haritayı göster
    st_folium(m, width=None, height=600)

def geographic_statistics(df):
    """Coğrafi istatistikler"""
    st.markdown("## 📊 Coğrafi İstatistikler")
    
    tab1, tab2, tab3 = st.tabs(["🏆 Ülke Sıralaması", "🌐 Kıtasal Analiz", "🏙️ Şehir Analizi"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # En çok saldırı alan ülkeler
            country_attacks = df['country'].value_counts().head(15)
            
            fig = px.bar(
                x=country_attacks.values,
                y=country_attacks.index,
                orientation='h',
                title="En Çok Saldırı Alan Ülkeler",
                labels={'x': 'Saldırı Sayısı', 'y': 'Ülke'},
                color=country_attacks.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # En yüksek ortalama risk
            country_risk = df.groupby('country')['risk'].mean().sort_values(ascending=False).head(15)
            
            fig = px.bar(
                x=country_risk.values,
                y=country_risk.index,
                orientation='h',
                title="En Yüksek Ortalama Risk Skoruna Sahip Ülkeler",
                labels={'x': 'Ortalama Risk Skoru', 'y': 'Ülke'},
                color=country_risk.values,
                color_continuous_scale="Oranges"
            )
            fig.update_layout(height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        # Kıtasal analiz için ülkeleri kıtalara göre grupla
        continent_mapping = {
            'United States': 'Kuzey Amerika',
            'Brazil': 'Güney Amerika',
            'United Kingdom': 'Avrupa',
            'Germany': 'Avrupa',
            'France': 'Avrupa',
            'Turkey': 'Avrupa/Asya',
            'Russia': 'Avrupa/Asya',
            'China': 'Asya',
            'Japan': 'Asya',
            'India': 'Asya'
        }
        
        df['continent'] = df['country'].map(continent_mapping).fillna('Diğer')
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Kıtaya göre saldırı dağılımı
            continent_attacks = df['continent'].value_counts()
            
            fig = px.pie(
                values=continent_attacks.values,
                names=continent_attacks.index,
                title="Kıtalara Göre Saldırı Dağılımı"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Kıtaya göre ortalama risk
            continent_risk = df.groupby('continent')['risk'].mean().sort_values(ascending=False)
            
            fig = px.bar(
                x=continent_risk.index,
                y=continent_risk.values,
                title="Kıtalara Göre Ortalama Risk Skoru",
                labels={'x': 'Kıta', 'y': 'Ortalama Risk'},
                color=continent_risk.values,
                color_continuous_scale="Viridis"
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        col1, col2 = st.columns(2)
        
        with col1:
            # En çok saldırı alan şehirler
            city_attacks = df['city'].value_counts().head(10)
            
            fig = px.bar(
                x=city_attacks.index,
                y=city_attacks.values,
                title="En Çok Saldırı Alan Şehirler",
                labels={'x': 'Şehir', 'y': 'Saldırı Sayısı'},
                color=city_attacks.values,
                color_continuous_scale="Blues"
            )
            fig.update_layout(height=400, xaxis_tickangle=-45, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Şehirlere göre risk dağılımı
            city_risk = df.groupby('city')['risk'].mean().sort_values(ascending=False).head(10)
            
            fig = px.bar(
                x=city_risk.index,
                y=city_risk.values,
                title="En Yüksek Risk Skoruna Sahip Şehirler",
                labels={'x': 'Şehir', 'y': 'Ortalama Risk'},
                color=city_risk.values,
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=400, xaxis_tickangle=-45, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

def heatmap_analysis(df):
    """Isı haritası analizi"""
    st.markdown("## 🔥 Coğrafi Isı Haritası Analizi")
    
    # Analiz türü seçimi
    analysis_type = st.selectbox(
        "Analiz Türü",
        options=['Saldırı Yoğunluğu', 'Risk Yoğunluğu', 'Kombinasyon']
    )
    
    if analysis_type == 'Saldırı Yoğunluğu':
        # Ülkeye göre saldırı sayısı haritası
        country_data = df['country'].value_counts().reset_index()
        country_data.columns = ['country', 'attacks']
        
        fig = px.choropleth(
            country_data,
            locations='country',
            color='attacks',
            hover_name='country',
            locationmode='country names',
            title="Dünya Saldırı Yoğunluğu Haritası",
            color_continuous_scale="Reds",
            labels={'attacks': 'Saldırı Sayısı'}
        )
        
    elif analysis_type == 'Risk Yoğunluğu':
        # Ülkeye göre ortalama risk haritası
        country_risk = df.groupby('country')['risk'].mean().reset_index()
        country_risk.columns = ['country', 'avg_risk']
        
        fig = px.choropleth(
            country_risk,
            locations='country',
            color='avg_risk',
            hover_name='country',
            locationmode='country names',
            title="Dünya Risk Yoğunluğu Haritası",
            color_continuous_scale="Oranges",
            labels={'avg_risk': 'Ortalama Risk'}
        )
        
    else:  # Kombinasyon
        # Saldırı sayısı * ortalama risk
        country_combined = df.groupby('country').agg({
            'ip': 'count',
            'risk': 'mean'
        }).reset_index()
        country_combined.columns = ['country', 'attacks', 'avg_risk']
        country_combined['threat_score'] = country_combined['attacks'] * country_combined['avg_risk'] / 100
        
        fig = px.choropleth(
            country_combined,
            locations='country',
            color='threat_score',
            hover_name='country',
            locationmode='country names',
            title="Dünya Kombinasyon Tehdit Skoru Haritası",
            color_continuous_scale="Plasma",
            labels={'threat_score': 'Tehdit Skoru'}
        )
    
    fig.update_layout(height=600)
    st.plotly_chart(fig, use_container_width=True)

def regional_comparison(df):
    """Bölgesel karşılaştırma"""
    st.markdown("## 🔄 Bölgesel Karşılaştırma")
    
    # Karşılaştırılacak ülkeleri seç
    selected_countries = st.multiselect(
        "Karşılaştırmak için ülkeleri seçin:",
        options=sorted(df['country'].unique()),
        default=['United States', 'Brazil', 'United Kingdom', 'Germany', 'Russia']
    )
    
    if len(selected_countries) >= 2:
        # Seçilen ülkelerin verilerini filtrele
        comparison_data = df[df['country'].isin(selected_countries)]
        
        # Çoklu analiz
        col1, col2 = st.columns(2)
        
        with col1:
            # Ülkeye göre saldırı sayısı ve risk karşılaştırması
            country_comparison = comparison_data.groupby('country').agg({
                'ip': 'count',
                'risk': 'mean'
            }).reset_index()
            country_comparison.columns = ['country', 'attacks', 'avg_risk']
            
            # İkili eksen grafiği
            fig = make_subplots(specs=[[{"secondary_y": True}]])
            
            fig.add_trace(
                go.Bar(
                    x=country_comparison['country'],
                    y=country_comparison['attacks'],
                    name="Saldırı Sayısı",
                    marker_color='lightblue'
                ),
                secondary_y=False
            )
            
            fig.add_trace(
                go.Scatter(
                    x=country_comparison['country'],
                    y=country_comparison['avg_risk'],
                    mode='lines+markers',
                    name="Ortalama Risk",
                    marker_color='red',
                    line=dict(width=3)
                ),
                secondary_y=True
            )
            
            fig.update_xaxes(title_text="Ülke")
            fig.update_yaxes(title_text="Saldırı Sayısı", secondary_y=False)
            fig.update_yaxes(title_text="Ortalama Risk Skoru", secondary_y=True)
            fig.update_layout(title="Ülke Karşılaştırması: Saldırı ve Risk")
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Risk kategorisi dağılımı karşılaştırması
            risk_comparison = comparison_data.groupby(['country', 'risk_category_en']).size().unstack(fill_value=0)
            
            fig = px.bar(
                risk_comparison.reset_index(),
                x='country',
                y=['Low', 'Medium', 'High'],
                title="Risk Kategorisi Dağılımı Karşılaştırması",
                labels={'value': 'Saldırı Sayısı', 'variable': 'Risk Kategorisi'},
                color_discrete_map={'Low': '#48dbfb', 'Medium': '#feca57', 'High': '#ff6b6b'}
            )
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
        
        # Detaylı karşılaştırma tablosu
        st.markdown("### 📋 Detaylı Karşılaştırma")
        
        detailed_comparison = comparison_data.groupby('country').agg({
            'ip': ['count', 'nunique'],
            'risk': ['mean', 'min', 'max', 'std'],
            'isp': 'nunique'
        }).round(2)
        
        # Sütun isimlerini düzenle
        detailed_comparison.columns = [
            'Toplam Saldırı', 'Benzersiz IP', 'Ortalama Risk', 'Min Risk', 
            'Max Risk', 'Risk Std Sapma', 'Benzersiz ISP'
        ]
        
        # En yüksek değerleri vurgula
        styled_df = detailed_comparison.style.highlight_max(axis=0, color='lightgreen')
        st.dataframe(styled_df, use_container_width=True)
        
    else:
        st.warning("Karşılaştırma için en az 2 ülke seçin.")

def time_geographic_analysis(df):
    """Zamansal-coğrafi analiz"""
    st.markdown("## ⏰ Zamansal-Coğrafi Analiz")
    
    # Saat dilimlerine göre analiz
    st.markdown("### 🕐 Saat Dilimlerine Göre Saldırı Analizi")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Saat dilimine göre saldırı dağılımı
        timezone_attacks = df['timezone'].value_counts().head(10)
        
        fig = px.bar(
            x=timezone_attacks.values,
            y=timezone_attacks.index,
            orientation='h',
            title="Saat Dilimlerine Göre Saldırı Dağılımı",
            labels={'x': 'Saldırı Sayısı', 'y': 'Saat Dilimi'},
            color=timezone_attacks.values,
            color_continuous_scale="Purples"
        )
        fig.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Zamana göre coğrafi dağılım
        df['hour'] = df['timestamp'].dt.hour
        hourly_country = df.groupby(['hour', 'country']).size().reset_index(name='attacks')
        
        # En aktif ülkeleri al
        top_countries = df['country'].value_counts().head(5).index
        hourly_top = hourly_country[hourly_country['country'].isin(top_countries)]
        
        fig = px.line(
            hourly_top,
            x='hour',
            y='attacks',
            color='country',
            title="Saatlik Saldırı Trendi (Top 5 Ülke)",
            labels={'hour': 'Saat', 'attacks': 'Saldırı Sayısı'}
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

# Ana fonksiyon
def main():
    df = load_data()
    
    # Dünya tehdit haritası
    world_threat_map(df)
    
    # Coğrafi istatistikler
    geographic_statistics(df)
    
    # Isı haritası analizi
    heatmap_analysis(df)
    
    # Bölgesel karşılaştırma
    regional_comparison(df)
    
    # Zamansal-coğrafi analiz
    time_geographic_analysis(df)

if __name__ == "__main__":
    main()
