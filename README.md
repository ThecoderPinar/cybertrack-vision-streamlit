# CyberTrack Vision - Siber Güvenlik Analiz Platformu

## 🛡️ Proje Açıklaması

CyberTrack Vision, kapsamlı bir siber güvenlik analiz ve izleme platformudur. Bu Streamlit uygulaması, siber saldırı verilerini analiz ederek gerçek zamanlı tehdit istihbaratı sağlar.

## ✨ Özellikler

### 📊 Ana Dashboard
- Gerçek zamanlı saldırı metriklerı
- Risk dağılım analizi
- Coğrafi tehdit haritası
- Zamansal trend analizi
- İnteraktif filtreleme

### 📈 Gerçek Zamanlı İzleme
- Canlı saldırı takibi
- Tehdit uyarıları
- Otomatik yenileme
- Kritik IP izleme

### 🔍 Gelişmiş Analitik
- İstatistiksel analiz
- Korelasyon analizi
- Anomali tespiti
- Tahminsel modelleme

### 🌍 Coğrafi Analiz
- İnteraktif dünya haritası
- Ülke bazlı istatistikler
- Isı haritası görünümü
- Bölgesel karşılaştırma

### 🌐 Ağ ve ISP Analizi
- ISP güvenlik analizi
- ASN tracking
- Port analizi
- Ağ topolojisi

### ⏰ Zamansal Analiz
- Saatlik/günlük trendler
- Mevsimsel analiz
- Zaman serisi tahminleri
- Saldırı desenleri

### 🤖 Makine Öğrenmesi
- Risk tahmin modelleri
- Anomali tespiti
- Kümeleme analizi
- Sınıflandırma modelleri

### 📊 Raporlama
- Yönetici özetleri
- Detaylı analiz raporları
- Tehdit istihbaratı
- Otomatik rapor oluşturma

## 🚀 Kurulum

### Gereksinimler
Python 3.8+ gereklidir.

### Bağımlılıkları Yükleme
```bash
pip install -r requirements.txt
```

### Uygulamayı Başlatma
```bash
streamlit run app.py
```

## 📁 Proje Yapısı

```
cybertrack-vision-streamlit/
├── app.py                           # Ana dashboard
├── requirements.txt                 # Python bağımlılıkları
├── data/                           # Veri dosyaları
│   ├── cybertrack_mock_dataset.csv # Ana veri seti
│   └── exports/                    # Dışa aktarılan dosyalar
└── pages/                          # Streamlit sayfaları
    ├── 1_📈_Real_Time_Monitoring.py
    ├── 2_🔍_Advanced_Analytics.py
    ├── 3_🌍_Geographic_Analysis.py
    ├── 4_🌐_Network_ISP_Analysis.py
    ├── 5_⏰_Temporal_Analysis.py
    ├── 6_🤖_Machine_Learning.py
    └── 7_📊_Reports.py
```

## 📊 Veri Seti

Veri seti aşağıdaki alanları içerir:
- **timestamp**: Saldırı zamanı
- **ip**: Kaynak IP adresi
- **risk**: Risk skoru (0-100)
- **country**: Ülke
- **city**: Şehir
- **latitude/longitude**: Coğrafi koordinatlar
- **isp**: İnternet servis sağlayıcısı
- **asn**: Otonom sistem numarası
- **attack_ports**: Hedeflenen portlar
- **attack_hours**: Saldırı saatleri
- **risk_category**: Risk kategorisi

## 🎯 Kullanım Alanları

### 🏢 Kurumsal Güvenlik
- SOC (Security Operations Center) izleme
- Incident response
- Threat hunting
- Risk değerlendirmesi

### 🔒 Güvenlik Analisti
- Saldırı pattern analizi
- Coğrafi tehdit haritalaması
- Anomali tespiti
- Tahmin modelleme

### 👔 Yönetim
- Güvenlik durumu raporları
- Risk değerlendirmesi
- Strateji planlaması
- ROI analizi

## 🛠️ Teknik Detaylar

### Kullanılan Teknolojiler
- **Streamlit**: Web framework
- **Plotly**: İnteraktif grafikler
- **Pandas**: Veri analizi
- **Scikit-learn**: Makine öğrenmesi
- **Folium**: Harita görselleştirme
- **NumPy**: Sayısal hesaplamalar

### Performans Optimizasyonları
- `@st.cache_data` decorator kullanımı
- Efficient data filtering
- Lazy loading
- Memory management

## 📈 Metrikler ve KPI'lar

### Güvenlik Metrikleri
- Toplam saldırı sayısı
- Benzersiz IP sayısı
- Ortalama risk skoru
- Yüksek riskli saldırı yüzdesi
- Etkilenen ülke sayısı

### Operasyonel Metrikler
- Anomali tespit oranı
- Response time
- False positive rate
- Coverage metrics

## 🔧 Özelleştirme

### Yeni Analiz Ekleme
1. `pages/` klasörüne yeni Python dosyası ekleyin
2. Streamlit page format'ını takip edin
3. Veri yükleme fonksiyonunu kullanın
4. İnteraktif bileşenler ekleyin

### Veri Kaynağı Değiştirme
`load_data()` fonksiyonunu düzenleyerek farklı veri kaynaklarını kullanabilirsiniz.

## 🚨 Güvenlik Notları

- Gerçek production ortamında hassas verileri korumak için:
  - HTTPS kullanın
  - Authentication ekleyin
  - Data encryption uygulayın
  - Access control implementasyonu yapın

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push yapın (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

## 📞 İletişim

Sorularınız ve önerileriniz için:
- GitHub Issues
- Email: piinartp@gmail.com

## 🔄 Versiyon Geçmişi

### v1.0.0 (2025-08-05)
- İlk sürüm
- Temel dashboard özellikleri
- 7 ana analiz modülü
- Makine öğrenmesi entegrasyonu
- Kapsamlı raporlama sistemi

---

**CyberTrack Vision** - Siber güvenlikte görünürlük ve kontrol için geliştirilmiştir. 🛡️
