# SSH Honeypot SIEM Dashboard

Bu proje, SSH honeypot loglarını gerçek zamanlı olarak analiz eden ve güvenlik tehditlerini tespit eden kapsamlı bir SIEM (Security Information and Event Management) sistemidir.

## 🚀 Özellikler

### 🔍 Log Toplama ve Analiz
- **Gerçek Zamanlı İzleme**: SSH honeypot loglarını anlık olarak takip eder
- **Çoklu Format Desteği**: JSON ve metin formatındaki logları destekler
- **Otomatik Parsing**: Logları otomatik olarak ayrıştırır ve veritabanına kaydeder

### 🛡️ Kural Tabanlı Tespit
- **Özelleştirilebilir Kurallar**: Regex tabanlı kural sistemi
- **Tehlike Seviyeleri**: Critical, High, Medium, Low seviyelerinde sınıflandırma
- **Otomatik Etiketleme**: Kurallara uyan logları otomatik olarak etiketler
- **Varsayılan Kurallar**: Yaygın saldırı desenleri için hazır kurallar

### 📊 Görsel Dashboard
- **Modern Web Arayüzü**: Bootstrap 5 ile responsive tasarım
- **Gerçek Zamanlı İstatistikler**: Toplam log, alarm ve aktivite sayıları
- **Gelişmiş Filtreleme**: IP, tehlike seviyesi, olay tipi ve tarih aralığına göre filtreleme
- **Analitik Grafikler**: Severity dağılımı ve en aktif IP'ler için görselleştirme

### 🔧 Yönetim Özellikleri
- **Kural Yönetimi**: Web arayüzünden kural ekleme, düzenleme ve silme
- **Pagination**: Büyük log verilerini sayfalama ile görüntüleme
- **Otomatik Yenileme**: 30 saniyede bir otomatik veri yenileme

## 🏗️ Sistem Mimarisi

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SSH Honeypot  │───▶│  Log Files      │───▶│  SIEM Dashboard │
│   (Port 2222)   │    │  (JSON/Text)    │    │  (Port 5000)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  File Watcher   │    │  SQLite DB      │
                       │  (Real-time)    │    │  (Logs/Rules)   │
                       └─────────────────┘    └─────────────────┘
```

## 🐳 Docker Kurulumu

### Gereksinimler
- Docker
- Docker Compose

### Kurulum ve Çalıştırma

1. **Projeyi klonlayın:**
```bash
git clone <repository-url>
cd ssh-honeypot-siem
```

2. **Sistemleri başlatın:**
```bash
docker-compose up -d --build
```

3. **Servisleri kontrol edin:**
```bash
docker ps
```

### Erişim Adresleri
- **SSH Honeypot**: `localhost:2222`
- **SIEM Dashboard**: `http://localhost:5000`

## 📋 Varsayılan Kurallar

Sistem aşağıdaki hazır kurallarla gelir:

| Kural Adı | Desen | Tehlike | Açıklama |
|-----------|-------|---------|----------|
| Command Injection - whoami | `\bwhoami\b` | High | whoami komutu tespiti |
| Command Injection - cat passwd | `cat\s+/etc/passwd` | Critical | Şifre dosyası okuma girişimi |
| Command Injection - ls | `\bls\b` | Medium | Dizin listeleme komutu |
| Command Injection - pwd | `\bpwd\b` | Low | Mevcut dizin sorgulama |
| Suspicious Username | `(admin\|root\|administrator\|test\|guest)` | Medium | Şüpheli kullanıcı adları |
| Password File Access | `(passwd\|shadow\|group)` | Critical | Sistem dosyalarına erişim |
| Network Commands | `(netstat\|ss\|ifconfig\|ip\s+addr)` | High | Ağ keşif komutları |
| System Information | `(uname\|hostname\|id\|whoami)` | Medium | Sistem bilgisi toplama |

## 🔧 Kullanım

### 1. Dashboard Erişimi
Web tarayıcınızda `http://localhost:5000` adresine gidin.

### 2. Log Görüntüleme
- **Logs** sekmesinde tüm logları görüntüleyin
- Filtreleme seçeneklerini kullanarak arama yapın
- Alarm tetiklenen loglar kırmızı kenarlıkla vurgulanır

### 3. Kural Yönetimi
- **Rules** sekmesinde mevcut kuralları görüntüleyin
- **Add Rule** butonu ile yeni kural ekleyin
- Mevcut kuralları düzenleyin veya silin

### 4. Analitik
- **Analytics** sekmesinde görsel raporları inceleyin
- Severity dağılımını ve en aktif IP'leri görün

## 🧪 Test Etme

### SSH Honeypot Testi
```bash
ssh -p 2222 -o StrictHostKeyChecking=no test@localhost
```

### SIEM Dashboard Testi
```bash
# API testi
curl http://localhost:5000/api/stats

# Web arayüzü
# Tarayıcıda http://localhost:5000 adresine gidin
```

## 📁 Proje Yapısı

```
ssh-honeypot-siem/
├── siem/                          # SIEM Dashboard
│   ├── app.py                     # Flask uygulaması
│   ├── requirements.txt           # Python bağımlılıkları
│   ├── Dockerfile                 # SIEM container tanımı
│   └── templates/
│       └── index.html             # Web arayüzü
├── src/                           # SSH Honeypot kaynak kodu
├── logs/                          # Log dosyaları
│   ├── ssh_honeypot.log          # Metin formatı loglar
│   └── ssh_honeypot.jsonl        # JSON formatı loglar
├── docker-compose.yml             # Docker servisleri
└── Dockerfile                     # SSH Honeypot container
```

## 🔒 Güvenlik Özellikleri

- **Non-root Container**: Tüm servisler güvenli kullanıcı hesapları ile çalışır
- **Read-only Log Access**: SIEM dashboard log dosyalarını sadece okur
- **SQL Injection Koruması**: SQLAlchemy ORM kullanımı
- **Input Validation**: Tüm kullanıcı girdileri doğrulanır

## 📊 Performans

- **Gerçek Zamanlı İşleme**: Log dosyaları anlık olarak izlenir
- **Veritabanı Optimizasyonu**: SQLite ile hızlı sorgular
- **Pagination**: Büyük veri setleri için sayfalama
- **Background Processing**: Log işleme arka planda çalışır

## 🛠️ Geliştirme

### Yeni Kural Ekleme
1. Dashboard'da **Rules** sekmesine gidin
2. **Add Rule** butonuna tıklayın
3. Kural bilgilerini doldurun:
   - **Name**: Kural adı
   - **Pattern**: Regex deseni
   - **Severity**: Tehlike seviyesi
   - **Description**: Açıklama

### API Endpoints
- `GET /api/logs` - Log listesi
- `GET /api/rules` - Kural listesi
- `POST /api/rules` - Yeni kural oluşturma
- `PUT /api/rules/<id>` - Kural güncelleme
- `DELETE /api/rules/<id>` - Kural silme
- `GET /api/stats` - İstatistikler

## 🐛 Sorun Giderme

### Container Çalışmıyor
```bash
docker-compose logs siem-dashboard
docker-compose logs ssh-honeypot
```

### Veritabanı Sorunları
```bash
docker exec -it siem-dashboard ls -la /app/data/
```

### Log Dosyası Bulunamıyor
```bash
docker exec -it siem-dashboard ls -la /var/log/ssh-honeypot/
```

## 📈 Gelecek Geliştirmeler

- [ ] Email/SMS alarm bildirimleri
- [ ] Machine Learning tabanlı anomali tespiti
- [ ] Grafana entegrasyonu
- [ ] Elasticsearch desteği
- [ ] Multi-honeypot desteği
- [ ] REST API genişletme
- [ ] Webhook entegrasyonu

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push yapın (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📞 Destek

Sorularınız için issue açabilir veya iletişime geçebilirsiniz.

