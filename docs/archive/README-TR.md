# AKVORIA Security Engine — Local 1.3.0

AKVORIA ASE Local, yerel ortamda çalışan savunma amaçlı bir güvenlik motorudur. Arayüz içermez; uygulama entegrasyonu için loopback API sağlar.

## İçerik

- Dosya SHA-256 taraması, yerel imza eşleştirmesi ve sınırlı statik/heuristik göstergeler
- ZIP arşivleri için boyut ve üye sayısı sınırlarıyla güvenli içerik incelemesi
- Kullanıcı onayıyla karantina ve bütünlük kontrolü sonrası geri yükleme
- Dosya bütünlük tabanı ve sınırlı aralıklı klasör izleme
- Salt-okunur süreç ve Linux procfs ağ bağlantısı envanteri
- Yerel tehdit göstergesi kaydı ve eşleştirme
- Kimlik doğrulama, loopback erişim kısıtlaması, hız sınırı ve istek kaydı olan API
- SQLite veritabanı şema geçişleri ve sembolik bağlantı kontrolleri

## Kurulum (Termux / Linux)

Proje klasörüne girip: 

```bash
python -m compileall -q .
python -m unittest discover -s tests -v
python main.py --version
python main.py --self-test
python main.py --status
```

Termux'ta yalnızca Termux'un erişim izni olan klasörleri izleyin. Android depolama izni gerekiyorsa Termux'un resmi depolama kurulum adımlarını ayrıca uygulayın. Mevcut `~/storage` yapınızı yeniden oluşturmanız istenirse, ne yaptığını anlamadan onaylamayın.

## API

Varsayılan adres `127.0.0.1:8765`'tir. API anahtarı ilk başlatmada `storage/ase_api.key` içine oluşturulur; paylaşmayın ve kaynak ZIP'ine eklemeyin. `/health` dışında uç noktalar `Authorization: Bearer <API_KEY>` ister. API dış ağ arayüzüne bağlanmayı reddeder.

- `GET /status` — motor durumu
- `GET /api/processes` — salt-okunur süreç envanteri
- `GET /api/network/connections` — desteklenen platformlarda salt-okunur bağlantı envanteri
- `POST /api/scan` — JSON gövdesi: `{"path":"/izinli/dosya-veya-klasor"}`
- `POST /api/indicators` — JSON gövdesi: `{"indicator":"198.51.100.7","type":"ip","source":"local"}`

## Güvenlik ve sınırlar

- `no_known_indicators` sonucu dosyanın zararsız olduğunu kanıtlamaz; yalnızca etkin kurallarda eşleşme bulunmadığını belirtir.
- Tarama dosyaları otomatik silmez. Karantina yalnızca açık kullanıcı talebiyle çalışır.
- Gerçek zamanlı izleme sınırlı aralıklı klasör taramasıdır; kernel seviyesinde veya OS-geneli anlık koruma değildir. İzleme listesi varsayılan olarak boştur.
- Süreç ve ağ envanteri salt-okunurdur; süreç sonlandırma veya ağ bağlantısı engelleme yapmaz.
- Tehdit göstergesi deposu başlangıçta boştur. İmzalı feed içe aktarma opsiyoneldir; otomatik feed dağıtım servisi yoktur.
- Davranışsal sandbox, kernel sürücüsü, OS firewall entegrasyonu ve bulut motoru bu sürümün kapsamında değildir.
- Android/Termux uygulama sandbox'larını aşamaz; arka plan çalışması Android pil ve süreç kısıtlamalarına tabidir. Windows ve Android gerçek cihaz testleri yapılmamıştır.

## Gizli ve çalışma verileri

`storage/` altındaki API anahtarı, SQLite veritabanı, günlükler, imzalar ve karantina verileri kullanıcıya dağıtılan kaynak ZIP'ine dahil edilmemelidir.
