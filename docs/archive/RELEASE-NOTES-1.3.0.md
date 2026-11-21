# AKVORIA ASE Local 1.3.0

## Düzeltmeler ve iyileştirmeler

- Loopback dışı API yapılandırması reddedilir; API anahtarı dosyası sembolik bağlantı olamaz ve izinleri sınırlandırılır.
- API eşzamanlı istekleri destekler; kimlik doğrulamalı POST dosya taraması ve yerel tehdit göstergesi kaydı eklendi.
- API süreç ve ağ bağlantısı envanteri uç noktaları eklendi.
- İstek gövdesi boyutu sınırlandırıldı; JSON doğrulaması ve güvenlik yanıt başlıkları eklendi.
- SQLite dosya yolu sembolik bağlantı kontrolü, baseline tablo geçişi ve tehdit göstergesi deposu eklendi.
- Dosya tarama/baseline işlemlerinde sembolik bağlantı reddi ve dosya/adet sınırları uygulandı.
- Olay dinleyicilerinden birinin hatası diğer dinleyicilerin çalışmasını durdurmaz.
- Dosya değişikliği korelasyonu ve yerel tehdit göstergesi eşleşmesi açıklanabilir uyarı üretir.
- Gerçek zamanlı izleme hataları artık durum bilgisinde raporlanır.
- Antivirüs tarayıcısında 64 MiB etkin dosya boyutu üst sınırı korunur; daha yüksek eski yapılandırma değerleri bu sınırı yükseltmez.

## Doğrulama

- 44 otomatik test geçti.
- Python bytecode derleme kontrolü başarılı.
- API tarama, kimlik doğrulama, gösterge ekleme, süreç ve ağ envanteri entegrasyon testleri başarılı.
- Test ortamı: Linux; Android/Termux ve Windows gerçek cihaz doğrulaması yapılmadı.

## Bilinen sınırlar

Bu sürüm kernel koruması, OS-geneli anlık dosya izleme, davranışsal sandbox, otomatik ağ engelleme veya bulut tehdit servisi sunmaz. Tespitler etkin imza ve sezgisel kurallarla sınırlıdır; temiz sonuç zararsızlık garantisi değildir.
