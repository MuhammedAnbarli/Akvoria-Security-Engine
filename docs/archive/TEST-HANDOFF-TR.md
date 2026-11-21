# Kullanıcı test paketi - 1.2.0

## Temel kontroller

```bash
python --version
python -m compileall -q core modules main.py
python -m unittest discover -v
python main.py --version
python main.py --self-test
```

## Dosya tarama

```bash
python main.py --scan /izinli/test/klasoru
```

## Klasör izleme

```bash
python main.py --watch /izinli/test/klasoru
```

İzleme, seçilen klasörü varsayılan olarak 3 saniyede bir kontrol eder. Bu kernel seviyesinde anlık koruma değildir. Durdurmak için CTRL+C kullanın.

## EICAR test dosyası

EICAR yalnızca antivirüs test imzasıdır; gerçek zararlı yazılım değildir. Test dosyasını güvenilir EICAR test kaynağından edinip izole test klasöründe tarayın. Bulduğunda karantina davranışını ayrıca deneyin.

## Raporlanacaklar

- Android/Termux ve Python sürümü
- Test komutlarının çıktısı
- Tarama/izleme sonuçları
- API başlatma ve durdurma davranışı
- Hata mesajları (API anahtarını ve kişisel dosya yollarını paylaşmadan)
