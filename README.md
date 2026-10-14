# Yasaklama — Merkezi DNS Filtreleme

Okulun **yetkili ağ yöneticilerinin** kendi yönettikleri LAN üzerinde alan adı engelleme kuralları yayımlaması için hazırlanmış Python projesi. Yönetim panelinden eklenen kurallar merkezi DNS sunucusuna anında yakın sürede yansır; kural alan adının kendisini ve alt alan adlarını kapsar.

## Neler var?

- Türkçe, telefon ve masaüstü uyumlu yönetim paneli.
- Yönetici parolası PBKDF2-HMAC-SHA256 ile 600.000 tur kullanılarak saklanır; varsayılan parola yoktur.
- Kısa ömürlü, imzalı, HttpOnly ve SameSite Strict oturum çerezi.
- Alan adı doğrulama, IDNA alan adları ve alt alan adı eşleştirmesi.
- UDP ve TCP DNS dinleyicisi; engellenmeyen sorguları seçilen üst DNS sunucusuna iletir.
- SQLite üzerinde kalıcı engel listesi. Gizlilik için yalnızca engellenen sorgular kaydedilir ve en son 1.000 olay tutulur.
- GitHub Actions üzerinde otomatik Python derleme ve test iş akışı.

## Mimari

    Yönetici tarayıcısı
          |
       HTTPS önerilir
          |
    Yasaklama web paneli ---- SQLite politika/veri tabanı
          |
    Merkezi DNS hizmeti
          |
    Engelli alan adı? ---- evet ---> NXDOMAIN / site açılamıyor
          |
          hayır
          v
    Üst DNS sunucusu

Bu proje, istemci bilgisayarlara gizli ajan kurmaz ve kullanıcı yetkilerini yükseltmeye çalışmaz. Merkezi DNS yaklaşımında istemcilerin okulun yönettiği DNS sunucusunu kullanması gerekir.

## Kurulum

Python 3.11 veya üzeri gerekir. Projeyi klonladıktan sonra depo klasöründe:

Windows PowerShell:

    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt
    python controller.py --init-admin

Linux:

    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install -r requirements.txt
    python controller.py --init-admin

İlk kurulum komutu parola oluşturur. Parola en az 14 karakter olmalıdır. Varsayılan yönetici hesabı veya sabit parola yoktur. Yapılandırma dosyası data/config.json içinde, politikalar data/policy.sqlite3 içinde tutulur. Bu dosyaları yedekleyin ve işletim sisteminin dosya izinleriyle koruyun.

### Yerel deneme

DNS hizmetini 5353 portunda başlatmak, gerçek okul ağına dokunmadan sorgu testi yapmak için uygundur:

    python controller.py --web-host 127.0.0.1 --web-port 8765 --dns-host 127.0.0.1 --dns-port 5353

Paneli http://127.0.0.1:8765 adresinde açın. DNS sorgusunu test etmek için bilgisayarınızda dig varsa:

    dig @127.0.0.1 -p 5353 example.com

### Okul ağına dağıtım

Bu aşama sadece ağın yetkili yöneticisi tarafından yapılmalıdır:

1. Yasaklama sunucusuna sabit bir LAN IP adresi verin.
2. Gerçek kullanımdan önce yönetim panelini geçerli TLS sertifikası olan HTTPS üzerinden sunun. Örneğin, sertifika dosyalarınız hazırsa --ssl-certfile ve --ssl-keyfile seçeneklerini kullanın. TLS olmadan yönetim panelini LAN'a açmak yönetici parolasını ağda açık metin halinde bırakabilir.
3. DNS hizmetini standart DNS portu olan 53'te çalıştırın. Bu port işletim sistemine göre yükseltilmiş yetki gerektirebilir. Örnek komut (sertifika dosyalarının yollarını kendinize göre değiştirin):

       python controller.py --web-host 0.0.0.0 --web-port 8765 --ssl-certfile /path/to/fullchain.pem --ssl-keyfile /path/to/privkey.pem --dns-host 0.0.0.0 --dns-port 53 --upstream 1.1.1.1

4. Ağ güvenlik duvarında yalnızca gereken istemci ağlarından UDP/TCP 53 erişimine izin verin. DHCP/router ayarlarında istemcilere bu DNS sunucusunu dağıtın. DNS trafiğinin doğrudan harici sunuculara çıkmasını kısıtlamak gibi ağ geçidi değişiklikleri yalnızca yetkili ağ yöneticisince yapılmalıdır.
5. Kuralları panelden ekleyin. Örneğin example.com kuralı example.com ve news.example.com gibi bütün alt alan adlarını eşleştirir.

Sunucunun işletim sistemi güvenlik duvarı, ağ geçidi/DHCP ve TLS ayarları bu uygulama tarafından kendiliğinden değiştirilmez.

## Bilinen sınırlar

- DNS filtresi yalnızca istemci sorguları bu DNS sunucusundan geçtiğinde uygulanır. VPN, farklı DNS sunucusu veya DNS-over-HTTPS (DoH) gibi yöntemler, ağ yöneticisi tarafından ayrıca yönetilmedikçe filtreyi atlayabilir. Mutlak engelleme iddiası yoktur.
- DNS üzerinden HTTPS içeriğine özel HTML sayfası enjekte edilemez. Bu proje TLS trafiğini çözmez, sahte sertifika kurmaz; engellenen alan adı için DNS NXDOMAIN yanıtı verir ve tarayıcı genellikle siteye ulaşılamadığını gösterir.
- Alan adı kuralları IP adresini, o IP üzerindeki diğer siteleri veya farklı alan adlarını engellemez.
- Paneli internete doğrudan açmayın. LAN yönetiminde HTTPS, güçlü parola, güvenlik duvarı sınırlandırması ve kontrollü yedekleme kullanın.
- Uygulama Windows UAC'yi atlatmaz, standart kullanıcıya yönetici yetkisi vermez ve kendini kaldırılamaz biçimde gizlemez. DNS portu ve ağ geçidi değişiklikleri için yetkili yönetici gerekir.

## Testler

    python -m compileall -q controller.py tests
    pytest -q

GitHub Actions bu kontrolleri her push ve pull request için otomatik çalıştırır. Otomatik testler gerçek okul router'ı veya her Windows ağ sürücüsünün davranışını garanti etmez; dağıtımdan önce kontrollü bir test ağında doğrulayın.

## Güvenli kullanım

Bu yazılımı yalnızca sahip olduğunuz veya yönetmeye yetkili olduğunuz ağlarda, kurumun onayladığı politika ve gizlilik kurallarıyla kullanın. Engelleme kayıtlarında istemci IP adresi ve engellenen alan adı bulunabilir; bu kayıtları okulun saklama politikasına göre yönetin.
