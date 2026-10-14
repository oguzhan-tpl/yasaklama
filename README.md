# Yasaklama — Merkezi DNS Filtreleme ve HTTP Engel Portalı

Yetkili okul ağı yöneticileri için merkezi alan adı filtreleme servisi ve Türkçe yönetim paneli. Yönetici paneline başka bir bilgisayardan bağlanıp URL yapıştırabilir, alan adını engelleyebilir veya kuralı kaldırabilirsiniz. DNS politikası sunucuda tutulur; istemci başına gizli ajan kurulmaz.

## Özellikler

- Türkçe, masaüstü ve mobil uyumlu yönetim paneli.
- Yapıştırılan https://example.com/sayfa bağlantısından alan adını çıkarır ve alan adının alt alan adlarını da eşleştirir.
- Parola varsayılan olarak gelmez. Kurulumda en az 14 karakterlik parola alınır; PBKDF2-HMAC-SHA256 (600.000 tur) ile doğrulama özeti saklanır.
- İmzalı, HttpOnly, SameSite Strict oturum çerezi; giriş deneme sınırı; temel güvenlik yanıt başlıkları.
- UDP ve TCP DNS sunucusu; engellenmeyen DNS sorgularını yapılandırılan üst DNS sunucusuna iletir.
- Kural ekleme/kaldırma, yönetim geçmişi ve engellenen sorgular için yerel SQLite kayıtları.
- İsteğe bağlı kurumsal görünümlü HTTP engel portalı: engelli A kayıtları sunucu IPv4 adresine yönlendirilir; port 80'de sade bir “Bu web sitesine erişim engellendi” sayfası gösterilir.
- GitHub Actions ile Python derleme ve otomatik test.

## Mimari

    Yönetici bilgisayarı (HTTPS)
             |
       FastAPI paneli -------- SQLite: kurallar + denetim kayıtları
                                    |
    Okul istemcileri ---> kurum DNS filtresi ---> üst DNS (izinli alanlar)
                              |
                     engelli alan adı
                              |
                NXDOMAIN veya isteğe bağlı A -> portal IP
                              |
                     HTTP engel sayfası

Kurallar yaklaşık bir saniyeden kısa süre içinde DNS filtre önbelleğine yansıyacak şekilde tasarlanmıştır. İstemcilerin kurum DNS sunucusunu kullanacak biçimde yapılandırılması gerekir. Uygulama router/DHCP veya işletim sistemi ayarlarını kendiliğinden değiştirmez.

## Kurulum

Python 3.11+ gerekir.

Windows PowerShell:

    git clone https://github.com/oguzhan-tpl/yasaklama.git
    cd yasaklama
    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt
    python controller.py --init-admin

Linux:

    git clone https://github.com/oguzhan-tpl/yasaklama.git
    cd yasaklama
    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install -r requirements.txt
    python controller.py --init-admin

Parolayı iki kez girin. Sabit veya varsayılan yönetici parolası yoktur. Yapılandırma data/config.json, kurallar ve kayıtlar data/policy.sqlite3 içinde tutulur. Bu dizini paylaşmayın; yedeklerin erişimini de kısıtlayın.

### Önce güvenli yerel test

    python controller.py --web-host 127.0.0.1 --web-port 8765 --dns-host 127.0.0.1 --dns-port 5353

Paneli yalnızca sunucu bilgisayarından http://127.0.0.1:8765 adresinde açın. Bu komut HTTP portal yönlendirmesini etkinleştirmez; yalnızca DNS filtreyi test eder.

## Okul LAN'ına dağıtım

Bu adım için ağın sahibinden/kurumdan izin ve router/DHCP yönetim yetkisi gerekir.

1. Sunucuya sabit bir yerel IPv4 adresi verin; aşağıdaki örnekte 192.168.1.50 kullanılıyor. Kendi ağınıza göre değiştirin.
2. Yönetim paneli için sunucu adı/IP'siyle eşleşen geçerli TLS sertifikası hazırlayın. Sertifikalar hazır olduğunda --ssl-certfile ve --ssl-keyfile seçeneklerini kullanın. Yönetim panelini sertifikasız olarak bütün LAN'a açmak parola ve oturum trafiğini şifrelemez.
3. Windows'ta port 53 ve 80 için izin gerekebilir; bu portları açmak için yetkili sunucuda uygun yönetici izni gerekir. UAC'yi atlamaya çalışmayın.
4. HTTPS sertifikası ve IP adresleri ayarlandıktan sonra örnek komut:

   Windows PowerShell'de aşağıdaki yolları kendi sertifika yolunuzla değiştirin:

       python controller.py --web-host 0.0.0.0 --web-port 8765 --ssl-certfile "C:\certs\fullchain.pem" --ssl-keyfile "C:\certs\privkey.pem" --dns-host 0.0.0.0 --dns-port 53 --upstream 1.1.1.1 --block-ip 192.168.1.50 --block-page-host 0.0.0.0 --block-page-port 80

   --block-ip verilirse engellenen alan adlarının IPv4 DNS sorgusu portal IP'sine döner. --block-ip verilmezse varsayılan engel yanıtı NXDOMAIN olur ve engel portalı çalıştırılmaz.

5. Kurum router/DHCP ayarlarında istemcilere bu DNS sunucusunun IP'sini dağıtın. Dış DNS'e doğrudan erişimi yalnızca onaylanmış ağ politikasıyla sınırlandırın; aksi halde bazı istemciler DNS ayarını değiştirebilir. DNS-over-HTTPS (DoH), VPN ve benzeri yöntemler ayrıca ele alınmadığı sürece ağ filtresini atlayabilir.
6. Başka bir bilgisayardan, sertifikadaki sunucu adını kullanarak https://SUNUCU-ADI:8765 adresini açın ve kurulumda oluşturduğunuz yönetici parolasıyla giriş yapın. Panelden tam web bağlantısı yapıştırabilir; kuralı kaldırabilir ve değişiklik geçmişini görebilirsiniz.
7. Önce test bilgisayarında deneme yapın. Bir okulun üretim ağına geçmeden önce DNS, TLS ve router ayarlarını ağ yöneticisiyle birlikte doğrulayın.

## Engel sayfası ve HTTPS sınırı

**HTTP sayfası:** --block-ip ile açıldığında, engellenen alan adının A kaydı filtre sunucusuna yöneltilir. Tarayıcı siteye http:// üzerinden bağlanırsa “Bu web sitesine erişim engellendi” sayfası görüntülenir.

**HTTPS sayfası:** DNS tek başına HTTPS bağlantısının içeriğini değiştiremez. Kullanıcı https://site.example açtığında tarayıcı TLS bağlantısı kurmaya çalışır ve engel portalı o alan adı için geçerli sertifikaya sahip olmadığı için özel HTML sayfasını gösteremez. HTTPS sayfasını bütün yönetilen cihazlarda kurumsal tasarımla göstermek için ağ yöneticisinin yönettiği bir web filtreleme/TLS denetim sistemi ve cihazlara kurum tarafından dağıtılmış güvenilir sertifika/politika gerekir. Bu proje sahte sertifika kurmaz ve TLS trafiğini çözmez.

## Sınırlar

- Filtre, istemci sorgusu bu sunucuya ulaştığında çalışır. Uygulama kendi başına router/DHCP yapılandırmaz; DNS trafiği başka yerden geçerse engelleme garanti edilmez.
- VPN, farklı DNS, DoH ve doğrudan IP erişimi için kurumun ağ geçidinde ayrıca uygulanmış politikalar gerekebilir. “Ağdaki hiç kimse hiçbir yöntemle aşamaz” garantisi, yalnızca bu Python programıyla verilemez.
- IP adresi yerine alan adı kuralı kullanılır. Bir alan adının farklı hizmetleri aynı IP'yi paylaşıyorsa bu proje onları IP düzeyinde ayırmaya çalışmaz.
- Paneli internete doğrudan açmayın. Yalnızca yetkili LAN/VPN üzerinden erişim, geçerli TLS, güvenlik duvarı kısıtlaması, güçlü parola ve kontrollü yedekleme kullanın.
- Program UAC'yi atlatmaz, standart kullanıcılara gizlice yönetici yetkisi vermez ve kendini kaldırılamaz biçimde gizlemez.

## Testler

    python -m compileall -q controller.py tests
    python -m pytest -q

GitHub Actions bu kontrolleri her push ve pull request'te yürütür. CI başarısı, gerçek okul router'ı, DNS istemci davranışı veya bütün tarayıcıların HTTPS davranışının test edildiği anlamına gelmez; dağıtım öncesi kontrollü test gerekir.

## Gizlilik

Engellenen DNS sorguları istemci IP adresi ve alan adı içerebilir. Tekrarlayan aynı istemci/alan adı olayları 10 saniyelik aralıkta tek kayda indirgenir; son 1.000 olay SQLite içinde tutulur. Okulun kayıt saklama ve gizlilik politikasını uygulayın.
