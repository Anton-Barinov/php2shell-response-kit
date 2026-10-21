# php2shell — CVE-2026-109618 / CVE-2026-109619 · ORBITRON müdahale kiti

> **Durum: v1.2.3 — RESMİ AÇIKLAMA ÖNCESİ (21.10.2026 14:55 TSİ / 11:55 UTC).**
> Teknik detayları, etkilenen ve düzeltilmiş sürümleri içeren resmi PHP duyurusu
> **21.10.2026 17:00 TSİ (14:00 UTC)** için planlandı. Sürüm çıktıktan sonra bu repo güncellenecek.
> Aşağıda *bildirilen* veya *doğrulanmamış* olarak işaretlenen her şey değişebilir. Değişiklikler: [CHANGELOG.md](CHANGELOG.md).
>
> English version: [README.md](README.md)

## Özet

* PHP çekirdeğinde iki kritik uzaktan kod çalıştırma (RCE) açığı var; PHP güvenlik ekibi ikisini de
  CVSS v4.0 9.2 olarak puanladı. Detaylar erken sızdı; yama **21 Ekim 17:00 TSİ**'de (istismar başlarsa daha erken) yayınlanacak.
* Doğrulanmış public PoC/exploit yok. 21 Ekim'de GitHub'da "exploit" adlı çok sayıda repo açıldı —
  **doğrulanmamış, izole lab dışında çalıştırmayın.**
* **Tek gerçek çözüm yama.** `session.upload_progress.enabled=0`, öneren firmanın kendi güncellemesine
  göre yalnızca *kısmi* bir azaltım.
* Açıklama öncesinde tespit yalnızca **davranışsal** olabilir (istismar sonrası). Bu kit; envanter
  script'leri ile Sigma, Splunk, QRadar, CrowdStrike Falcon, SentinelOne, Wazuh, YARA ve ModSecurity
  kurallarını, neyi kapsayıp neyi kapsamadıkları açıkça belirtilmiş olarak sunar.

## 1. Olay nedir?

| Konu | Durum |
|---|---|
| Her biri CVSS v4.0 9.2 olan iki kritik PHP açığı; yayın 21 Ekim 2026 14:00 UTC | php.net tarafından **doğrulandı** (20 Ekim ön duyurusu) |
| Açık sınıfı: PHP çekirdeğinde kimlik doğrulamasız RCE | watchTowr (CVE-2026-109618'i yeniden üretti) ve diğerleri bildirdi; PHP detay yayınlamadı |
| CVE numaraları CVE-2026-109618 / CVE-2026-109619 | watchTowr ve sızan materyalden; php.net duyurusunda geçmiyor; kayıtlar "reserved" |
| "php2shell" adı ve PHP ≥ 5.4'ü hedeflediğini iddia eden "PHP2Shell" aracı | Ekran görüntüsü sızıntısı — doğrulanmadı |
| Etkilenen sürümler "PHP 5'ten 8'e kadar" | Bildirildi — **doğrulanmadı** |
| Yama yalnızca desteklenen dallar için (8.2, 8.3, 8.4, 8.5) | Bildirildi; PHP destek politikasıyla uyumlu |
| *Session Upload Progress* (`ext/session`) ile bağlantı, bellek bozulması | GMO Flatt Security'nin değerlendirmesi; kendi araştırmalarının php2shell ile örtüşmesi *koşuluyla* |
| Sahada aktif istismar | 21 Ekim sabahı itibarıyla bildirilmedi (watchTowr, Huntress) |

Zaman çizelgesi: 20 Ekim ~18:20 TSİ Hacker News'te sızıntı → 20 Ekim 22:33 TSİ PHP ön duyurusu →
21 Ekim 17:00 TSİ planlı yayın.

## 2. Neden önemli?

* PHP, açık web'in büyük bir bölümünü çalıştırıyor: WordPress/WooCommerce, Magento/Adobe Commerce,
  Shopware, Drupal, Laravel/Symfony uygulamaları, hosting panelleri ve PHP gömülü birçok cihaz.
* Yorumlayıcı çekirdeğindeki bir RCE, etkilenen runtime üzerindeki *her* uygulama üzerinden erişilebilir;
  uygulama sıkılaştırması ve uygulama içi WAF eklentileri PHP isteği işledikten *sonra* devreye girer.
* Araştırmacılar (ör. Sansec) yama diff'i açığı ele vereceği için yayından dakikalar sonra kitlesel
  istismar bekliyor.
* Desteği bitmiş (EOL) sürüm nüfusu büyük: internet taramaları PHP 8.1 veya öncesini ilan eden yüz
  binlerce sunucu sayıyor; bunlara upstream yama gelmeyecek.

## 3. Etkilenen sistemler — şu an bilinenler

| Runtime | Beklenen durum (resmi duyuru bekleniyor) |
|---|---|
| php.net, Remi, deb.sury.org, resmi Docker imajları ve Windows build'lerinden gelen PHP 8.2 / 8.3 / 8.4 / 8.5 | Upstream yama 21 Ekim 17:00 TSİ bekleniyor |
| PHP 8.1 ve öncesi (upstream EOL) | **Upstream yama yok.** Yalnızca dağıtım/ESM/üretici backport'u veya yükseltme |
| Dağıtım paketleri (RHEL/Rocky/Alma, Debian, Ubuntu, SUSE) | Yama dağıtımın güvenlik süreciyle gelir — zamanlama farklı, bkz. §7 |
| Tüm SAPI'ler (mod_php, PHP-FPM, CGI/FastCGI, LiteSpeed) | Bildirilen denemeler mod_php ve php-fpm üzerinde WordPress/Laravel/Symfony ile yeniden üretimi içeriyor (Flatt Security'nin araştırmacı paylaşımı özetine göre) |

## 4. Neleri kontrol etmek lazım? (script'leri kullanın)

| Script | Platform | Ne yapar |
|---|---|---|
| [`scripts/linux/php2shell-check.sh`](scripts/linux/php2shell-check.sh) | Linux (RHEL ailesi, Debian/Ubuntu, Alpine, cPanel/Plesk/CloudLinux/Remi yolları) | Tüm PHP binary'lerini ve SAPI'leri bulur, SAPI bazında **etkin** ayarları okur (CLI, FPM, CGI, mod_php ini seti), FPM pool / web sunucusu / `.user.ini` / `.htaccess` override'larını listeler, paket ve kaynağını (dağıtım, Remi, Sury), paket changelog'unda CVE'lerin geçip geçmediğini, çalışan süreçleri, **çalışan FPM worker'larının / Apache alt süreçlerinin son config değişikliğinden sonra başlatılıp başlatılmadığını ve güncel binary'yi kullanıp kullanmadığını** (`LOADED` / `STALE` / `RESTART REQUIRED`) ve **sunucudaki container / Kubernetes pod'larının içindeki PHP'yi** (Docker, Podman, containerd, CRI-O) `/proc/<pid>/root` üzerinden salt okunur inceleyerek raporlar — container bazında sürüm, paket, `session.upload_progress` ve çalışma durumu; `crictl`/`docker`/`podman` varsa pod/container adlarıyla |
| [`scripts/windows/php2shell-check.ps1`](scripts/windows/php2shell-check.ps1) | Windows (IIS FastCGI, XAMPP, WAMP, Laragon, Plesk, PATH, çalışan süreçler) | Aynısını Windows için yapar; her IIS FastCGI uygulamasını kendi argümanları/`PHPRC` değeriyle değerlendirir; çalışan `php-cgi.exe` / Apache süreçlerinin son `php.ini` değişikliğinden veya PHP binary'sinden eski olup olmadığını kontrol eder (IIS `monitorChangesTo` dahil) |

İkisi de **yalnızca okuma yapar**, ağ bağlantısı kurmaz ve istismar denemez. Filo genelinde toplama
için JSON çıktı verir (ör. ORBITRON Command Engine, Ansible, SCCM/Intune).

```bash
sudo bash php2shell-check.sh                 # okunabilir çıktı
sudo bash php2shell-check.sh -o report.json  # + JSON
sudo bash php2shell-check.sh --no-containers   # (salt okunur) container / pod incelemesini atla
sudo bash php2shell-check.sh --container-exec  # ek olarak docker/podman exec ile 'php -r' çalıştırıp kesin CLI değerlerini al
```
```powershell
powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1 -OutFile report.json
```
Çıkış kodları: `0` PHP yok, `1` PHP var ve tüm runtime'lar yamalı doğrulandı, `2` PHP var ve en az bir
runtime yamalı **doğrulanamadı**.

Resmi duyuru çıktıktan sonra düzeltilmiş sürümleri (yalnızca php.net'ten) tanımlayın:
`PHP2SHELL_FIXED_UPSTREAM="8.2.x 8.3.x 8.4.x 8.5.x"`. Linux script'i, yamayı backport eden dağıtım
paketlerine (RHEL/Ubuntu eski sürüm numarasını korur) upstream sürüm karşılaştırması **uygulamaz**;
bunlar için paket changelog'unda CVE'nin geçmesine bakar.

Kontrol listesi:
1. Her PHP runtime'ını **ve web sunucusunun gerçekten kullandığı SAPI'yi** envanterleyin (CLI değerleri ≠ FPM değerleri).
2. Dağıtım/ESM backport'u kapsamında olmayan upstream-EOL dalları (≤ 8.1) işaretleyin.
3. Paketlerinizin nereden geldiğini kaydedin (dağıtım, Remi, Sury, panel üreticisi) — ne zaman yama yapabileceğinizi bu belirler.
4. İnternete açık sunuculara öncelik verin; 21 Ekim 17:00 TSİ sonrası için değişiklik pencereleri hazırlayın.
5. Güncellemeden sonra FPM pool'larının / container'ların **yeniden başlatıldığını** kontrol edin (çalışan worker eski binary'yi kullanmaya devam eder).
   Yukarıdaki ayarlar diskteki ini dosyalarından okunur; çalışan süreçlerin bunları gerçekten kullanıp kullanmadığını
   `Running:` satırı gösterir. `STALE` = reload gerekli, `RESTART REQUIRED` = süreçler paket güncellemesiyle değiştirilmiş
   eski binary'yi çalıştırıyor.

## 5. Bilinen workaround'lar — güncel durum

| Workaround | Durum (21 Ekim, 10:30 TSİ) | Notlar |
|---|---|---|
| `session.upload_progress.enabled = 0` | **Yalnızca kısmi azaltım.** Öneren Flatt Security yazısını güncelledi: saldırının yine mümkün olacağı değerlendiriliyor. PHP çekirdek geliştiricilerinin de INI ayarlarının tek başına korumayacağını söylediği aktarılıyor. Bir analiz, iki açıktan yalnızca birini kapsadığını iddia ediyor. | Maliyeti düşük: dosya yükleme çalışmaya devam eder, yalnızca ilerleme takibi durur. `INI_PERDIR`'dir: php.ini, FPM pool (`php_admin_flag`), Apache `php_admin_flag` ile ayarlanır — `ini_set()` ile **olmaz**. SAPI bazında etkin değeri script ile doğrulayın. |
| `session.use_strict_mode = 1` | **Bu mekanizma için azaltım değil** (lab notlarımız, §9) | Yine de iyi bir hijyen ayarı. |
| `PHP_SESSION_UPLOAD_PROGRESS` multipart alanı için WAF kuralı | **Avlama / yalnızca tek vektör** | Lab'da test edilmiş ModSecurity kuralları `rules/modsecurity/` altında. Engelleme varyantı varsayılan olarak kapalı. |
| Maruziyeti kısıtlama (VPN/IP izin listesi, yönetim panellerini kapatma, EOL sunucuları izole etme) | Etkili risk azaltımı | CERT-EU, yama gelene kadar internete açık uygulamaların izole edilmesini öneriyor. |
| PHP kullanıcısı için en az yetki, çıkış (egress) filtreleme, salt okunur web kökleri | Etkiyi sınırlar | Flatt Security de öneriyor; webshell kalıcılığını da zorlaştırır. |
| Yama | **Çözüm** | Upstream 21 Ekim 17:00 TSİ; dağıtım zamanlaması §7. |

## 6. Tespit ve izleme kuralları

Yama diff'i açıklanmadan istismara özel imza yazılamaz. Aşağıdaki kurallar saldırganın PHP'de kod
çalıştırdıktan *sonra* yaptıklarını ve şüphelenilen mekanizma etrafındaki avlama sinyallerini yakalar.
**Tüm SIEM/EDR sorguları canlı platformlarda TEST EDİLMEDİ** (Sigma kaynaklarından pySigma ile üretildi);
YARA, ModSecurity ve script'ler lab'ımızda test edildi. Alarm açmadan önce 1–2 saat baseline alın.

| Kullanım senaryosu | Sigma (kaynak) | Splunk | QRadar | CrowdStrike Falcon | SentinelOne | Wazuh | Diğer |
|---|---|---|---|---|---|---|---|
| Linux: PHP/web sunucusu shell, yorumlayıcı, indirme/keşif aracı başlatıyor | `lnx_..._spawns_shell_or_lolbin.yml` | `.spl`, `.cim.spl` | `.aql`, `.payload.aql` | `.logscale` | `.dv`, `.pq` | 109610–109612 (auditd) | — |
| Linux: PHP'den reverse shell / keşif komut satırı | `lnx_..._suspicious_cmdline.yml` | ✓ | ✓ | ✓ | ✓ | 109613 | — |
| Windows: php-cgi/php/httpd/w3wp shell/LOLBin başlatıyor | `win_..._spawns_shell_or_lolbin.yml` | ✓ | ✓ | ✓ | ✓ | 109620 (Sysmon) | — |
| Web köküne webshell / `.user.ini` / `.htaccess` yazılması | `lnx_/win_..._file_written_to_webroot.yml` | ✓ | ✓ | Falcon'un yerleşik webshell tespitleri | ✓ | 109615, 109616, 109621 | YARA |
| PHP worker çökmesi (SIGSEGV/SIGABRT) — bellek bozulması denemeleri | `php2shell_php_worker_crash.yml` | ✓ | payload | ✓ (log ingestion gerekir) | — | 109625, 109626 | — |
| Multipart isteklerde upload-progress alanı | — | — | — | — | — | — | ModSecurity 9109618/19/21 (+ engelleme 9109620) |
| Webshell, auto_prepend kalıcılığı, upload-progress session kalıntıları | — | — | — | — | — | — | YARA `rules/yara/` |

Veri gereksinimleri: üst süreç bilgisiyle süreç oluşturma (Linux/Windows için Sysmon, auditd `execve`,
EDR), web kökü kuralları için dosya oluşturma telemetrisi, çökme kuralı için PHP-FPM/Apache hata
logları, ModSecurity için istek gövdesi incelemesi. Platform notları:

* **Splunk** — `.spl` Sysmon alan adlarını (`Image`, `ParentImage`, `CommandLine`), `.cim.spl` CIM Endpoint veri modelini kullanır.
* **QRadar** — alan tabanlı `.aql` Sysmon/EDR custom property'leri (*Parent Process Path*, *Command*) gerektirir; Linux OS DSM (auditd) genelde üst süreç bilgisi taşımaz → `.payload.aql` veya Wazuh/auditd yaklaşımı.
* **CrowdStrike Falcon** — `ProcessRollup2` üzerinde LogScale / NG-SIEM / Advanced Event Search sözdizimi; dosya yazma kuralları üretilmedi (pipeline kısıtı).
* **SentinelOne** — `.dv` (Deep Visibility) `endswith` mantığını korur; `.pq` backend'i `endswith`'i `contains` ile yaklaşık çevirir (daha geniş eşleşme).
* **Wazuh** — `rules/wazuh/0910-orbitron-php2shell_rules.xml` + `auditd-php2shell.rules` + `ossec-agent-snippet.xml`. `wazuh-logtest` ile doğrulayın.
* **YARA** — `yara -r rules/yara/php2shell_hunting.yar /var/www` ve PHP session dizini.
* Platform sorgularını yeniden üretmek için: `python3 tools/build_rules.py` (bkz. `rules/BUILD_REPORT.md`).

Beklenen false positive'ler: meşru `exec()` kullanan PHP uygulamaları (görsel/PDF araçları, yedekleme,
deploy hook'ları, kontrol panelleri), PHP `mail()` (`sh -c sendmail`, filtrelendi), kendi `.php`
dosyalarını yazan CMS güncellemeleri, çöken üçüncü taraf eklentiler.

## 7. Güncelleme takvimi ve yamanın platformlara ulaşma süreci

| Kaynak | Yama nasıl gelir | Ne beklemeli / nasıl doğrulanır |
|---|---|---|
| **php.net (upstream)** | 21 Ekim 17:00 TSİ'de (veya daha erken) 8.2–8.5 için yeni ara sürümler | Gösterge sürüm numarasıdır (düzeltilmiş sürümler duyuruyla yayınlanır) |
| **Windows** (windows.php.net build'leri, XAMPP/WAMP/Laragon, IIS) | PHP binary'lerini yeni build ile değiştirin; paketlenmiş yığınlar daha sonra gelir | `php -v`; IIS app pool / Apache yeniden başlatma |
| **Remi (RHEL ailesi) / deb.sury.org ve ondrej PPA (Debian/Ubuntu)** | Upstream sürümleri takip eder, genelde yeni upstream sürümleri hızlı yayınlar | Upstream sürüm numarası geçerli; `dnf update` / `apt upgrade`, FPM yeniden başlatma |
| **RHEL 8/9/10 → Rocky / AlmaLinux / Oracle** | Red Hat yamayı mevcut pakete **backport** eder (sürüm numarası değişmez); Rocky/Alma RHSA'yı yeniden derler (Rocky'nin RLSA bildirimleri RHSA'dan aktarılır) | Geçmişte aynı gün gelmedi: ör. Mayıs 2026 PHP yamaları RHEL'e RHSA-2026:22143 (php:8.2, RHEL 9, 20 Temmuz tarihli), Rocky 8'e RLSA-2026:34354 (2 Temmuz) ile ulaştı. Kontrol: `dnf updateinfo list --cve CVE-2026-109618` ve `rpm -q --changelog php-common \| grep CVE-2026-10961` |
| **Debian** | Debian Güvenlik Ekibi DSA yayınlar; PHP için son dönemde yeni upstream ara sürümü gönderdi (ör. DSA-6255-1 → `8.2.31-1~deb12u1`, upstream'den bir gün sonra) | `apt list --upgradable 'php*'`; security-tracker.debian.org |
| **Ubuntu** | **Backport** edilmiş yamalarla USN (ör. `8.3.6-0ubuntu0.24.04.x` korunur); eski sürümler Ubuntu Pro/ESM ile | Geçmiş PHP USN'leri upstream'den günler-haftalar sonra geldi (ör. USN-8564-1, 20 Temmuz). ubuntu.com/security/CVE-… ve changelog'u kontrol edin |
| **Container'lar** (resmi `php:` imajları, özel imajlar) | İmajlar upstream yayından sonra yeniden derlenir | Yeniden derleyin **ve yeniden deploy edin**; sabitlenmiş base imajlar kendiliğinden güncellenmez |
| **Hosting panelleri / CloudLinux / cihazlar** (cPanel EA-PHP, Plesk, alt-php, üreticiler) | Üreticiye özgü | Hosting/panel/cihaz üreticisinden *bugün* hazır beklemesini isteyin |
| **Upstream EOL (≤ 8.1)** | Upstream yama yok | Yükseltme, üretici/ESM backport'u veya izolasyon |

Her durumda: güncellemeden sonra **PHP-FPM / Apache / IIS app pool'larını yeniden başlatın** ve script'i tekrar çalıştırın.

## 8. Bugün için önerilen plan

1. Şimdi: envanter script'lerini çalıştırın; internete açık PHP'leri, EOL dalları ve paket kaynaklarını listeleyin.
2. Şimdi: davranışsal kuralları (süreç, dosya, çökme) SIEM/EDR'de açın; ModSecurity kurallarını log modunda açın.
3. Şimdi: ilerleme çubuğu kullanılmayan yerlerde `session.upload_progress.enabled=0` ayarlayın — yama değil, risk azaltımı olarak.
4. Şimdi: hosting/panel/cihaz üreticilerinden ve dağıtım kanallarından yayın planlarını isteyin.
5. 17:00 TSİ: duyuruyu okuyun, `PHP2SHELL_FIXED_UPSTREAM`'i ayarlayın, önce upstream'i takip eden sunucuları yamalayın, servisleri yeniden başlatın.
6. Dağıtım paketleri gelene kadar: RHEL/Ubuntu paketli PHP'lerin maruziyetini kısıtlayın, kuralları yakından izleyin.
7. Sonrasında: maruz kalmış sunucularda webshell (YARA), yeni `.user.ini`/`.htaccess`, yeni cron job ve hesap avı yapın.

## 9. Lab notları (ORBITRON, Ubuntu 24.04, PHP 8.3.6, mod_php ve yerleşik sunucu)

Flatt Security'nin işaret ettiği *mekanizmayı* test ettik — açığın kendisini değil:
* `PHP_SESSION_UPLOAD_PROGRESS` adlı alan içeren bir multipart istek, hedef script `session_start()`
  **hiç çağırmasa bile** PHP'nin, istemcinin seçtiği session ID ile bir session dosyası oluşturmasına yol açtı (`session.use_strict_mode=Off`).
* `session.use_strict_mode=On` iken PHP ilerleme verisini yine yazdı, yalnızca rastgele bir ID ile → strict mode mekanizmayı durdurmuyor.
* `session.upload_progress.enabled=0` iken session dosyası oluşmadı.
* Varsayılan `session.upload_progress.cleanup=On` ile session dosyası boş olarak kaldı.
* Var olmayan bir `.php` yoluna (404) yapılan istek mekanizmayı tetiklemedi — *erişilebilir* her PHP script'i tetikliyor.
* ModSecurity 2.9: log kuralları yalnızca alanı taşıyan multipart isteklerde tetiklendi; normal yüklemeler işaretlenmedi; engelleme varyantı 403 döndü.

## 10. Kaynaklar

* PHP — Upcoming Critical PHP Security Release (20 Ekim 2026): https://www.php.net/archive/2026.php#2026-10-20-1
* GMO Flatt Security — php2shell özeti ve öneriler (Japonca, 21 Ekim'de güncellendi): https://blog.flatt.tech/entry/php2shell
* Sansec — Critical PHP RCE: https://sansec.io/research/php2shell
* Huntress — Rapid Response: https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
* The Hacker News: https://thehackernews.com/2026/10/php2shell-two-unpatched-critical-php.html
* Phoenix Security: https://phoenix.security/php-core-rce-cve-2026-109618-109619-critical-remote-code-execution/
* PHP kılavuzu — Session Upload Progress: https://www.php.net/manual/en/session.upload-progress.php
* Red Hat RHSA-2026:22143 · Rocky RLSA-2026:34354 · Debian DSA-6255-1 · Ubuntu USN-8564-1 (yama gecikmesi örnekleri)

## 11. ORBITRON üzerinden çalıştırma

ORBITRON müşterileri aynı incelemeyi hazır bir komut playbook'u olarak çalıştırabilir:
*PHP exposure and behavior investigation*. Playbook, filo genelinde salt okunur PHP / web worker
envanteri ve sınırlı kanıt toplama yapar.

![ORBITRON playbook: PHP exposure and behavior investigation](docs/images/orbitron-php2shell-investigation-playbook.png)

Playbook işletim sistemine göre dallanır. Linux sunucular ve container host'ları için PHP
envanteri, worker'lar, dosyalar, bağlantılar ve Docker bilgisi toplanır. Windows web sunucuları
için PHP/IIS envanteri, worker'lar, dosyalar ve bağlantılar toplanır. Her dal kanıtı ve kapsam
raporunu döndürür. Desteklenmeyen işletim sistemleri de ayrıca raporlanır, böylece kör noktalar
görünür kalır.

`scripts/` altındaki script'ler bağımsızdır, ORBITRON gerektirmez.

## Sorumluluk reddi ve lisans

Savunma amaçlı, olduğu gibi ve garanti olmaksızın sunulmuştur. Script ve kuralları üretimde kullanmadan
önce kendi ortamınızda doğrulayın. Bu repoda exploit kodu yoktur ve yayınlanmayacaktır. Script ve
kurallar: MIT Lisansı (bkz. [LICENSE](LICENSE)). © 2026 ORBITRON.
