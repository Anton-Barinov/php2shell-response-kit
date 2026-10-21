# php2shell: tespit ve müdahale rehberi

2026-10-21 · ORBITRON

CVE-2026-109618 ve CVE-2026-109619 (php2shell, CVSS v4.0 9.2), PHP'nin bir isteği ayrıştırırken (henüz hiçbir uygulama kodu çalışmadan) belleği tükendiğinde oluşan durum bozulmasıdır; **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** ile kapatıldı. Yamalanana kadar SOC ve müdahale ekipleri aşağıdaki log imzalarını izlemeli. Kritik ilke: **bu imzaların her biri bir *girişim* işaretidir; tek başına ne sistemin yamasız olduğunu ne de başarılı bir sömürüyü kanıtlar** — istek bağlamı, süreç telemetrisi ve etkin paket bilgisiyle birlikte değerlendirilmelidir.

## Kapsam ve doğrulama sınırları

Bu rehberdeki her bulgu, izole laboratuvarda PHP'nin **kendi resmi kaynak kodundan** derlenen yamasız ve yamalı sürümler ile PHP'nin **kendi yayınladığı regresyon testleri** kullanılarak üretilmiştir. Hiçbir üretim sistemine istek gönderilmemiş, exploit zinciri geliştirilmemiştir.

- **Doğrulanan:** Yamalı sürümler 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (php.net resmi duyurusu). Düzeltme tek commit: *"Avoid state corruption via bailout"* (GHSA-w8hw-w9fx-j79w / CVE-2026-109618, GHSA-6wmf-4rv5-p3rp / CVE-2026-109619).
- **Lab'de kanıtlanan:** Zafiyetin **ön koşulu** — istek ayrıştırılırken bellek tükenmesi, SAPI'ye göre farklı sonuçlar, ve upload-progress işleyicisinin RINIT'ten önce çalışması. Bu davranışların yamada düzeldiği testlerle gösterildi.
- **Lab'de kanıtlanMAYAN:** Tam bellek bozulması → RCE zinciri (heap grooming, pointer hijack) bilinçli olarak üretilmedi. RCE etkisi üçüncü taraflarca bildirilmiştir; biz yalnızca zafiyetin oluşması için gereken koşulu doğruladık.
- **DoğrulanMAYAN iddialar:** "PHP 5.4'ten beri etkilenir" ve "WordPress/Drupal vb. üzerinde RCE kanıtlandı" gibi ifadeler bu çalışmanın kapsamı dışındadır. php.net yalnızca 8.2–8.5 için yama yayınladı; 8.1 ve öncesi EOL'dir ve resmi upstream yaması yoktur, ancak henüz hangi eski sürümlerin etkilendiği bağımsız olarak teyit edilmemiştir.
- **En riskli kurulum mod_php'dir** (php.net): kalıcı worker, bozuk durumu aynı süreçteki bir sonraki isteğe taşıyabilir (CVE-2026-109619). PHP-FPM de CVE-2026-109618'den etkilenir.

## Zafiyet nasıl çalışıyor

PHP, gelen isteğin gövdesini (POST, multipart, upload) **uygulama kodu çalışmadan önce** ayrıştırır. Zincir şöyle işler:

1. **Giriş:** Saldırgan, ayrıştırılması boyutundan çok daha fazla bellek harcayan bir gövde gönderir — tek part içinde yüz binlerce başlık satırı, devasa alan adları, veya `Content-Length` ile uyumsuz gövde (yamasız sürümde `post_max_size` bazı yollarda aşılabiliyordu, GHSA-2cv3).
2. **Bozulma (CVE-2026-109618):** `memory_limit` aşılınca yamasız PHP `zend_bailout()` ile **çalışan C kodunun ortasında `longjmp`** yapar. Yarım kurulmuş yapılar bellekte işaretli kalır; ardından gelen temizlik bu yarım veriyi geçerli sanarak üzerinde dolaşır.
3. **Bayat state (CVE-2026-109619):** Başlatma hatası RINIT'ten önce olursa eklenti RSHUTDOWN'ları (`modules_activated=0`) atlanır; session gibi global değerler ne kurulur ne temizlenir ve serbest bırakılan belleği göstermeye devam eder.

Yama bunu şöyle kapatır: OOM artık atlama yapmaz, "gecikmeli OOM" olarak kuyruğa alınır (`EG(delayed_oom)`) ve güvenli noktada kesilir; ayrıştırıcılara `ZEND_HAS_OOM()` kontrolleri eklenir; upload-progress deserialize'ı **incomplete-classes-only** moduna alınır (sınıf çözümlenmez, kullanıcı kodu çalışmaz); `php_request_shutdown()` tüm global state'i sıfırlar.

**Tespit açısından en kritik nokta SAPI farkıdır** — aynı OOM, worker'ın türüne göre farklı iz bırakır:

| SAPI | Başlatma sırasında OOM olunca | Lab'de gözlemlenen iz | Sonraki isteğe taşınma |
| --- | --- | --- | --- |
| **PHP-FPM** | Worker kendini sonlandırır (`FPM_EXIT_SOFTWARE`) | FPM ana log: `child <PID> exited with code 70` + `PHP message: ... in Unknown on line 0` | Hayır (worker ölür) |
| **mod_php (Apache)** | İstek 500 döner, süreç yaşamaya devam eder | Apache error_log: `Allowed memory size ... in Unknown on line 0` | **Evet** — bozuk durum aynı süreçteki sonraki isteğe taşınabilir |
| **CGI (istek başına süreç)** | Süreç ölür | `in Unknown on line 0` | Hayır |

Lab'de tek-worker mod_php ile doğrulandı: OOM'dan **önceki ve sonraki istekleri aynı PID karşıladı**. FPM'de ise worker her başarısız başlatmada `code 70` ile kapandı — bu, SIGSEGV çökmesi **değildir** ve aşağıda ayrı bir imza olarak ele alınır.

## Lab doğrulaması

Yamasız ve yamalı sürümler debug + AddressSanitizer ile derlendi; PHP'nin yeni regresyon testleri her ikisinde çalıştırıldı.

**Kanıt matrisi** (PHP'nin kendi testleri; 8.3.35 yamasız, 8.3.36 yamalı):

| Test | Yamasız | Yamalı | Ne gösterir |
| --- | --- | --- | --- |
| Resmi regresyon testleri (toplam) | 27'den 5'i başarısız | 27/27 geçer | Düzeltmenin kapsamı |
| Multipart `post_max_size` bypass (GHSA-2cv3) | FAIL — bütün gövde `$_POST`'a alınır | PASS — uyarı + veri atılır | Kontrollü OOM giriş primitifi |
| 600.000 yinelenen part başlığı (GHSA-f883 007) | FAIL — sınırsız birikim → OOM | PASS — yalnızca 2 başlık saklanır | Bellek tüketim vektörü |
| Upload-progress, var olmayan betik (`rfc1867_no_user_code`) | FAIL — sınıf çözümlülür, `$_SESSION` geride kalır | PASS — kod çalışmaz, iz kalmaz | RINIT-öncesi kod çalıştırma |
| Geçersiz SID + upload-progress (`rfc1867_sid_invalid`) | FAIL — okuma başarısızken yazma denenir | PASS — hiçbir şey yazmaz | A4 imzasının kaynağı (aşağıda) |

**Önlem matrisi** — hangi geçici ayar OOM'u gerçekten durduruyor (yamasız 8.3.35 php-cgi, PHP'nin kendi test gövdesiyle):

| Ayar | Sonuç |
| --- | --- |
| Varsayılan (memory_limit=128M) | OOM — `in Unknown on line 0` |
| `post_max_size=8M` tek başına | OOM (durdurmaz) |
| `session.upload_progress.enabled=0` tek başına | OOM (durdurmaz) |
| `session.use_strict_mode=1` tek başına | OOM (durdurmaz) |
| `memory_limit=-1` | Tamamlanır (~218M tepe) |
| Yamalı 8.3.36, varsayılan | Tamamlanır (~2M tepe) |

Tek başına etkili olan ayar **`memory_limit=-1`**'dir; ama bu, birkaç MB'lık isteğin yüzlerce MB harcayabildiği bir **DoS riski** getirir — mutlaka cgroup/container bellek sınırıyla birlikte kullanılmalı. Not: Bu rakamlar debug + ASan derlemelerindendir; release derlemelerde bellek muhasebesi farklıdır, ancak Ubuntu'nun normal 8.3.6 mod_php'sinde de aynı test gövdesi 128M'yi tüketti.

## Loglar nerede bulunur

Aşağıdaki yollar yaygın örneklerdir; dağıtım, kurulum, container ve vhost yapılandırmasına göre değişir. **Gerçek yolu çalışan servisin yapılandırmasından doğrulayın.**

| Kurulum / kaynak | Toplanacak kayıtlar | Ne için |
| --- | --- | --- |
| Rocky / RHEL / Alma — Apache | `/var/log/httpd/error_log`, `/var/log/httpd/access_log`; vhost logları | PHP/Apache hataları + ilişkili istekler |
| Ubuntu / Debian — Apache | `/var/log/apache2/error.log`, `access.log`; vhost logları | Aynı; `ErrorLog`/`CustomLog` belirleyici |
| nginx | `/var/log/nginx/error.log`, `access.log` | FastCGI/upstream hataları, 5xx, istek bağlamı |
| Rocky/RHEL — PHP-FPM | `/var/log/php-fpm/error.log` + pool PHP hata dosyası (örn. `www-error.log`) | FPM süreç olayları + PHP fatal/warning |
| Ubuntu/Debian — PHP-FPM | `/var/log/php8.4-fpm.log` (sürüme göre ad değişir) + pool hata dosyası | Worker sonlanmaları + PHP hataları |
| systemd | `journalctl -u php\*-fpm\* -u httpd -u apache2 -u nginx` | Servis hataları, restart'lar, journal çıktısı |
| Container / Kubernetes | Container stdout/stderr + içerideki ayrı log dosyaları | Pod/container/node bilgisiyle PHP/FPM/web logları |
| WAF / reverse proxy | Güvenlik olayları, kural eşleşmeleri, body-inspection hataları | Multipart anomalileri, engelleme |
| Endpoint | EDR olayları; auditd varsa `/var/log/audit/audit.log` | PHP/web worker kaynaklı süreç/dosya/ağ etkinliği |

**Önemli ayrım:** FPM'in ana `error_log` ayarı ile PHP'nin `error_log` ayarı **farklı** kayıtları yönetir. Yalnızca birini toplamak diğerindeki olayları kaçırır. nginx access log'u toplamak, PHP hata log'unu toplamak anlamına gelmez.

**Gerçek yolu belirleme:**

- **Apache:** etkin sunucu ve vhost'taki `ErrorLog` / `CustomLog`.
- **nginx:** etkin `http`/`server`/`location` bloklarındaki `error_log` / `access_log`.
- **FPM:** `php-fpm.conf`'taki `error_log`; pool'daki `php_admin_value[error_log]`, `php_admin_flag[log_errors]`, `access.log`.
- **PHP:** web isteğini karşılayan SAPI'nin yüklediği php.ini. CLI'daki `php --ini` çıktısının web SAPI ile aynı olduğunu **varsaymayın**.

**Ön koşul:** `log_errors=On` ve `error_log` tanımlı olmalı. FPM'de worker stdout/stderr'in ana log'a taşınması için `catch_workers_output=yes` önerilir. `display_errors=Off` olsa bile fatal'ler log'a düşer.

## Tetik imzaları ve log örnekleri

Aşağıdaki ham log satırları yamasız 8.3.x FPM ve mod_php labında gerçek vektör tetiklenerek üretilmiştir. Her imza bir **girişim** işaretidir.

### A1 — Ana tetik: istek ayrıştırılırken OOM (CVE-2026-109618)

FPM (stderr ana log'a taşınmış):
```
WARNING: [pool www] child 849 said into stderr: "NOTICE: PHP message: PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted ... in Unknown on line 0"
```
mod_php (Apache error_log):
```
[php:error] [pid 587] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes) in Unknown on line 0
```
Regex:
```
Allowed memory size of [0-9]+ bytes exhausted .* in Unknown on line 0
```
**Neden kritik:** `in Unknown on line 0` — hata uygulama betiğine değil **request parse/startup'a** aittir. Normal uygulama OOM'u `.../foo.php on line 42` yazar. Aynı IP'den part sayısı/boyutu artarak gelen seri = kalibrasyon davranışı.

### A2 — Upload-progress vektörünün devrede olduğu (CVE-2026-109619 yolu)
```
PHP Warning:  PHP Request Startup: Session ID is too long or contains illegal characters ... in Unknown on line 0
```
`PHP Request Startup:` öneki, uyarının betik içinden değil, RINIT'ten önce upload-progress işleyicisinden geldiğini gösterir. Normal `session_start()` uyarıları bu öneki taşımaz. **Uyarı:** Bu satır yamalı sürümde de çıkar (vektör denemesinin izidir, zafiyete özel değil). Uygulamanız upload-progress kullanmıyorsa tek başına HIGH.

### A3 — Session okuma hatası (A2 ile aynı zincir)
```
PHP Warning:  PHP Request Startup: Failed to read session data: files (path: /var/lib/php/sessions) in Unknown on line 0
```
Bu da yamalı/yamasız ayırt etmez; vektörün denendiğini gösterir.

### A4 — Bayat-state yazma denemesi (dikkatli yorumlayın)
```
PHP Warning:  PHP Request Startup: Failed to write session data (files) ... in Unknown on line 0
```
Bu satır yamalı sürümde **üretilmez** (test diff'iyle doğrulandı): yamasız PHP okuma başarısızken bile yazmayı dener. **Ancak kritik sınırlama:** bu satır yalnızca **yazma da başarısız olursa** (geçersiz SID veya yazılamayan `save_path`) çıkar. Gerçek bir sunucuda `save_path` yazılabilir ve saldırgan **geçerli** bir SID seçerse, yamasız sürüm bayat state'i **sessizce, başarıyla yazar — A4 satırı hiç çıkmaz.** Bu nedenle A4, "yamasız PHP var" için **güvenilir bir envanter sinyali değildir**; yalnızca geçersiz-SID probu veya bozuk save_path durumunda ortaya çıkar. Envanter ve yama doğrulaması için paket sürümünü/changelog'u kullanın.

### A5 — Content-Length / limit bypass denemeleri
```
POST Content-Length of [0-9]+ bytes exceeds the limit of [0-9]+ bytes
Actual POST length does not match Content-Length, and exceeds [0-9]+ bytes
```
Yalan Content-Length'li büyük POST'lar — kontrollü OOM tetiğinin giriş primitifi (GHSA-2cv3). WAF'ta "gelen bayt ≠ Content-Length" karşılaştırılabiliyorsa orada da yakalanır.

### A6 — WAF / body inspection (log değil, kural)

Multipart gövdesinde, uygulama legit kullanmıyorsa şu alanları arayın:

- `name="PHP_SESSION_UPLOAD_PROGRESS"` form alanı
- `name="PHPSESSID"` gövdeden verilen SID
- Megabaytlarca yinelenen `Content-Disposition` / `Content-Type` başlığı; tek part'ta yüz binlerce başlık; `Content-Length: 0` + büyük gövde

## Bozulma ve başarı göstergeleri

Bu grup, sömürü **ilerlemişse** görülen izlerdir. Önemli bir ayırım var:

- **FPM `exited with code 70`** — başlatma sırasındaki OOM'un normal izidir; worker temiz çıkar. Lab'de her başarısız başlatmada görüldü. Bu bir çökme (SIGSEGV) **değildir**, ama OOM tetiğinin FPM'deki en yaygın gözlemlenebilir izidir. A1 ile birlikte korele edin.
- **SIGSEGV / SIGABRT** — yalnızca gerçek bellek bozulması tetiği işlediğinde beklenir (grooming gerektirir). Görülmesi A1'den daha ciddi bir sinyaldir.

| Nerede | Ne aranır |
| --- | --- |
| FPM ana log | `child [0-9]+ exited with code 70` (OOM-startup) · `exited on signal 11 (SIGSEGV)` · `exited on signal 6 (SIGABRT)` · kısa aralıklı worker respawn kümeleri |
| Apache error log | `seg fault or similar nasty error detected in the child` · `child pid [0-9]+ exit signal Segmentation fault \(11\)` |
| nginx error log | `upstream prematurely closed connection` · `recv\(\) failed` + access log'da 502 burst'ları |
| Apache + FPM | `AH01071: Got error 'PHP message: ...'` (PHP mesajı Apache log'una taşınır) |
| Access log (korelasyon) | Aynı IP'den multipart POST → hemen ardından 500/502/503 → aynı IP'nin devam etmesi |
| Session dizini | Uygulamanın oluşturmayacağı `sess_` dosyaları; içeriğinde `upload_progress_` anahtarları |
| HTTP yanıtları | Anormal uzun / tuhaf karakterli `Set-Cookie: PHPSESSID=...` — memory disclosure vektörünün olası izi |

**Not:** Başarılı **sessiz** sömürü (saf memory disclosure) hiç log üretmeyebilir. Bu yüzden B grubu + yanıt boyutu anomalileri birlikte izlenmeli. `Set-Cookie` ve response boyutu izleri bildirilmiş vektörlere dayanır; bizim labımızda memory disclosure üretilmediğinden bunları *bildirilen* (doğrulanmamış) sinyaller olarak ele alın.

## Trafik ve access log ayak izi

Saldırı yüzeyde "normal" görünebilir; status kodu taraması tek başına yetmez. Bu bölümdeki desenler ORBITRON lab'inde ölçülmüştür; access log deliği ve code-70 davranışı bu rehber için yeniden teyit edildi.

- **Status değil, davranış:** Kod çalıştıran multipart POST bile `status=200` döner; var olmayan bir endpoint'e (`404`) gelen büyük multipart POST da anormaldir. Access log'da aranacak şey URI'nin var/yok oluşu değil, **büyük/çok-part'lı multipart POST** davranışıdır.
- **⭐ Access log deliği (teyitli):** İstek *request startup'ta* (parse sırasında) ölürse FPM **access log'a hiç yazılmaz**, ama error log'da izi kalır. Lab'de normal istek access log'a düştü; OOM tetikleyen istek düşmedi ve worker `exited with code 70` ile kapandı. **Korelasyon kuralı:** error log'daki `Allowed memory size ... in Unknown on line 0` (veya `exited with code 70`) satırının access log'da zaman/pool karşılığı yoksa, o istek başlatmada ölmüştür = php2shell tarzı tetik denemesi (patchli sürümde bile).
- **Kalibrasyon deseni:** Sömürü, limiti istenen noktada kırmak için kademeli büyüyen gövdelerle dener. Aynı URI'ye **monoton büyüyen `bytes_in` serisi** (≥4-5 istek) ve gövde boyutuyla **süper-lineer artan `dur`** (upload-progress her part'ta session'ı yeniden encode ettiği için ~O(n²)) = kalibrasyon + yan etki olarak CPU/DoS. Tek başına MEDIUM; error-log imzalarıyla birlikte CRITICAL.
- **Trafik hacmi (tahmin):** Lab'de düşük `memory_limit` ile tetik birkaç yüz KB'lık gövdeyle oluşur; üretimdeki 128M sınırında bu kabaca onlarca kat büyür (~9-18 MB mertebesi). Ama uzun alan/dosya isimleri gibi amplifikasyon kolları gövdeyi küçük tutarken belleği büyük tükettiğinden, hacim eşiği tek başına kural olamaz — desenle birlikte kullanın.
- **Disk artefaktları:** Uygulama `session_start()` çağırmasa bile upload-progress saldırısında session dizininde `sess_*` yazma/mtime churn olur; session kullanmayan bir endpoint'te bu güçlü bir anomalidir. Ayrıca php-fpm/www-data kullanıcısına ait beklenmedik yeni dosyalar (bkz. post-exploitation). Not: Motorun RINIT'ten önce worker kimliğiyle **dosya yazabilmesi** lab'de yalnızca `opcache.preload` + session'a yerleştirilmiş bir gadget sınıfıyla (sunucu tarafı işbirliği) gösterildi; dışarıdan bir saldırgan bunu kendi başına kuramaz. Bu yüzden worker-uid'li yeni dosyaları genel bir RCE kanıtı değil, post-exploitation av sinyali olarak değerlendirin.

## Post-exploitation hunting

Kod çalıştırma gerçekleştiyse, PHP worker kullanıcısı (www-data / apache / php-fpm) adına beklenmedik süreç, dosya ve ağ etkinliği görülür.

- **auditd (süreç):** web worker kullanıcısının `euid`'siyle `execve` izleyin:
```
auditctl -a always,exit -F arch=b64 -S execve -F euid=48 -k php2shell_rce
```
`/bin/sh`, `/bin/bash`, `curl`, `wget`, `base64`, `perl`, `python` çalıştırmaları (euid = apache genelde 48, www-data 33).
- **Dosya sistemi:** `/tmp`, `/dev/shm`, upload dizinleri ve webroot'ta yeni dosyalar — özellikle yeni `.php` (webshell) ve anlamsız isimli script dosyaları.
- **Kalıcılık:** web worker kullanıcısına ait crontab girişleri, SSH `authorized_keys`, systemd user unit'leri.
- **Ağ:** PHP worker'dan beklenmedik giden bağlantılar (reverse shell, C2, veri sızıntısı).

Bu etkinlikleri değişiklik kayıtları ve uygulamanın normal davranışıyla karşılaştırın; meşru `exec()` kullanan uygulamalar (görsel/PDF araçları, yedekleme, deploy hook'ları) false positive üretir.

## Korelasyon ve alarm mantığı

PHP hata satırında kaynak IP **bulunmayabilir**; IP'yi HTTP access/WAF kaydıyla ilişkilendirin. Yalnızca yakın zaman damgasından kesin eşleşme üretmeyin; proxy arkasında gerçek istemci IP'sini güvenilen proxy zincirinden alın. Mümkünse request ID ve worker PID üzerinden ilişki kurun (FPM access log'una pool adı + child PID eklemek bunu kolaylaştırır).

| Alarm | Koşul | Güven / aksiyon |
| --- | --- | --- |
| CRITICAL | Aynı kaynak IP && A1 ≥ 3 kez && < 10 dk | Kalibrasyon / aktif deneme → IR başlat |
| CRITICAL | Multipart POST (A6) → ardından 5xx / worker respawn → IP devam ediyor | Kısmen başarılı olabilecek sömürü → IR |
| HIGH | A2 veya A3 (tek başına, uygulama upload-progress kullanmıyorsa) | Upload-progress vektörü tetiklendi |
| HIGH | C grubu (worker'dan execve/webshell) uygulamanın bilinen davranışı değilse | Sömürü sonrası → IR |
| MEDIUM | A1 + FPM `code 70` (aynı pool/zaman) | OOM tetiği FPM worker'ı düşürdü |
| MEDIUM | B grubu çökme sinyalleri, uygulamanın bilinen crash nedeni yoksa | Bellek bozulması olası |
| CRITICAL | Error log'da `Allowed memory size ... in Unknown on line 0` **var** && access log'da aynı zamana karşılık **yok** | Startup'ta ölmüş istek = tetik denemesi (access log deliği) |
| MEDIUM | Aynı URI'ye ≥4 monoton büyüyen `bytes_in` && `dur` süper-lineer | Kalibrasyon — error-log imzalarıyla birlikte CRITICAL |

**Örnek korelasyon zinciri:** Olağandışı multipart isteği → aynı sunucu/pool ve zaman aralığında A1/A2 → worker sonlanması (code 70) veya 5xx → benzer isteklerin tekrarı. Buna worker'dan beklenmedik komut/dosya/bağlantı eklenirse şüphe güçlenir.

**Mükerrer olay uyarısı:** Aynı hata hem FPM hem Apache log'undan gelebilir; iki kaynağı aynı olay sayarak "3 deneme" eşiğini yanlış tetiklemeyin.

## Hazır sorgular ve ORBITRON kuralları

Hızlı triyaj için grep'ler:
```
# A1: ana tetik (FPM + Apache error log)
grep -E "Allowed memory size of [0-9]+ bytes exhausted .*in Unknown on line 0" \
  /var/log/*fpm*.log /var/log/httpd/*error* /var/log/apache2/*error*

# A2-A4: istek-başlangıcı session imzaları
grep -F "PHP Request Startup:" /var/log/*fpm*.log /var/log/httpd/*error*

# FPM worker: OOM-startup (code 70) ve gerçek çökme (signal)
grep -E "exited with code 70|exited on signal (11|6)" /var/log/*fpm*.log

# Apache + FPM sarmalayıcısı
journalctl -u httpd --since today | grep "AH01071" | grep -E "Allowed memory|Request Startup"

# Access log'da davranış: multipart POST + 5xx
awk '$6=="\"POST" && $9~/^50[0-9]$/' /var/log/nginx/access.log
```

ORBITRON php2shell-response-kit (public repo) karşılıkları:

| Sinyal | Kural |
| --- | --- |
| A1 (OOM, in Unknown on line 0) | Sigma `php2shell_php_oom_during_request_parsing` · Wazuh 109627 |
| OOM + ardından worker çökmesi (2 dk) | Wazuh 109628 |
| OOM seri (5/5 dk) | Wazuh 109629 |
| FPM worker exited with code 70 (OOM-startup) | Sigma `php2shell_php_fpm_worker_exit_code70` · Wazuh 109630 |
| Code 70, bir OOM-during-parsing'i takip eden 2 dk içinde | Wazuh 109631 |
| Worker çökmesi (SIGSEGV/SIGABRT) | Sigma `php2shell_php_worker_crash` · Wazuh 109625/109626 |
| A6 multipart başlık seli / body hatası | ModSecurity 9109622 / 9109623 |
| Upload-progress alanı | ModSecurity 9109618/19/21 |
| C grubu (webserver → shell/webshell) | Sigma spawns_shell / file_written_to_webroot · Wazuh 109610–109621 · YARA |

Tüm SIEM/EDR sorguları pySigma ile üretilmiştir ve canlı platformlarda test edilmemiştir; script'ler, YARA ve ModSecurity kuralları lab'da test edildi. Alarm açmadan önce 1–2 saat baseline alın.

## Geçici önlemler, yama doğrulama ve kaynaklar

**Öncelik:** Dağıtımınızın iki CVE'yi gideren paketini uygulayın (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 veya vendor backport'u), ilgili servisleri ve **uzun ömürlü worker'ları yeniden başlatın**. Çalışan süreçlerin yamalı sürümü kullandığını doğrulayın. Yama doğrulamasını paket kaydı, üretici duyurusu ve çalışan süreç üzerinden yapın — A4 gibi log imzaları bunun için güvenilir değildir.

Geçici önlemlerin **izleme üzerindeki etkisi** (alarm görülmemesi = güvende olma demek değildir):

| Önlem | Detection'a etkisi |
| --- | --- |
| `session.upload_progress.enabled=Off` | A2/A3/A4 kaybolur (vektör kapanır); A1/A5/B grubu kalır |
| `memory_limit=-1` (+ cgroup) | A1 üretilmez; altta yatan tahsis hatası cgroup sınırında tetiklenebilir — B grubunu izlemeye devam |
| Düşük `post_max_size` (8M/32M) | A5 sıklığı artar (görünürlük kazanırsınız) |
| Web sunucusu allowlist (yalnızca mevcut, kullanılan `.php`) | Var olmayan betik vektörü kapanır; A1 azalır |
| `fatal_error_backtraces=Off` (yalnızca 8.5) | Bir UAF yüzeyini kapatır |

**Görünürlük boşlukları:** `log_errors` açık ve hata seviyesi ilgili mesajları kapsamalı; `display_errors=Off` loglamayı kapatmaz. Standart access log'lar multipart gövdesini içermez — `PHP_SESSION_UPLOAD_PROGRESS` alanını görmek için WAF/body inspection gerekir. Geçici önlemler bazı logların oluşmasını engelleyebilir; önlem öncesi/sonrası baseline alın.

**Kaynaklar:**

- PHP güvenlik sürümleri 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (21 Ekim 2026): [php.net/archive/2026](https://www.php.net/archive/2026.php)
- Düzeltme commit'i "Avoid state corruption via bailout" (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp): [github.com/php/php-src](https://github.com/php/php-src/commit/3c832b523ee13b1a010177d2ff84aea18be0015e)
- ORBITRON php2shell-response-kit (envanter script'leri + kurallar): [github.com/orbitron-ai/php2shell-response-kit](https://github.com/orbitron-ai/php2shell-response-kit)

Lab doğrulaması, ORBITRON tarafından 21 Ekim 2026'da izole ortamda, PHP'nin resmi kaynağından derlenen yamasız/yamalı sürümler ve resmi regresyon testleriyle yapılmıştır. Exploit zinciri üretilmemiş, üretim sistemlerinde tetiklenmemiştir.
