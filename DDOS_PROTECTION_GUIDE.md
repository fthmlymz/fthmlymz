# 🛡️ DDoS KORUMA KILAVUZU - KVKNET Login Sayfası

---

## 🎯 DDoS Saldırı Tipleri ve Korunma Yöntemleri

### 1. **Application Layer Attacks (Layer 7)**

#### HTTP Flood
**Saldırı:** Login sayfasına saniyede binlerce istek gönderilir.

**Korunma:**

```pascal
// ServerModule.pas - Rate Limiting Implementation

type
  TIPRequestInfo = record
    IP: string;
    RequestCount: Integer;
    FirstRequestTime: TDateTime;
    BlockedUntil: TDateTime;
  end;

  TServerMod = class(TUniGUIServerModule)
  private
    FIPRequestList: TDictionary<string, TIPRequestInfo>;
    FRateLimitLock: TCriticalSection;

    function IsIPRateLimited(const IP: string): Boolean;
    procedure IncrementIPRequestCount(const IP: string);
    procedure CleanupOldRequests;
  end;

implementation

procedure TServerMod.UniGUIServerModuleCreate(Sender: TObject);
begin
  FIPRequestList := TDictionary<string, TIPRequestInfo>.Create;
  FRateLimitLock := TCriticalSection.Create;
end;

procedure TServerMod.UniGUIServerModuleDestroy(Sender: TObject);
begin
  FIPRequestList.Free;
  FRateLimitLock.Free;
end;

function TServerMod.IsIPRateLimited(const IP: string): Boolean;
var
  Info: TIPRequestInfo;
begin
  Result := False;

  FRateLimitLock.Enter;
  try
    // Önce eski kayıtları temizle
    CleanupOldRequests;

    if FIPRequestList.TryGetValue(IP, Info) then
    begin
      // IP bloklanmış mı?
      if Now < Info.BlockedUntil then
      begin
        Result := True;
        Logger.AddLog('RATE_LIMIT', 'Blocked IP: ' + IP);
        Exit;
      end;

      // Son 1 dakikadaki istek sayısını kontrol et
      if SecondsBetween(Now, Info.FirstRequestTime) <= 60 then
      begin
        // Dakikada 30'dan fazla istek → Rate limit
        if Info.RequestCount > 30 then
        begin
          Info.BlockedUntil := IncMinute(Now, 15); // 15 dakika blokla
          FIPRequestList.AddOrSetValue(IP, Info);
          Result := True;

          Logger.AddLog('RATE_LIMIT', Format('IP blocked for 15 min: %s (Requests: %d)',
            [IP, Info.RequestCount]));
        end;
      end
      else
      begin
        // Yeni zaman dilimi, sayacı sıfırla
        Info.FirstRequestTime := Now;
        Info.RequestCount := 0;
        FIPRequestList.AddOrSetValue(IP, Info);
      end;
    end;
  finally
    FRateLimitLock.Leave;
  end;
end;

procedure TServerMod.IncrementIPRequestCount(const IP: string);
var
  Info: TIPRequestInfo;
begin
  FRateLimitLock.Enter;
  try
    if FIPRequestList.TryGetValue(IP, Info) then
    begin
      Inc(Info.RequestCount);
      FIPRequestList.AddOrSetValue(IP, Info);
    end
    else
    begin
      Info.IP := IP;
      Info.RequestCount := 1;
      Info.FirstRequestTime := Now;
      Info.BlockedUntil := 0;
      FIPRequestList.Add(IP, Info);
    end;
  finally
    FRateLimitLock.Leave;
  end;
end;

procedure TServerMod.CleanupOldRequests;
var
  IP: string;
  Info: TIPRequestInfo;
  ToRemove: TList<string>;
begin
  ToRemove := TList<string>.Create;
  try
    for IP in FIPRequestList.Keys do
    begin
      Info := FIPRequestList[IP];

      // 5 dakikadan eski kayıtları sil
      if MinutesBetween(Now, Info.FirstRequestTime) > 5 then
      begin
        if Now > Info.BlockedUntil then // Blok süresi de bittiyse
          ToRemove.Add(IP);
      end;
    end;

    for IP in ToRemove do
      FIPRequestList.Remove(IP);
  finally
    ToRemove.Free;
  end;
end;

procedure TServerMod.UniGUIServerModuleHTTPCommand(ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo; var Handled: Boolean);
var
  ClientIP: string;
begin
  ClientIP := ARequestInfo.RemoteIP;

  // ✅ Rate limiting kontrolü
  if IsIPRateLimited(ClientIP) then
  begin
    AResponseInfo.ResponseNo := 429; // Too Many Requests
    AResponseInfo.ResponseText := 'Too Many Requests';
    AResponseInfo.ContentText := 'Rate limit exceeded. Please try again later.';
    AResponseInfo.ContentType := 'text/plain';

    // Retry-After header ekle
    AResponseInfo.CustomHeaders.AddValue('Retry-After', '900'); // 15 dakika

    Handled := True;
    Exit;
  end;

  // İstek sayısını artır
  IncrementIPRequestCount(ClientIP);

  // ... normal işlem devam eder
end;
```

---

### 2. **Slowloris Attack** (Yavaş HTTP İstekleri)

**Saldırı:** Bağlantıyı açık tutar, tüm thread'leri tüketir.

**Korunma:**

```pascal
// ServerModule.dfm içinde timeout ayarları:

object ServerMod: TServerMod
  // ...
  ServerLimits.ThreadPoolSize = 500
  ServerLimits.MaxSessions = 500
  ServerLimits.MaxRequests = 500
  SessionTimeout = 900000  // 15 dakika

  // ✅ Yeni eklenecek:
  ConnectionTimeout = 30000        // 30 saniye
  KeepAliveTimeout = 15000         // 15 saniye
  RequestTimeout = 60000           // 60 saniye max request süresi
end;

// Kod içinde:
procedure TServerMod.UniGUIServerModuleBeforeInit(Sender: TObject);
begin
  // Thread pool optimizasyonu
  ServerLimits.ThreadPoolSize := 200;    // CPU * 2 * cores
  ServerLimits.MaxSessions := 1000;      // Aynı anda max 1000 kullanıcı
  ServerLimits.MaxRequests := 2000;      // Queue'da max 2000 istek

  // Timeout'ları kısalt
  SessionTimeout := 900000;               // 15 dakika
  IdleConnectionTimeout := 30000;         // 30 saniye idle → disconnect
end;
```

---

### 3. **SYN Flood** (Network Layer Attack)

**Saldırı:** TCP SYN paketleri gönderilir, bağlantı tamamlanmaz.

**Korunma (OS Level):**

```batch
REM Windows Server - SYN Flood koruması
netsh int tcp set global netdma=disabled
netsh int tcp set global dca=enabled
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global congestionprovider=ctcp
netsh int tcp set global ecncapability=disabled
netsh int tcp set global timestamps=disabled

REM SYN Flood parametreleri
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpen /t REG_DWORD /d 500 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpenRetried /t REG_DWORD /d 400 /f
```

---

### 4. **DNS Amplification**

**Saldırı:** DNS sunucuları kullanılarak hedef sunucuya büyük miktarda trafik yönlendirilir.

**Korunma:**
- ✅ Cloudflare DNS kullan
- ✅ DNSSEC aktif et
- ✅ Rate limiting uygula

---

## 🔥 Firewall Kuralları (Windows Firewall)

```powershell
# Login sayfası için spesifik kurallar

# 1. Sadece 443 (HTTPS) portunabağlantıya izin ver
New-NetFirewallRule -DisplayName "KVKNET HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# 2. HTTP'yi HTTPS'e yönlendir (IIS/Nginx kullanıyorsanız)
New-NetFirewallRule -DisplayName "KVKNET HTTP Redirect" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow

# 3. Belirli IP'leri blokla (örnek)
New-NetFirewallRule -DisplayName "Block Malicious IP" -Direction Inbound -RemoteAddress 192.0.2.1 -Action Block

# 4. Rate limiting için connection limit
New-NetFirewallRule -DisplayName "KVKNET Connection Limit" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 443 `
    -Action Allow `
    -DynamicTarget Any `
    -EdgeTraversalPolicy Allow `
    -IcmpType Any

# 5. Geo-blocking (Türkiye dışından erişimi engelle)
# Bu için 3. parti bir çözüm gerekir (Cloudflare, MaxMind vb.)
```

---

## ☁️ Cloudflare Entegrasyonu (Önerilen)

### Neden Cloudflare?
- ✅ DDoS koruması (Layer 3, 4, 7)
- ✅ WAF (Web Application Firewall)
- ✅ Rate limiting
- ✅ Bot koruma
- ✅ CDN (hız artışı)
- ✅ SSL/TLS yönetimi

### Cloudflare Ayarları:

```javascript
// Cloudflare Page Rules (giris.kvknet.com.tr için)

1. Security Level: High
2. Cache Level: Bypass (login sayfası cache'lenmemeli)
3. Browser Integrity Check: On
4. Hotlink Protection: On
5. Always Use HTTPS: On

// Firewall Rules
Rule 1: Challenge Türkiye dışından gelen istekleri
  (ip.geoip.country ne "TR") → Challenge

Rule 2: Blokla yüksek riskli ülkelerden gelenleri
  (ip.geoip.country in {"CN" "RU" "KP"}) → Block

Rule 3: Rate limit - Login endpoint
  (http.request.uri.path contains "/login" and
   cf.threat_score gt 10 and
   rate(5m) > 30) → Block for 15 minutes

Rule 4: Known attack patterns
  (http.user_agent contains "sqlmap" or
   http.user_agent contains "nikto" or
   http.user_agent contains "nmap") → Block

Rule 5: SQL Injection patterns
  (http.request.uri.query contains "UNION SELECT" or
   http.request.uri.query contains "DROP TABLE") → Block
```

### Cloudflare WAF Rules:

```
// OWASP Core Ruleset aktif et
- SQL Injection
- XSS
- Local File Inclusion
- Remote Code Execution
- Session Fixation

// Custom Rules
- Login brute force detection
- CAPTCHA bypass attempts
- Session hijacking attempts
```

---

## 🖥️ IIS / Nginx Yapılandırması

### IIS (Windows Server):

```xml
<!-- web.config -->
<configuration>
  <system.webServer>
    <!-- Request Filtering -->
    <security>
      <requestFiltering>
        <requestLimits maxAllowedContentLength="10485760" /> <!-- 10 MB -->

        <filteringRules>
          <filteringRule name="BlockNullByte" scanUrl="true" scanQueryString="true">
            <scanHeaders>
              <clear />
            </scanHeaders>
            <denyStrings>
              <add string="%00" />
            </denyStrings>
          </filteringRule>

          <filteringRule name="BlockSQLInjection" scanUrl="true" scanQueryString="true">
            <denyStrings>
              <add string="UNION SELECT" />
              <add string="DROP TABLE" />
              <add string="INSERT INTO" />
              <add string="exec(" />
              <add string="javascript:" />
              <add string="&lt;script" />
            </denyStrings>
          </filteringRule>
        </filteringRules>
      </requestFiltering>

      <!-- IP Security -->
      <ipSecurity allowUnlisted="true">
        <!-- Bloke edilecek IP'ler -->
        <add ipAddress="192.0.2.1" allowed="false" />
        <add ipAddress="198.51.100.0" subnetMask="255.255.255.0" allowed="false" />

        <!-- Sadece Türkiye IP'lerine izin (opsiyonel) -->
        <!-- GeoIP database kullanarak yapılabilir -->
      </ipSecurity>
    </security>

    <!-- Dynamic IP Restrictions (DDoS koruması) -->
    <dynamicIpSecurity>
      <denyByConcurrentRequests enabled="true" maxConcurrentRequests="20" />
      <denyByRequestRate enabled="true" maxRequests="30" requestIntervalInMilliseconds="60000" />
    </dynamicIpSecurity>

    <!-- HTTP Headers -->
    <httpProtocol>
      <customHeaders>
        <remove name="X-Powered-By" />
        <add name="X-Frame-Options" value="DENY" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="X-XSS-Protection" value="1; mode=block" />
        <add name="Referrer-Policy" value="no-referrer" />
        <add name="Permissions-Policy" value="geolocation=(), microphone=(), camera=()" />
        <add name="Content-Security-Policy" value="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" />
      </customHeaders>
    </httpProtocol>

    <!-- Compression (Bandwidth tasarrufu) -->
    <httpCompression>
      <dynamicTypes>
        <add mimeType="text/*" enabled="true" />
        <add mimeType="application/javascript" enabled="true" />
        <add mimeType="application/json" enabled="true" />
      </dynamicTypes>
    </httpCompression>
  </system.webServer>

  <system.web>
    <!-- Connection timeout -->
    <httpRuntime executionTimeout="90" maxRequestLength="10240" />

    <!-- Session configuration -->
    <sessionState timeout="15" mode="InProc" cookieless="UseCookies" cookieSameSite="Strict" />
  </system.web>
</configuration>
```

### Nginx (Linux):

```nginx
# /etc/nginx/sites-available/kvknet

# Rate limiting zones
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/s;
limit_req_zone $binary_remote_addr zone=general_limit:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Geo-blocking (Türkiye dışı engelle)
geo $allow_country {
    default no;
    # Türkiye IP blokları
    include /etc/nginx/geo/turkey.conf;
}

server {
    listen 443 ssl http2;
    server_name giris.kvknet.com.tr;

    # SSL Configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Hide nginx version
    server_tokens off;

    # Geo-blocking
    if ($allow_country = no) {
        return 403 "Access denied from your country";
    }

    # Rate limiting
    location / {
        limit_req zone=general_limit burst=10 nodelay;
        limit_conn conn_limit 10;

        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeout ayarları
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Login endpoint için daha sıkı rate limit
    location ~* /(login|auth) {
        limit_req zone=login_limit burst=3 nodelay;

        # Failed login tracking için
        access_log /var/log/nginx/login_access.log;
        error_log /var/log/nginx/login_error.log;

        proxy_pass http://127.0.0.1:8888;
    }

    # Block common attack patterns
    location ~* (\.php|\.asp|\.aspx|\.jsp|\.cgi)$ {
        return 403;
    }

    # Block SQL injection attempts
    if ($query_string ~* "union.*select|insert.*into|drop.*table") {
        return 403;
    }

    # Block XSS attempts
    if ($query_string ~* "<script|javascript:|onerror=") {
        return 403;
    }

    # Block directory traversal
    if ($query_string ~* "\.\./|\.\.\\") {
        return 403;
    }
}

# HTTP'yi HTTPS'e yönlendir
server {
    listen 80;
    server_name giris.kvknet.com.tr;
    return 301 https://$server_name$request_uri;
}
```

---

## 📊 Monitoring ve Alerting

### Gerçek Zamanlı İzleme:

```pascal
// DDoS Attack Detection
procedure TServerMod.MonitorTraffic;
var
  RequestsPerSecond: Integer;
  AnomalyThreshold: Integer;
begin
  AnomalyThreshold := 100; // Saniyede 100'den fazla istek → anomali

  RequestsPerSecond := GetCurrentRequestsPerSecond;

  if RequestsPerSecond > AnomalyThreshold then
  begin
    // ✅ Alert gönder
    SendEmailAlert('DDoS Attack Detected',
      Format('Unusual traffic: %d requests/second', [RequestsPerSecond]));

    // ✅ SMS alert
    SendSMSAlert('+905XXXXXXXXX',
      Format('DDoS Alert: %d req/s', [RequestsPerSecond]));

    // ✅ Log kaydet
    Logger.AddLog('DDOS', Format('Possible DDoS attack: %d requests/second',
      [RequestsPerSecond]));

    // ✅ Otomatik koruma moduna geç
    ActivateEmergencyMode;
  end;
end;

procedure TServerMod.ActivateEmergencyMode;
begin
  // Tüm IP'ler için daha sıkı rate limit
  EmergencyMode := True;

  // CAPTCHA'yı her istekte zorunlu kıl
  ForceCaptchaForAll := True;

  // Yeni kayıt/hesap oluşturmayı geçici durdur
  AllowNewRegistrations := False;

  // Admin'leri bilgilendir
  NotifyAdministrators('Emergency mode activated due to DDoS attack');

  Logger.AddLog('DDOS', 'Emergency mode activated');
end;
```

### Grafana Dashboard:

```sql
-- Prometheus metrics için

-- İstek sayısı (son 5 dakika)
SELECT COUNT(*) as request_count
FROM http_requests
WHERE timestamp > NOW() - INTERVAL 5 MINUTE
GROUP BY FLOOR(UNIX_TIMESTAMP(timestamp) / 60)

-- Benzersiz IP sayısı
SELECT COUNT(DISTINCT ip_address) as unique_ips
FROM http_requests
WHERE timestamp > NOW() - INTERVAL 1 HOUR

-- Başarısız login denemeleri
SELECT ip_address, COUNT(*) as failed_attempts
FROM failed_logins
WHERE timestamp > NOW() - INTERVAL 15 MINUTE
GROUP BY ip_address
HAVING failed_attempts > 5
ORDER BY failed_attempts DESC

-- Bloke edilen IP'ler
SELECT ip_address, block_reason, blocked_until
FROM blocked_ips
WHERE blocked_until > NOW()
ORDER BY blocked_until DESC
```

---

## 🚨 Incident Response Plan

### DDoS Saldırısı Tespit Edildiğinde:

**Adım 1: Doğrulama** (0-5 dakika)
- [ ] Grafana/Prometheus dashboard'u kontrol et
- [ ] Server logs'ları incele
- [ ] Cloudflare analytics'i kontrol et
- [ ] Saldırı tipini belirle (Layer 3/4/7)

**Adım 2: Hızlı Müdahale** (5-15 dakika)
- [ ] Cloudflare "Under Attack Mode" aktif et
- [ ] Emergency mode'u aktive et (`ActivateEmergencyMode`)
- [ ] En çok istek gönderen IP'leri blokla
- [ ] Geo-blocking'i sıkılaştır

**Adım 3: İletişim** (15-30 dakika)
- [ ] İnternet servis sağlayıcıyı bilgilendir
- [ ] Cloudflare support'a ticket aç
- [ ] Yönetimi bilgilendir
- [ ] Kullanıcılara duyuru yap (eğer servis kesintisi varsa)

**Adım 4: Uzun Vadeli Düzeltme** (30+ dakika)
- [ ] Saldırı vektörünü analiz et
- [ ] Kalıcı firewall kuralları ekle
- [ ] Rate limiting parametrelerini güncelle
- [ ] Post-mortem raporu hazırla

---

## 📝 DDoS Koruması Checklist

### Uygulama Seviyesi:
- [x] Rate limiting implementasyonu
- [ ] CAPTCHA entegrasyonu (reCAPTCHA v3)
- [x] Session validation
- [ ] Request size limiting
- [ ] Timeout konfigürasyonu
- [ ] Connection pooling

### Network Seviyesi:
- [ ] Cloudflare/CDN kullanımı
- [ ] Firewall kuralları
- [ ] IPS/IDS sistemi
- [ ] Load balancer
- [ ] DDoS mitigation service

### Monitoring:
- [ ] Real-time traffic monitoring
- [ ] Anomaly detection
- [ ] Alert sistemi (email/SMS)
- [ ] Log agregasyonu (ELK Stack)
- [ ] Grafana dashboards

### Disaster Recovery:
- [ ] Backup sunucu hazır
- [ ] Failover planı
- [ ] Incident response dokümantasyonu
- [ ] İletişim planı
- [ ] Düzenli drill'ler

---

## 💰 Maliyet/Fayda Analizi

### Ücretsiz Çözümler:
- ✅ Cloudflare Free Plan (basic DDoS protection)
- ✅ Nginx rate limiting
- ✅ Windows Firewall
- ✅ Fail2Ban (Linux)

### Ücretli Çözümler:
- Cloudflare Pro/Business ($20-200/month)
- Akamai Kona Site Defender ($$$)
- AWS Shield Advanced ($$)
- Imperva Incapsula ($$)

### Önerilen Strateji (KVKNET için):
1. **Cloudflare Pro** ($20/month) → En iyi maliyet/fayda
2. **Nginx + ModSecurity WAF** → Ücretsiz, güçlü
3. **Custom rate limiting** → Kodda mevcut düzeltmeler
4. **Monitoring (Grafana + Prometheus)** → Ücretsiz

**Toplam Maliyet:** ~$20/month
**Koruduğu Değer:** Priceless (veri güvenliği, reputation, uptime)

---

## 📞 Acil Durum İletişim

**DDoS Saldırısı Tespit Edildiğinde:**
- 🔴 Security Team: security@kvknet.com.tr
- 📱 On-Call Engineer: +90 XXX XXX XX XX
- ☁️ Cloudflare Support: https://dash.cloudflare.com/support
- 🌐 ISP: [Türk Telekom/Superonline vb.]

**Escalation Path:**
1. Security Engineer (0-15 min)
2. IT Manager (15-30 min)
3. CTO (30+ min)
4. CEO (Major incident)
