# 🛡️ OWASP TOP 10 (2021) GÜVENLİK KONTROL LİSTESİ
## KVKNET Login Sayfası İçin

---

## ✅ A01:2021 – Broken Access Control (Erişim Kontrolü Zafiyetleri)

### 🔴 Tespit Edilen Sorunlar:
1. **Session Hijacking** - `_S_ID` parametresi manipüle edilebiliyor
2. **Yetersiz HTTP Response Kodları** - 401/403 dönülmüyor
3. **Session Validation Eksik** - Geçersiz session ID'ler için yeterli kontrol yok

### ✅ Düzeltme Adımları:
- [x] `SECURITY_FIX_SESSION.pas` dosyasındaki düzeltmeleri uygula
- [ ] Rate limiting ekle (IP bazlı)
- [ ] Session timeout kontrolü ekle
- [ ] Concurrent session kontrolü ekle (aynı kullanıcı birden fazla yerden giriş yapamaz)

### 📋 Test Senaryoları:
```
1. Burp Suite ile _S_ID parametresini değiştir
   - Beklenen: HTTP 403 döner
   - Test edilen: ❌ Sadece Exit çağrılıyor

2. Başka kullanıcının session ID'sini kullan
   - Beklenen: HTTP 403 ve log kaydı
   - Test edilen: ❌ İşleme devam ediyor

3. Expired session ID kullan
   - Beklenen: HTTP 401 ve yeniden login yönlendirme
   - Test edilen: ⚠️ Test edilmedi
```

---

## ✅ A02:2021 – Cryptographic Failures (Kriptografik Hatalar)

### 🔴 Tespit Edilen Sorunlar:
1. **SSL/TLS Konfigürasyonu** - Sadece TLSv1.2 var, TLSv1.3 yok
2. **Parola Hash Algoritması Belirsiz** - Kodda hash algoritması görünmüyor
3. **Hassas Veri İletimi** - Token'lar URL'de taşınıyor (güvenli değil)

### ✅ Düzeltme Önerileri:

```pascal
// ServerModule.pas içinde:
SSL.SSLOptions.Method := sslvTLSv1_2;
SSL.SSLOptions.SSLVersions := [sslvTLSv1_2, sslvTLSv1_3]; // ✅ TLS 1.3 ekle

// Cipher suite güçlendirmesi
SSL.SSLOptions.CipherList :=
  'TLS_AES_256_GCM_SHA384:' +
  'TLS_AES_128_GCM_SHA256:' +
  'TLS_CHACHA20_POLY1305_SHA256:' +
  'ECDHE-RSA-AES256-GCM-SHA384:' +
  'ECDHE-RSA-AES128-GCM-SHA256';
```

### 📋 Test Senaryoları:
```
1. SSL Labs Test (https://www.ssllabs.com/ssltest/)
   - Hedef: A+ Rating
   - Mevcut: ⚠️ Test edilmeli

2. Parola Hash Kontrolü
   - BCrypt/Argon2 kullanılıyor mu?
   - Salt kullanılıyor mu?
   - Hash cost factor yeterli mi? (min 12)

3. HSTS Kontrolü
   - Beklenen: max-age=31536000; includeSubDomains; preload
   - Mevcut: ✅ Var (ServerModule.pas:265)
```

---

## ✅ A03:2021 – Injection (Enjeksiyon Saldırıları)

### 🔴 Tespit Edilen Sorunlar:
1. **SQL Injection Riski** - Bazı sorgular parametre kullanmıyor olabilir
2. **LDAP Injection** - LDAP username kontrolü eksik
3. **Command Injection** - Shell komutları çalıştırılıyor mu kontrol edilmeli

### ✅ Düzeltme Adımları:
- [x] `SECURITY_FIX_SQL_INJECTION.pas` dosyasındaki düzeltmeleri uygula
- [ ] Tüm veritabanı sorgularını gözden geçir
- [ ] Parametreli sorgular kullanıldığından emin ol
- [ ] Input validation fonksiyonları ekle

### 📋 Test Senaryoları:
```sql
-- SQL Injection Test Payloads:
Kullanıcı Adı: admin' OR '1'='1
Kurum Kodu: TEST'; DROP TABLE usr_user; --
Parola: ' OR '1'='1' --

-- LDAP Injection Test:
LDAP Username: admin)(uid=*))(|(uid=*

-- Expected: Input validation reddeder
-- Mevcut: ⚠️ Test edilmeli
```

---

## ✅ A04:2021 – Insecure Design (Güvensiz Tasarım)

### 🔴 Tespit Edilen Sorunlar:
1. **Zayıf CAPTCHA** - Basit matematiksel işlem, bot'lar için kolay
2. **Brute Force Koruması Yok** - Sınırsız login denemesi
3. **Account Lockout Yok** - Başarısız girişler sonrası kilitleme yok

### ✅ Düzeltme Önerileri:

```pascal
// Güçlü CAPTCHA Implementasyonu
procedure TfrmLogin.CreateCaptcha;
begin
  // ❌ ESKİ: Basit matematik
  // ActiveCaptchaStr := '( 5 + 3 ) - 2 = ';

  // ✅ YENİ: reCAPTCHA v3 veya hCaptcha kullan
  // Alternatif: Görsel CAPTCHA (distorted text)

  // Geçici çözüm: Daha karmaşık matematik
  Randomize;
  var a := Random(20) + 10;
  var b := Random(20) + 10;
  var c := Random(10) + 1;
  var op1 := Random(2); // 0: +, 1: -
  var op2 := Random(2); // 0: *, 1: /

  if op1 = 0 then
    ActiveCaptchaInt := a + b
  else
    ActiveCaptchaInt := a - b;

  if op2 = 0 then
    ActiveCaptchaInt := ActiveCaptchaInt * c
  else
    ActiveCaptchaInt := ActiveCaptchaInt div c;

  ActiveCaptchaStr := Format('(%d %s %d) %s %d = ',
    [a, IfThen(op1 = 0, '+', '-'), b, IfThen(op2 = 0, '*', '/'), c]);
end;

// Brute Force Koruması
procedure TfrmLogin.btnOkClick(Sender: TObject);
begin
  // ✅ Rate limiting kontrolü
  if IsIPBlocked(GetClientIP) then
  begin
    MessageDlg('Çok fazla başarısız giriş denemesi. 30 dakika sonra tekrar deneyin.',
               mtError, [mbOk]);
    ModalResult := mrCancel;
    Exit;
  end;

  // ✅ Account lockout kontrolü
  if IsAccountLocked(edUserName.Text) then
  begin
    MessageDlg('Hesabınız güvenlik nedeniyle kilitlenmiştir. ' +
               'Lütfen sistem yöneticisi ile iletişime geçin.',
               mtError, [mbOk]);
    ModalResult := mrCancel;
    Exit;
  end;

  // ... normal login işlemi
end;
```

### 📋 Test Senaryoları:
```
1. CAPTCHA Bypass Testi
   - Bot ile 100 deneme yap
   - Beklenen: CAPTCHA engeller
   - Mevcut: ❌ Basit matematik kolayca çözülür

2. Brute Force Testi
   - Aynı IP'den 10 başarısız deneme
   - Beklenen: IP 30 dakika bloklanır
   - Mevcut: ❌ Sınırsız deneme

3. Account Enumeration
   - Rastgele kullanıcı adı dene
   - Beklenen: Genel hata mesajı
   - Mevcut: ⚠️ "Kullanıcı bulunamadı" vs "Parola hatalı" ayırt edilebiliyor mu?
```

---

## ✅ A05:2021 – Security Misconfiguration (Güvenlik Yanlış Yapılandırma)

### 🔴 Tespit Edilen Sorunlar:
1. **Debug Modu Production'da** - `{$IFDEF DEBUG}` SessionTimeout = 1200000
2. **Verbose Error Messages** - Hata mesajlarında detay var mı?
3. **Directory Listing** - `/files/` klasörü listelenebiliyor mu?
4. **Default Credentials** - Varsayılan admin hesabı var mı?

### ✅ Düzeltme Önerileri:

```pascal
// ServerModule.pas içinde:
procedure TServerMod.UniGUIServerModuleBeforeInit(Sender: TObject);
begin
  // ❌ ESKİ:
  {$IFDEF DEBUG}
    SessionTimeout := 1200000; // 20 dakika
  {$ENDIF}

  // ✅ YENİ: Production'da debug kodu olmamalı
  SessionTimeout := 900000; // 15 dakika (hem debug hem production)

  // ✅ Güvenlik ayarları
  SuppressErrors := [seEcho]; // Hata detaylarını gizle

  // ✅ File access kontrolü
  AllowWebMonitor := False; // Web monitor'u kapat
end;

// Generic error messages kullan
procedure TfrmLogin.ShowError(ErrorCode: Integer);
begin
  // ❌ KÖTÜ:
  // case ErrorCode of
  //   -1: MessageDlg('Kullanıcı bulunamadı', ...);
  //   -2: MessageDlg('Parola hatalı', ...);
  // end;

  // ✅ İYİ:
  case ErrorCode of
    -1..-10:
      MessageDlg('Giriş bilgileri hatalı. Lütfen kontrol ediniz.', mtError, [mbOk]);
    else
      MessageDlg('Bir hata oluştu. Lütfen daha sonra tekrar deneyiniz.', mtError, [mbOk]);
  end;

  // Detaylı hatayı sadece log'a yaz
  Logger.AddLog('LOGIN_ERROR', Format('Error code: %d, User: %s, IP: %s',
    [ErrorCode, edUserName.Text, GetClientIP]));
end;
```

### 📋 Test Senaryoları:
```
1. Error Message Analysis
   - Hatalı login yap
   - SQL hatası oluştur
   - Beklenen: Genel hata mesajı
   - Mevcut: ⚠️ Test edilmeli

2. Directory Listing
   - https://giris.kvknet.com.tr/files/ ziyaret et
   - Beklenen: 403 Forbidden
   - Mevcut: ⚠️ Test edilmeli

3. HTTP Headers
   - Server: header gizlenmiş mi?
   - X-Powered-By: header var mı?
   - Beklenen: Bu header'lar olmamalı
```

---

## ✅ A06:2021 – Vulnerable and Outdated Components (Zafiyet İçeren Bileşenler)

### 🔴 Tespit Edilen Sorunlar:
1. **UniGUI Version** - Hangi versiyon kullanılıyor?
2. **Indy Version** - IdHTTP, IdSSLOpenSSL güncel mi?
3. **OpenSSL Version** - Güvenlik yamalarınca güncel mi?

### ✅ Kontrol Edilecekler:
```pascal
// Version kontrolü
uses
  IdSSLOpenSSL;

procedure TServerMod.CheckVersions;
begin
  // OpenSSL version
  Logger.AddLog('INFO', 'OpenSSL Version: ' + OpenSSLVersion);

  // UniGUI version
  Logger.AddLog('INFO', 'UniGUI Version: ' + UniServerModule.Version);

  // Veritabanı driver version
  Logger.AddLog('INFO', 'DB Driver: ' + DBMain.LibraryLocation);
end;
```

### 📋 Güncel Tutulacak Bileşenler:
- [ ] UniGUI Framework (son stable version)
- [ ] Indy Components (10.6.3+)
- [ ] OpenSSL (3.0+)
- [ ] Delphi IDE (güvenlik yamaları)
- [ ] Windows Server (monthly updates)

---

## ✅ A07:2021 – Identification and Authentication Failures (Kimlik Doğrulama Hataları)

### 🔴 Tespit Edilen Sorunlar:
1. **Weak Password Policy** - Parola karmaşıklığı kontrolü yok
2. **No MFA Enforcement** - 2FA zorunlu değil
3. **Session Fixation** - Session ID değiştirilmiyor
4. **Credential Stuffing** - Yaygın parola listesi kontrolü yok

### ✅ Düzeltme Önerileri:

```pascal
// Parola Politikası
function TfrmLogin.ValidatePassword(const Password: string): Boolean;
var
  HasUpper, HasLower, HasDigit, HasSpecial: Boolean;
  I: Integer;
begin
  Result := False;

  // Minimum uzunluk: 8 karakter
  if Length(Password) < 8 then
  begin
    MessageDlg('Parola en az 8 karakter olmalıdır.', mtError, [mbOk]);
    Exit;
  end;

  // Maksimum uzunluk: 64 karakter (DoS koruması)
  if Length(Password) > 64 then
  begin
    MessageDlg('Parola en fazla 64 karakter olabilir.', mtError, [mbOk]);
    Exit;
  end;

  // Karakter çeşitliliği kontrolü
  HasUpper := False;
  HasLower := False;
  HasDigit := False;
  HasSpecial := False;

  for I := 1 to Length(Password) do
  begin
    if Password[I] in ['A'..'Z'] then HasUpper := True
    else if Password[I] in ['a'..'z'] then HasLower := True
    else if Password[I] in ['0'..'9'] then HasDigit := True
    else HasSpecial := True;
  end;

  if not (HasUpper and HasLower and HasDigit) then
  begin
    MessageDlg('Parola en az 1 büyük harf, 1 küçük harf ve 1 rakam içermelidir.',
               mtError, [mbOk]);
    Exit;
  end;

  // Yaygın parolalar listesi kontrolü
  if IsCommonPassword(Password) then
  begin
    MessageDlg('Bu parola çok yaygın kullanılıyor. Lütfen daha güçlü bir parola seçin.',
               mtError, [mbOk]);
    Exit;
  end;

  Result := True;
end;

// Session Fixation koruması
procedure TfrmLogin.btnOkClick(Sender: TObject);
begin
  // Login başarılı olduktan sonra yeni session ID oluştur
  if FID > 0 then
  begin
    // ✅ Eski session'ı invalidate et
    UniSession.Terminate;

    // ✅ Yeni session oluştur
    UniSession.SessionID := TGUID.NewGuid.ToString;

    // Cookie'yi güncelle
    UpdateSessionCookie(UniSession.SessionID);
  end;
end;
```

### 📋 Test Senaryoları:
```
1. Weak Password Test
   - Parola: 12345678
   - Beklenen: Reddedilir
   - Mevcut: ⚠️ Test edilmeli

2. Session Fixation
   - Önceden bilinen session ID ile login
   - Beklenen: Login sonrası yeni session ID
   - Mevcut: ❌ Session ID değişmiyor

3. Concurrent Login
   - Aynı kullanıcı 2 farklı yerden login
   - Beklenen: İlk session sonlandırılır
   - Mevcut: ⚠️ Test edilmeli
```

---

## ✅ A08:2021 – Software and Data Integrity Failures (Yazılım ve Veri Bütünlüğü)

### 🔴 Tespit Edilen Sorunlar:
1. **CDN Integrity** - jQuery CDN'den yükleniyor, SRI yok
2. **Code Signing** - Executable imzalı mı?
3. **Auto-Update** - Güncellemeler doğrulanıyor mu?

### ✅ Düzeltme Önerileri:

```pascal
// ServerModule.pas - CDN Integrity
CustomMeta.Add('<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js" ' +
               'integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK" ' +
               'crossorigin="anonymous"></script>');

// Veya daha iyi: Yerel kopyasını kullan
CustomMeta.Add('<script src="/files/js/jquery-3.6.0.min.js"></script>');
```

### 📋 Kontrol Edilecekler:
- [ ] Tüm external script'lerde SRI hash var mı?
- [ ] Executable Authenticode ile imzalı mı?
- [ ] Güncellemelerde dijital imza kontrolü var mı?

---

## ✅ A09:2021 – Security Logging and Monitoring Failures (Loglama Eksiklikleri)

### 🔴 Tespit Edilen Sorunlar:
1. **Incomplete Logging** - Bazı güvenlik olayları loglanmıyor
2. **No Alerting** - Anomali tespit ve alarm yok
3. **Log Protection** - Loglar şifrelenmiyor

### ✅ Düzeltme Önerileri:

```pascal
// Comprehensive Logging
procedure TMainMod.LogSecurityEvent(const EventType, EventDetail, IPAddress: string);
begin
  QueryPrep(qTmp,
    'INSERT INTO sec_audit_log ' +
    '(event_type, event_detail, ip_address, user_agent, timestamp, user_id) ' +
    'VALUES (:event_type, :event_detail, :ip_address, :user_agent, :timestamp, :user_id)'
  );

  qTmp.ParamByName('event_type').AsString := EventType;
  qTmp.ParamByName('event_detail').AsString := EventDetail;
  qTmp.ParamByName('ip_address').AsString := IPAddress;
  qTmp.ParamByName('user_agent').AsString := GetUserAgent;
  qTmp.ParamByName('timestamp').AsDateTime := Now;
  qTmp.ParamByName('user_id').AsInteger := IfThen(LoginInfo.ID > 0, LoginInfo.ID, 0);
  qTmp.ExecSQL;

  // Kritik olaylar için SIEM'e gönder
  if EventType in ['FAILED_LOGIN', 'SESSION_HIJACK', 'SQL_INJECTION', 'XSS_ATTEMPT'] then
    SendToSIEM(EventType, EventDetail, IPAddress);
end;

// Loglanması gereken olaylar:
// - Başarılı/başarısız login
// - Parola değişikliği
// - Session sonlandırma
// - Yetki değişiklikleri
// - SQL Injection denemeleri
// - XSS denemeleri
// - CSRF denemeleri
// - Rate limiting tetiklenmesi
// - Hesap kilitleme
// - 2FA bypass denemeleri
```

### 📋 Monitoring Checklist:
- [ ] Gerçek zamanlı anomali tespit
- [ ] Başarısız login sayısı izleme (threshold: 5/15 dakika)
- [ ] Aynı IP'den multiple account test
- [ ] SQL injection pattern detection
- [ ] XSS payload detection
- [ ] Günlük log analiz raporu

---

## ✅ A10:2021 – Server-Side Request Forgery (SSRF)

### 🔴 Test Edilecek Alanlar:
1. **SSO Integration** - Token endpoint'leri harici URL kullanıyor mu?
2. **LDAP Connection** - LDAP server URL'si kullanıcı tarafından kontrol ediliyor mu?
3. **File Upload** - URL'den dosya çekme özelliği var mı?

### ✅ Kontrol Kodları:

```pascal
// SSRF koruması - URL validation
function TMainMod.IsValidURL(const URL: string): Boolean;
var
  URI: TIdURI;
  AllowedHosts: TStringList;
begin
  Result := False;

  try
    URI := TIdURI.Create(URL);
    try
      // Sadece HTTPS'e izin ver
      if not SameText(URI.Protocol, 'https') then
        Exit;

      // Internal IP'lere izin verme (SSRF koruması)
      if IsInternalIP(URI.Host) then
      begin
        Logger.AddLog('SEC', 'SSRF attempt blocked: ' + URL);
        Exit;
      end;

      // Whitelist kontrolü
      AllowedHosts := TStringList.Create;
      try
        AllowedHosts.Add('login.uab.gov.tr');
        AllowedHosts.Add('sts4.sdu.edu.tr');
        AllowedHosts.Add('ubs.ikc.edu.tr');

        if AllowedHosts.IndexOf(URI.Host) < 0 then
        begin
          Logger.AddLog('SEC', 'Non-whitelisted host: ' + URI.Host);
          Exit;
        end;
      finally
        AllowedHosts.Free;
      end;

      Result := True;
    finally
      URI.Free;
    end;
  except
    on E: Exception do
      Logger.AddLog('ERROR', 'URL validation error: ' + E.Message);
  end;
end;

function TMainMod.IsInternalIP(const Host: string): Boolean;
begin
  Result :=
    StartsStr('127.', Host) or          // Loopback
    StartsStr('10.', Host) or           // Private Class A
    StartsStr('172.16.', Host) or       // Private Class B
    StartsStr('172.17.', Host) or
    // ... 172.18-31
    StartsStr('192.168.', Host) or      // Private Class C
    StartsStr('169.254.', Host) or      // Link-local
    SameText(Host, 'localhost') or
    SameText(Host, 'metadata.google.internal'); // Cloud metadata
end;
```

---

## 📊 Öncelik Sıralaması (Risk Bazlı)

### 🔴 KRİTİK (Hemen düzeltilmeli):
1. **Session Hijacking (_S_ID)** → `SECURITY_FIX_SESSION.pas`
2. **XSS Zafiyeti** → `SECURITY_FIX_XSS.pas`
3. **Zayıf CAPTCHA** → reCAPTCHA v3 implementasyonu

### 🟠 YÜKSEK (1 hafta içinde):
4. **Brute Force Koruması** → Rate limiting + account lockout
5. **SQL Injection** → `SECURITY_FIX_SQL_INJECTION.pas`
6. **Generic Error Messages** → User enumeration engelleme

### 🟡 ORTA (1 ay içinde):
7. **Password Policy** → Güçlü parola zorunluluğu
8. **TLS 1.3** → SSL/TLS güncellemesi
9. **Security Logging** → Kapsamlı audit logging

### 🟢 DÜŞÜK (Sürekli iyileştirme):
10. **Component Updates** → Bileşen güncellemeleri
11. **Code Signing** → Executable imzalama
12. **SIEM Integration** → Merkezi log yönetimi

---

## 🧪 Test Araçları

### Manuel Test:
- [ ] **Burp Suite** - _S_ID manipulation
- [ ] **OWASP ZAP** - Otomatik zafiyet taraması
- [ ] **SQLMap** - SQL injection testi
- [ ] **XSStrike** - XSS payload testi

### Otomatik Tarama:
- [ ] **Nessus** - Zafiyet taraması
- [ ] **Acunetix** - Web uygulama güvenlik taraması
- [ ] **SonarQube** - Statik kod analizi
- [ ] **Snyk** - Bağımlılık güvenlik kontrolü

### Performans/DDoS:
- [ ] **Apache JMeter** - Load testing
- [ ] **Cloudflare** - DDoS koruması
- [ ] **ModSecurity** - WAF kuralları

---

## 📝 SonarQube Konfigürasyonu

```xml
<!-- sonar-project.properties -->
sonar.projectKey=kvknet-login
sonar.projectName=KVKNET Login Page
sonar.sources=.
sonar.language=delphi

# Güvenlik Kuralları
sonar.delphi.security.enabled=true
sonar.delphi.security.sqli=true
sonar.delphi.security.xss=true
sonar.delphi.security.csrf=true

# Code Quality
sonar.delphi.coverage.enabled=true
sonar.delphi.cpd.enabled=true

# Hotspots
sonar.security.hotspots.severity=HIGH
```

---

## ✅ Uygulama Adımları

1. **Acil Düzeltmeler (Bugün):**
   ```bash
   # Session hijacking düzeltmesi
   cp SECURITY_FIX_SESSION.pas ServerModule.pas

   # XSS koruması
   cp SECURITY_FIX_XSS.pas unLogin.pas

   # Compile ve test
   dcc32 KVKNET.dpr
   ```

2. **Kısa Vadeli (Bu Hafta):**
   - Rate limiting implementasyonu
   - SQL injection düzeltmeleri
   - Brute force koruması

3. **Orta Vadeli (Bu Ay):**
   - Password policy
   - 2FA enforcement
   - Comprehensive logging

4. **Uzun Vadeli (Sürekli):**
   - Security training
   - Penetration testing (yıllık)
   - Bug bounty programı

---

## 📞 Destek ve Raporlama

**Güvenlik Açığı Bulursanız:**
- ❌ Public disclosure yapmayın
- ✅ Güvenlik ekibine bildirin
- ✅ Responsible disclosure yapın

**Acil Durum İletişim:**
- Security Team: security@kvknet.com.tr
- Incident Response: +90 XXX XXX XX XX
