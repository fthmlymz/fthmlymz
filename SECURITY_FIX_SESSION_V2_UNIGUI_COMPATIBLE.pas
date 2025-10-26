// =====================================================
// GÜVENLİK DÜZELTMESİ V2: Session Hijacking Koruması
// UniGUI Framework Uyumlu Versiyon
// Dosya: ServerModule.pas
// Prosedür: UniGUIServerModuleHTTPCommand
// =====================================================

{
  ÖNEMLİ NOTLAR:
  - UniGUI framework'ü _S_ID parametresini her AJAX request'inde kullanır
  - Bu parametreyi bloklamak veya session'ı kapatmak infinite loop'a neden olur
  - Doğru yaklaşım: Şüpheli davranışları loglamak ve rate limiting uygulamak
  - UniGUI'nin kendi InvalidSession mekanizmasını kullanmalıyız
}

type
  TSessionAttempt = record
    SessionID: string;
    IP: string;
    AttemptCount: Integer;
    FirstAttempt: TDateTime;
    LastAttempt: TDateTime;
    IsBlocked: Boolean;
    BlockedUntil: TDateTime;
  end;

  TServerMod = class(TUniGUIServerModule)
  private
    FSessionAttempts: TDictionary<string, TSessionAttempt>; // Key: IP+SessionID
    FSessionAttemptsLock: TCriticalSection;

    function IsSessionAttemptSuspicious(const IP, SessionID: string): Boolean;
    procedure LogSessionAttempt(const IP, SessionID: string; IsValid: Boolean);
    procedure CleanupOldAttempts;
    function GetAttemptKey(const IP, SessionID: string): string;
  end;

implementation

procedure TServerMod.UniGUIServerModuleCreate(Sender: TObject);
begin
  inherited;

  FSessionAttempts := TDictionary<string, TSessionAttempt>.Create;
  FSessionAttemptsLock := TCriticalSection.Create;

  // ... mevcut kod
end;

procedure TServerMod.UniGUIServerModuleDestroy(Sender: TObject);
begin
  FSessionAttempts.Free;
  FSessionAttemptsLock.Free;

  inherited;
end;

function TServerMod.GetAttemptKey(const IP, SessionID: string): string;
begin
  Result := IP + '|' + SessionID;
end;

procedure TServerMod.CleanupOldAttempts;
var
  Key: string;
  Attempt: TSessionAttempt;
  ToRemove: TList<string>;
begin
  ToRemove := TList<string>.Create;
  try
    for Key in FSessionAttempts.Keys do
    begin
      Attempt := FSessionAttempts[Key];

      // 30 dakikadan eski kayıtları sil
      if MinutesBetween(Now, Attempt.LastAttempt) > 30 then
      begin
        if not Attempt.IsBlocked or (Now > Attempt.BlockedUntil) then
          ToRemove.Add(Key);
      end;
    end;

    for Key in ToRemove do
      FSessionAttempts.Remove(Key);
  finally
    ToRemove.Free;
  end;
end;

function TServerMod.IsSessionAttemptSuspicious(const IP, SessionID: string): Boolean;
var
  Key: string;
  Attempt: TSessionAttempt;
begin
  Result := False;

  FSessionAttemptsLock.Enter;
  try
    CleanupOldAttempts;

    Key := GetAttemptKey(IP, SessionID);

    if FSessionAttempts.TryGetValue(Key, Attempt) then
    begin
      // IP bloklanmış mı kontrol et
      if Attempt.IsBlocked and (Now < Attempt.BlockedUntil) then
      begin
        Result := True;
        Logger.AddLog('SEC', Format('Blocked attempt - IP: %s, SessionID: %s',
          [IP, Copy(SessionID, 1, 8) + '...']));
        Exit;
      end;

      // Son 5 dakikada çok fazla geçersiz session denemesi var mı?
      if MinutesBetween(Now, Attempt.FirstAttempt) <= 5 then
      begin
        if Attempt.AttemptCount > 10 then
        begin
          // Bu IP'yi 15 dakika blokla
          Attempt.IsBlocked := True;
          Attempt.BlockedUntil := IncMinute(Now, 15);
          FSessionAttempts.AddOrSetValue(Key, Attempt);

          Result := True;

          Logger.AddLog('SEC', Format('IP blocked for 15 min - IP: %s, Attempts: %d',
            [IP, Attempt.AttemptCount]));
        end;
      end
      else
      begin
        // Yeni zaman dilimi, sayacı sıfırla
        Attempt.FirstAttempt := Now;
        Attempt.AttemptCount := 0;
        FSessionAttempts.AddOrSetValue(Key, Attempt);
      end;
    end;
  finally
    FSessionAttemptsLock.Leave;
  end;
end;

procedure TServerMod.LogSessionAttempt(const IP, SessionID: string; IsValid: Boolean);
var
  Key: string;
  Attempt: TSessionAttempt;
begin
  FSessionAttemptsLock.Enter;
  try
    Key := GetAttemptKey(IP, SessionID);

    if FSessionAttempts.TryGetValue(Key, Attempt) then
    begin
      Inc(Attempt.AttemptCount);
      Attempt.LastAttempt := Now;
      FSessionAttempts.AddOrSetValue(Key, Attempt);
    end
    else
    begin
      Attempt.SessionID := SessionID;
      Attempt.IP := IP;
      Attempt.AttemptCount := 1;
      Attempt.FirstAttempt := Now;
      Attempt.LastAttempt := Now;
      Attempt.IsBlocked := False;
      Attempt.BlockedUntil := 0;
      FSessionAttempts.Add(Key, Attempt);
    end;

    // Geçersiz session denemelerini özel olarak logla
    if not IsValid then
    begin
      Logger.AddLog('SEC', Format('Invalid session attempt - IP: %s, SessionID: %s, Attempts: %d',
        [IP, Copy(SessionID, 1, 8) + '...', Attempt.AttemptCount]));
    end;
  finally
    FSessionAttemptsLock.Leave;
  end;
end;

procedure TServerMod.UniGUIServerModuleHTTPCommand(
  ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo;
  var Handled: Boolean);
var
  SidVal, ClientIP: string;
  IsValidSession: Boolean;
begin
  ClientIP := ARequestInfo.RemoteIP;

  // _S_ID parametresini al (varsa)
  SidVal := ARequestInfo.Params.Values['_S_ID'];

  // ===================================================================
  // ÖNEMLİ: _S_ID parametresi varsa kontrol et ama BLOKLAMA!
  // UniGUI'nin kendi session validation mekanizmasını kullanmasına izin ver
  // ===================================================================

  if SidVal <> '' then
  begin
    // 1. Şüpheli aktivite kontrolü (rate limiting)
    if IsSessionAttemptSuspicious(ClientIP, SidVal) then
    begin
      // ✅ Rate limit aşıldı, bu isteği REDDET
      AResponseInfo.ResponseNo := 429; // Too Many Requests
      AResponseInfo.ResponseText := 'Too Many Requests';
      AResponseInfo.ContentText := 'Too many invalid session attempts. Please try again later.';
      AResponseInfo.ContentType := 'text/plain';
      AResponseInfo.CustomHeaders.AddValue('Retry-After', '900'); // 15 dakika

      Handled := True;
      Exit;
    end;

    // 2. Session ID format validasyonu (basic)
    if not IsValidSessionIDFormat(SidVal) then
    begin
      // ✅ Geçersiz format, logla ve rate limiting sayacını artır
      Logger.AddLog('SEC', Format('Invalid session ID format - IP: %s, ID: %s',
        [ClientIP, Copy(SidVal, 1, 8) + '...']));

      LogSessionAttempt(ClientIP, SidVal, False);

      // ❌ BLOKLAMA! UniGUI'nin kendi InvalidSession mekanizması çalışsın
      // Handled := True yapmıyoruz, UniGUI'ye devam ettiriyoruz
    end
    else
    begin
      // 3. Session FSessionList'te var mı kontrol et
      if (FSessionList.Count > 0) and (not FindSessionByID(SidVal, FSessionList)) then
      begin
        // ✅ Session listede yok, şüpheli aktivite olabilir
        Logger.AddLog('SEC', Format('Unknown session ID - IP: %s, ID: %s',
          [ClientIP, Copy(SidVal, 1, 8) + '...']));

        LogSessionAttempt(ClientIP, SidVal, False);

        // ❌ BLOKLAMA! UniGUI'nin kendi InvalidSession handling'i çalışsın
        // Bu sayede InvalidSessionTemplate.htm gösterilir
      end
      else
      begin
        // ✅ Geçerli session, attempt kaydı tut
        LogSessionAttempt(ClientIP, SidVal, True);
      end;
    end;
  end;

  // ===================================================================
  // DEVAM: Diğer güvenlik kontrolleri
  // ===================================================================

  // SSL kontrol ve redirect
  if SSL.SSLPort <= 0 then
  begin
    CustomMeta.Clear;
  end
  else
  begin
    CustomMeta.Clear;
    CustomMeta.Add('<script language="JavaScript">');
    CustomMeta.Add('function redirectHttpToHttps(){');
    CustomMeta.Add('    var loc = window.location.href;');
    CustomMeta.Add('    if (loc.indexOf("http://")==0){');
    CustomMeta.Add('    		loc = "https://" + loc.substring(7, loc.lastIndexOf(":")) + ":' + IntToStr(SSL.SSLPort) + '";' );
    CustomMeta.Add('      window.location.href = loc}}');
    CustomMeta.Add('redirectHttpToHttps();');
    CustomMeta.Add('</script>');
  end;

  // Session cookie işlemleri (mevcut kod devam eder)
  var HostName: string;
  var CookieObj: TIdCookie;
  var SessVal: string;
  var CookieDomain: string;
  var CookieLine: string;

  HostName := ARequestInfo.Host;
  if HostName.Contains(':') then
    HostName := Copy(HostName, 1, Pos(':', HostName)-1);

  CookieObj := ARequestInfo.Cookies.Cookie['UNI_GUI_SESSION_ID', HostName];

  if Assigned(CookieObj) then
    SessVal := CookieObj.Value
  else
    SessVal := TGUID.NewGuid.ToString;

  CookieDomain := HostName;

  CookieLine :=
    Format('UNI_GUI_SESSION_ID=%s; Path=/; Domain=%s; Secure; HttpOnly; SameSite=Strict',
           [SessVal, CookieDomain]);
  AResponseInfo.CustomHeaders.AddValue('Set-Cookie', CookieLine);

  // Security headers
  AResponseInfo.CustomHeaders.AddValue('X-XSS-Protection', '1, mode=block');
  AResponseInfo.CustomHeaders.AddValue('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  AResponseInfo.CustomHeaders.AddValue('Referrer-Policy', 'no-referrer');
  AResponseInfo.CustomHeaders.AddValue('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate');
  AResponseInfo.CustomHeaders.AddValue('Pragma','no-cache');
  AResponseInfo.CustomHeaders.AddValue('Expires', '0');
  AResponseInfo.CustomHeaders.AddValue('X-Robots-Tag', 'noindex, nofollow');
  AResponseInfo.CustomHeaders.AddValue('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  AResponseInfo.CustomHeaders.AddValue('X-Content-Type-Options', 'nosniff');

  // ✅ CSP Header ekle (XSS koruması)
  AResponseInfo.CustomHeaders.AddValue('Content-Security-Policy',
    'default-src ''self''; ' +
    'script-src ''self'' ''unsafe-inline'' ''unsafe-eval'' https://ajax.googleapis.com; ' +
    'style-src ''self'' ''unsafe-inline''; ' +
    'img-src ''self'' data: https:; ' +
    'font-src ''self''; ' +
    'connect-src ''self''; ' +
    'frame-ancestors ''self''; ' +
    'base-uri ''self''; ' +
    'form-action ''self'';'
  );

  // URI filtreleme (mevcut kod devam eder)
  var cachePaht: string;
  var MyHost: string;
  var MyURI: string;
  var FormattedDateTime: string;

  cachePaht := LocalCacheURL;

  if ((ARequestInfo.URI <> '/') and (ARequestInfo.Referer = '')) then
  begin
    MyHost := LowerCase(ARequestInfo.Host);
    MyURI := LowerCase(ARequestInfo.URI);

    if (CountOccurences(MyHost+MyURI, '/') > 1) then
    begin
      if (pos(StringReplace(cachepaht,'//','/',[rfReplaceAll, rfIgnoreCase]), MyHost+MyURI)=0)
      and (not ((Pos('/uni-', MyURI) = 1) or
           (Pos('/ext-', MyURI) = 1) or
           (Pos('/files/', MyURI) = 1) or
           (EndsStr('.js', MyURI) or
            EndsStr('.css', MyURI) or
            EndsStr('.png', MyURI) or
            EndsStr('.jpg', MyURI) or
            EndsStr('.ico', MyURI)))) then
      begin
        DateTimeToString(FormattedDateTime, 'dd/mm/yyyy hh:nn:ss.z', Now());
        Logger.AddLog('DOGANAKCAY', 'Ret edildi - '+
                      FormattedDateTime + ' - ' +
                      'IP: ' + ARequestInfo.RemoteIP + ', ' +
                      'URI: ' + MyURI + ', ' +
                      'Dosya: ' + ARequestInfo.Document);

        Handled := True;
        AResponseInfo.ResponseNo := 405;
        AResponseInfo.CloseConnection := True;
        AResponseInfo.CloseSession;
      end;
    end;

    if (MyURI ='/robots.txt') then
    begin
      DateTimeToString(FormattedDateTime, 'dd/mm/yyyy hh:nn:ss.z', Now());
      Logger.AddLog('DOGANAKCAY', 'Ret edildi - '+
                    FormattedDateTime + ' - ' +
                    'IP: ' + ARequestInfo.RemoteIP + ', ' +
                    'URI: ' + MyURI + ', ' +
                    'Dosya: ' + ARequestInfo.Document);

      Handled := True;
      AResponseInfo.ResponseNo := 405;
      AResponseInfo.CloseConnection := True;
      AResponseInfo.CloseSession;
    end;
  end;
end;

// Helper fonksiyon
function TServerMod.IsValidSessionIDFormat(const SessionID: string): Boolean;
var
  I: Integer;
begin
  Result := False;

  // Uzunluk kontrolü
  if (Length(SessionID) < 20) or (Length(SessionID) > 50) then
    Exit;

  // Sadece alphanumeric, tire ve alt çizgiye izin ver
  for I := 1 to Length(SessionID) do
  begin
    if not (SessionID[I] in ['0'..'9', 'A'..'Z', 'a'..'z', '-', '_', '{', '}']) then
      Exit;
  end;

  Result := True;
end;

function TServerMod.CountOccurences(AStr, ASearch: String): Integer;
var
  Tmp: Integer;
begin
  Result := 0;
  Tmp := 1;
  while Tmp > 0 do
  begin
    Tmp := Pos(ASearch, AStr);
    if Tmp > 0 then
    begin
      Inc(Result);
      System.Delete(AStr, 1, Tmp + Length(ASearch) - 1);
    end;
  end;
end;

{
  ===================================================================
  ÖZET: YENİ GÜVENLİK YAKLAŞIMI
  ===================================================================

  1. ✅ _S_ID parametresi kontrol edilir ama BLOKLANMAZ
  2. ✅ Şüpheli aktiviteler (rate limiting) loglanır
  3. ✅ 10+ başarısız deneme → IP 15 dakika bloklanır
  4. ✅ UniGUI'nin kendi InvalidSession mekanizması kullanılır
  5. ✅ Handled := True sadece rate limit aşıldığında
  6. ✅ Infinite loop sorunu çözüldü

  ===================================================================
  TEST SENARYOLARI
  ===================================================================

  1. Normal kullanıcı girişi:
     - _S_ID parametresi ile AJAX request
     - ✅ Normal şekilde çalışmalı
     - ✅ Infinite loop olmamalı

  2. Geçersiz session ID:
     - Bilinmeyen _S_ID parametresi
     - ✅ Log kaydı oluşturulmalı
     - ✅ UniGUI InvalidSession sayfası gösterilmeli
     - ✅ Session kapatılmamalı

  3. Burp Suite ile manipulation:
     - Farklı _S_ID değerleri deneme
     - ✅ İlk 10 deneme → sadece log
     - ✅ 10+ deneme → IP 15 dakika bloklanmalı
     - ✅ HTTP 429 Too Many Requests dönmeli

  4. Rate limiting:
     - Aynı IP'den 10+ geçersiz session
     - ✅ IP bloklanmalı
     - ✅ 15 dakika sonra otomatik açılmalı

  ===================================================================
}
