// =====================================================
// GÜVENLİK DÜZELTMESİ: Session Hijacking Koruması
// Dosya: ServerModule.pas
// Prosedür: UniGUIServerModuleHTTPCommand
// =====================================================

procedure TServerMod.UniGUIServerModuleHTTPCommand(ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo; var Handled: Boolean);
var
  SessVal, HostName, CookieDomain, CookieLine: string;
  SidVal: string;
  // ... diğer değişkenler
begin
  // _S_ID Parametresi Kontrolü - GÜVENLİK İYİLEŞTİRMESİ
  SidVal := ARequestInfo.Params.Values['_S_ID'];

  if SidVal <> '' then
  begin
    // XSS Koruması: _S_ID parametresini sanitize et
    SidVal := Trim(SidVal);

    // Sadece alphanumeric ve tire karakterlerine izin ver
    if not IsValidSessionID(SidVal) then
    begin
      Logger.AddLog('SEC', 'Invalid _S_ID format: ' + SidVal + ' from ' + ARequestInfo.RemoteIP);

      // ✅ HTTP 401 Unauthorized response döndür
      AResponseInfo.ResponseNo := 401;
      AResponseInfo.ResponseText := 'Unauthorized';
      AResponseInfo.ContentText := 'Invalid session identifier';
      AResponseInfo.ContentType := 'text/plain';

      // Rate limiting için IP'yi kaydet
      LogFailedSessionAttempt(ARequestInfo.RemoteIP);

      Handled := True;
      Exit;
    end;

    if (FSessionList.Count > 0) and (not FindSessionByID(SidVal, FSessionList)) then
    begin
      Logger.AddLog('SEC', 'Forged or unknown _S_ID: ' + SidVal + ' from ' + ARequestInfo.RemoteIP);

      // ✅ HTTP 403 Forbidden response döndür
      AResponseInfo.ResponseNo := 403;
      AResponseInfo.ResponseText := 'Forbidden';
      AResponseInfo.ContentText := 'Session not found or expired';
      AResponseInfo.ContentType := 'text/plain';

      // Rate limiting için IP'yi kaydet
      LogFailedSessionAttempt(ARequestInfo.RemoteIP);

      Handled := True;
      Exit;
    end;
  end;

  // SSL kontrol ve redirect...
  // ... kodun geri kalanı
end;

// Yardımcı fonksiyonlar
function TServerMod.IsValidSessionID(const SessionID: string): Boolean;
var
  I: Integer;
begin
  Result := False;

  // Uzunluk kontrolü (GUID formatı: 36 karakter)
  if (Length(SessionID) < 32) or (Length(SessionID) > 40) then
    Exit;

  // Sadece alphanumeric ve tire karakterlerine izin ver
  for I := 1 to Length(SessionID) do
  begin
    if not (SessionID[I] in ['0'..'9', 'A'..'Z', 'a'..'z', '-']) then
      Exit;
  end;

  Result := True;
end;

procedure TServerMod.LogFailedSessionAttempt(const IPAddress: string);
begin
  // Rate limiting için başarısız denemeleri logla
  // Bu bilgiyi kullanarak IP bazlı rate limiting yapılabilir

  // Örnek: Redis veya veritabanında sayacı artır
  // IF failed_attempts[IP] > 10 THEN block_for_30_minutes
end;
