// =====================================================
// GÜVENLİK DÜZELTMESİ: SQL Injection Koruması
// Dosya: unLogin.pas
// =====================================================

// ❌ RİSKLİ KOD ÖRNEKLERİ (kodda bulunabilir):
{
// ASLA BÖYLE YAPMAYIN:
Query.SQL.Text := 'SELECT * FROM usr_user WHERE username = ''' + edUserName.Text + '''';

// veya
QueryOpen(mainmod.qTmp, 'SELECT phone FROM usr_user WHERE id=' + IntToStr(MainMod.LoginInfo.ID));
}

// ✅ GÜVENLİ KOD - PARAMETRELİ SORGULAR:

procedure TfrmLogin.CheckUserLogin;
begin
  // ✅ DOĞRU YÖNTEM: Parametreli sorgular kullan
  QueryPrep(MainMod.qTmp,
    'SELECT u.id, u.username, u.password_hash, u.is_active, u.phone ' +
    'FROM usr_user u ' +
    'JOIN sys_mcdef mc ON mc.id = u.mc_id ' +
    'WHERE mc.code = :kurum_kodu ' +
    'AND UPPER(u.username) = UPPER(:kullanici_adi) ' +
    'AND u.is_active = :aktif'
  );

  // Parametreleri güvenli şekilde set et
  MainMod.qTmp.ParamByName('kurum_kodu').AsString := Trim(edCompCode.Text);
  MainMod.qTmp.ParamByName('kullanici_adi').AsString := Trim(edUserName.Text);
  MainMod.qTmp.ParamByName('aktif').AsString := 'E';

  MainMod.qTmp.Open;

  if MainMod.qTmp.IsEmpty then
  begin
    // Kullanıcı bulunamadı
    Exit;
  end;

  // Parola kontrolü (hash ile)
  if not VerifyPassword(edUserPwd.Text, MainMod.qTmp.FieldByName('password_hash').AsString) then
  begin
    // Hatalı parola
    Exit;
  end;
end;

// ✅ Input Validation - Ekstra Güvenlik Katmanı
function TfrmLogin.ValidateKurumKodu(const KurumKodu: string): Boolean;
var
  I: Integer;
begin
  Result := False;

  // Boş olamaz
  if Trim(KurumKodu) = '' then
    Exit;

  // Maksimum uzunluk kontrolü
  if Length(KurumKodu) > 10 then
    Exit;

  // Sadece alphanumeric karakterlere izin ver
  for I := 1 to Length(KurumKodu) do
  begin
    if not (KurumKodu[I] in ['0'..'9', 'A'..'Z', 'a'..'z']) then
      Exit;
  end;

  Result := True;
end;

function TfrmLogin.ValidateKullaniciAdi(const KullaniciAdi: string): Boolean;
var
  I: Integer;
begin
  Result := False;

  // Boş olamaz
  if Trim(KullaniciAdi) = '' then
    Exit;

  // Uzunluk kontrolü
  if (Length(KullaniciAdi) < 3) or (Length(KullaniciAdi) > 50) then
    Exit;

  // Sadece alphanumeric, nokta ve alt çizgiye izin ver
  for I := 1 to Length(KullaniciAdi) do
  begin
    if not (KullaniciAdi[I] in ['0'..'9', 'A'..'Z', 'a'..'z', '.', '_']) then
      Exit;
  end;

  Result := True;
end;

// ✅ OWASP önerileri: Parola Hash'leme
function TfrmLogin.HashPassword(const Password: string): string;
begin
  // BCrypt, Argon2 veya PBKDF2 kullanın
  // Örnek: BCrypt ile hash
  Result := TBCrypt.HashPassword(Password);
end;

function TfrmLogin.VerifyPassword(const Password, Hash: string): Boolean;
begin
  // Hash doğrulama
  Result := TBCrypt.VerifyPassword(Password, Hash);
end;

// =====================================================
// MainModule.pas'ta Login Fonksiyonu İyileştirmesi
// =====================================================

function TMainMod.CheckLogin(const CompCode, UserName, Password: string;
  LDAPType: tLDAPType; LDAPActive: Boolean): Integer;
begin
  Result := -1;

  // ✅ Input validation
  if not ValidateCompCode(CompCode) then
  begin
    Result := -1; // Hatalı kurum kodu
    Exit;
  end;

  if not ValidateUserName(UserName) then
  begin
    Result := -4; // Hatalı kullanıcı adı
    Exit;
  end;

  if Trim(Password) = '' then
  begin
    Result := -6; // Parola boş
    Exit;
  end;

  // ✅ Parametreli sorgu ile veri çek
  try
    QueryPrep(qTmp,
      'SELECT u.id, u.username, u.password_hash, u.is_active, u.mc_id, ' +
      '       mc.code as mc_code, mc.is_active as mc_active ' +
      'FROM usr_user u ' +
      'JOIN sys_mcdef mc ON mc.id = u.mc_id ' +
      'WHERE mc.code = :comp_code ' +
      'AND UPPER(u.username) = UPPER(:username)'
    );

    qTmp.ParamByName('comp_code').AsString := CompCode;
    qTmp.ParamByName('username').AsString := UserName;
    qTmp.Open;

    if qTmp.IsEmpty then
    begin
      Result := -4; // Kullanıcı bulunamadı
      // Failed login attempt logla
      LogFailedLogin(CompCode, UserName, GetClientIP);
      Exit;
    end;

    // Kurum aktif mi?
    if qTmp.FieldByName('mc_active').AsString <> 'E' then
    begin
      Result := -2;
      Exit;
    end;

    // Kullanıcı aktif mi?
    if qTmp.FieldByName('is_active').AsString <> 'E' then
    begin
      Result := -5;
      Exit;
    end;

    // ✅ Parola hash kontrolü
    if not VerifyPasswordHash(Password, qTmp.FieldByName('password_hash').AsString) then
    begin
      Result := -6;
      // Failed login attempt logla
      LogFailedLogin(CompCode, UserName, GetClientIP);
      Exit;
    end;

    // Başarılı login
    Result := qTmp.FieldByName('id').AsInteger;
    LogSuccessfulLogin(CompCode, UserName, GetClientIP);

  except
    on E: Exception do
    begin
      // Hata logla ama kullanıcıya detay verme
      Logger.AddLog('ERROR', 'Login error: ' + E.Message);
      Result := -999; // Genel hata
    end;
  end;
end;

// Failed login sayısını takip et (Brute Force koruması)
procedure TMainMod.LogFailedLogin(const CompCode, UserName, IPAddress: string);
begin
  // Veritabanına veya Redis'e başarısız giriş kaydı yaz
  // Eğer son 15 dakikada 5'ten fazla başarısız giriş varsa, hesabı kilitle

  QueryPrep(qTmp,
    'INSERT INTO usr_failed_logins (comp_code, username, ip_address, attempt_time) ' +
    'VALUES (:comp_code, :username, :ip_address, :attempt_time)'
  );

  qTmp.ParamByName('comp_code').AsString := CompCode;
  qTmp.ParamByName('username').AsString := UserName;
  qTmp.ParamByName('ip_address').AsString := IPAddress;
  qTmp.ParamByName('attempt_time').AsDateTime := Now;
  qTmp.ExecSQL;

  // Son 15 dakikada kaç başarısız deneme var?
  QueryPrep(qTmp,
    'SELECT COUNT(*) as attempt_count ' +
    'FROM usr_failed_logins ' +
    'WHERE username = :username ' +
    'AND ip_address = :ip_address ' +
    'AND attempt_time > :time_threshold'
  );

  qTmp.ParamByName('username').AsString := UserName;
  qTmp.ParamByName('ip_address').AsString := IPAddress;
  qTmp.ParamByName('time_threshold').AsDateTime := IncMinute(Now, -15);
  qTmp.Open;

  if qTmp.FieldByName('attempt_count').AsInteger >= 5 then
  begin
    // Hesabı geçici olarak kilitle
    LockAccount(UserName, 30); // 30 dakika kilitle
  end;
end;
