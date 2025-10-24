// =====================================================
// GÜVENLİK DÜZELTMESİ: XSS Koruması
// Dosya: unLogin.pas
// Prosedür: UniLoginFormCreate
// =====================================================

procedure TfrmLogin.UniLoginFormCreate(Sender: TObject);
var
  id_Token: string;
begin
  // ❌ ESKİ KOD - XSS ZAAFİYETİ VAR:
  {
  UniSession.AddJS(
    ' Ext.onReady(function() { '+
    ' setTimeout(function() { '+
    ' var fragment = window.location.hash.substring(1); '+
    ' var params = new URLSearchParams(fragment); '+
    ' var accessToken = params.get("access_token"); '+
    ' var idToken = params.get("id_token"); '+
  }

  // ✅ YENİ KOD - XSS KORUMASLI:
  UniSession.AddJS(
    'Ext.onReady(function() {' +
    '  setTimeout(function() {' +
    '    try {' +
    '      var fragment = window.location.hash.substring(1);' +
    '      var params = new URLSearchParams(fragment);' +
    '      ' +
    '      // XSS Koruması: Token validasyonu' +
    '      var accessToken = params.get("access_token");' +
    '      var idToken = params.get("id_token");' +
    '      ' +
    '      // Sadece alphanumeric ve belirli karakterlere izin ver' +
    '      var tokenRegex = /^[A-Za-z0-9._-]+$/;' +
    '      ' +
    '      if (accessToken && !tokenRegex.test(accessToken)) {' +
    '        console.error("Invalid access_token format");' +
    '        return;' +
    '      }' +
    '      ' +
    '      if (idToken && !tokenRegex.test(idToken)) {' +
    '        console.error("Invalid id_token format");' +
    '        return;' +
    '      }' +
    '      ' +
    '      var newUrl = window.location.href.split("#")[0];' +
    '      var newParams = [];' +
    '      ' +
    '      if (accessToken) {' +
    '        // encodeURIComponent ile XSS koruması' +
    '        newParams.push("access_token=" + encodeURIComponent(accessToken));' +
    '      }' +
    '      ' +
    '      if (idToken) {' +
    '        newParams.push("id_token=" + encodeURIComponent(idToken));' +
    '      }' +
    '      ' +
    '      if (newParams.length > 0) {' +
    '        newUrl += "?" + newParams.join("&");' +
    '        if (window.location.href !== newUrl) {' +
    '          window.location.replace(newUrl);' +
    '        }' +
    '      }' +
    '    } catch(e) {' +
    '      console.error("Token processing error:", e);' +
    '    }' +
    '  }, 100);' +
    '});'
  );

  // ... kodun geri kalanı
end;

// =====================================================
// GÜVENLİK İYİLEŞTİRMESİ: Input Validation
// =====================================================

// Kullanıcı girişlerini sanitize eden fonksiyon
function TfrmLogin.SanitizeInput(const Input: string): string;
var
  I: Integer;
  C: Char;
begin
  Result := '';

  for I := 1 to Length(Input) do
  begin
    C := Input[I];

    // XSS karakterlerini filtrele
    case C of
      '<', '>', '"', '''', '&', ';', '/', '\':
        Continue; // Bu karakterleri atla

      else
        Result := Result + C;
    end;
  end;
end;

// HTML Encoding fonksiyonu
function TfrmLogin.HTMLEncode(const Text: string): string;
begin
  Result := StringReplace(Text, '&', '&amp;', [rfReplaceAll]);
  Result := StringReplace(Result, '<', '&lt;', [rfReplaceAll]);
  Result := StringReplace(Result, '>', '&gt;', [rfReplaceAll]);
  Result := StringReplace(Result, '"', '&quot;', [rfReplaceAll]);
  Result := StringReplace(Result, '''', '&#x27;', [rfReplaceAll]);
  Result := StringReplace(Result, '/', '&#x2F;', [rfReplaceAll]);
end;

// =====================================================
// ServerModule.pas'a Eklenecek CSP Header
// =====================================================

procedure TServerMod.UniGUIServerModuleHTTPCommand(...);
begin
  // ... mevcut kod

  // ✅ Content Security Policy ekle
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

  // ✅ X-Content-Type-Options zaten var (iyi)
  // AResponseInfo.CustomHeaders.AddValue('X-Content-Type-Options', 'nosniff');

  // ✅ X-Frame-Options iyileştir
  AResponseInfo.CustomHeaders.AddValue('X-Frame-Options', 'DENY');

  // ... kodun geri kalanı
end;
