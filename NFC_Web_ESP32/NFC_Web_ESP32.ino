#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <Preferences.h>
#include <esp_system.h>
#include "Pn532I2c.h"
#include "NdefCodec.h"
#include "WebPage.h"

// Ordinary ESP32 DevKit / WROOM-32. Change for C3/S3 boards as needed.
constexpr int NFC_SDA = 21;
constexpr int NFC_SCL = 22;
WebServer server(80);
Pn532I2c nfc;
String csrfToken;
bool nfcReady = false;

String hexBytes(const uint8_t* data, size_t length) {
  String s; s.reserve(length * 2);
  const char digits[] = "0123456789ABCDEF";
  for (size_t i = 0; i < length; ++i) { s += digits[data[i] >> 4]; s += digits[data[i] & 15]; }
  return s;
}
void reply(int code, const String& message) {
  server.sendHeader("Cache-Control", "no-store");
  server.send(code, "text/plain; charset=utf-8", message);
}
bool allowed() {
  if (server.header("X-NFC-Token") != csrfToken) { reply(403, "Обновите страницу: неверный токен сеанса"); return false; }
  if (!nfcReady) { reply(503, "PN532 не инициализирован. Нажмите «Перезапустить NFC»"); return false; }
  return true;
}
bool selectExpected() {
  if (!nfc.select()) { reply(422, nfc.error); return false; }
  if (server.arg("uid") != hexBytes(nfc.uid, nfc.uidLen)) {
    reply(409, "Метка изменилась. Выполните сканирование заново."); return false;
  }
  return true;
}
String tagInfo() {
  return String("UID: ") + hexBytes(nfc.uid, nfc.uidLen) + "\nТип: " + nfc.type +
    "\nSAK: " + String(nfc.sak, HEX) + "\nATQA: " + String(nfc.atqa, HEX) +
    "\nПользовательская память NTAG: " + String(nfc.userBytes) + " байт\n";
}
void scanTag() {
  if (!allowed()) return;
  if (!nfc.select()) { reply(422, nfc.error); return; }
  reply(200, tagInfo());
}
String dump(const uint8_t* data, size_t count, unsigned start, unsigned stride) {
  String s; s.reserve(count * 4);
  for (size_t i = 0; i < count; i += stride) {
    s += String(start + i / stride); s += ": ";
    const size_t take = (count - i < stride) ? count - i : stride;
    for (size_t j = 0; j < take; ++j) { s += hexBytes(data + i + j, 1); s += ' '; }
    s += '\n';
  }
  return s;
}
// Decode the first short, unchunked Text/URI record; raw dump remains available.
String decodeNdef(const uint8_t* bytes, size_t size) {
  size_t pos = 0;
  while (pos < size) {
    uint8_t tag = bytes[pos++];
    if (tag == 0) continue;
    if (tag == 0xFE || pos >= size) break;
    size_t len = bytes[pos++];
    if (len == 255) { if (pos + 2 > size) break; len = (size_t(bytes[pos]) << 8) | bytes[pos+1]; pos += 2; }
    if (len > size - pos) break;
    if (tag != 3) { pos += len; continue; }
    if (len < 4) break;
    const uint8_t* r = bytes + pos;
    if ((r[0] & 0x3F) != 0x11 || r[1] != 1 || size_t(r[2]) + 4 > len) break;
    const uint8_t* payload = r + 4; size_t plen = r[2];
    if (plen == 0) break;
    String result;
    if (r[3] == 'T') {
      if (payload[0] & 0x80) return "NDEF Text UTF-16 (смотрите HEX)";
      size_t skip = 1 + (payload[0] & 0x3F); if (skip > plen) break;
      result = "NDEF Text: ";
      for (size_t i = skip; i < plen; ++i) result += char(payload[i]);
      return result;
    }
    if (r[3] == 'U') {
      const char* prefixes[] = {"", "http://www.", "https://www.", "http://", "https://"};
      if (payload[0] > 4) return "NDEF URI с иным префиксом (смотрите HEX)";
      result = String("NDEF URI: ") + prefixes[payload[0]];
      for (size_t i = 1; i < plen; ++i) result += char(payload[i]);
      return result;
    }
    break;
  }
  return "Короткая NDEF-запись Text/URI не найдена; содержимое ниже в HEX.";
}
void readNtag() {
  if (!allowed() || !selectExpected()) return;
  if (!nfc.userBytes) { reply(422, "Чтение памяти здесь поддерживает подтверждённые NTAG213/215/216. Для Classic используйте раздел блоков."); return; }
  uint8_t data[888], part[16];
  for (unsigned offset = 0; offset < nfc.userBytes; offset += 16) {
    if (!nfc.read16(uint8_t(4 + offset / 4), part)) { reply(422, nfc.error + "\nЧтение прервано на байте " + String(offset)); return; }
    unsigned take = min(16U, nfc.userBytes - offset); memcpy(data + offset, part, take); delay(1);
  }
  reply(200, tagInfo() + decodeNdef(data, nfc.userBytes) + "\n\nСтраницы пользовательской памяти:\n" + dump(data, nfc.userBytes, 4, 4));
}
void writeNtag() {
  if (!allowed()) return;
  String mode = server.arg("mode"), value = server.arg("value");
  if ((mode != "text" && mode != "uri") || value.length() == 0 || value.length() > 240) {
    reply(400, "Нужен текст/URL длиной 1–240 байт UTF-8"); return;
  }
  if (mode == "uri" && !value.startsWith("https://") && !value.startsWith("http://")) {
    reply(400, "Ссылка должна начинаться с https:// или http://"); return;
  }
  if (!selectExpected()) return;
  if (!nfc.userBytes) { reply(422, "Запись NDEF разрешена только для подтверждённых NTAG213/215/216"); return; }
  uint8_t check[16];
  if (!nfc.read16(3, check)) { reply(422, nfc.error); return; }
  if (check[0] != 0xE1 || check[1] != 0x10 || (check[3] & 15) != 0) {
    reply(422, "CC метки не поддерживается или запись запрещена. Форматирование/снятие защиты не выполняется."); return;
  }
  const unsigned advertised = unsigned(check[2]) * 8;
  const unsigned capacity = min(nfc.userBytes, advertised);
  uint8_t bytes[888] = {};
  const size_t used = buildNdef(reinterpret_cast<const uint8_t*>(value.c_str()), value.length(), mode == "uri", bytes, capacity);
  if (!used) { reply(400, "Запись не помещается в пользовательскую память метки"); return; }
  const size_t padded = (used + 3) & ~size_t(3);
  // Conservative preflight: reject any locked user region and password-protected target pages.
  if (!nfc.read16(2, check)) { reply(422, nfc.error); return; }
  if (check[2] || check[3]) { reply(422, "Обнаружены статические lock-биты. Запись этой метки отключена."); return; }
  const uint8_t dynamicPage = uint8_t(4 + nfc.userBytes / 4);
  if (!nfc.read16(dynamicPage, check)) { reply(422, nfc.error); return; }
  if (check[0] || check[1] || check[2]) { reply(422, "Обнаружены динамические lock-биты. Запись этой метки отключена."); return; }
  if (check[7] <= 4 + (padded - 1) / 4) { reply(422, "Диапазон записи защищён паролем AUTH0. Эта версия не снимает защиту."); return; }

  // Invalidate the old NDEF before updating. Final first-page write commits the TLV.
  // On interruption this is NOT a rollback: rescan and repeat the write.
  const uint8_t empty[] = {3, 0, 0xFE, 0};
  if (!nfc.writePage(4, empty)) { reply(422, nfc.error + "\nНе удалось начать запись"); return; }
  for (size_t offset = 4; offset < padded; offset += 4) {
    const uint8_t page = uint8_t(4 + offset / 4);
    if (!nfc.writePage(page, bytes + offset) || !nfc.read16(page, check) || memcmp(check, bytes + offset, 4) != 0) {
      reply(422, String("Запись/проверка не завершена на странице ") + String(page) + ". Метка могла измениться частично. Повторите операцию.\n" + nfc.error); return;
    }
    delay(1);
  }
  if (!nfc.writePage(4, bytes) || !nfc.read16(4, check) || memcmp(check, bytes, 4) != 0) {
    reply(422, "Не удалось завершить/проверить NDEF. Метка могла измениться частично.\n" + nfc.error); return;
  }
  reply(200, "NDEF записан и проверен чтением.\n" + tagInfo());
}
bool parseBlock(unsigned& block) {
  const String s = server.arg("block");
  if (!s.length() || s.length() > 3) return false;
  for (size_t i = 0; i < s.length(); ++i) if (s[i] < '0' || s[i] > '9') return false;
  block = unsigned(s.toInt()); return block <= 255;
}
void classic(bool write) {
  if (!allowed()) return;
  unsigned block; uint8_t key[6], data[16], check[16];
  String keyType = server.arg("keytype");
  if (!parseBlock(block) || !parseHex(server.arg("key").c_str(), key, 6) || (keyType != "A" && keyType != "B")) {
    reply(400, "Укажите номер блока 0–255, ключ из 12 HEX-символов и тип A/B"); return;
  }
  if (write && !parseHex(server.arg("data").c_str(), data, 16)) { reply(400, "Данные: ровно 16 байт, то есть 32 HEX-символа"); return; }
  if (!selectExpected()) return;
  if (!nfc.classicBlocks || block >= nfc.classicBlocks) { reply(422, "Метка не Classic 1K/4K либо блок вне диапазона"); return; }
  if (write && !isClassicDataBlock(block, nfc.classicBlocks)) { reply(403, "Запись блока 0 и служебных блоков с ключами запрещена"); return; }
  if (!nfc.authenticate(uint8_t(block), key, keyType == "B")) { reply(422, "Аутентификация не выполнена.\n" + nfc.error); return; }
  if (write && !nfc.writeBlock(uint8_t(block), data)) { reply(422, "Запись не подтверждена; проверьте метку чтением.\n" + nfc.error); return; }
  if (!nfc.read16(uint8_t(block), check)) { reply(422, String(write ? "Запись выполнена, но проверка чтением не удалась.\n" : "") + nfc.error); return; }
  if (write && memcmp(data, check, 16) != 0) { reply(422, "Проверка не совпала: содержимое метки изменилось частично либо запись не принята"); return; }
  reply(200, tagInfo() + (write ? "Блок записан и проверен\n" : "Прочитан блок\n") + dump(check, 16, block, 16));
}

void setup() {
  Serial.begin(115200); delay(400);
  nfcReady = nfc.begin(NFC_SDA, NFC_SCL);
  Serial.println(nfcReady ? "PN532 OK" : nfc.error);
  WiFi.mode(WIFI_AP);
  Preferences prefs;
  prefs.begin("nfc-web", false);
  String password = prefs.getString("ap-pass", "");
  if (password.length() < 12) {
    char p[20]; snprintf(p, sizeof(p), "NFC-%08lX%04lX", (unsigned long)esp_random(), (unsigned long)(esp_random() & 0xFFFF));
    password = p; prefs.putString("ap-pass", password);
  }
  prefs.end();
  char token[33]; snprintf(token, sizeof(token), "%08lX%08lX%08lX%08lX", (unsigned long)esp_random(), (unsigned long)esp_random(), (unsigned long)esp_random(), (unsigned long)esp_random());
  csrfToken = token;
  if (!WiFi.softAP("NFC-ESP32", password.c_str(), 1, false, 2)) { Serial.println("WiFi AP failed"); return; }
  Serial.println("WiFi: NFC-ESP32"); Serial.println("Password: " + password);
  Serial.print("Browser: http://"); Serial.println(WiFi.softAPIP());
  const char* headers[] = {"X-NFC-Token"}; server.collectHeaders(headers, 1);
  server.on("/", HTTP_GET, []() {
    String html = FPSTR(WEB_PAGE); html.replace("@@TOKEN@@", csrfToken);
    server.sendHeader("Cache-Control", "no-store");
    server.sendHeader("X-Content-Type-Options", "nosniff");
    server.sendHeader("X-Frame-Options", "DENY");
    server.send(200, "text/html; charset=utf-8", html);
  });
  server.on("/api/scan", HTTP_POST, scanTag);
  server.on("/api/read", HTTP_POST, readNtag);
  server.on("/api/write", HTTP_POST, writeNtag);
  server.on("/api/classic-read", HTTP_POST, []() { classic(false); });
  server.on("/api/classic-write", HTTP_POST, []() { classic(true); });
  server.on("/api/reinit", HTTP_POST, []() {
    if (server.header("X-NFC-Token") != csrfToken) { reply(403, "Обновите страницу"); return; }
    nfcReady = nfc.initialize(); reply(nfcReady ? 200 : 503, nfcReady ? "PN532 готов" : nfc.error);
  });
  server.onNotFound([]() { reply(404, "Не найдено"); });
  server.begin();
}
void loop() { server.handleClient(); delay(2); }
