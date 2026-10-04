#pragma once
#include <Arduino.h>
#include <Wire.h>
#include <string.h>

class Pn532I2c {
 public:
  String error;
  uint8_t uid[10] = {}, uidLen = 0, sak = 0;
  uint16_t atqa = 0;
  unsigned userBytes = 0, classicBlocks = 0;
  const char* type = "Unknown ISO14443A";

  bool begin(int sda, int scl) {
    Wire.begin(sda, scl, 100000);
    Wire.setTimeOut(100);
    delay(100);
    return initialize();
  }
  bool initialize() {
    abortCommand();
    delay(20);
    uint8_t out[48]; size_t n;
    const uint8_t version[] = {0x02};
    if (!command(version, sizeof(version), out, n) || n < 4 || out[0] != 0x32) {
      error = "PN532 не найден. Проверьте I2C, питание и переключатели; перезапустите питание.";
      return false;
    }
    // SAM normal mode; hardware IRQ is not used. Host polls I2C status byte.
    const uint8_t sam[] = {0x14, 0x01, 0x14, 0x00};
    if (!command(sam, sizeof(sam), out, n)) return false;
    const uint8_t retries[] = {0x32, 0x05, 0xFF, 0x01, 0x00};
    return command(retries, sizeof(retries), out, n);
  }
  bool select() {
    uidLen = 0; userBytes = 0; classicBlocks = 0;
    type = "Unknown ISO14443A";
    uint8_t out[48]; size_t n;
    const uint8_t off[] = {0x32, 0x01, 0x00};
    if (!command(off, sizeof(off), out, n)) return false;
    delay(10);
    const uint8_t on[] = {0x32, 0x01, 0x01};
    if (!command(on, sizeof(on), out, n)) return false;
    delay(10);
    const uint8_t scan[] = {0x4A, 1, 0};
    if (!command(scan, sizeof(scan), out, n)) return false;
    if (n < 1 || out[0] == 0) { error = "Метка не найдена. Поднесите одну метку к антенне."; return false; }
    if (n < 6 || out[0] != 1 || out[1] != 1 || out[5] == 0 || out[5] > 10 || n < size_t(6 + out[5])) {
      error = "Некорректный ответ выбора метки"; return false;
    }
    atqa = (uint16_t(out[2]) << 8) | out[3]; sak = out[4]; uidLen = out[5];
    memcpy(uid, out + 6, uidLen);
    if (sak == 0x08) { type = "MIFARE Classic 1K"; classicBlocks = 64; }
    if (sak == 0x18) { type = "MIFARE Classic 4K"; classicBlocks = 256; }
    if (sak == 0 && uidLen == 7) {
      type = "Type 2 / Ultralight (неподтверждённый тип)";
      const uint8_t getVersion[] = {0x60};
      if (exchange(getVersion, 1, out, n) && n == 8 && out[0] == 0 && out[1] == 4 &&
          out[2] == 4 && out[3] == 2 && out[4] == 1 && out[5] == 0 && out[7] == 3) {
        if (out[6] == 0x0F) { type = "NTAG213"; userBytes = 144; }
        if (out[6] == 0x11) { type = "NTAG215"; userBytes = 504; }
        if (out[6] == 0x13) { type = "NTAG216"; userBytes = 888; }
      }
    }
    error = "";
    return true;
  }
  bool read16(uint8_t address, uint8_t* data) {
    const uint8_t cmd[] = {0x30, address}; uint8_t out[48]; size_t n;
    if (!exchange(cmd, sizeof(cmd), out, n)) return false;
    if (n != 16) { error = "Ожидалось 16 байт данных"; return false; }
    memcpy(data, out, 16); return true;
  }
  bool writePage(uint8_t page, const uint8_t* data) {
    uint8_t cmd[6] = {0xA2, page}; memcpy(cmd + 2, data, 4);
    uint8_t out[48]; size_t n;
    return exchange(cmd, sizeof(cmd), out, n);
  }
  bool authenticate(uint8_t block, const uint8_t* key, bool keyB) {
    if (uidLen != 4 && uidLen != 7) { error = "Неподдерживаемая длина UID Classic"; return false; }
    uint8_t cmd[12] = {uint8_t(keyB ? 0x61 : 0x60), block};
    memcpy(cmd + 2, key, 6); memcpy(cmd + 8, uid + uidLen - 4, 4);
    uint8_t out[48]; size_t n; return exchange(cmd, sizeof(cmd), out, n);
  }
  bool writeBlock(uint8_t block, const uint8_t* data) {
    uint8_t cmd[18] = {0xA0, block}; memcpy(cmd + 2, data, 16);
    uint8_t out[48]; size_t n; return exchange(cmd, sizeof(cmd), out, n);
  }
 private:
  static constexpr uint8_t Address = 0x24;
  void abortCommand() {
    const uint8_t ack[] = {0, 0, 0xFF, 0, 0xFF, 0};
    Wire.beginTransmission(Address); Wire.write(ack, sizeof(ack)); Wire.endTransmission();
  }
  bool ready(uint32_t timeout) {
    uint32_t start = millis();
    do {
      if (Wire.requestFrom(Address, uint8_t(1)) == 1 && Wire.read() == 1) return true;
      delay(5);
    } while (uint32_t(millis() - start) < timeout);
    error = "Таймаут PN532; повторите сканирование или отключите питание модуля";
    abortCommand(); return false;
  }
  bool command(const uint8_t* cmd, size_t count, uint8_t* out, size_t& outSize) {
    outSize = 0;
    if (count == 0 || count > 48) { error = "Слишком длинная команда"; return false; }
    uint8_t frame[56] = {0, 0, 0xFF};
    frame[3] = uint8_t(count + 1); frame[4] = uint8_t(0 - frame[3]); frame[5] = 0xD4;
    uint8_t sum = 0xD4;
    for (size_t i = 0; i < count; ++i) { frame[6 + i] = cmd[i]; sum += cmd[i]; }
    frame[6 + count] = uint8_t(0 - sum); frame[7 + count] = 0;
    Wire.beginTransmission(Address); Wire.write(frame, count + 8);
    if (Wire.endTransmission() != 0) { error = "PN532 не отвечает по I2C 0x24"; return false; }
    if (!ready(1000)) return false;
    uint8_t ack[7];
    if (Wire.requestFrom(Address, uint8_t(7)) != 7) { error = "Короткий ACK"; return false; }
    for (auto& b : ack) b = Wire.read();
    const uint8_t expected[] = {1, 0, 0, 0xFF, 0, 0xFF, 0};
    if (memcmp(ack, expected, 7) != 0) { error = "Некорректный ACK PN532"; abortCommand(); return false; }
    if (!ready(1500)) return false;
    uint8_t buf[64];
    if (Wire.requestFrom(Address, uint8_t(sizeof(buf))) != sizeof(buf)) { error = "Короткий ответ I2C"; return false; }
    for (auto& b : buf) b = Wire.read();
    const unsigned len = buf[4];
    if (buf[0] != 1 || buf[1] != 0 || buf[2] != 0 || buf[3] != 0xFF ||
        uint8_t(buf[4] + buf[5]) != 0 || len < 2 || len > 50 ||
        buf[6] != 0xD5 || buf[7] != uint8_t(cmd[0] + 1) || buf[7 + len] != 0) {
      error = "Повреждённый или неподдерживаемый кадр PN532"; return false;
    }
    sum = 0; for (unsigned i = 6; i <= 6 + len; ++i) sum += buf[i];
    if (sum != 0) { error = "Ошибка контрольной суммы PN532"; return false; }
    outSize = len - 2; memcpy(out, buf + 8, outSize); return true;
  }
  bool exchange(const uint8_t* data, size_t size, uint8_t* out, size_t& n) {
    if (size > 40) { error = "Команда метки слишком длинная"; return false; }
    uint8_t cmd[42] = {0x40, 1}; memcpy(cmd + 2, data, size);
    uint8_t response[48]; size_t length;
    if (!command(cmd, size + 2, response, length)) return false;
    if (length < 1 || response[0] != 0) {
      char msg[160]; snprintf(msg, sizeof(msg), "PN532 status 0x%02X: отказ, защита, неверный ключ или метка убрана", length ? response[0] : 255);
      error = msg; return false;
    }
    n = length - 1; memcpy(out, response + 1, n); return true;
  }
};
