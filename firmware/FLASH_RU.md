# Готовый образ (необязательный вариант)

`NFC_Web_ESP32_merged.bin` — полный образ для **обычного ESP32 DevKit/WROOM-32, 4 МБ flash**.
Он включает bootloader, стандартную таблицу разделов Arduino, boot_app0 и приложение.
Параметры: ESP32 Arduino core 2.0.17, DIO, 80 МГц flash. Не подходит для ESP8266, C3/S3/C6.
Образ собран, но физическая прошивка/работа NFC не проверялись.

Для Arduino IDE используйте скетч из папки NFC_Web_ESP32. Этот бинарник через IDE не открывается.

Если хотите прошить уже готовый образ esptool:

```bash
python3 -m venv ~/venvs/esptool
source ~/venvs/esptool/bin/activate
python -m pip install esptool
# Из папки firmware, для esptool 5:
python -m esptool --chip esp32 --port /dev/ttyUSB0 --baud 460800 write-flash 0x0 NFC_Web_ESP32_merged.bin
```

Для esptool 4 используется `write_flash` вместо `write-flash`.
Укажите фактический USB-порт. При нестабильной загрузке снизьте скорость до 115200.
Не нужно предварительно стирать всю flash: это удалило бы и пароль NVS.
Запись заменит прежнюю прошивку и её таблицу разделов. Если нужны старые данные, сначала сделайте резервную копию.
После записи нажмите EN/RESET, откройте монитор порта на 115200 и получите пароль сети NFC-ESP32.
