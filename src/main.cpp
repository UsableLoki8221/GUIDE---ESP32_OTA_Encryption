/*
Code and guide posted at:
https://github.com/UsableLoki8221/GUIDE---ESP32_OTA_Encryption
*/

#include <Arduino.h>

const String FIRMWARE_VERSION = "1.1.1";

#define FILESYSTEM true // remove sections of code if you don't have a filesystem

const char* version_url = "https://raw.githubusercontent.com/UsableLoki8221/GUIDE---ESP32_OTA_Encryption/refs/heads/main/version.txt";

const char* firmware_url_backup = "https://raw.githubusercontent.com/UsableLoki8221/GUIDE---ESP32_OTA_Encryption/refs/heads/main/encrypted_firmware.bin"; // set fallback URL
const char* filesystem_url_backup = "https://raw.githubusercontent.com/UsableLoki8221/GUIDE---ESP32_OTA_Encryption/refs/heads/main/encrypted_filesystem.bin"; //set fallback URL

const char* WIFI_SSID = "YOUR WIFI";
const char* WIFI_PASSWORD = "YOUR PASS";


#include <LittleFS.h>
#include <ArduinoJson.h>
#include <Adafruit_NeoPixel.h>

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>

#include "esp_system.h"
#include "esp_efuse.h"
#include "esp_hmac.h"

#include "mbedtls/md.h"
#include "mbedtls/aes.h"

#include "esp32-hal-log.h"

#include "esp_ota_ops.h"


#define LED_PIN 4
#define LED_PIN2 6

bool connectWiFi(uint32_t timeout = 20000) {
    if (WiFi.status() == WL_CONNECTED) {
        log_i("Already connected to WiFi");
        return true;
    }

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    log_i("Connecting to WiFi: %s", WIFI_SSID);

    uint32_t startTime = millis();

    while (WiFi.status() != WL_CONNECTED) {
        if (millis() - startTime >= timeout) {
            log_e("WiFi connection timed out");
            WiFi.disconnect();
            return false;
        }

        delay(250);
    }

    log_i("WiFi connected successfully");
    log_i("IP Address: %s", WiFi.localIP().toString().c_str());
    log_i("Signal Strength: %d dBm", WiFi.RSSI());

    return true;
}


Adafruit_NeoPixel LED1(2, LED_PIN, NEO_GRB + NEO_KHZ800);
Adafruit_NeoPixel LED2(2, LED_PIN2, NEO_GRB + NEO_KHZ800);

void showLEDms(int ms, int r, int g, int b) {
static bool initialize = true;
if (initialize){
initialize = false;
LED1.begin();
LED2.begin();
}

uint32_t color = LED1.Color(r, g, b);
LED1.setPixelColor(0, color);
LED1.setPixelColor(1, color);
LED1.show();
LED2.setPixelColor(0, color);
LED2.setPixelColor(1, color);
LED2.show();
delay(ms);
}


String getLocalFSVersion() {
    if (!LittleFS.begin()) {
        log_e("Failed to mount LittleFS");
        return "0.0.0"; // fallback if FS is missing
    }

    File versionFile = LittleFS.open("/fs_version.txt", "r");
    if (!versionFile) {
        log_e("No local FS version file, assuming 0.0.0");
        return "0.0.0";
    }

    String version = versionFile.readStringUntil('\n');
    version.trim();
    versionFile.close();
    return version;
}


int constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff; // 0 = equal, non-zero = different
}

struct AesCtr {
    mbedtls_aes_context ctx;

    AesCtr() { mbedtls_aes_init(&ctx); }
    ~AesCtr() { mbedtls_aes_free(&ctx); }

    mbedtls_aes_context* operator&() { return &ctx; }
};
struct MdCtx {
    mbedtls_md_context_t ctx;

    MdCtx() { mbedtls_md_init(&ctx); }
    ~MdCtx() { mbedtls_md_free(&ctx); }

    mbedtls_md_context_t* operator&() { return &ctx; }
};


bool derive_keys(uint8_t *enc_key, uint8_t *mac_key) {
    const char *ctx1 = "OTA_AES_KEY_V1";
    const char *ctx2 = "OTA_HMAC_KEY_V1";

    if (esp_hmac_calculate(HMAC_KEY1, (const uint8_t*)ctx1, strlen(ctx1), enc_key) != ESP_OK) {
        log_e("hmac fail-1");
        return false;
    }

    if (esp_hmac_calculate(HMAC_KEY1, (const uint8_t*)ctx2, strlen(ctx2), mac_key) != ESP_OK) {
      log_e("hmac fail-2");
        return false;
    }

    // enc_key = first 16 bytes
    // mac_key = full 32 bytes
    return true;
}


int updateOTA(const String& updateType,
              const String& newVersion,
              const String& newSize,
              const String& newHash,
              const String& firmware_url) {

    bool isFilesystem = updateType == "filesystem";
    bool isFirmware = updateType == "firmware";

    if (!isFilesystem && !isFirmware) {
        log_e("Invalid OTA update type: %s", updateType.c_str());
        return 1;
    }

    WiFiClientSecure client;
    client.setInsecure();

    HTTPClient http;

    if (!http.begin(client, firmware_url)) {
        log_e("Failed to initialize HTTP connection");
        return 2;
    }

    log_i("Starting OTA download");
    log_i("Sending HTTP GET request");
    log_i("Note: if crash occurs right after this message then there is an issue with the webpage being retrieved.");
    log_i("Webpage may not truly be a raw file download.");
    log_i("example: https://github.com/.../encrypted.bin causes crash, instead use https://raw.githubusercontent.com/.../encrypted.bin URL");

    int httpCode = http.GET();

    if (httpCode != HTTP_CODE_OK) {
        log_e("HTTP GET failed: %d", httpCode);
        http.end();
        client.stop();
        return 3;
    }

    int totalSize = http.getSize();

    if (totalSize < 0) {
        log_e("Invalid HTTP content length");
        http.end();
        client.stop();
        return 4;
    }

    int expected_size = newSize.toInt();

    if (expected_size <= 32 || totalSize != expected_size + 40) {
        log_e("Invalid OTA package size");
        http.end();
        client.stop();
        return 5;
    }

    if (newHash.length() != 64) {
        log_e("Invalid server hash length");
        http.end();
        client.stop();
        return 6;
    }

    WiFiClient *stream = http.getStreamPtr();

    uint8_t nonce[8];

    if (stream->readBytes(nonce, 8) != 8) {
        log_e("Failed to read encryption nonce");
        http.end();
        client.stop();
        return 7;
    }

    int ciphertext_len = totalSize - 8 - 32;

    uint8_t enc_key_full[32];
    uint8_t mac_key[32];

    if (!derive_keys(enc_key_full, mac_key)) {
        log_e("Encryption key derivation failed");
        http.end();
        client.stop();
        return 8;
    }

    uint8_t enc_key[16];
    memcpy(enc_key, enc_key_full, 16);

    AesCtr aes;
    MdCtx hmac;

    if (mbedtls_aes_setkey_enc(&aes.ctx, enc_key, 128) != 0) {
        log_e("AES key configuration failed");
        http.end();
        client.stop();
        return 9;
    }

    if (mbedtls_md_setup(&hmac.ctx,
                         mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1) != 0) {
        log_e("HMAC context configuration failed");
        http.end();
        client.stop();
        return 10;
    }

    if (mbedtls_md_hmac_starts(&hmac.ctx, mac_key, 32) != 0) {
        log_e("HMAC initialization failed");
        http.end();
        client.stop();
        return 11;
    }

    if (mbedtls_md_hmac_update(&hmac.ctx, nonce, sizeof(nonce)) != 0) {
        log_e("HMAC nonce authentication failed");
        http.end();
        client.stop();
        return 12;
    }

    uint8_t stream_block[16] = {0};
    size_t nc_off = 0;

    uint8_t nonce_counter[16] = {0};
    memcpy(nonce_counter, nonce, 8);

    int updateSize = expected_size - 32;
    int updateCommand = isFilesystem ? U_SPIFFS : U_FLASH;

    if (isFilesystem) {
        log_i("Unmounting LittleFS");
        LittleFS.end();
    }

    log_i("Beginning OTA update");

    if (!Update.begin(updateSize, updateCommand)) {
        log_e("Update.begin failed: %s", Update.errorString());
        http.end();
        client.stop();
        return 13;
    }

    uint8_t enc_buffer[1024];
    uint8_t dec_buffer[1024];

    uint8_t tail[32] = {0};
    int tail_len = 0;

    bool headerChecked = false;

    int ciphertext_remaining = ciphertext_len;
    size_t written = 0;

    log_i("Downloading and decrypting OTA package");

    while (ciphertext_remaining > 0) {

        int chunk = min(ciphertext_remaining, (int)sizeof(enc_buffer));

        int read = stream->readBytes(enc_buffer, chunk);

        if (read != chunk) {
            log_e("Encrypted data stream read failed");
            Update.abort();
            http.end();
            client.stop();
            return 14;
        }

        if (mbedtls_md_hmac_update(&hmac.ctx, enc_buffer, chunk) != 0) {
            log_e("HMAC update failed");
            Update.abort();
            http.end();
            client.stop();
            return 15;
        }

        if (mbedtls_aes_crypt_ctr(
                &aes.ctx,
                chunk,
                &nc_off,
                nonce_counter,
                stream_block,
                enc_buffer,
                dec_buffer) != 0) {
            log_e("AES decryption failed");
            Update.abort();
            http.end();
            client.stop();
            return 16;
        }

        if (isFirmware && !headerChecked) {
            if (dec_buffer[0] != 0xE9) {
                log_e("Invalid firmware image header");
                Update.abort();
                http.end();
                client.stop();
                return 17;
            }

            headerChecked = true;
        }

        uint8_t combined[1056];

        memcpy(combined, tail, tail_len);
        memcpy(combined + tail_len, dec_buffer, chunk);

        int combined_len = tail_len + chunk;

        int new_tail_len = min(32, combined_len);
        int new_data_len = combined_len - new_tail_len;

        if (new_data_len > 0) {

            if (Update.write(combined, new_data_len) != new_data_len) {
                log_e("Flash write failed: %s", Update.errorString());
                Update.abort();
                http.end();
                client.stop();
                return 18;
            }

            written += new_data_len;
        }

        memcpy(tail, combined + new_data_len, new_tail_len);
        tail_len = new_tail_len;

        ciphertext_remaining -= chunk;
    }

    log_i("OTA download and decryption completed");

    uint8_t expected_tag[32];

    if (stream->readBytes(expected_tag, 32) != 32) {
        log_e("HMAC read failed");
        Update.abort();
        http.end();
        client.stop();
        return 19;
    }

    uint8_t computed_tag[32];

    if (mbedtls_md_hmac_finish(&hmac.ctx, computed_tag) != 0) {
        log_e("HMAC calculation failed");
        Update.abort();
        http.end();
        client.stop();
        return 20;
    }

    if (constant_time_compare(expected_tag, computed_tag, 32) != 0) {
        log_e("HMAC verification failed");
        Update.abort();
        http.end();
        client.stop();
        return 21;
    }

    if (tail_len != 32) {
        log_e("Invalid embedded SHA length");
        Update.abort();
        http.end();
        client.stop();
        return 22;
    }

    char embedded_hash_hex[65];

    for (int i = 0; i < 32; i++) {
        sprintf(&embedded_hash_hex[i * 2], "%02x", tail[i]);
    }

    embedded_hash_hex[64] = '\0';

    if (!newHash.equalsIgnoreCase(embedded_hash_hex)) {
        log_e("SHA-256 hash mismatch");
        Update.abort();
        http.end();
        client.stop();
        return 23;
    }

    if (written != (size_t)updateSize) {
        log_e("OTA size mismatch: expected %d, wrote %u",
              updateSize, (unsigned int)written);
        Update.abort();
        http.end();
        client.stop();
        return 24;
    }

    log_i("Verifying and finalizing OTA update");

    if (!Update.end()) {
        log_e("Update.end failed: %s", Update.errorString());
        http.end();
        client.stop();
        return 25;
    }

    http.end();
    client.stop();

    if (isFilesystem) {

        if (newVersion != getLocalFSVersion()) {
            log_e("Filesystem OTA verification failed");
            return 26;
        }

        log_i("Filesystem OTA successful");

    } else {
        log_i("Firmware OTA successful");
    }

    log_i("OTA update completed successfully");

    return 0;
}



String extractJSONtag(const String& jsonPayload, const char* key) {
  //StaticJsonDocument<128> doc;
  JsonDocument doc;

  DeserializationError error = deserializeJson(doc, jsonPayload);
  if (error) {
    log_w("JSON parse failed: %s", error.c_str());
    return "";
  }

  const char* tag = doc[key];
  if (!tag) {
    log_w("Key '%s' missing\n", key);
    return "";
  }

  String result = String(tag);
  result.trim();
  return result;
}




void checkForUpdates() {

  static unsigned long lastCheckTime = 0;
  static const uint32_t updateInterval = 604800000UL - random(86400000UL); // stagger check time between 6–7 days so all devices do not update at the same time
  static bool initialState = true;

  if ((millis() - lastCheckTime >= updateInterval || initialState) && WiFi.status() == WL_CONNECTED) {
    lastCheckTime = millis();
    initialState = false;

    log_i("CHECKING FOR UPDATES...");

    bool restart = false;

    WiFiClientSecure client;
    client.setInsecure();

    HTTPClient http;

    if (!http.begin(client, version_url)) {
      log_w("Failed to initialize HTTP connection.");
      client.stop();
      return;
    }

    const int maxRetries = 3;
    int attempt = 0;
    int httpCode = 0;
    bool success = false;

    while (attempt < maxRetries && !success) {
      httpCode = http.GET();

      if (httpCode == HTTP_CODE_OK) {
        success = true;
      } else {
        attempt++;
        log_w("Attempt %d failed, HTTP error: %s",
              attempt,
              http.errorToString(httpCode).c_str());

        if (attempt < maxRetries) {
          delay(1000 * attempt); // simple exponential backoff
        }
      }
    }

    if (!success) {
      log_w("Failed to fetch firmware version after multiple attempts.");
      http.end();
      client.stop();

      lastCheckTime = millis() - (updateInterval * 0.9); // boost time check to try soon
      return;
    }

    String jsonStr = http.getString();

    http.end();
    client.stop();

    log_i("Successfully retrieved site JSON:");
    log_i("%s", jsonStr.c_str());
  
    String localFirmwareVersion = FIRMWARE_VERSION;

    String firmware_url = extractJSONtag(jsonStr, "fw_url");
    if (firmware_url.isEmpty()) firmware_url = firmware_url_backup; //fallback link

    String newFirmwareVersion = extractJSONtag(jsonStr, "fw_version");
    String newFirmwareSize = extractJSONtag(jsonStr, "fw_size");
    String newFirmwareHash = extractJSONtag(jsonStr, "fw_hash");
    if (newFirmwareVersion.isEmpty() ||
        newFirmwareSize.isEmpty() ||
        newFirmwareHash.isEmpty()) {
      log_w("Firmware metadata incomplete. Aborting OTA.");
      return;
    }


    if (FILESYSTEM) {
      String localFilesystemVersion = getLocalFSVersion();

      String filesystem_url = extractJSONtag(jsonStr, "fs_url");
      if (filesystem_url.isEmpty()) filesystem_url = filesystem_url_backup;
      
      String newFilesystemVersion = extractJSONtag(jsonStr, "fs_version");
      String newFilesystemSize = extractJSONtag(jsonStr, "fs_size");
      String newFilesystemHash = extractJSONtag(jsonStr, "fs_hash");
          if (newFilesystemVersion.isEmpty() ||
          newFilesystemSize.isEmpty() ||
          newFilesystemHash.isEmpty()) {
        log_w("Filesystem metadata incomplete. Aborting OTA.");
        return;
      }

      log_i("Current Firmware Version: %s", localFirmwareVersion.c_str());
      log_i("Available Firmware Version: %s", newFirmwareVersion.c_str());
      
      log_i("Current Filesystem Version: %s", localFilesystemVersion.c_str());
      log_i("Available Filesystem Version: %s", newFilesystemVersion.c_str());


      if (localFilesystemVersion != newFilesystemVersion) {
        log_i("New filesystem available. Updating...");
        int filesystemOTAcode = updateOTA(
                                          "filesystem",
                                          newFilesystemVersion,
                                          newFilesystemSize,
                                          newFilesystemHash,
                                          filesystem_url
                                          );
        if (filesystemOTAcode == 0) {
          restart = true;
        } else {
          log_e("ERROR WITH FILESYSTEM OTA: %i", filesystemOTAcode);
        }
      } else {
        log_i("Filesystem is up to date");
      }
    }


    if (localFirmwareVersion != newFirmwareVersion) {
      log_i("New firmware available. Updating...");
      int firmwareOTAcode = updateOTA(
                                      "firmware",
                                      newFirmwareVersion,
                                      newFirmwareSize,
                                      newFirmwareHash,
                                      firmware_url
                                      );
      if (firmwareOTAcode == 0) {
        log_i("Firmware updated successfully, restarting device...");
        restart = true;
      } else {
        log_e("ERROR WITH FIRMWARE OTA: %i", firmwareOTAcode);
      }
    } else {
      log_i("Firmware is up to date");
    }
    if (restart) {
      ESP.restart();
    }
  }
}

///////

/* BUILD FLAG PROVIDES AUTOMATIC UPDATE ROLLBACK FUNCTIONS OF...
-DCONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=1
firmware crashes during boot
watchdog resets early
kernel panic occurs before reaching stable runtime
*/
RTC_DATA_ATTR int otaBootCount = 0;
const int MAX_OTA_BOOT_COUNT = 3;

bool validationPending = false;

void checkFirstBootAfterOTA_SETUP() {
  const esp_partition_t* running = esp_ota_get_running_partition();
  esp_ota_img_states_t ota_state;

  checkFirstBootAfterOTA_LOOP();

  if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
    if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
      log_i("ESP_OTA_IMG_PENDING_VERIFY... waiting for OTA verification on WifI Connect");
      validationPending = true;
      otaBootCount++;
    }
  }
}

void checkFirstBootAfterOTA_LOOP() {
  if (!validationPending) return;

  if (otaBootCount > MAX_OTA_BOOT_COUNT) {
    log_e("OTA boot limit exceeded → rollback");
    esp_ota_mark_app_invalid_rollback_and_reboot();
    return;
  }

  if (WiFi.status() == WL_CONNECTED) {
    esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();

    if (err == ESP_OK) {
      log_i("OTA Update deemed valid and verified!");
      validationPending = false;
      otaBootCount = 0;
    } else {
      log_e("Failed to mark OTA firmware valid: %s", esp_err_to_name(err));
    }
  }
}


//////////////////////////////////////////////////

void setup() {
    Serial.begin(115200);
    delay(1000);

    log_i("START UP");

    checkFirstBootAfterOTA_SETUP();

    showLEDms(1000, 40, 40, 40);
    showLEDms(1000, 0, 0, 0);

    randomSeed(ESP.getEfuseMac());

    if (!connectWiFi()) {
        log_e("Unable to connect to WiFi");
    }

}


void loop() {
    checkFirstBootAfterOTA_LOOP(); // OTA marks itself as valid once you have WiFi connection, change this behavior if you prefer different verification

    String fsVersion = getLocalFSVersion();

    log_i("Current Firmware Version: %s", FIRMWARE_VERSION.c_str());
    log_i("Current Filesystem Version: %s", fsVersion.c_str());

    if (FIRMWARE_VERSION == "1.1.1") showLEDms(1000, 00, 40, 0); //GREEN
    if (fsVersion == "1.1.1") showLEDms(1000, 0, 40, 40); //CYAN
    
    if (FIRMWARE_VERSION == "2.2.2") showLEDms(1000, 00, 00, 40); //BLUE
    if (fsVersion == "2.2.2") showLEDms(1000, 40, 0, 40); //PURPLE


    checkForUpdates();
}

