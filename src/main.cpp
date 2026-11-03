// Presence Lock - ESP32-S3
//
// - Scans BLE for an iPhone, recognised through its IRK (Identity Resolving Key)
// - Publishes presence + RSSI to Home Assistant via MQTT discovery
// - Presses Win+L over USB HID once, when presence goes present -> away
// - Presses Up arrow twice when the phone comes back after 30+ s away
//
// Security rule: this device can type into the PC, so it never listens on the
// network. No MQTT subscribe, no OTA, no web server. The only keys the firmware
// sends are Win+L and Up arrow. Settings (including Wi-Fi/MQTT logins) are changed only
// over the local USB serial port, by typed commands or the Web Serial page in ui/.
//
// Lines starting with '@' are JSON for the settings page; everything else is
// plain log text.

#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <NimBLEDevice.h>
#include "USB.h"
#include "USBHIDKeyboard.h"
#include "mbedtls/aes.h"
#include "esp32-hal-tinyusb.h"

// Optional build-time defaults; values saved from the settings page win.
#if __has_include("secrets.h")
#include "secrets.h"
#endif
#ifndef WIFI_SSID
#define WIFI_SSID ""
#endif
#ifndef WIFI_PASSWORD
#define WIFI_PASSWORD ""
#endif
#ifndef MQTT_HOST
#define MQTT_HOST "192.168.68.80"  // Home Assistant on this network; .local names don't resolve here
#endif
#ifndef MQTT_PORT
#define MQTT_PORT 1883
#endif
#ifndef MQTT_USER
#define MQTT_USER ""
#endif
#ifndef MQTT_PASSWORD
#define MQTT_PASSWORD ""
#endif

static const int BOOT_PIN = 0;
static const uint32_t WAKE_AFTER_GONE_MS = 30000;  // gone this long -> press Up x2 on return

USBHIDKeyboard Keyboard;
Preferences prefs;
WiFiClient wifiClient;
PubSubClient mqtt(wifiClient);

// ---- settings (stored in NVS) ----
struct Settings {
  uint8_t irk[16];  // MSB-first, as printed
  bool hasIrk;
  int threshold;    // dBm, smoothed RSSI at or above = in the room
  int margin;       // dB, once present, stay present down to threshold - margin
  uint32_t awaySec; // seconds without a strong reading before "away"
  bool lockEnabled;
  String wifiSsid, wifiPass, mqttHost, mqttUser, mqttPass;
  uint16_t mqttPort;
} cfg;

// ---- IRK matching (written by loop, read by the BLE task) ----
static mbedtls_aes_context aesFwd, aesRev;  // IRK as stored, and byte-reversed
static volatile bool irkReady = false;

// ---- presence state (written by the BLE task) ----
static volatile uint32_t lastSeenMs = 0;
static volatile uint32_t lastStrongMs = 0;
static volatile float rssiEma = -100;
static volatile int lastRssi = -100;
static volatile uint32_t readings = 0;
static volatile uint32_t advCount = 0, rpaCount = 0;  // scanner diagnostics
static volatile bool seenEver = false;
static volatile bool reversedMatch = false;
static bool watch = false;   // plain-text readings
static bool stream = false;  // JSON readings + status for the settings page

enum Presence { UNKNOWN, PRESENT, AWAY };
static volatile Presence presence = UNKNOWN;  // read by the BLE task for the margin

static String devId;    // e.g. ed594c
static String topicBase;

// ======================================================================
// Bluetooth Core Spec ah(): hash = e(IRK, 0^104 || prand) mod 2^24
// ======================================================================
static bool rpaMatches(mbedtls_aes_context* ctx, const uint8_t* addrLe) {
  uint8_t in[16] = {0}, out[16];
  in[13] = addrLe[5];
  in[14] = addrLe[4];
  in[15] = addrLe[3];
  mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, in, out);
  return out[15] == addrLe[0] && out[14] == addrLe[1] && out[13] == addrLe[2];
}

static void loadIrkContexts() {
  irkReady = false;
  if (!cfg.hasIrk) return;
  uint8_t rev[16];
  for (int i = 0; i < 16; i++) rev[i] = cfg.irk[15 - i];
  mbedtls_aes_setkey_enc(&aesFwd, cfg.irk, 128);
  mbedtls_aes_setkey_enc(&aesRev, rev, 128);
  irkReady = true;
}

static bool selfTest() {
  // Core Spec Vol 3 Part H, D.7: IRK ec0234a357c8ad05341010a60a397d9b,
  // prand 708194 -> hash 0dfbaa, i.e. address 70:81:94:0d:fb:aa
  const uint8_t irk[16] = {0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05,
                           0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b};
  const uint8_t addrLe[6] = {0xaa, 0xfb, 0x0d, 0x94, 0x81, 0x70};
  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, irk, 128);
  bool ok = rpaMatches(&ctx, addrLe);
  mbedtls_aes_free(&ctx);
  return ok;
}
static bool selfTestOk = false;

// ======================================================================
// Helpers
// ======================================================================
static String hex(const uint8_t* b, size_t n) {
  static const char* h = "0123456789abcdef";
  String s;
  for (size_t i = 0; i < n; i++) { s += h[b[i] >> 4]; s += h[b[i] & 15]; }
  return s;
}

static bool parseHex(const String& s, uint8_t* out, size_t n) {
  String t = s;
  t.replace(":", ""); t.replace("-", ""); t.replace(" ", "");
  if (t.startsWith("irk")) t = t.substring(3);
  if (t.length() != n * 2) return false;
  for (size_t i = 0; i < n; i++) {
    char buf[3] = {t[i * 2], t[i * 2 + 1], 0};
    char* end;
    out[i] = strtoul(buf, &end, 16);
    if (*end) return false;
  }
  return true;
}

static String jstr(const String& s) {
  String o = "\"";
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if ((uint8_t)c < 0x20) o += ' ';
    else o += c;
  }
  return o + "\"";
}

static void event(const String& msg) {
  Serial.println(msg);
  if (stream) Serial.println("@{\"t\":\"e\",\"msg\":" + jstr(msg) + "}");
}

// ======================================================================
// Settings
// ======================================================================
static void loadSettings() {
  prefs.begin("plock", false);
  cfg.hasIrk = prefs.getBytes("irk", cfg.irk, 16) == 16;
  cfg.threshold = prefs.getInt("thresh", -75);
  cfg.margin = prefs.getInt("margin", 6);
  cfg.awaySec = prefs.getUInt("away", 45);
  cfg.lockEnabled = prefs.getBool("lock", true);
  cfg.wifiSsid = prefs.getString("wssid", WIFI_SSID);
  cfg.wifiPass = prefs.getString("wpass", WIFI_PASSWORD);
  cfg.mqttHost = prefs.getString("mhost", MQTT_HOST);
  cfg.mqttPort = prefs.getUShort("mport", MQTT_PORT);
  cfg.mqttUser = prefs.getString("muser", MQTT_USER);
  cfg.mqttPass = prefs.getString("mpass", MQTT_PASSWORD);
}

static void saveIrk(const uint8_t* irk) {
  memcpy(cfg.irk, irk, 16);
  cfg.hasIrk = true;
  prefs.putBytes("irk", cfg.irk, 16);
}

// ======================================================================
// USB keyboard
// ======================================================================
static void sendWinL() {
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('l');
  delay(60);
  Keyboard.releaseAll();
}

// Wakes the lock screen when the phone comes back.
static void sendUpTwice() {
  for (int i = 0; i < 2; i++) {
    Keyboard.press(KEY_UP_ARROW);
    delay(60);
    Keyboard.releaseAll();
    delay(100);
  }
}

// ======================================================================
// BLE scanning
// ======================================================================
class ScanCB : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice* d) override {
    advCount++;
    NimBLEAddress a = d->getAddress();
    if (a.getType() != BLE_ADDR_RANDOM) return;
    const uint8_t* le = a.getNative();
    if ((le[5] & 0xC0) != 0x40) return;  // resolvable private addresses only
    rpaCount++;
    if (!irkReady) return;

    bool fwd = rpaMatches(&aesFwd, le);
    bool rev = !fwd && rpaMatches(&aesRev, le);
    if (!fwd && !rev) return;
    if (rev) reversedMatch = true;

    int rssi = d->getRSSI();
    uint32_t now = millis();
    rssiEma = seenEver ? rssiEma * 0.7f + rssi * 0.3f : (float)rssi;
    lastRssi = rssi;
    lastSeenMs = now;
    seenEver = true;
    // hysteresis: entering needs the full threshold, staying needs threshold - margin,
    // so a signal hovering at the threshold doesn't flip presence back and forth
    int need = presence == PRESENT ? cfg.threshold - cfg.margin : cfg.threshold;
    if (rssiEma >= need) lastStrongMs = now;
    readings++;
  }
};

static void startScan() {
  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->setAdvertisedDeviceCallbacks(new ScanCB(), true);  // want duplicates
  scan->setDuplicateFilter(false);
  scan->setMaxResults(0);   // don't keep results, callback only
  scan->setActiveScan(false);
  scan->setInterval(100);
  scan->setWindow(60);      // leave airtime for Wi-Fi
  scan->start(0, nullptr, false);
}

// ======================================================================
// Enrollment: advertise as a heart-rate sensor (same approach as ESPresense)
// so the iPhone can pair; the bond gives us the phone's IRK.
// ======================================================================
static volatile bool enrollDone = false;
static uint8_t enrolledIrk[16];

static bool readPeerIrk(const ble_addr_t& idAddr, uint8_t* irkMsbFirst) {
  struct ble_store_key_sec key = {};
  struct ble_store_value_sec val = {};
  key.peer_addr = idAddr;
  if (ble_store_read_peer_sec(&key, &val) != 0 || !val.irk_present) return false;
  for (int i = 0; i < 16; i++) irkMsbFirst[i] = val.irk[15 - i];  // NimBLE stores LSB-first
  return true;
}

// The bond is written to the store shortly after the pairing callback fires,
// so look through every stored bond rather than trusting the callback's timing.
static bool findBondedIrk(uint8_t* irkMsbFirst) {
  int n = NimBLEDevice::getNumBonds();
  for (int i = 0; i < n; i++) {
    NimBLEAddress a = NimBLEDevice::getBondedAddress(i);
    ble_addr_t id;
    id.type = a.getType();
    memcpy(id.val, a.getNative(), 6);
    if (readPeerIrk(id, irkMsbFirst)) return true;
  }
  return false;
}
static volatile bool enrollPaired = false;

class EnrollCB : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer* s, ble_gap_conn_desc* desc) override {
    Serial.printf("enroll: connected %s, requesting pairing\n",
                  NimBLEAddress(desc->peer_ota_addr).toString().c_str());
    NimBLEDevice::startSecurity(desc->conn_handle);
  }
  void onDisconnect(NimBLEServer* s) override {
    Serial.println("enroll: disconnected");
    if (!enrollDone) NimBLEDevice::startAdvertising();
  }
  void onAuthenticationComplete(ble_gap_conn_desc* desc) override {
    if (!desc->sec_state.encrypted) {
      Serial.println("enroll: pairing failed (on the iPhone, Forget This Device and try again)");
      return;
    }
    Serial.printf("enroll: paired (bonded=%d, id %s), reading key...\n", desc->sec_state.bonded,
                  NimBLEAddress(desc->peer_id_addr).toString().c_str());
    enrollPaired = true;  // the enrollment loop picks the IRK out of the bond store
  }
};

static void runEnrollment() {
  Serial.println();
  Serial.println("=== PAIRING MODE (3 minutes) ===");
  Serial.println("iPhone: Settings > Bluetooth > tap 'Presence Lock' and accept pairing.");
  Serial.println("If it isn't listed, use a BLE app (e.g. nRF Connect) to connect to it.");
  Serial.println("Type 'cancel' to leave pairing mode.");

  NimBLEDevice::init("Presence Lock");
  NimBLEDevice::deleteAllBonds();
  NimBLEDevice::setSecurityAuth(true, true, true);  // bond, MITM flag, secure connections
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);
  NimBLEDevice::setSecurityInitKey(BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID);
  NimBLEDevice::setSecurityRespKey(BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID);

  NimBLEServer* srv = NimBLEDevice::createServer();
  srv->setCallbacks(new EnrollCB());

  NimBLEService* hr = srv->createService("180D");
  NimBLECharacteristic* hrm = hr->createCharacteristic(
      "2A37", NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_ENC | NIMBLE_PROPERTY::NOTIFY);
  uint8_t hrv[2] = {0, 60};
  hrm->setValue(hrv, 2);

  NimBLEService* dis = srv->createService("180A");
  dis->createCharacteristic("2A29", NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::READ_ENC)
      ->setValue("Presence Lock");

  hr->start();
  dis->start();

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID("180D");
  adv->setScanResponse(true);
  adv->start();

  uint32_t start = millis(), lastTick = 0, pairedAt = 0;
  String buf;
  bool cancelled = false;
  while (!enrollDone && !cancelled && millis() - start < 180000) {
    if (enrollPaired) {
      if (!pairedAt) pairedAt = millis();
      if (findBondedIrk(enrolledIrk)) enrollDone = true;
      else if (millis() - pairedAt > 10000) {
        Serial.printf("enroll: paired but no IRK found in %d stored bond(s)\n", NimBLEDevice::getNumBonds());
        enrollPaired = false;
        pairedAt = 0;
      }
    }
    while (Serial.available()) {
      char c = Serial.read();
      if (c == '\r' || c == '\n') { buf.trim(); if (buf == "cancel") cancelled = true; buf = ""; }
      else if (buf.length() < 20) buf += c;
    }
    if (millis() - lastTick > 1000) {
      lastTick = millis();
      Serial.printf("@{\"t\":\"p\",\"left\":%lu}\n", (180000 - (millis() - start)) / 1000);
    }
    delay(50);
  }

  if (enrollDone) {
    saveIrk(enrolledIrk);
    Serial.println("enroll: got IRK " + hex(enrolledIrk, 16));
    Serial.println("enroll: done. On the iPhone you can now Forget 'Presence Lock'; tracking still works.");
  } else {
    Serial.println(cancelled ? "enroll: cancelled" : "enroll: timed out");
  }
  delay(1500);
  ESP.restart();
}

// ======================================================================
// Wi-Fi / MQTT (publish only)
// ======================================================================
static uint32_t lastMqttTry = 0;
static int lastMqttState = 0;

static void connectWifi() {
  WiFi.disconnect();
  if (cfg.wifiSsid.length()) WiFi.begin(cfg.wifiSsid.c_str(), cfg.wifiPass.c_str());
}

static void applyMqttServer() {
  mqtt.disconnect();
  mqtt.setServer(cfg.mqttHost.c_str(), cfg.mqttPort);  // keeps the pointer; cfg owns it
  lastMqttTry = 0;
}

static void publishDiscovery() {
  String dev = "\"dev\":{\"ids\":[\"presence_lock_" + devId +
               "\"],\"name\":\"Presence Lock\",\"mf\":\"DIY\",\"mdl\":\"ESP32-S3\"}";
  String avty = "\"avty_t\":\"" + topicBase + "/status\"";

  String p = "{\"name\":\"Phone in room\",\"uniq_id\":\"presence_lock_" + devId +
             "_presence\",\"dev_cla\":\"occupancy\",\"stat_t\":\"" + topicBase +
             "/presence\"," + avty + "," + dev + "}";
  mqtt.publish(("homeassistant/binary_sensor/presence_lock_" + devId + "/presence/config").c_str(),
               p.c_str(), true);

  String r = "{\"name\":\"Phone signal\",\"uniq_id\":\"presence_lock_" + devId +
             "_rssi\",\"dev_cla\":\"signal_strength\",\"unit_of_meas\":\"dBm\","
             "\"stat_cla\":\"measurement\",\"ent_cat\":\"diagnostic\",\"stat_t\":\"" +
             topicBase + "/rssi\"," + avty + "," + dev + "}";
  mqtt.publish(("homeassistant/sensor/presence_lock_" + devId + "/rssi/config").c_str(),
               r.c_str(), true);
}

static void publishPresence() {
  if (!mqtt.connected() || presence == UNKNOWN) return;
  mqtt.publish((topicBase + "/presence").c_str(), presence == PRESENT ? "ON" : "OFF", true);
}

static void mqttLoop() {
  if (WiFi.status() != WL_CONNECTED || !cfg.mqttHost.length()) return;
  if (!mqtt.connected()) {
    if (lastMqttTry && millis() - lastMqttTry < 5000) return;
    lastMqttTry = millis();
    String will = topicBase + "/status";
    if (mqtt.connect(("presence-lock-" + devId).c_str(), cfg.mqttUser.c_str(), cfg.mqttPass.c_str(),
                     will.c_str(), 0, true, "offline")) {
      event("mqtt: connected");
      mqtt.publish(will.c_str(), "online", true);
      publishDiscovery();
      publishPresence();
    } else if (mqtt.state() != lastMqttState) {
      event(String("mqtt: connect failed (") +
            (mqtt.state() == 5 ? "bad username/password" :
             mqtt.state() == 4 ? "bad username/password" :
             mqtt.state() == -2 ? "can't reach broker" : "state " + String(mqtt.state())) + ")");
    }
    lastMqttState = mqtt.state();
    return;
  }
  mqtt.loop();
}

// ======================================================================
// Status output
// ======================================================================
static const char* presenceName() {
  return presence == PRESENT ? "PRESENT" : presence == AWAY ? "AWAY" : "UNKNOWN";
}

static void printStatusJson() {
  uint32_t now = millis();
  String s = "@{\"t\":\"s\",\"id\":" + jstr(devId) +
             ",\"selftest\":" + (selfTestOk ? "true" : "false") +
             ",\"irk\":" + jstr(cfg.hasIrk ? hex(cfg.irk, 16) : "") +
             ",\"irkReversed\":" + (reversedMatch ? "true" : "false") +
             ",\"presence\":\"" + presenceName() + "\"" +
             ",\"seen\":" + (seenEver ? "true" : "false") +
             ",\"rssi\":" + String((int)lastRssi) +
             ",\"avg\":" + String((float)rssiEma, 1) +
             ",\"seenAgo\":" + String(seenEver ? (long)((now - lastSeenMs) / 1000) : -1L) +
             ",\"strongAgo\":" + String(seenEver ? (long)((now - lastStrongMs) / 1000) : -1L) +
             ",\"threshold\":" + String(cfg.threshold) +
             ",\"margin\":" + String(cfg.margin) +
             ",\"away\":" + String(cfg.awaySec) +
             ",\"lock\":" + (cfg.lockEnabled ? "true" : "false") +
             ",\"ssid\":" + jstr(cfg.wifiSsid) +
             ",\"wifiPassSet\":" + (cfg.wifiPass.length() ? "true" : "false") +
             ",\"ip\":" + jstr(WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString() : "") +
             ",\"wifiRssi\":" + String(WiFi.status() == WL_CONNECTED ? WiFi.RSSI() : 0) +
             ",\"mqttHost\":" + jstr(cfg.mqttHost) +
             ",\"mqttPort\":" + String(cfg.mqttPort) +
             ",\"mqttUser\":" + jstr(cfg.mqttUser) +
             ",\"mqttPassSet\":" + (cfg.mqttPass.length() ? "true" : "false") +
             ",\"mqtt\":" + (mqtt.connected() ? "true" : "false") +
             ",\"uptime\":" + String(now / 1000) + "}";
  Serial.println(s);
}

static void printStatus() {
  uint32_t now = millis();
  Serial.printf("Self-test:  %s\n", selfTestOk ? "PASS" : "FAIL");
  Serial.printf("IRK:        %s%s\n", cfg.hasIrk ? hex(cfg.irk, 16).c_str() : "(none - run 'enroll')",
                reversedMatch ? "  (matched reversed; run 'fixirk')" : "");
  Serial.printf("Scanner:    %s, %lu adverts, %lu private addresses, %lu phone matches\n",
                NimBLEDevice::getScan()->isScanning() ? "running" : "STOPPED", (unsigned long)advCount,
                (unsigned long)rpaCount, (unsigned long)readings);
  Serial.printf("Presence:   %s\n", presenceName());
  if (seenEver)
    Serial.printf("Phone:      last rssi %d, avg %.1f, seen %lus ago, strong %lus ago\n", (int)lastRssi,
                  (float)rssiEma, (now - lastSeenMs) / 1000, (now - lastStrongMs) / 1000);
  else
    Serial.println("Phone:      not seen since boot");
  Serial.printf("Threshold:  %d dBm (stays present down to %d dBm)\nAway after: %lu s\nLocking:    %s\n",
                cfg.threshold, cfg.threshold - cfg.margin, cfg.awaySec, cfg.lockEnabled ? "on" : "off");
  Serial.printf("Wi-Fi:      %s %s\n", cfg.wifiSsid.length() ? cfg.wifiSsid.c_str() : "(not set)",
                WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString().c_str() : "not connected");
  Serial.printf("MQTT:       %s:%u %s\n", cfg.mqttHost.c_str(), cfg.mqttPort,
                mqtt.connected() ? "connected" : "not connected");
}

// ======================================================================
// Serial commands (local USB only)
// ======================================================================
static void printHelp() {
  Serial.println("Commands:");
  Serial.println("  status            show current state");
  Serial.println("  watch             toggle printing every phone reading");
  Serial.println("  enroll            restart into iPhone pairing mode (or hold BOOT 3s)");
  Serial.println("  irk <32 hex>      set the IRK by hand");
  Serial.println("  fixirk            store the IRK byte-reversed");
  Serial.println("  threshold <dBm>   e.g. threshold -72");
  Serial.println("  margin <dB>       once present, stay present this far below threshold, e.g. margin 6");
  Serial.println("  away <seconds>    e.g. away 45");
  Serial.println("  lock on|off       enable/disable Win+L");
  Serial.println("  testlock          send Win+L now");
  Serial.println("  testwake          send Up arrow twice now");
  Serial.println("  set <key> <value> wifi_ssid wifi_pass mqtt_host mqtt_port mqtt_user mqtt_pass");
  Serial.println("  reconnect         reconnect Wi-Fi and MQTT with the saved settings");
}

static void enterEnrollOnReboot() {
  prefs.putBool("enroll", true);
  event("Restarting into pairing mode...");
  delay(300);
  ESP.restart();
}

static void handleSet(const String& arg) {
  int sp = arg.indexOf(' ');
  String key = sp > 0 ? arg.substring(0, sp) : arg;
  String val = sp > 0 ? arg.substring(sp + 1) : "";  // may contain spaces
  key.toLowerCase();
  if (key == "wifi_ssid") { cfg.wifiSsid = val; prefs.putString("wssid", val); }
  else if (key == "wifi_pass") { cfg.wifiPass = val; prefs.putString("wpass", val); }
  else if (key == "mqtt_host") { val.trim(); cfg.mqttHost = val; prefs.putString("mhost", val); }
  else if (key == "mqtt_port" && val.toInt() > 0) { cfg.mqttPort = val.toInt(); prefs.putUShort("mport", cfg.mqttPort); }
  else if (key == "mqtt_user") { cfg.mqttUser = val; prefs.putString("muser", val); }
  else if (key == "mqtt_pass") { cfg.mqttPass = val; prefs.putString("mpass", val); }
  else { Serial.println("unknown setting"); return; }
  Serial.println(key + " saved");  // never echo the value (could be a password)
}

static void handleCommand(String line) {
  // strip only the line ending so values in 'set' keep their spaces
  while (line.length() && (line.endsWith("\r") || line.endsWith("\n"))) line.remove(line.length() - 1);
  String cmd = line, arg;
  int sp = line.indexOf(' ');
  if (sp > 0) { cmd = line.substring(0, sp); arg = line.substring(sp + 1); }
  cmd.trim();
  cmd.toLowerCase();

  if (cmd == "status") printStatus();
  else if (cmd == "jstatus") printStatusJson();
  else if (cmd == "stream") { stream = arg.startsWith("on"); if (stream) printStatusJson(); }
  else if (cmd == "watch") { watch = !watch; Serial.printf("watch %s\n", watch ? "on" : "off"); }
  else if (cmd == "enroll") enterEnrollOnReboot();
  else if (cmd == "set") handleSet(arg);
  else if (cmd == "reconnect") { connectWifi(); applyMqttServer(); event("reconnecting Wi-Fi and MQTT"); }
  else if (cmd == "irk") {
    uint8_t k[16];
    if (!parseHex(arg, k, 16)) { Serial.println("need 32 hex characters"); return; }
    saveIrk(k);
    reversedMatch = false;
    loadIrkContexts();
    event("IRK saved");
  } else if (cmd == "fixirk" && cfg.hasIrk) {
    uint8_t k[16];
    for (int i = 0; i < 16; i++) k[i] = cfg.irk[15 - i];
    saveIrk(k);
    reversedMatch = false;
    loadIrkContexts();
    event("IRK reversed and saved");
  } else if (cmd == "threshold" && arg.length()) {
    cfg.threshold = constrain(arg.toInt(), -110, -20);
    prefs.putInt("thresh", cfg.threshold);
    Serial.printf("threshold %d dBm\n", cfg.threshold);
  } else if (cmd == "margin" && arg.length()) {
    cfg.margin = constrain(arg.toInt(), 0, 20);
    prefs.putInt("margin", cfg.margin);
    Serial.printf("margin %d dB (stays present down to %d dBm)\n", cfg.margin, cfg.threshold - cfg.margin);
  } else if (cmd == "away" && arg.toInt() > 0) {
    cfg.awaySec = constrain(arg.toInt(), 5, 3600);
    prefs.putUInt("away", cfg.awaySec);
    Serial.printf("away after %lu s\n", cfg.awaySec);
  } else if (cmd == "lock") {
    cfg.lockEnabled = arg.startsWith("on");
    prefs.putBool("lock", cfg.lockEnabled);
    Serial.printf("locking %s\n", cfg.lockEnabled ? "on" : "off");
  } else if (cmd == "testlock") { sendWinL(); event("sent Win+L (test)"); }
  else if (cmd == "testwake") { sendUpTwice(); event("sent Up x2 (test)"); }
  else if (cmd == "bootloader") {
    // used by flash.ps1; serial-line tricks are disabled so the board can't
    // fall into download mode when a program opens or closes the port
    Serial.println("entering bootloader for flashing");
    delay(200);
    // hands the USB pins back to the built-in USB-Serial/JTAG before restarting;
    // a bare force-download restart leaves the ROM with no USB the PC can see
    usb_persist_restart(RESTART_BOOTLOADER);
  }
  else if (cmd.length()) printHelp();
}

static void serialLoop() {
  static String buf;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\r' || c == '\n') { if (buf.length()) handleCommand(buf); buf = ""; }
    else if (buf.length() < 200) buf += c;
  }
}

// ======================================================================

void setup() {
  pinMode(BOOT_PIN, INPUT_PULLUP);
  Keyboard.begin();
  USB.begin();
  Serial.enableReboot(false);  // flash.ps1 sends 'bootloader' instead
  Serial.begin(115200);
  delay(1500);

  uint8_t mac[6];
  WiFi.macAddress(mac);
  char id[7];
  snprintf(id, sizeof(id), "%02x%02x%02x", mac[3], mac[4], mac[5]);
  devId = id;
  topicBase = "presence_lock/" + devId;

  loadSettings();
  selfTestOk = selfTest();
  Serial.printf("\nPresence Lock %s - self-test %s\n", devId.c_str(), selfTestOk ? "PASS" : "FAIL");

  if (prefs.getBool("enroll", false)) {
    prefs.putBool("enroll", false);
    runEnrollment();  // restarts when done
  }

  mbedtls_aes_init(&aesFwd);
  mbedtls_aes_init(&aesRev);
  loadIrkContexts();
  if (!cfg.hasIrk) Serial.println("No IRK yet - type 'enroll' to pair your iPhone.");

  WiFi.mode(WIFI_STA);
  WiFi.setHostname(("presence-lock-" + devId).c_str());
  connectWifi();
  mqtt.setBufferSize(768);
  applyMqttServer();

  NimBLEDevice::init("");
  // A bond left over from pairing puts the phone's IRK in the controller's
  // resolving list, which then reports the phone by its identity address
  // instead of the rotating RPAs we match on. We only need our own IRK copy.
  if (NimBLEDevice::getNumBonds()) NimBLEDevice::deleteAllBonds();
  startScan();
  printHelp();
}

void loop() {
  serialLoop();
  mqttLoop();

  // hold BOOT for 3 s -> pairing mode
  static uint32_t bootDown = 0;
  if (digitalRead(BOOT_PIN) == LOW) {
    if (!bootDown) bootDown = millis();
    else if (millis() - bootDown > 3000) enterEnrollOnReboot();
  } else bootDown = 0;

  static wl_status_t lastWifi = WL_IDLE_STATUS;
  if (WiFi.status() != lastWifi) {
    lastWifi = WiFi.status();
    if (lastWifi == WL_CONNECTED) event("wifi: connected, " + WiFi.localIP().toString());
    else if (lastWifi == WL_NO_SSID_AVAIL) event("wifi: network not found (2.4 GHz only)");
    else if (lastWifi == WL_CONNECT_FAILED) event("wifi: connect failed, check the password");
  }

  uint32_t now = millis();

  // readings arrive on the BLE task; report the newest one from here
  static uint32_t lastReported = 0;
  if (readings != lastReported) {
    lastReported = readings;
    if (watch) Serial.printf("phone rssi %d avg %.1f\n", (int)lastRssi, (float)rssiEma);
    if (stream) Serial.printf("@{\"t\":\"r\",\"rssi\":%d,\"avg\":%.1f}\n", (int)lastRssi, (float)rssiEma);
  }
  static uint32_t lastStatus = 0;
  if (stream && now - lastStatus > 1000) { lastStatus = now; printStatusJson(); }

  // when the phone was last strongly seen before it went away (0 = not since boot)
  static uint32_t goneSinceMs = 0;

  Presence next = presence;
  if (seenEver && now - lastStrongMs < cfg.awaySec * 1000UL && rssiEma >= cfg.threshold)
    next = PRESENT;
  else if (seenEver && presence == PRESENT && now - lastStrongMs >= cfg.awaySec * 1000UL)
    next = AWAY;
  else if (presence == UNKNOWN && now > cfg.awaySec * 1000UL)
    next = AWAY;  // never seen strongly since boot: report away, but don't lock

  if (next != presence) {
    Presence prev = presence;
    // read before the state change: lastStrongMs keeps moving once the phone is back
    if (next == AWAY) goneSinceMs = seenEver ? (uint32_t)lastStrongMs : 0;
    presence = next;
    event(String("presence: ") + presenceName());
    publishPresence();
    if (prev == PRESENT && presence == AWAY && cfg.lockEnabled) {
      sendWinL();
      event("locked PC (Win+L)");
    }
    // the BLE task already set lastStrongMs to now, so time the absence from goneSinceMs
    if (prev == AWAY && presence == PRESENT && now - goneSinceMs >= WAKE_AFTER_GONE_MS) {
      sendUpTwice();
      event("phone back after " + String((now - goneSinceMs) / 1000) + " s, pressed Up x2");
    }
  }

  static uint32_t lastRssiPub = 0;
  if (mqtt.connected() && seenEver && now - lastRssiPub > 10000 && now - lastSeenMs < 10000) {
    lastRssiPub = now;
    mqtt.publish((topicBase + "/rssi").c_str(), String((int)lastRssi).c_str());
  }

  delay(20);
}
