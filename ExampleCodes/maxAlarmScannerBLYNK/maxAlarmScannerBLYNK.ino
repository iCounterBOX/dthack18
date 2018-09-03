/** WifiScan  + Hash + OLED + BLYNK in async Mode
Author: Mrs. Christin Koss

please also check the wiki:
https://github.com/iCounterBOX/dthack18/wiki/dthack18---maxAlarmScannerBLYNK
https://github.com/iCounterBOX/dthack18/blob/master/ExampleCodes/maxAlarmScannerBLYNK/maxAlarmScannerBLYNK.ino


fix / while-loop..

original:
void connectWiFi(const char* ssid, const char* pass)
{
BLYNK_LOG2(BLYNK_F("Connecting to "), ssid);
WiFi.mode(WIFI_STA);
if (WiFi.status() != WL_CONNECTED) {
if (pass && strlen(pass)) {
WiFi.begin(ssid, pass);
} else {
WiFi.begin(ssid);
}
}
while (WiFi.status() != WL_CONNECTED) {		// might be endless in case of an issue with wifi connection or   re-connection
BlynkDelay(500);
}
BLYNK_LOG1(BLYNK_F("Connected to WiFi"));

IPAddress myip = WiFi.localIP();
BLYNK_LOG_IP("IP: ", myip);
}

The FIX:

//Christin Koss / CK / ITcon :26.08.18 - No endles loop..mcu might hang we leave the loop
int wifiCounter = 0;
while (WiFi.status() != WL_CONNECTED) {
BlynkDelay(500);
Serial.print("BLYNK loop wifi waiting  for connection/ new Wifi-State: ");
Serial.println(WiFi.status());
//12.12.17/ nach 100 Versuchen Resetten wir den chip
if (++wifiCounter >= 100) {
Serial.println("WIFI_Connect()/ NO WIFI  !! RESET");
wifiCounter = 0;
wdt_reset(); ESP.restart(); while (1)wdt_reset();		//ESP.restart();
break;
}
}

*/

// Details and code ASAP..


