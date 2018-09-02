/** WifiScan  + Hash + OLED + BLYNK in async Mode

please also check the wiki:

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

//KRISTINA / CK / ITcon :26.08.18 - No endles loop..mcu might hang we leave the loop
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



#include <SPI.h>
#include <TimeLib.h>
#include <Hash.h>

//OLED DISPLAY I2C 
#include <Wire.h>		// 
#include <SSD1306Ascii.h>
#include <SSD1306AsciiWire.h>	// Original .h  zZ ein 64 Bit Display  - https://github.com/adafruit/Adafruit_SSD1306/issues/57

// BLYNK
/* Comment this out to disable prints and save space - macht eine BLYNK grafik  und gibt status aus zwischendurch */
#define BLYNK_PRINT Serial
#include <ESP8266WiFi.h>
#include <BlynkSimpleEsp8266.h>


//4 the sniffer:
#include <user_interface.h>
extern "C" {
#include <cont.h>
	extern cont_t g_cont;
}

#define DISABLE 0
#define ENABLE 1

//Specify digital pin on the Arduino that the positive lead of piezo buzzer is attached.
int piezoPin = D6;			// D3 normaler weise 
int _PiezoFreq = 1000;


int _payloadMaxCounter = 0;


int oledRowCount = 0;
float _BetrStdZaehler = 0;
// 0X3C+SA0 - 0x3C or 0x3D
#define I2C_ADDRESS 0x3C
// Define proper RST_PIN if required.
#define RST_PIN -1
SSD1306AsciiWire oled;

// ERROR - COUNTER

#define _ESP_ERR_COUNT_LIMIT 50		// Auslöser für den Reset wenn dieser Schwellwert erreicht ist
uint16 _ESP_ERROR_COUNTER = 0;

//>>>>>>> Configure the SNIFFER Stuff  ++  Configure the SNIFFER Stuff  ++  Configure the SNIFFER Stuff  <<<<<<<<<


// You should get Auth Token in the Blynk App.
// Go to the Project Settings (nut icon).
char auth[] = "the authCode from Blynk";


//wlanRouter @ Home
char ssid[] = "yourAPssid";
char pass[] = "yourAPpw";


int _BLYNK_numInput_MaxDevicesAllowed = 20;
bool gotTerminalData = false;
bool gotLCDdata = false;
bool PROMISCUOUS_MODE_ON = true;
WidgetLCD lcd(V4);
WidgetTerminal terminal(V2);

// TimeFrames Tick Tack
unsigned long CHANNEL_HOP_INTERVAL_MS = 1000;
unsigned long CHANNEL_HOP_previousMillis = 0;

/*
GEZIELTES RESETTEN DIESER ANWENDUNG ALL paar MINUTEN  -  RESET_ME_TIMER
10 min = 600000
20 min = 120000
*/
unsigned long RESET_OUTER_LOOP_LONG_TIMER = 60000;
unsigned long refreshTheLoopTimer_passedMillies = 0;

// A Struct Array to keep the sniffed MAC devices - 

bool dataPackReady = false;
int MACdeviceDataIndex = 0;	    // Index of this Struct Array

#define MAX_MAC_DEVICES_IN_ARRAY 400
struct payload_t
{
	uint8_t myNodeId;
	float hrs = 0;		// BtriebsStundenZähler	
	uint32_t mac[MAX_MAC_DEVICES_IN_ARRAY];		// anomysierte MAC  uint32 hat 4 byte  - https://de.wikibooks.org/wiki/C-Programmierung_mit_AVR-GCC/_Datentypen
};

payload_t _MacDevicePayload;


// 4 the sniffer --the data-structure

// The setup function is called once at startup of the sketch
#define DATA_LENGTH 112
#define TYPE_MANAGEMENT 0x00
#define TYPE_CONTROL 0x01
#define TYPE_DATA 0x02
#define SUBTYPE_PROBE_REQUEST 0x04

struct RxControl
{
	signed rssi : 8; // signal intensity of packet
	unsigned rate : 4;
	unsigned is_group : 1;
	unsigned : 1;
	unsigned sig_mode : 2;       // 0:is 11n packet; 1:is not 11n packet;
	unsigned legacy_length : 12; // if not 11n packet, shows length of packet.
	unsigned damatch0 : 1;
	unsigned damatch1 : 1;
	unsigned bssidmatch0 : 1;
	unsigned bssidmatch1 : 1;
	unsigned MCS : 7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
	unsigned CWB : 1; // if is 11n packet, shows if is HT40 packet or not
	unsigned HT_length : 16; // if is 11n packet, shows length of packet.
	unsigned Smoothing : 1;
	unsigned Not_Sounding : 1;
	unsigned : 1;
	unsigned Aggregation : 1;
	unsigned STBC : 2;
	unsigned FEC_CODING : 1; // if is 11n packet, shows if is LDPC packet or not.
	unsigned SGI : 1;
	unsigned rxend_state : 8;
	unsigned ampdu_cnt : 8;
	unsigned channel : 4; // which channel this packet in.
	unsigned : 12;
};

struct SnifferPacket
{
	struct RxControl rx_ctrl;
	uint8_t data[DATA_LENGTH];
	uint16_t cnt;
	uint16_t len;
};

// **********  CODE Section *********************************************************************

void IoT_WatchDog(bool active) 	// Schaltet	den IoT	-	Brick	-	Watchdog ein(true) oder aus(false)
{
	ESP.wdtFeed();
	// Watchdog Timer zurücksetzen
	if (active)
	{
		ESP.wdtEnable(65535);		// Watchdog Timer einschalten auf 5 Sekunden (5000 ms	.)
	}
	else
	{
		ESP.wdtDisable();		// Watchdog Timer ausschalten
	}
	ESP.wdtFeed();	// Watchdog Timer zurücksetzen
}


// gibt die BetriebsStunden als decimal wert zurück
float betriebsStundenCounter() {
	return hour() + ((float)minute() / 60) + ((float)second() / 3600);
}


long RAMfree(const char *str)
{
	//ESP.getVcc()  uu die Betriebspannung überwachen
	long s, h;
	Serial.printf("\n %s - Heap free = \'%d\', Stack free = \'%d\', Stack guard bytes were ", str, (h = system_get_free_heap_size()), (s = cont_get_free_stack(&g_cont)));
	if (!cont_check(&g_cont)) {
		Serial.printf("NOT ");
	}
	Serial.println("overwritten");
	return (s + h);
}

/*Tone needs 2 arguments, but can take three
1) Pin#
2) Frequency - this is in hertz (cycles per second) which determines the pitch of the noise made
3) Duration - how long teh tone plays
*/

void alarmSound() {

	tone(piezoPin, 4500, 1);

	//_PiezoFreq += 100;
	//if (_PiezoFreq >= 5000) _PiezoFreq = 1000;
	//Serial.print("PiezoFreq: "); Serial.println(_PiezoFreq);
	//delay(1000);

}





// device MAC without :
static void getMAC(char* addr, uint8_t* data, uint16_t offset)
{
	sprintf(addr, "%02x%02x%02x%02x%02x%02x", data[offset + 0], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]);
}


// device MAC without :
uint32_t getMACanonym(uint8_t* data, uint16_t offset)
{
	char mac[] = "e8abfa2d7f2f";
	sprintf(mac, "%02x%02x%02x%02x%02x%02x", data[offset + 0], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]);
	return adler32((byte*)mac, 10);
}


// check if MAC is in our macArray  0...n  ist die gefundene Position    -1 NICHT gefunden

int16_t findMacInArray(uint32_t mac) {

	for (uint16_t i = 0; _MacDevicePayload.mac[i] != 0; i++) {
		if (i >= MAX_MAC_DEVICES_IN_ARRAY) return -1;
		if ((_MacDevicePayload.mac[i] == mac)) {
			return i;					// i oder i -1  ????
		}
	}
	return -1;
}

// das struct bei(struct SnifferPacket* hatte gefehlt !!deshalb compile fehler !!
static void showMetadata(struct SnifferPacket* snifferPacket)
{
	unsigned int frameControl = ((unsigned int)snifferPacket->data[1] << 8) + snifferPacket->data[0];
	// uint8_t version      = (frameControl & 0b0000000000000011) >> 0;
	uint8_t frameType = (frameControl & 0b0000000000001100) >> 2;
	uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
	// uint8_t toDS         = (frameControl & 0b0000000100000000) >> 8;
	// uint8_t fromDS       = (frameControl & 0b0000001000000000) >> 9;

	// Only look for probe request packets
	if (frameType != TYPE_MANAGEMENT || frameSubType != SUBTYPE_PROBE_REQUEST)
	{
		//Serial.println("showMetadata() - bedingung nicht erfüllt: frameType != TYPE_MANAGEMENT || frameSubType != SUBTYPE_PROBE_REQUEST --- RETURN ");
		return;
	}

	//RAMfree("showMetadata()");

	//Serial.print(" RSSI: "); Serial.print(snifferPacket->rx_ctrl.rssi, DEC);
	//Serial.print(" Ch: ");  Serial.print(wifi_get_channel());


	alarmSound();  // NEW !!

	char deviceMacAddr[] = "000000000000";
	getMAC(deviceMacAddr, snifferPacket->data, 10);
	Serial.println("<> ADLER32: "); Serial.print(deviceMacAddr);

	uint32_t aMAC = getMACanonym(snifferPacket->data, 10);
	Serial.print(" = "); Serial.print(aMAC);

	int16_t pos = findMacInArray(aMAC);
	if (pos == -1) {
		// neue MAC .. -1  Nicht gefunden !
		if (MACdeviceDataIndex < MAX_MAC_DEVICES_IN_ARRAY) {
			_MacDevicePayload.mac[MACdeviceDataIndex++] = aMAC;
		}
		else {
			Serial.println("Concatination of NEW MAC not possible - To many DATA !!!!!!!!!");
		}
	}
	else {
		//Serial.print("found ["); Serial.print(aMAC); Serial.print("] at Pointer-pos / ignore! "); Serial.println(pos);
	}



	// dataset for THIS CHANEL ist finished !!}
}

/**
* Callback for promiscuous mode
*Meaning of ICACHE_FLASH_ATTR : http://bbs.espressif.com/viewtopic.php?t=1183
*Die bedeutung ist wohl nicht ganz klar!?
*/
static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t* buffer, uint16_t length)
{
	//Serial.print("sniffer_callback()/length: "); Serial.println(length);
	struct SnifferPacket* snifferPacket = (struct SnifferPacket*)buffer;
	showMetadata(snifferPacket);
}




/* Prüfen ob der ErrorCounter den kritischen Schwellwert überschriffen hat
ESP.reset() is a hard reset and can leave some of the registers in the old state which can lead to problems, its more or less like the reset button on the PC.
ESP.restart() tells the SDK to reboot, so its a more clean reboot, use this one if possible.
the boot mode:(1,7) problem is known and only happens at the first restart after serial flashing.
if you do one manual reboot by power or RST pin all will work more info see: #1017
*/
void Check_ESP_ErrCounter() {
	if (_ESP_ERROR_COUNTER >= _ESP_ERR_COUNT_LIMIT) {
		Serial.print("_ESP_ERROR_COUNTER exeed the limit: "); Serial.println(_ESP_ERR_COUNT_LIMIT);
		Serial.print("WE RESTART THE ESP - NOW !!!!!!!!!!!!!! ");
		oled.println("ESP_ERR_COUNTER! - REST NOW");  CheckOledMessage();		// check after each oled.println
		oled.println("ESP_ERR_COUNTER! - REST NOW");  CheckOledMessage();		// check after each oled.println
																				// ???? https://github.com/esp8266/Arduino/issues/1722
		wdt_reset(); ESP.restart(); while (1)wdt_reset();		//ESP.restart();
	}
}


void CheckOledMessage() {
	//Display  ** Display  ** Dosplay ************************
	if (oledRowCount >= 8) {	//bei 128 x 32  sind das 4   or bei 128 x 64  sind das 8
		oledRowCount = 0;
		oled.clear();		//oled.set1X();  //  alles ist auf 1 ..	
		oled.print("S ");  oled.print((float)betriebsStundenCounter(), 2); oled.print(" H"); oled.print(system_get_free_heap_size()); oled.print(" !_");	oled.println(_ESP_ERROR_COUNTER);	// check after each oled.println		
	}
	++oledRowCount;	// jedes CRLF ist eine Zeile und zählt als rowCount	
}


void sendDataPack()
{
	//eigentliches SENDEN - DIRECT zum COMMUNICATER 

	RAMfree("sendDataPack()");

	for (uint16_t i = 0; _MacDevicePayload.mac[i] != 0; i++) {
		Serial.print(_MacDevicePayload.mac[i]); Serial.print(",");
	}
	Serial.println();

	_MacDevicePayload.myNodeId = 99;
	_MacDevicePayload.hrs = betriebsStundenCounter();

	Serial.print("BetriebsStundenZaehler: "); Serial.println(_MacDevicePayload.hrs);

	if (MACdeviceDataIndex > 0 && MACdeviceDataIndex < MAX_MAC_DEVICES_IN_ARRAY) {
		// OK 
	}
	else
	{
		Serial.println("Payload to LONG or EMPTY");
		_MacDevicePayload.mac[0] = 0;	// Dann nur Hülle senden...damit Master uns nicht weg hängt
		oled.println("Payload to LONG or EMPTY"); CheckOledMessage();
	}

	//Für das OLED   OLED   OLED   OLED   OLED   OLED - https://github.com/greiman/SSD1306Ascii

	oled.print("n");  oled.print(99);	 oled.print("*");  oled.print((float)betriebsStundenCounter(), 2); 	oled.print("["); oled.print((String)MACdeviceDataIndex); oled.print("]");


	//network.update();                          // Check the network regularly
	if (MACdeviceDataIndex >= _payloadMaxCounter) _payloadMaxCounter = MACdeviceDataIndex; // sonst sehen wir den count nicht, wenn kein netz!


	Serial.println("ok.\n");
	oled.print(" "); oled.println(_payloadMaxCounter); CheckOledMessage();

}

/*
?? hier sehe ich nur 8 Stellen  hex? - http://www.unit-conversion.info/texttools/adler-32/#data
andere formel: https://calc.pw/de/
*/
const uint32_t MOD_ADLER = 65521;
uint32_t adler32(unsigned char *data, size_t len)
/*
where data is the location of the data in physical memory and
len is the length of the data in bytes
*/
{
	uint32_t a = 1, b = 0;
	size_t index;

	// Process each byte of the data in order
	for (index = 0; index < len; ++index)
	{
		a = (a + data[index]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}
	return (b << 16) | a;
}

void setup() {

	Serial.begin(115200);
	Serial.println("\nHI..THIS is SCANNER-Node! Part of the RF24 Mesh!");
	RAMfree("setup");

	//KEINE LED mehr NUR noch OLED

	Wire.begin(D1, D4); // sda, scl ok: (D1,D2)
	Wire.setClock(400000L);
#if RST_PIN >= 0
	oled.begin(&Adafruit128x64, I2C_ADDRESS, RST_PIN);
#else // RST_PIN >= 0
	oled.begin(&Adafruit128x64, I2C_ADDRESS);
#endif // RST_PIN >= 0
	oled.setFont(Adafruit5x7);
	oled.clear();
	oled.set1X();
	oledRowCount = 0;
	oled.clear();
	oled.print("S");  oled.print(99);	 oled.print("*");  oled.print((float)betriebsStundenCounter(), 2); oled.print(" H"); oled.print(system_get_free_heap_size()); oled.print(" !_");	oled.println(_ESP_ERROR_COUNTER);
	CheckOledMessage();

	IoT_WatchDog(true);
	Serial.printf("ESP8266 OWN MAC getChipId(): ESP_%08X\n", ESP.getChipId());  // https://github.com/esp8266/Arduino/issues/2309

																				//BLYNK
	Blynk.begin(auth, ssid, pass);
	Serial.println("BLYNK: Clear terminal and LCD.. ");
	terminal.clear();
	// This will print Blynk Software version to the Terminal Widget when
	// your hardware gets connected to Blynk Server
	terminal.println(F("Blynk v" BLYNK_VERSION ": Device started"));
	terminal.println(F("----------------------------------------"));
	terminal.println(F("Terminal is showing some State from the NodeMCU!"));

	lcd.clear();
	lcd.print(0, 0, "hrs:"); lcd.print(12, 0, 0);
	lcd.print(0, 1, "MaxLoad:"); lcd.print(12, 1, 0);

	//initialize the _BLYNK_numInput_MaxDevicesAllowed with some value
	Blynk.virtualWrite(V3, 20);

	//Level H
	Blynk.virtualWrite(V1, 0);

	terminal.flush();

	gotTerminalData = false;
	Serial.println("\n SETUP() - Blynk connected OK ");


	delay(6000);

	//----------------  The SNIFFER SETUP SECTOR -------------------------------------------------------------------------

	Serial.println("setup(): start & set Station_Mode & wifi_promiscuous...");

	wifi_set_opmode(STATION_MODE);
	wifi_set_channel(1);
	wifi_promiscuous_enable(DISABLE);
	delay(10);
	wifi_set_promiscuous_rx_cb(sniffer_callback);
	delay(10);
	wifi_promiscuous_enable(ENABLE);
	Serial.println("setup(): start & set Station_Mode wifi_promiscuous_enable(ENABLE)... - DONE!");
	delay(10);



	// ----  HEAP -----------------------------------------------------------------------------------------------------

	RAMfree("setup");

	//Set timer   BetriebsStunden-Zähler

	setTime(0, 0, 0, 0, 0, 2018);


	// weniger daten...sh1 gubt sehr lange strings zurück !! https://en.wikipedia.org/wiki/Adler-32
	// see also: https://stackoverflow.com/questions/4567089/hash-function-that-produces-short-hashes
}

int lastConnectionAttempt = millis();
int connectionDelay = 2000; // try to reconnect every 5 seconds


void WIFI_Connect()
{
	// check WiFi connection:
	if (WiFi.status() != WL_CONNECTED)
	{
		// (optional) "offline" part of code

		// check delay:
		if (millis() - lastConnectionAttempt >= connectionDelay)
		{
			lastConnectionAttempt = millis();

			// attempt to connect to Wifi network:
			if (pass && strlen(pass))
			{
				WiFi.begin((char*)ssid, (char*)pass);
			}
			else
			{
				WiFi.begin((char*)ssid);
			}
		}
	}

}

/*
Diese version hat funktioniert
durch das channelHopping wird scheinbar der ganze socket gekillt.
nur connect hat NICHT gereicht
wir bauen die Verbindung FRISCH auf
Noch genauer prüfen:  //if (gotTerminalData == true) break;   uu dann die while früher verlassen?

prüfen:

https://community.blynk.cc/t/temp-monitor-with-sms-alarm/3064/4
// send email temp is below and email button activated.
if ((floatTempC < alarm) && (button == 1))
Blynk.email("5551234567@vtext.com", "Temp Alert", "Temp below Alarm");

*/


bool connectBlynk4DataTransfer() {
	bool blyncSuccess = false;
	unsigned long time_now = 0;

	Blynk.begin(auth, ssid, pass);

	//_BLYNK_numInput_MaxDevicesAllowed  ist ein inputNumericField in blynk..interaktiv!
	if (MACdeviceDataIndex > _BLYNK_numInput_MaxDevicesAllowed) {
		Blynk.notify("Attention - MAXIMUM Exceeded: " + (String)_BLYNK_numInput_MaxDevicesAllowed);
		//Blynk.notify("Hey, Blynkers! My {DEVICE_NAME} can push now!");		// DEVICE_NAME is taken from the BLYNK app
	}


	Blynk.virtualWrite(V1, MACdeviceDataIndex);	// LEVEL H setting  http://docs.blynk.cc/#blynk-firmware-blynktimer-blynk_readvpin

	lcd.clear();
	//lcd.print (0,0,(String)betriebsStundenCounter());
	//lcd.print (0,1,(String)_payloadMaxCounter);
	lcd.print(0, 0, "hrs:"); lcd.print(12, 0, (String)betriebsStundenCounter());
	lcd.print(0, 1, "MaxLoad:"); lcd.print(12, 1, (String)_payloadMaxCounter);
	terminal.print(F("run/hrs: ")); terminal.print((String)betriebsStundenCounter()); terminal.print(F(" MAC idx: "));  terminal.print((String)MACdeviceDataIndex); terminal.print(F(" MAX: "));  terminal.println((String)_payloadMaxCounter);
	terminal.flush();

	Serial.print("\nLet BLYNK time to react: "); Serial.println(millis());
	time_now = millis();
	while (millis() < time_now + 15000) {
		delay(1000);
		Blynk.run();
		blyncSuccess = true;
		//if (gotTerminalData == true) break;
		ESP.wdtFeed();
	}
	Serial.print("\nBLYNK wait end: "); Serial.println(millis() - time_now);

	//gotTerminalData = false;
	//gotLCDdata == false;
	Serial.println("\nBlynk connected OK / 1DONE ");

	Blynk.disconnect();
	return blyncSuccess;

}

/*
issue table:

besser zum einzeln prüfen:  curr_channel = curr_channel + 1;
if (curr_channel > 0 && curr_channel <=14 )   wifi_set_channel(curr_channel);

*/


int i = 0;
uint8  curr_channel = 1;



void loop() {

	unsigned long currentMillis = millis(); // grab current time  -  check if "interval" time has passed (eg. some sec to do something )

											// CORE-LOOP The new Channel Hop Timer  --  hoping channels 1-14

	if ((unsigned long)(currentMillis - CHANNEL_HOP_previousMillis) >= CHANNEL_HOP_INTERVAL_MS) {
		curr_channel = curr_channel + 1;
		Serial.print("channelHopCallBack(): "); Serial.println(curr_channel);

		if (curr_channel >= 14)
		{
			if (PROMISCUOUS_MODE_ON == true)  wifi_promiscuous_enable(DISABLE);		// SNIFF PAUSE
			curr_channel = 1;
			dataPackReady = true;	//26.12.17 / sendData HIER stürtzte ab!  aber unten im loop ok	- Serial.print("set back to 1..channelHopCallBack(): "); Serial.print(curr_channel);	
		}
		if (PROMISCUOUS_MODE_ON == true) {
			if (curr_channel > 0 && curr_channel <= 14)   wifi_set_channel(curr_channel);
			delay(10);
			Serial.print("["); Serial.print(wifi_get_channel()); Serial.print("]");
		}
		CHANNEL_HOP_previousMillis = millis();// save the "current" time
	}
	//BLYNK die Statistik senden

	if (dataPackReady == true) {
		dataPackReady = false;
		connectBlynk4DataTransfer();
		wifi_set_channel(curr_channel);		// wichtig sinst durchläuft der nicht mehr alle channel, da die connection sich irgeinen nimmt

	}

	// If Buffer Full or refreshTheLoopTime is Finished  we send the Data and empty the buffers for a fresh loop

	bool timeToSendData = false;
	currentMillis = millis(); // grab current time  -  check if "interval" time has passed (eg. some sec to do something )
	if ((unsigned long)(currentMillis - refreshTheLoopTimer_passedMillies) >= RESET_OUTER_LOOP_LONG_TIMER) {
		refreshTheLoopTimer_passedMillies = millis();// save the "current" time	
		Serial.println("\n*************************************************************");
		Serial.print("Timer limit REACHED: "); Serial.println(refreshTheLoopTimer_passedMillies);
		Serial.print("Current Buffer Index: "); Serial.println(MACdeviceDataIndex);
		Serial.println("\n*************************************************************");
		timeToSendData = true;
	}
	else {
		timeToSendData = false;
	}

	//TIME over oder Buffer VOLL - WIR SENDEN
	if (timeToSendData == true || MACdeviceDataIndex > MAX_MAC_DEVICES_IN_ARRAY)
	{
		Serial.println("********************************* Wir senden jetzt die Daten");
		sendDataPack();
		memset(_MacDevicePayload.mac, 0, sizeof(_MacDevicePayload.mac));
		MACdeviceDataIndex = 0;
		timeToSendData = false;
	}


	if (PROMISCUOUS_MODE_ON == true) {
		wifi_promiscuous_enable(ENABLE);	// S N I F I N G   ACTIVE  A G A I N 
	}

	Check_ESP_ErrCounter();					// if errCounter exceed RESET the MCU
											// RESET vom WD Timer bzw - Watchdog Timer zurücksetzen delay(1);  Alternativ kann man auch 1 ms. warten, kostet aber CPU
	ESP.wdtFeed();							// https://www.brickrknowledge.de/content/uploads/2017/12/AllnetLibDokumentation.pdf


}



//V2 = Terminal...quasi das echo, wenn ein wert geschrieben wurde

BLYNK_WRITE(V2)
{
	// if you type "Marco" into Terminal Widget - it will respond: "Polo:"
	if (strlen(param.asStr()) > 1) {
		terminal.print("i got your ORDER: "); 	terminal.println(param.asStr());
		Serial.print("i got your ORDER: "); 	Serial.println(param.asStr());
	}
	else {
		// Send it back
		terminal.print("unsure what i get - Help me:");
		terminal.write(param.getBuffer(), param.getLength());
		terminal.println();
	}
	// Ensure everything is sent
	terminal.flush();
}

//InputField - Max Anzahl von Devices pro TOTAL-SCAN ( ca innerhalb von 1 Min )

BLYNK_WRITE(V3)
{
	int pinValue = param.asInt();
	Serial.print("V3 Maximum is: ");	Serial.println(pinValue);
	terminal.print("V3 MaximumDevicesAllowed: "); 	terminal.println(pinValue);
	_BLYNK_numInput_MaxDevicesAllowed = pinValue;

	// Ensure everything is sent
	terminal.flush();
}



