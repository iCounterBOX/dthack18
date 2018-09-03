/** WifiScanOnly  
Author: Mrs Christin Koss

please also check the wiki:

purpose of this sketch:
- scan in a loop 14 WifiChannels
- a basic introduction into wifiScan´s
*/

#include <SPI.h>
#include <TimeLib.h>
#include <Hash.h>

//4 the WiFiScanner:

#include <user_interface.h>		// used for e.g.  system_get_free_heap_size
extern "C" {
#include <cont.h>
	extern cont_t g_cont;
}

#define DISABLE 0
#define ENABLE 1

int _payloadMaxCounter = 0;
float _BetrStdZaehler = 0;

// ERROR - COUNTER

#define _ESP_ERR_COUNT_LIMIT 50		// Auslöser für den Reset wenn dieser Schwellwert erreicht ist
uint16 _ESP_ERROR_COUNTER = 0;

//>>>>>>> Configure the SNIFFER Stuff  ++  Configure the SNIFFER Stuff  ++  Configure the SNIFFER Stuff  <<<<<<<<<


// TimeFrames Tick Tack
unsigned long CHANNEL_HOP_INTERVAL_MS = 1000;
unsigned long CHANNEL_HOP_previousMillis = 0;

/*
Outer-Loop
10 min = 600000
20 min = 120000
*/
unsigned long OUTER_LOOP_LONG_TIMER = 60000;
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
		// OK -- IN THIS EXAMPLE NO transfer into CLOUD !!
	}
	else
	{
		Serial.println("Payload to LONG or EMPTY");
		_MacDevicePayload.mac[0] = 0;	// Dann nur Hülle senden...damit Master uns nicht weg hängt		
	}

				
	if (MACdeviceDataIndex >= _payloadMaxCounter) _payloadMaxCounter = MACdeviceDataIndex; // sonst sehen wir den count nicht, wenn kein netz!
	Serial.println("ok.\n");	
}


const uint32_t MOD_ADLER = 65521;
uint32_t adler32(unsigned char *data, size_t len)
/*
where data is the location of the data in physical memory and len is the length of the data in bytes
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
	Serial.println("\nHI..THIS is SCANNER-Node! start SETUP()");
	RAMfree("setup");

	
	IoT_WatchDog(true);
	Serial.printf("ESP8266 OWN MAC getChipId(): ESP_%08X\n", ESP.getChipId());  // https://github.com/esp8266/Arduino/issues/2309

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
			wifi_promiscuous_enable(DISABLE);		// SNIFF PAUSE
			curr_channel = 1;
			dataPackReady = true;	//26.12.17 / sendData HIER stürtzte ab!  aber unten im loop ok	- Serial.print("set back to 1..channelHopCallBack(): "); Serial.print(curr_channel);	
		}
		if (curr_channel > 0 && curr_channel <= 14)   wifi_set_channel(curr_channel);
		delay(10);
		Serial.print("["); Serial.print(wifi_get_channel()); Serial.print("]");
		
		CHANNEL_HOP_previousMillis = millis();// save the "current" time
	}
	//e.g. BLYNK communication

	if (dataPackReady == true) {
		dataPackReady = false;
		// for example you could connect to BLYNK..
		wifi_set_channel(curr_channel);		// wichtig sonst durchläuft der nicht mehr alle channel, da die connection sich irgeinen nimmt
	}

	// If Buffer Full or refreshTheLoopTime is Finished  we send the Data and empty the buffers for a fresh loop

	bool timeToSendData = false;
	currentMillis = millis(); // grab current time  -  check if "interval" time has passed (eg. some sec to do something )
	if ((unsigned long)(currentMillis - refreshTheLoopTimer_passedMillies) >= OUTER_LOOP_LONG_TIMER) {
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

	//TIME over oder Buffer VOLL - WIR SENDEN zur CLOUD ( OPTION for later USE!! )
	if (timeToSendData == true || MACdeviceDataIndex > MAX_MAC_DEVICES_IN_ARRAY)
	{
		Serial.println("********************************* Wir senden jetzt die Daten");
		sendDataPack();
		memset(_MacDevicePayload.mac, 0, sizeof(_MacDevicePayload.mac));
		MACdeviceDataIndex = 0;
		timeToSendData = false;
	}
		
	wifi_promiscuous_enable(ENABLE);	 		
	// RESET vom WD Timer bzw - Watchdog Timer zurücksetzen delay(1);  Alternativ kann man auch 1 ms. warten, kostet aber CPU
	ESP.wdtFeed();							
	
}





