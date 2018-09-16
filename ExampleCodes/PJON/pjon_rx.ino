/*
************************************* WAS IST DAS FÜR EIN STAND? **************************************************************************************************************
* R E C E I V E R*
* Version stammt aus dem ZYKLUS: double-Node trilateration-Study*
* Challenge:*
* Understand PJON
* Understand the basic concept from RX/TX
* Intracommunication (serial ) between 2 MCU´s*
* this setup is FIne
*
* is receiving from TX and send back some Data
*******************************************************************************************************************************************************************************
*/
#define SWBB_MODE 2
#define SWBB_LATENCY 2000
#define PJON_PACKET_MAX_LENGTH 4096
#define PJON_MAX_PACKETS 1

#include <pjon.h>
PJON<SoftwareBitBang> bus(44);
unsigned long time1;
void receiver_function(uint8_t *payload, uint16_t length, const PJON_Packet_Info &packet_info) {
	Serial.print("RX:");Serial.print(" Device id: ");	Serial.print(packet_info.receiver_id);	Serial.print(" | TX: ");
	Serial.print(" Device id: ");	Serial.print(packet_info.sender_id);
	//String str = (char*)(payload);		// RX: Device id: 44 | TX:  Device id: 45HalloE
	//Serial.print(str);	//Serial.println();
	for (int i = 0; i < length; i++) {
		Serial.print((char)payload[i]);
	}
	Serial.println();
}

void setup() {
	Serial.begin(115200);
	while (!Serial) continue;
	//bus.strategy.set_pin(12);   // war so alleine ok  muss also NICHT 12 sein
	//bus.strategy.set_pins(D7, D8);  // RECEIVE/TRANSMIT with TRANSMITTER - DataTransfer of SnifferData / set_pins(uint8_t input_pin , uint8_t output_pin )  
	bus.strategy.set_pins(D6, D7); // Set pin D6 input pin and pin D7 output pin
	bus.set_receiver(receiver_function);  // https://github.com/gioblu/PJON/wiki/Receive-data
	bus.set_error(error_handler);
	bus.begin();
	time1 = millis();

} // end of setup  

void loop() {
	if (millis() - time1 > 3000) {
		time1 = millis();
		Serial.println("send something 2 TX..");		
		Serial.flush();	/* Avoid Serial and PJON concurrency */		
		//packet = bus.send_packet_blocking(44, "Hallo", 5);	// ok..der braucht scheinbar kein bus.Update()
		int packet = bus.send(45, "Hallo", 5);						// auch OK
		bus.update();
	}
	bus.receive(1000);
}

void error_handler(uint8_t code, uint16_t data, void *custom_pointer) {
	if (code == PJON_CONNECTION_LOST) {
		Serial.print("Connection lost with device ");
		Serial.println((uint8_t)bus.packets[data].content[0], DEC);
	}
	if (code == PJON_ID_ACQUISITION_FAIL) {
		Serial.print("Connection lost with device ");
		Serial.println(data, DEC);
	}
	if (code == PJON_DEVICES_BUFFER_FULL) {
		Serial.print("Master devices buffer is full with a length of ");
		Serial.println(data);
	}
};
