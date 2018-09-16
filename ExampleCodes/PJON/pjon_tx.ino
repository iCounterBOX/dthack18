/*
************************************* WAS IST DAS FÜR EIN STAND? **************************************************************************************************************
* T R A N S M I T T E R*
* Version stammt aus dem ZYKLUS: double-Node trilateration-Study
* Challenge:*
* Understand PJON
* Understand the basic concept from RX/TX
* Intracommunication (serial ) between 2 MCU´s
* Transfer 2 RX
* Receive from RX
*
* ..IS transmitting AND receiving Data
*******************************************************************************************************************************************************************************
*/
#define SWBB_MODE 2
#define SWBB_LATENCY 2000
#define PJON_PACKET_MAX_LENGTH 4096
#define PJON_MAX_PACKETS 1

#include <pjon.h>
//************************ NEW ---  PJON  TRANSMITTER = 45**************************************************************************
PJON<SoftwareBitBang> bus(45);
unsigned long time1;

//----------- NON SNIFFER PART  ----------------------------------------------------------------------------
void receiver_function(uint8_t *payload, uint16_t length, const PJON_Packet_Info &packet_info) {
	Serial.println(" Got something vom Receiver: ");
	for (int i = 0; i < length; i++) {
		Serial.print((char)payload[i]);
	}
	Serial.println();
}
void setup()
{
	Serial.begin(115200);
	delay((unsigned long)1000);	
	//bus.strategy.set_pin(12);   // war so alleine ok  muss also NICHT 12 sein
	//bus.strategy.set_pins(D7, D8);  // RECEIVE/TRANSMIT with TRANSMITTER - DataTransfer of SnifferData / set_pins(uint8_t input_pin , uint8_t output_pin )  
	bus.strategy.set_pins(D6, D7);
	bus.set_receiver(receiver_function);  // https://github.com/gioblu/PJON/wiki/Receive-data
	bus.set_error(error_handler);
	bus.begin();
	Serial.print("\nTX /PJON - Device id: ");	Serial.println(bus.device_id());
}

void loop()
{
	if (millis() - time1 > 2500) {
		time1 = millis();
		Serial.println("send something ");
		/* Avoid Serial and PJON concurrency */
		Serial.flush();
		//packet = bus.send_packet_blocking(44, "Hallo", 5);	// ok..der braucht scheinbar kein bus.Update()
		int packet = bus.send(44, "Hallo", 5);						// auch OK
		bus.update();
	}
	//receive something from the Receiver
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
