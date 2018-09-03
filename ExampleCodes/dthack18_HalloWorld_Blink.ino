/*
  halloWorld_BLINK.ino
  Original ESP8266 Blink by Simon Peter ... from the examples in ide
  Blink the blue LED on the ESP-01 module
  CK: modified cause we need the ONBOARD LED
*/

void setup() {
  Serial.begin(115200);
  delay(1000);
  pinMode(2, OUTPUT);     // Initialize the LED_BUILTIN pin as an output
  Serial.println("HI the NODE MCU is ready to USE ...LED should BLINK   BLUE ");
}

// the loop function runs over and over again forever
void loop() {
  digitalWrite(2, LOW);   // Turn the LED on (Note that LOW is the voltage level
  // but actually the LED is on; this is because
  // it is active low on the ESP-01)
  delay(1000);                      // Wait for a second
  digitalWrite(2, HIGH);  // Turn the LED off by making the voltage HIGH
  delay(2000);                      // Wait for two seconds (to demonstrate the active low LED)
 Serial.println("Hallo World ");

}

