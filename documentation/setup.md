# WTF we are doing here?

## Concept:

We detect Devices which send so called WiFi-Beacons ( mobile, NB, SmartWatch, TomTom,….)
Users have to do nothing to be detected as the WiFi and Bluetooth radios integrated in their smartphones
(mobile, hands-free and cell phones) periodically send a "hellow!" message telling about their presence.
* The MAC address of the wireless interface, which allows to identify it uniquely.
* The strength of the signal (RSSI), which gives us the average distance of the device from the scanning point.
* The vendor of the smartphone (Apple, Samsung, etc)
* The WiFi Access Point where the user is connected (if any). e.g SSID
* WiFi by constantly sending out probes looking for networks
* Android does passive scans, it listens for beacons
* Set up a device to purely sit silent and listen for these probe requests, then write the MAC address and timestamp to a file

Example of information monitored by the WiFi Scanner:
| DB ID | Timestamp | MAC | AP | RSSI | Vendor |
| ------ | ------ | ------ | ------ | ------ | ------ |
53483 | 2012-04-24 07:56:25 | C4:2C:03:96:0E:4A| | 69 | Apple
| 53482 | 2012-04-24 09:11:26 | D8:2A:7E:10:1E:63 | myNiceBar | 60 | Nokia Corporation

It just detects the "beacon frames" originated by the WiFi and Bluetooth radios integrated in the smartphones. Users just need to have the WiFi radio ON with the visible option activated.

In both WiFi and Bluetooth radios these zones can also be increased or decreased by using a different antenna for the module as it counts with an standard N-Male connector. The default antenna which comes with the scanning modules is an omnidirectional antenna with a gain of 5 dBi.

## Which Device( e.g microController) is able to do such SCANS?
Basically every Router at “home” which is able run some Monitor-Mode and some WireShark your fine.
But then you ONLY “see”  devices are “around” this Router.
We focus Usecases which collect huge amounts of such Devices …for Example in a MESH. Even more collect all those Data to SHOW “Moves” of Devices or HeatMaps  vor very specific UseCases.

ALL this is possible with the **NodeMcu Lolin ESP8266 E-12**
