# tech-sbus-mqtt
Tech SBUS to MQTT gateway

# Overview
The script listens to communication between "Tech Sterowniki" devices over a RS485 bus (Tech SBUS protocol) and publishes the messages over MQTT.

It allows to send temperature change commands.

It also publishes MQTT discovery messages for Home Assistant so if the MQTT integration is enabled all zones will automatically become visible in Home Assistant.

It works fully locally, no connection to the Tech cloud / eModul is used. The updates are published over MQTT immediately once received from the device.

It requires an RS485 interface, I use USB to RS485 adapters that contain UART chip CH340C and RS485 transceiver MAX485, cost around $2-$3 and seem to be very reliable (I had one with FT232RL and it sometimes hung but maybe I had a broken one?).

# Configuration
The script requires a configuration file. It has to be placed in the script's directory, have name `tech-sbus-mqtt.conf` and the following yaml structure:
```
controllers:
  - name: Upstairs
    address: 00-00-00-01
    serial: 00001
    model: L-X WiFi
    regulators:
      - name: Bathroom
        address: 00-00-00-02
        serial: 0001
        model: R-12S
        default_duration: 1441
      - name: Childrens bedroom
        address: 00-00-00-03
        serial: 0002
        model: R-12S
        default_duration: 1441
      - name: Master bedroom
        address: 00-00-00-04
        serial: 0003
        model: R-12S
        default_duration: 1441
  - name: Downstairs
    address: 00-00-00-05
    serial: 00002
    model: L-X WiFi
    regulators:
      - name: Living room
        address: 00-00-00-06
        serial: 0004
        model: R-12S
        default_duration: 1441
      - name: Kitchen
        address: 00-00-00-07
        serial: 0005
        model: R-12S
        default_duration: 1441
      - name: Bathroom downstairs
        address: 00-00-00-08
        serial: 0006
        model: R-12S
        default_duration: 1441

serial_ports:
  - /dev/ttyUSB0
  - /dev/ttyUSB1

log_file: tech-sbus-mqtt.log
log_level: INFO
pid_file: /tmp/tech-sbus-mqtt.pid

mqtt:
  hostname: 192.168.1.15
  port: 1883
  topic_prefix: techcontrollers
#  username: tech
#  password:
#  tls: yes
#  tls_verify_peer: yes
#  tls_ca_cert:
#  tls_client_cert: 
#  tls_client_key: 
```
The example above contains a configuration for two central controllers (one for each floor) and 3 room regulators connected to each of them. Each controller is on a separate RS485 bus.
Devices' serial numbers should be printed on stickers on their back but serial numbers and model names aren't required for the script to function properly.
The devices' addresses are crucial. In order to get the addresses of the room regulators and controllers I recommend to start the script with the following basic configuration:
```
serial_ports:
  - /dev/ttyUSB0

log_file: tech-sbus-mqtt.log
log_level: DEBUG
pid_file: /tmp/tech-sbus-mqtt.pid

mqtt:
  hostname: 192.168.1.15
  port: 1883
  topic_prefix: techcontrollers
```
It'll listen on one serial port and will print all received messages to MQTT and the log_file (DEBUG mode).
Once it's listening, restart the Tech controller. During boot it sends the date&time message, search for the following in the log:
```
$ grep -a timestamp tech-sbus-mqtt.log
2025-04-10 20:53:36 INFO     aa-bb-cc-dd->ff-ff-ff-ff,timestamp,1744318421,-5
```
`aa-bb-cc-dd` is the address of your controller.
Then search for the following patterns (where `aa-bb-cc-dd` is your controller's address):
```
$ grep -a '\->aa-bb-cc-dd' tech-sbus-mqtt.log
```
Messages similar to the below will show up:
```
2025-04-10 21:49:04 DEBUG    a2-25-d9-fc->aa-bb-cc-dd,room temperature,21.6
2025-04-10 21:49:04 DEBUG    a2-25-d9-fc->aa-bb-cc-dd,humidity,49.2
2025-04-10 21:49:05 DEBUG    e2-a5-80-54->aa-bb-cc-dd,humidity,53.7
2025-04-10 21:49:14 DEBUG    a2-25-d9-fc->aa-bb-cc-dd,room temperature,21.6
2025-04-10 21:49:14 DEBUG    a2-25-d9-fc->aa-bb-cc-dd,humidity,49.1
2025-04-10 21:49:20 DEBUG    e2-a5-80-54->aa-bb-cc-dd,room temperature,21.2

```
The addresses before the "->" are addresses of your room regulators. If there're many of them, you can figure out the room/zone for each address by checking and comparing the humidity and temperatures on their displays. You can also temporarily change the target temperature in a zone to see a message as follows:
```
2025-04-10 21:57:19 DEBUG    64-e5-70-3d->aa-bb-cc-dd,target temperature (2),20.5
2025-04-10 21:57:19 DEBUG    64-e5-70-3d->aa-bb-cc-dd,target temperature time (2),60
2025-04-10 21:57:19 DEBUG    Publishing msg: 60 topic: techcontrollers/64-e5-70-3d/temperature/air/target2/duration
2025-04-10 21:57:19 DEBUG    Publishing msg: 20.5 topic: techcontrollers/64-e5-70-3d/temperature/air/target2
2025-04-10 21:57:20 DEBUG    aa-bb-cc-dd->64-e5-70-3d,target temperature time,59
2025-04-10 21:57:20 DEBUG    Publishing msg: 59 topic: techcontrollers/64-e5-70-3d/temperature/air/target/duration
2025-04-10 21:57:20 DEBUG    aa-bb-cc-dd->64-e5-70-3d,target temperature,20.5
2025-04-10 21:57:20 DEBUG    Publishing msg: 20.5 topic: techcontrollers/64-e5-70-3d/temperature/air/target
```
In this example `64-e5-70-3d` is the address of the room regulator on which the temperature change was requested and `aa-bb-cc-dd` is the controller's address.
When you have all the addresses collected, create the full configuration file and restart the script.
Once the script is started and new devices and entities appear in Home Assistant, I recommend to restart the Tech controller(s) so that Home Assistant becomes immediately aware of all the zones and parameters which aren't repeated regularly (for example the target temperatures for each zone).

# Setting temperatures by MQTT commands
You can use MQTT to change temperatures.

Temperature change request topic is "`topic_prefix`/`regulator_address`/temperature/air/target/set"

The payload is a JSON object with two keys:
* `temperature` - decimal number, range 5-35, Celsius degrees
* `duration` (optional) - integer, range 0-1441, minutes, values 0 and 1441 have special meanings:
  * `0` - switches back to the schedule (valid temperature has to be provided in the request although it's not used)
  * `1441` - sets the target temperature for an indefinite period

If the duration is not provided in the MQTT message, value `default_duration` from the config file is used - defaults to 1441 (indefinite).

Example MQTT message to set target temperature to 25 degrees for 3 hours on regulator xx-yy-zz-xx:
|topic|message|
| --- | ----- |
|techcontrollers/xx-yy-zz-xx/temperature/air/target/set|{"temperature": 25.0, "duration": 180}|

Example MQTT message to set target temperature to 25 degrees on regulator xx-yy-zz-xx for an indefinite period of time:
|topic|message|
| --- | ----- |
|techcontrollers/xx-yy-zz-xx/temperature/air/target/set|{"temperature": 25.0, "duration": 1441}|

Example MQTT message to switch back to the schedule on xx-yy-zz-xx:
|topic|message|
| --- | ----- |
|techcontrollers/xx-yy-zz-xx/temperature/air/target/set|{"temperature": 25.0, "duration": 0}|

Standard Home Assistant climate cards don't support setting duration, only the temperature. Automations can be used to achieve that.

# Protocol
The script is a result of my reverse engineering of the protocol so only limited functionality is available at the moment. If time permits new features may be added in future because some more data is transmitted. Everyone's encouraged to contribute.\
\
What I currently know about the protocol: [TECH_RS485_PROTOCOL](TECH_RS485_PROTOCOL.md)

# Devices tested
- L-X WiFi - central controller
- R-12S - wired room regulator with air temperature sensor, humidity sensor and a connector for floor temperature NTC sensor
- CH340/CH341 RS485<->USB converter
- Waveshare RS485 CAN HAT for Raspberry Pi

# TO DO
- Dockerfile, docker-compose

