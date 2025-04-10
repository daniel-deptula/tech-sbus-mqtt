import serial
import threading
import yaml
import json
import paho.mqtt.client as mqtt
import sys
import time
import base64
import binascii
import logging
import os
from pid import PidFile

LOG_FORMAT = ('%(asctime)-15s %(levelname)-8s %(message)s')
LOG_DATEFORMAT = ('%Y-%m-%d %H:%M:%S')

logger = logging.getLogger(__name__)
topic_prefix = None
status_topic = None
ha_discovery_prefix = "homeassistant"
# all devices, keys are addresses
all_devices = {}


class TechDevice:
    def __init__(self, address: str, name: str, model: str, serial_no: str):
        self.address = address
        self.name = name
        self.model = model
        self.serial_no = serial_no

class TechController(TechDevice):
    def __init__(self, address: str, name: str, model: str, serial_no: str):
        super().__init__(address, name, model, serial_no)

class TechRoomRegulator(TechDevice):
    def __init__(self, address: str, name: str, model: str, serial_no: str, controller: TechDevice):
        super().__init__(address, name, model, serial_no)
        self.controller = controller

class TechSbusMessageToMqttProcessor:
    def __init__(self, msg, mqtt_publisher):
        self.target_temp2 = None
        self.target_temp_time2 = None
        self.target_temp = None
        self.target_temp_time = None
        self.status = None
        self.humidity = None
        self.floor_temp = None
        self.room_temp = None
        self.received_timestamp = None
        self.timestamp = time.time()
        self.msg = msg
        self.mqtt_publisher = mqtt_publisher
        if len(self.msg) > 12:
            self.src_addr = self.msg[0:4]
            self.dst_addr = self.msg[6:10]
            self.src_addr_str = device_addr_str_from_bytes(self.src_addr)
            self.dst_addr_str = device_addr_str_from_bytes(self.dst_addr)
            self.fromto_header = self.src_addr_str + "->" + self.dst_addr_str
            logger.debug('Msg from: ' + self.src_addr_str + " to: " + self.dst_addr_str)

            # I don't know what this value is
            self.smth1 = self.msg[4:6]
            self.smth2 = self.msg[10:12]
            # But it's always set to 0x50 0x00 when environmental measurements or commands are sent
            if self.smth1 == bytes([0x50, 0]):
                logger.debug('The message (type1) data: ' + self.msg[12:].hex(' '))
                self.data = self.msg[12:]
                self.parse_data_from_msg()
            # 0xE9 0xFD when timestamp is sent
            elif self.smth1 == bytes([0xE9, 0xFD]):
                logger.debug('The message (type2) data: ' + self.msg[12:].hex(' '))
                self.data = self.msg[12:]
                self.parse_data_from_msg()
        else:
            logger.error("Message too short. Unable to parse.")

    def parse_data_from_msg(self):
        if len(self.data) == 12 and self.data[0:4] == bytes([0x3F, 0xA1, 0x2E, 0xD0]):
            # Timestamp
            self.received_timestamp = int.from_bytes(self.data[4:12], byteorder='little', signed=False)
            self.process_timestamp()
        elif len(self.data) == 8 and self.data[0:4] == bytes([0xAC, 0xFF, 0xFF, 0xAC]):
            # ACK (bytes 0xAC, 0xFF, 0xFF, 0xAC followed by CRC-32 of the data received from the other node)
            if logger.getEffectiveLevel() <= logging.DEBUG:
                crc32 = self.data[4:8].hex(' ')
                logger.debug("ACK. CRC32 of the message acknowledged: " + crc32)
        else:
            i = 0
            while i < len(self.data):
                item_len = self.data[i]
                if item_len > 0 and i + item_len < len(self.data):
                    if self.data[i + 1] == 0:
                        # Room temperature
                        self.room_temp = float(
                            int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little', signed=False)) / 10
                        self.process_room_temperature()
                    elif self.data[i + 1] == 1:
                        # Floor temperature
                        self.floor_temp = float(
                            int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little', signed=False)) / 10
                        self.process_floor_temperature()
                    elif self.data[i + 1] == 2:
                        # Humidity
                        self.humidity = float(
                            int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little', signed=False)) / 10
                        self.process_humidity()
                    elif self.data[i + 1] == 0x14:
                        # Heating start/stop
                        self.status = int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little',
                                                     signed=False)
                        self.process_status()
                    elif self.data[i + 1] == 0x20:
                        # Target temperature for how long
                        self.target_temp_time = int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little',
                                                               signed=False)
                        self.process_target_temp_time()
                    elif self.data[i + 1] == 0x21:
                        # Target temperature
                        self.target_temp = float(
                            int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little', signed=False)) / 10
                        self.process_target_temp()
                    elif self.data[i + 1] == 0x26 and item_len == 6:
                        # Time + target temperature (what's the purpose of it?!)
                        self.target_temp_time2 = int.from_bytes(self.data[i + 3:i + 5], byteorder='little',
                                                                signed=False)
                        self.target_temp2 = float(
                            int.from_bytes(self.data[i + 5:i + 7], byteorder='little', signed=False)) / 10
                        self.process_target_temp2()
                    else:
                        # Unknown parameter
                        logger.debug(self.fromto_header + ",Unknown parameter: " + hex(self.data[i + 1]))
                else:
                    # Something not supported
                    logger.debug(self.fromto_header + ",Unsupported data: " + self.data.hex(' '))
                i += (item_len + 1)

    def process_room_temperature(self):
        logger.debug(self.fromto_header + ",room temperature," + str(self.room_temp))
        self.mqtt_publisher.mqtt_publish_msg(self.src_addr_str, "temperature/air/current", str(self.room_temp))

    def process_floor_temperature(self):
        logger.debug(self.fromto_header + ",floor temperature," + str(self.floor_temp))
        self.mqtt_publisher.mqtt_publish_msg(self.src_addr_str, "temperature/floor/current", str(self.floor_temp))

    def process_humidity(self):
        logger.debug(self.fromto_header + ",humidity," + str(self.humidity))
        self.mqtt_publisher.mqtt_publish_msg(self.src_addr_str, "humidity/current", str(self.humidity))

    def process_status(self):
        if self.status == 1:
            status_str = "on"
        elif self.status == 0:
            status_str = "off"
        else:
            status_str = str(self.status)
        logger.debug(self.fromto_header + ",heating," + status_str)
        if isinstance(all_devices[self.src_addr_str], TechController):
            addr = self.dst_addr_str
        else:
            addr = self.src_addr_str
        self.mqtt_publisher.mqtt_publish_msg(addr, "heating", status_str)

    def process_target_temp_time(self):
        if self.target_temp_time == 0xFFFFFFFF:
            # time_str = "OFF"
            time_str = "0"
        elif self.target_temp_time == 1441:
            # time_str = "CON"
            time_str = "-1"
        else:
            time_str = str(self.target_temp_time)
        logger.debug(self.fromto_header + ",target temperature time," + time_str)
        if isinstance(all_devices[self.src_addr_str], TechController):
            addr = self.dst_addr_str
        else:
            addr = self.src_addr_str
        self.mqtt_publisher.mqtt_publish_msg(addr, "temperature/air/target/duration", time_str)

    def process_target_temp(self):
        logger.debug(self.fromto_header + ",target temperature," + str(self.target_temp))
        if isinstance(all_devices[self.src_addr_str], TechController):
            addr = self.dst_addr_str
        else:
            addr = self.src_addr_str
        self.mqtt_publisher.mqtt_publish_msg(addr, "temperature/air/target", str(self.target_temp))

    def process_target_temp2(self):
        if self.target_temp_time2 == 0xFFFF:
            # time_str = "OFF"
            time_str = "0"
        elif self.target_temp_time2 == 1441:
            # time_str = "CON"
            time_str = "-1"
        else:
            time_str = str(self.target_temp_time2)
        logger.debug(self.fromto_header + ",target temperature (2)," + str(self.target_temp2))
        logger.debug(self.fromto_header + ",target temperature time (2)," + time_str)
        if isinstance(all_devices[self.src_addr_str], TechController):
            addr = self.dst_addr_str
        else:
            addr = self.src_addr_str
        self.mqtt_publisher.mqtt_publish_msg(addr, "temperature/air/target2/duration", time_str)
        self.mqtt_publisher.mqtt_publish_msg(addr, "temperature/air/target2", str(self.target_temp2))

    def process_timestamp(self):
        my_timestamp = int(self.timestamp)
        tzoffset = time.localtime(my_timestamp).tm_gmtoff
        delta = my_timestamp + tzoffset - self.received_timestamp
        logger.info(self.fromto_header + ",timestamp," + str(self.received_timestamp) + "," + str(delta))

class SerialPort:
    def __init__(self, port_name, mqtt_publisher):
        self.logger = logging.getLogger(SerialPort.__name__)
        self.serial_port = port_name
        self.mqtt_publisher = mqtt_publisher
        logger.info("Initialized SerialPort " + port_name)

    def __call__(self):
        with serial.Serial(self.serial_port, 115200, parity=serial.PARITY_EVEN, bytesize=serial.SEVENBITS,
                           timeout=None) as serial_conn:
            while True:
                # Read until LF (0x0A)
                msg = serial_conn.read_until(expected='\x0a'.encode('utf-8'), size=None)
                if len(msg) > 1:
                    # Decoding the message
                    strmsg = msg[0:-1].decode('ascii')
                    logger.debug(f"[{self.serial_port}] Received: {strmsg}")
                    if len(strmsg) > 6:
                        if strmsg[0] != '>':
                            logger.error(f"[{self.serial_port}] Missing message start!")
                        # first char is ">"
                        # "==" at the end of the base64-encoded string is missing
                        # The last 6 characters are encoded CRC-32
                        encmsg = strmsg[1:-6]
                        enccrc = strmsg[-6:] + "=="
                        logger.debug(f"[{self.serial_port}] Base64 encoded message: {encmsg}")
                        logger.debug(f"[{self.serial_port}] Base64 encoded CRC-32: {enccrc}")
                        try:
                            decoded_msg = base64.b64decode(encmsg)
                            logger.debug(f"[{self.serial_port}] Base64 decoded message: " + decoded_msg.hex(' '))
                            decoded_crc = base64.b64decode(enccrc)
                            # Compute CRC-32 of the decoded message
                            crc = binascii.crc32(decoded_msg)
                            if crc.to_bytes(4, byteorder='little', signed=False) == decoded_crc:
                                logger.debug(f"[{self.serial_port}] CRC check pass")
                                TechSbusMessageToMqttProcessor(decoded_msg, self.mqtt_publisher)
                            else:
                                logger.error(f"[{self.serial_port}] CRC check failed")
                        except Exception as e:
                            logger.error(f"[{self.serial_port}] Message processing error: " + repr(e))
                    else:
                        logger.error(f"[{self.serial_port}] Message too short: " + str(len(strmsg)))

class MqttPublisher:
    def __init__(self, mqtt_config, all_devices: dict):
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self.publish_lock = threading.RLock()
        self.connected_to_broker = False
        self.mqtt_config = mqtt_config
        self.topic_prefix = mqtt_config["topic_prefix"]
        self.status_topic = self.topic_prefix + "/status"
        if "tls" in mqtt_config and mqtt_config["tls"] == "yes":
            if "tls_verify_peer" in mqtt_config and mqtt_config["tls_verify_peer"] == "no":
                logger.info("Enabling insecure TLS for MQTT broker connection")
                self.mqtt_client.tls_set(cert_reqs=ssl.CERT_NONE)
                self.mqtt_client.tls_insecure_set(True)
            else:
                logger.info("Enabling secure TLS for MQTT broker connection")
                self.mqtt_client.tls_set(
                    cert_reqs=ssl.CERT_REQUIRED,
                    ca_certs=mqtt_config["tls_ca_cert"],
                    certfile=mqtt_config["tls_client_cert"],
                    keyfile=mqtt_config["tls_client_key"],
                )
        if "username" in mqtt_config and "password" in mqtt_config:
            logger.info("Enabling username/password authentication for MQTT broker connection.")
            self.mqtt_client.username_pw_set(username=mqtt_config["username"], password=mqtt_config["password"])
        self.mqtt_client.on_connect = self.mqtt_on_connect
        self.mqtt_client.on_connect_fail = self.mqtt_on_connect_fail
        self.mqtt_client.on_disconnect = self.mqtt_on_disconnect
        self.mqtt_client.will_set(self.status_topic, "offline", retain=True, qos=1)
        self.all_devices = all_devices
        self.published_regulator_addresses = set()

    def __call__(self):
        try:
            self.mqtt_client.connect(self.mqtt_config["hostname"], self.mqtt_config["port"])
        except Exception as e:
            logger.error(f"Failed to connect: {str(e)}.")
        self.mqtt_client.loop_forever(timeout=5.0, retry_first_connection=True)

    def mqtt_on_connect(self, client, userdata, flags, reason_code, properties):
        if reason_code.is_failure:
            logger.error(f"Failed to connect: {reason_code}. loop_forever() will retry connection")
            self.connected_to_broker = False
            self.published_regulator_addresses = set()
        else:
            client.publish(self.status_topic, "online", retain=True, qos=1)
            self.connected_to_broker = True
            self.published_regulator_addresses = set()
            logger.info("Connected to MQTT broker")
            
    def mqtt_on_connect_fail(self, client, userdata):
        logger.error(f"Failed to connect to the MQTT broker. loop_forever() will retry connection")

    def mqtt_on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        logger.error("Disconnected from MQTT broker!")
        self.connected_to_broker = False

    def mqtt_publish(self, publish_topic, msg, retain: bool):
        logger.debug(f"Publishing msg: {str(msg)} topic: {publish_topic}")
        try:
            self.publish_lock.acquire()
            retval = self.mqtt_client.publish(publish_topic, msg, retain=retain, qos=1)
            retval.wait_for_publish(30)
        except ValueError as e:
            logger.error(f"MQTT outgoing queue is full: {str(e)}")
        except RuntimeError as e:
            logger.error(f"Unknown MQTT publishing error: {str(e)}")
        except OSError as e:
            logger.error(f"MQTT connection error: {str(e)}")
        finally:
            self.publish_lock.release()

    def mqtt_publish_msg(self, addr, topic, msg):
        if addr not in self.published_regulator_addresses and addr in self.all_devices and isinstance(all_devices[addr], TechRoomRegulator):
            self.mqtt_publish_discovery_msgs(addr, all_devices[addr].name, all_devices[addr].model, all_devices[addr].serial_no)
        self.mqtt_publish(self.topic_prefix + "/" + addr + "/" + topic, msg, False)

    def mqtt_publish_discovery_msgs(self, addr, name, model, serial_no):
        if name is not None:
            discovery_config_base = {
                "force_update": True,
                "availability_topic": self.status_topic,
                "device": {
                    "identifiers": [addr],
                    "name": name,
                    "manufacturer": "Tech Sterowniki",
                    "model": model,
                    "serial_number": serial_no,
                },
            }

            discovery_config_temperature = discovery_config_base.copy()
            discovery_config_temperature["unique_id"] = f"air_temperature_{addr}"
            discovery_config_temperature["expire_after"] = 3600
            discovery_config_temperature["name"] = f"air temperature"
            discovery_config_temperature["device_class"] = "temperature"
            discovery_config_temperature["unit_of_measurement"] = "°C"
            discovery_config_temperature["state_topic"] = self.topic_prefix + "/" + addr + "/temperature/air/current"
            self.mqtt_publish(f"{ha_discovery_prefix}/sensor/air_temperature_{addr}/config", json.dumps(discovery_config_temperature), True)
            
            discovery_config_target_temperature = discovery_config_base.copy()
            discovery_config_target_temperature["unique_id"] = f"target_temperature_{addr}"
            discovery_config_target_temperature["name"] = f"target temperature"
            discovery_config_target_temperature["device_class"] = "temperature"
            discovery_config_target_temperature["unit_of_measurement"] = "°C"
            discovery_config_target_temperature["state_topic"] = self.topic_prefix + "/" + addr + "/temperature/air/target"
            self.mqtt_publish(f"{ha_discovery_prefix}/sensor/target_temperature_{addr}/config", json.dumps(discovery_config_target_temperature), True)
            
            discovery_config_target_temperature_duration = discovery_config_base.copy()
            discovery_config_target_temperature_duration["unique_id"] = f"target_temperature_duration_{addr}"
            discovery_config_target_temperature_duration["name"] = f"target temperature duration"
            discovery_config_target_temperature_duration["device_class"] = "duration"
            discovery_config_target_temperature_duration["unit_of_measurement"] = "min"
            discovery_config_target_temperature_duration["state_topic"] = self.topic_prefix + "/" + addr + "/temperature/air/target/duration"
            self.mqtt_publish(f"{ha_discovery_prefix}/sensor/target_temperature_duration_{addr}/config", json.dumps(discovery_config_target_temperature_duration), True)

            discovery_config_humidity = discovery_config_base.copy()
            discovery_config_humidity["unique_id"] = f"humidity_{addr}"
            discovery_config_humidity["expire_after"] = 3600
            discovery_config_humidity["name"] = "humidity"
            discovery_config_humidity["device_class"] = "humidity"
            discovery_config_humidity["unit_of_measurement"] = "%"
            discovery_config_humidity["state_topic"] = self.topic_prefix + "/" + addr + "/humidity/current"
            self.mqtt_publish(f"{ha_discovery_prefix}/sensor/humidity_{addr}/config", json.dumps(discovery_config_humidity), True)
            
            discovery_config_heating = discovery_config_base.copy()
            discovery_config_heating["unique_id"] = f"heating_{addr}"
            discovery_config_heating["name"] = "heating"
            discovery_config_heating["device_class"] = "heat"
            discovery_config_heating["payload_on"] = "on"
            discovery_config_heating["payload_off"] = "off"
            discovery_config_heating["state_topic"] = self.topic_prefix + "/" + addr + "/heating"
            self.mqtt_publish(f"{ha_discovery_prefix}/binary_sensor/heating_{addr}/config", json.dumps(discovery_config_heating), True)
            
            discovery_config_climate = {
                "name": f"{name}",
                "current_humidity_topic": self.topic_prefix + "/" + addr + "/humidity/current",
                "current_temperature_topic": self.topic_prefix + "/" + addr + "/temperature/air/current",
                "temperature_state_topic": self.topic_prefix + "/" + addr + "/temperature/air/target",
                "temp_step": 0.1,
                "temperature_unit": "C",
                "mode_state_topic": self.topic_prefix + "/" + addr + "/heating",
                "mode_state_template": "{{ \"heat\" if value==\"on\" else \"off\" }}",
                "action_topic": self.topic_prefix + "/" + addr + "/heating",
                "action_template": "{{ \"heating\" if value==\"on\" else \"idle\" }}",
                "entity_category ": "EntityCategory.DIAGNOSTIC",  # will change to EntityCategory.CONFIG when write is implemented
                "modes": [ "off", "heat" ],
                "availability_topic": self.status_topic,
                "device": {
                    "identifiers": [addr],
                    "name": name,
                    "manufacturer": "Tech Sterowniki",
                    "model": model,
                    "serial_number": serial_no,
                },
            }
            self.mqtt_publish(f"{ha_discovery_prefix}/climate/climate_{addr}/config", json.dumps(discovery_config_climate), True)

            self.published_regulator_addresses.add(addr)

def device_addr_str_from_bytes(addr: bytes) -> str:
    return addr.hex('-')

if __name__ == "__main__":
    with open(os.path.dirname(os.path.abspath(__file__)) + '/tech-sbus-mqtt.conf', 'r') as file:
        config = yaml.safe_load(file)

    logging.basicConfig(filename=config["log_file"], encoding='utf-8', format=LOG_FORMAT, datefmt=LOG_DATEFORMAT,
                        level=config.get("log_level", "INFO"))

    with PidFile(config["pid_file"]):

        for controller_config in config.get("controllers", []):
            controller = TechController(controller_config["address"], controller_config["name"], controller_config.get("model", "Tech heating controller"), controller_config.get("serial", "00000"))
            all_devices[controller.address] = controller
            for regulator_config in controller_config["regulators"]:
                regulator = TechRoomRegulator(regulator_config["address"], regulator_config["name"], regulator_config.get("model", "Tech room regulator"), regulator_config.get("serial", "0000"), controller)
                all_devices[regulator.address] = regulator

        mqtt_publisher = MqttPublisher(config["mqtt"], all_devices)

        logger.info("Setting up and starting the serial port listeners.")

        for port in config["serial_ports"]:
            serial_port = SerialPort(port, mqtt_publisher)
            serial_port_thread = threading.Thread(target=serial_port, daemon=True)
            serial_port_thread.start()

        mqtt_publisher()

        sys.exit(0)

