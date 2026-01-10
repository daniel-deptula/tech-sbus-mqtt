import serial
import serial.threaded
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

logger = logging.getLogger(__name__)
topic_prefix = None
status_topic = None
ha_discovery_prefix = "homeassistant"
# all devices, keys are addresses
all_devices = {}
serial_instances = {}


class TechDevice:
    def __init__(self, address: str, name: str, model: str, serial_no: str):
        self.address = address
        self.name = name
        self.model = model
        self.serial_no = serial_no
        self.serial_port = ""

class TechController(TechDevice):
    def __init__(self, address: str, name: str, model: str, serial_no: str):
        super().__init__(address, name, model, serial_no)

class TechRoomRegulator(TechDevice):
    def __init__(self, address: str, name: str, model: str, serial_no: str, default_duration: int, controller: TechDevice):
        super().__init__(address, name, model, serial_no)
        self.controller = controller
        self.default_duration = default_duration

class TechSbusMessageToMqttProcessor:
    def __init__(self, msg, mqtt_publisher, serial_port_name):
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
        self.serial_port_name = serial_port_name
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
                crc32 = self.data[4:8]
                logger.debug("ACK. CRC32 of the message acknowledged: " + crc32.hex(' '))
                serial_instances[self.serial_port_name].handle_tech_sbus_ack((crc32, self.src_addr_str, self.dst_addr_str))
        else:
            i = 0
            while i < len(self.data):
                item_len = self.data[i]
                if item_len > 0 and i + item_len < len(self.data):
                    if item_len == 4 and self.data[i + 1] == 0:
                        # Room temperature
                        self.room_temp = float(
                            int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little', signed=False)) / 10
                        self.process_room_temperature()
                    elif item_len == 4 and self.data[i + 1] == 1:
                        # Floor temperature
                        self.floor_temp = float(
                            int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little', signed=False)) / 10
                        self.process_floor_temperature()
                    elif item_len == 4 and self.data[i + 1] == 2:
                        # Humidity
                        self.humidity = float(
                            int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little', signed=False)) / 10
                        self.process_humidity()
                    elif item_len == 6 and self.data[i + 1] == 0x14:
                        # Heating start/stop
                        self.status = int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little',
                                                     signed=False)
                        self.process_status()
                    elif item_len == 6 and self.data[i + 1] == 0x20:
                        # Target temperature for how long
                        self.target_temp_time = int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little',
                                                               signed=False)
                        self.process_target_temp_time()
                    elif item_len == 6 and self.data[i + 1] == 0x21:
                        # Target temperature
                        self.target_temp = float(
                            int.from_bytes(self.data[i + 3:i + item_len + 1], byteorder='little', signed=False)) / 10
                        self.process_target_temp()
                    elif item_len == 6 and self.data[i + 1] == 0x26 and item_len == 6:
                        # Time + target temperature (what's the purpose of it?!)
                        self.target_temp_time2 = int.from_bytes(self.data[i + 3:i + 5], byteorder='little',
                                                                signed=False)
                        self.target_temp2 = float(
                            int.from_bytes(self.data[i + 5:i + 7], byteorder='little', signed=False)) / 10
                        self.process_target_temp2()
                    else:
                        # Unknown parameter
                        logger.debug(self.fromto_header + ",Unknown parameter: " + self.data[i:i + item_len + 1].hex(' '))
                else:
                    # Something not supported
                    logger.debug(self.fromto_header + ",Unsupported data: " + self.data.hex(' '))
                i += (item_len + 1)

    def process_room_temperature(self):
        logger.debug(self.fromto_header + ",room temperature," + str(self.room_temp))
        self.mqtt_publisher.mqtt_publish_msg(self.src_addr_str, self.serial_port_name, "temperature/air/current", str(self.room_temp))

    def process_floor_temperature(self):
        logger.debug(self.fromto_header + ",floor temperature," + str(self.floor_temp))
        self.mqtt_publisher.mqtt_publish_msg(self.src_addr_str, self.serial_port_name, "temperature/floor/current", str(self.floor_temp))

    def process_humidity(self):
        logger.debug(self.fromto_header + ",humidity," + str(self.humidity))
        self.mqtt_publisher.mqtt_publish_msg(self.src_addr_str, self.serial_port_name, "humidity/current", str(self.humidity))

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
        self.mqtt_publisher.mqtt_publish_msg(addr, self.serial_port_name, "heating", status_str)

    def process_target_temp_time(self):
        if self.target_temp_time == 0xFFFFFFFF:
            time_str = "0"
        else:
            time_str = str(self.target_temp_time)
        logger.debug(self.fromto_header + ",target temperature time," + time_str)
        if isinstance(all_devices[self.src_addr_str], TechController):
            addr = self.dst_addr_str
        else:
            addr = self.src_addr_str
        self.mqtt_publisher.mqtt_publish_msg(addr, self.serial_port_name, "temperature/air/target/duration", time_str)

    def process_target_temp(self):
        logger.debug(self.fromto_header + ",target temperature," + str(self.target_temp))
        if isinstance(all_devices[self.src_addr_str], TechController):
            addr = self.dst_addr_str
        else:
            addr = self.src_addr_str
        self.mqtt_publisher.mqtt_publish_msg(addr, self.serial_port_name, "temperature/air/target", str(self.target_temp))

    def process_target_temp2(self):
        if self.target_temp_time2 == 0xFFFF:
            time_str = "0"
        else:
            time_str = str(self.target_temp_time2)
        logger.debug(self.fromto_header + ",target temperature (2)," + str(self.target_temp2))
        logger.debug(self.fromto_header + ",target temperature time (2)," + time_str)
        if isinstance(all_devices[self.src_addr_str], TechController):
            addr = self.dst_addr_str
        else:
            addr = self.src_addr_str
        self.mqtt_publisher.mqtt_publish_msg(addr, self.serial_port_name, "temperature/air/target2/duration", time_str)
        self.mqtt_publisher.mqtt_publish_msg(addr, self.serial_port_name, "temperature/air/target2", str(self.target_temp2))

    def process_timestamp(self):
        my_timestamp = int(self.timestamp)
        tzoffset = time.localtime(my_timestamp).tm_gmtoff
        delta = my_timestamp + tzoffset - self.received_timestamp
        logger.info(self.fromto_header + ",timestamp," + str(self.received_timestamp) + "," + str(delta))

class SerialPortReader(serial.threaded.LineReader):
    
    TERMINATOR = b'\x0a'
    
    def connection_made(self, transport):
        super(SerialPortReader, self).connection_made(transport)
        self.serial_port_name = transport.serial.port
        logger.info(f"Connected SerialPortReader {self.serial_port_name}")

    def __init__(self, mqtt_publisher):
        super(SerialPortReader, self).__init__()
        self.logger = logging.getLogger(SerialPortReader.__name__)
        self.serial_port_name = ""
        self.mqtt_publisher = mqtt_publisher
        self.msgs_pending_ack = set()
        self.ack_wait_timeout = 10.0

    def __call__(self):
        return self

    def handle_line(self, strmsg):
        if len(strmsg) > 0:
            logger.debug(f"[{self.serial_port_name}] Received: {strmsg}")
            if len(strmsg) > 6:
                if strmsg[0] == '>':
                    # first char is ">"
                    # "==" at the end of the base64-encoded string is missing
                    # The last 6 characters are encoded CRC-32
                    encmsg = strmsg[1:-6]
                    enccrc = strmsg[-6:] + "=="
                    logger.debug(f"[{self.serial_port_name}] Base64 encoded message: {encmsg}")
                    logger.debug(f"[{self.serial_port_name}] Base64 encoded CRC-32: {enccrc}")
                    try:
                        decoded_msg = base64.b64decode(encmsg)
                        logger.debug(f"[{self.serial_port_name}] Base64 decoded message: " + decoded_msg.hex(' '))
                        decoded_crc = base64.b64decode(enccrc)
                        # Compute CRC-32 of the decoded message
                        crc = binascii.crc32(decoded_msg)
                        if crc.to_bytes(4, byteorder='little', signed=False) == decoded_crc:
                            logger.debug(f"[{self.serial_port_name}] CRC check pass")
                            TechSbusMessageToMqttProcessor(decoded_msg, self.mqtt_publisher, self.serial_port_name)
                        else:
                            logger.error(f"[{self.serial_port_name}] CRC check failed")
                    except Exception as e:
                        logger.error(f"[{self.serial_port_name}] Message processing error: " + repr(e))
                else:
                    logger.error(f"[{self.serial_port_name}] Missing message start!")
            else:
                logger.error(f"[{self.serial_port_name}] Message too short: " + str(len(strmsg)))

    def write_line(self, data: bytes):
        """
        I'm overriding "write_line" to avoid unnecessary decoding/encoding, we have bytes object ready, not a string
        """
        return self.transport.write(data + self.TERMINATOR)

    def connection_lost(self, exc):
        if exc:
            logger.error(f"[{self.serial_port_name}] Connection lost: {exc}")
        logger.error(f"Serial port {self.serial_port_name} closed")

    def wait_for_tech_sbus_ack(self, ack_tuple: tuple) -> bool:
        timeout = time.time() + self.ack_wait_timeout
        while time.time() < timeout:
            if ack_tuple in self.msgs_pending_ack:
                time.sleep(0.01)
                continue
            else:
                return True
        return False

    def handle_tech_sbus_ack(self, ack_tuple: tuple):
        self.msgs_pending_ack.discard(ack_tuple)

    def add_pending_ack(self, ack_tuple: tuple):
        self.msgs_pending_ack.add(ack_tuple)

    def send_tech_sbus_frame(self, msg: bytes, ack_tuple: tuple):
        """
        Send a frame over the serial bus.
        If ACK required (ack_tuple provided), wait for the ACK for max. "ack_wait_timeout" seconds and raise an exception if it doesn't arrive.
        """
        crc = binascii.crc32(msg).to_bytes(4, byteorder='little', signed=False)
        logger.debug(f"[{self.serial_port_name}] Message to be sent: " + msg.hex(' '))
        logger.debug(f"[{self.serial_port_name}] CRC-32 to be sent: " + crc.hex(' '))
        b64msg = base64.b64encode(msg)
        b64crc = base64.b64encode(crc)[0:6]
        frame = b'>' + b64msg + b64crc
        logger.debug(f"[{self.serial_port_name}] Sending frame: {frame}")
        if ack_tuple != None:
            self.add_pending_ack(ack_tuple)
        try:
            bytes_written = self.write_line(frame)
        except Exception as e:
            if ack_tuple != None:
                self.handle_tech_sbus_ack(ack_tuple)
            raise
        logger.debug(f"[{self.serial_port_name}] Wrote {bytes_written} bytes.")
        if bytes_written != len(frame) + 1:
            if ack_tuple != None:
                self.handle_tech_sbus_ack(ack_tuple)
            raise RuntimeError("Incorrect number of bytes written. Serial write might have failed.")
        if ack_tuple != None:
            ack_received = self.wait_for_tech_sbus_ack(ack_tuple)
            if not ack_received:
                self.handle_tech_sbus_ack(ack_tuple)
                raise TimeoutError(f"ACK was expected but didn't arrive within required time: {ack_tuple}")

    def send_temp_set_msg(self, src_addr: str, dst_addr: str, new_temp: float, duration: int):
        try:
            if duration == 0:
                self.send_temp_reset_msgs(src_addr, dst_addr)
            else:
                self.send_tech_sbus_frame(self.contruct_temperature_set_msg(src_addr, dst_addr, new_temp, duration), None)
        except TimeoutError as e:
            logger.error(f"Timeout Error: {str(e)}")
        except Exception as e:
            logger.error(f"Serial write failed: {str(e)}")

    def send_temp_reset_msgs(self, src_addr: str, dst_addr: str):
        # Inform both the regulator and the controller that we're stopping manual temperature control
        data = bytes([0x06, 0x20, 0x00, 0xFF, 0xFF, 0xFF, 0xFF])
        # Expect an ACK from the controller and only then proceed
        self.send_tech_sbus_frame(self.construct_tech_sbus_header(src_addr, dst_addr) + data, self.construct_ack_tuple(src_addr, dst_addr, data))
        self.send_tech_sbus_frame(self.construct_tech_sbus_header(dst_addr, src_addr) + data, None)
        # Publishing the sent message over MQTT so that any listeners of the topic are aware of the change
        TechSbusMessageToMqttProcessor(self.construct_tech_sbus_header(src_addr, dst_addr) + data, self.mqtt_publisher, self.serial_port_name)

    def construct_tech_sbus_header(self, src_addr: str, dst_addr: str) -> bytes:
        bytes_src_addr = bytes.fromhex(src_addr.replace('-', ''))
        bytes_dst_addr = bytes.fromhex(dst_addr.replace('-', ''))
        return bytes_src_addr + bytes([0x50, 0x00]) + bytes_dst_addr + bytes([0x50, 0x00])

    def contruct_temperature_set_msg(self, src_addr: str, dst_addr: str, new_temp: float, duration: int) -> bytes:
        bytes_duration = duration.to_bytes(2, 'little')
        bytes_new_temp = int(round(new_temp*10)).to_bytes(2, 'little')
        return self.construct_tech_sbus_header(src_addr, dst_addr) + bytes([0x06, 0x26, 0x00]) + bytes_duration + bytes_new_temp

    def construct_ack_tuple(self, src_addr, dst_addr, data):
        # ACKs use bitwise NOT (complement) of the standard CRC-32
        crc = binascii.crc32(data)
        crc = ~crc
        return (crc.to_bytes(4, byteorder='little', signed=True), dst_addr, src_addr)

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
        self.mqtt_client.on_publish = self.mqtt_on_publish
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
            # Subscribe to the temperature set topic
            self.mqtt_client.message_callback_add(self.topic_prefix + "/+/temperature/air/target/set", self.on_target_temperature_set)
            self.mqtt_client.subscribe(self.topic_prefix + "/+/temperature/air/target/set")
            self.connected_to_broker = True
            self.published_regulator_addresses = set()
            logger.info("Connected to MQTT broker")
            
    def mqtt_on_connect_fail(self, client, userdata):
        logger.error(f"Failed to connect to the MQTT broker. loop_forever() will retry connection")

    def mqtt_on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        logger.error("Disconnected from MQTT broker!")
        self.connected_to_broker = False

    def mqtt_on_publish(self, client, userdata, mid, reason_code, properties):
        if reason_code.is_failure:
            logger.error(f"Failed to publish MQTT message {mid}: {reason_code.getName()}")
        else:
            logger.debug(f"Publishing result code for MQTT message {mid}: {reason_code.getName()}")

    def mqtt_publish(self, publish_topic, msg, retain: bool):
        log_msg_prefix = f"Publishing MQTT msg: {str(msg)} topic: {publish_topic}"
        try:
            self.publish_lock.acquire()
            retval = self.mqtt_client.publish(publish_topic, msg, retain=retain, qos=1)
            if retval.rc == mqtt.MQTT_ERR_SUCCESS:
                logger.debug(f"{log_msg_prefix} message_id: {retval.mid}")
            else:
                logger.error(f"{log_msg_prefix} - MQTT publishing error - client not connected?")
        except Exception as e:
            logger.error(f"log_msg_prefix - MQTT publishing error: {str(e)}")
        finally:
            self.publish_lock.release()

    def mqtt_publish_msg(self, addr, serial_port_name, topic, msg):
        if addr not in self.published_regulator_addresses and addr in self.all_devices and isinstance(all_devices[addr], TechRoomRegulator):
            self.mqtt_publish_discovery_msgs(addr, all_devices[addr].name, all_devices[addr].model, all_devices[addr].serial_no)
            all_devices[addr].serial_port = serial_port_name
            all_devices[addr].controller.serial_port = serial_port_name
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
                "temperature_command_topic": self.topic_prefix + "/" + addr + "/temperature/air/target/set",
                "temperature_command_template": "{\"temperature\": {{ value }}}",
                "min_temp": 5.0,
                "max_temp": 35.0,
                "temp_step": 0.1,
                "temperature_unit": "C",
                "mode_state_topic": self.topic_prefix + "/" + addr + "/heating",
                "mode_state_template": "{{ \"heat\" if value==\"on\" else \"off\" }}",
                "action_topic": self.topic_prefix + "/" + addr + "/heating",
                "action_template": "{{ \"heating\" if value==\"on\" else \"idle\" }}",
                "entity_category ": "EntityCategory.CONFIG",
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

    def on_target_temperature_set(self, client, userdata, msg):
        msg_topic = msg.topic
        msg_payload = msg.payload.decode()
        logger.debug(f"Temperature change request received: {msg_topic} {msg_payload}")
        topic_parts = msg_topic.split('/')
        if len(topic_parts) < 6:
            logger.error(f"Invalid topic for target temperature set: {msg.topic}")
            return
        addr = topic_parts[-5]
        if addr not in all_devices:
            logger.error(f"Target temperature set: Address {addr} not known!")
            return
        if len(all_devices[addr].serial_port) < 1:
            logger.error(f"Target temperature set: Serial port for device {addr} not (yet) known")
            return
        try:
            temp_change_object = json.loads(msg_payload)
            if 'temperature' not in temp_change_object:
                logger.error(f"Target temperature not provided in the temperature change request.")
                return
            temperature = float(temp_change_object["temperature"])
            if 'duration' not in temp_change_object:
                duration = all_devices[addr].default_duration
            else:
                duration = int(temp_change_object["duration"])
            if temperature < 5.0 or temperature > 35.0:
                logger.error(f"Requested temperature ({temperature}) out of range. Allowed values are 5.0 - 35.0 degrees.")
                return
            if duration < 0 or duration > 1441:
                logger.error(f"Requested temperature duration ({duration}) out of range. Allowed values are 0 - 1441 degrees.")
                return
        except Exception as e:
            logger.error(f"Invalid payload for target temperature set: {msg.payload}")
            return
        dst_addr = all_devices[addr].controller.address
        serial_instance = serial_instances[all_devices[addr].serial_port]
        logger.info(f"Sending temperature update from {addr} to {dst_addr} over {all_devices[addr].serial_port}. New target temperature: {temperature}, duration: {duration} minutes.")
        serial_instance.send_temp_set_msg(addr, dst_addr, temperature, duration)


def device_addr_str_from_bytes(addr: bytes) -> str:
    return addr.hex('-')

if __name__ == "__main__":
    with open(os.path.dirname(os.path.abspath(__file__)) + '/tech-sbus-mqtt.conf', 'r') as file:
        config = yaml.safe_load(file)

    logging.basicConfig(filename=config["log_file"], encoding='utf-8', format=LOG_FORMAT, level=config.get("log_level", "INFO"))

    with PidFile(config["pid_file"]):

        for controller_config in config.get("controllers", []):
            controller = TechController(controller_config["address"], controller_config["name"], controller_config.get("model", "Tech heating controller"), controller_config.get("serial", "00000"))
            all_devices[controller.address] = controller
            for regulator_config in controller_config["regulators"]:
                regulator = TechRoomRegulator(regulator_config["address"], regulator_config["name"], regulator_config.get("model", "Tech room regulator"), regulator_config.get("serial", "0000"), regulator_config.get("default_duration", 1441), controller)
                all_devices[regulator.address] = regulator

        mqtt_publisher = MqttPublisher(config["mqtt"], all_devices)

        logger.info("Setting up and starting the serial port listeners.")

        for port in config["serial_ports"]:
            logger.info("Initializing SerialPort " + port)
            try:
                serial_conn = serial.Serial(port, 115200, parity=serial.PARITY_NONE, bytesize=serial.EIGHTBITS, timeout=None)
                serial_thread = serial.threaded.ReaderThread(serial_conn, SerialPortReader(mqtt_publisher))
                serial_thread.start()
                transport, serial_instance = serial_thread.connect()
                serial_instances[port] = serial_instance
            except Exception as e:
                logger.error(f"Serial port {port} initialization failed: {e}")
                raise

        mqtt_publisher()

        sys.exit(0)
