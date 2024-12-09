from scapy.all import *
from scapy.contrib.mqtt import *
from datetime import datetime

import struct

def set_lsb_of_timestamp_float(timestamp, bit_value):
    # Convert float to its IEEE 754 binary representation (64-bit integer)
    float_bits = struct.unpack('Q', struct.pack('d', timestamp))[0]

    if bit_value == 1:
        # Set the LSB to 1 (ensure the last bit is 1 using OR operation)
        modified_bits = float_bits | 1
    elif bit_value == 0:
        # Set the LSB to 0 (ensure the last bit is 0 using AND operation)
        modified_bits = float_bits & ~1
    else:
        raise ValueError("bit_value must be 0 or 1")

    # Convert the modified bits back to a float
    modified_float = struct.unpack('d', struct.pack('Q', modified_bits))[0]

    return modified_float

def set_lsb_of_timestamp(timestamp, bit_value: int):
    int_part = int(timestamp)       # Split the integer part
    decimal_part = timestamp % 1    # Split the decimal part

    if bit_value == 1:
        # Set the LSB to 1 (ensure the last bit is 1 using OR operation)
        int_part = int_part | 1
    elif bit_value == 0:
        # Set the LSB to 0 (ensure the last bit is 0 using AND operation)
        int_part = int_part & ~1
    else:
        raise ValueError("bit_value must be 0 or 1")

    # Convert the modified bits back to a float
    modified_float = int_part + decimal_part
    return modified_float

def encode_message(msg="") -> int:
    if msg == "" or msg is None:
        return 0

    mqtt_packets = []
    start_message = [0, 0, 0, 0, 0, 0, 1, 0]    # STX
    count_start = 0
    end_message = [0, 0, 0, 0, 0, 0, 1, 1]      # ETX
    count_end = 0
    binary_message = ''.join(format(ord(char), '08b') for char in msg)
    count_bin = 0

    print(binary_message)

    # filted for MQTT packets
    for pkt in packets:
        if MQTTPublish in pkt:
            mqtt_packets.append(pkt)

    for mqtt_pkt in mqtt_packets:
        # Extract the payload from the MQTT layer
        mqtt_topic = mqtt_pkt[MQTTPublish].topic.decode('utf-8')
        mqtt_message = mqtt_pkt[MQTTPublish].value

        # print(mqtt_topic)

        data = json.loads(mqtt_message)
        # print(f"Payload: {json.dumps(data, indent=4)}")  # Print first 50 bytes of the payload

        # Attempt to use steganography in timestamp
        if "ts" not in data:
            continue

        # print(data["ts"])
        timestamp = datetime.strptime(data["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
        #print(f"Timestamp: {timestamp}")

        if count_start < len(start_message):
            timestamp = set_lsb_of_timestamp(timestamp, start_message[count_start])
            count_start += 1
        elif count_bin < len(binary_message):
            timestamp = set_lsb_of_timestamp(timestamp, int(binary_message[count_bin]))
            count_bin += 1
        elif count_end < len(end_message):
            timestamp = set_lsb_of_timestamp(timestamp, end_message[count_end])
            count_end += 1

        #print(f"Timestamp: {timestamp}")
        datetime_obj_utc = datetime.fromtimestamp(timestamp)
        date_string_utc = datetime_obj_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        print(f'>>>{date_string_utc}')

        # Encode or decode the message in the timestamp



if __name__ == "__main__":
    message = "hi"

    # Load the pcap file
    pcap_file = "capture_4.pcapng"  # Replace with your pcap file path
    packets = rdpcap(pcap_file)

    encode_message(message)
