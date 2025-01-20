from scapy.all import *
from scapy.contrib.mqtt import *
from datetime import datetime

import random

from scapy.layers.inet import IP

from lsb import set_lsb_of_timestamp


def encode_message(input_file, msg="") -> int:
    if msg == "" or msg is None:
        return 0

    start_message = [0, 0, 0, 0, 0, 0, 1, 0]    # STX
    count_start = 0
    end_message = [0, 0, 0, 0, 0, 0, 1, 1]      # ETX
    count_end = 0
    binary_message = ''.join(format(ord(char), '08b') for char in msg)
    count_bin = 0

    # DEBUG: Create delay so that the decode function can identify the beginning of the text
    delay_iterations = random.randint(0, 8)
    count_delay = 0
    # print(f"Delay of {delay_iterations} MQTT packets")

    counter = 0

    packets = rdpcap(input_file)

    # filter for MQTT packets
    for pkt in packets:
        # Filter by MQTT Publish packages
        if MQTTPublish not in pkt:
            continue

        counter += 1
        # DEBUG: So that the encoding message doesn't start imediatly in the first packet
        # To make the code more fault proof
        if count_delay < delay_iterations:
            count_delay += 1
            continue

        # Extract the payload from the MQTT layer
        #mqtt_topic = mqtt_pkt[MQTTPublish].topic.decode('utf-8')
        mqtt_message = pkt[MQTTPublish].value

        # print(mqtt_topic)

        data = json.loads(mqtt_message)

        # Check if there is a timestamp field in the data
        if "ts" not in data:
            continue

        timestamp = datetime.strptime(data["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()

        if count_start < len(start_message):
            timestamp = set_lsb_of_timestamp(timestamp, start_message[count_start])
            count_start += 1
        elif count_bin < len(binary_message):
            timestamp = set_lsb_of_timestamp(timestamp, int(binary_message[count_bin]))
            count_bin += 1
        elif count_end < len(end_message):
            timestamp = set_lsb_of_timestamp(timestamp, end_message[count_end])
            count_end += 1
        else:
            continue

        #print(f"Timestamp: {timestamp}")
        datetime_obj_utc = datetime.fromtimestamp(timestamp)
        date_string_utc = datetime_obj_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z"
        # print(f'>>>{data["ts"]} {date_string_utc}')

        # Update packet with the new modified timestamp
        data["ts"] = date_string_utc


        pkt[MQTTPublish].value = json.dumps(data).encode('utf-8')

        del pkt[MQTT].len
        del pkt.len  # Force recalculation of IP length
        del pkt.chksum  # Force recalculation of IP checksum

        # Rebuild the packet to ensure all fields are recalculated
        pkt = pkt.__class__(bytes(pkt))

    # Save file
    output_file = input_file.split('.')[0] + '_encoded.pcapng'
    wrpcap(output_file, packets)

    return len(binary_message) + 16


if __name__ == "__main__":
    message = input("Insert a message to encode: ")
    print("Encoding...")

    input_filename = "capture_4.pcapng"  # Replace with the pcap file path

    encode_message(input_filename, message)

    print(f"Encoded message: '{message}'")
    print(f"Saved to file: '{input_filename.split('.')[0]}_encoded.{input_filename.split('.')[1]}'")
