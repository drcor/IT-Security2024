from scapy.all import *
from scapy.contrib.mqtt import *
from datetime import datetime

from lsb import get_lsb_from_timestamp, contains_sequence, find_end_sequence


def binary_array_to_ascii(bin_array):
    # Ensure the length of the array is a multiple of 8
    if len(bin_array) % 8 != 0:
        raise ValueError("Binary array length must be a multiple of 8")

    # Group into 8-bit chunks and convert to ASCII
    utf8_string = ''.join(
        chr(int(''.join(map(str, bin_array[i:i + 8])), 2))
        for i in range(0, len(bin_array), 8)
    )
    return utf8_string


def decode_message(input_file):
    bin_array = []
    start_message = [0, 0, 0, 0, 0, 0, 1, 0]    # STX
    end_message = [0, 0, 0, 0, 0, 0, 1, 1]      # ETX

    counter = 0

    packets = rdpcap(input_file)
    for pkt in packets:
        # Filter by MQTT Publish packages
        if MQTTPublish not in pkt:
            continue

        counter += 1

        mqtt_message = pkt[MQTTPublish].value

        data = json.loads(mqtt_message)

        # Check if there is a timestamp field in the data
        if "ts" not in data:
            continue

        timestamp = datetime.strptime(data["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()

        bin_array.append(get_lsb_from_timestamp(timestamp))

    stx = contains_sequence(bin_array, start_message)
    etx = find_end_sequence(bin_array, stx, end_message)

    print(f"Number of MQTT Publish packets: {counter}")
    # print(f"[{stx}:{etx}]")

    msg_bin_array = bin_array[stx:etx]
    # print(''.join(str(x) for x in bin_array))
    msg = binary_array_to_ascii(msg_bin_array)

    return msg


if __name__ == "__main__":
    input_filename = "capture_4_encoded.pcapng"  # Replace with the pcap file path

    print(f"Decoding file: {input_filename}")

    message = decode_message(input_filename)
    print(f"Decoded message: '{message}'")
