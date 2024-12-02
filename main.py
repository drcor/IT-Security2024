from scapy.all import *
from scapy.contrib.mqtt import *
from datetime import datetime

def parse_mqtt():
    mqtt_packets = []

    # filted for MQTT packets
    for pkt in packets:
        if MQTTPublish in pkt:
            mqtt_packets.append(pkt)

    for mqtt_pkt in mqtt_packets:
        # Extract the payload from the MQTT layer
        mqtt_topic = mqtt_pkt[MQTTPublish].topic.decode('utf-8')
        mqtt_message = mqtt_pkt[MQTTPublish].value

        print(f"Topic: {mqtt_topic}")
        data = json.loads(mqtt_message)
        print(f"Payload: {json.dumps(data, indent=4)}")  # Print first 50 bytes of the payload

        # Attempt to use steganography in timestamp
        if "ts" not in data:
            continue

        print(data["ts"])
        timestamp = datetime.strptime(data["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
        print(f"Timestamp: {timestamp}")

        integer_part = int(timestamp)
        fractional_part = timestamp - integer_part

        binary_message = ''.join(format(ord(char), '08b') for char in "Hi")

        # Pack the fractional part into 23 bits and overwrite with the message bits
        max_bits_to_use = 10  # Keep it small
        hidden_fraction = int(fractional_part * (2 ** max_bits_to_use))
        hidden_fraction &= ~(2 ** len(binary_message) - 1)  # Clear bits
        hidden_fraction |= int(binary_message, 2)  # Embed message

        # Reconstruct the new timestamp
        new_fraction = hidden_fraction / (2 ** max_bits_to_use)
        new_timestamp = integer_part + new_fraction

        print(f'>>>>>>>{new_timestamp}')
        datetime_obj_utc = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        date_string_utc = datetime_obj_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        print(f'>>>>>>>{date_string_utc}\n')

        # Encode or decode the message in the timestamp

        # with open("capture_4_mqtt_data.json", "a") as file:
        #     file.write(mqtt_topic+"\n")
        #     json.dump(data, file, indent=4)
        #     file.write("\n\n")


if __name__ == "__main__":
    # Load the pcap file
    pcap_file = "capture_4.pcapng"  # Replace with your pcap file path
    packets = rdpcap(pcap_file)

    parse_mqtt()
