from encode import encode_message
from decode import decode_message

if __name__ == '__main__':
    # Load the pcap file
    input_filename = "capture_4.pcapng"  # Replace with your pcap file path
    output_filename = input_filename.split('.')[0] + '_edited.pcapng'

    message = input("Enter the message: ")

    encoded = encode_message(input_filename, message)
    print(f"Encoded message: '{message}' ({encoded} bits)")

    decoded = decode_message(output_filename)
    print(f"Decoded message: '{decoded}'")