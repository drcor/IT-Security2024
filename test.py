import struct
from datetime import datetime, timezone


def float_to_bin(f):
    """Convert a float to its binary representation (64-bit IEEE 754)."""
    return bin(struct.unpack('!Q', struct.pack('!d', f))[0])[2:].zfill(64)


def bin_to_float(b):
    """Convert a binary representation back to a float."""
    return struct.unpack('!d', struct.pack('!Q', int(b, 2)))[0]


def encode_message_in_timestamp(timestamp, message):
    """Encode a short message in the fractional part of a float timestamp."""
    # Convert the message to binary
    binary_message = ''.join(format(ord(c), '08b') for c in message)

    # Get the binary representation of the timestamp
    timestamp_bin = float_to_bin(timestamp)

    # Embed the message in the last bits of the fractional part
    new_timestamp_bin = timestamp_bin[:-len(binary_message)] + binary_message

    # Convert back to float
    modified_timestamp = bin_to_float(new_timestamp_bin)
    return modified_timestamp


def decode_message_from_timestamp(modified_timestamp, message_length):
    """Decode the hidden message from the fractional part of a modified timestamp."""
    # Get the binary representation of the modified timestamp
    modified_timestamp_bin = float_to_bin(modified_timestamp)

    # Extract the message from the LSBs
    binary_message = modified_timestamp_bin[-message_length * 8:]

    # Convert binary back to text
    message = ''.join(chr(int(binary_message[i:i + 8], 2)) for i in range(0, len(binary_message), 8))
    return message


# Original timestamp
original_timestamp = 1656414144.073  # Example timestamp (2022-06-28T11:42:24.073Z)

# Message to hide
message = "Hi!"

# Encode the message in the timestamp
encoded_timestamp = encode_message_in_timestamp(original_timestamp, message)
print("Original Timestamp:", original_timestamp)
print("Encoded Timestamp:", encoded_timestamp)

# Decode the message from the modified timestamp
decoded_message = decode_message_from_timestamp(encoded_timestamp, len(message))
print("Decoded Message:", decoded_message)

datetime_obj_utc = datetime.fromtimestamp(encoded_timestamp, tz=timezone.utc)
date_string_utc = datetime_obj_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
print(date_string_utc)