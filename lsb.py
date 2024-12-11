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


def get_lsb_from_timestamp(timestamp) -> int:
    int_part = int(timestamp)       # Split the integer part
    return int_part % 2


def contains_sequence(bin_array, sequence):
    sequence_length = len(sequence)
    # Check if the sequence exists anywhere in bin_array
    for i in range(len(bin_array) - sequence_length + 1):
        if bin_array[i:i + sequence_length] == sequence:
            return i + sequence_length
    return False

def find_end_sequence(bin_array, stx_index, sequence):
    sequence_length = len(sequence)
    # Check if the sequence exists after the stx_index in bin_array going byte by byte
    for i in range(stx_index, len(bin_array) - sequence_length + 1, 8):
        if bin_array[i:i + sequence_length] == sequence:
            return i
    return False
