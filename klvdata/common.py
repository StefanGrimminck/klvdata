#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# The MIT License (MIT)
#
# Copyright (c) 2017 Matthew Pare (paretech@gmail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from struct import pack
from struct import unpack
from datetime import datetime
from datetime import timezone
from binascii import hexlify, unhexlify

def datetime_to_bytes(value):
    """Return bytes representing UTC time in microseconds."""
    return pack('>Q', int(value.timestamp() * 1e6))


def bytes_to_datetime(value):
    """Return datetime from microsecond bytes."""
    return datetime.fromtimestamp(bytes_to_int(value)/1e6, tz=timezone.utc)


def bytes_to_int(value, signed=False):
    """Return integer given bytes."""
    return int.from_bytes(bytes(value), byteorder='big', signed=signed)


def int_to_bytes(value, length=1, signed=False):
    """Return bytes given integer"""
    return int(value).to_bytes(length, byteorder='big', signed=signed)


def ber_decode(value):
    """Return decoded BER length as integer given bytes."""
    if bytes_to_int(value) < 128:
        if len(value) > 1:
            raise ValueError

        # Return BER Short Form
        return bytes_to_int(value)
    else:
        if len(value) != (value[0] - 127):
            raise ValueError

        # Return BER Long Form
        return bytes_to_int(value[1:])


def ber_encode(value):
    """Return encoded BER length as bytes given integer."""
    if value < 128:
        # BER Short Form
        return int_to_bytes(value)
    else:
        # BER Long Form
        byte_length = ((value.bit_length() - 1) // 8) + 1

        return int_to_bytes(byte_length + 128) + int_to_bytes(value, length=byte_length)


def bytes_to_str(value):
    """Return UTF-8 formatted string from bytes object."""
    return bytes(value).decode('UTF-8')


def str_to_bytes(value):
    """Return bytes object from UTF-8 formatted string."""
    return bytes(str(value), 'UTF-8')


def hexstr_to_bytes(value):
    """Return bytes object and filter out formatting characters from a string of hexadecimal numbers."""
    return bytes.fromhex(''.join(filter(str.isalnum, value)))


def bytes_to_hexstr(value, start='', sep=' '):
    """Return string of hexadecimal numbers separated by spaces from a bytes object."""
    return start + sep.join(["{:02X}".format(byte) for byte in bytes(value)])


def linear_map(src_value, src_domain, dst_range):
    src_min, src_max, dst_min, dst_max = src_domain + dst_range

    # Adjust src_value if it's exactly the lower boundary of a signed integer
    if src_value < src_min or src_value > src_max :
        return None

    if not (src_min <= src_value <= src_max):
        print(f"Value {src_value} out of range ({src_min}, {src_max})")

    slope = (dst_max - dst_min) / (src_max - src_min)
    dst_value = slope * (src_value - src_min) + dst_min

    if not (dst_min <= dst_value <= dst_max):
        print(f"Destination value {dst_value} out of range ({dst_min}, {dst_max})")

    return dst_value


def bytes_to_float(value, _domain, _range):
    """Convert the fixed point value self.value to a floating point value."""
    src_value = int().from_bytes(value, byteorder='big', signed=(min(_domain) < 0))
    return linear_map(src_value, _domain, _range)


def float_to_bytes(value, _domain, _range):
    print(f"Original float: {value}")
    src_domain, dst_range = _range, _domain
    src_min, src_max, dst_min, dst_max = src_domain + dst_range
    length = (dst_max.bit_length() + 7) // 8  # Adjusted to ensure correct byte length
    dst_value = linear_map(value, src_domain=src_domain, dst_range=dst_range)
    byte_result = round(dst_value).to_bytes(length, byteorder='big', signed=(dst_min < 0))
    print(f"Mapped int: {dst_value}, Byte representation: {byte_result}")
    return byte_result


def packet_checksum(data):
    """Return two byte checksum from a SMPTE ST 336 KLV structured bytes object."""
    length = len(data) - 2
    word_size, mod = divmod(length, 2)

    words = sum(unpack(">{:d}H".format(word_size), data[0:length - mod]))

    if mod:
        words += data[length - 1] << 8

    return pack('>H', words & 0xFFFF)
