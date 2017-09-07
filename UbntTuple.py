#!/usr/bin/env python3
# coding=utf-8

"""Class file for TLV tuples"""


from struct import pack, unpack


def lookup_tlv_type(type_id):
    """Convert TLV type to human readable strings by best guess"""

    result = 'unknown'

    if type_id == 0x01:
        result = 'MAC address'
    elif type_id == 0x02:
        result = 'address'
    elif type_id == 0x03:
        result = 'software'
    elif type_id == 0x06:
        result = 'username'
    elif type_id == 0x07:
        result = 'salt'
    elif type_id == 0x08:
        result = 'challenge'
    elif type_id == 0x0a:
        result = 'uptime'
    elif type_id == 0x0b:
        result = 'hostname'
    elif type_id == 0x0c:
        result = 'model name'
    elif type_id == 0x0d:
        result = 'essid'
    elif type_id == 0x0e:
        result = 'wmode'
    elif type_id == 0x12:
        result = 'counter'
    elif type_id == 0x13:
        result = 'MAC address (UniFi)'
    elif type_id == 0x15:
        result = 'model name (UniFi)'
    elif type_id == 0x16:
        result = 'firmware revision'
    elif type_id == 0x17:
        result = 'unknown (UniFi)'
    elif type_id == 0x18:
        result = 'unknown (UniFi)'
    elif type_id == 0x19:
        result = 'DHCP enabled (UniFi)'
    elif type_id == 0x1b:
        result = 'min firmware (UniFi)'  # ?
    elif type_id == 0x1a:
        result = 'unknown (UniFi)'

    result += ' (' + str(type_id) + ')'

    return result


class UbntTuple:
    """An entry in an Ubnt Discovery Protocol Packet"""

    def __init__(self):
        self.Type = 0
        self.Value = b''

    def value_to_str(self):
        """Convert my value to a human readable string"""

        if self.Type in (0x03, 0x0b, 0x0c, 0x15, 0x16, 0x1b):  # str
            return self.Value.decode(encoding='iso-8859-1')
        elif self.Type == 0x01 or self.Type == 0x13:
            return '{0[0]:02X}:{0[1]:02X}:{0[2]:02X}:{0[3]:02X}:{0[4]:02X}:{0[5]:02X}'.format(self.Value)
        elif self.Type == 0x02:
            return \
                ('hwaddr: {0[0]:02X}:{0[1]:02X}:{0[2]:02X}:{0[3]:02X}:{0[4]:02X}:{0[5]:02X}, ipv4: ' +
                 '{0[6]:d}.{0[7]:d}.{0[8]:d}.{0[9]:d}').format(self.Value)
        elif self.Type == 0x0a:
            return str(unpack('!I', self.Value)[0]) + ' seconds'
        elif self.Type == 0x12:
            return str(unpack('!I', self.Value)[0])
        elif self.Type in (0x17, 0x18, 0x19, 0x1a):
            return str(int.from_bytes(self.Value, byteorder='big') == 1)
        else:
            return str(self.Value)

    def __str__(self):
        return lookup_tlv_type(self.Type) + ': ' + \
               self.value_to_str()

    def to_byte_array(self):
        """Convert myself to a bytearray ready for sending"""
        return pack('!BH', self.Type, len(self.Value)) + self.Value
