#!/usr/bin/env python3
# coding=utf-8

"""Class file for Ubnt Discovery Protocol Packet"""

from typing import List
from UbntTuple import UbntTuple
from struct import unpack, pack


class UbntTLV:
    """This class represents a packet of the Ubiquiti Discovery Protocol"""

    def __init__(self, packet: bytearray=None):
        self.TLVs: List[UbntTuple] = []
        self.Version: int = 1
        self.Opcode: int = 0

        if packet is not None:
            if len(packet) >= 4:
                header: bytearray = packet[0:4]

                (self.Version,
                 self.Opcode,
                 length) = unpack('!BBH', header)

                if length + 4 != len(packet):
                    raise Exception('Wrong packet length: ' + str(length + 4) +
                                    ' expected vs ' + str(len(packet)) + ' received.')

                raw_tlv_data: bytearray = packet[len(header):]

                while len(raw_tlv_data) >= 3:
                    tlv_header: bytearray = raw_tlv_data[0:3]
                    raw_tlv_data: bytearray = raw_tlv_data[len(tlv_header):]
                    (tlv_type, tlv_length) = unpack('!BH', tlv_header)
                    if len(raw_tlv_data) < tlv_length:
                        raise Exception('Packet too short, TLV ' + str(tlv_type) +
                                        ', expected ' + str(tlv_length) + ', ' + str(len(raw_tlv_data)) + ' left.')

                    tlv: UbntTuple = UbntTuple()
                    tlv.Type = tlv_type
                    tlv.Value = raw_tlv_data[0:tlv_length]
                    raw_tlv_data = raw_tlv_data[tlv_length:]

                    self.TLVs.append(tlv)

                if len(raw_tlv_data) > 0:
                    raise Exception('Packet too long: ' + str(len(raw_tlv_data)) + ' Bytes left behind TLVs.')

            else:
                raise Exception('Packet too short: ' + str(len(packet)) + ' vs 4 bytes minimum.')

    def to_byte_array(self) -> bytes:
        """Prepare myself for sending"""

        payload = b''

        for t in self.TLVs:
            c_payload = t.to_byte_array()
            payload += c_payload if c_payload is not None else b''

        packed = pack('!BBH', self.Version, self.Opcode, len(payload)) + payload

        return packed

    def identifier(self) -> str:
        """Returns identifier for checking for uniqueness of the discovered device"""

        for t in self.TLVs:
            if t.Type == 0x02:
                return str(t)

        return ''

    def __str__(self) -> str:
        result = ('Version: ' + str(self.Version) +
                  '\nOpcode: ' + str(self.Opcode) + '\n')

        for t in self.TLVs:
            result += str(t) + '\n'

        return result
