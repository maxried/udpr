#!/usr/bin/env python3
# coding=utf-8

"""Ubiquiti Networks Discovery Protocol Tool"""

import socket
from time import time
from UbntTLV import UbntTLV
from UbntTuple import lookup_tlv_type
from UbntLogging import l, e, d, set_debugging
import getopt
import sys

SOCKET = None
GLOBAL_TIMEOUT = 20
DISPLAY_MODE = 'edge'  # 'edge', 'oneline', 'everything'

def print_one_line(packet):
    hostname = ''
    ipv4 = ''
    model = ''
    hostname = ''

    for t in packet.TLVs:
        cur_type = t.Type
        if cur_type == 0x0b:  # hostname
            hostname = t.value_to_str()
        elif cur_type == 0x0c:  # model name
            model = t.value_to_str()
        elif cur_type == 0x02:  # 'MAC address and IP address'
            ipv4 = t.value_to_str().split('ipv4: ')[1]
        elif cur_type == 0x01:  # 'MAC address'
            hwaddr = t.value_to_str()

    l('{:17}  {:15}  {:10} \''.format(hwaddr, ipv4, model) + hostname + '\'')

def print_everything(packet):
    for t in packet.TLVs:
        l('{:26}: {:}'.format(lookup_tlv_type(t.Type), t.value_to_str()))

def print_edge_detail_style(packet):
    """Print a discovery result mimicking ERs show ubnt discovery detail output"""

    hostname = ''
    hwaddr = ''
    ipv4 = ''
    product = ''
    fwversion = ''
    uptime = ''
    addresses = ''

    for t in packet.TLVs:
        cur_type = t.Type
        if cur_type == 0x0b:  # hostname
            hostname = t.value_to_str()
        elif cur_type == 0x0c:  # model name
            product = t.value_to_str()
        elif cur_type == 0x02:  # 'MAC address and IP address'
            addresses += '\n    ' + t.value_to_str()
            ipv4 = t.value_to_str().split('ipv4: ')[1]
        elif cur_type == 0x01:  # 'MAC address'
            hwaddr = t.value_to_str()
        elif cur_type == 0x0a:  # 'uptime'
            uptime = t.value_to_str()
        elif cur_type == 0x03:  # 'firmware version'
            fwversion = t.value_to_str()

    l('hostname: ' + hostname)
    l('hwaddr: ' + hwaddr)
    l('ipv4: ' + ipv4)
    l('product: ' + product)
    l('fwversion: ' + fwversion)
    l('uptime: ' + uptime)
    l('addresses:' + addresses)


def init_socket():
    """Initialize the socket"""

    try:
        global SOCKET, GLOBAL_TIMEOUT

        d('Creating socket...')
        SOCKET = socket.socket(type=socket.SOCK_DGRAM)
        d('Making socket broadcast capable...')
        SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        d('Binding socket to port 10001...')
        SOCKET.bind(('', 10001))
        d('Set timeout to ' + str(GLOBAL_TIMEOUT) + 's...')
        SOCKET.settimeout(GLOBAL_TIMEOUT)
        d('Socket setup done.')
    except OSError as r:
        e('Could not create socket: ' + str(r))
        exit(-1)
    except Exception as ex:
        e('Error during socket setup: ' + str(ex))
        exit(-1)


def main():
    """Main function"""

    global GLOBAL_TIMEOUT, DISPLAY_MODE

    discovery_request = UbntTLV()
    d('Sending a discovery request to broadcast.')
    SOCKET.sendto(discovery_request.to_byte_array(), ('255.255.255.255', 10001))
    d('Sent.')

    d('Sending a discovery request to multicast.')
    SOCKET.sendto(discovery_request.to_byte_array(), ('233.89.188.1', 10001))
    d('Sent.')

    received_packets = []

    timeout = time() + GLOBAL_TIMEOUT

    while True:
        data = None
        came_from = (None, None)

        try:
            data, came_from = SOCKET.recvfrom(2048)
        except socket.timeout:
            d('Timeout reached')
            break
        except Exception as ex:
            d('Could not receive incoming packets: ' + str(ex))

        d('Incoming packet from ' + str(came_from))

        parsed_packet = None

        try:
            parsed_packet = UbntTLV(data)
        except Exception as r:
            e('Malformed packet: ' + str(r))

        if parsed_packet is not None:
            d('Received version ' + str(parsed_packet.Version) + ', opcode ' + str(parsed_packet.Opcode))
            if parsed_packet.Opcode in (0, 6) and len(parsed_packet.TLVs) > 2:
                received_packets.append(parsed_packet)
            else:
                d('Received non discovery response packet: \n' + str(parsed_packet))
        else:
            d('Received malformed packet: ' + str(data))

        if timeout < time():
            d('Timeout reached. Exiting loop.')
            break

    received_unique_packets = []

    for i in received_packets:
        found = False
        for i2 in received_unique_packets:
            if i.identifier() == i2.identifier():
                d('Found duplicate announcement.')
                found = True
                break
        if not found:
            received_unique_packets.append(i)

    l('Discovered ' + str(len(received_unique_packets)) + ' devices:')

    if DISPLAY_MODE == 'edgedetail':
        for unique_device in received_unique_packets:
            print_edge_detail_style(unique_device)
            l('')
    elif DISPLAY_MODE == 'oneline':
        l('{:17}  {:15}  {:10} '.format('Hardware Address', 'IP address', 'Model') + 'hostname')
        for unique_device in received_unique_packets:
            print_one_line(unique_device)

    elif DISPLAY_MODE == 'everthing':
        for unique_device in received_unique_packets:
            print_edge_detail_style(unique_device)


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hvt:m:")
    except getopt.GetoptError as err:
        l('Wrong usage!\n   -h   Help\n   -m   Display mode: oneline, everything, edge\n   -v   Verbose')
        exit(-1)
    set_debugging(False)
    DISPLAY_MODE = None
    GLOBAL_TIMEOUT = 11

    for o, a in opts:
        if o == '-v':
            set_debugging(True)
            d('Debugging enabled')
        elif o == '-m':
            if DISPLAY_MODE is not None or a not in ('edge', 'everything', 'oneline'):
                e('Mode must be EITHER edge, everything or oneline.')
                exit(-1)

            DISPLAY_MODE = a
            d('Display mode set to ' + a)
        elif o == '-t':
            if not str(a).isdigit():
                e('Timeout must be a number.')
                exit(-1)
            else:
                GLOBAL_TIMEOUT = int(a)
                d('Timeout set to ' + a)
        elif o == '-h':
            l('Ubiquiti Discovery Tool\n   -h   Help\n   -m   Display mode: oneline, everything, edge\n   -v   Verbose')
            exit(0)

    if DISPLAY_MODE is None:
        DISPLAY_MODE = 'oneline'

    init_socket()
    main()
