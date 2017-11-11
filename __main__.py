#!/usr/bin/env python3
# coding=utf-8

"""Ubiquiti Networks Discovery Protocol Tool"""

import socket
from typing import List, Tuple
from platform import platform
from uuid import getnode as get_mac
from time import time
from struct import pack
from UbntTLV import UbntTLV
from UbntTuple import lookup_tlv_type, UbntTuple
from UbntLogging import l, e, d, set_debugging
import getopt
import sys

SOCKET = None
GLOBAL_TIMEOUT = 20
DISPLAY_MODE = 'edge'  # 'edge', 'oneline', 'everything'


def print_one_line(packet: UbntTLV) -> None:
    """Print a discovery as one line for column view"""

    ipv4: str = ''
    model: str = ''
    hostname: str = ''
    hwaddr: str = ''

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


def print_everything(packet: UbntTLV) -> None:
    """Most verbose output for discovery packets"""

    for t in packet.TLVs:
        l('{:26}: {:}'.format(lookup_tlv_type(t.Type), t.value_to_str()))


def print_edge_detail_style(packet: UbntTLV) -> None:
    """Print a discovery result mimicking ERs show ubnt discovery detail output"""

    hostname: str = ''
    hwaddr: str = ''
    ipv4: str = ''
    product: str = ''
    fwversion: str = ''
    uptime: str = ''
    addresses: str = ''

    for t in packet.TLVs:
        cur_type: int = t.Type
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


def init_socket() -> None:
    """Initialize the socket"""

    try:
        global SOCKET, GLOBAL_TIMEOUT

        d('Creating socket...')
        SOCKET = socket.socket(type=socket.SOCK_DGRAM)
        d('Making socket broadcast capable...')
        SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        d('Binding socket to port 10001...')
        SOCKET.bind(('', 10001))
        if GLOBAL_TIMEOUT == 0:
            d('No timeout.')
        else:
            d('Set timeout to ' + str(GLOBAL_TIMEOUT) + 's...')
            SOCKET.settimeout(GLOBAL_TIMEOUT)
        d('Socket setup done.')
    except OSError as r:
        e('Could not create socket: ' + str(r))
        exit(-1)
    except Exception as ex:
        e('Error during socket setup: ' + str(ex))
        exit(-1)


def create_answer_packet():
    """Creates a legit packet for discovery"""

    my_hostname: str = socket.gethostname()
    my_uptime: int = int(time() - BOOT_TIME)

    d('Hostname is ' + str(my_hostname))
    d('Uptime is ' + str(my_uptime))

    result: UbntTLV = UbntTLV()
    result.Opcode = 0
    result.Version = 1

    data: UbntTuple = UbntTuple()
    data.Type = 0x0a
    data.Value = pack('!I', my_uptime)

    result.TLVs.append(data)

    data: UbntTuple = UbntTuple()
    data.Type = 0x0b
    data.Value = my_hostname.encode(encoding='iso-8859-1')

    result.TLVs.append(data)

    data: UbntTuple = UbntTuple()
    data.Type = 0x01
    data.Value = get_mac().to_bytes(length=6, byteorder='big')

    result.TLVs.append(data)

    data: UbntTuple = UbntTuple()
    data.Type = 0x02
    data.Value = get_mac().to_bytes(length=6, byteorder='big') + \
                 b''.join(map(lambda x: int(x).to_bytes(length=1, byteorder='big'),
                              socket.gethostbyname(socket.gethostname()).split('.')))

    result.TLVs.append(data)

    data: UbntTuple = UbntTuple()
    data.Type = 0x03
    data.Value = platform().encode(encoding='iso-8859-1')

    result.TLVs.append(data)

    d('Prepared for outgoing:')
    d(str(result))

    return result


def server():
    """Main server function"""

    global GLOBAL_TIMEOUT

    timeout: int = time() + GLOBAL_TIMEOUT

    try:
        while True:
            if GLOBAL_TIMEOUT != 0 and time() >= timeout:
                l('Timeout reached, exiting.')
                break

            try:
                data, came_from = SOCKET.recvfrom(2048)
            except socket.timeout:
                d('Timeout reached')
                break
            except Exception as ex:
                e('Could not receive incoming packets: ' + str(ex))

            d('Incoming packet from ' + str(came_from))

            parsed_packet: UbntTLV = None

            try:
                parsed_packet = UbntTLV(data)
            except Exception as r:
                e('Malformed packet: ' + str(r))

            if parsed_packet is not None:
                d('Received version ' + str(parsed_packet.Version) + ', opcode ' + str(parsed_packet.Opcode))
                if parsed_packet.Version == 1 and parsed_packet.Opcode == 0:
                    l('Received query from ' + str(came_from) + '. Answering.')
                    answer: UbntTLV = create_answer_packet()
                    SOCKET.sendto(answer.to_byte_array(), came_from)
                else:
                    d('Received non discovery request packet: \n' + str(parsed_packet))
            else:
                d('Received malformed packet: ' + str(data))

    except KeyboardInterrupt:
        l('Goodbye')
    except Exception as err:
        e('Uncaught exception in server mode: ' + str(err))
        exit(-1)


def client() -> None:
    """Main client function"""

    global GLOBAL_TIMEOUT, DISPLAY_MODE

    discovery_request: UbntTLV = UbntTLV()
    d('Sending a discovery request to broadcast.')
    SOCKET.sendto(discovery_request.to_byte_array(), ('255.255.255.255', 10001))
    d('Sent.')

    d('Sending a discovery request to multicast.')
    SOCKET.sendto(discovery_request.to_byte_array(), ('233.89.188.1', 10001))
    d('Sent.')

    received_packets: List[UbntTLV] = []

    timeout: int = time() + GLOBAL_TIMEOUT

    while True:
        data: bytearray = None
        came_from: Tuple[str, int] = ('', 0)

        try:
            data, came_from = SOCKET.recvfrom(2048)
        except socket.timeout:
            d('Timeout reached')
            break
        except Exception as ex:
            e('Could not receive incoming packets: ' + str(ex))

        d('Incoming packet from ' + str(came_from))

        parsed_packet: UbntTLV = None

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

    received_unique_packets: List[UbntTLV] = []

    for i in received_packets:
        found: bool = False
        for i2 in received_unique_packets:
            if i.identifier() == i2.identifier():
                d('Found duplicate announcement.')
                found = True
                break
        if not found:
            received_unique_packets.append(i)

    l('Discovered ' + str(len(received_unique_packets)) + ' devices:')

    if DISPLAY_MODE == 'edge':
        for unique_device in received_unique_packets:
            print_edge_detail_style(unique_device)
            l('')
    elif DISPLAY_MODE == 'oneline':
        l('{:17}  {:15}  {:10} '.format('Hardware Address', 'IP address', 'Model') + 'hostname')
        for unique_device in received_unique_packets:
            print_one_line(unique_device)

    elif DISPLAY_MODE == 'everything':
        for unique_device in received_unique_packets:
            print_edge_detail_style(unique_device)


def usage() -> None:
    """Show usage"""

    l('Ubiquiti Discovery Tool\n   -h   Help\n   -m   Display mode: oneline, everything, edge\n' +
      '   -v   Verbose\n   -s   Server mode\n   -c   Client mode\n   -B   Seconds since boot for server mode')


if __name__ == '__main__':
    opts: Tuple = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], "scB:hvt:m:")
    except getopt.GetoptError:
        e('Wrong usage!')
        exit(-1)

    set_debugging(False)
    DISPLAY_MODE = None
    MODE = None
    GLOBAL_TIMEOUT = None
    BOOT_TIME = None

    for o, a in opts:
        if o == '-v':
            set_debugging(True)
            d('Debugging enabled')
        elif o == '-m':
            if DISPLAY_MODE is not None or a not in ('edge', 'everything', 'oneline'):
                e('Display mode must be EITHER edge, everything or oneline.')
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
            usage()
            exit(0)
        elif o == '-s':
            if MODE is not None:
                e('Mode must be EITHER client or server.')
                exit(-1)
            else:
                MODE = 'server'
        elif o == '-c':
            if MODE is not None:
                e('Mode must be EITHER client or server.')
                exit(-1)
            else:
                MODE = 'client'
        elif o == '-B':
            if not str(a).isdigit():
                e('Boot time must be a number.')
                exit(-1)
            else:
                BOOT_TIME = int(a)
                d('Boot time set to ' + a)

    if GLOBAL_TIMEOUT is None:
        GLOBAL_TIMEOUT = 11
        d('Defaulting timeout to ' + str(GLOBAL_TIMEOUT))

    if DISPLAY_MODE is None:
        DISPLAY_MODE = 'oneline'
        d('Defaulting to display mode ' + DISPLAY_MODE)

    if MODE is None:
        MODE = 'client'
        d('Defaulting to mode ' + MODE)

    init_socket()

    if MODE == 'client':
        if GLOBAL_TIMEOUT == 0:
            e('Timeout of 0 is invalid for client mode.')
            exit(-1)
        d('Launching client mode.')
        client()
    elif MODE == 'server':
        if BOOT_TIME is None:
            d('Saving current time as server boot time.')
            BOOT_TIME = time()
            d('Boot time is ' + str(BOOT_TIME))

        d('Launching server mode.')
        server()
