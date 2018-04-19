#
# Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v1.0 which accompanies this distribution,
# and is available at http://www.eclipse.org/legal/epl-v10.html

import sys
import socket
import logging
import asyncio
import binascii
import ipaddress
import platform
import queue
import time

from threading import Thread

from struct import pack, unpack

from ..common.sfc_globals import sfc_globals
from ..nsh.common import *  # noqa
from ..nsh import decode as nsh_decode
from ..nsh.encode import add_sf_to_trace_pkt
from ..nsh.service_index import process_service_index

__author__ = "Jim Guichard, Reinaldo Penno"
__copyright__ = "Copyright(c) 2014, Cisco Systems, Inc."
__version__ = "0.3"
__email__ = "jguichar@cisco.com, rapenno@gmail.com"
__status__ = "beta"

"""
All supported services
"""

logger = logging.getLogger(__name__)

#: Global flags used for indication of current packet processing status
# Packet needs more processing within this SFF
PACKET_CHAIN = 0b00000000
# Packet was sent to another SFF or service function
PACKET_CONSUMED = 0b00000001
# Packet will be dropped
PACKET_ERROR = 0b00000010
# Referenced service function is invalid
SERVICE_HOP_INVALID = 0xDEADBEEF

#: Services names
CC = 'Central_Cloud'


def find_service(service_type):
    """Service dispatcher - get service class based on its type

    :param service_type: service type
    :type service_type: str

    :return `:class:Baseservice`

    """
    if service_type == CC :
        return MyCCService
    else:
        raise ValueError('Service "%s" not supported' % service_type)


class BasicService(object):
    def __init__(self, loop):
        """
        Service Blueprint Class

        :param loop:
        :type loop: `:class:asyncio.unix_events._UnixSelectorEventLoop`

        """
        self.loop = loop
        self.transport = None
        self.server_vxlan_values = VXLANGPE()
        self.server_base_values = BASEHEADER()
        self.server_ctx_values = CONTEXTHEADER()
        self.server_eth_values = ETHHEADER()
        self.server_trace_values = TRACEREQHEADER()

        # MUST be set by EACH descendant class
        self.service_type = None
        self.service_name = None

        self.packet_queue = queue.Queue()

        self.sending_thread = Thread(target=self.read_queue)
        self.sending_thread.daemon = True
        self.sending_thread.start()

    def set_name(self, name):
        self.service_name = name

    def get_name(self):
        """
        :return service name which is the same as SF/SFF name
        :rtype: str
        """
        return self.service_name

    def _decode_headers(self, data):
        """
        Procedure for decoding packet headers.

        Decode the incoming packet for debug purposes and to strip out various
        header values.

        """
        # decode vxlan-gpe header
        nsh_decode.decode_vxlan(data, self.server_vxlan_values)
        # decode NSH base header
        nsh_decode.decode_baseheader(data, self.server_base_values)
        # decode NSH context headers
        nsh_decode.decode_contextheader(data, self.server_ctx_values)
        # decode NSH eth headers
        nsh_decode.decode_ethheader(data, self.server_eth_values)
        # decode common trace header
        if nsh_decode.is_trace_message(data):
            nsh_decode.decode_trace_req(data, self.server_trace_values)

    def _process_incoming_packet(self, data, addr):
        """
        Decode NSH headers and process service index

        :param data: packet payload
        :type data: bytes
        :param addr: IP address and port to which data are passed
        :type addr: tuple

        """
        logger.debug('%s: Processing received packet(basicservice) service name :%s',
                     self.service_type, self.service_name)

        self._decode_headers(data)

        rw_data = bytearray(data)
        rw_data, _ = process_service_index(rw_data, self.server_base_values)
        sfc_globals.sf_processed_packets += 1

        return rw_data

    def _update_metadata(self, data,
                         network_platform=None, network_shared=None,
                         service_platform=None, service_shared=None):
        """
        Update NSH context header in received packet data

        :param data: packet data
        :type data: bytes
        :param network_platform: new network_platform value
        :type network_platform: int
        :param network_shared: new network_shared value
        :type network_shared: int
        :param service_platform: new service_platform value
        :type service_platform: int
        :param service_shared: new service_shared value
        :type service_shared: int

        :return bytearray

        """
        if network_platform is not None:
            self.server_ctx_values.network_platform = network_platform

        if network_shared is not None:
            self.server_ctx_values.network_shared = network_shared

        if service_platform is not None:
            self.server_ctx_values.service_platform = service_platform

        if service_shared is not None:
            self.server_ctx_values.service_shared = service_shared

        new_ctx_header = pack('!I I I I',
                              self.server_ctx_values.network_platform,
                              self.server_ctx_values.network_shared,
                              self.server_ctx_values.service_platform,
                              self.server_ctx_values.service_shared)

        data = bytearray(data)
        data[16:32] = new_ctx_header

        return data

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        """
        Put received packet into the internal queue

        :param data: packet data
        :type data: bytes
        :param addr: IP address and port to which data are passed
        :type addr: tuple

        """
        logger.info('ITS service received packet from %s:', self.service_type, addr)
        logger.debug('%s %s', addr, binascii.hexlify(data))
        packet = (data, addr)
        try:
            self.packet_queue.put_nowait(packet)
        except:
            msg = 'Putting into queue failed'
            # logger.info(msg)
            logger.exception(msg)

        if self.service_type == DPI:
            sfc_globals.sf_queued_packets += 1
        else:
            sfc_globals.sff_queued_packets += 1

    def process_datagram(self, data, addr):
        """
        Forward received packet accordingly based on its type

        :param data: packet data
        :type data: bytes
        :param addr: IP address and port to which data are passed
        :type addr: tuple

        """
        logger.info('ITS service processing..')
        logger.debug('%s %s', addr, binascii.hexlify(data))
        rw_data = self._process_incoming_packet(data, addr)
        if nsh_decode.is_data_message(data):
	    #logger.debug('%s: Sending packets to %s', self.service_type, addr)
            if nsh_decode.is_vxlan_nsh_legacy_message(data):
                # Disregard source port of received packet and send packet back to 6633
                addr_l = list(addr)
                addr_l[1] = 6633
                addr = tuple(addr_l)
        elif nsh_decode.is_trace_message(data):
            # Add SF information to packet
            if self.server_base_values.service_index == self.server_trace_values.sil:
                trace_pkt = add_sf_to_trace_pkt(rw_data, self.service_type, self.service_name)
                self.transport.sendto(trace_pkt, addr)
            # Send packet back to SFF
            else:
                self.transport.sendto(rw_data, addr)

    def read_queue(self):
        """
        Read received packet from the internal queue

        """
        try:
            while True:
                packet = self.packet_queue.get(block=True)
                self.process_datagram(data=packet[0], addr=packet[1])
                self.packet_queue.task_done()
        except:
            msg = 'Reading from queue failed'
            logger.info(msg)
            logger.exception(msg)
            raise

    def process_trace_pkt(self, rw_data, data):
        logger.info('%s: Sending trace report packet', self.service_type)
        ipv6_addr = ipaddress.IPv6Address(data[
                                          NSH_OAM_TRACE_DEST_IP_REPORT_OFFSET:NSH_OAM_TRACE_DEST_IP_REPORT_OFFSET + NSH_OAM_TRACE_DEST_IP_REPORT_LEN])  # noqa
        if ipv6_addr.ipv4_mapped:
            ipv4_str_trace_dest_addr = str(ipaddress.IPv4Address(self.server_trace_values.ip_4))
            trace_dest_addr = (ipv4_str_trace_dest_addr, self.server_trace_values.port)
            logger.info("IPv4 destination:port address for trace reply: %s", trace_dest_addr)
            self.transport.sendto(rw_data, trace_dest_addr)
        else:
            ipv6_str_trace_dest_addr = str(ipaddress.IPv6Address(ipv6_addr))
            trace_dest_addr = (ipv6_str_trace_dest_addr, self.server_trace_values.port)
            logger.info("IPv6 destination address for trace reply: %s", trace_dest_addr)
            self.transport.sendto(rw_data, trace_dest_addr)

    @staticmethod
    def connection_refused(exc):
        logger.error('Connection refused: %s', exc)

    def connection_lost(self, exc):
        logger.warning('Closing transport', exc)
        loop = asyncio.get_event_loop()
        loop.stop()



class MyCCService(BasicService):
    def __init__(self, loop):
        super(MyCCService, self).__init__(loop)

        self.service_type = CC




class ControlUdpServer(BasicService):
    def __init__(self, loop):
        """
        This control server class listen on a socket for commands from the main
        process. For example, if a SFF is deleted the main program can send a
        command to this data plane thread to exit.
        """
        # super(ControlUdpServer, self).__init__(loop)
        self.loop = loop
        self.transport = None
        self.service_name = None
        self.service_type = 'Control UDP Server'

    def datagram_received(self, data, addr):
        logger.info('%s received a packet from: %s', self.service_type, addr)
        self.loop.call_soon_threadsafe(self.loop.stop)
        # data = data.decode('utf-8')
        # print(data_plane_path)
        # sfp_topo = json.loads(data)
        # print(sfp_topo)
        # print(sfp_topo['3']['3'])

    def connection_lost(self, exc):
        logger.error('stop: %s', exc)


