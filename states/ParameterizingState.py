import socket
from collections import deque

import dpkt
from IPy import IP

import common
from State import State
from states.GatheringState import GatheringState


def ingoing_traffic(ip_frame):
    """
    Check it the traffic is from outside the net to inside

    :param ip_frame: frame to
    :return: True if the communication is from outside to internal network
    """
    src_ip = socket.inet_ntoa(ip_frame.src)
    dest_ip = socket.inet_ntoa(ip_frame.dst)

    src_ip_type = IP(src_ip).iptype()
    dest_ip_type = IP(dest_ip).iptype()

    return src_ip_type == 'PUBLIC' and dest_ip_type == 'PRIVATE'


def filter_ingoing_ip_traffic(packet):
    # Parse the input
    eth_frame = dpkt.ethernet.Ethernet(packet)

    # Check if IP
    if eth_frame.type != dpkt.ethernet.ETH_TYPE_IP:
        return

    # If not IP return
    ip_frame = eth_frame.data

    # If the traffic is not incoming traffic - return
    if not ingoing_traffic(ip_frame):
        return

    return ip_frame


class ParameterizingState(State):
    def __init__(self, context):
        State.__init__(self)
        self.context = context
        self.packets_counter = 0
        self.name = "Parameterizing State"

    def process_packet(self, timestamp, packet):
        if not common.start_time:
            common.start_time = timestamp

        ip_frame = filter_ingoing_ip_traffic(packet)

        if not ip_frame:
            return

        self.packets_counter += 1

        if self.check_if_move_to_next_state(timestamp):
            # Time parameterizing ended. parameterize.

            # Average time for 10000 packets to arrive
            common.BATCH_PERIOD = common.TIME_TO_PARAMETERIZE / (self.packets_counter / 10000)

            common.PERIODS_IN_HOUR = 60 * 60 / common.BATCH_PERIOD

            common.PERIODS_IN_DAY = 24 * common.PERIODS_IN_HOUR

            common.NUMBER_OF_BATCHES_TO_REMEMBER = common.PERIODS_IN_DAY * common.DAYS_REMEMBER

            # Fix-sized queue, holds the number of incoming packets in each batch
            common.batches_queue = deque([], common.NUMBER_OF_BATCHES_TO_REMEMBER)

            # Fix-sized queue, holds variance of rate packets in each batch
            common.rate_queue = deque([], common.NUMBER_OF_BATCHES_TO_REMEMBER)

            # Set start time for next phase
            common.start_time = timestamp

            # change State to Learning
            self.context.set_state(GatheringState(self.context))

    def check_if_move_to_next_state(self, timestamp):
        return timestamp - common.start_time > common.TIME_TO_PARAMETERIZE
