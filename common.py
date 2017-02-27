import socket

import dpkt
import numpy
from IPy import IP
from collections import defaultdict

import dal
import sessions_extractor

start_time = None

# Batch of the current period
current_batch = None

# probability critics for length of batch
BATCH_LEN_EPSILON = 0.01

# probability critics for rate in batch
RATE_EPSILON = 0.01

# Time period for each batch
BATCH_PERIOD = None

# Size of batches_count
PERIODS_IN_HOUR = None

PERIODS_IN_DAY = None

# Number of required batches before checking the traffic
TIME_TO_PARAMETERIZE = 24 * 60 * 60  # 1 Day

GATHERING_TIME = 24 * 60 * 60 * 14  # 2 weeks

# Days backwards to remember batches
DAYS_REMEMBER = 30

# Number of batches to remember
NUMBER_OF_BATCHES_TO_REMEMBER = None


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


def handle_batch():
    global current_batch, start_time, BATCH_PERIOD

    # Sessions
    map(lambda ts_pckt: sessions_extractor.handle_sessions(ts_pckt[0], ts_pckt[1]), current_batch)

    # Num of packets
    # Calc rate and number of packets in current batch
    n_packets_in_batch = len(current_batch)

    # Rate STD
    current_rate = calc_batch_rate_std()

    # add to DB rate and num of packets
    dal.append_batches_count(n_packets_in_batch)

    dal.append_batches_rate(current_rate)

    # Init new batch
    current_batch = []

    # Init start time to current timestamp
    start_time += BATCH_PERIOD


def calc_batch_rate_std():
    """

    :return: the std of packets per second in the current batch
    """
    global current_batch

    packets_per_sec = defaultdict(int)

    for ts_pckt in current_batch:
        packets_per_sec[ts_pckt[0]] += 1

    return numpy.var(packets_per_sec.values())
