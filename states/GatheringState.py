from collections import defaultdict

import numpy

import common
import dal
from State import State
import sessions_extractor
from states.DetectingState import DetectingState


def calc_batch_rate_std():
    """

    :return: the std of packets per second in the current batch
    """
    packets_per_sec = defaultdict(int)

    for ts_pckt in common.current_batch:
        packets_per_sec[ts_pckt[0]] += 1

    return numpy.var(packets_per_sec.values())


def handle_batch():
    # Sessions
    map(lambda ts_pckt: sessions_extractor.handle_sessions(ts_pckt[0], ts_pckt[1]), common.current_batch)

    # Num of packets
    # Calc rate and number of packets in current batch
    n_packets_in_batch = len(common.current_batch)

    # Rate STD
    current_rate = calc_batch_rate_std()

    # add to DB rate and num of packets
    dal.append_batches_count(n_packets_in_batch)

    dal.append_batches_rate(current_rate)


class GatheringState(State):
    """
    This state is all about measuring the bandwidth and defining the size of a batch
    """

    def __init__(self, context):
        State.name = "Gathering State"
        State.__init__(self)
        self.context = context

    def process_packet(self, timestamp, packet):
        ip_frame = common.filter_ingoing_ip_traffic(packet)

        if not ip_frame:
            return

        # If current batch is not initialized, init and exit
        if common.current_batch is None:
            common.current_batch = []
            common.start_time = timestamp

        common.current_batch.append((timestamp, packet))

        # Else, check if time for new batch
        if common.start_time + common.BATCH_PERIOD > timestamp:
            return

        # Check current_batch for anomaly
        handle_batch()

        # Init new batch
        common.current_batch = []

        # Init start time to current timestamp
        common.start_time += common.BATCH_PERIOD

        if self.check_if_move_to_next_state(timestamp):
            self.context.current_state = DetectingState(self.context)

    def check_if_move_to_next_state(self, timestamp):
        return
