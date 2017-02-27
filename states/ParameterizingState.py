from collections import deque

from states.GatheringState import GatheringState

import common
from State import State


class ParameterizingState(State):
    def __init__(self, context):
        State.name = "Parameterizing State"
        State.__init__(self)
        self.context = context
        self.packets_counter = 0

    def process_packet(self, timestamp, packet):
        if not common.start_time:
            State.state_start_time = common.start_time = timestamp

        ip_frame = common.filter_ingoing_ip_traffic(packet)

        if not ip_frame:
            return

        self.packets_counter += 1

        if self.check_if_move_to_next_state(timestamp):
            # Time parameterizing ended. parameterize.

            # Average time for 10000 packets to arrive
            common.BATCH_PERIOD = common.TIME_TO_PARAMETERIZE / (self.packets_counter / 10000.0)

            common.PERIODS_IN_HOUR = 60 * 60 / common.BATCH_PERIOD

            common.PERIODS_IN_DAY = 24 * common.PERIODS_IN_HOUR

            common.NUMBER_OF_BATCHES_TO_REMEMBER = int(common.PERIODS_IN_DAY * common.DAYS_REMEMBER)

            # Set start time for next phase
            State.state_start_time = common.start_time = timestamp

            # change State to Learning
            self.context.set_state(GatheringState(self.context))

    def check_if_move_to_next_state(self, timestamp):
        return timestamp - common.start_time > common.TIME_TO_PARAMETERIZE
