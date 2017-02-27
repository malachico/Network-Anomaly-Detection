from collections import deque

from states.GatheringState import GatheringState

import common
from State import State


class ParameterizingState(State):
    def __init__(self, context):
        State.name = "Parameterizing State"
        State.__init__(self)
        self.context = context

    def process_packet(self, timestamp, packet):
        if not common.batch_start_time:
            State.state_start_time = common.batch_start_time = timestamp

        if not common.filter_packet(packet):
            return

        common.count_packet()

        if self.check_if_move_to_next_state(timestamp):
            common.parameterize(common.TIME_TO_PARAMETERIZE)

            # Set start time for next phase
            State.state_start_time = common.batch_start_time = timestamp

            # change State to Learning
            self.context.set_state(GatheringState(self.context))

    def check_if_move_to_next_state(self, timestamp):
        return timestamp - common.batch_start_time > common.TIME_TO_PARAMETERIZE
