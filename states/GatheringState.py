import common
from State import State
from states.ModelingState import ModelingState


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
        common.handle_batch()

        if self.check_if_move_to_next_state(timestamp):
            self.context.current_state = ModelingState(self.context)
            State.state_start_time = timestamp

    def check_if_move_to_next_state(self, timestamp):
        timestamp - State.state_start_time > common.GATHERING_TIME
