import common
from State import State
from states.DetectingState import DetectingState


class GatheringState(State):
    """
    This state is all about measuring the bandwidth and defining the size of a batch
    """

    def __init__(self, context):
        State.name = "Gathering State"
        State.__init__(self)
        self.context = context

    def process_packet(self, timestamp, packet):
        ip_frame = common.filter_packet(packet)

        if not ip_frame:
            return

        common.count_packet()

        common.add_packet_to_batch(timestamp, ip_frame)

        if common.is_batch_time_over(timestamp):
            common.check_whitelist_packets()
            common.extract_kpis(timestamp)
            common.reset_batch()

        if self.check_if_move_to_next_state(timestamp):
            common.parameterize(common.GATHERING_TIME)

            # Set start time for next phase
            State.state_start_time = timestamp

            common.build_model()

            # change State to Learning
            self.context.set_state(DetectingState(self.context))

    def check_if_move_to_next_state(self, timestamp):
        return timestamp - State.state_start_time > common.GATHERING_TIME
