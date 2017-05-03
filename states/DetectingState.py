import common
from State import State


class DetectingState(State):
    def __init__(self, context):
        State.name = "Detecting State"
        State.__init__(self)
        self.context = context

    def process_packet(self, timestamp, packet):
        ip_frame = common.filter_packet(packet)

        if not ip_frame:
            return

        common.count_packet()

        common.add_packet_to_batch(timestamp, ip_frame)

        if common.is_batch_time_over(timestamp):
            common.preprocess_batch()
            common.extract_kpis(timestamp)
            common.check_batch_probability()
            common.reset_batch()

    def check_if_move_to_next_state(self, timestamp):
        return False
