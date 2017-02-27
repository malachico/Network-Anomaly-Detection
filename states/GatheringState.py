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
        if not common.filter_packet(packet):
            return

        common.count_packet()

        common.add_packet_to_batch(timestamp, packet)

        if common.batch_time_over(timestamp):
            common.extract_kpis()
            common.reset_batch()

        if self.check_if_move_to_next_state(timestamp):
            common.parameterize(common.GATHERING_TIME)

            # Set start time for next phase
            State.state_start_time = timestamp

            common.build_model()

            # change State to Learning
            self.context.set_state(GatheringState(self.context))

    def check_if_move_to_next_state(self, timestamp):
        timestamp - State.state_start_time > common.GATHERING_TIME

