from State import State


class GatheringState(State):
    """
    This state is all about measuring the bandwidth and defining the size of a batch
    """

    def __init__(self, context):
        State.__init__(self)
        self.context = context
        self.name = "Learning State"

    def process_packet(self, timestamp, packet):
        pass

    def check_if_move_to_next_state(self, timestamp):
        return
