from states.State import State


class DetectingState(State):
    def __init__(self, context):
        State.name = "Modeling State"
        State.__init__(self)
        self.context = context

    def process_packet(self, timestamp, packet):
        pass

    def check_if_move_to_next_state(self, timestamp):
        pass
