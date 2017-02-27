from states.DetectingState import DetectingState
from states.State import State


class ModelingState(State):
    def __init__(self, context):
        State.name = "Modeling State"
        State.__init__(self)
        self.context = context

    def process_packet(self, timestamp, packet):

        if self.check_if_move_to_next_state(timestamp):
            self.context.current_state = DetectingState(self.context)
            State.state_start_time = timestamp

    def check_if_move_to_next_state(self, timestamp):
        return True
