from states.ParameterizingState import ParameterizingState


class StateContext:
    def __init__(self):
        self.current_state = ParameterizingState(self)

    def set_state(self, new_state):
        self.current_state = new_state
