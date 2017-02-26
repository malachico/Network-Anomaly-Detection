"""
interface for state
"""


class State:
    name = ""

    def __init__(self):
        print "starting", State.name

    def process_packet(self, timestamp, packet):
        raise NotImplementedError("process_packet : NotImplementedError")

    def check_if_move_to_next_state(self, timestamp):
        raise NotImplementedError("check_if_move_to_next_state : NotImplementedError")
