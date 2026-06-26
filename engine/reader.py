import queue, threading

q = queue.Queue()

class Reader:
    def __init__(self):
        self.queue = q

    def read(self):
        while True:
            item = self.queue.get()
            if item is None:
                break
            print(f"Read: {item}")
            self.queue.task_done()