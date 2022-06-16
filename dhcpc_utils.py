from abc import ABCMeta,abstractmethod
import queue

class NonBlockingQueue(metaclass=ABCMeta):
    @abstractmethod
    def put(self):
        pass
    @abstractmethod
    def get(self):
        pass
    @abstractmethod
    def foreach(self):
        pass

class NonBlockingQueueFromPy(NonBlockingQueue):
    def __init__(self):
        self.q = queue.Queue(1000)
    def put(self, msg):
        return self.q.put_nowait(msg)
    def get(self):
        return self.q.get_nowait()
    def foreach(self, cb):
        for _ in range(0, self.q.qsize()):
            cb(self.q.get())

class NonBlockingQueueRealize(NonBlockingQueue):
    def __init__(self):
        self.q = []
        self.q_maxsize = 1000
        self.q_size = 0
    def put(self, msg):
        if (self.q_size >= self.q_maxsize):
            return
        self.q_size += 1
        self.q.append(msg)
    def get(self):
        if (self.q_size <= 0):
            return None
        self.q_size -= 1
        return self.q.pop(0)

    def foreach(self, cb):
        for _ in range(0, self.q_size):
            cb(self.get())

# realize frompy
class NonBlockingQueueSimpleFactory():
    def create_nonblockingqueue(t):
        if (t == "realize"):
            return NonBlockingQueueRealize()
        elif (t == "frompy"):
            return NonBlockingQueueFromPy()

# que = NonBlockingQueueSimpleFactory.create_nonblockingqueue("frompy")