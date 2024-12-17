import heapq
class SetPriorityQueue:
    def __init__(self):
        self._data = []  # Internal heap storage
        self._set = set()  # Set to avoid duplicates

    def put(self, priority, item):
        """
        Add an item to the priority queue with a given priority.
        If the item already exists, it will not be added again.
        """
        if item not in self._set:
            heapq.heappush(self._data, (priority, item))
            self._set.add(item)

    def get(self):
        """
        Remove and return the item with the highest priority (smallest value).
        """
        if not self._data:
            raise KeyError("Pop from an empty priority queue")
        priority, item = heapq.heappop(self._data)
        self._set.remove(item)
        return priority, item

    def peek(self):
        """
        Peek at the item with the highest priority without removing it.
        """
        if not self._data:
            raise KeyError("Peek from an empty priority queue")
        return self._data[0]

    def __contains__(self, item):
        """
        Check if an item exists in the priority queue.
        """
        return item in self._set

    def __len__(self):
        """
        Return the number of items in the priority queue.
        """
        return len(self._set)

    def empty(self):
        """
        Check if the priority queue is empty.
        """
        return len(self._set) == 0

    def clear(self):
        """
        Clear all items from the priority queue.
        """
        self._data.clear()
        self._set.clear()
