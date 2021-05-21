class StreamToLogger:
    """
    Class used to redirect all python errors into the logger.
    """

    def __init__(self, logger, level):
        self.logger = logger
        self.level = level
        self.buffer = []

    def write(self, msg):
        msg = msg.strip()
        if msg:
            self.buffer.append(msg)

    def flush(self):
        if self.buffer:
            for i in range(len(self.buffer)):
                if len(self.buffer[i]) == 1 and i > 0 and i < len(self.buffer) - 1:
                    self.buffer[i - 1] = "{} {} {}".format(
                        *self.buffer[i - 1 : i + 2]  # noqa: E203
                    )
                    self.buffer[i] = self.buffer[i + 1] = ""

            self.logger.log(
                self.level, "\n".join([line for line in self.buffer if line])
            )
            self.buffer = []
