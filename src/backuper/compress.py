"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""
import lzma


class LZMACompressor:
    def __init__(self, preset=0.5):
        self.preset = max(min(int(preset * 10), 9), 0)

    def compress(self, data: bytes):
        return lzma.compress(data, preset=self.preset)

    def decompress(self, data: bytes):
        try:
            return lzma.decompress(data)
        except Exception as error:
            raise Exception("Could not decompress given data.") from error
