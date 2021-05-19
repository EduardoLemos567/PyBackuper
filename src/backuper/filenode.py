"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""
from . import node


class FileNode(node.Node):
    def __init__(self, name, parent):
        """
        :param name str: Its used as file/folder name.
        :param parent foldernode.FolderNode | None: expected a foldernode as the parent of this node.
        """
        super().__init__(name, parent)
        self.signature = ""  # file hash see: localstorage.LocalStorage.get_signature

    def __str__(self):
        """
        :return str: string representation of the file with name.
        """
        return "FileNode(name={})".format(self.name)

    def __eq__(self, other):
        """
        Check if their names and signatures are equal.
        :param other FileNode: the other file to be compared.
        :return bool: True if other FileNode is conceptually equal, except for parents, we dont check those.
        """
        if (
            self.name != other.name
            or type(other) is not FileNode
            or other.signature != self.signature
        ):
            return False
        return True
