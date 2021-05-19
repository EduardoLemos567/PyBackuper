"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""
import pathlib


class Node:
    def __init__(self, name, parent=None):
        """
        :param name str: Its used as file/folder name.
        :param parent foldernode.FolderNode | None: expected a foldernode as the parent of this node.
        """
        self.name = name
        if parent is not None:
            self.set_parent(parent)
        else:
            self.parent = None

    def set_parent(self, other_node):
        """
        Set the other_node as the parent of this 'self' node.
        :param other_node foldernode.FolderNode | None: the soon to be parent of the 'self' node.
        """
        if not hasattr(other_node, "__setitem__"):
            raise AttributeError("Invalid argument type.")
        other_node[self.name] = self
        self.parent = other_node

    def reparent(self, other_node):
        """
        Reparent the 'self' Node into the other_node, removing the parentship from the actual
        self.parent. Accept None, leaving the Node unparented.
        :param other_node foldernode.FolderNode | None: the new parent.
        """
        if self.parent is not None:
            self.parent.remove(self)
        if other_node is not None:
            self.set_parent(other_node)
        else:
            self.parent = None

    def get_parts(self):
        """
        Get the path of this Node as single list of parts, each part a string.
        :return list(str): list of strings representing the path.
        """
        parts = []
        node_instance = self
        while node_instance.parent is not None:
            parts.append(node_instance.name)
            node_instance = node_instance.parent
        parts.reverse()
        return parts

    def get_path(self):
        """
        :return pathlib.Path: a path instance representing the path of this Node.
        """
        return pathlib.Path(*self.get_parts())

    def get_path_str(self):
        """
        :return str: a str representing the path as parent.../parent.parent.name/parent.name/name.
        """
        return "/".join(self.get_parts())
