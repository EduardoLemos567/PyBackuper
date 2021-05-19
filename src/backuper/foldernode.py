"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""
from . import node


class FolderNode(node.Node):
    def __init__(self, name, parent=None):
        """
        :param name str: Its used as file/folder name.
        :param parent foldernode.FolderNode | None: expected a foldernode as the parent of this node.
        """
        super().__init__(name, parent)
        self._children = {}

    def __contains__(self, name):
        """
        :param name str: value to be searched
        :return bool: True if the a Node with given name is found within its children.
        """
        return name in self._children

    def __getitem__(self, name):
        """
        :param name str: value to be searched
        :return Node: return the node with the given name found within its children.
        Raise error if name is not found.
        """
        return self._children[name]

    def __setitem__(self, name, node_instance):
        """
        :param name str: name value to be found by.
        :param node_instance Node: node to be added as child
        """
        self._children[name] = node_instance

    def __len__(self):
        """
        :return int: children count.
        """
        return len(self._children)

    def __eq__(self, other):
        """
        Check if two folders have the same name and contains the same kinds of nodes with the same name.
        No deep comparison between folders (meaning we just compare this folder, not children folders),
        just names and types.
        :param other FolderNode: other folder to compare to.
        :return bool: True if the other FolderNode got the same name and children names, and its children types are equal.
        Comparasion is just for both these folders only.
        """
        if (
            self.name != other.name
            or type(other) is not FolderNode
            or self._children.keys() ^ other._children.keys()
        ):
            return False
        for node_instance in self.get_children():
            if type(other._children[node_instance.name]) != type(node_instance):
                return False
        return True

    def diff_nodes(self, other, include_files=True, include_folders=True):
        """
        Return all nodes that exist in the 'self' folder and dont exist on the 'other' folder
        or in case of FileNodes, return it if the signature is different.
        :param other FolderNode: other foldernode used to comparasion.
        :param include_files bool: should return FileNodes
        :param include_folders bool: should return FolderNodes
        :return generator(Node): a generator that return Nodes, deppending on the include.
        """
        if (not include_files) and (not include_folders):
            return
        for node_instance in self.get_children():
            if type(node_instance) is FolderNode:
                if include_folders:
                    if node_instance.name not in other._children or type(
                        other._children[node_instance.name]
                    ) != type(node_instance):
                        yield node_instance
            else:
                if include_files:
                    if (
                        node_instance.name not in other._children
                        or type(other._children[node_instance.name])
                        != type(node_instance)
                        or node_instance.signature
                        != other._children[node_instance.name].signature
                    ):
                        yield node_instance

    def remove(self, node_instance):
        """
        :param node_instance Node: remove the node instance from its children values.
        """
        if node_instance.parent == self:
            del self._children[node_instance.name]

    def clear(self):
        """
        Orphanize all children in which the parent is 'self'.
        """
        for child_node in tuple(self._children.values()):
            child_node.reparent(None)

    def get_children(self):
        """
        Get a tuple copy of self._children.values()
        :return tuple(Node): tuple (works as frozen set) of children Nodes.
        """
        return tuple(self._children.values())

    def __str__(self):
        """
        :return str: string representation of the instance.
        """
        return "FolderNode(name={}, children={})".format(
            self.name, [str(node_instance) for node_instance in self._children.values()]
        )
