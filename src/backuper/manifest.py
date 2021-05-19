"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""
import collections

from . import foldernode


class Manifest:
    """
    Class to keep the folder structure and files paths and signatures.
    Also keep the timestamp for future sync compares.
    """

    def __init__(self):
        self.timestamp = None  # float
        self.root = foldernode.FolderNode(":root:")

    def __eq__(self, other):
        """
        :param other Manifest: other manifest to compare to.
        :return bool: False if any 'self' manifest's folder or file doesnt exist on 'other' manifest.
        Or in case of files, the signature doesnt match.
        """
        if type(other) is not Manifest:
            return False
        queue = collections.deque([(self.root, other.root)])
        while len(queue) > 0:
            self_folder, other_folder = queue.popleft()
            # if any name is missing or is different
            if self_folder._children.keys() ^ other_folder._children.keys():
                return False
            # we know both side got the same names in keys
            for self_node_instance in self_folder._children.values():
                other_node_instance = other_folder[self_node_instance.name]
                # if both names points to the same type of object
                if type(self_node_instance) == type(other_node_instance):
                    if type(self_node_instance) is foldernode.FolderNode:
                        # case its a folder, add for the next cycle
                        queue.append(
                            (self_node_instance, other_folder[self_node_instance.name])
                        )
                    # case its a file, check signature
                    elif self_node_instance.signature != other_node_instance.signature:
                        return False
                else:
                    return False
        return True

    def diff_nodes(self, other, include_files=True, include_folders=True):
        """
        :param other Manifest: other manifest to compare nodes of.
        :param include_files bool: should return FileNodes
        :param include_folders bool: should return FolderNodes
        :return generator(Node): (files/folders) existing on 'self' manifest
        but without corresponding copy on 'other' manifest.
        """
        if (not include_files) and (not include_folders):
            return
        # iterate all 'self' folders from 'root'
        for folder_node in self.iterate(include_files=False):
            # try to find a corresponding folder on 'other'
            result = other.find_child(folder_node.get_parts())
            if result is None:
                # if not found, all 'self' folder's content are unique, include on the results
                for value in folder_node.get_children():
                    if type(value) is foldernode.FolderNode:
                        if include_folders:
                            yield value
                    elif include_files:
                        yield value
            else:
                for value in folder_node.diff_nodes(
                    result, include_files, include_folders
                ):
                    yield value

    def get_signatures_set(self):
        """
        :return set(str): Return a set (each set member is unique, no copies) of all signatures
        for all files existing on this manifest.
        """
        s = set()
        for file_node in self.iterate(include_folders=False):
            s.add(file_node.signature)
        return s

    def get_signatures_dict(self, limit=None):
        """
        Method to group all FileNode under its signatures, making it easy to test and find those.
        :param limit int|None: You can set a limit to the lists, None = no limit. If you set
        limit==1 instead of a list, the values are just single FileNodes (the first one found)
        :return dict(key:str, value:list(FileNode)): A dict grouping all files by its signature.
        Key are the signature and values is a list of all FileNode with that signature (but in case
        of limit==1 we get single FileNodes instead of lists).
        """
        d = dict()
        for file_node in self.iterate(include_folders=False):
            if file_node.signature in d:
                if limit is None or len(d[file_node.signature]) < limit:
                    d[file_node.signature].append(file_node)
            else:
                if limit is None or limit > 1:
                    d[file_node.signature] = [file_node]
                else:
                    d[file_node.signature] = file_node
        return d

    def iterate(self, include_files=True, include_folders=True):
        """
        Do a iteration returning a generator, including all nodes by given parameters.
        Can include: only files, only folders or both.
        :param include_files bool: should return FileNodes
        :param include_folders bool: should return FolderNodes
        :return generator(Node): Generator object that yields Nodes doing a deep listing of children.
        """
        if (not include_files) and (not include_folders):
            return
        queue = collections.deque([self.root])
        while len(queue) > 0:
            folder = queue.popleft()
            if include_folders:
                yield folder
            # NOTE: why we use here get_children()?
            # So we have a frozen set, ignoring outside changes.
            for node_instance in folder.get_children():
                if type(node_instance) is foldernode.FolderNode:
                    queue.append(node_instance)  # yield on the next cycle
                elif include_files:
                    yield node_instance

    def find_child(self, parts, ensure_folder_exists=False):
        """
        Find the correct child following the parts sequence,
        doing a deep search on the "folder" children nodes.
        (Always start looking on the self.root folder)
        :param parts sequence: any sequence object to look for parts.
        :param ensure_folder_exists bool: If any part of the parts doesnt exist,
        we create them and assume the whole path point to a folders.
        (Meaning you should not use it for file paths)
        :return Node: the Node pointing to that path, in case of ensure_folder_exists and
        path doesnt exist, we create it as a path of folders.
        Can return None if ensure_folder_exists is False and the path doesnt not exist.
        """
        created = False  # its a flag to indicate we should stop lookin and from now on create folders
        folder = self.root
        for name in parts:
            if not created:
                if name in folder:
                    folder = folder[name]
                elif ensure_folder_exists:
                    created = True
                else:
                    return None
            if created:
                folder = foldernode.FolderNode(name, folder)
        return folder

    def print_debug(self):
        """
        Method to print the whole manifest in a human readable way.
        """
        print("Manifest:\n")
        print(
            "Folders:\n{}\n".format(
                "\n".join(
                    [
                        folder_node.get_path_str()
                        for folder_node in self.iterate(include_files=False)
                    ]
                )
            )
        )
        print(
            "Files:\n{}\n".format(
                "\n".join(
                    [
                        file_node.get_path_str()
                        for file_node in self.iterate(include_folders=False)
                    ]
                )
            )
        )
