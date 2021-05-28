"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""
import collections
import hashlib
import pickle
import random
import shutil
import string
import pathlib
import tempfile
import datetime

from . import compress
from . import crypto
from . import filenode
from . import foldernode
from . import manifest


class LocalStorage:
    """
    Class used to encapsulate some tasks made from the local filesystem: copy, creation, deletion, encryption, compression
    """

    MAX_CACHED_TEMPFILES = 8

    def __init__(self, app):
        """
        :param app app.App: a instance of the App class, where we access the configs.
        """
        self.app = app
        self.cached_tempfiles = collections.deque(maxlen=self.MAX_CACHED_TEMPFILES)

    def has_files(self):
        """
        Check if has at least one file/folder in the self.local_folder_path.
        :return bool:   True if at least one node exists in the path.
        """
        for item in self.app.config.local_folder_path.iterdir():
            # leave on the first iteration
            return True
        # else: didnt leave above them it must be empty
        return False

    def has_manifest(self):
        """
        Check only if the manifest file exists in the place it should.
        """
        return (
            self.app.config.local_manifest_folder_path / self.app.MANIFEST_FILENAME
        ).exists()

    def get_manifest(self):
        """
        Retrieve the manifest.Manifest instace from the local filesystem path: self.app.config.local_manifest_folder_path.
        :return manifest.Manifest: return the instance of the manifest, unpickled, decrypted, uncompressed.
        """
        return self.unpack_unpickle(
            self.app.config.local_manifest_folder_path / self.app.MANIFEST_FILENAME
        )

    def set_manifest(self, manifest_instance):
        """
        Save the instance of the manifest instance, pickling, compressing and encrypting using the app.configs.
        :param manifest_instance manifest.Manifest: The given instance to save in disk.
        """
        return self.pickle_pack(
            manifest_instance,
            self.app.config.local_manifest_folder_path / self.app.MANIFEST_FILENAME,
        )

    def delete_manifest(self):
        """
        Delete the manifest file.
        :return bool: True if succesful
        """
        if self.has_manifest():
            (
                self.app.config.local_manifest_folder_path / self.app.MANIFEST_FILENAME
            ).unlink()
            return True
        return False

    def build_manifest(self, include_files=True, timestamp_files=False):
        """
        This builds the manifest from filesystem. It scans files and folder at the self.app.config.local_folder_path and
        hash files to get its signatures.
        :param include_files bool: If True the manifest is built faster without files, only folder structure.
        :return manifest.Manifest: the manifest instance built from the local folder.
        """
        self.app.logger.debug("Building local manifest...")
        manifest_instance = manifest.Manifest()
        self.app.logger.log(9, "Scanning filesystem...")
        if timestamp_files:
            # get mtime in nanoseconds
            timestamp = self.scan_filesystem(
                manifest_instance, include_files, timestamp_files=True
            )
            # convert it back to timestamp in UTC, the same timestamp used by self.app._gettimestamp()
            manifest_instance.timestamp = datetime.datetime.fromtimestamp(
                timestamp / 1000 ** 3, datetime.timezone.utc
            ).timestamp()
        else:
            self.scan_filesystem(
                manifest_instance, include_files, timestamp_files=False
            )
        if include_files:
            self.app.logger.log(9, "Updating files signatures on manifest...")
            self.update_signatures(manifest_instance)
        self.app.logger.debug("Local manifest built.")
        return manifest_instance

    def scan_filesystem(
        self, manifest_instance, include_files=True, timestamp_files=False
    ):
        """
        Do a deep scan of the file system folder given at config.local_folder_path, save the results on
        the root attribute of the Manifest.
        :param manifest_instance manifest.Manifest: The manifest instance to save the folder structure
        in its 'Manifest.root' attribute.
        :param include_files bool: If True the manifest is built faster without files, only folder structure.
        :param timestamp_files bool: If True check files modification time and return the most recent one, include_files must be True.
        :return int: Timestamp of the modification time of the most recent modified file, only
        if timestamp_files is True otherwise return 0
        """
        if not include_files and timestamp_files:
            self.app.logger.debug(
                "timestamp_files is True, include_files cant be False"
            )
        timestamp = 0
        manifest_instance.root.clear()
        queue = collections.deque(
            [(self.app.config.local_folder_path, manifest_instance.root)]
        )
        while len(queue) > 0:
            folder_path, folder_node = queue.popleft()
            for node_path in self.iterdir_filtered(folder_path):
                if node_path.is_dir():
                    queue.append(
                        (node_path, foldernode.FolderNode(node_path.name, folder_node))
                    )
                elif include_files:
                    filenode.FileNode(node_path.name, folder_node)
                    if timestamp_files:
                        timestamp = max(timestamp, node_path.stat().st_mtime_ns)
        return timestamp

    def update_signatures(self, manifest_instance):
        """
        Iterate over the Manifest.root folder, find all files without the signature and update
        it calling the hash function at self.get_signature.
        :param manifest_instance manifest.Manifest: the instance with the root folder to get all possible files.
        """
        for file_node in manifest_instance.iterate(include_folders=False):
            if file_node.signature == "":
                file_node.signature = self.get_signature(self.abs_path(file_node))
        return True

    def pack(self, src_abs_path, dest_abs_path, use_key=None):
        """
        Apply compression and encryption of the src into the dest file. It doesnt change the filename.
        :param src_abs_path pathlib.Path | str: expects either a absolute Path instance or a str
        pointing the path of the source initial file.
        :param dest_abs_path pathlib.Path | str: expects either a absolute Path instance or a str
        pointing the path of the destination result file.
        :param use_key bytes | None: if None use self.app.salted_key, otherwise use the provided
        key as [de]encryption key.
        """
        src_file = open(src_abs_path, "rb")
        dest_file = open(dest_abs_path, "wb")
        try:
            cmp = compress.LZMACompressor(self.app.config.compression_ratio)
            cry = crypto.AESCipher(self.app.salted_key if use_key is None else use_key)
            # write the iv first
            dest_file.write(cry.iv)
            while True:
                # read block size first
                data = src_file.read(self.app.BLOCK_SIZE)
                if len(data) == 0:
                    break  # finish
                # compress and encrypt
                data = cmp.compress(data)
                data = cry.encrypt(data)
                # write data length as bytes (max 3 length = 16MB), before the data
                dest_file.write(int.to_bytes(len(data), 3, "big"))
                # write the data
                dest_file.write(data)
            return True
        finally:
            src_file.close()
            dest_file.close()

    def unpack(self, src_abs_path, dest_abs_path, use_key=None):
        """
        Apply decryption and decompression of the src into the dest file. It doesnt change the filename.
        :param src_abs_path pathlib.Path | str: expects either a absolute Path instance or a str
        pointing the path of the source initial file.
        :param dest_abs_path pathlib.Path | str: expects either a absolute Path instance or a str
        pointing the path of the destination result file.
        :param use_key bytes | None: if None use self.app.salted_key, otherwise use the provided
        key as [de]encryption key.
        """
        src_file = open(src_abs_path, "rb")
        dest_file = open(dest_abs_path, "wb")
        try:
            cmp = compress.LZMACompressor()  # no need to set preset to decompress
            # set the iv used by file
            cry = crypto.AESCipher(
                self.app.salted_key if use_key is None else use_key,
                src_file.read(crypto.AESCipher.IV_LENGTH),
            )
            while True:
                data = src_file.read(int.from_bytes(src_file.read(3), "big"))
                if len(data) == 0:
                    break  # finish
                data = cry.decrypt(data)
                data = cmp.decompress(data)
                dest_file.write(data)
            return True
        finally:
            src_file.close()
            dest_file.close()

    def pickle_pack(self, obj, dest_abs_path, use_key=None):
        """
        Apply pickle and pack (compression and encryption) on a object.
        :param obj any pickable object: object to be pickled.
        :param dest_abs_path pathlib.Path | str: expects either a absolute Path instance or a str
        pointing the path of the destination result file.
        :param use_key bytes | None: if None use self.app.salted_key, otherwise use the provided
        key as [de]encryption key.
        """
        temp_file_path = self.get_new_tempfile()
        try:
            with temp_file_path.open("wb") as file:
                pickle.dump(obj, file)
            return self.pack(temp_file_path, dest_abs_path, use_key)
        finally:
            self.dispose_tempfile(temp_file_path)

    def unpack_unpickle(self, src_abs_path, use_key=None):
        """
        Apply unpack (decryption and decompression) and unpickle of a saved object.
        :param src_abs_path pathlib.Path | str: expects either a absolute Path instance or a str
        pointing the path of the source initial file.
        :param use_key bytes | None: if None use self.app.salted_key, otherwise use the provided
        key as [de]encryption key.
        :return any pickled object: the unpickled object.
        """
        temp_file_path = self.get_new_tempfile()
        try:
            if self.unpack(src_abs_path, temp_file_path, use_key):
                with temp_file_path.open("rb") as file:
                    return pickle.load(file)
            else:
                return None
        except EOFError:
            self.app.logger(
                "unpack_unpickle: File was empty or pickled data was incomplete: {}".format(
                    src_abs_path
                )
            )
            return None
        finally:
            self.dispose_tempfile(temp_file_path)

    def get_new_tempfile(self):
        """
        Return a random file name inside the temp folder (config.temp_folder_path) that doesnt exist yet.
        Note the file will have the '.tmp' extension.
        But first will look into the cache and reuse any of the previously disposed files.
        :return pathlib.Path: a non existent file Path inside the temp folder.
        """
        if len(self.cached_tempfiles) > 0:
            return self.cached_tempfiles.pop()
        else:
            while True:
                new_tempfile = self.app.config.temp_folder_path / (
                    "".join(
                        random.choices(string.ascii_lowercase + string.digits, k=16)
                    )
                    + ".tmp"
                )
                if not new_tempfile.exists():
                    return new_tempfile

    def dispose_tempfile(self, temp_file_path):
        """
        Facility function to get rid or cache the temporary file.
        :param temp_file_path pathlib.Path: Path pointing to a file name, inside the temp folder, to be deleted.
        """
        if len(self.cached_tempfiles) < self.MAX_CACHED_TEMPFILES:
            self.cached_tempfiles.append(temp_file_path)
        else:
            if temp_file_path.exists():
                temp_file_path.unlink()

    def get_default_tempfolder_path():
        """
        Static function
        :return pathlib.Path: path to the system's default temp folder, provided by Python lib tempfile.
        """
        return pathlib.Path(tempfile.gettempdir())

    def get_signature(self, src_abs_path):
        """
        Get a hash signature using blake2b. Changing either: app.HASH_DIGEST_LENGTH,
        app.HASH_PARTIAL_BLOCK or app.BLOCK_SIZE will affect the resulting signature.
        :param src_abs_path pathlib.Path | str: Absolute path for the file to execute the
        hash function on.
        :return str: hexadecimal str of the calculated digest.
        """
        with open(src_abs_path, "rb") as src_file:
            signator = hashlib.blake2b(digest_size=self.app.HASH_DIGEST_LENGTH)
            part = 0
            size = 0
            while True:
                piece = src_file.read(self.app.BLOCK_SIZE)
                if len(piece) == 0:
                    break
                size += len(piece)
                signator.update(piece)
                for i in range(len(piece) // self.app.HASH_PARTIAL_BLOCK):
                    part += piece[i * self.app.HASH_PARTIAL_BLOCK]
                if len(piece) < self.app.HASH_PARTIAL_BLOCK:
                    part += piece[-1]
            signator.update((str(size) + str(part)).encode())
            return signator.hexdigest()

    def copy(self, src_abs_path, dest_abs_path):
        """
        Facility function to realize copy of file system's nodes.
        :param src_abs_path pathlib.Path | str: absolute path of the filesystem node source of the copy.
        :param dest_abs_path pathlib.Path | str: absolute path of the filesystem node destionation of the copy.
        :return bool: True on success
        """
        shutil.copyfile(src_abs_path, dest_abs_path)
        return True

    def move(self, src_abs_path, dest_abs_path):
        """
        Facility function to move file system's nodes.
        :param src_abs_path pathlib.Path | str: absolute path of the filesystem node source of the move.
        :param dest_abs_path pathlib.Path | str: absolute path of the filesystem node destionation of the move.
        """
        shutil.move(src_abs_path, dest_abs_path)
        return True

    def abs_path(self, node_instance):
        """
        :return pathlib.Path: absolute path instance based on node_instance parents.
        """
        return self.app.config.local_folder_path / node_instance.get_path()

    def copy_node(self, src_node, dest_node):
        """
        Facility function to copy files given by node.Node paths.
        :param src_node node.Node: node source of the copy.
        :param dest_node node.Node: node destination of the copy.
        """
        return self.copy(self.abs_path(src_node), self.abs_path(dest_node))

    def move_node(self, src_node, dest_node):
        """
        Facility function to move files given by node.Node paths.
        :param src_node node.Node: node source of the move.
        :param dest_node node.Node: node destination of the move.
        """
        return self.move(self.abs_path(src_node), self.abs_path(dest_node))

    def ensure_folder_exists(self, node_instance):
        """
        Check if given folder path exists, and create all needed folder if it doesnt.
        In case its a FileNode, use its parent instead.
        :param node_instance node.Node: If its a FileNode, use its parent node instead. Ensure
        that the folder path exists, if doesnt, create it on the system.
        """
        if type(node_instance) is filenode.FileNode:
            node_instance = node_instance.parent
        complete_folder_path = self.abs_path(node_instance)
        if not complete_folder_path.exists():
            complete_folder_path.mkdir(parents=True)
        return True

    def folder_node_is_empty(self, folder_node):
        """
        Check (in filesystem) if the given folder node does have at least one child or its empty.
        :param folder_node foldernode.FolderNode: given folder node to check.
        :return bool: False if at least one node exists inside it, True if empty.
        """
        for item in self.abs_path(folder_node).iterdir():
            # leave on the first iteration
            return False
        # else: didnt leave above them it must be empty
        return True

    def delete_node(self, node_instace):
        """
        Delete the file or folder given (folder only if empty) by the Node instance.
        :param node_instance node.Node: expected it to be FileNode or FolderNode.
        :return bool: return True if successful.
        """
        if type(node_instace) is filenode.FileNode:
            self.abs_path(node_instace).unlink()
            node_instace.reparent(None)
            return True
        elif self.folder_node_is_empty(node_instace):
            self.abs_path(node_instace).rmdir()
            node_instace.reparent(None)
            return True
        return False

    def delete_empty_folders(self, folder_node):
        """
        Delete empty folders in sequence following the parents.
        Ex: you delete the folder_node, it checks if the parent is now empty, if it is
        delete the parent also and repeat for the parent.parent...until reach the root
        folder where the parent is None.
        :param folder_node FolderNode: folder node to be removed and have its parent checked in a loop.
        We stop before deleting the root folder.
        """
        if type(folder_node) is foldernode.FolderNode:
            while folder_node.parent is not None:
                if self.folder_node_is_empty(folder_node):
                    self.abs_path(folder_node).rmdir()
                    parent = folder_node.parent
                    folder_node.reparent(None)
                    folder_node = parent
                else:
                    break

    def iterdir_filtered(self, folder_path):
        """
        Get a iterator object listing all the folder's children, but only if approved by the
        filter function from config.filter_function.
        :return iterator: lists all nodes just like pathlib.Path.iterdir, but check if the
        path is approved by config.filter_function.
        """
        for item in folder_path.iterdir():
            if self.app.config.filter_function(item):
                yield item

    def clear_tempfiles(self):
        """
        Delete cached tempfiles. Called from the atexit from self.app.
        """
        for cached_path in self.cached_tempfiles:
            if cached_path.exists():
                cached_path.unlink()
