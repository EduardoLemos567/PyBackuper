"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""
from . import remotestorage


class DiskRemoteStorage(remotestorage.RemoteStorage):
    FILES_FOLDERNAME = "files"

    def __init__(self, app):
        super().__init__(app)

    def setup(self):
        files_folder = self.app.config.remote_folder_path / "files"
        if not files_folder.exists():
            files_folder.mkdir()
        return True

    def has_files(self):
        files_folder = self.app.config.remote_folder_path / self.FILES_FOLDERNAME
        for node in files_folder.iterdir():
            if node.is_file():
                return True
        return False

    def has_manifest(self):
        return (
            self.app.config.remote_folder_path / self.app.MANIFEST_FILENAME
        ).exists()

    def set_manifest(self, manifest_instance):
        self.app.local_storage.pickle_pack(
            manifest_instance,
            self.app.config.remote_folder_path / self.app.MANIFEST_FILE_NAME,
        )
        return True

    def get_manifest(self):
        if (self.app.config.remote_folder_path / self.app.MANIFEST_FILE_NAME).exists():
            return self.app.local_storage.unpack_unpickle(
                self.app.config.remote_folder_path / self.app.MANIFEST_FILE_NAME
            )
        else:
            return None

    def delete_manifest(self):
        manifest_path = self.app.config.remote_folder_path / self.app.MANIFEST_FILE_NAME
        if manifest_path.exists():
            manifest_path.unlink()
            return True
        return False

    def has_salt(self):
        return (self.app.config.remote_folder_path / self.app.SALT_FILENAME).exists()

    def get_salt(self):
        salt_path = self.app.config.remote_folder_path / self.app.SALT_FILENAME
        if salt_path.exists():
            with salt_path.open("rb") as file:
                return file.read()

    def set_salt(self, salt):
        salt_path = self.app.config.remote_folder_path / self.app.SALT_FILENAME
        with salt_path.open("wb") as file:
            file.write(salt)
            return True

    def delete_salt(self):
        salt_path = self.app.config.remote_folder_path / self.app.SALT_FILENAME
        if salt_path.exists():
            salt_path.unlink()
            return True
        return False

    def get_file(self, signature, dest_abs_path):
        files_folder = self.app.config.remote_folder_path / self.FILES_FOLDERNAME
        for node_path in files_folder.iterdir():
            if node_path.is_file() and node_path.stem == signature:
                self.app.local_storage.unpack(node_path, dest_abs_path)
                return True
        return False

    def set_file(self, src_abs_path, signature):
        if self.file_exists(signature):
            self.app.logger.warn(
                "set_file: Cant set a file that already exists, ignoring..."
            )
            return False
        self.app.local_storage.pack(
            src_abs_path,
            self.app.config.remote_folder_path
            / self.FILES_FOLDERNAME
            / (signature + self.app.PACKED_FILE_EXTENSION),
        )
        return True

    def delete_file(self, signature):
        if not self.file_exists(signature):
            self.app.logger.debug(
                "delete_file_node: Trying to delete a remote file that doesnt exist, ignoring..."
            )
            return False
        (
            self.app.config.remote_folder_path
            / self.FILES_FOLDERNAME
            / (signature + self.app.PACKED_FILE_EXTENSION)
        ).unlink()
        return True

    def file_exists(self, signature):
        return (
            self.app.config.remote_folder_path
            / self.FILES_FOLDERNAME
            / (signature + self.app.PACKED_FILE_EXTENSION)
        ).exists()

    def clear_all_files(self):
        files_folder = self.app.config.remote_folder_path / self.FILES_FOLDERNAME
        for node_path in files_folder.iterdir():
            if node_path.is_file():
                node_path.unlink()
        return True

    def check_manifest_consistency(self, manifest_instance):
        result = True
        for file_node in manifest_instance.iterate(include_folders=False):
            if not self.file_exists(file_node.signature):
                self.app.logger.warn(
                    "File content not found on remote: {}".format(
                        file_node.get_path_str()
                    )
                )
                result = False
        return result

    def get_remote_signatures_set(self):
        s = set()
        files_folder = self.app.config.remote_folder_path / self.FILES_FOLDERNAME
        for node_path in files_folder.iterdir():
            if node_path.is_file():
                s.add(node_path.name)
        return s
