"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""


class RemoteStorage:
    """
    Every remote storage will have this folder structure:
        - given base folder from config.remote_folder_path.
        - inside the base folder: manifest pickled and packed with the name as
        self.app.MANIFEST_FILE_NAME.
        - inside the base folder: salt file as plain bytes.
        - inside the base folder: a folder with the name 'files' where every
        file is stored with their signature as name and extension from
        self.app.PACKED_FILE_EXTENSION.
    """

    def __init__(self, app):
        self.app = app

    def setup(self):
        raise NotImplementedError

    def has_files(self):
        raise NotImplementedError

    def has_manifest(self):
        raise NotImplementedError

    def set_manifest(self, manifest_instance):
        raise NotImplementedError

    def get_manifest(self):
        raise NotImplementedError

    def delete_manifest(self):
        raise NotImplementedError

    def has_salt(self):
        raise NotImplementedError

    def get_salt(self):
        raise NotImplementedError

    def set_salt(self, salt):
        raise NotImplementedError

    def delete_salt(self):
        raise NotImplementedError

    def get_file(self, signature, dest_abs_path):
        raise NotImplementedError

    def set_file(self, src_abs_path, signature):
        raise NotImplementedError

    def delete_file(self, signature):
        raise NotImplementedError

    def file_exists(self, signature):
        raise NotImplementedError

    def clear_all_files(self):
        raise NotImplementedError

    def check_manifest_consistency(self, manifest_instance):
        raise NotImplementedError

    def get_remote_signatures_set(self):
        raise NotImplementedError
