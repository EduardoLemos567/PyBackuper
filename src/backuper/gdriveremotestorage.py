"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""
import google.auth.transport.requests as requests
import google_auth_oauthlib.flow as flow
import googleapiclient.discovery as discovery
import googleapiclient.http as http

from . import remotestorage

MIME_TYPE_FOLDER = "application/vnd.google-apps.folder"


class GDriveRemoteStorage(remotestorage.RemoteStorage):
    """
    A remote storage that interfaces with google drive cloud service.
    Every file or folder in the gdrive cloud have an unique id to identify it when doing requests.
    """

    FILES_FOLDERNAME = "files"

    def __init__(self, app):
        """
        param app app.App: app instance where to retrieve config and call certain methods from.
        """
        super().__init__(app)
        self._file_service = None
        self._path_id = None  # id to the remote_path
        self._manifest_id = None  # id to the manifest file
        self._salt_id = None  # id to the salt file
        self._files_folder_id = None  # id to the 'files' folder
        self._files_id_table = (
            None  # dict of signature -> id conversion: {signature : file_id}
        )

    def _connect(self):
        """
        Start the connection by checking the credentials, if invalid try to autorize and
        create a new one. The 'file service' is a resource that accept a defined set of
        operations and it translate it into https requests.
        :return bool: True = success
        """
        if self._file_service is None:
            credential_data = None
            if self.app.config.gdrive_save_token_flag:
                token_path = (
                    self.app.config.gdrive_token_folder_path / self.app.TOKEN_FILENAME
                )
                if token_path.exists():
                    self.app.logger.debug("Loading credential...")
                    try:
                        credential_data = self.app.local_storage.unpack_unpickle(
                            token_path, self.app.app_key
                        )
                        self.app.logger.debug("Credential loaded.")
                    except Exception as error:
                        self.app.logger.error(
                            "Could not load credential, error: {error_type}: {error_description}".format(
                                error_type=type(error).__name__, error_description=error
                            )
                        )
                if not credential_data or not credential_data.valid:
                    if (
                        credential_data
                        and credential_data.expired
                        and credential_data.refresh_token
                    ):
                        self.app.logger.debug(
                            "Credential expired, trying to refresh..."
                        )
                        request = requests.Request()
                        credential_data.refresh(request)
                        request.session.close()
                        self.app.logger.debug("Credential refreshed.")
                    else:
                        self.app.logger.debug("Acquiring new credential...")
                        app_flow = flow.InstalledAppFlow.from_client_secrets_file(
                            self.app.config.gdrive_secret_file_path,
                            scopes=["https://www.googleapis.com/auth/drive.file"],
                        )
                        credential_data = app_flow.run_local_server()
                        self.app.logger.debug("New credential is now valid.")
                    self.app.logger.debug("Saving new credential...")
                    self.app.local_storage.pickle_pack(
                        credential_data, token_path, self.app.app_key
                    )
                    self.app.logger.debug("New credential saved.")
            else:
                self.app.logger.debug("Acquiring new credential...")
                app_flow = flow.InstalledAppFlow.from_client_secrets_file(
                    self.app.config.gdrive_secret_file_path,
                    scopes=["https://www.googleapis.com/auth/drive.file"],
                )
                credential_data = app_flow.run_local_server()
                self.app.logger.debug("New credential is now valid.")
            self.app.logger.debug("Building service...")
            self._file_service = discovery.build(
                "drive", "v3", credentials=credential_data, num_retries=2
            ).files()
            self.app.logger.debug("Service built.")
        return True

    def setup(self):
        """
        Connect to gdrive with your autorized credentials and search and cache all necessary
        files gdrive ids and folder gdrive ids.
        :return bool: True = success
        """
        if not self._connect():
            self.app.logger.error("Could not connect.")
            self.app.exit(1)
        folder_id = "root"  # start by the default folder id
        # This flag will tell if the path was created or found.
        # If any the parts were created, them ignore the searchs and assume
        # file ids doesnt exist leaving them as None.
        path_creation_mode = False
        # start searching folder name by folder name in the path
        for part_name in self.app.config.remote_folder_path.parts:
            if part_name in ("\\", "/"):  # ignore part_name with these strings
                continue
            if not path_creation_mode:
                # try to find it by listing nodes
                results = self._list_node(folder_id, include_files=False)
                if part_name in results:
                    folder_id = results[part_name]["id"]
                else:  # if not found, start creating one by one
                    path_creation_mode = True
            if path_creation_mode:
                folder_id = self._create_folder(folder_id, part_name)
                if folder_id is None:
                    self.app.logger.error(
                        "Could not create needed folder in the remote path."
                    )
                    self.app.exit(1)
        self._path_id = (
            folder_id  # at this point folder_id was either found or created.
        )
        if not path_creation_mode:
            results = self._list_node(folder_id)
        # at this point if path_creation_mode is True we dont waste time looking for it,
        # we create everything new, otherwise we try to search for nodes in place.
        if path_creation_mode or self.app.MANIFEST_FILENAME not in results:
            self._manifest_id = None
        else:
            self._manifest_id = results[self.app.MANIFEST_FILENAME]["id"]
        if path_creation_mode or self.app.SALT_FILENAME not in results:
            self._salt_id = None
        else:
            self._salt_id = results[self.app.SALT_FILENAME]["id"]
        if path_creation_mode or self.FILES_FOLDERNAME not in results:
            self._files_folder_id = self._create_folder(
                folder_id, self.FILES_FOLDERNAME
            )
            if self._files_folder_id is None:
                self.app.logger.error(
                    "Could not create needed folder for the self.FILES_FOLDERNAME."
                )
                self.app.exit(1)
        else:
            self._files_folder_id = results[self.FILES_FOLDERNAME]["id"]
        if path_creation_mode:
            self._files_id_table = {}
        else:
            # list the 'files' folder and save its ids.
            results = self._list_node(self._files_folder_id, include_folders=False)
            ext_len = len(self.app.PACKED_FILE_EXTENSION)
            self._files_id_table = {
                name[:-ext_len]: result["id"]
                for name, result in results.items()
                if name[-ext_len:] == self.app.PACKED_FILE_EXTENSION
            }
        return True

    def has_files(self):
        """
        :return bool: True if it has any file in the 'files' folder.
        """
        return len(self._files_id_table) > 0

    def has_manifest(self):
        """
        :return bool: True if manifest file exists.
        """
        return self._manifest_id is not None

    def get_manifest(self):
        """
        Retrieve the Manifest instance from the file in the server, named: self.app.MANIFEST_FILENAME.
        :return manifest.Manifest | None: saved manifest instance or None if nothing is found in place.
        """
        if self._manifest_id is not None:
            temp_file_path = self.app.local_storage.get_new_tempfile()
            try:
                self.app.logger.log(9, "Downloading remote manifest...")
                self._download_file(self._manifest_id, temp_file_path)
                return self.app.local_storage.unpack_unpickle(temp_file_path)
            finally:
                self.app.local_storage.dispose_tempfile(temp_file_path)
        else:
            self.app.logger.debug("get_manifest: remote manifest file not found.")
            return None

    def set_manifest(self, manifest_instance):
        """
        Pickle, pack and upload the instance into the server.
        :param manifest_instance manifest.Manifest: manifest instance to save.
        :return bool: True if successful.
        """
        if self._manifest_id is not None:
            if not self._delete_node(self._manifest_id):
                return False
        temp_file_path = self.app.local_storage.get_new_tempfile()
        try:
            self.app.local_storage.pickle_pack(manifest_instance, temp_file_path)
            self._manifest_id = self._upload_file(
                temp_file_path, self._path_id, self.app.MANIFEST_FILENAME
            )
            return True
        finally:
            self.app.local_storage.dispose_tempfile(temp_file_path)

    def delete_manifest(self):
        """
        :return bool: True if file was erased.
        """
        if self._manifest_id is not None:
            result = self._delete_node(self._manifest_id)
            self._manifest_id = None
            return result

    def has_salt(self):
        """
        :return bool: True if salt file exists.
        """
        return self._salt_id is not None

    def get_salt(self):
        """
        Return existing salt on remote.
        :return bytes: Salt value or None if doesnt exist.
        """
        if self._salt_id is not None:
            temp_file_path = self.app.local_storage.get_new_tempfile()
            try:
                self.app.logger.log(9, "Downloading salt...")
                self._download_file(self._salt_id, temp_file_path)
                with temp_file_path.open("rb") as file:
                    return file.read()
            finally:
                self.app.local_storage.dispose_tempfile(temp_file_path)
        else:
            self.app.logger.debug("get_salt: remote salt file not found.")
            return None

    def set_salt(self, salt):
        """
        Save salt on remote.
        :param salt bytes: salt value.
        :return bool: True = success.
        """
        if self._salt_id is not None:
            if not self._delete_node(self._salt_id):
                return False
        temp_file_path = self.app.local_storage.get_new_tempfile()
        try:
            with temp_file_path.open("wb") as file:
                file.write(salt)
            self._salt_id = self._upload_file(
                temp_file_path, self._path_id, self.app.SALT_FILENAME
            )
            return True
        finally:
            self.app.local_storage.dispose_tempfile(temp_file_path)

    def delete_salt(self):
        """
        Delete existing salt on remote.
        :return bool: True = success.
        """
        if self._salt_id is not None:
            result = self._delete_node(self._salt_id)
            self._salt_id = None
            return result

    def _delete_node(self, node_id):
        """
        :return bool: True if file was erased.
        """
        try:
            self._file_service.delete(fileId=node_id).execute()
        except Exception as error:
            self.app.logger.error(
                "delete_node: id: {node_id} : {error_type}: {error_description}, ignoring...".format(
                    node_id=node_id,
                    error_type=type(error).__name__,
                    error_description=error,
                )
            )
            return False
        self.app.logger.log(9, "Node deleted by id: {id}".format(id=node_id))
        return True

    def _create_folder(self, folder_id, folder_name):
        """
        :return str | None: str with the new folder_id if successful or None.
        """
        try:
            folder_id = self._file_service.create(
                body={
                    "name": folder_name,
                    "mimeType": MIME_TYPE_FOLDER,
                    "parents": [folder_id],
                },
                fields="id",
            ).execute()["id"]
        except Exception as error:
            self.app.logger.error(
                "create_folder: name: {folder} : {error_type}: {error_description}, ignoring...".format(
                    folder=folder_name,
                    error_type=type(error).__name__,
                    error_description=error,
                )
            )
            return None
        self.app.logger.log(
            9, "create_folder: '{folder}' created.".format(folder=folder_name)
        )
        return folder_id

    def _list_node(
        self,
        folder_id="root",
        include_folders=True,
        include_files=True,
        limit_results=None,
    ):
        """
        :param folder_id str: folder id used by the gdrive, root is the base folder always.
        (a node can be either a folder or a file.)
        :param include_folders bool: True if folders must be included in the results.
        :param include_files bool: True if files must be included in the results.
        :param limit_results None | int: None = no limit, a number limiting the results.
        :result dict(of dict) | None: {"name":{"id": gdrive id of the node, "is_folder": boolean value self explanatory}} or None if listing failed.
        """
        if (not include_files) and (not include_folders):
            return []
        arguments = {}
        arguments["corpora"] = "user"
        arguments["q"] = "'{}' in parents".format(folder_id)
        if not (include_files and include_folders):
            arguments["q"] += " and mimeType{}='{}'".format(
                ("" if include_folders else "!"), MIME_TYPE_FOLDER
            )
        arguments["spaces"] = "drive"
        if include_files and include_folders:
            arguments["fields"] = "nextPageToken, files(id, name, mimeType, trashed)"
        else:
            arguments["fields"] = "nextPageToken, files(id, name, trashed)"
        arguments["pageToken"] = None
        arguments["pageSize"] = (
            100 if limit_results is None else min(limit_results, 100)
        )
        results = []
        try:
            while True:
                response = self._file_service.list(**arguments).execute()
                results += response.get("files", [])
                arguments["pageToken"] = response.get("nextPageToken", None)
                if arguments["pageToken"] is None or (
                    limit_results is not None and len(results) >= limit_results
                ):
                    break
        except Exception as error:
            self.app.logger.error(
                "_list_node: {error_type}: {error_description}, ignoring...".format(
                    error_type=type(error).__name__, error_description=error
                )
            )
            return None
        self.app.logger.log(
            9,
            "Listing folder: id: {}, limit: {}, include_folders: {}, include_files: {}".format(
                folder_id, limit_results, include_folders, include_files
            ),
        )
        if include_files and include_folders:
            return {
                item["name"]: {
                    "id": item["id"],
                    "is_folder": item["mimeType"] == MIME_TYPE_FOLDER,
                }
                for item in results
                if not item["trashed"]
            }
        else:
            return {
                item["name"]: {"id": item["id"], "is_folder": include_folders}
                for item in results
                if not item["trashed"]
            }

    def _folder_has_nodes(self, folder_id):
        """
        Check if the remote folder id has any node inside it (file or folder).
        :param folder_id str: gdrive id of the folder.
        :return bool | None: True if it has at least one node, false otherwise. None if request failed.
        """
        return len(self._list_node(self._files_folder_id, limit_results=1)) > 0

    def _upload_file(self, local_abs_file_path, remote_parent_id, remote_name):
        """
        :param local_abs_file_path pathlib.Path | str: absolute path pointing to the file.
        :param remote_parent_id str: remote id of the folder where the file will reside.
        :param remote_name str: the new name the file will have on the server.
        :return str | None: remote id of the uploaded file. None if failed.
        """
        media = http.MediaFileUpload(local_abs_file_path, resumable=True)
        meta = {"name": remote_name, "parents": [remote_parent_id]}
        request = self._file_service.create(body=meta, media_body=media, fields="id")
        try:
            # execute
            response = None
            while response is None:
                # keep executing chunk by chunk until response means its done.
                response = request.next_chunk()[1]
        except Exception as error:
            self.app.logger.error(
                "upload_file: {name} : {error_type} : {error_description}, ignoring...".format(
                    name=remote_name,
                    error_type=type(error).__name__,
                    error_description=error,
                )
            )
            return None
        self.app.logger.log(9, "file uploaded id: {}".format(response["id"]))
        return response["id"]

    def _download_file(self, remote_id, local_abs_file_path):
        """
        :param remote_id str: id of the file to be downloaded.
        :param local_abs_file_path pathlib.Path: path to name and folder where the file will be saved
        once it was downloaded.
        :return bool: True if successful.
        """
        media = self._file_service.get_media(fileId=remote_id)
        with local_abs_file_path.open("wb") as file:
            request = http.MediaIoBaseDownload(file, media)
            try:
                response = False
                while response is False:
                    response = request.next_chunk()[1]
            except Exception as error:
                self.app.logger.error(
                    "download_file: {name} : {error_type} : {error_description}, ignoring...".format(
                        name=local_abs_file_path.name,
                        error_type=type(error).__name__,
                        error_description=error,
                    )
                )
                return False
        self.app.logger.log(9, "file downloaded id: {}".format(remote_id))
        return True

    def set_file(self, src_abs_path, signature):
        """
        Send a ready file into storage, in this case upload into gdrive.
        :param dest_abs_path pathlib.Path: path to read the upload.
        :param signature str: file signature to save.
        :return bool: True = success
        """
        if self.file_exists(signature):
            self.app.logger.warn(
                "set_file: Cant set a file that already exists, ignoring..."
            )
            return False
        self._files_id_table[signature] = self._upload_file(
            src_abs_path,
            self._files_folder_id,
            signature + self.app.PACKED_FILE_EXTENSION,
        )
        return True

    def get_file(self, signature, dest_abs_path):
        """
        Retrieve a file from storage, download and save on dest_abs_path.
        :param signature str: file signature to obtain.
        :param dest_abs_path pathlib.Path: path to save the download.
        :return bool: True = success
        """
        if not self.file_exists(signature):
            self.app.logger.debug("get_file: File not found by signature, ignoring...")
            return False
        return self._download_file(self._files_id_table[signature], dest_abs_path)

    def file_exists(self, signature):
        """
        :param signature str: file signature to check
        :return bool: True = signature exists on remote
        """
        return signature in self._files_id_table

    def delete_file(self, signature):
        """
        Delete remote file by signature.
        :param signature str: file signature to delete
        :return bool: True = success
        """
        if not self.file_exists(signature):
            self.app.logger.debug(
                "delete_file_node: Trying to delete a remote file that doesnt exist, ignoring..."
            )
            return False
        if self._delete_node(self._files_id_table[signature]):
            del self._files_id_table[signature]
            return True
        else:
            return False

    def clear_all_files(self):
        """
        Clear all files inside files folder by removing and recreating the folder, used in case of orphaned files: without manifest.
        :return bool: True = success
        """
        self._delete_node(self._files_folder_id)
        self._files_folder_id = self._create_folder(
            self._path_id, self.FILES_FOLDERNAME
        )
        self._files_id_table = {}
        return True

    def check_manifest_consistency(self, manifest_instance):
        """
        Check if manifest all files signatures are found on RemoteStorage.
        :param manifest_instance manifest.Manifest: manifest instance to check signatures.
        :return bool: True if all files are present or False if at least a single file is missing
        """
        result = True
        for file_node in manifest_instance.iterate(include_folders=False):
            if file_node.signature not in self._files_id_table:
                self.app.logger.warn(
                    "File content not found on remote: {}".format(
                        file_node.get_path_str()
                    )
                )
                result = False
        return result

    def get_remote_signatures_set(self):
        """
        :return set(str): A set of signature strings present on RemoteStorage.
        """
        return set(self._files_id_table.keys())
