"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/dev-567/PyBackuper/blob/main/LICENSE
:author:
    Eduardo Lemos de Moraes
:packages:
    packages used in the project:
    - oscrypto
    - google-api-python-client google-auth-httplib2 google-auth-oauthlib
    You can install these packages using the install.py provided.
"""
import sys
import datetime
import importlib.util as import_util
import logging
import pathlib
import atexit

from . import localstorage
from . import crypto
from . import streamtologger


class App:
    APP_NAME = "Backuper"
    APP_VERSION = "0.7"
    # This value will leave 2048 bytes of extra space, allowing encrypted data (which sometimes
    # increase in size) not overflow our max value of 16MB, also included in this 2048, the 3
    # bytes we use for the block length info.
    # Reason for this max value of 16MB is the use of only 3 bytes to indicate each block length
    # in the stream.
    BLOCK_SIZE = (2 ** (3 * 8) - 1) - 2048
    HASH_DIGEST_LENGTH = 64  # max value for blake2b: 64
    HASH_PARTIAL_BLOCK = 123  # used on localstorage.LocalStorage.get_signature()
    PACKED_FILE_EXTENSION = ".packed"  # used to identify files after localstorage.LocalStorage.pack (compressed and encrypted)
    PLAINBYTES_EXTENSION = ".bytes"  # used to save files with plain bytes, used for salt and app_key, as they shouldnt be encrypted.
    MANIFEST_FILENAME = "manifest" + PACKED_FILE_EXTENSION
    APP_KEY_FILENAME = "app_key" + PLAINBYTES_EXTENSION
    SALTED_FILENAME = "salted" + PACKED_FILE_EXTENSION
    SALT_FILENAME = "salt" + PLAINBYTES_EXTENSION
    TOKEN_FILENAME = "token" + PACKED_FILE_EXTENSION

    def __init__(self, config_file_path, press_enter_to_finish=False):
        """
        :param config_file_path str | pathlib.Path: path pointing to the config file.
        :param press_enter_to_finish bool: if True, will wait for press enter input when the script is done.
        """
        self.config_file_path = config_file_path
        self.press_enter_to_finish = press_enter_to_finish
        # config instance: remember if you change this you have to update the
        # local_storage and remote_storage versions of the config.
        self.config = None  # Config instance from config file
        self.logger = None  # logger used to communicate messages to user/dev
        self.local_storage = None
        self.remote_storage = None
        self.salted_key = None  # user key to [de]encrypt user files
        self.app_key = None  # app key used to [de]encrypt local app files (salted and token, these files are disposables)
        assert (
            self.BLOCK_SIZE < (2 ** (3 * 8)) - 1
        ), "BLOCK_SIZE should be lower than 16MB-1 (because of the three length bytes)"
        assert (
            self.HASH_PARTIAL_BLOCK <= self.BLOCK_SIZE
        ), "HASH_PARTIAL_BLOCK should be equal or lower than the BLOCK_SIZE"
        assert (
            self.HASH_DIGEST_LENGTH <= 64
        ), "HASH_DIGEST_LENGTH should be at max 64, this is the max allowed value for blake2b digest"
        atexit.register(self._on_exit)

    def _check_config(self, config_instance):
        """
        Check if the config structure have the minimum attributes required to proceed.
        :param config_instance config_example.Config: any class with those minimum attributes.
        """
        keys = (
            "local_folder_path",
            "remote_folder_path",
            "local_manifest_folder_path",
            "temp_folder_path",
            "log_file_path",
            "print_debug_flag",
            "fulldebug_flag",
            "format_debug_flag",
            "save_debug_to_file_flag",
            "gdrive_secret_file_path",
            "gdrive_save_token_flag",
            "gdrive_token_folder_path",
            "compression_ratio",
            "encryption_save_salted_password_flag",
            "encryption_salted_folder_path",
            "app_key_folder_path",
        )
        for key in keys:
            if key not in config_instance.__dict__:
                raise AttributeError("Attribute {} missing on class.".format(key))
            if key.endswith("_path"):
                if not isinstance(config_instance.__dict__[key], pathlib.Path):
                    config_instance.__dict__[key] = pathlib.Path(
                        config_instance.__dict__[key]
                    )
                # ignore those
                if key in ("remote_folder_path"):
                    continue
                # check those if parent folder exists
                elif key in ("log_file_path"):
                    if not config_instance.__dict__[key].parent.exists():
                        raise AttributeError(
                            "Folder from path at config_instance.{} doesnt exist.".format(
                                key
                            )
                        )
                # everything else check if file exists
                elif not config_instance.__dict__[key].exists():
                    raise AttributeError(
                        "Path at config_instance.{} doesnt exist.".format(key)
                    )
            elif key.endswith("_flag"):
                if type(config_instance.__dict__[key]) is not bool:
                    raise AttributeError(
                        "config_instance.{} should be a 'boolean' value.".format(key)
                    )
            elif key == "compression_ratio":
                if type(config_instance.__dict__[key]) is not float:
                    raise AttributeError(
                        "config_instance.{} should be a 'float' value.".format(key)
                    )
                if not (0.0 <= config_instance.__dict__[key] <= 1.0):
                    raise AttributeError(
                        "config_instance.{} should be at the interval 0.0...1.0 (inclusive both).".format(
                            key
                        )
                    )
        if not hasattr(config_instance, "filter_function"):
            raise AttributeError("Config class should define a filter_function")

    def _load_config(self):
        """
        Load the self.config_file_path file as a python file where its expected to have a
        single class called Config. In this class with expect some attributes as configuration
        values for our program. These values are checked on self._check_config. At the end
        we have a self.config set and its accessed globally by the application.
        """
        # load config module
        spec = import_util.spec_from_file_location("config", self.config_file_path)
        config_module = import_util.module_from_spec(spec)
        spec.loader.exec_module(config_module)
        # read config data
        self.config = config_module.Config(
            module_folder_path=pathlib.Path(__file__).parent,
            app_folder_path=pathlib.Path(sys.argv[0]).parent,
            config_folder_path=self.config_file_path.parent,
            system_tempfolder_path=localstorage.LocalStorage.get_default_tempfolder_path(),
        )
        self._check_config(self.config)
        self.salted_key = None  # user key to encrypt user files
        self.app_key = None  # app key to encrypt app files

    def _setup_logger(self):
        """
        Setup the self.logger instance used by other classes like: LocalStorage or RemoteStorage.
        """
        if self.config.print_debug_flag:
            if self.config.fulldebug_flag:
                logging.addLevelName(9, "FULLDEBUG")
                debug_level = logging.DEBUG - 1  # fulldebug
            else:
                debug_level = logging.DEBUG  # debug
        else:
            debug_level = logging.INFO  # debug disabled
        self.logger = logging.getLogger(self.APP_NAME + " " + self.APP_VERSION)
        self.logger.setLevel(
            logging.NOTSET + 1
        )  # all inclusive, cant be zero = inactive
        if self.config.format_debug_flag:
            formatter = logging.Formatter(
                "(%(processName)s | %(threadName)s | %(asctime)s | %(levelname)s)\n%(message)s"
            )
        else:
            formatter = logging.Formatter("%(message)s")
        if self.config.log_file_path.exists():
            if self.config.log_file_path.stat().st_size > 100 * 1024:
                log_path_old = self.config.log_file_path.parent / (
                    self.config.log_file_path.stem
                    + "_old"
                    + self.config.log_file_path.suffix
                )
                if log_path_old.exists():
                    log_path_old.unlink()
                self.config.log_file_path.rename(log_path_old)

        handler = logging.FileHandler(self.config.log_file_path)
        handler.setFormatter(formatter)
        # file logging config
        # if the flag is off, only save log INFO or above.
        handler.setLevel(
            debug_level if self.config.save_debug_to_file_flag else logging.INFO
        )
        self.logger.addHandler(handler)
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        # stream/prompt config
        handler.setLevel(debug_level)  # console logging level
        self.logger.addHandler(handler)
        if self.config.print_debug_flag:
            # only redirect python errors if in debug mode
            stderr = streamtologger.StreamToLogger(self.logger, logging.DEBUG)
            # do a small test as DEBUG level
            stderr.write("Stderr redirect is working.")
            stderr.flush()
            stderr.level = logging.ERROR  # change to ERROR level
            sys.stderr = stderr  # redirect sys.stderr into StreamToLogger instance
        self.logger.info("Logger created.")

    def _load_app_key(self):
        """
        Load the self.app_key from file (if not found, its randomly generated).
        Its supposed to be a key package wide, used by any projects or instances.
        This key is used to encrypt local disposable files which is better than leaving
        them as plain text.
        """
        self.logger.debug("Loading app key...")
        key_path = self.config.app_key_folder_path / self.APP_KEY_FILENAME
        if not key_path.exists():
            self.logger.debug("App key not found, generating...")
            self.app_key = crypto.generate_app_key()
            self.logger.debug("App key generated, saving...")
            with key_path.open("wb") as file:
                file.write(self.app_key)
            self.logger.debug("App key saved.")
        else:
            with key_path.open("rb") as file:
                self.app_key = file.read()
            self.logger.debug("App key loaded.")

    def _load_salted_key(self):
        """
        Try to load the salted version of password from file, if its not available ask the user,
        acquire the salt and apply the salt. Both ways the password is saved on self.salted_key.
        :return None:
        """
        if self.config.encryption_save_salted_password_flag:
            self.logger.debug("Loading salted...")
            salted_path = (
                self.config.encryption_salted_folder_path / self.SALTED_FILENAME
            )
            if salted_path.exists():
                if not self.remote_storage.has_salt():
                    self.logger.warn(
                        "Remote salt doesnt exist, but local salted hash is present.\nIf you lose the salted hash you wont be able to regenerate the same hash without the salt."
                    )
                temp_file_path = self.local_storage.get_new_tempfile()
                try:
                    self.local_storage.unpack(salted_path, temp_file_path, self.app_key)
                    with temp_file_path.open("rb") as file:
                        self.salted_key = file.read()
                except AttributeError:
                    self.salted_key = None
                    self.logger.debug(
                        "Could not load salted file, type your password again."
                    )
                finally:
                    self.local_storage.dispose_tempfile(temp_file_path)
                self.logger.debug("Salted loaded.")
            else:
                self.salted_key = None
                self.logger.debug("Salted file doesnt exist, type your password again.")
            if self.salted_key is None:
                self._capture_password_salted()
                self.logger.debug("Saving your salted password hash...")
                temp_file_path = self.local_storage.get_new_tempfile()
                try:
                    with temp_file_path.open("wb") as file:
                        file.write(self.salted_key)
                    self.local_storage.pack(temp_file_path, salted_path, self.app_key)
                finally:
                    self.local_storage.dispose_tempfile(temp_file_path)
                self.logger.debug("Password saved.")
        else:
            self.logger.debug(
                "Encryption salted password save/load disabled, capturing and using live..."
            )
            self._capture_password_salted()

    def _capture_password_salted(self):
        """
        This function capture the password typed by the user, load and apply the salt (if salt is not
        found on remote, its generated and saved). At the end of a succesful execution we have set
        the self.salted_key.
        """
        while True:
            password = input(
                "Type your encryption password (min length: 8, type 'e' to exit):"
            )
            if len(password) == 0:
                print("Password cant be empty.")
            elif password == "e":
                self.logger.debug("Password capture cancelled, exiting.")
                self._exit(1)
            elif len(password) < 8:
                print("Password length need to be at least 8 characters.")
            else:
                print("Password accepted.")
                break
        self.logger.debug("Loading salt...")
        if self.remote_storage.has_salt():
            salt = self.remote_storage.get_salt()
            self.logger.debug("Salt loaded.")
        else:
            self.logger.debug("Salt not found, generating new one...")
            salt = crypto.generate_salt()
            self.logger.debug("Saving salt...")
            self.remote_storage.set_salt(salt)
            self.logger.debug("New salt saved.")
        self.logger.debug("Generating salted password hash...")
        self.salted_key = crypto.apply_salt(password.encode(), salt)
        self.logger.debug("Salted password hash generation done.")

    def setup(self, remote_storage_type):
        """
        Prepare the App to start operating.
        Load configs from the Config file, setup loggers used by other classes,
        create the storages versions.
        """
        print("Realizing setup...")
        # read, load, adjust configs from the file
        self._load_config()  # check and load config file
        self._setup_logger()
        self.logger.info("Continuing setup...")
        self._load_app_key()
        self.logger.debug("Creating local storage...")
        self.local_storage = localstorage.LocalStorage(self)
        self.logger.debug("Local storage created. Creating remote storage...")
        self.remote_storage = remote_storage_type(self)
        self.logger.debug(
            "Remote storage created. Realizing the remote storage setup..."
        )
        self.remote_storage.setup()
        self.logger.debug("Remote storage setup done.")
        self._load_salted_key()  # load the salted password, the user key
        self.logger.info("Setup done.")

    def _pull_group_set(self, signatures_set, files_dict):
        """
        Acquire once each file by the signature and copy into FileNode paths given by the list.
        :param signatures_set set(str): set of keys to select which files to acquire.
        :param files_dict dict(key=signature, value=list(FileNode,...)): dictionary with signature as key and a list of FileNode as values.
        """
        temp_file_path = self.local_storage.get_new_tempfile()
        temp_file_path2 = self.local_storage.get_new_tempfile()
        counter1 = 0
        counter2 = 0
        try:
            for signature in signatures_set:
                counter1 += 1
                # Acquire it once, into the temp file
                if self.remote_storage.get_file(signature, temp_file_path):
                    # Unpack it on the temp file 2
                    if self.local_storage.unpack(temp_file_path, temp_file_path2):
                        # If we succesfully unpacked, we check the signature before proceeding.
                        if (
                            self.local_storage.get_signature(temp_file_path2)
                            == signature
                        ):
                            # Copy the correct file on all places its copy is needed.
                            for file_node in files_dict[signature]:
                                counter2 += 1
                                if self.local_storage.ensure_folder_exists(
                                    file_node.parent
                                ):
                                    self.local_storage.copy(
                                        temp_file_path2,
                                        self.local_storage.abs_path(file_node),
                                    )
                                else:
                                    self.logger.error(
                                        "Could not ensure that parent folder exists, for this file: {}".format(
                                            str(file_node.get_path())
                                        )
                                    )
                        else:
                            self.logger.error(
                                "File unpacked resulted in a different signature from original, affecting those files:\n{}".format(
                                    "\n".join(
                                        [
                                            str(file_node.get_path())
                                            for file_node in files_dict[signature]
                                        ]
                                    )
                                )
                            )
                    else:
                        self.logger.error(
                            "Could not unpack file by signature: {}".format(signature)
                        )
                else:
                    self.logger.error(
                        "Could not acquire file signature: {}".format(signature)
                    )
        finally:
            self.local_storage.dispose_tempfile(temp_file_path)
            self.local_storage.dispose_tempfile(temp_file_path2)
        self.logger.debug(
            "(total files added on local:{} / files acquired from remote: {} / files copied from downloaded: {})".format(
                counter2, counter1, counter2 - counter1
            )
        )

    def pull(self, authorized=False, local_manifest=None, remote_manifest=None):
        """
        Pull files from RemoteStorage into LocalStorage, warns you before continuing if the result
        operation will delete or overwrite any file or folder.
        This operation follow the file system structure described on the pickled remote Manifest.
        Files are decrypted, decompressed and signature checked before copied into LocalStorage.
        :param authorized bool: If False, when a file deletion is required a confirmation will be asked from the user.
        Otherwise it will just proceed without confirmation.
        :param local_manifest manifest.Manifest: cached version the local manifest, used to avoid reload/rebuilding, passed by sync
        :param remote_manifest manifest.Manifest: cached version the remote manifest, used to avoid downloading, passed by sync
        """
        self.logger.info("Pulling...")
        if self.remote_storage.has_files():
            if self.remote_storage.has_manifest():
                if remote_manifest is None:
                    remote_manifest = self.remote_storage.get_manifest()
                # check if all files in remote manifest are present on remote storage
                if not self.remote_storage.check_manifest_consistency(remote_manifest):
                    self.logger.error(
                        "Not all files in the manifest are present, can't proceed."
                    )
                    self._exit(1)
                if self.local_storage.has_files():
                    # local_storage has files, we need to clean up before acquiring more files
                    if not authorized:
                        if self._confirm_proceeding(
                            "Proceeding with the 'pull' may cause some files/folders in {} to be REPLACE or ERASED!".format(
                                self.config.local_folder_path
                            )
                        ):
                            authorized = True
                        else:
                            self.logger.error(
                                "Could not proceed with clean up, operation not authorized by the user."
                            )
                            self._exit(1)
                    # do a local filesystem scan
                    if local_manifest is None:
                        local_manifest = self.local_storage.build_manifest()
                    # group files by signatures
                    local_group_dict = local_manifest.get_signatures_dict()
                    remote_group_dict = remote_manifest.get_signatures_dict()
                    counter1 = 0
                    counter2 = 0
                    counter3 = 0
                    # keys = signatures that only exist on local (excluding the ones shared with remote)
                    # delete files that exist only on local
                    for signature in local_group_dict.keys() - remote_group_dict.keys():
                        for file_node in local_group_dict[signature]:
                            self.local_storage.delete_node(file_node)
                            counter1 += 1
                        del local_group_dict[signature]
                    # move or copy local files: on files that exist on remote and local
                    for signature in local_group_dict.keys() & remote_group_dict.keys():
                        # all files in this loop have the same signature
                        # here files that already exist on local
                        local_files_dict = {
                            file_node.get_path_str(): file_node
                            for file_node in local_group_dict[signature]
                        }
                        # here files that need to exist, following what the remote manifest says
                        remote_files_dict = {
                            file_node.get_path_str(): file_node
                            for file_node in remote_group_dict[signature]
                        }
                        # keys = we use the path as a common hashable key between local and remote
                        # iterate over files that need to be created
                        for remote_key in (
                            remote_files_dict.keys() - local_files_dict.keys()
                        ):
                            # check if we have a local file that is in the wrong place and move to the path needed in the remote_files_dict[remote_key]
                            for local_key in (
                                local_files_dict.keys() - remote_files_dict.keys()
                            ):
                                self.local_storage.ensure_folder_exists(
                                    remote_files_dict[remote_key]
                                )
                                self.local_storage.move_node(
                                    local_files_dict[local_key],
                                    remote_files_dict[remote_key],
                                )
                                local_files_dict[remote_key] = local_files_dict[
                                    local_key
                                ]  # add the new path
                                del local_files_dict[local_key]  # delete previous path
                                counter2 += 1
                                break  # execute once
                            # this 'else' here only executes if we finished the above 'for' without a break (counts for case where len() == 0)
                            else:
                                # get any existing local file and make a copy to the path needed in the remote_files_dict[remote_key]
                                for local_key in local_files_dict.keys():
                                    self.local_storage.ensure_folder_exists(
                                        remote_files_dict[remote_key]
                                    )
                                    self.local_storage.copy_node(
                                        local_files_dict[local_key],
                                        remote_files_dict[remote_key],
                                    )
                                    local_files_dict[remote_key] = local_files_dict[
                                        local_key
                                    ]
                                    counter3 += 1
                                    break  # execute once
                        # delete exceeding files
                        for local_key in (
                            local_files_dict.keys() - remote_files_dict.keys()
                        ):
                            self.local_storage.delete_node(local_files_dict[local_key])
                            counter1 += 1
                    del local_files_dict, remote_files_dict
                    self.logger.info(
                        "(files removed from local: {} / files moved from local: {} / files copied from local: {})".format(
                            counter1, counter2, counter3
                        )
                    )
                    # acquire missing files
                    self._pull_group_set(
                        remote_group_dict.keys() - local_group_dict.keys(),
                        remote_group_dict,
                    )
                    del local_group_dict, remote_group_dict
                    # do a fast scan and delete all folders that shouldnt exist
                    local_manifest = self.local_storage.build_manifest(
                        include_files=False
                    )
                    for folder_node in local_manifest.diff_nodes(
                        remote_manifest, include_files=False
                    ):
                        self.local_storage.delete_empty_folders(folder_node)
                    # do another fast scan and create empty folders existing on remote_folder and not on local (yet)
                    local_manifest = self.local_storage.build_manifest(
                        include_files=False
                    )
                    for folder_node in remote_manifest.diff_nodes(
                        local_manifest, include_files=False
                    ):
                        self.local_storage.ensure_folder_exists(folder_node)
                else:
                    # there's no local files, no need to clean up and all files need to be acquired from zero
                    remote_group_dict = remote_manifest.get_signatures_dict()
                    self._pull_group_set(remote_group_dict.keys(), remote_group_dict)
                # Do a final scan for consistency check
                local_manifest = self.local_storage.build_manifest()
                # If they are not equal, exit with error.
                if local_manifest != remote_manifest:
                    self.logger.error("Local consistency check failed.")
                    diff = [
                        file_node.get_path_str()
                        for file_node in local_manifest.diff_nodes(remote_manifest)
                    ]
                    self.logger.warn("local-remote files:\n{}".format("\n".join(diff)))
                    diff = [
                        file_node.get_path_str()
                        for file_node in remote_manifest.diff_nodes(local_manifest)
                    ]
                    self.logger.warn("remote-local files:\n{}".format("\n".join(diff)))
                    self._exit(1)
                # Otherwise replace the local manifest
                else:
                    self.local_storage.set_manifest(remote_manifest)
                    self.logger.info("Local consistency checked.")
                self.logger.info("Pull finished.")
            else:
                if not self._confirm_proceeding(
                    "Since remote_manifest was not found and there's orphaned files into the {folder}/files folder.\nProceeding will cause all files into {folder}/files folder do be ERASED!".format(
                        folder=self.config.remote_folder_path
                    )
                ):
                    self.logger.error(
                        "Could not proceed with clean up, operation not authorized by the user."
                    )
                    self._exit(1)
                self.remote_storage.clear_all_files()
                self.logger.error("No files on the server to pull from.")
                self._exit(1)
        else:
            self.logger.error("No files on the server to pull from.")

    def push(self, authorized=False, local_manifest=None, remote_manifest=None):
        """
        Push files from LocalStorage into RemoteStorage, warns you before continuing if the resulting
        operation will delete or overwrite any file or folder.
        This operation create files into the remote folder files, which their signature being used as name.
        Files are compressed and encrypted before copied into RemoteStorage.
        :param authorized bool: If False, when a file deletion is required a confirmation will be asked from the user.
        Otherwise it will just proceed without confirmation.
        :param local_manifest manifest.Manifest: cached version the local manifest, used to avoid reload/rebuilding, passed by sync
        :param remote_manifest manifest.Manifest: cached version the remote manifest, used to avoid downloading, passed by sync
        """
        self.logger.info("Pushing...")
        # check if theres local files, otherwise there's nothing to push
        if self.local_storage.has_files():
            if local_manifest is None:
                local_manifest = (
                    self.local_storage.build_manifest()
                )  # scan local filesystem and build a manifest to compare next
            if self.remote_storage.has_manifest():
                if remote_manifest is None:
                    remote_manifest = self.remote_storage.get_manifest()
                if self.remote_storage.has_files():
                    if not authorized:
                        if self._confirm_proceeding(
                            "Proceeding with the 'push' may cause some files/folders in {} to be REPLACE or ERASED!".format(
                                self.config.remote_folder_path
                            )
                        ):
                            authorized = True
                        else:
                            self.logger.error(
                                "Could not proceed with clean up, operation not authorized by the user."
                            )
                            self._exit(1)
                    # we got remote manifest and remote files:
                    if not self.remote_storage.check_manifest_consistency(
                        remote_manifest
                    ):
                        self.logger.error(
                            "Not all files in the manifest are present, can't proceed."
                        )
                        self._exit(1)
                    # clean up remote, filter all files that exist on remote but not on local,
                    # only remove a file if the content has no more file users/subscribers.
                    remote_set = self.remote_storage.get_remote_signatures_set()
                    local_set = local_manifest.get_signatures_set()
                    counter1 = len(remote_set - local_set)
                    for signature in remote_set - local_set:
                        self.remote_storage.delete_file(signature)
                    self.logger.info(
                        "(files removed from remote on cleanup: {})".format(counter1)
                    )
                    del remote_set, local_set
            else:
                # we have no remote manifest
                # NOTE: we set the remote manifest as requirement to operate on the 'files' folder, otherwise
                # we cant be sure if the existing files are encrypted with the correct key (we could check though, but
                # i decided its not worth for now). So if remote manifest exists and its operable with the current key,
                # we good.
                if self.remote_storage.has_files():
                    # no manifest + remote files = delete orphaned files
                    if not self._confirm_proceeding(
                        "Since remote_manifest was not found and there's orphaned files into the {folder}/files folder.\nProceeding will cause all files into {folder}/files folder do be ERASED!".format(
                            folder=self.config.remote_folder_path
                        )
                    ):
                        self.logger.error(
                            "Could not proceed with clean up, operation not authorized by the user."
                        )
                        self._exit(1)
                    self.remote_storage.clear_all_files()
            # send all local files and check if file exists before sending
            counter1 = 0
            counter2 = 0
            temp_file_path = self.local_storage.get_new_tempfile()
            try:
                # grab each file from the local filesystem, check if the signature already exists on the remote
                # and only send new files, skip files already there (with the same content = signature)
                for file_node in local_manifest.iterate(include_folders=False):
                    counter1 += 1
                    if not self.remote_storage.file_exists(file_node.signature):
                        counter2 += 1
                        # pack (encrypt+compress) and send
                        self.local_storage.pack(
                            self.local_storage.abs_path(file_node), temp_file_path
                        )
                        self.remote_storage.set_file(
                            temp_file_path, file_node.signature
                        )
            finally:
                self.local_storage.dispose_tempfile(temp_file_path)
            self.logger.info(
                "(total files to be on remote: {} / new files copied into remote: {} / skipped: {})".format(
                    counter1, counter2, counter1 - counter2
                )
            )
            # in case the resulting manifest is different from remote: replace it.
            if remote_manifest is None or remote_manifest != local_manifest:
                local_manifest.timestamp = self._get_timestamp()
                self.logger.debug("Replacing remote manifest...")
                if self.remote_storage.set_manifest(local_manifest):
                    if self.remote_storage.check_manifest_consistency(local_manifest):
                        self.logger.info("Remote consistency checked.")
                    else:
                        self.logger.error("Remote consistency check failed.")
                        self._exit(1)
                else:
                    self.logger.error("Could not set remote manifest.")
                    self._exit(1)
            self.local_storage.set_manifest(local_manifest)
            self.logger.info("Push finished.")
        else:
            self.logger.error("No files on local storage to push from.")
            self._exit(1)

    def sync(self, authorized=False):
        """
        Realize a pull or push based on local state and timestamp of manifests.
        WARNING: for this method to work properly you need to follow two rules:
            - Start your local (or locals) with a push or pull, so we have local manifests
            (and remote manifests, this is actually enforced and doesnt proceed if no local
            or remote manifest exists)
            - End every work session with a pull, push or sync.
        This method understands if your local folder is different from the last local manifest,
        it must use be newer.
        This can lead to a conflict:
        - worked on local 1, forgot to update
        - worked on local 2, updated
        - run sync on local 1: older state will overwrite newer state (because different state means newer for sync).
        :param authorized bool: If False, when a file deletion is required a confirmation will be asked from the user.
        Otherwise it will just proceed without confirmation.
        WARNING: leaving to False is safer as it will require you to confirm before overwriting.
        """
        self.logger.info("Synching...")
        if self.local_storage.has_manifest():
            if self.remote_storage.has_manifest():
                last_local_manifest = self.local_storage.get_manifest()
                actual_local_manifest = self.local_storage.build_manifest()
                if last_local_manifest == actual_local_manifest:
                    local_timestamp = last_local_manifest.timestamp
                else:
                    local_timestamp = self._get_timestamp()
                del last_local_manifest  # wont need this anymore, we only work with the fresh
                remote_manifest = self.remote_storage.get_manifest()
                # update local_manifest timestamp before calling pull or push
                actual_local_manifest.timestamp = local_timestamp
                if remote_manifest.timestamp > local_timestamp:
                    # remote is more recent
                    self.pull(
                        authorized=authorized,
                        local_manifest=actual_local_manifest,
                        remote_manifest=remote_manifest,
                    )
                elif remote_manifest.timestamp < local_timestamp:
                    # local is more recent
                    self.push(
                        authorized=authorized,
                        local_manifest=actual_local_manifest,
                        remote_manifest=remote_manifest,
                    )
                else:
                    # we do nothing, they are up to date.
                    self.logger.info("Storages are up to date.")
            else:
                self.logger.error(
                    "No remote manifest present, ensure you updated your remote folder with at least a 'pull' or 'push' before synching."
                )
                self._exit(1)
        else:
            self.logger.error(
                "No local manifest present, ensure you updated your local folder with at least a 'pull' or 'push' before synching."
            )
            self._exit(1)
        self.logger.info("Sync finished.")

    def clear(self, authorized=False):
        """
        Clear all remote files, when you want to start fresh your push.
        :param authorized bool: If False, when a file deletion is required a confirmation will be asked from the user.
        Otherwise it will just proceed without confirmation.
        """
        self.logger.info("Cleaning...")
        if not authorized:
            if self._confirm_proceeding(
                "Proceeding will remove all files from remote folder 'files', manifest and salt..."
            ):
                authorized = True
            else:
                self.logger.error(
                    "Could not proceed with clean up, operation not authorized by the user."
                )
                self._exit(1)
        self.remote_storage.delete_manifest()
        self.remote_storage.delete_salt()
        self.remote_storage.clear_all_files()
        # by consequence we must also clear local manifest (no key to decrypt it):
        self.local_storage.delete_manifest()
        # and delete the salted password, since we'll change the remote salt
        (self.config.encryption_salted_folder_path / self.SALTED_FILENAME).unlink()
        self.logger.info("You must set a new password and salt before proceeding.")
        self._load_salted_key()
        self.logger.info("Clear finished.")

    def _confirm_proceeding(self, msg):
        """
        Simply show the 'msg' and the following question and capture the answer
        :return bool: True/False based on the answer.
        """
        print(msg)
        while True:
            answer = input("Are you sure you want to proceed? (y/N) ")
            if answer in ("y", "Y"):
                print("answer: yes")
                return True
            elif answer in ("", "n", "N"):
                print("answer: no")
                return False

    def _get_timestamp(self):
        """
        Get local time as timestamp used in the Manifest file.
        :return float: timestamp unix time.
        """
        return datetime.datetime.now(datetime.timezone.utc).timestamp()

    def _exit(self, code=0):
        """
        Centralize the code exit function here.
        :param code int: code to exit the interpreter. 0 = no errors, >=1 = errors
        """
        if self.logger is not None:
            self.logger.debug("Exiting with code: {}...".format(code))
        exit(code)

    def _on_exit(self):
        """
        Used by the module atexit, called before the interpreter leave (normal or on exception).
        Execute some cleanup functions like clear the cached tempfiles.
        """
        if self.local_storage is not None:
            self.local_storage.clear_tempfiles()
        if self.logger is not None:
            self.logger.info("Bye.")
        if self.press_enter_to_finish:
            input("Press Enter to finish... ")
