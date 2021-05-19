"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
"""


class Config:
    def __init__(
        self,
        module_folder_path,
        app_folder_path,
        config_folder_path,
        system_tempfolder_path,
    ):
        """
        :param module_folder_path pathlib.Path: parent folder where the module is stored.
        :param app_folder_path pathlib.Path: parent folder where the file is executed.
        :param config_folder_path pathlib.Path: parent folder where the config file is store.
        :param system_tempfolder_path pathlib.Path: system temporary folder.
        """
        # local folder where the files/folders will be copy from and to
        self.local_folder_path = config_folder_path / "source_folder"
        # remote folder path where the manifest and the 'files' folder will be stored.
        self.remote_folder_path = "/remote/folder"
        # local folder where the manifest file will be saved
        self.local_manifest_folder_path = config_folder_path
        # folder where temporary files will be allocated, suggestion to use the system's folder
        self.temp_folder_path = system_tempfolder_path
        # debug settings
        # folder and file name where to save log messages, has a limit of 100kb
        self.log_file_path = config_folder_path / "log_file.txt"
        # decide if it should print debug messages on stream/prompt
        self.print_debug_flag = True
        # disable all non important debug messages, attribute missing is equal to True
        self.fulldebug_flag = False
        # give a extense format on messages: "[%(processName)s|%(threadName)s][%(asctime)s][%(levelname)s]\n%(message)s"
        self.format_debug_flag = True
        # include debug messages on file
        self.save_debug_to_file_flag = False
        # gdrive stuff settings
        # client secret is supplied by gdrive API, check for more info: https://developers.google.com/drive/api/v3/enable-drive-api
        self.gdrive_secret_file_path = module_folder_path / "client_secret.json"
        # save gdrive token or request oauth2 authorization for every use
        self.gdrive_save_token_flag = True
        # this is where your authentication cookie will be saved, avoiding it to request authorization every time you run.
        self.gdrive_token_folder_path = config_folder_path
        # compression settings
        # compression level, 0.0 to 1.0 and we'll convert into appropriate level for the protocol
        self.compression_ratio = 1.0
        # encryption settings
        # decide if we save a salted hashed (secure) version of your password on local, otherwise ask for it every use.
        self.encryption_save_salted_password_flag = True
        # where to save your salted password hash
        self.encryption_salted_folder_path = config_folder_path

    def filter_function(self, node_path):
        """
        This function is made to able to filter files or folders. It receives a pathlib.Path and
        should analize and return True to allow or False to ignore/hide it from the system scan.
        """
        return True
