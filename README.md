# PyBackuper


Tutorial em português: [LEIAME.md](https://github.com/EduardoLemos567/PyBackuper/blob/master/LEIAME.md "ass")

## Tutorial:

#### 1. Read the license file and only proceed if you agree.

#### 2. Create a "client secret" API key:
This is used to identify your copy of app on the Google's OAuth system
so they can grant you access Google Drive API calls.

 The reason is simple: google made it very hard and complicated to share
API application keys, even for free software. I may not have time 
and i dont wanna be responsable to manage this application credentials 
with Google.

 So instead you are creating your own application credentials leaving 
yourself responsable for sharing or not, these credentials. (I recommend you do not share)
1. Follow the both tutorials from: https://developers.google.com/workspace/guides/create-project
 - On the "Enable a Google Workspace API" part, step 5, instead of "Gmail API" choose "Drive API".
2. Now follow this one https://developers.google.com/workspace/guides/create-credentials
 - On step 6, if internal is not avaliable, you can use external. (It wont really be external without you sending the application for approval, and its not needed to send, no worries.)
 - On step 10, you only need to add one scope: "https://www.googleapis.com/auth/drive" (This only allow modifying files created using the application, any other file on your drive cant be touched.)
3. Now follow the "Create a OAuth client ID credential" part.
 - On step 5, choose "Create Desktop application credentials".
##### Save the .json file somewhere accessible for our application.

#### 3. Create your project folder, copy the file "config_example.py" into it:
Change these lines:
- self.local_folder_path: path to the folder you want to backup.
- self.remote_folder_path: remote path to the folder in the Google Drive to save the backup.
- self.gdrive_secret_file_path: local where you saved the .json file from the previous step (1.).

#### 4. Create a simple script to run our application:
(Modify some fields)
```python
#!/usr/bin/python3
    import sys

    sys.path.insert(1, "path/to/our/application/backuper")  # or install at site-packages folder
    import backuper.app as app
    import backuper.gdriveremotestorage as gdriveremotestorage

    if __name__ == "__main__":
            app = app.App(config_file_path="path/to/config.py")
            app.setup(gdriveremotestorage.GDriveRemoteStorage)
            app.push() # push, pull, sync or clear
```
#### Notes:
 - **push**: send local files into remote folder, clear remote files not on local.
 - **pull**: receive remote files into local folder, clear local files not on remote.
 - **clear**: erase everything at your remote folder (only the one defined in the config.py).
 - **sync**: realize a pull or a push deppending on local/remote state of files.

Beware, to use sync you need to follow these steps:
- Start your folder with either a pull or a push.
- Remember to update with either pull/push/sync everytime you finished your "work",
   otherwise the application wont handle the conflict and the next you use the sync,
   if you have updated the remote with another work (more recent maybe?), sync will
   decide that the "changed" state means "new" and will overwrite your remote work.
   To avoid this, you can pull or push, before to fix it.