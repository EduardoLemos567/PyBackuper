#!/usr/bin/python3
"""
:license:
    license is described in the LICENSE file provided.
    A copy can be accessed in: https://github.com/EduardoLemos567/PyBackuper/blob/master/LICENSE
:author:
    Eduardo Lemos de Moraes
:description:
    Used to install the required packages.
"""
import subprocess
import sys

packages = [
    "oscrypto",
    "google-api-python-client",
    "google-auth-httplib2",
    "google-auth-oauthlib",
]  # used only for future UI: , "pywebview"]


def start():
    try:
        for name in packages:
            install_package(name)
            print("")
    finally:
        input("Press Enter to finish...")


def install_package(name):
    blank = "-" * 40
    print("Trying to install now: {name}...".format(name=name))
    print(blank)
    subprocess.check_call([sys.executable, "-m", "pip", "install", name])
    print(blank)
    print("{name} is installed.".format(name=name))


if __name__ == "__main__":
    start()
