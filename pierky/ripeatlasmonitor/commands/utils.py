import os

from ..Config import Config


def edit_file(file_path, ask=None):
    # return True if user tries to edit the file
    if ask:
        try:
            answer = raw_input(ask)
        except KeyboardInterrupt:
            return False

        if answer.lower() != "yes":
            return False

    editor = os.environ.get("EDITOR", Config.get("misc.editor"))

    res = os.system("{} {}".format(editor, file_path))

    if res != 0:
        print("Error executing the default editor ({})".format(editor))

    return res == 0
