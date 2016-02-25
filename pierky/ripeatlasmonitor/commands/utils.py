# Copyright (C) 2016 Pier Carlo Chiodi
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from six.moves import input
import os

from ..Config import Config


def edit_file(file_path, ask=None):
    # return True if user tries to edit the file
    if ask:
        try:
            answer = input(ask)
        except KeyboardInterrupt:
            return False

        if answer.lower() != "yes":
            return False

    editor = os.environ.get("EDITOR", Config.get("misc.editor"))

    res = os.system("{} {}".format(editor, file_path))

    if res != 0:
        print("Error executing the default editor ({})".format(editor))

    return res == 0
