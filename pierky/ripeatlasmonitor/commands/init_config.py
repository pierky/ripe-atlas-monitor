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

import os
from six.moves import input

from .utils import edit_file
from ..Config import Config
from ..Errors import GlobalConfigError


def execute(args):
    file_path = args.cfg_file

    print("Initializing {}".format(file_path))

    if os.path.isfile(file_path):
        edit_file(
            file_path, ask="The global configuration file {} "
                           "already exists. Do you want to edit it now? "
                           "[yes/NO] ".format(file_path)
        )
        return

    dir_name = os.path.dirname(file_path)

    if not os.path.exists(dir_name):
        try:
            answer = input(
                "Directory {} does not exist. Do you want to "
                "create it now? [yes/NO] ".format(dir_name)
            )
        except KeyboardInterrupt:
            return

        if answer.lower() != "yes":
            return

        try:
            os.makedirs(dir_name)
        except Exception as e:
            raise GlobalConfigError(
                "Error while creating the global config directory "
                "{}: {}".format(dir_name, e)
            )

    try:
        answer = input(
            "The global configuration file will be created in {}: "
            "do you want to proceed? [yes/NO] ".format(file_path)
        )
    except KeyboardInterrupt:
        return

    if answer.lower() == "yes":
        Config.init_file(file_path)

        edit_file(file_path, ask="Global configuration file created. "
                  "Do you want to edit it now? [yes/NO] ")
