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

from datetime import date
import unittest

from pierky.ripeatlasmonitor.version import COPYRIGHT_YEAR

class MiscTestsUnit(unittest.TestCase):

    def copyright_year_test(self):
        """Copyright year"""
        self.assertEquals(COPYRIGHT_YEAR, date.today().year)

    def copyright_file_test(self):
        """Copyright year in COPYRIGHT file"""
        with open("COPYRIGHT", "r") as f:
            text = f.read()
        self.assertTrue("Copyright (C) {}".format(date.today().year) in text,
                        "Update the COPYRIGHT file and the copyright and "
                        "license statement at the start of every source file "
                        "by running the 'apply_copyright' bash script.")
