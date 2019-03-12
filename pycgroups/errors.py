"""
Author: Liran Funaro <liran.funaro@gmail.com>

Copyright (C) 2006-2018 Liran Funaro

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
from enum import Enum, auto


class CGroupsException(Exception):
    def __init__(self, obj, path, msg):
        self.obj = obj
        self.path = path
        super().__init__(msg)


class CGroupAccessViolation(CGroupsException):
    class Type(Enum):
        FAILED_WRITE = auto()

    def __init__(self, obj, error: Type, data):
        msg = f"Access violation: {data}."
        if error == self.Type.FAILED_WRITE:
            msg = f"Failed to write: {data}."

        super().__init__(obj, data, msg)


class CGroupLookupError(CGroupsException):
    class Type(Enum):
        FILE_INSTEAD_OF_GROUP = auto()
        GROUP_INSTEAD_OF_FILE = auto()
        LINK = auto()

        FILE_NOT_EXISTS = auto()
        GROUP_NOT_EXISTS = auto()
        NOT_EXISTS = auto()

        AMBIGUITY_FILE_OR_GROUP = auto()
        AMBIGUITY_MULTI_FILES = auto()

    def __init__(self, obj, error: Type, path):
        msg = f"Lookup error on {path}."

        if error == self.Type.FILE_INSTEAD_OF_GROUP:
            msg = f"Requested a group, but {path} is a file."
        elif error == self.Type.GROUP_INSTEAD_OF_FILE:
            msg = f"Requested a file, but {path} is a group."
        elif error == self.Type.LINK:
            msg = f"Cannot operate on a link: {path}."
        elif error == self.Type.FILE_NOT_EXISTS:
            msg = f"Requested a file {path} does not exist."
        elif error == self.Type.GROUP_NOT_EXISTS:
            msg = f"Requested a group {path} does not exist."
        elif error == self.Type.NOT_EXISTS:
            msg = f"Could not find a file/folder with this name: {path}."
        elif error == self.Type.AMBIGUITY_FILE_OR_GROUP:
            raise ValueError(f"Ambiguity: the same name given to files and groups: {path}.")
        elif error == self.Type.AMBIGUITY_MULTI_FILES:
            raise ValueError(f"Ambiguity: more than one subsystem have the file: {path}.")
        super().__init__(obj, path, msg)
