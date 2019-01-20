"""
Author: Liran Funaro <funaro@cs.technion.ac.il>

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
import os
import pathlib
from typing import Union, Iterable, Optional

from cgroup.errors import CGroupLookupError, CGroupAccessViolation

CGROUP_PATH = "/sys/fs/cgroup"
TASKS_FILE_NAME = "tasks"
PROCS_FILE_NAME = "cgroup.procs"
TASK_CGROUP_LIST = "/proc/%s/cgroup"

TYPING_LOOKUP = Union[str, Iterable, None]


###########################################################################
# Subsystems lookup
###########################################################################

def subsystem_path(subsystem: str, *path: str):
    """
    Generate a path to a subsystem sub path

    Parameters
    ----------
    subsystem: str
        The subsystem name.
    path: str
        The sub path.

    Returns
    -------
    str
        A path of a subsystem.
    """
    return os.path.join(CGROUP_PATH, subsystem, *path)


def iter_subsystems(lookup_subsystems: TYPING_LOOKUP = None, include_aliases: bool = False):
    """
    Traverse all the available subsystems on this machine.

    Parameters
    ----------
    lookup_subsystems: str, iterable, optional
        The subsystem(s) to lookup.
    include_aliases: bool
        If True, will yield subsystem aliases (soft link).

    Yields
    -------
    str
        Subsystem names.
    """
    if isinstance(lookup_subsystems, str):
        lookup_subsystems = {lookup_subsystems}
    elif lookup_subsystems is not None:
        lookup_subsystems = set(lookup_subsystems)

    for s in os.listdir(CGROUP_PATH):
        path = subsystem_path(s)
        if not os.path.isdir(path):
            continue
        if not include_aliases and os.path.islink(path):
            continue
        if lookup_subsystems is not None and s not in lookup_subsystems:
            continue
        yield s


def iter_subsystem_path(*path: str, lookup_subsystems: TYPING_LOOKUP = None, include_aliases: bool = False):
    """
    Traverse all the available subsystem paths on this machine.

    Parameters
    ----------
    lookup_subsystems: str, iterable, optional
        The subsystem(s) to lookup.
    include_aliases: bool
        If True, will yield subsystem aliases (soft link).

    Yields
    -------
    str
        Subsystem paths.
    """
    for s in iter_subsystems(lookup_subsystems, include_aliases):
        yield subsystem_path(s, *path)


def validate_subsystem_path(subsystem: str, *path: str, create: bool = False):
    """
    Validate a subsystem path is valid, and create the path if required.

    Parameters
    ----------
    subsystem: str
        A cgroup subsystem name.
    path: str
        A path in the subsystem.
    create: bool
        Creates the path if does not exists.

    Returns
    -------
    str
        The path if it exists, otherwise raise an exception.

    Raises
    ------
    CGroupLookupError
        If the path leads to a file or the folder does not exists.
    """
    sub_path = subsystem_path(subsystem, *path)
    if os.path.isfile(sub_path):
        raise CGroupLookupError(None, CGroupLookupError.Type.FILE_INSTEAD_OF_FOLDER, sub_path)
    elif not os.path.isdir(sub_path):
        if not create:
            raise CGroupLookupError(None, CGroupLookupError.Type.GROUP_NOT_EXISTS, sub_path)

        os.makedirs(sub_path, exist_ok=True)

    # Fix bug in cpuset (might be solved using cgroup.clone_children)
    if subsystem == 'cpuset':
        init_cgroup_settings_from_parents(subsystem, *path,
                                          file_list=['cpuset.mems', 'cpuset.cpus'])

    return sub_path


def supported_subsystems_path(*path: str, lookup_subsystems: TYPING_LOOKUP = None, create: bool = False):
    """
    Return a list of subsystem that have a specific path.

    Parameters
    ----------
    path: str
        A path in the subsystem.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.
    create: bool
        Creates the path if does not exists.

    Returns
    -------
    set of str
        A set of subsystem that have the required path.
    """
    supported = set()

    for s in iter_subsystems(lookup_subsystems):
        try:
            validate_subsystem_path(s, *path, create=create)
            supported.add(s)
        except CGroupLookupError:
            pass

    return supported


###########################################################################
# Cgroup lookup
###########################################################################

def cgroups_content(subsystem: str, *path: str):
    """
    The content of a cgroup.

    Parameters
    ----------
    subsystem: str
        The subsystem to check.
    path: str
        The path to check.

    Returns
    -------
    tuple:
        - list of the names of all the sub cgroups of this cgroup
        - list of the files supported by the cgroup
    """
    full_path = subsystem_path(subsystem, *path)
    path, dirs, files = next(os.walk(full_path))
    return dirs, files


def sub_cgroups(subsystem: str, *path: str):
    """
    The sub cgroups in a cgroup.

    Parameters
    ----------
    subsystem: str
        The subsystem to check.
    path: str
        The path to check.

    Returns
    -------
    list
        A list of the names of all the sub cgroups in this cgroup.
    """
    return cgroups_content(subsystem, *path)[0]


def cgroup_files(subsystem: str, *path: str):
    """
    The supported files in a cgroup.

    Parameters
    ----------
    subsystem: str
        The subsystem to check.
    path: str
        The path to check.

    Returns
    -------
    list
        A list of the files supported by this cgroup.
    """
    return cgroups_content(subsystem, *path)[1]


def subsystems_sub_cgroups(*path: str, lookup_subsystems: TYPING_LOOKUP = None):
    """
    Find the subsystems that support each sub-cgroup of a specific path.

    Parameters
    ----------
    path: str
        The path to check.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.

    Returns
    -------
    dict
       The names of all the sub cgroups of this cgroup with a set of subsystems that includes them.
    """
    ret = {}
    for s in iter_subsystems(lookup_subsystems):
        for sub_path in sub_cgroups(s, *path):
            if sub_path in ret:
                ret[sub_path].add(s)
            else:
                ret[sub_path] = {s}
    return ret


def interpret_cgroup_path(*path: str, lookup_subsystems: TYPING_LOOKUP = None):
    """
    Interpret if a cgroup path is a file/directory or not exist in any of the sub-systems.

    Parameters
    ----------
    path: str
        The path to check.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.

    Returns
    -------
    tuple
        For simplicity, two elements are always returned.
        "file", the path to the file in a specific subsystem
                (only if it exclusive to one subsystem)
        "dir", a list of subsystems that have this folder (cgroup)
        None, None (if it does not exists)

    Raises
    ------
    CGroupLookupError
        If there is ambiguity.
    """
    subsystems = list(iter_subsystems(lookup_subsystems))
    paths = [subsystem_path(s, *path) for s in subsystems]

    is_file = [os.path.isfile(p) for p in paths]
    is_file_count = is_file.count(True)

    is_dir = [os.path.isdir(p) for p in paths]
    is_dir_count = is_dir.count(True)

    # First, lets detect if there is ambiguity
    full_path = os.path.join(*path)
    if is_dir_count > 0 and is_file_count > 0:
        raise CGroupLookupError(None, CGroupLookupError.Type.AMBIGUITY_FILE_OR_GROUP, full_path)
    if is_file_count > 1:
        raise CGroupLookupError(None, CGroupLookupError.Type.AMBIGUITY_MULTI_FILES, full_path)

    if is_file_count == 1:
        i = is_file.index(True)
        return "file", paths[i]

    # At this point, we know that it is not a file

    if is_dir_count > 0:
        include_subsystems = {s for s, d in zip(subsystems, is_dir) if d}
        return "dir", include_subsystems

    return None, None


###########################################################################
# Tasks and Processes
###########################################################################

def _normalize_process_id(proc_id: Union[str, int]):
    """
    Normalize a process/task ID to string.

    Parameters
    ----------
    proc_id: str, int
        A process/task ID.

    Returns
    -------
    str
        The process ID as a string.

    Raises
    ------
    ValueError
        If the ID is not a string or an integer.
    """
    if isinstance(proc_id, str):
        return proc_id
    elif isinstance(proc_id, int):
        return str(proc_id)
    else:
        raise ValueError(f"Process/task ID must be an integer or a string, but got {type(proc_id)} instead.")


def _normalize_process_id_list(proc_ids: Union[str, int, Iterable[str], Iterable[int]]):
    """
    Normalize the process/task ID to a list/tuple of strings.

    Parameters
    ----------
    proc_ids: str, int, Iterable of str, Iterable of int
        A process/task ID or an iterable of these.

    Returns
    -------
    list, tuple
        Of process/tasks IDs.
    """
    try:
        return _normalize_process_id(proc_ids),
    except ValueError:
        return [_normalize_process_id(i) for i in proc_ids]


def _cgroup_procs(fname: str, subsystem: str, *path: str):
    """
    Traverse the process/tasks of a cgroup.

    Parameters
    ----------
    fname: str
        The file name to read from (tasks or procs).
    subsystem: str
        The subsystem to check.
    path: str
        The path to check.

    Yields
    ------
    str
        Process/task ID.
    """
    file_path = subsystem_path(subsystem, *path, fname)
    with open(file_path, "r") as f:
        proc_lines = f.readlines()

    for p in proc_lines:
        yield p.strip()


def _add_procs(fname: str, subsystem: str, proc_ids: Union[str, int, Iterable[str], Iterable[int]], *path: str):
    """
    Add process/task IDs to subsystem path.

    Parameters
    ----------
    fname: str
        The file name to read from (tasks or procs).
    subsystem: str
        The subsystem to check.
    proc_ids: str, int, Iterable of str, Iterable of int
        A process/task ID or an iterable of these.
    path: str
        The path to check.
    """
    file_path = subsystem_path(subsystem, *path, fname)
    for p in _normalize_process_id_list(proc_ids):
        with open(file_path, "w") as f:
            f.write(f"{p}\n")


def _subsystems_add_procs(fname: str, proc_ids: Union[str, int, Iterable[str], Iterable[int]], *path: str,
                          lookup_subsystems: TYPING_LOOKUP = None):
    """
    Add process/task IDs to all subsystems path.

    Parameters
    ----------
    fname: str
        The file name to read from (tasks or procs).
    proc_ids: str, int, Iterable of str, Iterable of int
        A process/task ID or an iterable of these.
    path: str
        The path to check.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.

    Raises
    ------
    CGroupAccessViolation
        If Failed to add processes/tasks.
    """
    failed = {}
    for s in iter_subsystems(lookup_subsystems):
        try:
            _add_procs(fname, s, proc_ids, *path)
        except Exception as e:
            failed[s] = str(e)

    if failed:
        raise CGroupAccessViolation(None, CGroupAccessViolation.Type.FAILED_WRITE, failed)


def _subsystems_cgroup_procs_intersection(fname: str, *path: str, lookup_subsystems: TYPING_LOOKUP = None):
    """
    Intersection of the processes/tasks that belong to this path in all subsystem

    Parameters
    ----------
    fname: str
        The file name to read from (tasks or procs).
    path: str
        The path to check.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.

    Returns
    -------
    set
        Process/task IDs.

    See Also
    --------
    _cgroup_procs : For more information.
    """
    ret = set()
    for s in iter_subsystems(lookup_subsystems):
        ret.intersection_update(_cgroup_procs(fname, s, *path))
    return ret


def task_cgroups(task: Union[str, int]):
    """
    Get the cgroups of the task in all the subsystems.

    Parameters
    ----------
    task: str
        A task ID.

    Returns
    -------
    dict
        All the cgroups this tasks belongs to in all the subsystems:
            {
                'path1': set('subsystem1', 'subsystem2'),
                'path2': set('subsystem1'),
                ...
            }
    """
    proc_path = TASK_CGROUP_LIST % _normalize_process_id(task)
    with open(proc_path, "r") as f:
        data = f.readlines()

    res = {}
    for l in data:
        _, subsystem, path = l.strip().split(":")
        subsystem = subsystem.lstrip('name=')
        path = path.lstrip(os.path.sep)
        if path in res:
            res[path].add(subsystem)
        else:
            res[path] = {subsystem}

    return res


def cgroup_tasks(subsystem: str, *path: str):
    """
    Traverse the tasks of a cgroup.

    Parameters
    ----------
    subsystem: str
        The subsystem to check.
    path: str
        The path to check.

    Yields
    ------
    str
        Task ID.

    See Also
    --------
    _cgroup_procs : For more information.
    """
    yield from _cgroup_procs(TASKS_FILE_NAME, subsystem, *path)


def cgroup_procs(subsystem: str, *path: str):
    """
    Traverse the processes of a cgroup.

    Parameters
    ----------
    subsystem: str
        The subsystem to check.
    path: str
        The path to check.

    Yields
    ------
    str
        Process ID.

    See Also
    --------
    _cgroup_procs : For more information.
    """
    yield from _cgroup_procs(PROCS_FILE_NAME, subsystem, *path)


def add_tasks(subsystem: str, task_ids: Union[str, int, Iterable[str], Iterable[int]], *path: str):
    """
    Add task IDs to subsystem path.

    Parameters
    ----------
    subsystem: str
        The subsystem to check.
    task_ids: str, int, Iterable of str, Iterable of int
        A task ID or an iterable of these.
    path: str
        The path to check.

    See Also
    --------
    _add_procs : For more information.
    """
    _add_procs(TASKS_FILE_NAME, subsystem, task_ids, *path)


def add_procs(subsystem: str, proc_ids: Union[str, int, Iterable[str], Iterable[int]], *path: str):
    """
    Add process IDs to subsystem path.

    Parameters
    ----------
    subsystem: str
        The subsystem to check.
    proc_ids: str, int, Iterable of str, Iterable of int
        A process ID or an iterable of these.
    path: str
        The path to check.

    See Also
    --------
    _add_procs : For more information.
    """
    _add_procs(PROCS_FILE_NAME, subsystem, proc_ids, *path)


def subsystems_add_tasks(task_ids: Union[str, int, Iterable[str], Iterable[int]], *path: str,
                         lookup_subsystems: TYPING_LOOKUP = None):
    """
    Add task IDs to all subsystems path.

    Parameters
    ----------
    task_ids: str, int, Iterable of str, Iterable of int
        A task ID or an iterable of these.
    path: str
        The path to check.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.

    Raises
    ------
    CGroupAccessViolation
        If Failed to add tasks.

    See Also
    --------
    _subsystems_add_procs : For more information.
    """
    _subsystems_add_procs(TASKS_FILE_NAME, task_ids, *path, lookup_subsystems=lookup_subsystems)


def subsystems_add_procs(proc_ids: Union[str, int, Iterable[str], Iterable[int]], *path: str,
                         lookup_subsystems: TYPING_LOOKUP = None):
    """
    Add process IDs to all subsystems path.

    Parameters
    ----------
    proc_ids: str, int, Iterable of str, Iterable of int
        A process ID or an iterable of these.
    path: str
        The path to check.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.

    Raises
    ------
    CGroupAccessViolation
        If Failed to add processes.

    See Also
    --------
    _subsystems_add_procs : For more information.
    """
    _subsystems_add_procs(PROCS_FILE_NAME, proc_ids, *path, lookup_subsystems=lookup_subsystems)


def subsystems_cgroup_tasks(*path: str, lookup_subsystems: TYPING_LOOKUP = None):
    """
    Intersection of the tasks that belong to this path in all subsystem

    Parameters
    ----------
    path: str
        The path to check.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.

    Returns
    -------
    set
        Task IDs.

    See Also
    --------
    _cgroup_procs : For more information.
    _subsystems_cgroup_procs_intersection : For more information.
    """
    return _subsystems_cgroup_procs_intersection(TASKS_FILE_NAME, *path, lookup_subsystems=lookup_subsystems)


def subsystems_cgroup_procs(*path: str, lookup_subsystems: TYPING_LOOKUP = None):
    """
    Intersection of the processes that belong to this path in all subsystem

    Parameters
    ----------
    path: str
        The path to check.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.

    Returns
    -------
    set
        Process IDs.

    See Also
    --------
    _cgroup_procs : For more information.
    _subsystems_cgroup_procs_intersection : For more information.
    """
    return _subsystems_cgroup_procs_intersection(PROCS_FILE_NAME, *path, lookup_subsystems=lookup_subsystems)


###########################################################################
# Cleanup
###########################################################################

def delete_cgroup(subsystem: str, *path: str):
    """
    Delete a cgroup.

    Parameters
    ----------
    subsystem: str
        The subsystem to use.
    path: str
        The path to delete.

    Raises
    ------
    CGroupLookupError
        If fail to delete (if it is not empty for example).
        Will also try to remove its parents if they are empty.
    """
    cgroup_path = subsystem_path(subsystem, *path)
    if os.path.isfile(cgroup_path):
        raise CGroupLookupError(None, CGroupLookupError.Type.FILE_INSTEAD_OF_GROUP, cgroup_path)
    if os.path.islink(cgroup_path):
        raise CGroupLookupError(None, CGroupLookupError.Type.LINK, cgroup_path)
    if not os.path.exists(cgroup_path):
        raise CGroupLookupError(None, CGroupLookupError.Type.NOT_EXISTS, cgroup_path)

    os.removedirs(cgroup_path)


def subsystems_delete_cgroup(*path: str, lookup_subsystems: TYPING_LOOKUP = None):
    """
    Delete a cgroup in all the subsystems.

    Parameters
    ----------
    path: str
        The path to delete.
    lookup_subsystems: str, Iterable, optional
        A list of cgroup subsystem names to lookup.

    Returns
    -------
    dict
        Failed deletes and reasons.
    """
    failed = {}
    for s in iter_subsystems(lookup_subsystems):
        try:
            delete_cgroup(s, *path)
        except Exception as e:
            failed[s] = str(e)

    return failed


###########################################################################
# Default
###########################################################################


def init_cgroup_default(subsystem: str, *path: str, default_data: Optional[dict] = None):
    """
    Init the cgroup to default data if no data is set.

    Parameters
    ----------
    subsystem: str
        The subsystem to init.
    path: str
        The path to init.
    default_data: dict, optional
        For each file, its default data.

    Returns
    -------
    dict
        The data of the specified default after the init.

    Raises
    ------
    CGroupLookupError
        If the specified file does not exist or is not a file.
    """
    if not default_data:
        default_data = {}
    output_data = {}

    for file_name, data in default_data.items():
        full_path = subsystem_path(subsystem, *path, file_name)
        if os.path.isdir(full_path):
            raise CGroupLookupError(None, CGroupLookupError.Type.GROUP_INSTEAD_OF_FILE, full_path)
        if not os.path.exists(full_path):
            raise CGroupLookupError(None, CGroupLookupError.Type.NOT_EXISTS, full_path)

        with open(full_path, "r") as fp:
            current_data = fp.read().strip()

        if current_data is not None and current_data != "":
            output_data[file_name] = current_data
        else:
            with open(full_path, "w") as fp:
                fp.write(f"{data}\n")
            output_data[file_name] = data

    return output_data


def init_cgroup_settings_from_parents(subsystem: str, *path: str, file_list: Optional[Iterable] = None):
    """
    Init the settings of a cgroup by its parents.
    Used to fix a bug in cpuset.

    Parameters
    ----------
    subsystem: str
        The subsystem to init.
    path: str
        The path to init.
    file_list:
    The file list to init.

    Raises
    ------
    ValueError
        If could not inherit the data from the subsystem's root path.

    See Also
    --------
    init_cgroup_default : For more information.
    """
    if file_list is None:
        file_list = cgroup_files(subsystem, *path)

    files_data = init_cgroup_default(subsystem, default_data={name: None for name in file_list})
    for n, d in files_data.items():
        if d is None:
            raise ValueError(f"No data is set for file {n} in {subsystem}'s root path.")

    path_list = pathlib.Path(*path).parts
    for i in range(1, len(path_list) + 1):
        files_data = init_cgroup_default(subsystem, *path_list[:i], default_data=files_data)
