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
import getpass
import warnings

from cgroup import path as cp


class Cgroup:
    """
    Manage cgroup subsystems using dict like semantics

    Usage Examples
    ===========================================================================
    >>> Cgroup('cpu', 'system/daemon')['cpu.shares'] = 10
    >>> Cgroup('cpu', 'system', 'daemon')['cpu.shares'] = 10
    >>> Cgroup('cpu/system/daemon')['cpu.shares'] = 10

    >>> c = Cgroup('system/daemon')
    >>> c['subgroup1', 'cpu.shares'] = 10
    >>> c.subsystem('cpu')['subgroup1', 'cpu.shares'] = 10

    >>> current_shares = c['subgroup2', 'cpu.shares']

    >>> c3 = c['subgroup3']
    >>> known_tasks = c3.tasks
    >>> my_tasks = '1234', '5678', '9012'
    >>> c3.add_tasks(*my_tasks)
    >>> c3['cpu.shares'] = 100

    # Will add the tasks to all the subsystems under that path
    >>> Cgroup('system/daemon').add_tasks(*my_tasks)

    # Will add the tasks to cpu and memory subsystems under that path
    >>> Cgroup('system/daemon', subsystems=['cpu', 'memory']).add_tasks(*my_tasks)
    """

    def __init__(self, *path, subsystems=None, create=False):
        """
        :param path: The sub path in the subsystem
        """
        self.subsystems = set(cp.iter_subsystems(subsystems))

        self.path_parts = pathlib.Path(*path).parts
        # First argument of the path might be the subsystem
        if len(self.path_parts) > 0 and self.path_parts[0] in self.subsystems:
            self.subsystems = {self.path_parts[0]}
            self.path_parts = self.path_parts[1:]

        ret = cp.supported_subsystems_path(*self.path_parts, lookup_subsystems=self.subsystems, create=create)
        if subsystems is not None:
            missing = self.subsystems.difference(ret)
            if missing:
                raise ValueError(f"The path does not exist in all the required subsystems. Missing: {missing}.")
        else:
            self.subsystems = set(ret)

    ###########################################################################
    # Permissions
    ###########################################################################

    def fix_permissions(self, user_name, group_name=None):
        """
        Change the permissions of all the subsystem to a specified username and group.
        Will run as root using "sudo". The current user must have "sudo" permissions without password.
        :param user_name: The user name to change to
        :param group_name: (Optional) A group name
        :return: None
        """
        cp.fix_permissions(*self.path_parts, lookup_subsystems=self.subsystems, user_name=user_name,
                           group_name=group_name)

    def fix_permissions_current_user(self, group_name=None):
        """
        Fix permissions for script's user
        :param group_name: (Optional) A group name
        :return: The script's username
        """
        user_name = getpass.getuser()
        self.fix_permissions(user_name, group_name)
        return user_name

    ###########################################################################
    # Lookup
    ###########################################################################

    @property
    def path(self):
        """ Return the full path of the cgroup as string """
        if self.is_root:
            return os.path.sep
        else:
            return os.path.join(*self.path_parts)

    @property
    def is_root(self):
        """ Return if the current cgroup is the root """
        return not self.path_parts

    @property
    def root(self):
        """
        :return: A new instance of this class for the root subsystem path
        """
        return Cgroup(subsystems=self.subsystems)

    @property
    def back(self):
        """
        :return: A new instance of this class for the parent cgroup
        """
        if self.is_root:
            raise ValueError("Cannot go back. Already in the root of the subsystem.")

        return Cgroup(*self.path_parts[:-1],
                      subsystems=self.subsystems)

    def subsystem(self, *subsystems, **kwargs):
        """
        Operate over a specific subsystem(s)
        :param subsystems: The subsystem(s) to operate on
        :return: A new instance of this class for this subsystem(s)
        """
        create = kwargs.get("create", False)

        return Cgroup(*self.path_parts,
                      subsystems=subsystems,
                      create=create)

    def sub_cgroup(self, *sub_path, **kwargs):
        """
        Retrieve sub cgroup
        :param sub_path: A sub-path of the current subsystem path
        :param kwargs:
            subsystems: Can specific specific subsystems
            create: Can specify to create the sub path if not exists
        :return: A new instance of this class for the new path
        """
        subsystems = kwargs.get("subsystems", self.subsystems)
        create = kwargs.get("create", False)

        return Cgroup(*self.path_parts, *sub_path,
                      subsystems=subsystems,
                      create=create)

    def create_sub_cgroup(self, *sub_path, **kwargs):
        """
        Retrieve and create sub cgroup.
        See sub_cgroup().
        """
        kwargs["create"] = True
        return self.sub_cgroup(*sub_path, **kwargs)

    def sub_cgroups(self, **kwargs):
        """
        :return: A list of instances of all the sub cgroups of this cgroup
        """
        subsystems = kwargs.get("subsystems", self.subsystems)
        create = kwargs.get("create", False)

        groups = cp.subsystems_sub_cgroups(*self.path_parts, lookup_subsystems=subsystems)

        for d, s in groups.items():
            yield self.sub_cgroup(d, subsystems=s, create=create)

    ###########################################################################
    # Tasks and Processes
    ###########################################################################

    @classmethod
    def task_cgroups(cls, task):
        """
        Iterate over the cgroups of a task
        :param task: A task ID
        :return: An iterator over cgroup object for the cgroup of the task
        """
        for d, s in cp.task_cgroups(task).items():
            yield Cgroup(d, subsystems=s, create=False)

    @property
    def tasks(self):
        """
        :return: A list of the tasks assigned to this cgroup folder
        """
        return cp.subsystems_cgroup_tasks(*self.path_parts, lookup_subsystems=self.subsystems)

    @property
    def procs(self):
        """
        :return: A list of the processes (Tgid) assigned to this cgroup folder
        """
        return cp.subsystems_cgroup_procs(*self.path_parts, lookup_subsystems=self.subsystems)

    def add_tasks(self, *tasks):
        """
        Add tasks to this cgroup folder
        :param tasks: A list of tasks to add
        :return: None
        """
        cp.subsystems_add_tasks(tasks, *self.path_parts, lookup_subsystems=self.subsystems)

    def add_procs(self, *procs):
        """
        Add processes (Tgid) to this cgroup folder
        :param procs: A list of tasks to add
        :return: None
        """
        cp.subsystems_add_procs(procs, *self.path_parts, lookup_subsystems=self.subsystems)

    def hierarchy_tasks(self):
        """
        :return: All the tasks in the cgroup and all its sub cgroups
        """
        task_set = set(self.tasks)

        for c in self.sub_cgroups():
            task_set.update(c.hierarchy_tasks())

        return task_set

    def hierarchy_procs(self):
        """
        :return: All the processes in the cgroup and all its sub cgroups
        """
        proc_set = set(self.procs)

        for c in self.sub_cgroups():
            proc_set.update(c.hierarchy_procs())

        return proc_set

    ###########################################################################
    # Cleanup
    ###########################################################################

    def clear_tasks(self, recursive=False):
        """
        Remove all the tasks from the cgroup.
        Will move all the tasks to the parent cgroup.
        :param recursive: If True, will remove the tasks of all the sub-cgroups as well
        :return: None
        """
        if self.is_root:
            raise ValueError("Cannot clear tasks of root cgroup.")
        if recursive:
            tasks_to_move = self.hierarchy_tasks()
        else:
            tasks_to_move = self.tasks
        try:
            self.root.add_tasks(*tasks_to_move)
        except Exception as e:
            warnings.warn(f"Failed to clear tasks: {e}.", RuntimeWarning)

    def delete(self, recursive=False):
        """
        Delete a cgroup. Only works if the cgroup is empty (no tasks and subgroups).
        Will change the current subsystems to the once who still have the subgroup.
         I.e., failed to delete.
        :param recursive: If True, will first delete all the sub cgroups
        :return: None
        """
        if self.is_root:
            raise ValueError("Cannot remove the root cgroup.")
        if recursive:
            for c in self.sub_cgroups():
                c.delete(recursive=True)

        failed_subsystems = cp.subsystems_delete_cgroup(*self.path_parts,
                                                        lookup_subsystems=self.subsystems)
        if failed_subsystems:
            warnings.warn(f"Cannot delete {self.path_parts} on subsystems: {failed_subsystems}.", RuntimeWarning)
        self.subsystems = set(failed_subsystems.keys())

    def clear_and_delete(self, recursive=False):
        """
        Clear and delete the cgroup.
        :param recursive: If True, will first clear and delete all the sub-cgroups
        :return: None
        """
        self.clear_tasks(recursive=recursive)
        self.delete(recursive=recursive)

    ###########################################################################
    # dict-like API
    ###########################################################################

    def get(self, key, default_value=None, create=False):
        """
        Get a sub cgroup or a content of a file in this cgroup folder
        :param key: The name of the file/folder
        :param default_value: Return if not file or directory exits with that name
        :param create: Create a sub-group if not file or sub-group exits
        :return: If the name is a folder, will return a sub-cgroup instance,
            If the name is a file, it will read its content
            Otherwise will return the default value
        """
        if self.is_root and key in self.subsystems:
            return self.subsystem(key)

        if type(key) not in (tuple, list):
            key = (key,)

        path_type, extra_data = cp.interpret_cgroup_path(*self.path_parts, *key,
                                                         lookup_subsystems=self.subsystems)
        # If a file, read it
        if path_type == "file":
            with open(extra_data, "r") as f:
                return f.read().strip()
        # If create is True, then no need to check if the sub-groups exits
        elif create:
            return self.sub_cgroup(key, create=True)
        # If some sub-groups exists, use them
        elif path_type == "dir":
            return self.sub_cgroup(key, subsystems=extra_data)
        else:
            return default_value

    def put(self, key, value):
        """
        Write a content to a cgroup file. If the key is not a file, will raise an exception
        :param key: The file name
        :param value: The content to append
        :return: None
        """
        if type(key) not in (tuple, list):
            key = (key,)

        path_type, extra_data = cp.interpret_cgroup_path(*self.path_parts, *key,
                                                         lookup_subsystems=self.subsystems)
        if path_type is 'dir':
            raise ValueError("Cannot write to a cgroup folder")
        if path_type is None:
            raise ValueError("File does not exist")

        # Now we know it is a file
        with open(extra_data, "w") as f:
            return f.write("%s\n" % value)

    def __getitem__(self, key):
        """ Wrapper for get(). Raise an exception if not found. """
        default_ret = {}
        ret = self.get(key, default_ret)
        if ret is default_ret:
            raise ValueError("No subsystem, sub-group or file with that name.")
        return ret

    def __setitem__(self, key, value):
        """ Wrapper for put(). """
        return self.put(key, value)

    def __delitem__(self, key):
        """ Delete a sub cgroup """
        if type(key) not in (tuple, list):
            key = (key,)

        path_type, extra_data = cp.interpret_cgroup_path(*self.path_parts, *key,
                                                         lookup_subsystems=self.subsystems)
        if path_type is 'file':
            raise ValueError("Cannot delete a cgroup file")
        if path_type is None:
            raise ValueError("Sub cgroup does not exist")

        # Now we know it is a folder
        return self.sub_cgroup(key).delete()
