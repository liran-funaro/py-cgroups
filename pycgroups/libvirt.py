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
from pycgroups import Cgroup

LIBVIRT_MACHINES_CGROUP = "machine/%s.libvirt-qemu"


def vm_cgroup_path(vm_name):
    """
    :param vm_name: A guest name
    :return: The cgroup path used for this guest by libvirt-qemu
    """
    return LIBVIRT_MACHINES_CGROUP % vm_name


def vm_tasks(vm_name):
    """
    Get a list of all the tasks that belongs to a guest
    :param vm_name: A guest name
    :return: A list of tasks
    """
    return LibvirtQemuCgroup(vm_name).hierarchy_tasks()


def vm_procs(vm_name):
    """
    Get a list of all the tasks that belongs to a guest
    :param vm_name: A guest name
    :return: A list of tasks
    """
    return LibvirtQemuCgroup(vm_name).hierarchy_procs()


class LibvirtQemuCgroup(Cgroup):
    """
    Cgroups for libvirt-qemu
    """
    def __init__(self, vm_name, subsystems=None):
        self.vm_name = vm_name
        path = vm_cgroup_path(vm_name)
        super().__init__(path, subsystems=subsystems, create=False)

    def add_tasks(self, *tasks):
        """ We don't want to add tasks to libvirt cgroup """
        raise NotImplementedError('Cannot add tasks to a virtual machine cgroup.')

    def add_procs(self, *tasks):
        """ We don't want to add processes to libvirt cgroup """
        raise NotImplementedError('Cannot add processes to a virtual machine cgroup.')

    @property
    def tasks(self):
        """ We want to have all the tasks that belongs to a VM """
        return super().hierarchy_tasks()

    @property
    def procs(self):
        """ We want to have all the processes that belongs to a VM """
        return super().hierarchy_procs()
