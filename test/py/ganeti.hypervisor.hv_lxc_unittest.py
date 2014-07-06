#!/usr/bin/python
#

# Copyright (C) 2011 Google Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.


"""Script for testing ganeti.hypervisor.hv_lxc"""

import unittest

from ganeti import constants
from ganeti import objects
from ganeti import hypervisor
from ganeti import utils

from ganeti.hypervisor import hv_base
from ganeti.hypervisor import hv_lxc
from ganeti.hypervisor.hv_lxc import LXCHypervisor

import mock
import os
import shutil
import tempfile
import testutils
import types

def setUpModule():
  # Creating instance of LXCHypervisor will fail by permission issue of
  # instance directories
  temp_dir = tempfile.mkdtemp()
  LXCHypervisor._ROOT_DIR = utils.PathJoin(temp_dir, "root")
  LXCHypervisor._LOG_DIR = utils.PathJoin(temp_dir, "log")

def tearDownModule():
  shutil.rmtree(LXCHypervisor._LOG_DIR)

class RunCmdMock(object):
  def __init__(self, hook_commands):
    self.hook_commands = hook_commands

  def __call__(self, cmd):
    if cmd[0] in self.hook_commands:
      return self.hook_commands[cmd[0]](cmd)
    else:
      return utils.RunCmd(cmd)

class TestConsole(unittest.TestCase):
  def test(self):
    instance = objects.Instance(name="lxc.example.com",
                                primary_node="node199-uuid")
    node = objects.Node(name="node199", uuid="node199-uuid",
                        ndparams={})
    group = objects.NodeGroup(name="group991", ndparams={})
    cons = hv_lxc.LXCHypervisor.GetInstanceConsole(instance, node, group,
                                                   {}, {})
    self.assertEqual(cons.Validate(), None)
    self.assertEqual(cons.kind, constants.CONS_SSH)
    self.assertEqual(cons.host, node.name)
    self.assertEqual(cons.command[-1], instance.name)

class TestLXCHypervisorGetInstanceInfo(unittest.TestCase):
  def setUp(self):
    self.orig_RunCmd = utils.RunCmd
    self.orig__GetCgroupCpuList = LXCHypervisor._GetCgroupCpuList
    LXCHypervisor._GetCgroupCpuList = mock.Mock(return_value=[1])
    self.orig__GetCgroupMemoryLimit = LXCHypervisor._GetCgroupMemoryLimit
    LXCHypervisor._GetCgroupMemoryLimit = mock.Mock(return_value=128*(1024**2))
    self.hv = LXCHypervisor()

  def tearDown(self):
    utils.RunCmd = self.orig_RunCmd
    LXCHypervisor._GetCgroupCpuList = self.orig__GetCgroupCpuList
    LXCHypervisor._GetCgroupMemoryLimit = self.orig__GetCgroupMemoryLimit

  def testRunningInstance(self):
    output = testutils.ReadTestData("lxc-info-running.txt")
    result = utils.RunResult(0, None, output, "", [], None, None)
    utils.RunCmd = RunCmdMock({"lxc-info": mock.Mock(return_value=result)})
    self.assertEqual(self.hv.GetInstanceInfo("foo"),
                     ("foo", 0, 128, 1, hv_base.HvInstanceState.RUNNING, 0))

  def testUnactiveOrNotExistInstance(self):
    output = testutils.ReadTestData("lxc-info-stopped.txt")
    result = utils.RunResult(0, None, output, "", [], None, None)
    utils.RunCmd = RunCmdMock({"lxc-info": mock.Mock(return_value=result)})
    self.assertIsNone(self.hv.GetInstanceInfo("foo"))

class TestCgroupMount(unittest.TestCase):
  def setUp(self):
    self.orig_utils_GetMounts = utils.GetMounts
    mounts = [
      ("/dev/foo", "/foo", "foo", "cpuset"),
      ("cpuset", "/sys/fs/cgroup/cpuset", "cgroup", "rw,relatime,cpuset"),
      ("devices", "/sys/fs/cgroup/devices", "cgroup", "rw,devices,relatime"),
      ("cpumem", "/sys/fs/cgroup/cpumem", "cgroup", "cpu,memory,rw,relatime"),
      ]
    utils.GetMounts = mock.Mock(return_value=mounts)
    self.orig__MountCgroupSubsystem = LXCHypervisor._MountCgroupSubsystem
    LXCHypervisor._MountCgroupSubsystem = mock.Mock(return_value="/foo")

  def tearDown(self):
    utils.GetMounts = self.orig_utils_GetMounts
    LXCHypervisor._MountCgroupSubsystem = self.orig__MountCgroupSubsystem

  def test_GetOrPrepareCgroupSubsysMountPoint(self):
    hv = LXCHypervisor()
    self.assertEqual(hv._GetOrPrepareCgroupSubsysMountPoint("cpuset"),
                     "/sys/fs/cgroup/cpuset")
    self.assertEqual(hv._GetOrPrepareCgroupSubsysMountPoint("devices"),
                     "/sys/fs/cgroup/devices")
    self.assertEqual(hv._GetOrPrepareCgroupSubsysMountPoint("cpu"),
                     "/sys/fs/cgroup/cpumem")
    self.assertEqual(hv._GetOrPrepareCgroupSubsysMountPoint("memory"),
                     "/sys/fs/cgroup/cpumem")
    self.assertEqual(hv._GetOrPrepareCgroupSubsysMountPoint("freezer"),
                     "/foo")
    LXCHypervisor._MountCgroupSubsystem.assert_called_with("freezer")

class TestCgroupReadData(unittest.TestCase):
  def setUp(self):
    self.orig__CGROUP_ROOT_DIR = LXCHypervisor._CGROUP_ROOT_DIR
    self.cgroup_root = testutils.TestDataFilename("cgroup_root")
    self.cgroup_root = os.path.abspath(self.cgroup_root)
    LXCHypervisor._CGROUP_ROOT_DIR = self.cgroup_root

    self.orig__PROC_SELF_CGROUP_FILE = LXCHypervisor._PROC_SELF_CGROUP_FILE
    LXCHypervisor._PROC_SELF_CGROUP_FILE = testutils.TestDataFilename(
      "proc_cgroup.txt")

    orig = LXCHypervisor._GetOrPrepareCgroupSubsysMountPoint
    self.orig__GetOrPrepareCgroupSubsysMountPoint = orig
    dummy = types.MethodType(lambda _, x: utils.PathJoin(self.cgroup_root, x),
                             LXCHypervisor)
    LXCHypervisor._GetOrPrepareCgroupSubsysMountPoint = dummy

    self.hv = LXCHypervisor()

  def tearDown(self):
    LXCHypervisor._CGROUP_ROOT_DIR = self.orig__CGROUP_ROOT_DIR
    LXCHypervisor._PROC_SELF_CGROUP_FILE = self.orig__PROC_SELF_CGROUP_FILE
    orig = self.orig__GetOrPrepareCgroupSubsysMountPoint
    LXCHypervisor._GetOrPrepareCgroupSubsysMountPoint = orig

  def test_GetCgroupMountPoint(self):
    self.assertEqual(self.hv._GetCgroupMountPoint(), self.cgroup_root)

  def test_GetCurrentCgroupSubsysGroups(self):
    expected_groups = {
      "memory": "", # root
      "cpuset": "some_group",
      "devices": "some_group",
      }
    self.assertEqual(self.hv._GetCurrentCgroupSubsysGroups(), expected_groups)

  def test_GetCgroupInstanceSubsysDir(self):
    self.assertEqual(self.hv._GetCgroupInstanceSubsysDir("instance1", "memory"),
                     utils.PathJoin(self.cgroup_root, "memory", "lxc",
                                    "instance1"))
    self.assertEqual(self.hv._GetCgroupInstanceSubsysDir("instance1", "cpuset"),
                     utils.PathJoin(self.cgroup_root, "cpuset", "some_group",
                                    "lxc", "instance1"))
    self.assertEqual(self.hv._GetCgroupInstanceSubsysDir("instance1",
                                                         "devices"),
                     utils.PathJoin(self.cgroup_root, "devices", "some_group",
                                    "lxc", "instance1"))

  def test_GetCgroupInstanceValue(self):
    self.assertEqual(self.hv._GetCgroupInstanceValue("instance1", "memory",
                                                     "memory.limit_in_bytes"),
                     "128")
    self.assertEqual(self.hv._GetCgroupInstanceValue("instance1", "cpuset",
                                                     "cpuset.cpus"),
                     "0-1")
    self.assertEqual(self.hv._GetCgroupInstanceValue("instance1", "devices",
                                                     "devices.list"),
                     "a *:* rwm")

  def test_GetCgroupCpuList(self):
    self.assertEqual(self.hv._GetCgroupCpuList("instance1"), [0, 1])

  def test_GetCgroupMemoryLimit(self):
    self.assertEqual(self.hv._GetCgroupMemoryLimit("instance1"), 128)

    # return 0 if could not read the file
    orig_method = LXCHypervisor._GetCgroupInstanceValue
    LXCHypervisor._GetCgroupInstanceValue = mock.Mock(
      side_effect=EnvironmentError)
    self.assertEqual(self.hv._GetCgroupMemoryLimit("instance1"), 0)
    LXCHypervisor._GetCgroupInstanceValue = orig_method

if __name__ == "__main__":
  testutils.GanetiTestProgram()
