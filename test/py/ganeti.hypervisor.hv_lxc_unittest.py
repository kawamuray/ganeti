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
from ganeti import pathutils
from ganeti import utils

from ganeti.hypervisor import hv_lxc
from ganeti.hypervisor.hv_lxc import LXCHypervisor

import mock
import testutils

def RunCmdMock(object):
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

class TestLXCHypervisorCgroupMount(unittest.TestCase):
  def test(self):
    hv = LXCHypervisor()
    cgroup_root = pathutils.RUN_DIR + "/lxc/cgroup"
    self.assertEqual(hv._GetCgroupMountPoint(),
                     cgroup_root)
    cpuset_subdir = cgroup_root + "/cpuset"
    self.assertEqual(hv._MountCgroupSubsystem('cpuset'),
                     cpuset_subdir)
    self.assertTrue(os.path.ismount(cpuset_subdir))
    self.assertIn(('cpuset', cpuset_subdir, 'cgroup'),
                  (x[0:2] for x in utils.GetMounts()))

class TestLXCHypervisorGetInstanceInfo(unittest.TestCase):
  def setUp(self):
    self.orig__GetCgroupCpuList = hv_lxc.LXCHypervisor._GetCgroupCpuList
    hv_lxc.LXCHypervisor._GetCgroupCpuList = mock.Mock(return_value=[1])
    self.orig__GetCgroupMemoryLimit = hv_lxc.LXCHypervisor._GetCgroupMemoryLimit
    hv_lxc.LXCHypervisor._GetCgroupMemoryLimit = mock.Mock(return_value=128*(1024 ** 2))

  def tearDown(self):
    hv_lxc.LXCHypervisor._GetCgroupCpuList = self.orig__GetCgroupCpuList
    hv_lxc.LXCHypervisor._GetCgroupMemoryLimit = self.orig__GetCgroupMemoryLimit

  def testRunningInstance(self):
    hv = hv_lxc.LXCHypervisor(run_cmd_fn=RunCmdMock({
      'lxc-info': mock.Mock(return_value=testutils.ReadTestData('lxc-info-running.txt')),
    }))
    self.assertEqual(hv.GetInstanceInfo('foo'),
                     ('foo', 0, 128, 1, hv_base.HvInstanceState.RUNNING, 0))

  def testUnactiveOrNotExistInstance(self):
    hv = hv_lxc.LXCHypervisor(run_cmd_fn=RunCmdMock({
      'lxc-info': mock.Mock(return_value=testutils.ReadTestData('lxc-info-stopped.txt')),
    }))
    self.assertIsNone(hv.GetInstanceInfo('foo'))



class TestLXCHypervisorGetCgroupCpuList(unittest.TestCase):
  def setUp(self):
    self.orig_ReadFile = utils.ReadFile
    utils.ReadFile = mock.Mock(return_value=testutils.ReadTestData('cgroup-cpuset.cpus.txt'))

  def tearDown(self):
    utils.ReadFile = self.orig_ReadFile

  def test(self):
    pass # TODO

class TestLXCHypervisorGetCgroupCpuList(unittest.TestCase):
  def setUp(self):
    self.orig_ReadFile = utils.ReadFile
    utils.ReadFile = mock.Mock(return_value=testutils.ReadTestData('cgroup-cpuset.txt'))

  def tearDown(self):
    utils.ReadFile = self.orig_ReadFile

  def test(self):
    pass

if __name__ == "__main__":
  testutils.GanetiTestProgram()
