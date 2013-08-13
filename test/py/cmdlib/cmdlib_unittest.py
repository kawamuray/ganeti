#!/usr/bin/python
#

# Copyright (C) 2008, 2011, 2012, 2013 Google Inc.
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


"""Script for unittesting the cmdlib module"""


import unittest
import operator
import itertools
import copy

from ganeti import constants
from ganeti import mcpu
from ganeti import cmdlib
from ganeti.cmdlib import cluster
from ganeti.cmdlib import group
from ganeti.cmdlib import instance
from ganeti.cmdlib import instance_storage
from ganeti.cmdlib import instance_utils
from ganeti.cmdlib import common
from ganeti.cmdlib import query
from ganeti import opcodes
from ganeti import errors
from ganeti import utils
from ganeti import luxi
from ganeti import ht
from ganeti import objects
from ganeti import compat
from ganeti import rpc
from ganeti import locking
from ganeti.masterd import iallocator

import testutils
import mocks


class TestOpcodeParams(testutils.GanetiTestCase):
  def testParamsStructures(self):
    for op in sorted(mcpu.Processor.DISPATCH_TABLE):
      lu = mcpu.Processor.DISPATCH_TABLE[op]
      lu_name = lu.__name__
      self.failIf(hasattr(lu, "_OP_REQP"),
                  msg=("LU '%s' has old-style _OP_REQP" % lu_name))
      self.failIf(hasattr(lu, "_OP_DEFS"),
                  msg=("LU '%s' has old-style _OP_DEFS" % lu_name))
      self.failIf(hasattr(lu, "_OP_PARAMS"),
                  msg=("LU '%s' has old-style _OP_PARAMS" % lu_name))


class TestIAllocatorChecks(testutils.GanetiTestCase):
  def testFunction(self):
    class TestLU(object):
      def __init__(self, opcode):
        self.cfg = mocks.FakeConfig()
        self.op = opcode

    class OpTest(opcodes.OpCode):
       OP_PARAMS = [
        ("iallocator", None, ht.TAny, None),
        ("node", None, ht.TAny, None),
        ]

    default_iallocator = mocks.FakeConfig().GetDefaultIAllocator()
    other_iallocator = default_iallocator + "_not"

    op = OpTest()
    lu = TestLU(op)

    c_i = lambda: common.CheckIAllocatorOrNode(lu, "iallocator", "node")

    # Neither node nor iallocator given
    for n in (None, []):
      op.iallocator = None
      op.node = n
      c_i()
      self.assertEqual(lu.op.iallocator, default_iallocator)
      self.assertEqual(lu.op.node, n)

    # Both, iallocator and node given
    for a in ("test", constants.DEFAULT_IALLOCATOR_SHORTCUT):
      op.iallocator = a
      op.node = "test"
      self.assertRaises(errors.OpPrereqError, c_i)

    # Only iallocator given
    for n in (None, []):
      op.iallocator = other_iallocator
      op.node = n
      c_i()
      self.assertEqual(lu.op.iallocator, other_iallocator)
      self.assertEqual(lu.op.node, n)

    # Only node given
    op.iallocator = None
    op.node = "node"
    c_i()
    self.assertEqual(lu.op.iallocator, None)
    self.assertEqual(lu.op.node, "node")

    # Asked for default iallocator, no node given
    op.iallocator = constants.DEFAULT_IALLOCATOR_SHORTCUT
    op.node = None
    c_i()
    self.assertEqual(lu.op.iallocator, default_iallocator)
    self.assertEqual(lu.op.node, None)

    # No node, iallocator or default iallocator
    op.iallocator = None
    op.node = None
    lu.cfg.GetDefaultIAllocator = lambda: None
    self.assertRaises(errors.OpPrereqError, c_i)


class TestLUTestJqueue(unittest.TestCase):
  def test(self):
    self.assert_(cmdlib.LUTestJqueue._CLIENT_CONNECT_TIMEOUT <
                 (luxi.WFJC_TIMEOUT * 0.75),
                 msg=("Client timeout too high, might not notice bugs"
                      " in WaitForJobChange"))


class TestLUQuery(unittest.TestCase):
  def test(self):
    self.assertEqual(sorted(query._QUERY_IMPL.keys()),
                     sorted(constants.QR_VIA_OP))

    assert constants.QR_NODE in constants.QR_VIA_OP
    assert constants.QR_INSTANCE in constants.QR_VIA_OP

    for i in constants.QR_VIA_OP:
      self.assert_(query._GetQueryImplementation(i))

    self.assertRaises(errors.OpPrereqError, query._GetQueryImplementation,
                      "")
    self.assertRaises(errors.OpPrereqError, query._GetQueryImplementation,
                      "xyz")


class _FakeLU:
  def __init__(self, cfg=NotImplemented, proc=NotImplemented,
               rpc=NotImplemented):
    self.warning_log = []
    self.info_log = []
    self.cfg = cfg
    self.proc = proc
    self.rpc = rpc

  def LogWarning(self, text, *args):
    self.warning_log.append((text, args))

  def LogInfo(self, text, *args):
    self.info_log.append((text, args))


class TestLoadNodeEvacResult(unittest.TestCase):
  def testSuccess(self):
    for moved in [[], [
      ("inst20153.example.com", "grp2", ["nodeA4509", "nodeB2912"]),
      ]]:
      for early_release in [False, True]:
        for use_nodes in [False, True]:
          jobs = [
            [opcodes.OpInstanceReplaceDisks().__getstate__()],
            [opcodes.OpInstanceMigrate().__getstate__()],
            ]

          alloc_result = (moved, [], jobs)
          assert iallocator._NEVAC_RESULT(alloc_result)

          lu = _FakeLU()
          result = common.LoadNodeEvacResult(lu, alloc_result,
                                             early_release, use_nodes)

          if moved:
            (_, (info_args, )) = lu.info_log.pop(0)
            for (instname, instgroup, instnodes) in moved:
              self.assertTrue(instname in info_args)
              if use_nodes:
                for i in instnodes:
                  self.assertTrue(i in info_args)
              else:
                self.assertTrue(instgroup in info_args)

          self.assertFalse(lu.info_log)
          self.assertFalse(lu.warning_log)

          for op in itertools.chain(*result):
            if hasattr(op.__class__, "early_release"):
              self.assertEqual(op.early_release, early_release)
            else:
              self.assertFalse(hasattr(op, "early_release"))

  def testFailed(self):
    alloc_result = ([], [
      ("inst5191.example.com", "errormsg21178"),
      ], [])
    assert iallocator._NEVAC_RESULT(alloc_result)

    lu = _FakeLU()
    self.assertRaises(errors.OpExecError, common.LoadNodeEvacResult,
                      lu, alloc_result, False, False)
    self.assertFalse(lu.info_log)
    (_, (args, )) = lu.warning_log.pop(0)
    self.assertTrue("inst5191.example.com" in args)
    self.assertTrue("errormsg21178" in args)
    self.assertFalse(lu.warning_log)


class TestUpdateAndVerifySubDict(unittest.TestCase):
  def setUp(self):
    self.type_check = {
        "a": constants.VTYPE_INT,
        "b": constants.VTYPE_STRING,
        "c": constants.VTYPE_BOOL,
        "d": constants.VTYPE_STRING,
        }

  def test(self):
    old_test = {
      "foo": {
        "d": "blubb",
        "a": 321,
        },
      "baz": {
        "a": 678,
        "b": "678",
        "c": True,
        },
      }
    test = {
      "foo": {
        "a": 123,
        "b": "123",
        "c": True,
        },
      "bar": {
        "a": 321,
        "b": "321",
        "c": False,
        },
      }

    mv = {
      "foo": {
        "a": 123,
        "b": "123",
        "c": True,
        "d": "blubb"
        },
      "bar": {
        "a": 321,
        "b": "321",
        "c": False,
        },
      "baz": {
        "a": 678,
        "b": "678",
        "c": True,
        },
      }

    verified = common._UpdateAndVerifySubDict(old_test, test, self.type_check)
    self.assertEqual(verified, mv)

  def testWrong(self):
    test = {
      "foo": {
        "a": "blubb",
        "b": "123",
        "c": True,
        },
      "bar": {
        "a": 321,
        "b": "321",
        "c": False,
        },
      }

    self.assertRaises(errors.TypeEnforcementError,
                      common._UpdateAndVerifySubDict, {}, test,
                      self.type_check)


class TestHvStateHelper(unittest.TestCase):
  def testWithoutOpData(self):
    self.assertEqual(common.MergeAndVerifyHvState(None, NotImplemented),
                     None)

  def testWithoutOldData(self):
    new = {
      constants.HT_XEN_PVM: {
        constants.HVST_MEMORY_TOTAL: 4096,
        },
      }
    self.assertEqual(common.MergeAndVerifyHvState(new, None), new)

  def testWithWrongHv(self):
    new = {
      "i-dont-exist": {
        constants.HVST_MEMORY_TOTAL: 4096,
        },
      }
    self.assertRaises(errors.OpPrereqError, common.MergeAndVerifyHvState,
                      new, None)

class TestDiskStateHelper(unittest.TestCase):
  def testWithoutOpData(self):
    self.assertEqual(common.MergeAndVerifyDiskState(None, NotImplemented),
                     None)

  def testWithoutOldData(self):
    new = {
      constants.LD_LV: {
        "xenvg": {
          constants.DS_DISK_RESERVED: 1024,
          },
        },
      }
    self.assertEqual(common.MergeAndVerifyDiskState(new, None), new)

  def testWithWrongStorageType(self):
    new = {
      "i-dont-exist": {
        "xenvg": {
          constants.DS_DISK_RESERVED: 1024,
          },
        },
      }
    self.assertRaises(errors.OpPrereqError, common.MergeAndVerifyDiskState,
                      new, None)


class TestComputeMinMaxSpec(unittest.TestCase):
  def setUp(self):
    self.ispecs = {
      constants.ISPECS_MAX: {
        constants.ISPEC_MEM_SIZE: 512,
        constants.ISPEC_DISK_SIZE: 1024,
        },
      constants.ISPECS_MIN: {
        constants.ISPEC_MEM_SIZE: 128,
        constants.ISPEC_DISK_COUNT: 1,
        },
      }

  def testNoneValue(self):
    self.assertTrue(common._ComputeMinMaxSpec(constants.ISPEC_MEM_SIZE, None,
                                              self.ispecs, None) is None)

  def testAutoValue(self):
    self.assertTrue(common._ComputeMinMaxSpec(constants.ISPEC_MEM_SIZE, None,
                                              self.ispecs,
                                              constants.VALUE_AUTO) is None)

  def testNotDefined(self):
    self.assertTrue(common._ComputeMinMaxSpec(constants.ISPEC_NIC_COUNT, None,
                                              self.ispecs, 3) is None)

  def testNoMinDefined(self):
    self.assertTrue(common._ComputeMinMaxSpec(constants.ISPEC_DISK_SIZE, None,
                                              self.ispecs, 128) is None)

  def testNoMaxDefined(self):
    self.assertTrue(common._ComputeMinMaxSpec(constants.ISPEC_DISK_COUNT,
                                              None, self.ispecs, 16) is None)

  def testOutOfRange(self):
    for (name, val) in ((constants.ISPEC_MEM_SIZE, 64),
                        (constants.ISPEC_MEM_SIZE, 768),
                        (constants.ISPEC_DISK_SIZE, 4096),
                        (constants.ISPEC_DISK_COUNT, 0)):
      min_v = self.ispecs[constants.ISPECS_MIN].get(name, val)
      max_v = self.ispecs[constants.ISPECS_MAX].get(name, val)
      self.assertEqual(common._ComputeMinMaxSpec(name, None,
                                                 self.ispecs, val),
                       "%s value %s is not in range [%s, %s]" %
                       (name, val,min_v, max_v))
      self.assertEqual(common._ComputeMinMaxSpec(name, "1",
                                                 self.ispecs, val),
                       "%s/1 value %s is not in range [%s, %s]" %
                       (name, val,min_v, max_v))

  def test(self):
    for (name, val) in ((constants.ISPEC_MEM_SIZE, 256),
                        (constants.ISPEC_MEM_SIZE, 128),
                        (constants.ISPEC_MEM_SIZE, 512),
                        (constants.ISPEC_DISK_SIZE, 1024),
                        (constants.ISPEC_DISK_SIZE, 0),
                        (constants.ISPEC_DISK_COUNT, 1),
                        (constants.ISPEC_DISK_COUNT, 5)):
      self.assertTrue(common._ComputeMinMaxSpec(name, None, self.ispecs, val)
                      is None)


def _ValidateComputeMinMaxSpec(name, *_):
  assert name in constants.ISPECS_PARAMETERS
  return None


def _NoDiskComputeMinMaxSpec(name, *_):
  if name == constants.ISPEC_DISK_COUNT:
    return name
  else:
    return None


class _SpecWrapper:
  def __init__(self, spec):
    self.spec = spec

  def ComputeMinMaxSpec(self, *args):
    return self.spec.pop(0)


class TestComputeIPolicySpecViolation(unittest.TestCase):
  # Minimal policy accepted by _ComputeIPolicySpecViolation()
  _MICRO_IPOL = {
    constants.IPOLICY_DTS: [constants.DT_PLAIN, constants.DT_DISKLESS],
    constants.ISPECS_MINMAX: [NotImplemented],
    }

  def test(self):
    compute_fn = _ValidateComputeMinMaxSpec
    ret = common.ComputeIPolicySpecViolation(self._MICRO_IPOL, 1024, 1, 1, 1,
                                             [1024], 1, constants.DT_PLAIN,
                                             _compute_fn=compute_fn)
    self.assertEqual(ret, [])

  def testDiskFull(self):
    compute_fn = _NoDiskComputeMinMaxSpec
    ret = common.ComputeIPolicySpecViolation(self._MICRO_IPOL, 1024, 1, 1, 1,
                                             [1024], 1, constants.DT_PLAIN,
                                             _compute_fn=compute_fn)
    self.assertEqual(ret, [constants.ISPEC_DISK_COUNT])

  def testDiskLess(self):
    compute_fn = _NoDiskComputeMinMaxSpec
    ret = common.ComputeIPolicySpecViolation(self._MICRO_IPOL, 1024, 1, 1, 1,
                                             [1024], 1, constants.DT_DISKLESS,
                                             _compute_fn=compute_fn)
    self.assertEqual(ret, [])

  def testWrongTemplates(self):
    compute_fn = _ValidateComputeMinMaxSpec
    ret = common.ComputeIPolicySpecViolation(self._MICRO_IPOL, 1024, 1, 1, 1,
                                             [1024], 1, constants.DT_DRBD8,
                                             _compute_fn=compute_fn)
    self.assertEqual(len(ret), 1)
    self.assertTrue("Disk template" in ret[0])

  def testInvalidArguments(self):
    self.assertRaises(AssertionError, common.ComputeIPolicySpecViolation,
                      self._MICRO_IPOL, 1024, 1, 1, 1, [], 1,
                      constants.DT_PLAIN,)

  def testInvalidSpec(self):
    spec = _SpecWrapper([None, False, "foo", None, "bar", None])
    compute_fn = spec.ComputeMinMaxSpec
    ret = common.ComputeIPolicySpecViolation(self._MICRO_IPOL, 1024, 1, 1, 1,
                                             [1024], 1, constants.DT_PLAIN,
                                             _compute_fn=compute_fn)
    self.assertEqual(ret, ["foo", "bar"])
    self.assertFalse(spec.spec)

  def testWithIPolicy(self):
    mem_size = 2048
    cpu_count = 2
    disk_count = 1
    disk_sizes = [512]
    nic_count = 1
    spindle_use = 4
    disk_template = "mytemplate"
    ispec = {
      constants.ISPEC_MEM_SIZE: mem_size,
      constants.ISPEC_CPU_COUNT: cpu_count,
      constants.ISPEC_DISK_COUNT: disk_count,
      constants.ISPEC_DISK_SIZE: disk_sizes[0],
      constants.ISPEC_NIC_COUNT: nic_count,
      constants.ISPEC_SPINDLE_USE: spindle_use,
      }
    ipolicy1 = {
      constants.ISPECS_MINMAX: [{
        constants.ISPECS_MIN: ispec,
        constants.ISPECS_MAX: ispec,
        }],
      constants.IPOLICY_DTS: [disk_template],
      }
    ispec_copy = copy.deepcopy(ispec)
    ipolicy2 = {
      constants.ISPECS_MINMAX: [
        {
          constants.ISPECS_MIN: ispec_copy,
          constants.ISPECS_MAX: ispec_copy,
          },
        {
          constants.ISPECS_MIN: ispec,
          constants.ISPECS_MAX: ispec,
          },
        ],
      constants.IPOLICY_DTS: [disk_template],
      }
    ipolicy3 = {
      constants.ISPECS_MINMAX: [
        {
          constants.ISPECS_MIN: ispec,
          constants.ISPECS_MAX: ispec,
          },
        {
          constants.ISPECS_MIN: ispec_copy,
          constants.ISPECS_MAX: ispec_copy,
          },
        ],
      constants.IPOLICY_DTS: [disk_template],
      }
    def AssertComputeViolation(ipolicy, violations):
      ret = common.ComputeIPolicySpecViolation(ipolicy, mem_size, cpu_count,
                                               disk_count, nic_count,
                                               disk_sizes, spindle_use,
                                               disk_template)
      self.assertEqual(len(ret), violations)

    AssertComputeViolation(ipolicy1, 0)
    AssertComputeViolation(ipolicy2, 0)
    AssertComputeViolation(ipolicy3, 0)
    for par in constants.ISPECS_PARAMETERS:
      ispec[par] += 1
      AssertComputeViolation(ipolicy1, 1)
      AssertComputeViolation(ipolicy2, 0)
      AssertComputeViolation(ipolicy3, 0)
      ispec[par] -= 2
      AssertComputeViolation(ipolicy1, 1)
      AssertComputeViolation(ipolicy2, 0)
      AssertComputeViolation(ipolicy3, 0)
      ispec[par] += 1 # Restore
    ipolicy1[constants.IPOLICY_DTS] = ["another_template"]
    AssertComputeViolation(ipolicy1, 1)


class _StubComputeIPolicySpecViolation:
  def __init__(self, mem_size, cpu_count, disk_count, nic_count, disk_sizes,
               spindle_use, disk_template):
    self.mem_size = mem_size
    self.cpu_count = cpu_count
    self.disk_count = disk_count
    self.nic_count = nic_count
    self.disk_sizes = disk_sizes
    self.spindle_use = spindle_use
    self.disk_template = disk_template

  def __call__(self, _, mem_size, cpu_count, disk_count, nic_count, disk_sizes,
               spindle_use, disk_template):
    assert self.mem_size == mem_size
    assert self.cpu_count == cpu_count
    assert self.disk_count == disk_count
    assert self.nic_count == nic_count
    assert self.disk_sizes == disk_sizes
    assert self.spindle_use == spindle_use
    assert self.disk_template == disk_template

    return []


class _FakeConfigForComputeIPolicyInstanceViolation:
  def __init__(self, be, excl_stor):
    self.cluster = objects.Cluster(beparams={"default": be})
    self.excl_stor = excl_stor

  def GetClusterInfo(self):
    return self.cluster

  def GetNodeInfo(self, _):
    return {}

  def GetNdParams(self, _):
    return {
      constants.ND_EXCLUSIVE_STORAGE: self.excl_stor,
      }


class TestComputeIPolicyInstanceViolation(unittest.TestCase):
  def test(self):
    beparams = {
      constants.BE_MAXMEM: 2048,
      constants.BE_VCPUS: 2,
      constants.BE_SPINDLE_USE: 4,
      }
    disks = [objects.Disk(size=512, spindles=13)]
    cfg = _FakeConfigForComputeIPolicyInstanceViolation(beparams, False)
    instance = objects.Instance(beparams=beparams, disks=disks, nics=[],
                                disk_template=constants.DT_PLAIN)
    stub = _StubComputeIPolicySpecViolation(2048, 2, 1, 0, [512], 4,
                                            constants.DT_PLAIN)
    ret = common.ComputeIPolicyInstanceViolation(NotImplemented, instance,
                                                 cfg, _compute_fn=stub)
    self.assertEqual(ret, [])
    instance2 = objects.Instance(beparams={}, disks=disks, nics=[],
                                 disk_template=constants.DT_PLAIN)
    ret = common.ComputeIPolicyInstanceViolation(NotImplemented, instance2,
                                                 cfg, _compute_fn=stub)
    self.assertEqual(ret, [])
    cfg_es = _FakeConfigForComputeIPolicyInstanceViolation(beparams, True)
    stub_es = _StubComputeIPolicySpecViolation(2048, 2, 1, 0, [512], 13,
                                               constants.DT_PLAIN)
    ret = common.ComputeIPolicyInstanceViolation(NotImplemented, instance,
                                                 cfg_es, _compute_fn=stub_es)
    self.assertEqual(ret, [])
    ret = common.ComputeIPolicyInstanceViolation(NotImplemented, instance2,
                                                 cfg_es, _compute_fn=stub_es)
    self.assertEqual(ret, [])


class TestComputeIPolicyInstanceSpecViolation(unittest.TestCase):
  def test(self):
    ispec = {
      constants.ISPEC_MEM_SIZE: 2048,
      constants.ISPEC_CPU_COUNT: 2,
      constants.ISPEC_DISK_COUNT: 1,
      constants.ISPEC_DISK_SIZE: [512],
      constants.ISPEC_NIC_COUNT: 0,
      constants.ISPEC_SPINDLE_USE: 1,
      }
    stub = _StubComputeIPolicySpecViolation(2048, 2, 1, 0, [512], 1,
                                            constants.DT_PLAIN)
    ret = instance._ComputeIPolicyInstanceSpecViolation(NotImplemented, ispec,
                                                        constants.DT_PLAIN,
                                                        _compute_fn=stub)
    self.assertEqual(ret, [])


class _CallRecorder:
  def __init__(self, return_value=None):
    self.called = False
    self.return_value = return_value

  def __call__(self, *args):
    self.called = True
    return self.return_value


class TestComputeIPolicyNodeViolation(unittest.TestCase):
  def setUp(self):
    self.recorder = _CallRecorder(return_value=[])

  def testSameGroup(self):
    ret = instance_utils._ComputeIPolicyNodeViolation(
      NotImplemented,
      NotImplemented,
      "foo", "foo", NotImplemented,
      _compute_fn=self.recorder)
    self.assertFalse(self.recorder.called)
    self.assertEqual(ret, [])

  def testDifferentGroup(self):
    ret = instance_utils._ComputeIPolicyNodeViolation(
      NotImplemented,
      NotImplemented,
      "foo", "bar", NotImplemented,
      _compute_fn=self.recorder)
    self.assertTrue(self.recorder.called)
    self.assertEqual(ret, [])


class _FakeConfigForTargetNodeIPolicy:
  def __init__(self, node_info=NotImplemented):
    self._node_info = node_info

  def GetNodeInfo(self, _):
    return self._node_info


class TestCheckTargetNodeIPolicy(unittest.TestCase):
  def setUp(self):
    self.instance = objects.Instance(primary_node="blubb")
    self.target_node = objects.Node(group="bar")
    node_info = objects.Node(group="foo")
    fake_cfg = _FakeConfigForTargetNodeIPolicy(node_info=node_info)
    self.lu = _FakeLU(cfg=fake_cfg)

  def testNoViolation(self):
    compute_recoder = _CallRecorder(return_value=[])
    instance.CheckTargetNodeIPolicy(self.lu, NotImplemented, self.instance,
                                    self.target_node, NotImplemented,
                                    _compute_fn=compute_recoder)
    self.assertTrue(compute_recoder.called)
    self.assertEqual(self.lu.warning_log, [])

  def testNoIgnore(self):
    compute_recoder = _CallRecorder(return_value=["mem_size not in range"])
    self.assertRaises(errors.OpPrereqError, instance.CheckTargetNodeIPolicy,
                      self.lu, NotImplemented, self.instance,
                      self.target_node, NotImplemented,
                      _compute_fn=compute_recoder)
    self.assertTrue(compute_recoder.called)
    self.assertEqual(self.lu.warning_log, [])

  def testIgnoreViolation(self):
    compute_recoder = _CallRecorder(return_value=["mem_size not in range"])
    instance.CheckTargetNodeIPolicy(self.lu, NotImplemented, self.instance,
                                     self.target_node, NotImplemented,
                                     ignore=True, _compute_fn=compute_recoder)
    self.assertTrue(compute_recoder.called)
    msg = ("Instance does not meet target node group's (bar) instance policy:"
           " mem_size not in range")
    self.assertEqual(self.lu.warning_log, [(msg, ())])


class TestApplyContainerMods(unittest.TestCase):
  def testEmptyContainer(self):
    container = []
    chgdesc = []
    instance._ApplyContainerMods("test", container, chgdesc, [], None, None,
                                None)
    self.assertEqual(container, [])
    self.assertEqual(chgdesc, [])

  def testAdd(self):
    container = []
    chgdesc = []
    mods = instance._PrepareContainerMods([
      (constants.DDM_ADD, -1, "Hello"),
      (constants.DDM_ADD, -1, "World"),
      (constants.DDM_ADD, 0, "Start"),
      (constants.DDM_ADD, -1, "End"),
      ], None)
    instance._ApplyContainerMods("test", container, chgdesc, mods,
                                None, None, None)
    self.assertEqual(container, ["Start", "Hello", "World", "End"])
    self.assertEqual(chgdesc, [])

    mods = instance._PrepareContainerMods([
      (constants.DDM_ADD, 0, "zero"),
      (constants.DDM_ADD, 3, "Added"),
      (constants.DDM_ADD, 5, "four"),
      (constants.DDM_ADD, 7, "xyz"),
      ], None)
    instance._ApplyContainerMods("test", container, chgdesc, mods,
                                None, None, None)
    self.assertEqual(container,
                     ["zero", "Start", "Hello", "Added", "World", "four",
                      "End", "xyz"])
    self.assertEqual(chgdesc, [])

    for idx in [-2, len(container) + 1]:
      mods = instance._PrepareContainerMods([
        (constants.DDM_ADD, idx, "error"),
        ], None)
      self.assertRaises(IndexError, instance._ApplyContainerMods,
                        "test", container, None, mods, None, None, None)

  def testRemoveError(self):
    for idx in [0, 1, 2, 100, -1, -4]:
      mods = instance._PrepareContainerMods([
        (constants.DDM_REMOVE, idx, None),
        ], None)
      self.assertRaises(IndexError, instance._ApplyContainerMods,
                        "test", [], None, mods, None, None, None)

    mods = instance._PrepareContainerMods([
      (constants.DDM_REMOVE, 0, object()),
      ], None)
    self.assertRaises(AssertionError, instance._ApplyContainerMods,
                      "test", [""], None, mods, None, None, None)

  def testAddError(self):
    for idx in range(-100, -1) + [100]:
      mods = instance._PrepareContainerMods([
        (constants.DDM_ADD, idx, None),
        ], None)
      self.assertRaises(IndexError, instance._ApplyContainerMods,
                        "test", [], None, mods, None, None, None)

  def testRemove(self):
    container = ["item 1", "item 2"]
    mods = instance._PrepareContainerMods([
      (constants.DDM_ADD, -1, "aaa"),
      (constants.DDM_REMOVE, -1, None),
      (constants.DDM_ADD, -1, "bbb"),
      ], None)
    chgdesc = []
    instance._ApplyContainerMods("test", container, chgdesc, mods,
                                None, None, None)
    self.assertEqual(container, ["item 1", "item 2", "bbb"])
    self.assertEqual(chgdesc, [
      ("test/2", "remove"),
      ])

  def testModify(self):
    container = ["item 1", "item 2"]
    mods = instance._PrepareContainerMods([
      (constants.DDM_MODIFY, -1, "a"),
      (constants.DDM_MODIFY, 0, "b"),
      (constants.DDM_MODIFY, 1, "c"),
      ], None)
    chgdesc = []
    instance._ApplyContainerMods("test", container, chgdesc, mods,
                                None, None, None)
    self.assertEqual(container, ["item 1", "item 2"])
    self.assertEqual(chgdesc, [])

    for idx in [-2, len(container) + 1]:
      mods = instance._PrepareContainerMods([
        (constants.DDM_MODIFY, idx, "error"),
        ], None)
      self.assertRaises(IndexError, instance._ApplyContainerMods,
                        "test", container, None, mods, None, None, None)

  class _PrivateData:
    def __init__(self):
      self.data = None

  @staticmethod
  def _CreateTestFn(idx, params, private):
    private.data = ("add", idx, params)
    return ((100 * idx, params), [
      ("test/%s" % idx, hex(idx)),
      ])

  @staticmethod
  def _ModifyTestFn(idx, item, params, private):
    private.data = ("modify", idx, params)
    return [
      ("test/%s" % idx, "modify %s" % params),
      ]

  @staticmethod
  def _RemoveTestFn(idx, item, private):
    private.data = ("remove", idx, item)

  def testAddWithCreateFunction(self):
    container = []
    chgdesc = []
    mods = instance._PrepareContainerMods([
      (constants.DDM_ADD, -1, "Hello"),
      (constants.DDM_ADD, -1, "World"),
      (constants.DDM_ADD, 0, "Start"),
      (constants.DDM_ADD, -1, "End"),
      (constants.DDM_REMOVE, 2, None),
      (constants.DDM_MODIFY, -1, "foobar"),
      (constants.DDM_REMOVE, 2, None),
      (constants.DDM_ADD, 1, "More"),
      ], self._PrivateData)
    instance._ApplyContainerMods("test", container, chgdesc, mods,
                                self._CreateTestFn, self._ModifyTestFn,
                                self._RemoveTestFn)
    self.assertEqual(container, [
      (000, "Start"),
      (100, "More"),
      (000, "Hello"),
      ])
    self.assertEqual(chgdesc, [
      ("test/0", "0x0"),
      ("test/1", "0x1"),
      ("test/0", "0x0"),
      ("test/3", "0x3"),
      ("test/2", "remove"),
      ("test/2", "modify foobar"),
      ("test/2", "remove"),
      ("test/1", "0x1")
      ])
    self.assertTrue(compat.all(op == private.data[0]
                               for (op, _, _, private) in mods))
    self.assertEqual([private.data for (op, _, _, private) in mods], [
      ("add", 0, "Hello"),
      ("add", 1, "World"),
      ("add", 0, "Start"),
      ("add", 3, "End"),
      ("remove", 2, (100, "World")),
      ("modify", 2, "foobar"),
      ("remove", 2, (300, "End")),
      ("add", 1, "More"),
      ])


class _FakeConfigForGenDiskTemplate:
  def __init__(self, enabled_disk_templates):
    self._unique_id = itertools.count()
    self._drbd_minor = itertools.count(20)
    self._port = itertools.count(constants.FIRST_DRBD_PORT)
    self._secret = itertools.count()
    self._enabled_disk_templates = enabled_disk_templates

  def GetVGName(self):
    return "testvg"

  def GenerateUniqueID(self, ec_id):
    return "ec%s-uq%s" % (ec_id, self._unique_id.next())

  def AllocateDRBDMinor(self, nodes, instance):
    return [self._drbd_minor.next()
            for _ in nodes]

  def AllocatePort(self):
    return self._port.next()

  def GenerateDRBDSecret(self, ec_id):
    return "ec%s-secret%s" % (ec_id, self._secret.next())

  def GetInstanceInfo(self, _):
    return "foobar"

  def GetClusterInfo(self):
    cluster = objects.Cluster()
    cluster.enabled_disk_templates = self._enabled_disk_templates
    return cluster


class _FakeProcForGenDiskTemplate:
  def GetECId(self):
    return 0


class TestGenerateDiskTemplate(unittest.TestCase):

  def _SetUpLUWithTemplates(self, enabled_disk_templates):
    self._enabled_disk_templates = enabled_disk_templates
    cfg = _FakeConfigForGenDiskTemplate(self._enabled_disk_templates)
    proc = _FakeProcForGenDiskTemplate()

    self.lu = _FakeLU(cfg=cfg, proc=proc)

  def setUp(self):
    nodegroup = objects.NodeGroup(name="ng")
    nodegroup.UpgradeConfig()

    self._enabled_disk_templates = list(constants.DISK_TEMPLATES)
    self._SetUpLUWithTemplates(self._enabled_disk_templates)
    self.nodegroup = nodegroup

  @staticmethod
  def GetDiskParams():
    return copy.deepcopy(constants.DISK_DT_DEFAULTS)

  def testWrongDiskTemplate(self):
    gdt = instance.GenerateDiskTemplate
    disk_template = "##unknown##"

    assert disk_template not in constants.DISK_TEMPLATES

    self.assertRaises(errors.OpPrereqError, gdt, self.lu, disk_template,
                      "inst26831.example.com", "node30113.example.com", [], [],
                      NotImplemented, NotImplemented, 0, self.lu.LogInfo,
                      self.GetDiskParams())

  def testDiskless(self):
    gdt = instance.GenerateDiskTemplate

    result = gdt(self.lu, constants.DT_DISKLESS, "inst27734.example.com",
                 "node30113.example.com", [], [],
                 NotImplemented, NotImplemented, 0, self.lu.LogInfo,
                 self.GetDiskParams())
    self.assertEqual(result, [])

  def _TestTrivialDisk(self, template, disk_info, base_index, exp_dev_type,
                       file_storage_dir=NotImplemented,
                       file_driver=NotImplemented):
    gdt = instance.GenerateDiskTemplate

    map(lambda params: utils.ForceDictType(params,
                                           constants.IDISK_PARAMS_TYPES),
        disk_info)

    # Check if non-empty list of secondaries is rejected
    self.assertRaises(errors.ProgrammerError, gdt, self.lu,
                      template, "inst25088.example.com",
                      "node185.example.com", ["node323.example.com"], [],
                      NotImplemented, NotImplemented, base_index,
                      self.lu.LogInfo, self.GetDiskParams())

    result = gdt(self.lu, template, "inst21662.example.com",
                 "node21741.example.com", [],
                 disk_info, file_storage_dir, file_driver, base_index,
                 self.lu.LogInfo, self.GetDiskParams())

    for (idx, disk) in enumerate(result):
      self.assertTrue(isinstance(disk, objects.Disk))
      self.assertEqual(disk.dev_type, exp_dev_type)
      self.assertEqual(disk.size, disk_info[idx][constants.IDISK_SIZE])
      self.assertEqual(disk.mode, disk_info[idx][constants.IDISK_MODE])
      self.assertTrue(disk.children is None)

    self._CheckIvNames(result, base_index, base_index + len(disk_info))
    instance._UpdateIvNames(base_index, result)
    self._CheckIvNames(result, base_index, base_index + len(disk_info))

    return result

  def _CheckIvNames(self, disks, base_index, end_index):
    self.assertEqual(map(operator.attrgetter("iv_name"), disks),
                     ["disk/%s" % i for i in range(base_index, end_index)])

  def testPlain(self):
    disk_info = [{
      constants.IDISK_SIZE: 1024,
      constants.IDISK_MODE: constants.DISK_RDWR,
      }, {
      constants.IDISK_SIZE: 4096,
      constants.IDISK_VG: "othervg",
      constants.IDISK_MODE: constants.DISK_RDWR,
      }]

    result = self._TestTrivialDisk(constants.DT_PLAIN, disk_info, 3,
                                   constants.LD_LV)

    self.assertEqual(map(operator.attrgetter("logical_id"), result), [
      ("testvg", "ec0-uq0.disk3"),
      ("othervg", "ec0-uq1.disk4"),
      ])

  def testFile(self):
    # anything != DT_FILE would do here
    self._SetUpLUWithTemplates([constants.DT_PLAIN])
    self.assertRaises(errors.OpPrereqError, self._TestTrivialDisk,
                      constants.DT_FILE, [], 0, NotImplemented)
    self.assertRaises(errors.OpPrereqError, self._TestTrivialDisk,
                      constants.DT_SHARED_FILE, [], 0, NotImplemented)

    for disk_template in [constants.DT_FILE, constants.DT_SHARED_FILE]:
      disk_info = [{
        constants.IDISK_SIZE: 80 * 1024,
        constants.IDISK_MODE: constants.DISK_RDONLY,
        }, {
        constants.IDISK_SIZE: 4096,
        constants.IDISK_MODE: constants.DISK_RDWR,
        }, {
        constants.IDISK_SIZE: 6 * 1024,
        constants.IDISK_MODE: constants.DISK_RDWR,
        }]

      self._SetUpLUWithTemplates([disk_template])
      result = self._TestTrivialDisk(disk_template, disk_info, 2,
        constants.LD_FILE, file_storage_dir="/tmp",
        file_driver=constants.FD_BLKTAP)

      self.assertEqual(map(operator.attrgetter("logical_id"), result), [
        (constants.FD_BLKTAP, "/tmp/disk2"),
        (constants.FD_BLKTAP, "/tmp/disk3"),
        (constants.FD_BLKTAP, "/tmp/disk4"),
        ])

  def testBlock(self):
    disk_info = [{
      constants.IDISK_SIZE: 8 * 1024,
      constants.IDISK_MODE: constants.DISK_RDWR,
      constants.IDISK_ADOPT: "/tmp/some/block/dev",
      }]

    result = self._TestTrivialDisk(constants.DT_BLOCK, disk_info, 10,
                                   constants.LD_BLOCKDEV)

    self.assertEqual(map(operator.attrgetter("logical_id"), result), [
      (constants.BLOCKDEV_DRIVER_MANUAL, "/tmp/some/block/dev"),
      ])

  def testRbd(self):
    disk_info = [{
      constants.IDISK_SIZE: 8 * 1024,
      constants.IDISK_MODE: constants.DISK_RDONLY,
      }, {
      constants.IDISK_SIZE: 100 * 1024,
      constants.IDISK_MODE: constants.DISK_RDWR,
      }]

    result = self._TestTrivialDisk(constants.DT_RBD, disk_info, 0,
                                   constants.LD_RBD)

    self.assertEqual(map(operator.attrgetter("logical_id"), result), [
      ("rbd", "ec0-uq0.rbd.disk0"),
      ("rbd", "ec0-uq1.rbd.disk1"),
      ])

  def testDrbd8(self):
    gdt = instance.GenerateDiskTemplate
    drbd8_defaults = constants.DISK_LD_DEFAULTS[constants.LD_DRBD8]
    drbd8_default_metavg = drbd8_defaults[constants.LDP_DEFAULT_METAVG]

    disk_info = [{
      constants.IDISK_SIZE: 1024,
      constants.IDISK_MODE: constants.DISK_RDWR,
      }, {
      constants.IDISK_SIZE: 100 * 1024,
      constants.IDISK_MODE: constants.DISK_RDONLY,
      constants.IDISK_METAVG: "metavg",
      }, {
      constants.IDISK_SIZE: 4096,
      constants.IDISK_MODE: constants.DISK_RDWR,
      constants.IDISK_VG: "vgxyz",
      },
      ]

    exp_logical_ids = [[
      (self.lu.cfg.GetVGName(), "ec0-uq0.disk0_data"),
      (drbd8_default_metavg, "ec0-uq0.disk0_meta"),
      ], [
      (self.lu.cfg.GetVGName(), "ec0-uq1.disk1_data"),
      ("metavg", "ec0-uq1.disk1_meta"),
      ], [
      ("vgxyz", "ec0-uq2.disk2_data"),
      (drbd8_default_metavg, "ec0-uq2.disk2_meta"),
      ]]

    assert len(exp_logical_ids) == len(disk_info)

    map(lambda params: utils.ForceDictType(params,
                                           constants.IDISK_PARAMS_TYPES),
        disk_info)

    # Check if empty list of secondaries is rejected
    self.assertRaises(errors.ProgrammerError, gdt, self.lu, constants.DT_DRBD8,
                      "inst827.example.com", "node1334.example.com", [],
                      disk_info, NotImplemented, NotImplemented, 0,
                      self.lu.LogInfo, self.GetDiskParams())

    result = gdt(self.lu, constants.DT_DRBD8, "inst827.example.com",
                 "node1334.example.com", ["node12272.example.com"],
                 disk_info, NotImplemented, NotImplemented, 0, self.lu.LogInfo,
                 self.GetDiskParams())

    for (idx, disk) in enumerate(result):
      self.assertTrue(isinstance(disk, objects.Disk))
      self.assertEqual(disk.dev_type, constants.LD_DRBD8)
      self.assertEqual(disk.size, disk_info[idx][constants.IDISK_SIZE])
      self.assertEqual(disk.mode, disk_info[idx][constants.IDISK_MODE])

      for child in disk.children:
        self.assertTrue(isinstance(disk, objects.Disk))
        self.assertEqual(child.dev_type, constants.LD_LV)
        self.assertTrue(child.children is None)

      self.assertEqual(map(operator.attrgetter("logical_id"), disk.children),
                       exp_logical_ids[idx])

      self.assertEqual(len(disk.children), 2)
      self.assertEqual(disk.children[0].size, disk.size)
      self.assertEqual(disk.children[1].size, constants.DRBD_META_SIZE)

    self._CheckIvNames(result, 0, len(disk_info))
    instance._UpdateIvNames(0, result)
    self._CheckIvNames(result, 0, len(disk_info))

    self.assertEqual(map(operator.attrgetter("logical_id"), result), [
      ("node1334.example.com", "node12272.example.com",
       constants.FIRST_DRBD_PORT, 20, 21, "ec0-secret0"),
      ("node1334.example.com", "node12272.example.com",
       constants.FIRST_DRBD_PORT + 1, 22, 23, "ec0-secret1"),
      ("node1334.example.com", "node12272.example.com",
       constants.FIRST_DRBD_PORT + 2, 24, 25, "ec0-secret2"),
      ])


class _ConfigForDiskWipe:
  def __init__(self, exp_node_uuid):
    self._exp_node_uuid = exp_node_uuid

  def SetDiskID(self, device, node_uuid):
    assert isinstance(device, objects.Disk)
    assert node_uuid == self._exp_node_uuid

  def GetNodeName(self, node_uuid):
    assert node_uuid == self._exp_node_uuid
    return "name.of.expected.node"


class _RpcForDiskWipe:
  def __init__(self, exp_node, pause_cb, wipe_cb):
    self._exp_node = exp_node
    self._pause_cb = pause_cb
    self._wipe_cb = wipe_cb

  def call_blockdev_pause_resume_sync(self, node, disks, pause):
    assert node == self._exp_node
    return rpc.RpcResult(data=self._pause_cb(disks, pause))

  def call_blockdev_wipe(self, node, bdev, offset, size):
    assert node == self._exp_node
    return rpc.RpcResult(data=self._wipe_cb(bdev, offset, size))


class _DiskPauseTracker:
  def __init__(self):
    self.history = []

  def __call__(self, (disks, instance), pause):
    assert not (set(disks) - set(instance.disks))

    self.history.extend((i.logical_id, i.size, pause)
                        for i in disks)

    return (True, [True] * len(disks))


class _DiskWipeProgressTracker:
  def __init__(self, start_offset):
    self._start_offset = start_offset
    self.progress = {}

  def __call__(self, (disk, _), offset, size):
    assert isinstance(offset, (long, int))
    assert isinstance(size, (long, int))

    max_chunk_size = (disk.size / 100.0 * constants.MIN_WIPE_CHUNK_PERCENT)

    assert offset >= self._start_offset
    assert (offset + size) <= disk.size

    assert size > 0
    assert size <= constants.MAX_WIPE_CHUNK
    assert size <= max_chunk_size

    assert offset == self._start_offset or disk.logical_id in self.progress

    # Keep track of progress
    cur_progress = self.progress.setdefault(disk.logical_id, self._start_offset)

    assert cur_progress == offset

    # Record progress
    self.progress[disk.logical_id] += size

    return (True, None)


class TestWipeDisks(unittest.TestCase):
  def _FailingPauseCb(self, (disks, _), pause):
    self.assertEqual(len(disks), 3)
    self.assertTrue(pause)
    # Simulate an RPC error
    return (False, "error")

  def testPauseFailure(self):
    node_name = "node1372.example.com"

    lu = _FakeLU(rpc=_RpcForDiskWipe(node_name, self._FailingPauseCb,
                                     NotImplemented),
                 cfg=_ConfigForDiskWipe(node_name))

    disks = [
      objects.Disk(dev_type=constants.LD_LV),
      objects.Disk(dev_type=constants.LD_LV),
      objects.Disk(dev_type=constants.LD_LV),
      ]

    inst = objects.Instance(name="inst21201",
                            primary_node=node_name,
                            disk_template=constants.DT_PLAIN,
                            disks=disks)

    self.assertRaises(errors.OpExecError, instance.WipeDisks, lu, inst)

  def _FailingWipeCb(self, (disk, _), offset, size):
    # This should only ever be called for the first disk
    self.assertEqual(disk.logical_id, "disk0")
    return (False, None)

  def testFailingWipe(self):
    node_uuid = "node13445-uuid"
    pt = _DiskPauseTracker()

    lu = _FakeLU(rpc=_RpcForDiskWipe(node_uuid, pt, self._FailingWipeCb),
                 cfg=_ConfigForDiskWipe(node_uuid))

    disks = [
      objects.Disk(dev_type=constants.LD_LV, logical_id="disk0",
                   size=100 * 1024),
      objects.Disk(dev_type=constants.LD_LV, logical_id="disk1",
                   size=500 * 1024),
      objects.Disk(dev_type=constants.LD_LV, logical_id="disk2", size=256),
      ]

    inst = objects.Instance(name="inst562",
                            primary_node=node_uuid,
                            disk_template=constants.DT_PLAIN,
                            disks=disks)

    try:
      instance.WipeDisks(lu, inst)
    except errors.OpExecError, err:
      self.assertTrue(str(err), "Could not wipe disk 0 at offset 0 ")
    else:
      self.fail("Did not raise exception")

    # Check if all disks were paused and resumed
    self.assertEqual(pt.history, [
      ("disk0", 100 * 1024, True),
      ("disk1", 500 * 1024, True),
      ("disk2", 256, True),
      ("disk0", 100 * 1024, False),
      ("disk1", 500 * 1024, False),
      ("disk2", 256, False),
      ])

  def _PrepareWipeTest(self, start_offset, disks):
    node_name = "node-with-offset%s.example.com" % start_offset
    pauset = _DiskPauseTracker()
    progresst = _DiskWipeProgressTracker(start_offset)

    lu = _FakeLU(rpc=_RpcForDiskWipe(node_name, pauset, progresst),
                 cfg=_ConfigForDiskWipe(node_name))

    instance = objects.Instance(name="inst3560",
                                primary_node=node_name,
                                disk_template=constants.DT_PLAIN,
                                disks=disks)

    return (lu, instance, pauset, progresst)

  def testNormalWipe(self):
    disks = [
      objects.Disk(dev_type=constants.LD_LV, logical_id="disk0", size=1024),
      objects.Disk(dev_type=constants.LD_LV, logical_id="disk1",
                   size=500 * 1024),
      objects.Disk(dev_type=constants.LD_LV, logical_id="disk2", size=128),
      objects.Disk(dev_type=constants.LD_LV, logical_id="disk3",
                   size=constants.MAX_WIPE_CHUNK),
      ]

    (lu, inst, pauset, progresst) = self._PrepareWipeTest(0, disks)

    instance.WipeDisks(lu, inst)

    self.assertEqual(pauset.history, [
      ("disk0", 1024, True),
      ("disk1", 500 * 1024, True),
      ("disk2", 128, True),
      ("disk3", constants.MAX_WIPE_CHUNK, True),
      ("disk0", 1024, False),
      ("disk1", 500 * 1024, False),
      ("disk2", 128, False),
      ("disk3", constants.MAX_WIPE_CHUNK, False),
      ])

    # Ensure the complete disk has been wiped
    self.assertEqual(progresst.progress,
                     dict((i.logical_id, i.size) for i in disks))

  def testWipeWithStartOffset(self):
    for start_offset in [0, 280, 8895, 1563204]:
      disks = [
        objects.Disk(dev_type=constants.LD_LV, logical_id="disk0",
                     size=128),
        objects.Disk(dev_type=constants.LD_LV, logical_id="disk1",
                     size=start_offset + (100 * 1024)),
        ]

      (lu, inst, pauset, progresst) = \
        self._PrepareWipeTest(start_offset, disks)

      # Test start offset with only one disk
      instance.WipeDisks(lu, inst,
                         disks=[(1, disks[1], start_offset)])

      # Only the second disk may have been paused and wiped
      self.assertEqual(pauset.history, [
        ("disk1", start_offset + (100 * 1024), True),
        ("disk1", start_offset + (100 * 1024), False),
        ])
      self.assertEqual(progresst.progress, {
        "disk1": disks[1].size,
        })


class TestDiskSizeInBytesToMebibytes(unittest.TestCase):
  def testLessThanOneMebibyte(self):
    for i in [1, 2, 7, 512, 1000, 1023]:
      lu = _FakeLU()
      result = instance_storage._DiskSizeInBytesToMebibytes(lu, i)
      self.assertEqual(result, 1)
      self.assertEqual(len(lu.warning_log), 1)
      self.assertEqual(len(lu.warning_log[0]), 2)
      (_, (warnsize, )) = lu.warning_log[0]
      self.assertEqual(warnsize, (1024 * 1024) - i)

  def testEven(self):
    for i in [1, 2, 7, 512, 1000, 1023]:
      lu = _FakeLU()
      result = instance_storage._DiskSizeInBytesToMebibytes(lu,
                                                            i * 1024 * 1024)
      self.assertEqual(result, i)
      self.assertFalse(lu.warning_log)

  def testLargeNumber(self):
    for i in [1, 2, 7, 512, 1000, 1023, 2724, 12420]:
      for j in [1, 2, 486, 326, 986, 1023]:
        lu = _FakeLU()
        size = (1024 * 1024 * i) + j
        result = instance_storage._DiskSizeInBytesToMebibytes(lu, size)
        self.assertEqual(result, i + 1, msg="Amount was not rounded up")
        self.assertEqual(len(lu.warning_log), 1)
        self.assertEqual(len(lu.warning_log[0]), 2)
        (_, (warnsize, )) = lu.warning_log[0]
        self.assertEqual(warnsize, (1024 * 1024) - j)


class TestCopyLockList(unittest.TestCase):
  def test(self):
    self.assertEqual(instance.CopyLockList([]), [])
    self.assertEqual(instance.CopyLockList(None), None)
    self.assertEqual(instance.CopyLockList(locking.ALL_SET), locking.ALL_SET)

    names = ["foo", "bar"]
    output = instance.CopyLockList(names)
    self.assertEqual(names, output)
    self.assertNotEqual(id(names), id(output), msg="List was not copied")


class TestCheckOpportunisticLocking(unittest.TestCase):
  class OpTest(opcodes.OpCode):
    OP_PARAMS = [
      ("opportunistic_locking", False, ht.TBool, None),
      ("iallocator", None, ht.TMaybe(ht.TNonEmptyString), "")
      ]

  @classmethod
  def _MakeOp(cls, **kwargs):
    op = cls.OpTest(**kwargs)
    op.Validate(True)
    return op

  def testMissingAttributes(self):
    self.assertRaises(AttributeError, instance._CheckOpportunisticLocking,
                      object())

  def testDefaults(self):
    op = self._MakeOp()
    instance._CheckOpportunisticLocking(op)

  def test(self):
    for iallocator in [None, "something", "other"]:
      for opplock in [False, True]:
        op = self._MakeOp(iallocator=iallocator,
                          opportunistic_locking=opplock)
        if opplock and not iallocator:
          self.assertRaises(errors.OpPrereqError,
                            instance._CheckOpportunisticLocking, op)
        else:
          instance._CheckOpportunisticLocking(op)


class _OpTestVerifyErrors(opcodes.OpCode):
  OP_PARAMS = [
    ("debug_simulate_errors", False, ht.TBool, ""),
    ("error_codes", False, ht.TBool, ""),
    ("ignore_errors",
     [],
     ht.TListOf(ht.TElemOf(constants.CV_ALL_ECODES_STRINGS)),
     "")
    ]


class _LuTestVerifyErrors(cluster._VerifyErrors):
  def __init__(self, **kwargs):
    cluster._VerifyErrors.__init__(self)
    self.op = _OpTestVerifyErrors(**kwargs)
    self.op.Validate(True)
    self.msglist = []
    self._feedback_fn = self.msglist.append
    self.bad = False

  def DispatchCallError(self, which, *args, **kwargs):
    if which:
      self._Error(*args, **kwargs)
    else:
      self._ErrorIf(True, *args, **kwargs)

  def CallErrorIf(self, c, *args, **kwargs):
    self._ErrorIf(c, *args, **kwargs)


class TestVerifyErrors(unittest.TestCase):
  # Fake cluster-verify error code structures; we use two arbitary real error
  # codes to pass validation of ignore_errors
  (_, _ERR1ID, _) = constants.CV_ECLUSTERCFG
  _NODESTR = "node"
  _NODENAME = "mynode"
  _ERR1CODE = (_NODESTR, _ERR1ID, "Error one")
  (_, _ERR2ID, _) = constants.CV_ECLUSTERCERT
  _INSTSTR = "instance"
  _INSTNAME = "myinstance"
  _ERR2CODE = (_INSTSTR, _ERR2ID, "Error two")
  # Arguments used to call _Error() or _ErrorIf()
  _ERR1ARGS = (_ERR1CODE, _NODENAME, "Error1 is %s", "an error")
  _ERR2ARGS = (_ERR2CODE, _INSTNAME, "Error2 has no argument")
  # Expected error messages
  _ERR1MSG = _ERR1ARGS[2] % _ERR1ARGS[3]
  _ERR2MSG = _ERR2ARGS[2]

  def testNoError(self):
    lu = _LuTestVerifyErrors()
    lu.CallErrorIf(False, self._ERR1CODE, *self._ERR1ARGS)
    self.assertFalse(lu.bad)
    self.assertFalse(lu.msglist)

  def _InitTest(self, **kwargs):
    self.lu1 = _LuTestVerifyErrors(**kwargs)
    self.lu2 = _LuTestVerifyErrors(**kwargs)

  def _CallError(self, *args, **kwargs):
    # Check that _Error() and _ErrorIf() produce the same results
    self.lu1.DispatchCallError(True, *args, **kwargs)
    self.lu2.DispatchCallError(False, *args, **kwargs)
    self.assertEqual(self.lu1.bad, self.lu2.bad)
    self.assertEqual(self.lu1.msglist, self.lu2.msglist)
    # Test-specific checks are made on one LU
    return self.lu1

  def _checkMsgCommon(self, logstr, errmsg, itype, item, warning):
    self.assertTrue(errmsg in logstr)
    if warning:
      self.assertTrue("WARNING" in logstr)
    else:
      self.assertTrue("ERROR" in logstr)
    self.assertTrue(itype in logstr)
    self.assertTrue(item in logstr)

  def _checkMsg1(self, logstr, warning=False):
    self._checkMsgCommon(logstr, self._ERR1MSG, self._NODESTR,
                         self._NODENAME, warning)

  def _checkMsg2(self, logstr, warning=False):
    self._checkMsgCommon(logstr, self._ERR2MSG, self._INSTSTR,
                         self._INSTNAME, warning)

  def testPlain(self):
    self._InitTest()
    lu = self._CallError(*self._ERR1ARGS)
    self.assertTrue(lu.bad)
    self.assertEqual(len(lu.msglist), 1)
    self._checkMsg1(lu.msglist[0])

  def testMultiple(self):
    self._InitTest()
    self._CallError(*self._ERR1ARGS)
    lu = self._CallError(*self._ERR2ARGS)
    self.assertTrue(lu.bad)
    self.assertEqual(len(lu.msglist), 2)
    self._checkMsg1(lu.msglist[0])
    self._checkMsg2(lu.msglist[1])

  def testIgnore(self):
    self._InitTest(ignore_errors=[self._ERR1ID])
    lu = self._CallError(*self._ERR1ARGS)
    self.assertFalse(lu.bad)
    self.assertEqual(len(lu.msglist), 1)
    self._checkMsg1(lu.msglist[0], warning=True)

  def testWarning(self):
    self._InitTest()
    lu = self._CallError(*self._ERR1ARGS,
                         code=_LuTestVerifyErrors.ETYPE_WARNING)
    self.assertFalse(lu.bad)
    self.assertEqual(len(lu.msglist), 1)
    self._checkMsg1(lu.msglist[0], warning=True)

  def testWarning2(self):
    self._InitTest()
    self._CallError(*self._ERR1ARGS)
    lu = self._CallError(*self._ERR2ARGS,
                         code=_LuTestVerifyErrors.ETYPE_WARNING)
    self.assertTrue(lu.bad)
    self.assertEqual(len(lu.msglist), 2)
    self._checkMsg1(lu.msglist[0])
    self._checkMsg2(lu.msglist[1], warning=True)

  def testDebugSimulate(self):
    lu = _LuTestVerifyErrors(debug_simulate_errors=True)
    lu.CallErrorIf(False, *self._ERR1ARGS)
    self.assertTrue(lu.bad)
    self.assertEqual(len(lu.msglist), 1)
    self._checkMsg1(lu.msglist[0])

  def testErrCodes(self):
    self._InitTest(error_codes=True)
    lu = self._CallError(*self._ERR1ARGS)
    self.assertTrue(lu.bad)
    self.assertEqual(len(lu.msglist), 1)
    self._checkMsg1(lu.msglist[0])
    self.assertTrue(self._ERR1ID in lu.msglist[0])


class TestGetUpdatedIPolicy(unittest.TestCase):
  """Tests for cmdlib._GetUpdatedIPolicy()"""
  _OLD_CLUSTER_POLICY = {
    constants.IPOLICY_VCPU_RATIO: 1.5,
    constants.ISPECS_MINMAX: [
      {
        constants.ISPECS_MIN: {
          constants.ISPEC_MEM_SIZE: 32768,
          constants.ISPEC_CPU_COUNT: 8,
          constants.ISPEC_DISK_COUNT: 1,
          constants.ISPEC_DISK_SIZE: 1024,
          constants.ISPEC_NIC_COUNT: 1,
          constants.ISPEC_SPINDLE_USE: 1,
          },
        constants.ISPECS_MAX: {
          constants.ISPEC_MEM_SIZE: 65536,
          constants.ISPEC_CPU_COUNT: 10,
          constants.ISPEC_DISK_COUNT: 5,
          constants.ISPEC_DISK_SIZE: 1024 * 1024,
          constants.ISPEC_NIC_COUNT: 3,
          constants.ISPEC_SPINDLE_USE: 12,
          },
        },
      constants.ISPECS_MINMAX_DEFAULTS,
      ],
    constants.ISPECS_STD: constants.IPOLICY_DEFAULTS[constants.ISPECS_STD],
    }
  _OLD_GROUP_POLICY = {
    constants.IPOLICY_SPINDLE_RATIO: 2.5,
    constants.ISPECS_MINMAX: [{
      constants.ISPECS_MIN: {
        constants.ISPEC_MEM_SIZE: 128,
        constants.ISPEC_CPU_COUNT: 1,
        constants.ISPEC_DISK_COUNT: 1,
        constants.ISPEC_DISK_SIZE: 1024,
        constants.ISPEC_NIC_COUNT: 1,
        constants.ISPEC_SPINDLE_USE: 1,
        },
      constants.ISPECS_MAX: {
        constants.ISPEC_MEM_SIZE: 32768,
        constants.ISPEC_CPU_COUNT: 8,
        constants.ISPEC_DISK_COUNT: 5,
        constants.ISPEC_DISK_SIZE: 1024 * 1024,
        constants.ISPEC_NIC_COUNT: 3,
        constants.ISPEC_SPINDLE_USE: 12,
        },
      }],
    }

  def _TestSetSpecs(self, old_policy, isgroup):
    diff_minmax = [{
      constants.ISPECS_MIN: {
        constants.ISPEC_MEM_SIZE: 64,
        constants.ISPEC_CPU_COUNT: 1,
        constants.ISPEC_DISK_COUNT: 2,
        constants.ISPEC_DISK_SIZE: 64,
        constants.ISPEC_NIC_COUNT: 1,
        constants.ISPEC_SPINDLE_USE: 1,
        },
      constants.ISPECS_MAX: {
        constants.ISPEC_MEM_SIZE: 16384,
        constants.ISPEC_CPU_COUNT: 10,
        constants.ISPEC_DISK_COUNT: 12,
        constants.ISPEC_DISK_SIZE: 1024,
        constants.ISPEC_NIC_COUNT: 9,
        constants.ISPEC_SPINDLE_USE: 18,
        },
      }]
    diff_std = {
        constants.ISPEC_DISK_COUNT: 10,
        constants.ISPEC_DISK_SIZE: 512,
        }
    diff_policy = {
      constants.ISPECS_MINMAX: diff_minmax
      }
    if not isgroup:
      diff_policy[constants.ISPECS_STD] = diff_std
    new_policy = common.GetUpdatedIPolicy(old_policy, diff_policy,
                                          group_policy=isgroup)

    self.assertTrue(constants.ISPECS_MINMAX in new_policy)
    self.assertEqual(new_policy[constants.ISPECS_MINMAX], diff_minmax)
    for key in old_policy:
      if not key in diff_policy:
        self.assertTrue(key in new_policy)
        self.assertEqual(new_policy[key], old_policy[key])

    if not isgroup:
      new_std = new_policy[constants.ISPECS_STD]
      for key in diff_std:
        self.assertTrue(key in new_std)
        self.assertEqual(new_std[key], diff_std[key])
      old_std = old_policy.get(constants.ISPECS_STD, {})
      for key in old_std:
        self.assertTrue(key in new_std)
        if key not in diff_std:
          self.assertEqual(new_std[key], old_std[key])

  def _TestSet(self, old_policy, diff_policy, isgroup):
    new_policy = common.GetUpdatedIPolicy(old_policy, diff_policy,
                                           group_policy=isgroup)
    for key in diff_policy:
      self.assertTrue(key in new_policy)
      self.assertEqual(new_policy[key], diff_policy[key])
    for key in old_policy:
      if not key in diff_policy:
        self.assertTrue(key in new_policy)
        self.assertEqual(new_policy[key], old_policy[key])

  def testSet(self):
    diff_policy = {
      constants.IPOLICY_VCPU_RATIO: 3,
      constants.IPOLICY_DTS: [constants.DT_FILE],
      }
    self._TestSet(self._OLD_GROUP_POLICY, diff_policy, True)
    self._TestSetSpecs(self._OLD_GROUP_POLICY, True)
    self._TestSet({}, diff_policy, True)
    self._TestSetSpecs({}, True)
    self._TestSet(self._OLD_CLUSTER_POLICY, diff_policy, False)
    self._TestSetSpecs(self._OLD_CLUSTER_POLICY, False)

  def testUnset(self):
    old_policy = self._OLD_GROUP_POLICY
    diff_policy = {
      constants.IPOLICY_SPINDLE_RATIO: constants.VALUE_DEFAULT,
      }
    new_policy = common.GetUpdatedIPolicy(old_policy, diff_policy,
                                          group_policy=True)
    for key in diff_policy:
      self.assertFalse(key in new_policy)
    for key in old_policy:
      if not key in diff_policy:
        self.assertTrue(key in new_policy)
        self.assertEqual(new_policy[key], old_policy[key])

    self.assertRaises(errors.OpPrereqError, common.GetUpdatedIPolicy,
                      old_policy, diff_policy, group_policy=False)

  def testUnsetEmpty(self):
    old_policy = {}
    for key in constants.IPOLICY_ALL_KEYS:
      diff_policy = {
        key: constants.VALUE_DEFAULT,
        }
    new_policy = common.GetUpdatedIPolicy(old_policy, diff_policy,
                                          group_policy=True)
    self.assertEqual(new_policy, old_policy)

  def _TestInvalidKeys(self, old_policy, isgroup):
    INVALID_KEY = "this_key_shouldnt_be_allowed"
    INVALID_DICT = {
      INVALID_KEY: 3,
      }
    invalid_policy = INVALID_DICT
    self.assertRaises(errors.OpPrereqError, common.GetUpdatedIPolicy,
                      old_policy, invalid_policy, group_policy=isgroup)
    invalid_ispecs = {
      constants.ISPECS_MINMAX: [INVALID_DICT],
      }
    self.assertRaises(errors.TypeEnforcementError, common.GetUpdatedIPolicy,
                      old_policy, invalid_ispecs, group_policy=isgroup)
    if isgroup:
      invalid_for_group = {
        constants.ISPECS_STD: constants.IPOLICY_DEFAULTS[constants.ISPECS_STD],
        }
      self.assertRaises(errors.OpPrereqError, common.GetUpdatedIPolicy,
                        old_policy, invalid_for_group, group_policy=isgroup)
    good_ispecs = self._OLD_CLUSTER_POLICY[constants.ISPECS_MINMAX]
    invalid_ispecs = copy.deepcopy(good_ispecs)
    invalid_policy = {
      constants.ISPECS_MINMAX: invalid_ispecs,
      }
    for minmax in invalid_ispecs:
      for key in constants.ISPECS_MINMAX_KEYS:
        ispec = minmax[key]
        ispec[INVALID_KEY] = None
        self.assertRaises(errors.TypeEnforcementError,
                          common.GetUpdatedIPolicy, old_policy,
                          invalid_policy, group_policy=isgroup)
        del ispec[INVALID_KEY]
        for par in constants.ISPECS_PARAMETERS:
          oldv = ispec[par]
          ispec[par] = "this_is_not_good"
          self.assertRaises(errors.TypeEnforcementError,
                            common.GetUpdatedIPolicy,
                            old_policy, invalid_policy, group_policy=isgroup)
          ispec[par] = oldv
    # This is to make sure that no two errors were present during the tests
    common.GetUpdatedIPolicy(old_policy, invalid_policy,
                             group_policy=isgroup)

  def testInvalidKeys(self):
    self._TestInvalidKeys(self._OLD_GROUP_POLICY, True)
    self._TestInvalidKeys(self._OLD_CLUSTER_POLICY, False)

  def testInvalidValues(self):
    for par in (constants.IPOLICY_PARAMETERS |
                frozenset([constants.IPOLICY_DTS])):
      bad_policy = {
        par: "invalid_value",
        }
      self.assertRaises(errors.OpPrereqError, common.GetUpdatedIPolicy, {},
                        bad_policy, group_policy=True)

if __name__ == "__main__":
  testutils.GanetiTestProgram()