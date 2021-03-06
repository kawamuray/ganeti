#!/usr/bin/python
#

# Copyright (C) 2006, 2007, 2010, 2011 Google Inc.
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


"""Script for testing ganeti.utils.io (tests that require root access)"""

import os
import tempfile
import shutil
import errno
import grp
import pwd
import stat

from ganeti import constants
from ganeti import utils
from ganeti import compat
from ganeti import errors

import testutils


class TestWriteFile(testutils.GanetiTestCase):
  def setUp(self):
    testutils.GanetiTestCase.setUp(self)
    self.tmpdir = None
    self.tfile = tempfile.NamedTemporaryFile()
    self.did_pre = False
    self.did_post = False
    self.did_write = False

  def tearDown(self):
    testutils.GanetiTestCase.tearDown(self)
    if self.tmpdir:
      shutil.rmtree(self.tmpdir)

  def testFileUid(self):
    self.tmpdir = tempfile.mkdtemp()
    target = utils.PathJoin(self.tmpdir, "target")
    tuid = os.geteuid() + 1
    utils.WriteFile(target, data="data", uid=tuid + 1)
    self.assertFileUid(target, tuid + 1)
    utils.WriteFile(target, data="data", uid=tuid)
    self.assertFileUid(target, tuid)
    utils.WriteFile(target, data="data", uid=tuid + 1,
                    keep_perms=utils.KP_IF_EXISTS)
    self.assertFileUid(target, tuid)
    utils.WriteFile(target, data="data", keep_perms=utils.KP_ALWAYS)
    self.assertFileUid(target, tuid)

  def testNewFileUid(self):
    self.tmpdir = tempfile.mkdtemp()
    target = utils.PathJoin(self.tmpdir, "target")
    tuid = os.geteuid() + 1
    utils.WriteFile(target, data="data", uid=tuid,
                    keep_perms=utils.KP_IF_EXISTS)
    self.assertFileUid(target, tuid)

  def testFileGid(self):
    self.tmpdir = tempfile.mkdtemp()
    target = utils.PathJoin(self.tmpdir, "target")
    tgid = os.getegid() + 1
    utils.WriteFile(target, data="data", gid=tgid + 1)
    self.assertFileGid(target, tgid + 1)
    utils.WriteFile(target, data="data", gid=tgid)
    self.assertFileGid(target, tgid)
    utils.WriteFile(target, data="data", gid=tgid + 1,
                    keep_perms=utils.KP_IF_EXISTS)
    self.assertFileGid(target, tgid)
    utils.WriteFile(target, data="data", keep_perms=utils.KP_ALWAYS)
    self.assertFileGid(target, tgid)

  def testNewFileGid(self):
    self.tmpdir = tempfile.mkdtemp()
    target = utils.PathJoin(self.tmpdir, "target")
    tgid = os.getegid() + 1
    utils.WriteFile(target, data="data", gid=tgid,
                    keep_perms=utils.KP_IF_EXISTS)
    self.assertFileGid(target, tgid)

class TestCanRead(testutils.GanetiTestCase):
  def setUp(self):
    testutils.GanetiTestCase.setUp(self)
    self.tmpdir = tempfile.mkdtemp()
    self.confdUid = pwd.getpwnam(constants.CONFD_USER).pw_uid
    self.masterdUid = pwd.getpwnam(constants.MASTERD_USER).pw_uid
    self.masterdGid = grp.getgrnam(constants.MASTERD_GROUP).gr_gid

  def tearDown(self):
    testutils.GanetiTestCase.tearDown(self)
    if self.tmpdir:
      shutil.rmtree(self.tmpdir)

  def testUserCanRead(self):
    target = utils.PathJoin(self.tmpdir, "target1")
    f=open(target, "w")
    f.close()
    utils.EnforcePermission(target, 0400, uid=self.confdUid,
                            gid=self.masterdGid)
    self.assertTrue(utils.CanRead(constants.CONFD_USER, target))
    if constants.CONFD_USER != constants.MASTERD_USER:
      self.assertFalse(utils.CanRead(constants.MASTERD_USER, target))

  def testGroupCanRead(self):
    target = utils.PathJoin(self.tmpdir, "target2")
    f=open(target, "w")
    f.close()
    utils.EnforcePermission(target, 0040, uid=self.confdUid,
                            gid=self.masterdGid)
    self.assertFalse(utils.CanRead(constants.CONFD_USER, target))
    if constants.CONFD_USER != constants.MASTERD_USER:
      self.assertTrue(utils.CanRead(constants.MASTERD_USER, target))

    utils.EnforcePermission(target, 0040, uid=self.masterdUid+1,
                            gid=self.masterdGid)
    self.assertTrue(utils.CanRead(constants.MASTERD_USER, target))


if __name__ == "__main__":
  testutils.GanetiTestProgram()
