#
#

# Copyright (C) 2010, 2013 Google Inc.
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


"""LXC hypervisor

"""

import os
import os.path
import time
import logging

from ganeti import constants
from ganeti import errors # pylint: disable=W0611
from ganeti import utils
from ganeti import objects
from ganeti import pathutils
from ganeti.hypervisor import hv_base
from ganeti.errors import HypervisorError


class LXCHypervisor(hv_base.BaseHypervisor):
  """LXC-based virtualization.

  TODO:
    - move hardcoded parameters into hypervisor parameters, once we
      have the container-parameter support

  Problems/issues:
    - LXC is very temperamental; in daemon mode, it succeeds or fails
      in launching the instance silently, without any error
      indication, and when failing it can leave network interfaces
      around, and future successful startups will list the instance
      twice

  """
  _ROOT_DIR = pathutils.RUN_DIR + "/lxc"
  _CGROUP_ROOT_DIR = _ROOT_DIR + "/cgroup"
  _DEVS = [
    "c 1:3",   # /dev/null
    "c 1:5",   # /dev/zero
    "c 1:7",   # /dev/full
    "c 1:8",   # /dev/random
    "c 1:9",   # /dev/urandom
    "c 1:10",  # /dev/aio
    "c 5:0",   # /dev/tty
    "c 5:1",   # /dev/console
    "c 5:2",   # /dev/ptmx
    "c 136:*", # first block of Unix98 PTY slaves
    ]
  _DENIED_CAPABILITIES = [
    "mac_override",    # Allow MAC configuration or state changes
    # TODO: remove sys_admin too, for safety
    #"sys_admin",       # Perform  a range of system administration operations
    "sys_boot",        # Use reboot(2) and kexec_load(2)
    "sys_module",      # Load  and  unload kernel modules
    "sys_time",        # Set  system  clock, set real-time (hardware) clock
    ]
  _DIR_MODE = 0755

  PARAMETERS = {
    constants.HV_CPU_MASK: hv_base.OPT_CPU_MASK_CHECK,
    }

  def __init__(self):
    hv_base.BaseHypervisor.__init__(self)
    utils.EnsureDirs([(self._ROOT_DIR, self._DIR_MODE)])

  @staticmethod
  def _GetMountSubdirs(path):
    """Return the list of mountpoints under a given path.

    """
    result = []
    for _, mountpoint, _, _ in utils.GetMounts():
      if (mountpoint.startswith(path) and
          mountpoint != path):
        result.append(mountpoint)

    result.sort(key=lambda x: x.count("/"), reverse=True)
    return result

  @classmethod
  def _InstanceDir(cls, instance_name):
    """Return the root directory for an instance.

    """
    return utils.PathJoin(cls._ROOT_DIR, instance_name)

  @classmethod
  def _InstanceConfFile(cls, instance_name):
    """Return the configuration file for an instance.

    """
    return utils.PathJoin(cls._ROOT_DIR, instance_name + ".conf")

  @classmethod
  def _InstanceLogFile(cls, instance_name):
    """Return the log file for an instance.

    """
    return utils.PathJoin(cls._ROOT_DIR, instance_name + ".log")

  def _MountCgroupSubsystem(self, subsystem):
    """Mount cgroup subsystem fs under the cgruop_root

    """
    cgroup_root = self._GetCgroupMountPoint()
    if not os.path.isdir(cgroup_root):
      os.mkdir(cgroup_root)

    subsys_dir = utils.PathJoin(cgroup_root, subsystem)
    if os.path.isdir(subsys_dir):
      # Check if cgroup subsystem is already mounted at this point
      if os.path.ismount(subsys_dir) and \
         any(x[1] == subsys_dir and x[2] == 'cgroup' and subsystem in x[3].split(',')
             for x in utils.GetMounts()):
        return subsys_dir
    else:
      os.mkdir(subsys_dir) # TODO should be makedirs?

    mount_cmd = ['mount', '-t', 'cgroup', '-o', subsystem, subsystem, subsys_dir]
    result = utils.RunCmd(mount_cmd)
    if result.failed:
      raise HypervisorError("Running %s failed: %s" % (' '.join(mount_cmd), result.output))

    return subsys_dir

  def CleanupCgroupMounts(self):
    for subsys_dir in self._GetMountSubdirs(self._GetCgroupMountPoint()):
      umount_cmd = ['umount', subsys_dir]
      result = utils.RunCmd(umount_cmd)
      if result.failed:
        logging.warn("Running %s failed: %s", umount_cmd, result.output)

  @classmethod
  def _GetCgroupMountPoint(cls):
    return cls._CGROUP_ROOT_DIR

  @classmethod
  def _GetCgroupSubsystemMountPoint(cls, subsystem):
    # TODO: consider more better way
    return os.path.join(cls._GetCgroupMountPoint(), subsystem)

  def _GetCgroupCpuList(self, instance_name):
    """Return the list of CPU ids for an instance.

    """
    cgroup = self._MountCgroupSubsystem('cpuset')
    try:
      cpus = utils.ReadFile(utils.PathJoin(cgroup, 'lxc',
                                           instance_name,
                                           "cpuset.cpus"))
    except EnvironmentError, err:
      raise errors.HypervisorError("Getting CPU list for instance"
                                   " %s failed: %s" % (instance_name, err))

    return utils.ParseCpuMask(cpus)

  def _GetCgroupMemoryLimit(self, instance_name):
    """Return the memory limit for an instance

    """
    cgroup = self._MountCgroupSubsystem('memory')
    try:
      memory = int(utils.ReadFile(utils.PathJoin(cgroup, 'lxc',
                                                 instance_name,
                                                 "memory.limit_in_bytes")))
    except EnvironmentError:
      # memory resource controller may be disabled, ignore
      memory = 0

    return memory

  def ListInstances(self, hvparams=None):
    """Get the list of running instances.

    """
    return [iinfo[0] for iinfo in self.GetAllInstancesInfo()]

  def GetInstanceInfo(self, instance_name, hvparams=None):
    """Get instance properties.

    @type instance_name: string
    @param instance_name: the instance name
    @type hvparams: dict of strings
    @param hvparams: hvparams to be used with this instance
    @rtype: tuple of strings
    @return: (name, id, memory, vcpus, stat, times)

    """
    # TODO: read container info from the cgroup mountpoint

    result = utils.RunCmd(["lxc-info", "-s", "-n", instance_name])
    if result.failed:
      raise errors.HypervisorError("Running lxc-info failed: %s" %
                                   result.output)
    # lxc-info output examples:
    # 'state: STOPPED
    # 'state: RUNNING
    _, state = result.stdout.rsplit(None, 1)
    if state != "RUNNING":
      return None

    cpu_list = self._GetCgroupCpuList(instance_name)
    memory = self._GetCgroupMemoryLimit(instance_name) / (1024 ** 2)
    return (instance_name, 0, memory, len(cpu_list),
            hv_base.HvInstanceState.RUNNING, 0)

  def GetAllInstancesInfo(self, hvparams=None):
    """Get properties of all instances.

    @type hvparams: dict of strings
    @param hvparams: hypervisor parameter
    @return: [(name, id, memory, vcpus, stat, times),...]

    """
    data = []
    for name in os.listdir(self._ROOT_DIR):
      try:
        info = self.GetInstanceInfo(name)
      except errors.HypervisorError:
        continue
      if info:
        data.append(info)
    return data

  def _CreateConfigFile(self, instance, root_dir):
    """Create an lxc.conf file for an instance.

    """
    out = []
    # hostname
    out.append("lxc.utsname = %s" % instance.name)

    # separate pseudo-TTY instances
    out.append("lxc.pts = 255")
    # standard TTYs
    out.append("lxc.tty = 6")
    # console log file
    console_log = utils.PathJoin(self._ROOT_DIR, instance.name + ".console")
    try:
      utils.WriteFile(console_log, data="", mode=constants.SECURE_FILE_MODE)
    except EnvironmentError, err:
      raise errors.HypervisorError("Creating console log file %s for"
                                   " instance %s failed: %s" %
                                   (console_log, instance.name, err))
    out.append("lxc.console = %s" % console_log)

    # root FS
    out.append("lxc.rootfs = %s" % root_dir)

    # TODO: additional mounts, if we disable CAP_SYS_ADMIN

    # CPUs
    if instance.hvparams[constants.HV_CPU_MASK]:
      cpu_list = utils.ParseCpuMask(instance.hvparams[constants.HV_CPU_MASK])
      cpus_in_mask = len(cpu_list)
      if cpus_in_mask != instance.beparams["vcpus"]:
        raise errors.HypervisorError("Number of VCPUs (%d) doesn't match"
                                     " the number of CPUs in the"
                                     " cpu_mask (%d)" %
                                     (instance.beparams["vcpus"],
                                      cpus_in_mask))
      out.append("lxc.cgroup.cpuset.cpus = %s" %
                 instance.hvparams[constants.HV_CPU_MASK])

    # Memory
    # Conditionally enable, memory resource controller might be disabled
    cgroup = self._MountCgroupSubsystem('memory')
    if os.path.exists(utils.PathJoin(cgroup, 'memory.limit_in_bytes')):
      out.append("lxc.cgroup.memory.limit_in_bytes = %dM" %
                 instance.beparams[constants.BE_MAXMEM])

    if os.path.exists(utils.PathJoin(cgroup, 'memory.memsw.limit_in_bytes')):
      out.append("lxc.cgroup.memory.memsw.limit_in_bytes = %dM" %
                 instance.beparams[constants.BE_MAXMEM])

    # Device control
    # deny direct device access
    out.append("lxc.cgroup.devices.deny = a")
    for devinfo in self._DEVS:
      out.append("lxc.cgroup.devices.allow = %s rw" % devinfo)

    # Networking
    for idx, nic in enumerate(instance.nics):
      out.append("# NIC %d" % idx)
      mode = nic.nicparams[constants.NIC_MODE]
      link = nic.nicparams[constants.NIC_LINK]
      if mode == constants.NIC_MODE_BRIDGED:
        out.append("lxc.network.type = veth")
        out.append("lxc.network.link = %s" % link)
      else:
        raise errors.HypervisorError("LXC hypervisor only supports"
                                     " bridged mode (NIC %d has mode %s)" %
                                     (idx, mode))
      out.append("lxc.network.hwaddr = %s" % nic.mac)
      out.append("lxc.network.flags = up")

    # Capabilities
    for cap in self._DENIED_CAPABILITIES:
      out.append("lxc.cap.drop = %s" % cap)

    return "\n".join(out) + "\n"

  def StartInstance(self, instance, block_devices, startup_paused):
    """Start an instance.

    For LXC, we try to mount the block device and execute 'lxc-start'.
    We use volatile containers.

    """
    root_dir = self._InstanceDir(instance.name)
    try:
      utils.EnsureDirs([(root_dir, self._DIR_MODE)])
    except errors.GenericError, err:
      raise HypervisorError("Creating instance directory failed: %s", str(err))

    conf_file = self._InstanceConfFile(instance.name)
    utils.WriteFile(conf_file, data=self._CreateConfigFile(instance, root_dir))

    log_file = self._InstanceLogFile(instance.name)
    if not os.path.exists(log_file):
      try:
        utils.WriteFile(log_file, data="", mode=constants.SECURE_FILE_MODE)
      except EnvironmentError, err:
        raise errors.HypervisorError("Creating hypervisor log file %s for"
                                     " instance %s failed: %s" %
                                     (log_file, instance.name, err))

    if not os.path.ismount(root_dir):
      if not block_devices:
        raise HypervisorError("LXC needs at least one disk")

      sda_dev_path = block_devices[0][1]
      result = utils.RunCmd(["mount", sda_dev_path, root_dir])
      if result.failed:
        raise HypervisorError("Mounting the root dir of LXC instance %s"
                              " failed: %s" % (instance.name, result.output))
    result = utils.RunCmd(["lxc-start", "-n", instance.name,
                           "-o", log_file,
                           "-l", "DEBUG",
                           "-f", conf_file, "-d"])
    if result.failed:
      raise HypervisorError("Running the lxc-start script failed: %s" %
                            result.output)

  def StopInstance(self, instance, force=False, retry=False, name=None,
                   timeout=None):
    """Stop an instance.

    This method has complicated cleanup tests, as we must:
      - try to kill all leftover processes
      - try to unmount any additional sub-mountpoints
      - finally unmount the instance dir

    """
    assert(timeout is None or force is not None)

    if name is None:
      name = instance.name

    stop_cmd = []
    if timeout is not None:
      stop_cmd.extend(["timeout", str(timeout)])

    root_dir = self._InstanceDir(name)
    if not os.path.exists(root_dir):
      return

    if name in self.ListInstances():
      # Signal init to shutdown; this is a hack
      if not retry and not force:
        result = utils.RunCmd(["chroot", root_dir, "poweroff"])
        if result.failed:
          logging.warn("Running 'poweroff' on the instance failed: %s",
                       result.output)
      time.sleep(2)
      stop_cmd.extend(["lxc-stop", "-n", name])
      result = utils.RunCmd(stop_cmd)
      if result.failed:
        logging.warning("Error while doing lxc-stop for %s: %s", name,
                        result.output)

    if not os.path.ismount(root_dir):
      return

    for mpath in self._GetMountSubdirs(root_dir):
      stop_cmd.extend(["umount", mpath])
      result = utils.RunCmd(stop_cmd)
      if result.failed:
        logging.warning("Error while umounting subpath %s for instance %s: %s",
                        mpath, name, result.output)

    stop_cmd.extend(["umount", root_dir])
    result = utils.RunCmd(stop_cmd)
    if result.failed and force:
      msg = ("Processes still alive in the chroot: %s" %
             utils.RunCmd("fuser -vm %s" % root_dir).output)
      logging.error(msg)
      raise HypervisorError("Unmounting the chroot dir failed: %s (%s)" %
                            (result.output, msg))

  def RebootInstance(self, instance):
    """Reboot an instance.

    This is not (yet) implemented (in Ganeti) for the LXC hypervisor.

    """
    # TODO: implement reboot
    raise HypervisorError("The LXC hypervisor doesn't implement the"
                          " reboot functionality")

  def BalloonInstanceMemory(self, instance, mem):
    """Balloon an instance memory to a certain value.

    @type instance: L{objects.Instance}
    @param instance: instance to be accepted
    @type mem: int
    @param mem: actual memory size to use for instance runtime

    """
    # Currently lxc instances don't have memory limits
    pass

  def GetNodeInfo(self, hvparams=None):
    """Return information about the node.

    See L{BaseHypervisor.GetLinuxNodeInfo}.

    """
    return self.GetLinuxNodeInfo()

  @classmethod
  def GetInstanceConsole(cls, instance, primary_node, node_group,
                         hvparams, beparams):
    """Return a command for connecting to the console of an instance.

    """
    ndparams = node_group.FillND(primary_node)
    return objects.InstanceConsole(instance=instance.name,
                                   kind=constants.CONS_SSH,
                                   host=primary_node.name,
                                   port=ndparams.get(constants.ND_SSH_PORT),
                                   user=constants.SSH_CONSOLE_USER,
                                   command=["lxc-console", "-n", instance.name])

  def Verify(self, hvparams=None):
    """Verify the hypervisor.

    For the LXC manager, it just checks the existence of the base dir.

    @type hvparams: dict of strings
    @param hvparams: hypervisor parameters to be verified against; not used here

    @return: Problem description if something is wrong, C{None} otherwise

    """
    msgs = []

    if not os.path.exists(self._ROOT_DIR):
      msgs.append("The required directory '%s' does not exist" %
                  self._ROOT_DIR)

    try:
      self._GetCgroupMountPoint()
    except errors.HypervisorError, err:
      msgs.append(str(err))

    return self._FormatVerifyResults(msgs)

  @classmethod
  def PowercycleNode(cls, hvparams=None):
    """LXC powercycle, just a wrapper over Linux powercycle.

    @type hvparams: dict of strings
    @param hvparams: hypervisor params to be used on this node

    """
    cls.LinuxPowercycle()

  def MigrateInstance(self, cluster_name, instance, target, live):
    """Migrate an instance.

    @type cluster_name: string
    @param cluster_name: name of the cluster
    @type instance: L{objects.Instance}
    @param instance: the instance to be migrated
    @type target: string
    @param target: hostname (usually ip) of the target node
    @type live: boolean
    @param live: whether to do a live or non-live migration

    """
    raise HypervisorError("Migration is not supported by the LXC hypervisor")

  def GetMigrationStatus(self, instance):
    """Get the migration status

    @type instance: L{objects.Instance}
    @param instance: the instance that is being migrated
    @rtype: L{objects.MigrationStatus}
    @return: the status of the current migration (one of
             L{constants.HV_MIGRATION_VALID_STATUSES}), plus any additional
             progress info that can be retrieved from the hypervisor

    """
    raise HypervisorError("Migration is not supported by the LXC hypervisor")
