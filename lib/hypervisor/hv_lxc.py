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
import logging

from ganeti import constants
from ganeti import errors # pylint: disable=W0611
from ganeti import utils
from ganeti import objects
from ganeti import pathutils
from ganeti import serializer
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
    constants.HV_LXC_WAIT_TIMEOUT: hv_base.OPT_NONNEGATIVE_INT_CHECK,
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

  @classmethod
  def _InstanceStashFile(cls, instance_name):
    """Return the stash file for an instance.

    Stash file is used to keep informations that needs to complete
    instance destruction during instance life.
    """
    return utils.PathJoin(cls._ROOT_DIR, instance_name + ".stash")

  def _SaveInstanceStash(self, instance_name, data):
    """Save data to instance stash file in serialized format

    """
    stash_file = self._InstanceStashFile(instance_name)
    serialized = serializer.Dump(data)
    try:
      utils.WriteFile(stash_file, data=serialized,
                      mode=constants.SECURE_FILE_MODE)
    except EnvironmentError, err:
      raise HypervisorError("Failed to save instance stash file %s : %s" %
                            (stash_file, err))

  def _LoadInstanceStash(self, instance_name):
    """Load stashed informations in file which was created by
    L{_SaveInstanceStash}

    """
    stash_file = self._InstanceStashFile(instance_name)
    try:
      return serializer.Load(utils.ReadFile(stash_file))
    except EnvironmentError, err:
      raise HypervisorError("Failed to load instance stash file %s : %s" %
                            (stash_file, err))

  @classmethod
  def _MountCgroupSubsystem(cls, subsystem):
    """Mount cgroup subsystem fs under the cgruop_root

    """
    subsys_dir = utils.PathJoin(cls._GetCgroupMountPoint(), subsystem)
    if not os.path.isdir(subsys_dir):
      try:
        os.makedirs(subsys_dir)
      except EnvironmentError, err:
        raise HypervisorError("Failed to create directory %s: %s" %
                              (subsys_dir, err))

    mount_cmd = ["mount", "-t", "cgroup", "-o", subsystem, subsystem,
                 subsys_dir]
    result = utils.RunCmd(mount_cmd)
    if result.failed:
      raise HypervisorError("Failed to mount cgroup subsystem '%s': %s" %
                            (subsystem, result.output))

    return subsys_dir

  @classmethod
  def _RecursiveUnmount(cls, path):
    mount_paths = cls._GetMountSubdirs(path)
    mount_paths.append(path)

    for path in mount_paths:
      umount_cmd = ["umount", path]
      result = utils.RunCmd(umount_cmd)
      if result.failed:
        raise errors.CommandError("Running %s failed : %s" %
                                  (umount_cmd, result.output))

  def _UnmountInstanceDir(self, instance_name):
    root_dir = self._InstanceDir(instance_name)
    if os.path.ismount(root_dir):
      try:
        self._RecursiveUnmount(root_dir)
      except errors.CommandError:
        msg = ("Processes still alive inside the container: %s" %
               utils.RunCmd("fuser -vm %s" % root_dir).output)
        logging.error(msg)
        raise HypervisorError("Unmounting the instance root dir failed : %s" %
                              msg)

  def _CleanupInstance(self, instance_name, stash):
    """Actual implementation of instance cleanup procedure

    """
    self._UnmountInstanceDir(instance_name)
    try:
      if "loopback-device" in stash:
        utils.ReleaseDiskImageDeviceMapper(stash["loopback-device"])
    except errors.CommandError, err:
      raise HypervisorError("Failed to cleanup partition mapping : %s" % err)

    utils.RemoveFile(self._InstanceStashFile(instance_name))

  def CleanupInstance(self, instance_name):
    """Cleanup after a stopped instance

    """
    try:
      stash = self._LoadInstanceStash(instance_name)
    except HypervisorError, err:
      logging.warn("%s", err)
      stash = {}

    self._CleanupInstance(instance_name, stash)

  @classmethod
  def _GetCgroupMountPoint(cls):
    return cls._CGROUP_ROOT_DIR

  @classmethod
  def _GetOrPrepareCgroupSubsysMountPoint(cls, subsystem):
    """Prepare cgroup subsystem mount point

    """
    for _, mpoint, fstype, options in utils.GetMounts():
      if fstype == "cgroup" and subsystem in options.split(","):
        return mpoint

    return cls._MountCgroupSubsystem(subsystem)

  @classmethod
  def _GetCgroupInstanceValue(cls, instance_name, subsystem, param):
    """Return the value of specified cgroup parameter

    """
    subsys_dir = cls._MountCgroupSubsystem(subsystem)
    param_file = utils.PathJoin(subsys_dir, "lxc", instance_name, param)
    return utils.ReadFile(param_file).rstrip("\n")

  @classmethod
  def _GetCgroupCpuList(cls, instance_name):
    """Return the list of CPU ids for an instance.

    """
    try:
      cpumask = cls._GetCgroupInstanceValue(instance_name,
                                            "cpuset", "cpuset.cpus")
    except EnvironmentError, err:
      raise errors.HypervisorError("Getting CPU list for instance"
                                   " %s failed: %s" % (instance_name, err))

    return utils.ParseCpuMask(cpumask)

  @classmethod
  def _GetCgroupMemoryLimit(cls, instance_name):
    """Return the memory limit for an instance

    """
    try:
      mem_limit = cls._GetCgroupInstanceValue(instance_name,
                                              "memory",
                                              "memory.limit_in_bytes")
      mem_limit = int(mem_limit)
    except EnvironmentError:
      # memory resource controller may be disabled, ignore
      mem_limit = 0

    return mem_limit

  def ListInstances(self, hvparams=None):
    """Get the list of running instances.

    """
    return [iinfo[0] for iinfo in self.GetAllInstancesInfo()]

  @classmethod
  def _IsInstanceAlive(cls, instance_name):
    """Return True if instance is alive

    """
    result = utils.RunCmd(["lxc-info", "-s", "-n", instance_name])
    if result.failed:
      raise HypervisorError("Running lxc-info failed: %s" % result.output)

    # lxc-info output examples:
    # 'state: STOPPED
    # 'state: RUNNING
    _, state = result.stdout.rsplit(None, 1)

    return state == "RUNNING"

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

    if not self._IsInstanceAlive(instance_name):
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
    uniq_suffix = ".conf"
    for filename in os.listdir(self._ROOT_DIR):
      if not filename.endswith(uniq_suffix):
        # listing all files in root directory will include instance root
        # directory, console file, and etc, so use .conf as a representation
        # of instance listings.
        continue
      try:
        info = self.GetInstanceInfo(filename[0:-len(uniq_suffix)])
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
    cgroup = self._GetOrPrepareCgroupSubsysMountPoint("memory")
    if os.path.exists(utils.PathJoin(cgroup, "memory.limit_in_bytes")):
      out.append("lxc.cgroup.memory.limit_in_bytes = %dM" %
                 instance.beparams[constants.BE_MAXMEM])

    if os.path.exists(utils.PathJoin(cgroup, "memory.memsw.limit_in_bytes")):
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

  @classmethod
  def _PrepareFileStorageForMount(cls, storage_path):
    try:
      (loop_dev, partition_devs) = \
        utils.CreateDiskImageDeviceMapper(storage_path)
    except errors.CommandError, err:
      raise HypervisorError("Failed to create partition mapping for %s"
                            " : %s" % (storage_path, err))

    return (loop_dev, partition_devs[0])

  @classmethod
  def _WaitInstanceState(cls, instance_name, state, timeout):
    """Wait instance state transition within timeout

    Return True if instance state is changed to state within timeout secs.
    """
    lxc_wait_cmd = ["timeout", str(timeout),
                    "lxc-wait", "-n", instance_name, "-s", state]
    result = utils.RunCmd(lxc_wait_cmd)
    if result.failed:
      if result.exit_code == 124: # exit with timeout
        return False
      else:
        raise HypervisorError("Failed to wait instance state transition: %s" %
                              result.output)
    else:
      return True

  def _SpawnLXC(self, instance, log_file, conf_file):
    """Execute lxc-start and wait until container health is confirmed

    """
    lxc_start_cmd = [
      "lxc-start",
      "-n", instance.name,
      "-o", log_file,
      "-l", "DEBUG",
      "-f", conf_file,
      "-d"
      ]

    result = utils.RunCmd(lxc_start_cmd)
    if result.failed:
      raise HypervisorError("Failed to start instance %s : %s" %
                            (instance.name, result.output))

    lxc_wait_timeout = instance.hvparams[constants.HV_LXC_WAIT_TIMEOUT]
    if not self._WaitInstanceState(instance.name, "RUNNING", lxc_wait_timeout):
      raise HypervisorError("Instance %s state didn't changed to RUNNING within"
                            " %s secs" % (instance.name, lxc_wait_timeout))

    # Ensure that the instance is running correctly after daemonized
    if not self._IsInstanceAlive(instance.name):
      raise HypervisorError("Failed to start instance %s :"
                            " lxc process exitted after daemonized" %
                            instance.name)

  def StartInstance(self, instance, block_devices, startup_paused):
    """Start an instance.

    For LXC, we try to mount the block device and execute 'lxc-start'.
    We use volatile containers.

    """
    stash = {}
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

    need_cleanup = False
    try:
      if not os.path.ismount(root_dir):
        if not block_devices:
          raise HypervisorError("LXC needs at least one disk")

        sda_dev_path = block_devices[0][1]
        # LXC needs to use partition mapping devices to access each partition
        # of the storage
        (loop_dev, root_part) = self._PrepareFileStorageForMount(sda_dev_path)
        stash["loopback-device"] = loop_dev
        sda_dev_path = root_part

        logging.info("Mounting rootfs %s", sda_dev_path)
        result = utils.RunCmd(["mount", sda_dev_path, root_dir])
        if result.failed:
          raise HypervisorError("Mounting the root dir of LXC instance %s"
                                " failed: %s" % (instance.name, result.output))

      logging.info("Starting LXC container")
      try:
        self._SpawnLXC(instance, log_file, conf_file)
      except:
        logging.error("Failed to start instance %s. Please take a look at %s to"
                      " see errors from LXC.", instance.name, log_file)
        raise
    except:
      need_cleanup = True
      raise
    finally:
      if need_cleanup:
        try:
          self._CleanupInstance(instance.name, stash)
        except HypervisorError, err:
          logging.warn("Cleanup for instance %s incomplete : %s",
                       instance.name, err)

    self._SaveInstanceStash(instance.name, stash)

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

    if self._IsInstanceAlive(instance.name):
      if force:
        result = utils.RunCmd(["lxc-stop", "-n", name])
        if result.failed:
          raise HypervisorError("Failed to run lxc-stop for instance %s: %s" %
                                (name, result.output))
      else:
        # TODO should use lxc-shutdown
        # Avoid to run poweroff command on host
        root_dir = self._InstanceDir(name)
        if not retry and os.path.ismount(root_dir):
          poweroff_cmd = []
          if timeout is not None:
            poweroff_cmd.extend(["timeout", str(timeout)])
          # Signal init to shutdown; this is a hack
          poweroff_cmd.extend(["chroot", root_dir, "poweroff"])
          result = utils.RunCmd(poweroff_cmd)
          if result.failed:
            logging.warn("Running 'poweroff' on the instance failed: %s",
                         result.output)
        else:
          logging.warn("Nothing can do to gracefully shutdown instance %s",
                       name)

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
