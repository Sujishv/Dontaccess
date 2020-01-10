import hashlib
import io
import os
import re
import sys
import time
import imp
import os,sys
import sys
import pickle
import subprocess

# cmd = "echo $MY_ENV_VARIABLE"
# PROJECT_PATH = os.system(cmd)
# print(PROJECT_PATH)
import os,pickle
shared = {}
if os.path.getsize("/tmp/shared.pkl") > 0:
    with open("shared.pkl", "rb") as f:
        unpickler = pickle.Unpickler(f)
        shared = unpickler.load()
PROJECT_PATH = str(os.getcwd())
print(PROJECT_PATH)
sys.path.insert(1, str(PROJECT_PATH) + r'/packages/')
#C:\Users\AnirudhSomanchi\Desktop\Ansible and Ruby Scripts\Ansible and Ruby Scripts\Working_Scripts\Scripts\Ansible\Main\Test_Ansible_Module_Framework\library\Modules_Frame.py
# CiscoBaseConnection = imp.load_source('CiscoBaseConnection', str(PROJECT_PATH)+r'/library/Modules_Frame.py')
# CiscoFileTransfer = imp.load_source('CiscoFileTransfer', str(PROJECT_PATH)+r'/library/Modules_Frame.py')
# LinuxSSH = imp.load_source('LinuxSSH', str(PROJECT_PATH)+r'/library/Modules_Frame.py')
# BaseConnection = imp.load_source('BaseConnection', str(PROJECT_PATH)+r'/library/Modules_Frame.py')
# TerminalServerSSH = imp.load_source('TerminalServerSSH', str(PROJECT_PATH)+r'/library/Modules_Frame.py')
# LinuxFileTransfer = imp.load_source('LinuxFileTransfer', str(PROJECT_PATH)+r'/library/Modules_Frame.py')
from Modules_Frame import CiscoBaseConnection, CiscoFileTransfer, LinuxSSH, BaseConnection, TerminalServerSSH, LinuxFileTransfer

def path(PROJECT_PATH):
    sys.path.append(str(PROJECT_PATH) + '/library/')

    # from Modules_Frame import CiscoBaseConnection, CiscoFileTransfer, LinuxSSH, BaseConnection, TerminalServerSSH, LinuxFileTransfer
###################################################################################################################
# Redispatch and Connection Handler
####################################################################################################################

def ConnectHandler(*args, **kwargs):
    """Factory function selects the proper class and creates object based on device_type."""
    if kwargs["device_type"] not in platforms:
        raise ValueError(
            "Unsupported device_type: "
            "currently supported platforms are: {}".format(platforms_str)
        )
    ConnectionClass = ssh_dispatcher(kwargs["device_type"])
    return ConnectionClass(*args, **kwargs)

def ssh_dispatcher(device_type):
    """Select the class to be instantiated based on vendor/platform."""
    return CLASS_MAPPER[device_type]

def redispatch(obj, device_type, session_prep=True):
    """Dynamically change Net_Connect object's class to proper class.
    Generally used with terminal_server device_type when you need to redispatch after interacting
    with terminal server.
    """
    new_class = ssh_dispatcher(device_type)
    obj.device_type = device_type
    obj.__class__ = new_class
    if session_prep:
        obj._try_session_preparation()

#######################################################################################################################

#Cisco
#######################################################################################################################


class CiscoIosBase(CiscoBaseConnection):
    """Common Methods for IOS (both SSH and telnet)."""

    def session_preparation(self):
        """Prepare the session after the connection has been established."""
        self._test_channel_read(pattern=r"[>#]")
        self.set_base_prompt()
        self.disable_paging()
        self.set_terminal_width(command="terminal width 511")
        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    def check_config_mode(self, check_string=")#", pattern="#"):
        """
        Checks if the device is in configuration mode or not.

        Cisco IOS devices abbreviate the prompt at 20 chars in config mode
        """
        return super(CiscoIosBase, self).check_config_mode(
            check_string=check_string, pattern=pattern
        )

    def save_config(self, cmd="write mem", confirm=False, confirm_response=""):
        """Saves Config Using Copy Run Start"""
        return super(CiscoIosBase, self).save_config(
            cmd=cmd, confirm=confirm, confirm_response=confirm_response
        )


class CiscoIosSSH(CiscoIosBase):
    """Cisco IOS SSH driver."""

    pass

#
# class CiscoIosTelnet(CiscoIosBase):
#     """Cisco IOS Telnet driver."""
#
#     pass
#
#
# class CiscoIosSerial(CiscoIosBase):
#     """Cisco IOS Serial driver."""
#
#     pass
#
#
# class CiscoIosFileTransfer(CiscoFileTransfer):
#     """Cisco IOS SCP File Transfer driver."""
#
#     pass
#
#
# class InLineTransfer(CiscoIosFileTransfer):
#     """Use TCL on Cisco IOS to directly transfer file."""
#
#     def __init__(
#         self,
#         ssh_conn,
#         source_file=None,
#         dest_file=None,
#         file_system=None,
#         direction="put",
#         source_config=None,
#     ):
#         if source_file and source_config:
#             msg = "Invalid call to InLineTransfer both source_file and source_config specified."
#             raise ValueError(msg)
#         if direction != "put":
#             raise ValueError("Only put operation supported by InLineTransfer.")
#
#         self.ssh_ctl_chan = ssh_conn
#         if source_file:
#             self.source_file = source_file
#             self.source_config = None
#             self.source_md5 = self.file_md5(source_file)
#             self.file_size = os.stat(source_file).st_size
#         elif source_config:
#             self.source_file = None
#             self.source_config = source_config
#             self.source_md5 = self.config_md5(source_config)
#             self.file_size = len(source_config.encode("UTF-8"))
#         self.dest_file = dest_file
#         self.direction = direction
#
#         if not file_system:
#             self.file_system = self.ssh_ctl_chan._autodetect_fs()
#         else:
#             self.file_system = file_system
#
#     @staticmethod
#     def _read_file(file_name):
#         with io.open(file_name, "rt", encoding="utf-8") as f:
#             return f.read()
#
#     @staticmethod
#     def _tcl_newline_rationalize(tcl_string):
#         """
#         When using put inside a TCL {} section the newline is considered a new TCL
#         statement and causes a missing curly-brace message. Convert "\n" to "\r". TCL
#         will convert the "\r" to a "\n" i.e. you will see a "\n" inside the file on the
#         Cisco IOS device.
#         """
#         NEWLINE = r"\n"
#         CARRIAGE_RETURN = r"\r"
#         tmp_string = re.sub(NEWLINE, CARRIAGE_RETURN, tcl_string)
#         if re.search(r"[{}]", tmp_string):
#             msg = "Curly brace detected in string; TCL requires this be escaped."
#             raise ValueError(msg)
#         return tmp_string
#
#     def __enter__(self):
#         self._enter_tcl_mode()
#         return self
#
#     def __exit__(self, exc_type, exc_value, traceback):
#         _ = self._exit_tcl_mode()  # noqa
#
#     def _enter_tcl_mode(self):
#         TCL_ENTER = "tclsh"
#         cmd_failed = ['Translating "tclsh"', "% Unknown command", "% Bad IP address"]
#         output = self.ssh_ctl_chan.send_command(
#             TCL_ENTER,
#             expect_string=r"\(tcl\)#",
#             strip_prompt=False,
#             strip_command=False,
#         )
#         for pattern in cmd_failed:
#             if pattern in output:
#                 raise ValueError(
#                     "Failed to enter tclsh mode on router: {}".format(output)
#                 )
#         return output
#
#     def _exit_tcl_mode(self):
#         TCL_EXIT = "tclquit"
#         self.ssh_ctl_chan.write_channel("\r")
#         time.sleep(1)
#         output = self.ssh_ctl_chan.read_channel()
#         if "(tcl)" in output:
#             self.ssh_ctl_chan.write_channel(TCL_EXIT + "\r")
#         time.sleep(1)
#         output += self.ssh_ctl_chan.read_channel()
#         return output
#
#     def establish_scp_conn(self):
#         raise NotImplementedError
#
#     def close_scp_chan(self):
#         raise NotImplementedError
#
#     def local_space_available(self):
#         raise NotImplementedError
#
#     def file_md5(self, file_name):
#         """Compute MD5 hash of file."""
#         file_contents = self._read_file(file_name)
#         file_contents = file_contents + "\n"  # Cisco IOS automatically adds this
#         file_contents = file_contents.encode("UTF-8")
#         return hashlib.md5(file_contents).hexdigest()
#
#     def config_md5(self, source_config):
#         """Compute MD5 hash of file."""
#         file_contents = source_config + "\n"  # Cisco IOS automatically adds this
#         file_contents = file_contents.encode("UTF-8")
#         return hashlib.md5(file_contents).hexdigest()
#
#     def put_file(self):
#         curlybrace = r"{"
#         TCL_FILECMD_ENTER = 'puts [open "{}{}" w+] {}'.format(
#             self.file_system, self.dest_file, curlybrace
#         )
#         TCL_FILECMD_EXIT = "}"
#
#         if self.source_file:
#             file_contents = self._read_file(self.source_file)
#         elif self.source_config:
#             file_contents = self.source_config
#         file_contents = self._tcl_newline_rationalize(file_contents)
#
#         # Try to remove any existing data
#         self.ssh_ctl_chan.clear_buffer()
#
#         self.ssh_ctl_chan.write_channel(TCL_FILECMD_ENTER)
#         time.sleep(0.25)
#         self.ssh_ctl_chan.write_channel(file_contents)
#         self.ssh_ctl_chan.write_channel(TCL_FILECMD_EXIT + "\r")
#
#         # This operation can be slow (depends on the size of the file)
#         max_loops = 400
#         sleep_time = 4
#         if self.file_size >= 2500:
#             max_loops = 1500
#             sleep_time = 12
#         elif self.file_size >= 7500:
#             max_loops = 3000
#             sleep_time = 25
#
#         # Initial delay
#         time.sleep(sleep_time)
#
#         # File paste and TCL_FILECMD_exit should be indicated by "router(tcl)#"
#         output = self.ssh_ctl_chan._read_channel_expect(
#             pattern=r"\(tcl\)", max_loops=max_loops
#         )
#
#         # The file doesn't write until tclquit
#         TCL_EXIT = "tclquit"
#         self.ssh_ctl_chan.write_channel(TCL_EXIT + "\r")
#
#         time.sleep(1)
#         # Read all data remaining from the TCLSH session
#         output += self.ssh_ctl_chan._read_channel_expect(max_loops=max_loops)
#         return output
#
#     def get_file(self):
#         raise NotImplementedError
#
#     def enable_scp(self, cmd=None):
#         raise NotImplementedError
#
#     def disable_scp(self, cmd=None):
#         raise NotImplementedError



#######################################################################################################################

#F5
#######################################################################################################################

class F5LinuxSSH(LinuxSSH):
    pass

class F5LtmSSH(BaseConnection):
    def session_preparation(self):
        """Prepare the session after the connection has been established."""
        self._test_channel_read()
        self.set_base_prompt()
        self.tmsh_mode()
        self.set_base_prompt()
        self.disable_paging(
            command="modify cli preference pager disabled display-threshold 0"
        )
        self.clear_buffer()
        cmd = 'run /util bash -c "stty cols 255"'
        self.set_terminal_width(command=cmd)

    def tmsh_mode(self, delay_factor=5):
        """tmsh command is equivalent to config command on F5."""
        delay_factor = self.select_delay_factor(delay_factor)
        self.clear_buffer()
        command = "{}tmsh{}".format(self.RETURN, self.RETURN)
        self.write_channel(command)
        time.sleep(1 * delay_factor)
        self.clear_buffer()
        return None


class F5TmshSSH(BaseConnection):
    def session_preparation(self):
        """Prepare the session after the connection has been established."""
        self._test_channel_read()
        self.set_base_prompt()
        self.tmsh_mode()
        self.set_base_prompt()
        self.disable_paging(
            command="modify cli preference pager disabled display-threshold 0"
        )
        self.clear_buffer()
        cmd = 'run /util bash -c "stty cols 255"'
        self.set_terminal_width(command=cmd)

    def tmsh_mode(self, delay_factor=5):
        """tmsh command is equivalent to config command on F5."""
        delay_factor = self.select_delay_factor(delay_factor)
        self.clear_buffer()
        command = "{}tmsh{}".format(self.RETURN, self.RETURN)
        self.write_channel(command)
        time.sleep(1 * delay_factor)
        self.clear_buffer()
        return None



###################################
# Network Variables
####################################
CLASS_MAPPER_BASE = {
    "generic_termserver": TerminalServerSSH,
    "cisco_ios": CiscoIosSSH,
    "terminal_server": TerminalServerSSH,
    "f5_ltm": F5TmshSSH,
    "f5_tmsh": F5TmshSSH,
    "f5_linux": F5LinuxSSH,
}
#
# FILE_TRANSFER_MAP = {
#     "cisco_ios": CiscoIosFileTransfer,
#     "linux": LinuxFileTransfer,
#     "terminal_server": TerminalServerSSH
# }
new_mapper = {}
for k, v in CLASS_MAPPER_BASE.items():
    new_mapper[k] = v
    alt_key = k + "_ssh"
    new_mapper[alt_key] = v
CLASS_MAPPER = new_mapper


new_mapper = {}
# for k, v in FILE_TRANSFER_MAP.items():
#     new_mapper[k] = v
#     alt_key = k + "_ssh"
#     new_mapper[alt_key] = v
# FILE_TRANSFER_MAP = new_mapper

CLASS_MAPPER["terminal_server"] = TerminalServerSSH
CLASS_MAPPER["autodetect"] = TerminalServerSSH

platforms = list(CLASS_MAPPER.keys())
platforms.sort()
platforms_base = list(CLASS_MAPPER_BASE.keys())
platforms_base.sort()
platforms_str = "\n".join(platforms_base)
platforms_str = "\n" + platforms_str
#
# scp_platforms = list(FILE_TRANSFER_MAP.keys())
# scp_platforms.sort()
# scp_platforms_str = "\n".join(scp_platforms)
# scp_platforms_str = "\n" + scp_platforms_str

