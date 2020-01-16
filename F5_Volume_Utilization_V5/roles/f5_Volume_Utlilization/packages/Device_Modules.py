
import time
import sys
import pickle
import subprocess

import os,pickle
shared = {}
if os.path.getsize("/tmp/shared.pkl") > 0:
    with open("shared.pkl", "rb") as f:
        unpickler = pickle.Unpickler(f)
        shared = unpickler.load()
PROJECT_PATH = str(os.getcwd())
sys.path.insert(1, str(PROJECT_PATH) + r'/roles/F5_Device_Volume_Utilization/packages/')
from Modules_Frame import CiscoBaseConnection, CiscoFileTransfer, LinuxSSH, BaseConnection, TerminalServerSSH, LinuxFileTransfer

def path(PROJECT_PATH):
    sys.path.append(str(PROJECT_PATH) + '/library/')

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
new_mapper = {}
for k, v in CLASS_MAPPER_BASE.items():
    new_mapper[k] = v
    alt_key = k + "_ssh"
    new_mapper[alt_key] = v
CLASS_MAPPER = new_mapper


new_mapper = {}

CLASS_MAPPER["terminal_server"] = TerminalServerSSH
#CLASS_MAPPER["autodetect"] = TerminalServerSSH

platforms = list(CLASS_MAPPER.keys())
platforms.sort()
platforms_base = list(CLASS_MAPPER_BASE.keys())
platforms_base.sort()
platforms_str = "\n".join(platforms_base)
platforms_str = "\n" + platforms_str

