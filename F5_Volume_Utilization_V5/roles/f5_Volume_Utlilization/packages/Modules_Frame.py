from __future__ import unicode_literals
from __future__ import print_function
from __future__ import unicode_literals

import telnetlib
import textwrap,  re, io, paramiko,hashlib,copy,threading, socket,getopt,os, sys, time
from os import path
from collections import deque
from paramiko.pkey import PKey
from paramiko import file

from paramiko.ssh_exception import (
    SSHException,
    PasswordRequiredException,
    BadAuthenticationType,
    ChannelException,
    BadHostKeyException,
    AuthenticationException,
    )
from paramiko.client import (
    SSHClient,
    MissingHostKeyPolicy,
    AutoAddPolicy,
    RejectPolicy,
    WarningPolicy,
)

import logging

unicode = str

########################################################################################################################
# Log
########################################################################################################################
log = logging.getLogger(__name__)  # noqa
log.addHandler(logging.NullHandler())  # noqa

########################################################################################################################
# Variables
########################################################################################################################


SGR = {
    'reset': 0,
    'bold': 1,
    'underline': 4,
    'blink': 5,
    'negative': 7,
    'underline_off': 24,
    'blink_off': 25,
    'positive': 27,
    'black': 30,
    'red': 31,
    'green': 32,
    'yellow': 33,
    'blue': 34,
    'magenta': 35,
    'cyan': 36,
    'white': 37,
    'fg_reset': 39,
    'bg_black': 40,
    'bg_red': 41,
    'bg_green': 42,
    'bg_yellow': 43,
    'bg_blue': 44,
    'bg_magenta': 45,
    'bg_cyan': 46,
    'bg_white': 47,
    'bg_reset': 49,
    }

# Provide a familar descriptive word for some ansi sequences.
FG_COLOR_WORDS = {'black': ['black'],
                  'dark_gray': ['bold', 'black'],
                  'blue': ['blue'],
                  'light_blue': ['bold', 'blue'],
                  'green': ['green'],
                  'light_green': ['bold', 'green'],
                  'cyan': ['cyan'],
                  'light_cyan': ['bold', 'cyan'],
                  'red': ['red'],
                  'light_red': ['bold', 'red'],
                  'purple': ['magenta'],
                  'light_purple': ['bold', 'magenta'],
                  'brown': ['yellow'],
                  'yellow': ['bold', 'yellow'],
                  'light_gray': ['white'],
                  'white': ['bold', 'white']}

BG_COLOR_WORDS = {'black': ['bg_black'],
                  'red': ['bg_red'],
                  'green': ['bg_green'],
                  'yellow': ['bg_yellow'],
                  'dark_blue': ['bg_blue'],
                  'purple': ['bg_magenta'],
                  'light_blue': ['bg_cyan'],
                  'grey': ['bg_white']}

ANSI_START = '\001'
ANSI_END = '\002'


sgr_re = re.compile(r'(%s?\033\[\d+(?:;\d+)*m%s?)' % (
    ANSI_START, ANSI_END))


unicode = str
PY2 = sys.version_info.major == 2
PY3 = sys.version_info.major == 3
if PY3:
    string_types = (str,)
    text_type = str
    bufferedio_types = io.BufferedIOBase
else:
    string_types = (str,)  # noqa
    text_type = unicode  # noqa
    bufferedio_types = (io.BufferedIOBase, file)  # noqa  # paramiko

MAX_BUFFER = 65535
BACKSPACE_CHAR = "\x08"

LINUX_PROMPT_PRI = os.getenv("Net_Connect_LINUX_PROMPT_PRI", "$")
LINUX_PROMPT_ALT = os.getenv("Net_Connect_LINUX_PROMPT_ALT", "#")
LINUX_PROMPT_ROOT = os.getenv("Net_Connect_LINUX_PROMPT_ROOT", "#")



#################################################
# Network Base Connection
#################################################


class BaseConnection(object):
    """
    Defines vendor independent methods.

    Otherwise method left as a stub method.
    """
    def __init__(
        self,
        ip="",
        host="",
        username="",
        password=None,
        secret="",
        port=None,
        device_type="",
        verbose=False,
        global_delay_factor=5,
        use_keys=False,
        key_file=None,
        pkey=None,
        passphrase=None,
        allow_agent=False,
        ssh_strict=False,
        system_host_keys=False,
        alt_host_keys=False,
        alt_key_file="",
        ssh_config_file=None,
        timeout=100,
        session_timeout=60,
        auth_timeout=None,
        blocking_timeout=8,
        banner_timeout=5,
        keepalive=0,
        default_enter=None,
        response_return=None,
        serial_settings=None,
        fast_cli=False,
        session_log=None,
        session_log_record_writes=False,
        session_log_file_mode="write",
        allow_auto_change=False,
        encoding="ascii",
    ):

        self.remote_conn = None

        self.TELNET_RETURN = "\r\n"
        if default_enter is None:
            if "telnet" not in device_type:
                self.RETURN = "\n"
            else:
                self.RETURN = self.TELNET_RETURN
        else:
            self.RETURN = default_enter

        # Line Separator in response lines
        self.RESPONSE_RETURN = "\n" if response_return is None else response_return
        if ip:
            self.host = ip.strip()
        elif host:
            self.host = host.strip()
        if port is None:
            if "telnet" in device_type:
                port = 23
            else:
                port = 22
        self.port = int(port)

        self.username = username
        self.password = password
        self.secret = secret
        self.device_type = device_type
        self.ansi_escape_codes = False
        self.verbose = verbose
        self.timeout = timeout
        self.auth_timeout = auth_timeout
        self.banner_timeout = banner_timeout
        self.session_timeout = session_timeout
        self.blocking_timeout = blocking_timeout
        self.keepalive = keepalive
        self.allow_auto_change = allow_auto_change
        self.encoding = encoding

        # Net_Connect will close the session_log if we open the file
        self.session_log = None
        self.session_log_record_writes = session_log_record_writes
        self._session_log_close = False
        # Ensures last write operations prior to disconnect are recorded.
        self._session_log_fin = False
        if session_log is not None:
            if isinstance(session_log, string_types):
                # If session_log is a string, open a file corresponding to string name.
                self.open_session_log(filename=session_log, mode=session_log_file_mode)
            elif isinstance(session_log, bufferedio_types):
                # In-memory buffer or an already open file handle
                self.session_log = session_log
            else:
                raise ValueError(
                    "session_log must be a path to a file, a file handle, "
                    "or a BufferedIOBase subclass."
                )

        self.fast_cli = fast_cli
        self.global_delay_factor = global_delay_factor
        if self.fast_cli and self.global_delay_factor == 5:
            self.global_delay_factor = 0.1

        # set in set_base_prompt method
        self.base_prompt = ""
        self._session_locker = threading.Lock()

        # determine if telnet or SSH
        if "_telnet" in device_type:
            self.protocol = "telnet"
            self.password = password or ""
        else:
            self.protocol = "ssh"

            if not ssh_strict:
                self.key_policy = AutoAddPolicy()
            else:
                self.key_policy = paramiko.RejectPolicy()

            # Options for SSH host_keys
            self.use_keys = use_keys
            self.key_file = key_file
            self.pkey = pkey
            self.passphrase = passphrase
            self.allow_agent = allow_agent
            self.system_host_keys = system_host_keys
            self.alt_host_keys = alt_host_keys
            self.alt_key_file = alt_key_file

            # For SSH proxy support
            self.ssh_config_file = ssh_config_file

        # Establish the remote connection
        self._open()

    def _open(self):
        """Decouple connection creation from __init__ for mocking."""
        self._modify_connection_params()
        self.establish_connection()
        self._try_session_preparation()

    def __enter__(self):
        """Establish a session using a Context Manager."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Gracefully close connection on Context Manager exit."""
        self.disconnect()

    def _modify_connection_params(self):
        """Modify connection parameters prior to SSH connection."""
        pass

    def _timeout_exceeded(self, start, msg="Timeout exceeded!"):
        """Raise Net_ConnectTimeoutException if waiting too much in the serving queue.

        :param start: Initial start time to see if session lock timeout has been exceeded
        :type start: float (from time.time() call i.e. epoch time)

        :param msg: Exception message if timeout was exceeded
        :type msg: str
        """
        if not start:
            # Must provide a comparison time
            return False
        if time.time() - start > self.session_timeout:
            # session_timeout exceeded
            raise Net_ConnectTimeoutException(msg)
        return False

    def _lock_Net_Connect_session(self, start=None):
        """Try to acquire the Net_Connect session lock. If not available, wait in the queue until
        the channel is available again.

        :param start: Initial start time to measure the session timeout
        :type start: float (from time.time() call i.e. epoch time)
        """
        if not start:
            start = time.time()
        # Wait here until the SSH channel lock is acquired or until session_timeout exceeded
        while not self._session_locker.acquire(False) and not self._timeout_exceeded(
            start, "The Net_Connect channel is not available!"
        ):
            time.sleep(0.1)
        return True

    def _unlock_Net_Connect_session(self):
        """
        Release the channel at the end of the task.
        """
        if self._session_locker.locked():
            self._session_locker.release()

    def _write_channel(self, out_data):
        """Generic handler that will write to both SSH and telnet channel.

        :param out_data: data to be written to the channel
        :type out_data: str (can be either unicode/byte string)
        """
        if self.protocol == "ssh":
            self.remote_conn.sendall(write_bytes(out_data, encoding=self.encoding))
        elif self.protocol == "telnet":
            self.remote_conn.write(write_bytes(out_data, encoding=self.encoding))
        else:
            raise ValueError("Invalid protocol specified")
        try:
            log.debug(
                "write_channel: {}".format(
                    write_bytes(out_data, encoding=self.encoding)
                )
            )
            if self._session_log_fin or self.session_log_record_writes:
                self._write_session_log(out_data)
        except UnicodeDecodeError:
            # Don't log non-ASCII characters; this is null characters and telnet IAC (PY2)
            pass

    def _write_session_log(self, data):
        if self.session_log is not None and len(data) > 0:
            # Hide the password and secret in the session_log
            if self.password:
                data = data.replace(self.password, "********")
            if self.secret:
                data = data.replace(self.secret, "********")
            self.session_log.write(write_bytes(data, encoding=self.encoding))
            self.session_log.flush()

    def write_channel(self, out_data):
        """Generic handler that will write to both SSH and telnet channel.

        :param out_data: data to be written to the channel
        :type out_data: str (can be either unicode/byte string)
        """
        self._lock_Net_Connect_session()
        try:
            self._write_channel(out_data)
        finally:
            # Always unlock the SSH channel, even on exception.
            self._unlock_Net_Connect_session()

    def is_alive(self):
        """Returns a boolean flag with the state of the connection."""
        null = chr(0)
        if self.remote_conn is None:
            log.error("Connection is not initialised, is_alive returns False")
            return False
        if self.protocol == "telnet":
            try:
                # Try sending IAC + NOP (IAC is telnet way of sending command)
                # IAC = Interpret as Command; it comes before the NOP.
                log.debug("Sending IAC + NOP")
                # Need to send multiple times to test connection
                self.remote_conn.sock.sendall(telnetlib.IAC + telnetlib.NOP)
                self.remote_conn.sock.sendall(telnetlib.IAC + telnetlib.NOP)
                self.remote_conn.sock.sendall(telnetlib.IAC + telnetlib.NOP)
                return True
            except AttributeError:
                return False
        else:
            # SSH
            try:
                # Try sending ASCII null byte to maintain the connection alive
                log.debug("Sending the NULL byte")
                self.write_channel(null)
                return self.remote_conn.transport.is_active()
            except (socket.error, EOFError):
                log.error("Unable to send", exc_info=True)
                # If unable to send, we can tell for sure that the connection is unusable
                return False
        return False

    def _read_channel(self):
        """Generic handler that will read all the data from an SSH or telnet channel."""
        if self.protocol == "ssh":
            output = ""
            while True:
                if self.remote_conn.recv_ready():
                    outbuf = self.remote_conn.recv(MAX_BUFFER)
                    if len(outbuf) == 0:
                        raise EOFError("Channel stream closed by remote device.")
                    output += outbuf.decode("utf-8", "ignore")
                else:
                    break
        elif self.protocol == "telnet":
            output = self.remote_conn.read_very_eager().decode("utf-8", "ignore")
        log.debug("read_channel: {}".format(output))
        self._write_session_log(output)
        return output

    def read_channel(self):
        """Generic handler that will read all the data from an SSH or telnet channel."""
        output = ""
        self._lock_Net_Connect_session()
        try:
            output = self._read_channel()
        finally:
            # Always unlock the SSH channel, even on exception.
            self._unlock_Net_Connect_session()
        return output

    def _read_channel_expect(self, pattern="", re_flags=0, max_loops=500):
        """Function that reads channel until pattern is detected.

        pattern takes a regular expression.

        By default pattern will be self.base_prompt

        Note: this currently reads beyond pattern. In the case of SSH it reads MAX_BUFFER.
        In the case of telnet it reads all non-blocking data.

        There are dependencies here like determining whether in config_mode that are actually
        depending on reading beyond pattern.

        :param pattern: Regular expression pattern used to identify the command is done \
        (defaults to self.base_prompt)
        :type pattern: str (regular expression)

        :param re_flags: regex flags used in conjunction with pattern to search for prompt \
        (defaults to no flags)
        :type re_flags: int

        :param max_loops: max number of iterations to read the channel before raising exception.
            Will default to be based upon self.timeout.
        :type max_loops: int
        """
        output = ""
        if not pattern:
            pattern = re.escape(self.base_prompt)
        log.debug("Pattern is: {}".format(pattern))

        i = 1
        loop_delay = 0.1
        # Default to making loop time be roughly equivalent to self.timeout (support old max_loops
        # argument for backwards compatibility).
        if max_loops == 500:
            max_loops = int(self.timeout / loop_delay)
        while i < max_loops:
            if self.protocol == "ssh":
                try:
                    # If no data available will wait timeout seconds trying to read
                    self._lock_Net_Connect_session()
                    new_data = self.remote_conn.recv(MAX_BUFFER)
                    if len(new_data) == 0:
                        raise EOFError("Channel stream closed by remote device.")
                    new_data = new_data.decode("utf-8", "ignore")
                    log.debug("_read_channel_expect read_data: {}".format(new_data))
                    output += new_data
                    self._write_session_log(new_data)
                except socket.timeout:
                    raise Net_ConnectTimeoutException(
                        "Timed-out reading channel, data not available."
                    )
                finally:
                    self._unlock_Net_Connect_session()
            if re.search(pattern, output, flags=re_flags):
                log.debug("Pattern found: {} {}".format(pattern, output))
                return output
            time.sleep(loop_delay * self.global_delay_factor)
            i += 1
        raise Net_ConnectTimeoutException(
            "Timed-out reading channel, pattern not found in output: {}".format(pattern)
        )

    def _read_channel_timing(self, delay_factor=1, max_loops=500):
        """Read data on the channel based on timing delays.

        Attempt to read channel max_loops number of times. If no data this will cause a 15 second
        delay.

        Once data is encountered read channel for another two seconds (2 * delay_factor) to make
        sure reading of channel is complete.

        :param delay_factor: multiplicative factor to adjust delay when reading channel (delays
            get multiplied by this factor)
        :type delay_factor: int or float

        :param max_loops: maximum number of loops to iterate through before returning channel data.
            Will default to be based upon self.timeout.
        :type max_loops: int
        """
        # Time to delay in each read loop
        loop_delay = 0.1
        final_delay = 2

        # Default to making loop time be roughly equivalent to self.timeout (support old max_loops
        # and delay_factor arguments for backwards compatibility).
        delay_factor = self.select_delay_factor(delay_factor)
        if delay_factor == 1 and max_loops == 150:
            max_loops = int(self.timeout / loop_delay)

        channel_data = ""
        i = 0
        while i <= max_loops:
            time.sleep(loop_delay * delay_factor)
            new_data = self.read_channel()
            if new_data:
                channel_data += new_data
            else:
                # Safeguard to make sure really done
                time.sleep(final_delay * delay_factor)
                new_data = self.read_channel()
                if not new_data:
                    break
                else:
                    channel_data += new_data
            i += 1
        return channel_data

    def read_until_prompt(self, *args, **kwargs):
        """Read channel until self.base_prompt detected. Return ALL data available."""
        return self._read_channel_expect(*args, **kwargs)

    def read_until_pattern(self, *args, **kwargs):
        """Read channel until pattern detected. Return ALL data available."""
        return self._read_channel_expect(*args, **kwargs)

    def read_until_prompt_or_pattern(self, pattern="", re_flags=0):
        """Read until either self.base_prompt or pattern is detected.

        :param pattern: the pattern used to identify that the output is complete (i.e. stop \
        reading when pattern is detected). pattern will be combined with self.base_prompt to \
        terminate output reading when the first of self.base_prompt or pattern is detected.
        :type pattern: regular expression string

        :param re_flags: regex flags used in conjunction with pattern to search for prompt \
        (defaults to no flags)
        :type re_flags: int

        """
        combined_pattern = re.escape(self.base_prompt)
        if pattern:
            combined_pattern = r"({}|{})".format(combined_pattern, pattern)
        return self._read_channel_expect(combined_pattern, re_flags=re_flags)


    def telnet_login(
        self,
        pri_prompt_terminator=r"#\s*$",
        alt_prompt_terminator=r">\s*$",
        username_pattern=r"(?:user:|username|login|user name)",
        pwd_pattern=r"assword",
        delay_factor=1,
        max_loops=20,
    ):

        delay_factor = self.select_delay_factor(delay_factor)
        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        i = 1
        while i <= max_loops:
            try:
                output = self.read_channel()
                return_msg += output

                # Search for username pattern / send username
                if re.search(username_pattern, output, flags=re.I):
                    self.write_channel(self.username + self.TELNET_RETURN)
                    time.sleep(1 * delay_factor)
                    output = self.read_channel()
                    return_msg += output

                # Search for password pattern / send password
                if re.search(pwd_pattern, output, flags=re.I):
                    self.write_channel(self.password + self.TELNET_RETURN)
                    time.sleep(0.5 * delay_factor)
                    output = self.read_channel()
                    return_msg += output
                    if re.search(
                        pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                    alt_prompt_terminator, output, flags=re.M
                ):
                    return return_msg

                self.write_channel(self.TELNET_RETURN)
                time.sleep(0.5 * delay_factor)
                i += 1
            except EOFError:
                self.remote_conn.close()
                msg = "Login failed: {}".format(self.host)
                raise Net_ConnectAuthenticationException(msg)

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
            alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        msg = "Login failed: {}".format(self.host)
        self.remote_conn.close()
        raise Net_ConnectAuthenticationException(msg)

    def _try_session_preparation(self):
        """
        In case of an exception happening during `session_preparation()` Net_Connect should
        gracefully clean-up after itself. This might be challenging for library users
        to do since they do not have a reference to the object. This is possibly related
        to threads used in Paramiko.
        """
        try:
            self.session_preparation()
        except Exception:
            self.disconnect()
            raise

    def session_preparation(self):
        self._test_channel_read()
        self.set_base_prompt()
        self.disable_paging()
        self.set_terminal_width()

        # Clear the read buffer
        time.sleep(0.3 * self.global_delay_factor)
        self.clear_buffer()

    def _use_ssh_config(self, dict_arg):
        """Update SSH connection parameters based on contents of SSH config file.

        :param dict_arg: Dictionary of SSH connection parameters
        :type dict_arg: dict
        """
        connect_dict = dict_arg.copy()

        # Use SSHConfig to generate source content.
        full_path = path.abspath(path.expanduser(self.ssh_config_file))
        if path.exists(full_path):
            ssh_config_instance = paramiko.SSHConfig()
            with io.open(full_path, "rt", encoding="utf-8") as f:
                ssh_config_instance.parse(f)
                source = ssh_config_instance.lookup(self.host)
        else:
            source = {}

        # Keys get normalized to lower-case
        if "proxycommand" in source:
            proxy = paramiko.ProxyCommand(source["proxycommand"])
        elif "proxyjump" in source:
            hops = list(reversed(source["proxyjump"].split(",")))
            if len(hops) > 1:
                raise ValueError(
                    "ProxyJump with more than one proxy server is not supported."
                )
            port = source.get("port", self.port)
            host = source.get("hostname", self.host)
            # -F {full_path} forces the continued use of the same SSH config file
            cmd = "ssh -F {} -W {}:{} {}".format(full_path, host, port, hops[0])
            proxy = paramiko.ProxyCommand(cmd)
        else:
            proxy = None

        # Only update 'hostname', 'sock', 'port', and 'username'
        # For 'port' and 'username' only update if using object defaults
        if connect_dict["port"] == 22:
            connect_dict["port"] = int(source.get("port", self.port))
        if connect_dict["username"] == "":
            connect_dict["username"] = source.get("user", self.username)
        if proxy:
            connect_dict["sock"] = proxy
        connect_dict["hostname"] = source.get("hostname", self.host)

        return connect_dict

    def _connect_params_dict(self):
        """Generate dictionary of Paramiko connection parameters."""
        conn_dict = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "look_for_keys": self.use_keys,
            "allow_agent": self.allow_agent,
            "key_filename": self.key_file,
            "pkey": self.pkey,
            "passphrase": self.passphrase,
            "timeout": self.timeout,
            "auth_timeout": self.auth_timeout,
            "banner_timeout": self.banner_timeout,
        }

        # Check if using SSH 'config' file mainly for SSH proxy support
        if self.ssh_config_file:
            conn_dict = self._use_ssh_config(conn_dict)
        return conn_dict

    def _sanitize_output(
        self, output, strip_command=False, command_string=None, strip_prompt=False
    ):
        """Strip out command echo, trailing router prompt and ANSI escape codes.

        :param output: Output from a remote network device
        :type output: unicode string

        :param strip_command:
        :type strip_command:
        """
        if self.ansi_escape_codes:
            output = self.strip_ansi_escape_codes(output)
        output = self.normalize_linefeeds(output)
        if strip_command and command_string:
            command_string = self.normalize_linefeeds(command_string)
            output = self.strip_command(command_string, output)
        if strip_prompt:
            output = self.strip_prompt(output)
        return output

    def establish_connection(self, width=None, height=None):
        """Establish SSH connection to the network device

        Timeout will generate a Net_ConnectTimeoutException
        Authentication failure will generate a Net_ConnectAuthenticationException

        width and height are needed for Fortinet paging setting.

        :param width: Specified width of the VT100 terminal window
        :type width: int

        :param height: Specified height of the VT100 terminal window
        :type height: int
        """
        if self.protocol == "telnet":
            self.remote_conn = telnetlib.Telnet(
                self.host, port=self.port, timeout=self.timeout
            )
            self.telnet_login()
        elif self.protocol == "ssh":
            ssh_connect_params = self._connect_params_dict()
            self.remote_conn_pre = self._build_ssh_client()

            # initiate SSH connection
            try:
                self.remote_conn_pre.connect(**ssh_connect_params)
            except socket.error:
                self.paramiko_cleanup()
                msg = "Connection to device timed-out: {device_type} {ip}:{port}".format(
                    device_type=self.device_type, ip=self.host, port=self.port
                )
                raise Net_ConnectTimeoutException(msg)
            except paramiko.ssh_exception.AuthenticationException as auth_err:
                self.paramiko_cleanup()
                msg = "Authentication failure: unable to connect {device_type} {ip}:{port}".format(
                    device_type=self.device_type, ip=self.host, port=self.port
                )
                msg += self.RETURN + text_type(auth_err)
                raise Net_ConnectAuthenticationException(msg)

            if self.verbose:
                print(
                    "SSH connection established to {}:{}".format(self.host, self.port)
                )

            # Use invoke_shell to establish an 'interactive session'
            if width and height:
                self.remote_conn = self.remote_conn_pre.invoke_shell(
                    term="vt100", width=width, height=height
                )
            else:
                self.remote_conn = self.remote_conn_pre.invoke_shell()

            self.remote_conn.settimeout(self.blocking_timeout)
            if self.keepalive:
                self.remote_conn.transport.set_keepalive(self.keepalive)
            self.special_login_handler()
            if self.verbose:
                print("Interactive SSH session established")
        return ""

    def _test_channel_read(self, count=40, pattern=""):
        """Try to read the channel (generally post login) verify you receive data back.

        :param count: the number of times to check the channel for data
        :type count: int

        :param pattern: Regular expression pattern used to determine end of channel read
        :type pattern: str
        """

        def _increment_delay(main_delay, increment=1.1, maximum=8):
            """Increment sleep time to a maximum value."""
            main_delay = main_delay * increment
            if main_delay >= maximum:
                main_delay = maximum
            return main_delay

        i = 0
        delay_factor = self.select_delay_factor(delay_factor=0)
        main_delay = delay_factor * 0.1
        time.sleep(main_delay * 10)
        new_data = ""
        while i <= count:
            new_data += self._read_channel_timing()
            if new_data and pattern:
                if re.search(pattern, new_data):
                    break
            elif new_data:
                break
            else:
                self.write_channel(self.RETURN)
            main_delay = _increment_delay(main_delay)
            time.sleep(main_delay)
            i += 1

        # check if data was ever present
        if new_data:
            return new_data
        else:
            raise Net_ConnectTimeoutException("Timed out waiting for data")

    def _build_ssh_client(self):
        """Prepare for Paramiko SSH connection."""
        # Create instance of SSHClient object
        remote_conn_pre = paramiko.SSHClient()

        # Load host_keys for better SSH security
        if self.system_host_keys:
            remote_conn_pre.load_system_host_keys()
        if self.alt_host_keys and path.isfile(self.alt_key_file):
            remote_conn_pre.load_host_keys(self.alt_key_file)

        # Default is to automatically add untrusted hosts (make sure appropriate for your env)
        remote_conn_pre.set_missing_host_key_policy(self.key_policy)
        return remote_conn_pre

    def select_delay_factor(self, delay_factor):
        if self.fast_cli:
            if delay_factor <= self.global_delay_factor:
                return delay_factor
            else:
                return self.global_delay_factor
        else:
            if delay_factor >= self.global_delay_factor:
                return delay_factor
            else:
                return self.global_delay_factor

    def special_login_handler(self, delay_factor=5):
        """Handler for devices like WLC, Extreme ERS that throw up characters prior to login."""
        pass

    def disable_paging(self, command="terminal length 0", delay_factor=5):

        delay_factor = self.select_delay_factor(delay_factor)
        time.sleep(delay_factor * 0.1)
        self.clear_buffer()
        command = self.normalize_cmd(command)
        log.debug("In disable_paging")
        log.debug("Command: {0}".format(command))
        self.write_channel(command)
        output = self.read_until_prompt()
        if self.ansi_escape_codes:
            output = self.strip_ansi_escape_codes(output)
        log.debug("{0}".format(output))
        log.debug("Exiting disable_paging")
        return output

    def set_terminal_width(self, command="", delay_factor=5):
        """CLI terminals try to automatically adjust the line based on the width of the terminal.
        This causes the output to get distorted when accessed programmatically.

        Set terminal width to 511 which works on a broad set of devices.

        :param command: Command string to send to the device
        :type command: str

        :param delay_factor: See __init__: global_delay_factor
        :type delay_factor: int
        """
        if not command:
            return ""
        delay_factor = self.select_delay_factor(delay_factor)
        command = self.normalize_cmd(command)
        self.write_channel(command)
        output = self.read_until_prompt()
        if self.ansi_escape_codes:
            output = self.strip_ansi_escape_codes(output)
        return output

    def set_base_prompt(
        self, pri_prompt_terminator="#", alt_prompt_terminator=">", delay_factor=5
    ):
        """Sets self.base_prompt

        Used as delimiter for stripping of trailing prompt in output.

        Should be set to something that is general and applies in multiple contexts. For Cisco
        devices this will be set to router hostname (i.e. prompt without > or #).

        This will be set on entering user exec or privileged exec on Cisco, but not when
        entering/exiting config mode.

        :param pri_prompt_terminator: Primary trailing delimiter for identifying a device prompt
        :type pri_prompt_terminator: str

        :param alt_prompt_terminator: Alternate trailing delimiter for identifying a device prompt
        :type alt_prompt_terminator: str

        :param delay_factor: See __init__: global_delay_factor
        :type delay_factor: int
        """
        prompt = self.find_prompt(delay_factor=delay_factor)
        if not prompt[-1] in (pri_prompt_terminator, alt_prompt_terminator):
            raise ValueError("Router prompt not found: {0}".format(repr(prompt)))
        # Strip off trailing terminator
        self.base_prompt = prompt[:-1]
        return self.base_prompt

    def find_prompt(self, delay_factor=5):
        """Finds the current network device prompt, last line only.

        :param delay_factor: See __init__: global_delay_factor
        :type delay_factor: int
        """
        delay_factor = self.select_delay_factor(delay_factor)
        self.clear_buffer()
        self.write_channel(self.RETURN)
        time.sleep(delay_factor * 0.1)

        # Initial attempt to get prompt
        prompt = self.read_channel()
        if self.ansi_escape_codes:
            prompt = self.strip_ansi_escape_codes(prompt)

        # Check if the only thing you received was a newline
        count = 0
        prompt = prompt.strip()
        while count <= 10 and not prompt:
            prompt = self.read_channel().strip()
            if prompt:
                if self.ansi_escape_codes:
                    prompt = self.strip_ansi_escape_codes(prompt).strip()
            else:
                self.write_channel(self.RETURN)
                time.sleep(delay_factor * 0.1)
            count += 1

        # If multiple lines in the output take the last line
        prompt = self.normalize_linefeeds(prompt)
        prompt = prompt.split(self.RESPONSE_RETURN)[-1]
        prompt = prompt.strip()
        if not prompt:
            raise ValueError("Unable to find prompt: {}".format(prompt))
        time.sleep(delay_factor * 0.1)
        self.clear_buffer()
        return prompt

    def clear_buffer(self):
        """Read any data available in the channel."""
        self.read_channel()

    def send_command_timing(
        self,
        command_string,
        delay_factor=5,
        max_loops=150,
        strip_prompt=True,
        strip_command=True,
        normalize=True,
        use_textfsm=False,
        use_genie=False,
    ):
        """Execute command_string on the SSH channel using a delay-based mechanism. Generally
        used for show commands.

        :param command_string: The command to be executed on the remote device.
        :type command_string: str

        :param delay_factor: Multiplying factor used to adjust delays (default: 1).
        :type delay_factor: int or float

        :param max_loops: Controls wait time in conjunction with delay_factor. Will default to be
            based upon self.timeout.
        :type max_loops: int

        :param strip_prompt: Remove the trailing router prompt from the output (default: True).
        :type strip_prompt: bool

        :param strip_command: Remove the echo of the command from the output (default: True).
        :type strip_command: bool

        :param normalize: Ensure the proper enter is sent at end of command (default: True).
        :type normalize: bool

        :param use_textfsm: Process command output through TextFSM template (default: False).
        :type normalize: bool

        :param use_genie: Process command output through PyATS/Genie parser (default: False).
        :type normalize: bool
        """
        output = ""
        delay_factor = self.select_delay_factor(delay_factor)
        self.clear_buffer()
        if normalize:
            command_string = self.normalize_cmd(command_string)

        self.write_channel(command_string)
        output = self._read_channel_timing(
            delay_factor=delay_factor, max_loops=max_loops
        )
        output = self._sanitize_output(
            output,
            strip_command=strip_command,
            command_string=command_string,
            strip_prompt=strip_prompt,
        )
        # If both TextFSM and Genie are set, try TextFSM then Genie
        for parser_flag, parser_func in (
            (use_textfsm, get_structured_data),
            (use_genie, get_structured_data_genie),
        ):
            if parser_flag:
                structured_output = parser_func(
                    output, platform=self.device_type, command=command_string.strip()
                )
                # If we have structured data; return it.
                if not isinstance(structured_output, string_types):
                    return structured_output
        return output

    def strip_prompt(self, a_string):
        """Strip the trailing router prompt from the output.

        :param a_string: Returned string from device
        :type a_string: str
        """
        response_list = a_string.split(self.RESPONSE_RETURN)
        last_line = response_list[-1]
        if self.base_prompt in last_line:
            return self.RESPONSE_RETURN.join(response_list[:-1])
        else:
            return a_string

    def _first_line_handler(self, data, search_pattern):
        """
        In certain situations the first line will get repainted which causes a false
        match on the terminating pattern.

        Filter this out.

        returns a tuple of (data, first_line_processed)

        Where data is the original data potentially with the first line modified
        and the first_line_processed is a flag indicating that we have handled the
        first line.
        """
        try:
            # First line is the echo line containing the command. In certain situations
            # it gets repainted and needs filtered
            lines = data.split(self.RETURN)
            first_line = lines[0]
            if BACKSPACE_CHAR in first_line:
                pattern = search_pattern + r".*$"
                first_line = re.sub(pattern, repl="", string=first_line)
                lines[0] = first_line
                data = self.RETURN.join(lines)
            return (data, True)
        except IndexError:
            return (data, False)

    def send_command(
        self,
        command_string,
        expect_string=None,
        delay_factor=5,
        max_loops=500,
        auto_find_prompt=True,
        strip_prompt=True,
        strip_command=True,
        normalize=True,
        use_textfsm=False,
        use_genie=False,
    ):
        """Execute command_string on the SSH channel using a pattern-based mechanism. Generally
        used for show commands. By default this method will keep waiting to receive data until the
        network device prompt is detected. The current network device prompt will be determined
        automatically.

        :param command_string: The command to be executed on the remote device.
        :type command_string: str

        :param expect_string: Regular expression pattern to use for determining end of output.
            If left blank will default to being based on router prompt.
        :type expect_string: str

        :param delay_factor: Multiplying factor used to adjust delays (default: 1).
        :type delay_factor: int

        :param max_loops: Controls wait time in conjunction with delay_factor. Will default to be
            based upon self.timeout.
        :type max_loops: int

        :param strip_prompt: Remove the trailing router prompt from the output (default: True).
        :type strip_prompt: bool

        :param strip_command: Remove the echo of the command from the output (default: True).
        :type strip_command: bool

        :param normalize: Ensure the proper enter is sent at end of command (default: True).
        :type normalize: bool

        :param use_textfsm: Process command output through TextFSM template (default: False).
        :type normalize: bool

        :param use_genie: Process command output through PyATS/Genie parser (default: False).
        :type normalize: bool
        """
        # Time to delay in each read loop
        loop_delay = 0.2

        # Default to making loop time be roughly equivalent to self.timeout (support old max_loops
        # and delay_factor arguments for backwards compatibility).
        delay_factor = self.select_delay_factor(delay_factor)
        if delay_factor == 1 and max_loops == 500:
            # Default arguments are being used; use self.timeout instead
            max_loops = int(self.timeout / loop_delay)

        # Find the current router prompt
        if expect_string is None:
            if auto_find_prompt:
                try:
                    prompt = self.find_prompt(delay_factor=delay_factor)
                except ValueError:
                    prompt = self.base_prompt
            else:
                prompt = self.base_prompt
            search_pattern = re.escape(prompt.strip())
        else:
            search_pattern = expect_string

        if normalize:
            command_string = self.normalize_cmd(command_string)

        time.sleep(delay_factor * loop_delay)
        self.clear_buffer()
        self.write_channel(command_string)

        i = 1
        output = ""
        past_three_reads = deque(maxlen=3)
        first_line_processed = False

        # Keep reading data until search_pattern is found or until max_loops is reached.
        while i <= max_loops:
            new_data = self.read_channel()
            if new_data:
                if self.ansi_escape_codes:
                    new_data = self.strip_ansi_escape_codes(new_data)

                output += new_data
                past_three_reads.append(new_data)

                # Case where we haven't processed the first_line yet (there is a potential issue
                # in the first line (in cases where the line is repainted).
                if not first_line_processed:
                    output, first_line_processed = self._first_line_handler(
                        output, search_pattern
                    )
                    # Check if we have already found our pattern
                    if re.search(search_pattern, output):
                        break

                else:
                    # Check if pattern is in the past three reads
                    if re.search(search_pattern, "".join(past_three_reads)):
                        break

            time.sleep(delay_factor * loop_delay)
            i += 1
        else:  # nobreak
            raise IOError(
                "Search pattern never detected in send_command_expect: {}".format(
                    search_pattern
                )
            )

        output = self._sanitize_output(
            output,
            strip_command=strip_command,
            command_string=command_string,
            strip_prompt=strip_prompt,
        )

        # If both TextFSM and Genie are set, try TextFSM then Genie
        for parser_flag, parser_func in (
            (use_textfsm, get_structured_data),
            (use_genie, get_structured_data_genie),
        ):
            if parser_flag:
                structured_output = parser_func(
                    output, platform=self.device_type, command=command_string.strip()
                )
                # If we have structured data; return it.
                if not isinstance(structured_output, string_types):
                    return structured_output
        return output

    def send_command_expect(self, *args, **kwargs):
        """Support previous name of send_command method.

        :param args: Positional arguments to send to send_command()
        :type args: list

        :param kwargs: Keyword arguments to send to send_command()
        :type kwargs: dict
        """
        return self.send_command(*args, **kwargs)

    @staticmethod
    def strip_backspaces(output):
        """Strip any backspace characters out of the output.

        :param output: Output obtained from a remote network device.
        :type output: str
        """
        backspace_char = "\x08"
        return output.replace(backspace_char, "")

    def strip_command(self, command_string, output):
        """
        Strip command_string from output string

        Cisco IOS adds backspaces into output for long commands (i.e. for commands that line wrap)

        :param command_string: The command string sent to the device
        :type command_string: str

        :param output: The returned output as a result of the command string sent to the device
        :type output: str
        """
        backspace_char = "\x08"

        # Check for line wrap (remove backspaces)
        if backspace_char in output:
            output = output.replace(backspace_char, "")
            output_lines = output.split(self.RESPONSE_RETURN)
            new_output = output_lines[1:]
            return self.RESPONSE_RETURN.join(new_output)
        else:
            command_length = len(command_string)
            return output[command_length:]

    def normalize_linefeeds(self, a_string):
        """Convert `\r\r\n`,`\r\n`, `\n\r` to `\n.`

        :param a_string: A string that may have non-normalized line feeds
            i.e. output returned from device, or a device prompt
        :type a_string: str
        """
        newline = re.compile("(\r\r\r\n|\r\r\n|\r\n|\n\r)")
        a_string = newline.sub(self.RESPONSE_RETURN, a_string)
        if self.RESPONSE_RETURN == "\n":
            # Convert any remaining \r to \n
            return re.sub("\r", self.RESPONSE_RETURN, a_string)
        else:
            return a_string

    def normalize_cmd(self, command):
        """Normalize CLI commands to have a single trailing newline.

        :param command: Command that may require line feed to be normalized
        :type command: str
        """
        command = command.rstrip()
        command += self.RETURN
        return command

    def check_enable_mode(self, check_string=""):
        """Check if in enable mode. Return boolean.

        :param check_string: Identification of privilege mode from device
        :type check_string: str
        """
        self.write_channel(self.RETURN)
        output = self.read_until_prompt()
        return check_string in output

    def enable(self, cmd="", pattern="ssword", re_flags=re.IGNORECASE):
        """Enter enable mode.

        :param cmd: Device command to enter enable mode
        :type cmd: str

        :param pattern: pattern to search for indicating device is waiting for password
        :type pattern: str

        :param re_flags: Regular expression flags used in conjunction with pattern
        :type re_flags: int
        """
        output = ""
        msg = (
            "Failed to enter enable mode. Please ensure you pass "
            "the 'secret' argument to ConnectHandler."
        )
        if not self.check_enable_mode():
            self.write_channel(self.normalize_cmd(cmd))
            try:
                output += self.read_until_prompt_or_pattern(
                    pattern=pattern, re_flags=re_flags
                )
                self.write_channel(self.normalize_cmd(self.secret))
                output += self.read_until_prompt()
            except Net_ConnectTimeoutException:
                raise ValueError(msg)
            if not self.check_enable_mode():
                raise ValueError(msg)
        return output

    def exit_enable_mode(self, exit_command=""):
        """Exit enable mode.

        :param exit_command: Command that exits the session from privileged mode
        :type exit_command: str
        """
        output = ""
        if self.check_enable_mode():
            self.write_channel(self.normalize_cmd(exit_command))
            output += self.read_until_prompt()
            if self.check_enable_mode():
                raise ValueError("Failed to exit enable mode.")
        return output

    def check_config_mode(self, check_string="", pattern=""):
        """Checks if the device is in configuration mode or not.

        :param check_string: Identification of configuration mode from the device
        :type check_string: str

        :param pattern: Pattern to terminate reading of channel
        :type pattern: str
        """
        self.write_channel(self.RETURN)
        # You can encounter an issue here (on router name changes) prefer delay-based solution
        if not pattern:
            output = self._read_channel_timing()
        else:
            output = self.read_until_pattern(pattern=pattern)
        return check_string in output

    def config_mode(self, config_command="", pattern=""):
        """Enter into config_mode.

        :param config_command: Configuration command to send to the device
        :type config_command: str

        :param pattern: Pattern to terminate reading of channel
        :type pattern: str
        """
        output = ""
        if not self.check_config_mode():
            self.write_channel(self.normalize_cmd(config_command))
            output = self.read_until_pattern(pattern=pattern)
            if not self.check_config_mode():
                raise ValueError("Failed to enter configuration mode.")
        return output

    def exit_config_mode(self, exit_config="", pattern=""):
        """Exit from configuration mode.

        :param exit_config: Command to exit configuration mode
        :type exit_config: str

        :param pattern: Pattern to terminate reading of channel
        :type pattern: str
        """
        output = ""
        if self.check_config_mode():
            self.write_channel(self.normalize_cmd(exit_config))
            output = self.read_until_pattern(pattern=pattern)
            if self.check_config_mode():
                raise ValueError("Failed to exit configuration mode")
        log.debug("exit_config_mode: {}".format(output))
        return output

    def send_config_from_file(self, config_file=None, **kwargs):
        """
        Send configuration commands down the SSH channel from a file.

        The file is processed line-by-line and each command is sent down the
        SSH channel.

        **kwargs are passed to send_config_set method.

        :param config_file: Path to configuration file to be sent to the device
        :type config_file: str

        :param kwargs: params to be sent to send_config_set method
        :type kwargs: dict
        """
        with io.open(config_file, "rt", encoding="utf-8") as cfg_file:
            return self.send_config_set(cfg_file, **kwargs)

    def send_config_set(
        self,
        config_commands=None,
        exit_config_mode=True,
        delay_factor=1,
        max_loops=150,
        strip_prompt=False,
        strip_command=False,
        config_mode_command=None,
    ):
        """
        Send configuration commands down the SSH channel.

        config_commands is an iterable containing all of the configuration commands.
        The commands will be executed one after the other.

        Automatically exits/enters configuration mode.

        :param config_commands: Multiple configuration commands to be sent to the device
        :type config_commands: list or string

        :param exit_config_mode: Determines whether or not to exit config mode after complete
        :type exit_config_mode: bool

        :param delay_factor: Factor to adjust delays
        :type delay_factor: int

        :param max_loops: Controls wait time in conjunction with delay_factor (default: 150)
        :type max_loops: int

        :param strip_prompt: Determines whether or not to strip the prompt
        :type strip_prompt: bool

        :param strip_command: Determines whether or not to strip the command
        :type strip_command: bool

        :param config_mode_command: The command to enter into config mode
        :type config_mode_command: str
        """
        delay_factor = self.select_delay_factor(delay_factor)
        if config_commands is None:
            return ""
        elif isinstance(config_commands, string_types):
            config_commands = (config_commands,)

        if not hasattr(config_commands, "__iter__"):
            raise ValueError("Invalid argument passed into send_config_set")

        # Send config commands
        cfg_mode_args = (config_mode_command,) if config_mode_command else tuple()
        output = self.config_mode(*cfg_mode_args)
        for cmd in config_commands:
            self.write_channel(self.normalize_cmd(cmd))
            if self.fast_cli:
                pass
            else:
                time.sleep(delay_factor * 0.05)

        # Gather output
        output += self._read_channel_timing(
            delay_factor=delay_factor, max_loops=max_loops
        )
        if exit_config_mode:
            output += self.exit_config_mode()
        output = self._sanitize_output(output)
        log.debug("{}".format(output))
        return output

    def strip_ansi_escape_codes(self, string_buffer):
        """
        Remove any ANSI (VT100) ESC codes from the output

        http://en.wikipedia.org/wiki/ANSI_escape_code

        Note: this does not capture ALL possible ANSI Escape Codes only the ones
        I have encountered

        Current codes that are filtered:
        ESC = '\x1b' or chr(27)
        ESC = is the escape character [^ in hex ('\x1b')
        ESC[24;27H   Position cursor
        ESC[?25h     Show the cursor
        ESC[E        Next line (HP does ESC-E)
        ESC[K        Erase line from cursor to the end of line
        ESC[2K       Erase entire line
        ESC[1;24r    Enable scrolling from start to row end
        ESC[?6l      Reset mode screen with options 640 x 200 monochrome (graphics)
        ESC[?7l      Disable line wrapping
        ESC[2J       Code erase display
        ESC[00;32m   Color Green (30 to 37 are different colors) more general pattern is
                     ESC[\d\d;\d\dm and ESC[\d\d;\d\d;\d\dm
        ESC[6n       Get cursor position

        HP ProCurve and Cisco SG300 require this (possible others).

        :param string_buffer: The string to be processed to remove ANSI escape codes
        :type string_buffer: str
        """  # noqa
        log.debug("In strip_ansi_escape_codes")
        log.debug("repr = {}".format(repr(string_buffer)))

        code_position_cursor = chr(27) + r"\[\d+;\d+H"
        code_show_cursor = chr(27) + r"\[\?25h"
        code_next_line = chr(27) + r"E"
        code_erase_line_end = chr(27) + r"\[K"
        code_erase_line = chr(27) + r"\[2K"
        code_erase_start_line = chr(27) + r"\[K"
        code_enable_scroll = chr(27) + r"\[\d+;\d+r"
        code_form_feed = chr(27) + r"\[1L"
        code_carriage_return = chr(27) + r"\[1M"
        code_disable_line_wrapping = chr(27) + r"\[\?7l"
        code_reset_mode_screen_options = chr(27) + r"\[\?\d+l"
        code_reset_graphics_mode = chr(27) + r"\[00m"
        code_erase_display = chr(27) + r"\[2J"
        code_graphics_mode = chr(27) + r"\[\d\d;\d\dm"
        code_graphics_mode2 = chr(27) + r"\[\d\d;\d\d;\d\dm"
        code_graphics_mode3 = chr(27) + r"\[(3|4)\dm"
        code_graphics_mode4 = chr(27) + r"\[(9|10)[0-7]m"
        code_get_cursor_position = chr(27) + r"\[6n"
        code_cursor_position = chr(27) + r"\[m"
        code_erase_display = chr(27) + r"\[J"
        code_attrs_off = chr(27) + r"\[0m"
        code_reverse = chr(27) + r"\[7m"

        code_set = [
            code_position_cursor,
            code_show_cursor,
            code_erase_line,
            code_enable_scroll,
            code_erase_start_line,
            code_form_feed,
            code_carriage_return,
            code_disable_line_wrapping,
            code_erase_line_end,
            code_reset_mode_screen_options,
            code_reset_graphics_mode,
            code_erase_display,
            code_graphics_mode,
            code_graphics_mode2,
            code_graphics_mode3,
            code_graphics_mode4,
            code_get_cursor_position,
            code_cursor_position,
            code_erase_display,
            code_attrs_off,
            code_reverse,
        ]

        output = string_buffer
        for ansi_esc_code in code_set:
            output = re.sub(ansi_esc_code, "", output)

        # CODE_NEXT_LINE must substitute with return
        output = re.sub(code_next_line, self.RETURN, output)

        log.debug("new_output = {0}".format(output))
        log.debug("repr = {0}".format(repr(output)))

        return output

    def cleanup(self):
        """Any needed cleanup before closing connection."""
        pass

    def paramiko_cleanup(self):
        """Cleanup Paramiko to try to gracefully handle SSH session ending."""
        self.remote_conn_pre.close()
        del self.remote_conn_pre

    def disconnect(self):
        """Try to gracefully close the SSH connection."""
        try:
            self.cleanup()
            if self.protocol == "ssh":
                self.paramiko_cleanup()
            elif self.protocol == "telnet":
                self.remote_conn.close()
        except Exception:
            # There have been race conditions observed on disconnect.
            pass
        finally:
            self.remote_conn_pre = None
            self.remote_conn = None
            self.close_session_log()

    def commit(self):
        """Commit method for platforms that support this."""
        raise AttributeError("Network device does not support 'commit()' method")

    def save_config(self, *args, **kwargs):
        """Not Implemented"""
        raise NotImplementedError

    def open_session_log(self, filename, mode="write"):
        """Open the session_log file."""
        if mode == "append":
            self.session_log = open(filename, mode="ab")
        else:
            self.session_log = open(filename, mode="wb")
        self._session_log_close = True

    def close_session_log(self):
        """Close the session_log file (if it is a file that we opened)."""
        if self.session_log is not None and self._session_log_close:
            self.session_log.close()
            self.session_log = None

class TerminalServer(BaseConnection):
    """Generic Terminal Server driver.

    Allow direct write_channel / read_channel operations without session_preparation causing
    an exception.
    """

    def session_preparation(self):
        """Do nothing here; base_prompt is not set; paging is not disabled."""
        pass

class TerminalServerSSH(TerminalServer):
    """Generic Terminal Server driver SSH."""
    pass

class BaseFileTransfer(object):
    """Class to manage SCP file transfer and associated SSH control channel."""
    def __init__(
        self, ssh_conn, source_file, dest_file, file_system=None, direction="put"
    ):
        self.ssh_ctl_chan = ssh_conn
        self.source_file = source_file
        self.dest_file = dest_file
        self.direction = direction

        auto_flag = (
            "cisco_ios" in ssh_conn.device_type
            or "cisco_xe" in ssh_conn.device_type
            or "cisco_xr" in ssh_conn.device_type
        )
        if not file_system:
            if auto_flag:
                self.file_system = self.ssh_ctl_chan._autodetect_fs()
            else:
                raise ValueError("Destination file system not specified")
        else:
            self.file_system = file_system

        if direction == "put":
            self.source_md5 = self.file_md5(source_file)
            self.file_size = os.stat(source_file).st_size
        elif direction == "get":
            self.source_md5 = self.remote_md5(remote_file=source_file)
            self.file_size = self.remote_file_size(remote_file=source_file)
        else:
            raise ValueError("Invalid direction specified")

    def __enter__(self):
        """Context manager setup"""
        self.establish_scp_conn()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Context manager cleanup."""
        self.close_scp_chan()

    def establish_scp_conn(self):
        """Establish SCP connection."""
        self.scp_conn = SCPConn(self.ssh_ctl_chan)

    def close_scp_chan(self):
        """Close the SCP connection to the remote network device."""
        self.scp_conn.close()
        self.scp_conn = None

    def remote_space_available(self, search_pattern=r"(\d+) \w+ free"):
        """Return space available on remote device."""
        remote_cmd = "dir {}".format(self.file_system)
        remote_output = self.ssh_ctl_chan.send_command_expect(remote_cmd)
        match = re.search(search_pattern, remote_output)
        if "kbytes" in match.group(0) or "Kbytes" in match.group(0):
            return int(match.group(1)) * 1000
        return int(match.group(1))

    def _remote_space_available_unix(self, search_pattern=""):
        """Return space available on *nix system (BSD/Linux)."""
        self.ssh_ctl_chan._enter_shell()
        remote_cmd = "/bin/df -k {}".format(self.file_system)
        remote_output = self.ssh_ctl_chan.send_command(
            remote_cmd, expect_string=r"[\$#]"
        )

        # Try to ensure parsing is correct:
        # Filesystem   1K-blocks  Used   Avail Capacity  Mounted on
        # /dev/bo0s3f    1264808 16376 1147248     1%    /cf/var
        remote_output = remote_output.strip()
        output_lines = remote_output.splitlines()

        # First line is the header; second is the actual file system info
        header_line = output_lines[0]
        filesystem_line = output_lines[1]

        if "Filesystem" not in header_line or "Avail" not in header_line.split()[3]:
            # Filesystem  1K-blocks  Used   Avail Capacity  Mounted on
            msg = "Parsing error, unexpected output from {}:\n{}".format(
                remote_cmd, remote_output
            )
            raise ValueError(msg)

        space_available = filesystem_line.split()[3]
        if not re.search(r"^\d+$", space_available):
            msg = "Parsing error, unexpected output from {}:\n{}".format(
                remote_cmd, remote_output
            )
            raise ValueError(msg)

        self.ssh_ctl_chan._return_cli()
        return int(space_available) * 1024

    def local_space_available(self):
        """Return space available on local filesystem."""
        destination_stats = os.statvfs(".")
        return destination_stats.f_bsize * destination_stats.f_bavail

    def verify_space_available(self, search_pattern=r"(\d+) \w+ free"):
        """Verify sufficient space is available on destination file system (return boolean)."""
        if self.direction == "put":
            space_avail = self.remote_space_available(search_pattern=search_pattern)
        elif self.direction == "get":
            space_avail = self.local_space_available()
        if space_avail > self.file_size:
            return True
        return False

    def check_file_exists(self, remote_cmd=""):
        """Check if the dest_file already exists on the file system (return boolean)."""
        if self.direction == "put":
            if not remote_cmd:
                remote_cmd = "dir {}/{}".format(self.file_system, self.dest_file)
            remote_out = self.ssh_ctl_chan.send_command_expect(remote_cmd)
            search_string = r"Directory of .*{0}".format(self.dest_file)
            if (
                "Error opening" in remote_out
                or "No such file or directory" in remote_out
                or "Path does not exist" in remote_out
            ):
                return False
            elif re.search(search_string, remote_out, flags=re.DOTALL):
                return True
            else:
                raise ValueError("Unexpected output from check_file_exists")
        elif self.direction == "get":
            return os.path.exists(self.dest_file)

    def _check_file_exists_unix(self, remote_cmd=""):
        """Check if the dest_file already exists on the file system (return boolean)."""
        if self.direction == "put":
            self.ssh_ctl_chan._enter_shell()
            remote_cmd = "ls {}".format(self.file_system)
            remote_out = self.ssh_ctl_chan.send_command(
                remote_cmd, expect_string=r"[\$#]"
            )
            self.ssh_ctl_chan._return_cli()
            return self.dest_file in remote_out
        elif self.direction == "get":
            return os.path.exists(self.dest_file)

    def remote_file_size(self, remote_cmd="", remote_file=None):
        """Get the file size of the remote file."""
        if remote_file is None:
            if self.direction == "put":
                remote_file = self.dest_file
            elif self.direction == "get":
                remote_file = self.source_file
        if not remote_cmd:
            remote_cmd = "dir {}/{}".format(self.file_system, remote_file)
        remote_out = self.ssh_ctl_chan.send_command(remote_cmd)
        # Strip out "Directory of flash:/filename line
        remote_out = re.split(r"Directory of .*", remote_out)
        remote_out = "".join(remote_out)
        # Match line containing file name
        escape_file_name = re.escape(remote_file)
        pattern = r".*({}).*".format(escape_file_name)
        match = re.search(pattern, remote_out)
        if match:
            line = match.group(0)
            # Format will be 26  -rw-   6738  Jul 30 2016 19:49:50 -07:00  filename
            file_size = line.split()[2]
        if "Error opening" in remote_out or "No such file or directory" in remote_out:
            raise IOError("Unable to find file on remote system")
        else:
            return int(file_size)

    def _remote_file_size_unix(self, remote_cmd="", remote_file=None):
        """Get the file size of the remote file."""
        if remote_file is None:
            if self.direction == "put":
                remote_file = self.dest_file
            elif self.direction == "get":
                remote_file = self.source_file
        remote_file = "{}/{}".format(self.file_system, remote_file)
        if not remote_cmd:
            remote_cmd = "ls -l {}".format(remote_file)

        self.ssh_ctl_chan._enter_shell()
        remote_out = self.ssh_ctl_chan.send_command(remote_cmd, expect_string=r"[\$#]")
        self.ssh_ctl_chan._return_cli()

        if "No such file or directory" in remote_out:
            raise IOError("Unable to find file on remote system")

        escape_file_name = re.escape(remote_file)
        pattern = r"^.* ({}).*$".format(escape_file_name)
        match = re.search(pattern, remote_out, flags=re.M)
        if match:
            # Format: -rw-r--r--  1 pyclass  wheel  12 Nov  5 19:07 /var/tmp/test3.txt
            line = match.group(0)
            file_size = line.split()[4]
            return int(file_size)

        raise ValueError(
            "Search pattern not found for remote file size during SCP transfer."
        )

    def file_md5(self, file_name):
        """Compute MD5 hash of file."""
        with open(file_name, "rb") as f:
            file_contents = f.read()
            file_hash = hashlib.md5(file_contents).hexdigest()
        return file_hash

    @staticmethod
    def process_md5(md5_output, pattern=r"=\s+(\S+)"):
        """
        Process the string to retrieve the MD5 hash

        Output from Cisco IOS (ASA is similar)
        .MD5 of flash:file_name Done!
        verify /md5 (flash:file_name) = 410db2a7015eaa42b1fe71f1bf3d59a2
        """
        match = re.search(pattern, md5_output)
        if match:
            return match.group(1)
        else:
            raise ValueError("Invalid output from MD5 command: {}".format(md5_output))

    def compare_md5(self):
        """Compare md5 of file on network device to md5 of local file."""
        if self.direction == "put":
            remote_md5 = self.remote_md5()
            return self.source_md5 == remote_md5
        elif self.direction == "get":
            local_md5 = self.file_md5(self.dest_file)
            return self.source_md5 == local_md5

    def remote_md5(self, base_cmd="verify /md5", remote_file=None):
        """Calculate remote MD5 and returns the hash.

        This command can be CPU intensive on the remote device.
        """
        if remote_file is None:
            if self.direction == "put":
                remote_file = self.dest_file
            elif self.direction == "get":
                remote_file = self.source_file
        remote_md5_cmd = "{} {}/{}".format(base_cmd, self.file_system, remote_file)
        dest_md5 = self.ssh_ctl_chan.send_command(remote_md5_cmd, max_loops=1500)
        dest_md5 = self.process_md5(dest_md5)
        return dest_md5

    def transfer_file(self):
        """SCP transfer file."""
        if self.direction == "put":
            self.put_file()
        elif self.direction == "get":
            self.get_file()

    def get_file(self):
        """SCP copy the file from the remote device to local system."""
        source_file = "{}/{}".format(self.file_system, self.source_file)
        self.scp_conn.scp_get_file(source_file, self.dest_file)
        self.scp_conn.close()

    def put_file(self):
        """SCP copy the file from the local system to the remote device."""
        destination = "{}/{}".format(self.file_system, self.dest_file)
        self.scp_conn.scp_transfer_file(self.source_file, destination)
        # Must close the SCP connection to get the file written (flush)
        self.scp_conn.close()

    def verify_file(self):
        """Verify the file has been transferred correctly."""
        return self.compare_md5()

    def enable_scp(self, cmd=None):
        """
        Enable SCP on remote device.

        Defaults to Cisco IOS command
        """
        if cmd is None:
            cmd = ["ip scp server enable"]
        elif not hasattr(cmd, "__iter__"):
            cmd = [cmd]
        self.ssh_ctl_chan.send_config_set(cmd)

    def disable_scp(self, cmd=None):
        """
        Disable SCP on remote device.

        Defaults to Cisco IOS command
        """
        if cmd is None:
            cmd = ["no ip scp server enable"]
        elif not hasattr(cmd, "__iter__"):
            cmd = [cmd]
        self.ssh_ctl_chan.send_config_set(cmd)

class CiscoFileTransfer(BaseFileTransfer):
    pass

class LinuxFileTransfer(CiscoFileTransfer):
    """
    Linux SCP File Transfer driver.

    Mostly for testing purposes.
    """
    def __init__(
        self, ssh_conn, source_file, dest_file, file_system="/var/tmp", direction="put"
    ):
        return super(LinuxFileTransfer, self).__init__(
            ssh_conn=ssh_conn,
            source_file=source_file,
            dest_file=dest_file,
            file_system=file_system,
            direction=direction,
        )

    def remote_space_available(self, search_pattern=""):
        """Return space available on remote device."""
        return self._remote_space_available_unix(search_pattern=search_pattern)

    def check_file_exists(self, remote_cmd=""):
        """Check if the dest_file already exists on the file system (return boolean)."""
        return self._check_file_exists_unix(remote_cmd=remote_cmd)

    def remote_file_size(self, remote_cmd="", remote_file=None):
        """Get the file size of the remote file."""
        return self._remote_file_size_unix(
            remote_cmd=remote_cmd, remote_file=remote_file
        )

    def remote_md5(self, base_cmd="md5sum", remote_file=None):
        if remote_file is None:
            if self.direction == "put":
                remote_file = self.dest_file
            elif self.direction == "get":
                remote_file = self.source_file
        remote_md5_cmd = "{} {}/{}".format(base_cmd, self.file_system, remote_file)
        dest_md5 = self.ssh_ctl_chan.send_command(
            remote_md5_cmd, max_loops=750, delay_factor=5
        )
        dest_md5 = self.process_md5(dest_md5)
        return dest_md5

    @staticmethod
    def process_md5(md5_output, pattern=r"^(\S+)\s+"):
        return super(LinuxFileTransfer, LinuxFileTransfer).process_md5(
            md5_output, pattern=pattern
        )

    def enable_scp(self, cmd=None):
        raise NotImplementedError

    def disable_scp(self, cmd=None):
        raise NotImplementedError

class CiscoBaseConnection(BaseConnection):
    """Base Class for cisco-like behavior."""
    def check_enable_mode(self, check_string="#"):
        """Check if in enable mode. Return boolean."""
        return super(CiscoBaseConnection, self).check_enable_mode(
            check_string=check_string
        )

    def enable(self, cmd="enable", pattern="ssword", re_flags=re.IGNORECASE):
        """Enter enable mode."""
        return super(CiscoBaseConnection, self).enable(
            cmd=cmd, pattern=pattern, re_flags=re_flags
        )

    def exit_enable_mode(self, exit_command="disable"):
        """Exits enable (privileged exec) mode."""
        return super(CiscoBaseConnection, self).exit_enable_mode(
            exit_command=exit_command
        )

    def check_config_mode(self, check_string=")#", pattern=""):
        """
        Checks if the device is in configuration mode or not.

        Cisco IOS devices abbreviate the prompt at 20 chars in config mode
        """
        return super(CiscoBaseConnection, self).check_config_mode(
            check_string=check_string, pattern=pattern
        )

    def config_mode(self, config_command="config term", pattern=""):
        """
        Enter into configuration mode on remote device.

        Cisco IOS devices abbreviate the prompt at 20 chars in config mode
        """
        if not pattern:
            pattern = re.escape(self.base_prompt[:16])
        return super(CiscoBaseConnection, self).config_mode(
            config_command=config_command, pattern=pattern
        )

    def exit_config_mode(self, exit_config="end", pattern="#"):
        """Exit from configuration mode."""
        return super(CiscoBaseConnection, self).exit_config_mode(
            exit_config=exit_config, pattern=pattern
        )


    def telnet_login(
        self,
        pri_prompt_terminator=r"#\s*$",
        alt_prompt_terminator=r">\s*$",
        username_pattern=r"(?:user:|username|login|user name)",
        pwd_pattern=r"assword",
        delay_factor=5,
        max_loops=20,
    ):
        """Telnet login. Can be username/password or just password."""
        delay_factor = self.select_delay_factor(delay_factor)
        time.sleep(1 * delay_factor)

        output = ""
        return_msg = ""
        i = 1
        while i <= max_loops:
            try:
                output = self.read_channel()
                return_msg += output

                # Search for username pattern / send username
                if re.search(username_pattern, output, flags=re.I):
                    self.write_channel(self.username + self.TELNET_RETURN)
                    time.sleep(1 * delay_factor)
                    output = self.read_channel()
                    return_msg += output

                # Search for password pattern / send password
                if re.search(pwd_pattern, output, flags=re.I):
                    self.write_channel(self.password + self.TELNET_RETURN)
                    time.sleep(0.5 * delay_factor)
                    output = self.read_channel()
                    return_msg += output
                    if re.search(
                        pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Support direct telnet through terminal server
                if re.search(r"initial configuration dialog\? \[yes/no\]: ", output):
                    self.write_channel("no" + self.TELNET_RETURN)
                    time.sleep(0.5 * delay_factor)
                    count = 0
                    while count < 15:
                        output = self.read_channel()
                        return_msg += output
                        if re.search(r"ress RETURN to get started", output):
                            output = ""
                            break
                        time.sleep(2 * delay_factor)
                        count += 1

                # Check for device with no password configured
                if re.search(r"assword required, but none set", output):
                    self.remote_conn.close()
                    msg = "Login failed - Password required, but none set: {}".format(
                        self.host
                    )
                    raise Net_ConnectAuthenticationException(msg)

                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                    alt_prompt_terminator, output, flags=re.M
                ):
                    return return_msg

                self.write_channel(self.TELNET_RETURN)
                time.sleep(0.5 * delay_factor)
                i += 1
            except EOFError:
                self.remote_conn.close()
                msg = "Login failed: {}".format(self.host)
                raise Net_ConnectAuthenticationException(msg)

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
            alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        self.remote_conn.close()
        msg = "Login failed: {}".format(self.host)
        raise Net_ConnectAuthenticationException(msg)

    def cleanup(self):
        """Gracefully exit the SSH session."""
        try:
            self.exit_config_mode()
        except Exception:
            pass
        # Always try to send final 'exit' regardless of whether exit_config_mode works or not.
        self._session_log_fin = True
        self.write_channel("exit" + self.RETURN)

    def _autodetect_fs(self, cmd="dir", pattern=r"Directory of (.*)/"):
        """Autodetect the file system on the remote device. Used by SCP operations."""
        if not self.check_enable_mode():
            raise ValueError("Must be in enable mode to auto-detect the file-system.")
        output = self.send_command_expect(cmd)
        match = re.search(pattern, output)
        if match:
            file_system = match.group(1)
            # Test file_system
            cmd = "dir {}".format(file_system)
            output = self.send_command_expect(cmd)
            if "% Invalid" in output or "%Error:" in output:
                raise ValueError(
                    "An error occurred in dynamically determining remote file "
                    "system: {} {}".format(cmd, output)
                )
            else:
                return file_system

        raise ValueError(
            "An error occurred in dynamically determining remote file "
            "system: {} {}".format(cmd, output)
        )

    def save_config(
        self,
        cmd="copy running-config startup-config",
        confirm=False,
        confirm_response="",
    ):
        """Saves Config."""
        self.enable()
        if confirm:
            output = self.send_command_timing(command_string=cmd)
            if confirm_response:
                output += self.send_command_timing(confirm_response)
            else:
                # Send enter by default
                output += self.send_command_timing(self.RETURN)
        else:
            # Some devices are slow so match on trailing-prompt if you can
            output = self.send_command(command_string=cmd)
        return output

class CiscoSSHConnection(CiscoBaseConnection):
    pass

class Net_ConnectTimeoutException(SSHException):
    """SSH session timed trying to connect to the device."""
    pass

class LinuxSSH(CiscoSSHConnection):

    def session_preparation(self):
        """Prepare the session after the connection has been established."""
        self.ansi_escape_codes = True
        return super(LinuxSSH, self).session_preparation()

    def _enter_shell(self):
        """Already in shell."""
        return ""

    def _return_cli(self):
        """The shell is the CLI."""
        return ""

    def disable_paging(self, *args, **kwargs):
        """Linux doesn't have paging by default."""
        return ""

    def set_base_prompt(
        self,
        pri_prompt_terminator=LINUX_PROMPT_PRI,
        alt_prompt_terminator=LINUX_PROMPT_ALT,
        delay_factor=1,
    ):
        """Determine base prompt."""
        return super(LinuxSSH, self).set_base_prompt(
            pri_prompt_terminator=pri_prompt_terminator,
            alt_prompt_terminator=alt_prompt_terminator,
            delay_factor=delay_factor,
        )

    def send_config_set(self, config_commands=None, exit_config_mode=True, **kwargs):
        """Can't exit from root (if root)"""
        if self.username == "root":
            exit_config_mode = False
        return super(LinuxSSH, self).send_config_set(
            config_commands=config_commands, exit_config_mode=exit_config_mode, **kwargs
        )

    def check_config_mode(self, check_string=LINUX_PROMPT_ROOT):
        """Verify root"""
        return self.check_enable_mode(check_string=check_string)

    def config_mode(self, config_command="sudo su"):
        """Attempt to become root."""
        return self.enable(cmd=config_command)

    def exit_config_mode(self, exit_config="exit"):
        return self.exit_enable_mode(exit_command=exit_config)

    def check_enable_mode(self, check_string=LINUX_PROMPT_ROOT):
        """Verify root"""
        return super(LinuxSSH, self).check_enable_mode(check_string=check_string)

    def exit_enable_mode(self, exit_command="exit"):
        """Exit enable mode."""
        delay_factor = self.select_delay_factor(delay_factor=0)
        output = ""
        if self.check_enable_mode():
            self.write_channel(self.normalize_cmd(exit_command))
            time.sleep(0.3 * delay_factor)
            self.set_base_prompt()
            if self.check_enable_mode():
                raise ValueError("Failed to exit enable mode.")
        return output

    def enable(self, cmd="sudo su", pattern="ssword", re_flags=re.IGNORECASE):
        """Attempt to become root."""
        delay_factor = self.select_delay_factor(delay_factor=0)
        output = ""
        if not self.check_enable_mode():
            self.write_channel(self.normalize_cmd(cmd))
            time.sleep(0.3 * delay_factor)
            try:
                output += self.read_channel()
                if re.search(pattern, output, flags=re_flags):
                    self.write_channel(self.normalize_cmd(self.secret))
                self.set_base_prompt()
            except socket.timeout:
                raise Net_ConnectTimeoutException(
                    "Timed-out reading channel, data not available."
                )
            if not self.check_enable_mode():
                msg = (
                    "Failed to enter enable mode. Please ensure you pass "
                    "the 'secret' argument to ConnectHandler."
                )
                raise ValueError(msg)
        return output

    def cleanup(self):
        """Try to Gracefully exit the SSH session."""
        self._session_log_fin = True
        self.write_channel("exit" + self.RETURN)

    def save_config(self, *args, **kwargs):
        """Not Implemented"""
        raise NotImplementedError


########################################################################################################################
# Text Format Syntaxes
########################################################################################################################


def write_bytes(out_data, encoding="ascii"):
    """Write Python2 and Python3 compatible byte stream."""
    if sys.version_info[0] >= 3:
        if isinstance(out_data, type("")):
            if encoding == "utf-8":
                return out_data.encode("utf-8")
            else:
                return out_data.encode("ascii", "ignore")
        elif isinstance(out_data, type(b"")):
            return out_data
    else:
        if isinstance(out_data, type("")):
            if encoding == "utf-8":
                return out_data.encode("utf-8")
            else:
                return out_data.encode("ascii", "ignore")
        elif isinstance(out_data, type(str(""))):
            return out_data
    msg = "Invalid value for out_data neither unicode nor byte string: {}".format(
        out_data
    )
    raise ValueError(msg)

class CopyableRegexObject(object):
  """Like a re.RegexObject, but can be copied."""

  def __init__(self, pattern):
    self.pattern = pattern
    self.regex = re.compile(pattern)

  def match(self, *args, **kwargs):
    return self.regex.match(*args, **kwargs)

  def sub(self, *args, **kwargs):
    return self.regex.sub(*args, **kwargs)

  def __copy__(self):
    return CopyableRegexObject(self.pattern)

  def __deepcopy__(self, unused_memo):
    return self.__copy__()

class Error(Exception):
    """The base error class."""

class Usage(Error):
    """Command line format error."""

def EncloseAnsiText(text):
  """Enclose ANSI/SGR escape sequences with ANSI_START and ANSI_END."""
  return sgr_re.sub(lambda x: ANSI_START + x.group(1) + ANSI_END, text)

def clitable_to_dict(cli_table):
    """Converts TextFSM cli_table object to list of dictionaries."""
    objs = []
    for row in cli_table:
        temp_dict = {}
        for index, element in enumerate(row):
            temp_dict[cli_table.header[index].lower()] = element
        objs.append(temp_dict)
    return objs

def get_template_dir():
    """Find and return the ntc-templates/templates dir."""
    try:
        template_dir = os.path.expanduser(os.environ["NET_TEXTFSM"])
        index = os.path.join(template_dir, "index")
        if not os.path.isfile(index):
            # Assume only base ./ntc-templates specified
            template_dir = os.path.join(template_dir, "templates")
    except KeyError:
        # Construct path ~/ntc-templates/templates
        home_dir = os.path.expanduser("~")
        template_dir = os.path.join(home_dir, "ntc-templates", "templates")

    index = os.path.join(template_dir, "index")
    if not os.path.isdir(template_dir) or not os.path.isfile(index):
        msg = """
Valid ntc-templates not found, please install https://github.com/networktocode/ntc-templates
and then set the NET_TEXTFSM environment variable to point to the ./ntc-templates/templates
directory."""
        raise ValueError(msg)
    return os.path.abspath(template_dir)

def get_structured_data(raw_output, platform, command):
    """Convert raw CLI output to structured data using TextFSM template."""
    template_dir = get_template_dir()
    index_file = os.path.join(template_dir, "index")
    textfsm_obj = clitable.CliTable(index_file, template_dir)
    attrs = {"Command": command, "Platform": platform}
    try:
        # Parse output through template
        textfsm_obj.ParseCmd(raw_output, attrs)
        structured_data = clitable_to_dict(textfsm_obj)
        output = raw_output if structured_data == [] else structured_data
        return output
    except CliTableError:
        return raw_output

def get_structured_data_genie(raw_output, platform, command):
    if not sys.version_info >= (3, 4):
        raise ValueError("Genie requires Python >= 3.4")

    if not GENIE_INSTALLED:
        msg = (
            "\nGenie and PyATS are not installed. Please PIP install both Genie and PyATS:\n"
            "pip install genie\npip install pyats\n"
        )
        raise ValueError(msg)

    if "cisco" not in platform:
        return raw_output

    genie_device_mapper = {
        "cisco_ios": "ios",
        "cisco_xe": "iosxe",
        "cisco_xr": "iosxr",
        "cisco_nxos": "nxos",
        "cisco_asa": "asa",
    }

    os = None
    # platform might be _ssh, _telnet, _serial strip that off
    if platform.count("_") > 1:
        base_platform = platform.split("_")[:-1]
        base_platform = "_".join(base_platform)
    else:
        base_platform = platform

    os = genie_device_mapper.get(base_platform)
    if os is None:
        return raw_output

    # Genie specific construct for doing parsing (based on Genie in Ansible)
    device = Device("new_device", os=os)
    device.custom.setdefault("abstraction", {})
    device.custom["abstraction"]["order"] = ["os"]
    device.cli = AttrDict({"execute": None})
    try:
        # Test of whether their is a parser for the given command (will return Exception if fails)
        get_parser(command, device)
        parsed_output = device.parse(command, output=raw_output)
        return parsed_output
    except Exception:
        return raw_output

class Error(Exception):
  """Base class for errors."""

class IndexTableError(Error):
  """General INdexTable error."""

class CliTableError(Error):
  """General CliTable error."""

################################################################################################################
                    # Net_Connect Modules
###############################################################################################################

class SSHException(Exception):
    """
    Exception raised by failures in SSH2 protocol negotiation or logic errors.
    """
    pass

class AuthenticationException(SSHException):
    """
    Exception raised when authentication failed for some reason.  It may be
    possible to retry with different credentials.  (Other classes specify more
    specific reasons.)
    .. versionadded:: 1.6
    """
    pass

class PasswordRequiredException(AuthenticationException):
    """
    Exception raised when a password is needed to unlock a private key file.
    """
    pass

class BadAuthenticationType(AuthenticationException):
    """
    Exception raised when an authentication type (like password) is used, but
    the server isn't allowing that type.  (It may only allow public-key, for
    example.)
    .. versionadded:: 1.1
    """
    allowed_types = []

    # TODO 3.0: remove explanation kwarg
    def __init__(self, explanation, types):
        # TODO 3.0: remove this supercall unless it's actually required for
        # pickling (after fixing pickling)
        AuthenticationException.__init__(self, explanation, types)
        self.explanation = explanation
        self.allowed_types = types

    def __str__(self):
        return "{}; allowed types: {!r}".format(
            self.explanation, self.allowed_types
        )

class PartialAuthentication(AuthenticationException):
    """
    An internal exception thrown in the case of partial authentication.
    """

    allowed_types = []

    def __init__(self, types):
        AuthenticationException.__init__(self, types)
        self.allowed_types = types

    def __str__(self):
        return "Partial authentication; allowed types: {!r}".format(
            self.allowed_types
        )

class ChannelException(SSHException):
    """
    Exception raised when an attempt to open a new `.Channel` fails.

    :param int code: the error code returned by the server

    .. versionadded:: 1.6
    """
    def __init__(self, code, text):
        SSHException.__init__(self, code, text)
        self.code = code
        self.text = text

    def __str__(self):
        return "ChannelException({!r}, {!r})".format(self.code, self.text)

class BadHostKeyException(SSHException):
    """
    The host key given by the SSH server did not match what we were expecting.

    :param str hostname: the hostname of the SSH server
    :param PKey got_key: the host key presented by the server
    :param PKey expected_key: the host key expected

    .. versionadded:: 1.6
    """

    def __init__(self, hostname, got_key, expected_key):
        SSHException.__init__(self, hostname, got_key, expected_key)
        self.hostname = hostname
        self.key = got_key
        self.expected_key = expected_key

    def __str__(self):
        msg = (
            "Host key for server '{}' does not match: got '{}', expected '{}'"
        )  # noqa
        return msg.format(
            self.hostname,
            self.key.get_base64(),
            self.expected_key.get_base64(),
        )

class ProxyCommandFailure(SSHException):
    """
    The "ProxyCommand" found in the .ssh/config file returned an error.

    :param str command: The command line that is generating this exception.
    :param str error: The error captured from the proxy command output.
    """
    def __init__(self, command, error):
        SSHException.__init__(self, command, error)
        self.command = command
        self.error = error

    def __str__(self):
        return 'ProxyCommand("{}") returned nonzero exit status: {}'.format(
            self.command, self.error
        )

class NoValidConnectionsError(socket.error):
    """
    Multiple connection attempts were made and no families succeeded.

    This exception class wraps multiple "real" underlying connection errors,
    all of which represent failed connection attempts. Because these errors are
    not guaranteed to all be of the same error type (i.e. different errno,
    `socket.error` subclass, message, etc) we expose a single unified error
    message and a ``None`` errno so that instances of this class match most
    normal handling of `socket.error` objects.

    To see the wrapped exception objects, access the ``errors`` attribute.
    ``errors`` is a dict whose keys are address tuples (e.g. ``('127.0.0.1',
    22)``) and whose values are the exception encountered trying to connect to
    that address.

    It is implied/assumed that all the errors given to a single instance of
    this class are from connecting to the same hostname + port (and thus that
    the differences are in the resolution of the hostname - e.g. IPv4 vs v6).

    .. versionadded:: 1.16
    """
    def __init__(self, errors):
        """
        :param dict errors:
            The errors dict to store, as described by class docstring.
        """
        addrs = sorted(errors.keys())
        body = ", ".join([x[0] for x in addrs[:-1]])
        tail = addrs[-1][0]
        if body:
            msg = "Unable to connect to port {0} on {1} or {2}"
        else:
            msg = "Unable to connect to port {0} on {2}"
        super(NoValidConnectionsError, self).__init__(
            None, msg.format(addrs[0][1], body, tail)  # stand-in for errno
        )
        self.errors = errors

    def __reduce__(self):
        return (self.__class__, (self.errors,))

class Error(Exception):
    """Base class for errors."""

class IndexTableError(Error):
    """General INdexTable error."""

class CliTableError(Error):
    """General CliTable error."""

class IndexTable(object):
    """Class that reads and stores comma-separated values as a TextTable.
  Stores a compiled regexp of the value for efficient matching.
  Includes functions to preprocess Columns (both compiled and uncompiled).
  Attributes:
    index: TextTable, the index file parsed into a texttable.
    compiled: TextTable, the table but with compiled regexp for each field.
  """

    def __init__(self, preread=None, precompile=None, file_path=None):
        """Create new IndexTable object.
    Args:
      preread: func, Pre-processing, applied to each field as it is read.
      precompile: func, Pre-compilation, applied to each field before compiling.
      file_path: String, Location of file to use as input.
    """
        self.index = None
        self.compiled = None
        if file_path:
            self._index_file = file_path
            self._index_handle = open(self._index_file, "r")
            self._ParseIndex(preread, precompile)

    def __del__(self):
        """Close index handle."""
        if hasattr(self, "_index_handle"):
            self._index_handle.close()

    def __len__(self):
        """Returns number of rows in table."""
        return self.index.size

    def __copy__(self):
        """Returns a copy of an IndexTable object."""
        clone = IndexTable()
        if hasattr(self, "_index_file"):
            # pylint: disable=protected-access
            clone._index_file = self._index_file
            clone._index_handle = self._index_handle

        clone.index = self.index
        clone.compiled = self.compiled
        return clone

    def __deepcopy__(self, memodict=None):
        """Returns a deepcopy of an IndexTable object."""
        clone = IndexTable()
        if hasattr(self, "_index_file"):
            # pylint: disable=protected-access
            clone._index_file = copy.deepcopy(self._index_file)
            clone._index_handle = open(clone._index_file, "r")

        clone.index = copy.deepcopy(self.index)
        clone.compiled = copy.deepcopy(self.compiled)
        return clone

    def _ParseIndex(self, preread, precompile):
        """Reads index file and stores entries in TextTable.
    For optimisation reasons, a second table is created with compiled entries.
    Args:
      preread: func, Pre-processing, applied to each field as it is read.
      precompile: func, Pre-compilation, applied to each field before compiling.
    Raises:
      IndexTableError: If the column headers has illegal column labels.
    """
        self.index = texttable.TextTable()
        self.index.CsvToTable(self._index_handle)

        if preread:
            for row in self.index:
                for col in row.header:
                    row[col] = preread(col, row[col])

        self.compiled = copy.deepcopy(self.index)

        for row in self.compiled:
            for col in row.header:
                if precompile:
                    row[col] = precompile(col, row[col])
                if row[col]:
                    row[col] = copyable_regex_object.CopyableRegexObject(row[col])

    def GetRowMatch(self, attributes):
        """Returns the row number that matches the supplied attributes."""
        for row in self.compiled:
            try:
                for key in attributes:
                    # Silently skip attributes not present in the index file.
                    # pylint: disable=E1103
                    if (
                        key in row.header
                        and row[key]
                        and not row[key].match(attributes[key])
                    ):
                        # This line does not match, so break and try next row.
                        raise StopIteration()
                return row.row
            except StopIteration:
                pass
        return 0

class SCPConn(object):
    """
    Establish a secure copy channel to the remote network device.

    Must close the SCP connection to get the file to write to the remote filesystem
    """
    def __init__(self, ssh_conn):
        self.ssh_ctl_chan = ssh_conn
        self.establish_scp_conn()

    def establish_scp_conn(self):
        """Establish the secure copy connection."""
        ssh_connect_params = self.ssh_ctl_chan._connect_params_dict()
        self.scp_conn = self.ssh_ctl_chan._build_ssh_client()
        self.scp_conn.connect(**ssh_connect_params)
        self.scp_client = scp.SCPClient(self.scp_conn.get_transport())

    def scp_transfer_file(self, source_file, dest_file):
        """Put file using SCP (for backwards compatibility)."""
        self.scp_client.put(source_file, dest_file)

    def scp_get_file(self, source_file, dest_file):
        """Get file using SCP."""
        self.scp_client.get(source_file, dest_file)

    def scp_put_file(self, source_file, dest_file):
        """Put file using SCP."""
        self.scp_client.put(source_file, dest_file)

    def close(self):
        """Close the SCP connection."""
        self.scp_conn.close()

class Net_ConnectAuthenticationException(AuthenticationException):
    """SSH authentication exception based on Paramiko AuthenticationException."""
    pass

class TelnetConnection(BaseConnection):
    pass

class TerminalServerTelnet(TerminalServer):
    """Generic Terminal Server driver telnet."""
    def telnet_login(self, *args, **kwargs):
        # Disable automatic handling of username and password when using terminal server driver
        pass

    def std_login(self, *args, **kwargs):
        return super(TerminalServerTelnet, self).telnet_login(*args, **kwargs)

