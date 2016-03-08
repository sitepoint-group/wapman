#!/usr/bin/env python
#
# Adam Bolte <adam.bolte@sitepoint.com>
# Copyright (c) 2016 SitePoint Pty Ltd.


# Python Standard Library
import argparse
import getpass
import operator
import re
import sys
from textwrap import dedent

# 3rd party modules
try:
    import pexpect
except ImportError:
    sys.stdout.write('Error: pexpect module not found.\n')
    sys.exit(1)
try:
    import yaml
except ImportError:
    sys.stdout.write('Error: yaml module not found.\n')
    sys.exit(1)


class AccessPointConnections(object):
    """Define local WAP connection details"""

    devices = {
        'ruckus': {
            '7982': {
            }
        }
    }

    def __init__(self, yaml_data):
        """Define access point credentials here"""
        yaml_as_dict = yaml.load(yaml_data)
        append_device_settings = {}

        if 'access_points' not in yaml_as_dict:
            sys.stdout.write("Error: 'access_points' yaml key missing.\n")
            sys.exit(1)
        else:
            self.access_points = yaml.load(yaml_data).get('access_points')

        # Add any device-specific configuration as required.
        for wap in self.access_points:
            brand = self.access_points[wap].get('brand')
            model = self.access_points[wap].get('model')
            if brand in self.devices:
                if model in self.devices[brand]:
                    append_device_settings.update(
                        self.devices[brand][model]
                    )
            self.access_points[wap].update(append_device_settings)

    def list_wap_hosts(self):
        """Return a list of all known access points."""
        return self.access_points.keys()

    def get_connection_settings(self, ap_name):
        """Return a dictionary containing defined settings for one WAP"""
        return self.access_points.get(ap_name, None)


class WAPManagement(object):
    """Base class listing all generic WAP functions to be overridden"""

    def __init__(self):
        pass

    def get_ssid_interface(self, ap_name, status='up', ssid_filter=None):
        pass

    def get_logs(self, ap_name):
        pass

    def change_psk_passphrase(self, ap_name, interface, passphrase):
        pass


class RuckusSSHManagement(WAPManagement):
    """Support for Ruckus WAP management using SSH"""

    def __init__(self, apc):
        """Takes an instance of AccessPointConnections()"""
        self.apc = apc

    def __do_ssh_login(self, ap_name, cs):
        """Establish an SSH session to the WAP"""
        try:
            ip = cs.get('ip')
            fingerprint = cs['protocol']['ssh']['fingerprint']
        except KeyError:
            sys.stderr.write('Missing required connection data.\n')
            sys.exit(1)

        username, password, protocol = self.__get_login_credentials(
            ap_name
        )
        new_ssh = " fingerprint is {0}.\r\n".format(fingerprint) + \
            "Are you sure you want to continue connecting (yes/no)?"
        p = pexpect.spawn('ssh', args=[ip], timeout=2)
        i = p.expect([new_ssh, 'Please login: ', pexpect.EOF], timeout=2)

        if i == 0:
            p.sendline('yes')
            i = p.expect([new_ssh, 'Please login: ', pexpect.EOF])
        if i == 1:
            p.sendline(username)
        if i == 2:
            print "Connection failure to '{0}'.".format(ip)
            sys.exit(1)
        p.expect('password : ')
        p.sendline(password)

        return p

    def __get_login_credentials(self, ap_name):
        """Return management credentials"""
        cs = self.apc.get_connection_settings(ap_name)
        try:
            username = cs['username']
            password = cs['password']
            protocol = cs['protocol']
        except TypeError:
            sys.stderr.write("Failed lookup for '{0}'.\n".format(ap_name))
            sys.exit(1)
        except KeyError:
            sys.stderr.write(
                "Failed to obtain credentials for '{0}'.\n".format(
                    ap_name
                )
            )
            sys.exit(1)

        return (username, password, protocol)

    def __get_pexpect_spawn(self, ap_name):
        """Verify SSH is available, and spawn a session"""
        cs = self.apc.get_connection_settings(ap_name)

        if 'ssh' in cs.get('protocol'):
            p = self.__do_ssh_login(ap_name, cs)
        else:
            sys.stdout.write(
                "Unsupported protocol defined for '{0}'.\n".format(
                    ap_name
                )
            )
            sys.exit(1)

        return p

    def get_ssid_interfaces(self, ap_name, status='up', ssid_filter=None):
        """Print configured SSIDs"""
        p = self.__get_pexpect_spawn(ap_name)
        result = {}
        p.expect('rkscli: ')
        p.sendline('get wlanlist')
        p.expect('rkscli: ')
        re_status = re.compile(r'^\w+\s+up\s+.*')

        for line in [x.strip() for x in p.before.splitlines()]:
            line_list = re.split('\s+', line)
            # Version 9.8.* output of "get wlanlist" looks like:
            # svcp up AP wlan0 0 e0:10:7f:3e:7a:98 sitepoint-guest
            if (
                len(line_list) == 7 and line_list[1] == status and
                line_list[5] != '00:00:00:00:00:00'
            ):
                if not ssid_filter or re.match(ssid_filter, line_list[6]):
                    result[line_list[3]] = {
                        'radioID': line_list[4],
                        'bssid': line_list[5],
                        'ssid': line_list[6]
                    }
            # Older firmware didn't print the last ssid column. This
            # section adds backwards compatibility for pre-9.8.*
            # firmware, but is slower than the above due to the extra
            # command required.
            elif (
                len(line_list) == 6 and line_list[1] == status and
                line_list[5] != '00:00:00:00:00:00'
            ):
                p.sendline('get ssid {}'.format(line_list[3]))
                p.expect('OK')
                ssid = re.split(
                    '\s+', p.before.splitlines()[-1].strip()
                )[-1]
                p.expect('rkscli:')

                if not ssid_filter or re.match(ssid_filter, ssid):
                    result[line_list[3]] = {
                        'radioID': line_list[4],
                        'bssid': line_list[5],
                        'ssid': ssid
                    }

        p.sendline('exit')
        return result

    def get_logs(self, ap_name):
        """Print WAP logs"""
        p = self.__get_pexpect_spawn(ap_name)
        result = ""

        p.expect('rkscli: ')
        p.sendline('get syslog log')
        p.expect('rkscli: ')
        result += p.before
        p.sendline('exit')
        return result

    def change_psk_passphrase(self, ap_name, interface, passphrase):
        """Change the PSK passphrase for a given WAP interface"""

        wpa_protocol='2' # WPA2
        wpa_auth='1'     # OPEN (PSK)
        wpa_cipher='3'   # AUTO
        p = self.__get_pexpect_spawn(ap_name)

        p.expect('rkscli: ')
        p.sendline('set encryption %s' % interface)
        p.expect('Wireless Encryption Type: ')
        p.sendline('3')
        p.expect('WPA Protocol Version: ')
        p.sendline(wpa_protocol)
        p.expect('WPA Authentication Type: ')
        p.sendline(wpa_auth)
        p.expect('WPA Cipher Type: ')
        p.sendline(wpa_cipher)
        p.expect_exact(
            'Enter A New PassPhrase [8-63 letters], or ' + \
            'Press "Enter" to Accept : '
        )
        #sys.stdout.write("Replacing old {}\n".format(
        #    p.before.splitlines()[-1])
        #)
        p.sendline(passphrase)
        i = p.expect(['WPA no error', pexpect.EOF])
        p.expect('OK')
        p.expect('rkscli: ')
        p.sendline('exit')

        if i != 0:
            return False
        return True


class InitSetup(object):
    """Arguments and settings handler"""

    def __init__(self):
        self.apc = None
        self.args = None
        self.valid_commands = ['logs', 'passwd', 'ssid']

    def command_string(self, argument):
        """Accept partial but unique command arguments"""
        matches = []
        for command in self.valid_commands:
            if re.match(r'^{}'.format(argument), command):
                matches.append(command)

        if len(matches) > 1:
            sys.stderr.write(
                "Error: Ambiguous command!\n\nMultiple matches found:\n"
            )
            for match in matches:
                sys.stderr.write(" {}\n".format(match))
            sys.exit(1)
        elif not matches:
            sys.stderr.write(
                "Error: Invalid command!\n\nCommand options include:\n"
            )
            for command in self.valid_commands:
                sys.stderr.write(" {}\n".format(command))
            sys.exit(1)
        else:
            return matches[0]

    def parse_args(self):
        """Parse command line options"""

        description = """
        Ruckus WAP manager

        The supported commands are:
         logs         Print the logs
         passwd       Change an SSID password
         ssid         Print the configured SSIDs
        """
        parser = argparse.ArgumentParser(
            description=dedent(description),
            formatter_class=argparse.RawTextHelpFormatter

        )
        parser.add_argument(
            '-H', '--host',
            action='append',
            help='Host defined in configuration, can be\n' + \
                'specified multiple times (default: all hosts)',
            dest='hosts'
        )
        parser.add_argument(
            '-c', '--config',
            default='access_points.yml',
            help='YAML configuration file defining access point\n' + \
                'credentials (default: %(default)s)'
        )
        parser.add_argument(
            'command',
            type=self.command_string,
            help=('Command to run'),
            metavar='COMMAND'
        )
        parser.add_argument(
            'remainder',
            nargs=argparse.REMAINDER,
            help=argparse.SUPPRESS
        )

        self.args = parser.parse_args()

        # Typically we would only run parse_args and import_config
        # once, but the order doesn't matter. Validate the WAPs when
        # both are ready.
        if self.apc:
            self.host_config_check()

        return self.args

    def import_config(self, config):
        """Return YAML configuration file contents as dict"""

        try:
            f = open(config, 'r')
            self.apc = AccessPointConnections(f.read())
            f.close()
        except IOError:
            sys.stderr.write(
                "Unable to open '{0}' config file.\n".format(config)
            )
            sys.exit(1)

        # Typically we would only run parse_args and import_config
        # once, but the order doesn't matter. Validate the WAPs when
        # both are ready.
        if self.args:
            self.host_config_check()

        return self.apc

    def host_config_check(self):
        """Check all host arguments are in the configuration file"""

        if self.args.hosts:
            for requested_wap in self.args.hosts:
                if requested_wap not in self.apc.list_wap_hosts():
                    sys.stderr.write(
                        "WAP {} is missing from config {}!\n".format(
                            requested_wap, self.args.config
                        )
                    )
                    sys.exit(1)
        else:
            self.args.hosts = self.apc.list_wap_hosts()


def loop_over_waps(f):
    def wap_loop(self, *args, **kwargs):
        results = {}
        for wap in self.apc.list_wap_hosts():
            if wap in options.hosts:
                results[wap] = f(self, wap, *args, **kwargs)
        return results
    return wap_loop


class MarkdownFormatter(object):
    """Basic Markdown-compatible string formatting"""

    @staticmethod
    def format_heading(heading, underscore_char='='):
        """Format string as a Markdown heading"""
        formatted_heading = "{0}\n".format(heading)
        for i in range(len(heading)):
            formatted_heading += underscore_char
        formatted_heading += "\n"
        return formatted_heading

    @staticmethod
    def format_sub_heading(heading):
        """Format string as a Markdown sub-heading"""
        return MarkdownFormatter.format_heading(heading, '-')


class Controller(object):
    """Figures out what to do and issues the order"""

    def __init__(self, options, apc, rm):
        self.options = options
        self.apc = apc
        self.rm = rm
        self.ssid = None
        self.password = None

        # Basic stats tracking
        self.password_updates = 0
        self.wap_updates = 0

    @loop_over_waps
    def __get_logs(self, wap):
        """Return formatted logs as a string for a given WAP"""
        return "{0}{1}".format(
            MarkdownFormatter.format_heading(wap),
            rm.get_logs(wap)
        )

    @loop_over_waps
    def __get_ssid_interfaces(self, wap, ssid_filter=None):

        ssid = rm.get_ssid_interfaces(
            wap, status='up', ssid_filter=ssid_filter
        )
        output = MarkdownFormatter.format_heading(wap)

        for wlanID, entry in sorted(
            ssid.iteritems(),
            key=operator.itemgetter(1)
        ):
            output += "{0}\t{1}\t{2}\t{3}\n".format(
                entry['ssid'],
                wlanID,
                entry['radioID'],
                entry['bssid']
            )
        return output

    @loop_over_waps
    def __change_ssid_password(self, wap):
        old_updates = self.password_updates
        iface_configs = rm.get_ssid_interfaces(
            wap, status='up', ssid_filter=r'^{}$'.format(self.ssid)
        )
        for interface in iface_configs.keys():
            print "Updating %s (%s)..." % (wap, interface)
            if rm.change_psk_passphrase(wap, interface, self.password):
                self.password_updates += 1
        # Check any password updates were actually performed.
        if old_updates < self.password_updates:
            self.wap_updates += 1

    def __print_logs(self):
        """Get formatted logs and print them."""
        for wap_log in self.__get_logs().values():
            print wap_log

    def __print_ssid_interfaces(self):
        """Get SSID interfaces and print them."""
        for value in self.__get_ssid_interfaces().values():
            print value

    def __prompt_user_for_password(self):
        try:
            self.password = getpass.getpass(
                prompt="Please enter a new {} password: ".format(self.ssid)
            )
            if self.password != getpass.getpass(
                prompt="Please re-enter the {} password: ".format(self.ssid)
            ):
                print "Password mismatch! Aborting."
            elif not self.password:
                print "You must enter a password. Aborting."
        except KeyboardInterrupt:
            sys.stderr.write("\nAborting.\n")
            sys.exit(1)

        if not self.password:
            return False
        else:
            return self.password

    def __print_passwd_help(self):
        sys.stderr.write(dedent(
            """
            passwd sub-arguments:
             SSID             SSID name to reset
             [PASSWORD]       Set PSK to this (default: user is prompted)
            """
        ).lstrip())

    def __print_stats(self):
        # Only print a separator if other we have results.
        if self.password_updates:
            print "\n---"
        print "Password updated on {} WAPs.".format(self.wap_updates)
        print "Password updated on {} interfaces.".format(
            self.password_updates
        )

    def issue_command(self):
        """Run the command from the class self.options"""

        if options.command == 'logs':
            self.__print_logs()
        elif options.command == 'ssid':
            self.__print_ssid_interfaces()
        elif options.command == 'passwd':
            if not self.options.remainder:
                self.__print_passwd_help()
                sys.exit(1)
            else:
                self.ssid = self.options.remainder[0]
            if not self.password:
                if len(self.options.remainder) == 2:
                    self.password = self.options.remainder[1]
                else:
                    self.__prompt_user_for_password()
            self.__change_ssid_password()
            self.__print_stats()
        else:
            sys.stderr.write("Unavailable option requested.\n")
            sys.exit(1)


if __name__ == "__main__":
    try:
        setup = InitSetup()
        options = setup.parse_args()
        apc = setup.import_config(options.config)
        rm = RuckusSSHManagement(apc)
        controller = Controller(options, apc, rm)
        controller.issue_command()
    except KeyboardInterrupt:
        sys.exit(1)
