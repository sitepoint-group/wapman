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
        return self.access_points.keys()

    def get_connection_settings(self, ap_name):
        return self.access_points.get(ap_name, None)


class WAPManagement(object):

    def __init__(self):
        pass

    def get_ssid_interface(self):
        pass


class RuckusManagement(WAPManagement):

    def __init__(self, apc):
        """Takes an instance of AccessPointConnections()"""
        self.apc = apc

    def __do_ssh_login(self, ap_name, cs):
        try:
            ip = cs.get('ip')
            fingerprint = cs['protocol']['ssh']['fingerprint']
        except KeyError:
            sys.stderr.write('Missing required connection data.\n')
            sys.exit(1)

        username, password, protocol = self.__get_login_credentials(ap_name)

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
            if (
                len(line_list) == 7 and line_list[1] == status and
                line_list[6] != '00:00:00:00:00:00'
            ):
                if not ssid_filter or re.match(ssid_filter, line_list[6]):
                    result[line_list[3]] = {
                        'radioID': line_list[4],
                        'bssid': line_list[5],
                        'ssid': line_list[6]
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
        """Change the PSK passphrase for a given WAP interface

        rkscli: set encryption wlan8
        Wireless Encryption Type: [0] quit, [1] OPEN, [2] WEP, or [3] WPA
        Wireless Encryption Type:  3
        WPA Protocol Version: [0] quit, [1] WPA, [2] WPA2, or [3] AUTO
        Wpa Protocol Version: 2
        WPA Authentication Type: [0] quit, [1] OPEN (PSK), [2] EAP (.1X), or [3] AUTO
        WPA Authentication Type:  1
        WPA Cipher Type: [0] quit, [1] TKIP, [2] AES-CCMP, or [3] AUTO
        WPA Cipher Type:  3
        WPA PassPhrase: "SomePassword"
        Enter A New PassPhrase [8-63 letters], or Press "Enter" to Accept : SomeOtherPassword
        WPA no error
        OK
        """

        # WPA2
        wpa_protocol='2'
        # OPEN (PSK)
        wpa_auth='1'
        # AUTO
        wpa_cipher='3'

        p = self.__get_pexpect_spawn(ap_name)

        p.expect('rkscli: ')
        p.sendline('set encryption %s' % interface)
        p.expect('Wireless Encryption Type: ')
        p.sendline('3')
        p.expect('WPA Protocol Version: ')
        p.sendline('2')
        p.expect('WPA Authentication Type: ')
        p.sendline('1')  # OPEN (PSK)
        p.expect('WPA Cipher Type: ')
        p.sendline('3')  # AUTO
        p.expect_exact('Enter A New PassPhrase [8-63 letters], or Press "Enter" to Accept : ')
        sys.stdout.write("Replacing old {}\n".format(p.before.splitlines()[-1]))
        p.sendline(passphrase)
        p.expect('WPA no error')
        p.expect('OK')
        p.expect('rkscli: ')
        p.sendline('exit')


class InitSetup(object):

    def __init__(self):
        self.apc = None
        self.args = None

    def parse_args(self):
        """Parse command line options"""

        parser = argparse.ArgumentParser(
            description="""Ruckus WAP manager

The supported commands are:
 guestpasswd  Change the guest password (short-cut alias: "g")
 logs         Print the logs (short-cut alias: "l")
 ssid         Print the configured SSIDs (short-cut alias: "s")
""",
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
            choices=['logs', 'ssid', 'guestpasswd'],
            help=('Command to run'),
            metavar='COMMAND'
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
        for wap in self.apc.list_wap_hosts():
            if wap in options.hosts:
                return f(self, wap, *args, **kwargs)
    return wap_loop


class MarkdownFormatter(object):
    """Basic Markdown-compatible string formatting"""

    @staticmethod
    def format_heading(heading, underscore_char='='):
        formatted_heading = "{0}\n".format(heading)
        for i in range(len(heading)):
            formatted_heading += underscore_char
        formatted_heading += "\n"
        return formatted_heading

    @staticmethod
    def format_sub_heading(heading):
        return MarkdownFormatter.format_heading(heading, '-')


class Controller(object):
    """Figures out what to do and issues the order"""

    def __init__(self, options, apc, rm):
        self.options = options
        self.apc = apc
        self.rm = rm
        self.password = None

    @loop_over_waps
    def __get_logs(self, wap):
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
    def __change_guest_password(self, wap):
        # get interface
        iface_configs = rm.get_ssid_interfaces(
            wap, status='up', ssid_filter='^sitepoint-guest$'
        )
        for interface in iface_configs.keys():
            print "Updating password on %s, %s..." % (wap, interface)
            rm.change_psk_passphrase(wap, interface, self.password)

    def __print_logs(self):
        print self.__get_logs()

    def __print_ssid_interfaces(self):
        print self.__get_ssid_interfaces()

    def issue_command(self):
        """Run the command from the class self.options"""

        if options.command == 'logs':
            self.__print_logs()
        elif options.command == 'ssid':
            self.__print_ssid_interfaces()
        elif options.command == 'guestpasswd':
            self.password = getpass.getpass(
                prompt="Please enter a new guest password: "
            )
            if self.password != getpass.getpass(
                    prompt="Please re-enter the guest password: "
            ):
                print "Password mismatch! Aborting."
            elif not self.password:
                print "You must enter a password. Aborting."
            else:
                self.__change_guest_password()
        else:
            sys.stderr.write("Unavailable option requested.\n")
            sys.exit(1)


m = MarkdownFormatter()
setup = InitSetup()
options = setup.parse_args()
apc = setup.import_config(options.config)
rm = RuckusManagement(apc)
controller = Controller(options, apc, rm)
controller.issue_command()
