#!/usr/bin/env python
#
# Adam Bolte <adam.bolte@sitepoint.com>
# Copyright (c) 2016 SitePoint Pty Ltd.


# Python Standard Library
import argparse
import pprint
import sys
import textwrap

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

    def get_ssid_interfaces(self, ap_name):
        """Print configured SSIDs"""
        p = self.__get_pexpect_spawn(ap_name)

        p.expect('rkscli: ')
        p.sendline('get wlanlist')
        p.expect('rkscli: ')
        print p.before
        p.sendline('exit')

    def get_logs(self, ap_name):
        """Print WAP logs"""
        p = self.__get_pexpect_spawn(ap_name)

        p.expect('rkscli: ')
        p.sendline('get syslog log')
        p.expect('rkscli: ')
        print p.before
        p.sendline('exit')

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

        p = self.__get_pexpect_spawn(
            self.__get_login_credentials(
                ap_name
            )
        )

        # This will fail since expect will match the question as well as the prompt:
        p.expect('rkscli: ')
        p.sendline('get encryption wlan8')
        p.expect('Wireless Encryption Type: ')
        p.sendline('3')
        p.expect('WPA Protocol Version: ')
        p.sendline('2')
        p.expect('WPA Authentication Type: ')
        p.sendline('1')  # OPEN (PSK)
        p.expect('WPA Cipher Type: ')
        p.sendline('3')  # AUTO
        p.expect('Enter A New PassPhrase [8-63 letters], or Press "Enter" to Accept : ')
        p.sendline("MoonshineSolosCreation'sBrushwood")


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


def loop_over_waps(command):
    def wap_loop(self):
        for wap in self.apc.list_wap_hosts():
            if wap in options.hosts:
                print "{0}:".format(wap)
                command(self, wap)
    return wap_loop


class Controller(object):
    """Figures out what to do and issues the order"""

    def __init__(self, options, apc, rm):
        self.options = options
        self.apc = apc
        self.rm = rm

    @loop_over_waps
    def __get_logs(self, wap):
        rm.get_logs(wap)

    @loop_over_waps
    def __get_ssid_interfaces(self, wap):
        rm.get_ssid_interfaces(wap)

    @loop_over_waps
    def __change_guest_password(self, wap):
        rm.change_psk_passphrase(wap)

    def issue_command(self):
        """Run the command from the class self.options"""

        if options.command == 'logs':
            self.__get_logs()
        elif options.command == 'ssid':
            self.__get_ssid_interfaces()
        elif options.command == 'guestpasswd':
            print "Please enter a new guest password:"
            # ...
            self.__change_guest_password()
        else:
            sys.stderr.write("Unavailable option requested.\n")
            sys.exit(1)


setup = InitSetup()
options = setup.parse_args()
apc = setup.import_config(options.config)
rm = RuckusManagement(apc)
controller = Controller(options, apc, rm)
controller.issue_command()
