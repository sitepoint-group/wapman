#!/usr/bin/env python
#
# Adam Bolte <adam.bolte@sitepoint.com>
# Copyright (c) 2016 SitePoint Pty Ltd.


# Python Standard Library
import pprint
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
    """ Define local WAP connection details """

    devices = {
        'ruckus': {
            '7982': {
            }
        }
    }

    def __init__(self, yaml_data):
        """Define access point credentials here."""

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

    def list_wireless_access_points(self):
        return self.access_points.keys()

    def get_connection_settings(self, ap_name):
        return self.access_points.get(ap_name, None)


class WAPManagement(object):

    def __init__(self):
        pass

    def get_ssid_interface(self):
        pass


# FIXME: Remove all print statements from this class.
class RuckusManagement(WAPManagement):

    def __init__(self, apc):
        """Takes an instance of AccessPointConnections()."""
        self.apc = apc

    def __do_ssh_login(self, ap_name, cs):
        try:
            ip = cs.get('ip')
            fingerprint = cs['protocol']['ssh']['fingerprint']
        except KeyError:
            sys.stderr.write('Missing required connection data.\n')
            sys.exit(1)

        username, password, protocol = self.__get_login_credentials(ap_name)

        new_ssh = " fingerprint is %s.\r\n" % fingerprint + \
            "Are you sure you want to continue connecting (yes/no)?"
        p = pexpect.spawn('ssh', args=[ip], timeout=2)
        i = p.expect([new_ssh, 'Please login: ', pexpect.EOF], timeout=2)

        if i == 0:
            p.sendline('yes')
            i = p.expect([new_ssh, 'Please login: ', pexpect.EOF])
        if i == 1:
            p.sendline(username)
        if i == 2:
            print "Connection failure to '%s'." % ip
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
            sys.stderr.write("Failed lookup for '%s'.\n" % ap_name)
            sys.exit(1)
        except KeyError:
            sys.stderr.write(
                "Failed to obtain credentials for '%s'.\n" % ap_name
            )
            sys.exit(1)

        return (username, password, protocol)

    def __get_pexpect_spawn(self, ap_name):
        cs = self.apc.get_connection_settings(ap_name)

        if 'ssh' in cs.get('protocol'):
            p = self.__do_ssh_login(ap_name, cs)
        else:
            sys.stdout.write(
                "Unsupported protocol defined for '%s'.\n" % ap_name
            )
            sys.exit(1)

        return p

    def get_ssid_interfaces(self, ap_name):
        """Print configured SSIDs."""
        p = self.__get_pexpect_spawn(ap_name)

        p.expect('rkscli: ')
        p.sendline('get wlanlist')
        p.expect('rkscli: ')
        print p.before
        p.sendline('exit')

    def get_logs(self, ap_name):
        """Print WAP logs."""
        p = self.__get_pexpect_spawn(ap_name)

        p.expect('rkscli: ')
        p.sendline('get syslog log')
        p.expect('rkscli: ')
        print p.before
        p.sendline('exit')

    def change_psk_passphrase(self, ap_name, interface, passphrase):
        """Change the PSK passphrase for a given WAP interface.

        rkscli: set encryption wlan8
        Wireless Encryption Type: [0] quit, [1] OPEN, [2] WEP, or [3] WPA
        Wireless Encryption Type:  3
        WPA Protocol Version: [0] quit, [1] WPA, [2] WPA2, or [3] AUTO
        WPA Protocol Version: 2
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



f = open('access_points.yml', 'r')
apc = AccessPointConnections(f.read())
f.close()
rm = RuckusManagement(apc)

for wap in apc.list_wireless_access_points():
    print "=== %s ===" % wap
    print "Settings:"
    pprint.pprint(apc.get_connection_settings(wap))
    print "Configured SSIDs:"
    rm.get_ssid_interfaces(wap)
    print "Logs:"
    rm.get_logs(wap)
    print
