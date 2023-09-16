import requests
import urllib3
import json

#Disabling warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Dictionary that contains all network devices to be configured
# Along with the hostname that will be configured on each of them
switches = {"10.10.10.50": "arubaoscxsw01"}

# Credentials for the network devices, this case assumes all credentials are the same
# on all network devices
credentials = {"username": "admin", "password": "123456"}

# This is the base config dictionary, modify this as needed
# This could perfectly be a list of parameters so we can use this script faster in real implementations
base_config = {"dns_servers": ["1.1.1.1", "8.8.8.8"],
               "dns_domain_name": "domain.local",
               "ntp_server": "time.google1.com",
               "timezone": "UTC",
               "syslog_server": {"address": "syslogserver.local", "severity": "err"},
               "radius_server": {"group": "radiusgroup", "address": "radiusserver.local", "key": "serverkey"},
               "vlans": {9: "Users", 10: "SRV", 20: "VoIP", 50: "WiFi"},
               "voice_vlan": 20,
               "uplink_description": "UPLINK",
               "uplink_ports": ["1/1/1"],
               "wap_ports": ["1/1/2", "1/1/3"],
               "access_ports": ["1/1/4", "1/1/5", "1/1/6"],
               "server_ports": ["1/1/7"],
               "authorized_dhcp_servers": ["10.0.10.9"]
               }


# Here we build the JSON configs from the base_config
# Consult the API to know how to build the config and
# where to POST/PATCH your desired configuration
# In this case, dictionaries match the JSON structure of the ArubaOS CX 10.12 API
dns_dhcp_auth_srv_config = {"dns_domain_name": base_config["dns_domain_name"],
              "dns_name_servers": {str(index): value for index, value in enumerate(base_config["dns_servers"])},
              "dhcpv4_snooping_authorized_servers": base_config["authorized_dhcp_servers"]}

ntp_server = {"address": base_config["ntp_server"],
              "association_attributes": {
                  "burst_mode": "iburst",
                  "maxpoll": 10,
                  "minpoll": 6,
                  "ntp_version": 4,
                  "prefer": False,
                  "ref_clock_id": "--"
              },
              "key_id": None,
              "origin": "configuration",
              "vrf": "/rest/v10.12/system/vrfs/default"}

syslog_server = {"remote_host": base_config["syslog_server"]["address"],
                 "severity": base_config["syslog_server"]["severity"],
                 "tls_auth_mode": "certificate",
                 "transport": "udp",
                 "unsecure_tls_renegotiation": False,
                 "vrf": {
                     "default": "/rest/v10.12/system/vrfs/default"}}

radius_dyn_auth_client = {
    "address": base_config["radius_server"]["address"],
    "connection_type": "udp",
    "replay_protection_enable": True,
    "secret_key": base_config["radius_server"]["key"],
    "time_window": 300,
    "vrf": "/rest/v10.12/system/vrfs/default"}


radius_server_groups = {"group_name": base_config["radius_server"]["group"],
                        "group_type": "radius",
                        "origin": "configuration"}

radius_server = {"accounting_udp_port": 1813,
                 "address": base_config["radius_server"]["address"],
                 "auth_type": "pap",
                 "passkey": base_config["radius_server"]["key"],
                 "port": 1812,
                 "port_access": "status-server",
                 "port_type": "udp",
                 "retries": None,
                 "server_group": {
                     f"/rest/v10.12/system/aaa_server_groups/{base_config['radius_server']['group']}": 1
                 },
                 "timeout": None,
                 "vrf": "/rest/v10.12/system/vrfs/default"}

aaa_prio_ssh_https = {"authentication_group_prios":
                    {"0": f"/rest/v10.12/system/aaa_server_groups/{base_config['radius_server']['group']}"}
                }
vlan_config = {"id": None, "name": None
               }
voice_vlan = {"voice": True}

access_port_config = {"vlan_mode": "native-untagged",
                      "vlan_tag": {
                          "9": "/rest/v10.12/system/vlans/9"
                      },
                      "vlan_trunks": {
                          "9": "/rest/v10.12/system/vlans/9",
                          "20": "/rest/v10.12/system/vlans/20"},
                      "admin": "up"
                      }

server_port_config = {"vlan_mode": "access",
                      "vlan_tag": {
                          "10": "/rest/v10.12/system/vlans/10"},
                      "admin": "up"
                      }

wap_port_config = {"vlan_mode": "native-untagged",
                      "vlan_tag": {
                          "50": "/rest/v10.12/system/vlans/50"
                      },
                      "vlan_trunks": {
                          "9": "/rest/v10.12/system/vlans/9",
                          "50": "/rest/v10.12/system/vlans/50"},
                   "admin": "up"
                   }

uplink_port_config = {"vlan_mode": "native-untagged",
                      "vlan_tag": None,
                      "vlan_trunks": {
                          "1": "/rest/v10.12/system/vlans/1",
                          "9": "/rest/v10.12/system/vlans/9",
                          "10": "/rest/v10.12/system/vlans/10",
                          "20": "/rest/v10.12/system/vlans/20",
                          "50": "/rest/v10.12/system/vlans/50"},
                      "dhcpv4_snooping_configuration": {
                          "trusted": "true"},
                      "description": base_config["uplink_description"],
                      "admin": "up"
                      }
# We create our request session
sesion = requests.Session()

# We loop for every network device in our dictionary and apply configuration as
# the API says
for switch in switches:
    # This part substitutes the hostname in every network device
    # iteration in the dictionary for later use it to apply it
    sysconf = {"hostname": switches[switch],
               "timezone": base_config["timezone"],
               "radius_dynamic_authorization": {
                   "enable": True},
               "dhcpv4_snooping_general_configuration": {
                   "enable": True},
               }
    # We log in our device
    login = sesion.post(f"https://{switch}/rest/v10.12/login", data=credentials, verify=False)
    try:
        # Patching hostname, timezone and DHCP Snooping
        step_1 = sesion.patch(f"https://{switch}/rest/v10.12/system", json=sysconf, verify=False)
        print("step_1 " + str(step_1.status_code))
        # Patching DNS servers and domain_name
        step_2 = sesion.patch(f"https://{switch}/rest/v10.12/system/vrfs/default", json=dns_dhcp_auth_srv_config, verify=False)
        print("step_2 " + str(step_2.status_code))
        # Posting NTP Server
        step_3 = sesion.post(f"https://{switch}/rest/v10.12/system/vrfs/default/ntp_associations", json=ntp_server, verify=False)
        print("step_3 " + str(step_3.status_code))
        # Posting Syslog Server
        step_4 = sesion.post(f"https://{switch}/rest/v10.12/system/syslog_remotes", json=syslog_server, verify=False)
        print("step_4 " + str(step_4.status_code))
        # Posting Radius Dynamic Authentication Client
        step_5 = sesion.post(f"https://{switch}/rest/v10.12/system/vrfs/default/radius_dynamic_authorization_clients", json=radius_dyn_auth_client, verify=False)
        print("step_5 " + str(step_5.status_code))
        # Posting AAA Group
        step_6 = sesion.post(f"https://{switch}/rest/v10.12/system/aaa_server_groups", json=radius_server_groups, verify=False)
        print("step_6 " + str(step_6.status_code))
        # Posting Radius Servers
        step_7 = sesion.post(f"https://{switch}/rest/v10.12/system/vrfs/default/radius_servers", json=radius_server, verify=False)
        print("step_7 " + str(step_7.status_code))
        # Patching SSH and HTTPS login priorities
        # This enables admin login using radius
        step_8 = sesion.patch(f"https://{switch}/rest/v10.12/system/aaa_server_group_prios/ssh", json=aaa_prio_ssh_https, verify=False)
        print("step_8 " + str(step_8.status_code))
        step_9 = sesion.patch(f"https://{switch}/rest/v10.12/system/aaa_server_group_prios/https-server", json=aaa_prio_ssh_https, verify=False)
        print("step_9 " + str(step_9.status_code))
        # Creating VLANS
        for vlan in base_config["vlans"]:
            vlan_config["id"] = vlan
            vlan_config["name"] = base_config["vlans"][vlan]
            step_10 = sesion.post(f"https://{switch}/rest/v10.12/system/vlans", json=vlan_config, verify=False)
            print("step_10 " + str(step_10.status_code))
        # Assigning Voice VLAN
        step_11 = sesion.patch(f"https://{switch}/rest/v10.12/system/vlans/{base_config['voice_vlan']}", json=voice_vlan, verify=False)
        print("step_11 " + str(step_11.status_code))
        # Access port config
        for access_port in base_config["access_ports"]:
            step_12 = sesion.patch(f"https://{switch}/rest/v10.12/system/interfaces/{access_port.replace('/', '%2F')}", json=access_port_config, verify=False)
            print("step_12 " + str(step_12.status_code))
        # Server ports config
        for server_port in base_config["server_ports"]:
            step_13 = sesion.patch(f"https://{switch}/rest/v10.12/system/interfaces/{server_port.replace('/', '%2F')}", json=server_port_config, verify=False)
            print("step_13 " + str(step_13.status_code))
        # WAP ports config
        for wap_port in base_config["wap_ports"]:
            step_14 = sesion.patch(f"https://{switch}/rest/v10.12/system/interfaces/{wap_port.replace('/', '%2F')}", json=wap_port_config, verify=False)
            print("step_14 " + str(step_14.status_code))
        # Saving changes made to switch
        save_config = sesion.put(f"https://{switch}/rest/v10.12/fullconfigs/startup-config?from=%2Frest%2Fv10.12%2Ffullconfigs%2Frunning-config", verify=False)
        print(save_config.status_code)
        # Loging Out
        sesion.post(f"https://{switch}/rest/v10.12/logout")
    except Exception as e:
        print(e)
