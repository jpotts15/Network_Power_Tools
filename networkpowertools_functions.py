from netmiko import ConnectHandler
import json
import csv
from pyvis.network import Network
import os
import re
import telnetlib
import time

'''
This python script is meant to house modules for the networkpowertools 
'''


def process_input_file(filename, csv_function, json_function):
    """
    Processes an input file (either CSV or JSON) by calling the appropriate function.

    Parameters:
    - filename (str): The name of the file to process.
    - csv_function (callable): The function to call if the file is a CSV.
    - json_function (callable): The function to call if the file is a JSON.

    Returns:
    - The result of the called function.
    """
    _, file_extension = os.path.splitext(filename)

    if file_extension.lower() == '.csv':
        return csv_function(filename)
    elif file_extension.lower() == '.json':
        return json_function(filename)
    else:
        raise ValueError(f"Unsupported file type: {file_extension}")


def save_to_csv(data, filename):
    """Saves dictionary data to a CSV file."""
    with open(filename, 'w', newline='') as file:
        # Assuming data is a list of dictionaries for CSV
        keys = data[0].keys()
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        for item in data:
            writer.writerow(item)


def save_to_json(data, filename):
    """Saves dictionary data to a JSON file."""
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)


def save_dictionary(data, filename):
    """
    Determines whether to save data as CSV or JSON based on filename extension.
    """
    _, file_extension = os.path.splitext(filename)

    if file_extension.lower() == '.csv':
        save_to_csv(data, filename)
    elif file_extension.lower() == '.json':
        save_to_json(data, filename)
    else:
        raise ValueError(f"Unsupported file type: {file_extension}")


def send_commands_to_devices(devices, commands):
    """
    Log into devices and send commands.

    Parameters:
    - devices (dict): Dictionary of devices to connect to.
    - commands (list): List of commands to send.

    Returns:
    - results: output of commands
    """
    results = {}

    for device_name, device_details in devices.items():
        try:
            connection = ConnectHandler(**device_details)
            device_output = ""

            for command in commands:
                device_output += f"\nCommand: {command}\n"
                device_output += "-" * 50 + "\n"
                device_output += connection.send_command(command) + "\n"

            results[device_name] = device_output

        except Exception as e:
            results[device_name] = str(e)

        finally:
            if connection:
                connection.disconnect()

    return results


def import_devices_from_csv(filename):
    """
    Import csv to create devices dictionary

    Parameters:
    - filename: filename/path for csv file

    Returns:
    - dict: Dictionary with devices

    Input format:
    device_name,device_type,host,username,password
    device1,cisco_ios,192.168.2.181,admin,adminpass
    device2,cisco_ios,192.168.2.182,admin,adminpass

    """
    devices = {}

    with open(filename, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            device_name = row.pop('device_name')
            devices[device_name] = row

    return devices


def import_devices_from_json(filename):
    """
    Import json to create devices dictionary

    Parameters:
    - filename: filename/path for json file

    Returns:
    - dict: Dictionary with devices

    Input Format:
    [
    {
        "device_name": "device1",
        "device_type": "cisco_ios",
        "host": "192.168.2.181",
        "username": "admin",
        "password": "adminpass"
    },
    {
        "device_name": "device2",
        "device_type": "cisco_ios",
        "host": "192.168.2.182",
        "username": "admin",
        "password": "adminpass"
    }
    ]
    """
    devices = {}

    with open(filename, mode='r') as file:
        data = json.load(file)
        for device in data:
            device_name = device.pop('device_name')
            devices[device_name] = device

    return devices


def import_commands_from_csv(filename):
    """
    Import csv to create list of commands to send to a device

    Parameters:
    - filename: filename/path for csv file

    Returns:
    - dict: list of commands

    Input Format:
    show version,
    show interfaces,
    ...
    """
    commands = []

    with open(filename, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            commands.append(row[0])

    return commands


def import_commands_from_json(filename):
    """
    Import json to create list of commands to send to a device

    Parameters:
    - filename: filename/path for json file

    Returns:
    - dict: list of commands

    Input Format:
    [
    "show version",
    "show interfaces",
    ...
    ]
    """
    with open(filename, mode='r') as file:
        commands = json.load(file)

    return commands


def generate_graph_from_devices(devices):
    """
    Generates a Pyvis graph from the given devices dictionary.

    Parameters:
    - devices (dict): Dictionary of devices and their configurations.

    Returns:
    - Network: A Pyvis Network object.
    """
    g = Network()

    # Add nodes for each device
    for device in devices:
        g.add_node(device, label=device)

    # Add edges based on the interfaces and neighbor relations
    for device, details in devices.items():
        for interface, neighbor in details.get('interfaces', {}).items():
            # We'll label the edge with the interface name
            g.add_edge(device, neighbor, title=interface)

    return g


def import_interfaces_from_csv(filename, devices):
    """
    Import csv to add interfaces to the device dict to generate graphs

    Parameters:
    - filename: filename/path for csv file
    - devices: devices dict

    Returns:
    - dict: modified devices dict

    Input Format:
    device_name,interface,neighbor
    device1,Gi0/1,device2
    device2,Gi0/2,device1
    """
    with open(filename, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            device_name = row['device_name']
            interface = row['interface']
            neighbor = row['neighbor']

            if device_name in devices:
                if 'interfaces' not in devices[device_name]:
                    devices[device_name]['interfaces'] = {}
                devices[device_name]['interfaces'][interface] = neighbor

    return devices


def import_interfaces_from_json(filename, devices):
    """
    Import csv to add interfaces to the device dict to generate graphs

    Parameters:
    - filename: filename/path for csv file
    - devices: devices dict

    Returns:
    - dict: modified devices dict

    Input Format:
    [
    {
        "device_name": "device1",
        "interface": "Gi0/1",
        "neighbor": "device2"
    },
    {
        "device_name": "device2",
        "interface": "Gi0/2",
        "neighbor": "device1"
    }
    ]
    """
    with open(filename, mode='r') as file:
        data = json.load(file)
        for item in data:
            device_name = item['device_name']
            interface = item['interface']
            neighbor = item['neighbor']

            if device_name in devices:
                if 'interfaces' not in devices[device_name]:
                    devices[device_name]['interfaces'] = {}
                devices[device_name]['interfaces'][interface] = neighbor

    return devices


def parse_traceroute_output(device_ip, target_ip, output):
    """Parse the output of a traceroute command."""
    # Split the traceroute output by lines
    lines = output.split("\n")

    # Regular expression pattern to capture IP addresses
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

    # List to store IPs from traceroute
    route_ips = []
    traceroute_dict = {}
    hop_counter = 0

    # Loop through each line and capture IPs
    for line in lines:
        match = ip_pattern.search(line)
        if match:
            ip = match.group()
            if ip not in route_ips:
                route_ips.add(ip)
            hop_counter += 1
            traceroute_dict[hop_counter] = ip
        elif "* * *" in line:
            hop_counter += 1
            traceroute_dict[hop_counter] = "no reply"

    # Return the result in the desired format
    return {device_ip: {target_ip: route_ips}}, traceroute_dict


def bootstrap_telnet(devices):
    """
    Connect to devices using telnet and execute commands.

    Args:
    - devices (list): List of dictionaries containing device details.
    - telnet_ports (dict): Dictionary containing telnet ports mapped to device hosts.
    - commands (dict): Dictionary mapping device hosts to lists of commands to be executed.

    Returns:
    - Dictionary containing output for each command executed.

    Input Format:
    devices = [
    {
        "device_name": "device1",
        "device_type": "cisco_ios",
        "host": "192.168.2.181",
        "username": "admin",
        "password": "adminpass",
        "telnet_port" : 3223,
        "device_commands" : ["show interfaces", "show version"]
    },
    {
        "device_name": "device2",
        "device_type": "cisco_ios",
        "host": "192.168.2.182",
        "username": "admin",
        "password": "adminpass"
        "telnet_port" : 23,
        "device_commands" : ["show interfaces", "show ip route"]
    }
    ]
    """

    results = {}
    prompt = ""
    loopcounter = 0

    for device in devices:
        device_name = device["device_name"]
        host = device["host"]
        username = device["username"]
        password = device["password"]
        telnet_port = device["telnet_port"]
        device_commands = device["device_commands"]
        ipport = f"{host}:{telnet_port}"

        # Create an initial Telnet connection
        tn = telnetlib.Telnet(host, telnet_port)  # default port is 23
        tn = handle_telnet_prompt(tn, username, password)

        # Handling device-specific commands
        device_output = {}

        for cmd in device_commands:
            retry_count = 0
            while retry_count < 3:
                tn.write(cmd.encode('ascii') + b"\r\n")
                # Assuming a simple sleep is enough for the command to be executed and output to be shown
                time.sleep(1)
                output = tn.read_very_eager().decode('ascii')
                if cmd in output:
                    device_output[cmd] = output.strip()
                    break
                if "--More--" in output:
                    tn.write("     ".encode('ascci')+b"\r\n")
                retry_count += 1

        results[ipport] = device_output
        tn.close()

    return results


def handle_telnet_prompt(tn, username, password):
    loopcounter = 0
    prompt = tn.read_very_eager().decode('ascii').split("\n")[-1]
    time.sleep(5)

    # Add some handling for initial prompts
    while ">" not in prompt and "#" not in prompt and loopcounter < 10:
        tn.write(b"\r\n")
        time.sleep(1)
        prompt = tn.read_very_eager().decode('ascii').split("\n")[-1]
        time.sleep(2)

        if prompt == "":
            continue
        elif "initial" in prompt or "Please answer 'yes' or 'no'" in prompt:
            tn.write("no".encode('ascii') + b"\r\n")
        elif "username" in prompt.lower():
            tn.write(username.encode('ascii') + b"\r\n")
        elif "password" in prompt.lower():
            tn.write(password.encode('ascii') + b"\r\n")
        elif "Press ENTER to get the prompt" in prompt.lower():
            tn.write(b"\r\n")
        else:
            tn.write(b"\r\n")
        loopcounter += 1

    return tn
