import streamlit as st
from networkpowertools_functions import (process_input_file, send_commands_to_devices,
                                        save_dictionary, generate_graph_from_devices,
                                        import_devices_from_csv, import_devices_from_json,
                                         parse_traceroute_output, bootstrap_telnet)
from streamlit.components.v1 import html
import json



def networkpowertools_frontend():
    # Initialize session state
    if 'devices' not in st.session_state:
        st.session_state.devices = {}

    if 'interfaces' not in st.session_state:
        st.session_state.interfaces = {}

    if 'commands' not in st.session_state:
        st.session_state.commands = []

    if 'output' not in st.session_state:
        st.session_state.output = {}

    if 'page' not in st.session_state:
        st.session_state.page = 'Home'

    if 'todo' not in st.session_state:
        st.session_state.todo = ''

    if 'ping_output' not in st.session_state:
        st.session_state.ping_output = ''

    if 'traceroute_output' not in st.session_state:
        st.session_state.traceroute_output = ''

    if "traceroute_processed_output" in st.session_state:
        st.session_state.traceroute_processed_output = {}

    if "traceroute_hop_ping" in st.session_state:
        st.session_state.traceroute_hop_ping = {}

    # Examples
    device_format_example = """
            Expected format for Devices:
            ```json
            CSV
            device_name,device_type,host,username,password
            device1,cisco_ios,192.168.2.181,admin,adminpass
            device2,cisco_ios,192.168.2.182,admin,adminpass
            json
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
            ```
            """

    interface_format_example = """
                    Expected format for Interfaces:
                    ```json
                    CSV
                    device_name,interface,neighbor
                    device1,Gi0/1,device2
                    device2,Gi0/2,device1
                    
                    JSON
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
                    ```
                    """
    commands_format_example = """
                            ```json
                            CSV
                            Input Format:
                            show version,
                            show interfaces,
                            ...
                            JSON
                            [
                            "show version",
                            "show interfaces",
                            ...
                            ]
                            ```
                            """

    # Streamlit app structure
    st.sidebar.title("Network Power Tools")

    page_list = [
        "Home", "Multi-send without Checks", "Network Diagram", "Remote Ping", "Super Ping", "Bootstrap Device"]

    for p in page_list:
        if st.sidebar.button(p):
            st.session_state.page = p

    if st.session_state.page == "Home":
        st.header("Welcome")
        st.session_state.todo = st.text_area("To Do list", value=st.session_state.todo)

    elif st.session_state.page == "Multi-send without Checks":
        st.title('Network Device Manager')

        # Upload file for devices
        devices_file = st.file_uploader("Upload your devices file (CSV/JSON)", type=['csv', 'json'])
        show_device_format = st.checkbox('Show expected format for devices')
        if show_device_format:
            st.markdown(device_format_example)
        if devices_file:
            st.session_state.devices = process_input_file(devices_file, import_devices_from_csv, import_devices_from_json)

        # Upload file for commands
        commands_file = st.file_uploader("Upload your commands file (CSV/JSON)", type=['csv', 'json'])
        show_commands_format = st.checkbox('Show expected format for commands')
        if show_commands_format:
            st.markdown(commands_format_example)
        if commands_file:
            st.session_state.commands = process_input_file(commands_file, import_devices_from_csv, import_devices_from_json)

        # Display devices, interfaces, and commands
        st.write("Devices:")
        st.json(st.session_state.devices)
        st.write("Commands:")
        st.json(st.session_state.commands)

        override_user_pw = st.checkbox('Override Username and Password?')
        if override_user_pw:
            # Field to override username and password in an obfuscated manner
            st.subheader("Credentials Override")
            override_username = st.text_input("Override Username:", value="")
            override_password = st.text_input("Override Password:", value="", type="password")

            # If the fields are filled, update the st.session_state.devices dictionary
            if override_username and override_password:
                for device in st.session_state.devices.values():
                    device["username"] = override_username
                    device["password"] = override_password

        # Button to run the send_commands_to_devices function
        if st.button('Run Commands'):
            st.session_state.output = send_commands_to_devices(st.session_state.commands, st.session_state.devices)
            st.write('Commands executed successfully!')

        # Display command outputs
        st.write("Command Outputs:")
        st.json(st.session_state.output)

        # Save the devices dictionary
        save_format = st.radio("Choose your save format:", ['JSON', 'CSV'])
        if st.button('Save Devices Dictionary'):
            ext = '.json' if save_format == 'JSON' else '.csv'
            filename = st.text_input("Enter the filename (without extension):", value='output') + ext
            save_dictionary(st.session_state.devices, filename)
            st.write(f'Devices saved to {filename}!')

        # Save the command outputs
        if st.button('Save Command Outputs'):
            ext = '.json' if save_format == 'JSON' else '.csv'
            filename = st.text_input("Enter the filename for command outputs (without extension):", value='output_commands') + ext
            save_dictionary(st.session_state.output, filename)
            st.write(f'Command outputs saved to {filename}!')

    elif st.session_state.page == "Network Diagram":
        st.title('Network Diagram Generator')

        # Upload file for devices
        devices_file = st.file_uploader("Upload your devices file (CSV/JSON)", type=['csv', 'json'])
        show_device_format = st.checkbox('Show expected format for devices')
        if show_device_format:
            st.markdown(device_format_example)
        if devices_file:
            st.session_state.devices = process_input_file(devices_file, import_devices_from_csv,
                                                          import_devices_from_json)

        # Upload file for device interfaces
        interfaces_file = st.file_uploader("Upload your device interfaces file (CSV/JSON)", type=['csv', 'json'])
        show_interfaces_format = st.checkbox('Show expected format for interfaces')
        if show_interfaces_format:
            st.markdown(interface_format_example)
        if interfaces_file:
            st.session_state.interfaces = process_input_file(interfaces_file, lambda f: import_devices_from_csv(f,
                                                                                                                st.session_state.devices),
                                                             lambda f: import_devices_from_json(f,
                                                                                                st.session_state.devices))

        # Display devices and interfaces
        st.write("Devices:")
        st.json(st.session_state.devices)

        if st.button('Generate Network Diagram'):
            # This function should generate the Pyvis network diagram and return its HTML
            diagram_html = generate_graph_from_devices(st.session_state.devices)
            html(diagram_html, width=800, height=600)
        else:
            st.write('Upload devices and interfaces to see the network diagram.')



    elif st.session_state.page == "Remote Ping":
        st.title('Remote Ping')
        # Upload file for devices
        devices_file = st.file_uploader("Upload your devices file (CSV/JSON)", type=['csv', 'json'])
        show_device_format = st.checkbox('Show expected format for devices')
        if show_device_format:
            st.markdown(device_format_example)
        if devices_file:
            st.session_state.devices = process_input_file(devices_file, import_devices_from_csv,
                                                          import_devices_from_json)
            st.write("Devices loaded successfully!")
        else:
            st.warning("Please upload a valid devices file to proceed.")
        # Display devices, interfaces, and commands
        st.write("Devices:")
        st.json(st.session_state.devices)
        override_user_pw = st.checkbox('Override Username and Password?')
        if override_user_pw:
            # Field to override username and password in an obfuscated manner
            st.subheader("Credentials Override")
            override_username = st.text_input("Override Username:", value="")
            override_password = st.text_input("Override Password:", value="", type="password")
            # If the fields are filled, update the st.session_state.devices dictionary
            if override_username and override_password:
                for device in st.session_state.devices.values():
                    device["username"] = override_username
                    device["password"] = override_password
                st.success("Credentials overridden successfully!")
        # Get the IP address to be pinged from the user
        target_ip = st.text_input("Enter the IP address to ping:")
        if devices_file and st.button('Ping'):
            # Check if the IP is valid before sending it out
            if target_ip:
                ping_command = f"ping {target_ip}"
                st.session_state.ping_output = send_commands_to_devices([ping_command], st.session_state.devices)
                st.write("Ping Results:")
                st.json(st.session_state.ping_output)
            else:
                st.warning("Please enter a valid IP address.")
        if devices_file and st.button('Traceroute'):
            # Check if the IP is valid before sending it out
            if target_ip:
                traceroute_command = f"traceroute {target_ip}"
                st.session_state.traceroute_output = send_commands_to_devices([traceroute_command],
                                                                              st.session_state.devices)
                st.write("Traceroute Results:")
                st.json(st.session_state.traceroute_output)
            else:
                st.warning("Please enter a valid IP address.")

        if target_ip and st.session_state.traceroute_output:
            for device_ip, output in st.session_state.traceroute_output.items():
                selected_device_ip = st.selectbox("Traceroute select", [device_ip])
                parsed_outputs, traceroute_hops = parse_traceroute_output(selected_device_ip, target_ip, output)
                st.write("Traceroute parsed Results:")
                st.json(parsed_outputs)
                st.json(traceroute_hops)
                st.write("Ping all hops in traceroute?")
                if st.button(f"Traceroute ping {selected_device_ip}"):
                    hop_ping_outputs = {}
                    for hop_ip in parsed_outputs[selected_device_ip][target_ip]:
                        ping_command = f"ping {hop_ip}"
                        devices = {selected_device_ip: st.session_state.devices[selected_device_ip]}
                        hop_ping_outputs[hop_ip] = send_commands_to_devices([ping_command], devices)
                    st.session_state.traceroute_hop_ping = hop_ping_outputs
                    st.json(st.session_state.traceroute_hop_ping)




    elif st.session_state.page == "Super Ping":
        st.title("Super Ping")
        pass

    elif st.session_state.page == "Bootstrap Device":
        st.title('Device Bootstrapper')

        # Bootstrap by Telnet
        with st.expander('Bootstrap by Telnet'):
            st.subheader('Telnet Command Sender')

            input_type = st.radio('Choose input method:', ['Manual Entry', 'Upload'])

            if input_type == 'Manual Entry':
                num_devices = st.slider('Select number of devices:', 1, 10)

                devices = []
                telnet_ports = []
                commands = {}

                for i in range(num_devices):
                    st.subheader(f'Device {i + 1}')
                    host = st.text_input(f'Host for Device {i + 1}')
                    port = st.number_input(f'Telnet Port for Device {i + 1}', min_value=1, max_value=65535, value=23)
                    cmd_input = st.text_area(f'Commands for Device {i + 1} (comma-separated)')

                    # Convert comma-separated commands into a list
                    cmd_list = [cmd.strip() for cmd in cmd_input.split(",")]

                    devices.append({
                        "device_name": f"device{i + 1}",
                        "device_type": "cisco_ios",  # This can be adjusted as needed
                        "host": host,
                        "username": "admin",  # Placeholder - can be changed
                        "password": "adminpass",  # Placeholder - can be changed
                        "telnet_port" : port,

                        "device_commands" : cmd_list
                    })

            else:
                # Upload for devices
                devices_file = st.file_uploader("Upload your devices file (CSV/JSON)", type=['csv', 'json'])
                if devices_file:
                    if devices_file.type == 'application/json':
                        devices = import_devices_from_json(devices_file)
                    else:
                        devices = import_devices_from_csv(devices_file)

                # Upload for commands
                commands_file = st.file_uploader("Upload your commands file (JSON)", type=['json'])
                if commands_file:
                    commands = json.load(commands_file)

                # Upload for telnet ports
                telnet_ports_file = st.file_uploader("Upload your telnet ports file (JSON)", type=['json'])
                if telnet_ports_file:
                    telnet_ports = json.load(telnet_ports_file)

            # Displaying the user input
            st.subheader('Inputs')
            st.write("Devices:")
            st.json(devices)

            if st.button('Send Commands via Telnet'):
                result = bootstrap_telnet(devices)
                st.subheader('Command Results')
                st.json(result)

        # Bootstrap by SSH
        with st.expander('Bootstrap by SSH'):
            # The code to use the send_commands_to_devices function will be placed here.
            # For example:
            devices_file = st.file_uploader("Upload your SSH devices file (CSV/JSON)", type=['csv', 'json'])
            commands_file = st.file_uploader("Upload your SSH commands file (JSON)", type=['json'])

            # Displaying the user input
            st.subheader('Inputs for SSH')
            if devices_file and commands_file:
                devices = import_devices_from_json(
                    devices_file) if devices_file.type == 'application/json' else import_devices_from_csv(devices_file)
                commands = json.load(commands_file)

                st.write("Devices for SSH:")
                st.json(devices)
                st.write("Commands for SSH:")
                st.json(commands)

                if st.button('Send Commands via SSH'):
                    ssh_results = send_commands_to_devices(commands, devices)
                    st.subheader('SSH Command Results')
                    st.json(ssh_results)

        # Send Commands by API
        with st.expander('Send Commands by API'):
            st.subheader("Send command by API")
            # Placeholder for future development
            pass


if __name__ == '__main__':
    networkpowertools_frontend()
