import streamlit as st
from networkpowertools_functions import (process_input_file, send_commands_to_devices,
                                        save_dictionary, generate_graph_from_devices,
                                        import_devices_from_csv, import_devices_from_json)
from streamlit.components.v1 import html



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

    if 'st.session_state.todo' not in st.session_state:
        st.session_state.todo = ''

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
        "Home", "Multi-send without Checks", "Network Diagram", "Remote Ping"]

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

    elif st.session_state.page == "Remote Ping":
        st.title('Remote Ping')

        st.title('Network Device Manager')

        # Upload file for devices
        devices_file = st.file_uploader("Upload your devices file (CSV/JSON)", type=['csv', 'json'])
        show_device_format = st.checkbox('Show expected format for devices')
        if show_device_format:
            st.markdown(device_format_example)
        if devices_file:
            st.session_state.devices = process_input_file(devices_file, import_devices_from_csv,
                                                          import_devices_from_json)

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

        # Get the IP address to be pinged from the user
        target_ip = st.text_input("Enter the IP address to ping:")

        if st.button('Ping'):
            # Check if the IP is valid before sending it out
            if target_ip:
                ping_command = f"ping {target_ip}"
                st.session_state.ping_output = send_commands_to_devices([ping_command], st.session_state.devices)
                st.write("Ping Results:")
                st.json(st.session_state.ping_output)
            else:
                st.warning("Please enter a valid IP address.")


if __name__ == '__main__':
    networkpowertools_frontend()
