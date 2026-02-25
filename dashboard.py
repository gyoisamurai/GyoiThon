import streamlit as st
import os
import configparser
import subprocess
import pandas as pd
import glob
import time
import signal

st.set_page_config(page_title="GyoiThon Dashboard", layout="wide")

st.title("GyoiThon Dashboard")
st.markdown("Next generation penetration test tool control panel.")

# Initialize session state for process management
if 'process' not in st.session_state:
    st.session_state.process = None
if 'process_pid' not in st.session_state:
    st.session_state.process_pid = None

tab_config, tab_run, tab_reports, tab_inventory = st.tabs(["Configuration", "Run", "Reports", "Inventory"])

with tab_config:
    st.header("Configuration")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Target Hosts (host.txt)")
        if os.path.exists("host.txt"):
            with open("host.txt", "r") as f:
                host_content = f.read()
        else:
            host_content = ""

        new_host_content = st.text_area("Edit host.txt", host_content, height=300)
        if st.button("Save host.txt"):
            with open("host.txt", "w") as f:
                f.write(new_host_content)
            st.success("host.txt saved!")

    with col2:
        st.subheader("Settings (config.ini)")
        if os.path.exists("config.ini"):
            with open("config.ini", "r") as f:
                config_content = f.read()
        else:
            config_content = ""

        new_config_content = st.text_area("Edit config.ini", config_content, height=300)
        if st.button("Save config.ini"):
            with open("config.ini", "w") as f:
                f.write(new_config_content)
            st.success("config.ini saved!")

with tab_run:
    st.header("Execution")

    st.info("Select options and run GyoiThon.")

    col_opts1, col_opts2 = st.columns(2)

    with col_opts1:
        opt_s = st.checkbox("Cloud Service Check (-s)", help="Examine cloud service.")
        opt_m = st.checkbox("Machine Learning (-m)", help="Analyze HTTP response for identify product/version using Machine Learning.")
        opt_g = st.checkbox("Google Hack (-g)", help="Google Custom Search for identify product/version.")
        opt_e = st.checkbox("Explore Default Path (-e)", help="Explore default path of product.")

    with col_opts2:
        opt_c = st.checkbox("Censys (-c)", help="Discover open ports and wrong ssl server certification using Censys.")
        opt_p = st.checkbox("Exploit (-p)", help="Execute exploit module using Metasploit. WARNING: Dangerous!")
        opt_no_update = st.checkbox("No VulnDB Update", value=True, help="Skip updating Vulnerability Database.")

    if st.button("Start GyoiThon"):
        if st.session_state.process is not None:
             st.warning("GyoiThon is already running!")
        else:
            cmd = ["python3", "gyoithon.py"]
            if opt_s: cmd.append("-s")
            if opt_m: cmd.append("-m")
            if opt_g: cmd.append("-g")
            if opt_e: cmd.append("-e")
            if opt_c: cmd.append("-c")
            if opt_p: cmd.append("-p")
            if opt_no_update: cmd.append("--no-update-vulndb")

            st.code(" ".join(cmd), language="bash")

            # Start process
            # We use subprocess.Popen to run it in background
            try:
                # Use a log file to capture output
                log_file = open("dashboard_run.log", "w")
                proc = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT)
                st.session_state.process = proc
                st.session_state.process_pid = proc.pid
                st.success(f"GyoiThon started with PID {proc.pid}")
            except Exception as e:
                st.error(f"Failed to start: {e}")

    if st.button("Stop GyoiThon"):
        if st.session_state.process_pid is not None:
            try:
                os.kill(st.session_state.process_pid, signal.SIGTERM)
                st.success("Stopped process.")
                st.session_state.process = None
                st.session_state.process_pid = None
            except Exception as e:
                st.error(f"Failed to stop: {e}")
        else:
            st.warning("No process running.")

    st.subheader("Live Logs")
    if st.button("Refresh Logs"):
        st.rerun()

    log_placeholder = st.empty()

    # Simple log viewer
    if os.path.exists("dashboard_run.log"):
        with open("dashboard_run.log", "r") as f:
            lines = f.readlines()
            log_placeholder.text_area("Output", "".join(lines[-20:]), height=300)

with tab_reports:
    st.header("Reports")
    if st.button("Refresh Reports"):
        st.rerun()

    report_dir = "report"
    if os.path.exists(report_dir):
        files = glob.glob(os.path.join(report_dir, "*.csv"))
        files.sort(key=os.path.getmtime, reverse=True)

        if not files:
            st.info("No reports found.")
        else:
            selected_file = st.selectbox("Select Report", files)
            if selected_file:
                try:
                    df = pd.read_csv(selected_file)
                    st.dataframe(df)

                    st.download_button(
                        label="Download CSV",
                        data=df.to_csv(index=False).encode('utf-8'),
                        file_name=os.path.basename(selected_file),
                        mime='text/csv',
                    )
                except Exception as e:
                    st.error(f"Error reading CSV: {e}")
    else:
        st.warning("Report directory does not exist.")

with tab_inventory:
    st.header("Inventory")
    # Similar logic for inventory if needed, or just list inventory files
    st.info("Inventory reports are stored in 'report' directory as well.")
    # Maybe filter for inventory reports?
