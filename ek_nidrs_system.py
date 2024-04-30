import base64
import ctypes
import datetime
import logging
import re
import subprocess
import smtplib
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from os.path import basename

alerts = []  # Initialize an empty list to store alert data
unsorted_alerts = [] # For alert data with failed details classification
ip_count = defaultdict(int)

# Configure based logging
logging.basicConfig(filename='EK_NIDRS.log',
                    filemode='a',
                    level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# Print Network Interfaces
def print_network_interfaces():
    snort_exe_path = read_setting("snort_exe_path")
    result = subprocess.run([snort_exe_path, '-W'], capture_output=True, text=True)
    return result.stdout

# Start Network Monitoring using Snort
def start_snort():
    snort_exe_path = read_setting("snort_exe_path")
    snort_conf_path = read_setting("snort_conf_path")
    filter_pattern = read_setting("filter_pattern")
    interface_num = read_setting("interface_num")

    global snort_process, log_name
    log_name = ""

    try:
        snort_process = subprocess.Popen(
            [snort_exe_path, "-A", "console", "-c", snort_conf_path, "-i", interface_num],
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True
        )
        
        if snort_process.stdout:
            for line in iter(snort_process.stdout.readline, ''):
                if re.match(filter_pattern, line):
                    get_alert_info(line)
    except Exception as e:
        logging.info(f"Error starting Snort: {e}")

    if snort_process.returncode != 0:
        if snort_process.returncode != None:
            logging.info(f"Snort exited with an error. Return code: {snort_process.returncode}")

# Stop Network Monitoring
def stop_snort():
    global snort_process
    if snort_process:
        send_email()
        snort_process.terminate() 
        snort_process.wait()

# Offline Detection
def snort_offline(offline_file):
    snort_exe_path = read_setting("snort_exe_path")
    snort_conf_path = read_setting("snort_conf_path")
    filter_pattern = read_setting("filter_pattern")
    
    global log_name
    log_name = ""
    
    snort_process = subprocess.Popen(
        [snort_exe_path, "-A", "console", "-c", snort_conf_path, "-r", offline_file],
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True
    )
    
    if snort_process.stdout:
        for line in iter(snort_process.stdout.readline, ''):
            if re.match(filter_pattern, line):
                get_alert_info(line)
        send_email()
    returncode = snort_process.wait()
    
    if returncode != 0:
        logging.info(f"Snort exited with an error. Return code: {returncode}")
    
    return snort_process.pid

# Get Alert Details
def get_alert_info(line):
    global alerts, unsorted_alerts
    alert_pattern = read_setting("alert_pattern")
    alert_prio = read_setting("priority")
    alert_threshold = read_setting("threshold")
    blacklists = blacklist_ip("rd", "0")
    whitelists = whitelist_ip("rd", "0")
    match = re.search(alert_pattern, line)
    if match:
        alert_data = {
            "timestamp": match.group(1),
            "alert_msg": match.group(2),
            "classification": match.group(3) if match.group(3) else "Not Classified",
            "priority": int(match.group(4)),
            "protocol": match.group(5),
            "src_ip": match.group(6),
            "src_port": int(match.group(7)) if match.group(7) else None,
            "dst_ip": match.group(8),
            "dst_port": int(match.group(9)) if match.group(9) else None,
        }
        alerts.append(alert_data)
    else:
        unsorted_alerts.append(line)
    
    try:
        if (alert_data['priority'] <= alert_prio):
            source_ip = alert_data['src_ip']
            if (source_ip not in blacklists) and (source_ip not in whitelists):
                ip_count[source_ip] += 1

            if ip_count[source_ip] >= alert_threshold:
                blacklist_ip("add", source_ip)
    except:
        pass

# Sort Alerts Before Sending Emails
def sort_alerts():
    global alerts
    alerts.sort(key=lambda alert: alert['priority'])

# Send Email To User
def send_email():
    global alerts
    global log_name
    log_name = log_time()

    if (alerts != []) or (unsorted_alerts != []):
        sort_alerts()
        
        count = 0
        log_info = "All Alerts:\n\n"
        if alerts != []:
            for alert in alerts:
                count += 1
                log_info += f"Alert {count}:\nTimestamp: {alert['timestamp']}\nMessage: {alert['alert_msg']}\nClassification: {alert['classification']}\nPriority: {alert['priority']}\nProtocol: {alert['protocol']}\nSource: {alert['src_ip']}:{alert['src_port']}\nDestination: {alert['dst_ip']}:{alert['dst_port']}\n\n"
        if unsorted_alerts != []:
            for alert in unsorted_alerts:
                count += 1
                log_info += f"Alert {count}:\n{alert}\n\n"
        
        with open(log_name, 'w') as file:
            file.write(log_info)

        log_info = [] # Reset log_info after use

        MAX_ALERTS = 20
        alerts_to_send = alerts[:MAX_ALERTS]

        # Start Sending Email
        sender_email = read_setting("sender_email")
        app_password = read_setting("app_password")
        receiver_email = read_setting("receiver_email")

        # Format the email body with all alerts
        alert_info = "Dear User,\n\nThis is a consolidated alert message from EK Network Intrusion Detection and Response System.\n\n"
        count = 0
        if alerts_to_send != []:
            if len(alerts_to_send) == MAX_ALERTS:
                alert_info += "Top 20 Alerts:\n"
            else:
                alert_info += "Detected Alerts:\n"
            for alert in alerts_to_send:
                count += 1
                alert_info += f"Alert {count}:\nTimestamp: {alert['timestamp']}\nMessage: {alert['alert_msg']}\nClassification: {alert['classification']}\nPriority: {alert['priority']}\nProtocol: {alert['protocol']}\nSource: {alert['src_ip']}:{alert['src_port']}\nDestination: {alert['dst_ip']}:{alert['dst_port']}\n\n"

            if len(alerts_to_send) == MAX_ALERTS:
                alert_info += f"\nOverall alerts can be found in the attachment or in the log directory of your device.\nYour alerts file name is: {log_name}"
            else:
                alert_info += f"\nAlerts details can be found in the attachment or in the log directory of your device.\nYour alerts file name is: {log_name}"

        if count > 0:
            message = MIMEMultipart()
            message['From'] = sender_email
            message['To'] = receiver_email
            message['Subject'] = 'Network Intrusion Detection Alerts'

            message.attach(MIMEText(alert_info, 'plain'))

            with open(log_name, "rb") as f:
                attachment = MIMEApplication(f.read(), Name=basename(log_name))
            attachment['Content-Disposition'] = 'attachment; filename="{}"'.format(basename(log_name))
            message.attach(attachment)

            try:
                server = smtplib.SMTP('smtp.gmail.com', 587)  # Gmail SMTP server and port
                server.starttls()
                server.login(sender_email, app_password)
                server.sendmail(sender_email, receiver_email, message.as_string())
                server.quit()
            except Exception as e:
                logging.info(f"An error occurred: {e}")

        # Clear the alerts list after sending the email
        alerts = []
    else:
        return

# Read Settings File
def read_setting(config):
    with open('settings.encrypted', 'r') as file:
        for line in file:
            if line.startswith('#') or not line.strip():
                continue
            name, value = line.strip().split('=', 1)
            if name == config:
                return base64.b64decode(value.encode('utf-8')).decode('utf-8')
        return 0

# Data Validation
def validate_input(input_string, config):
    if config == "receiver_email":
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", input_string):
            return False
    elif config == "interface_num" or config == "threshold":
        try:
            int(input_string)
            return True
        except:
            return False
    elif config == "priority":
        try:
            input_int = int(input_string)
            if input_int >= 1 and input_int <= 4:
                return True
            else:
                return False
        except:
            return False
    elif config == "ip":
        if not re.match(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", input_string):
            return False
    return True

# Change Settings
def change_setting(config, new_value):
    settings = {}
    changed = 0
    with open('settings.encrypted', 'r') as file:
        for line in file:
            name, value = line.strip().split('=', 1)
            if name == config:
                settings[name] = base64.b64encode(new_value.encode('utf-8')).decode('utf-8')
                changed += 1
            else:
                settings[name] = value

    with open('settings.encrypted', 'w') as file:
        for name, value in settings.items():
            file.write(f'{name}={value}\n')

# Determine If The User Is Having Administrative Privilege
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Write Firewall Rule
def add_firewall_rule(name, protocol, direction, port, action, source_ip):
    if is_admin():
        command = f"netsh advfirewall firewall add rule name=\"{name}\" protocol={protocol} dir={direction} localport={port} action={action} remoteip={source_ip}"
        subprocess.run(command, shell=True)
        with open("FwRule.txt", 'a') as file:
            fw_message = f"{name}"
            fw_message = base64.b64encode(fw_message.encode('utf-8')).decode('utf-8') + "\n"
            file.write(fw_message)
    else:
        logging.info("Not running in administrator mode!")
        pass

# Delete Added Firewall Rule
def delete_firewall_rule(rule_name):
    if is_admin():
        command = f"netsh advfirewall firewall delete rule name=\"{rule_name}\""
        subprocess.run(command, shell=True)

        with open("FwRule.txt", "r") as infile:
            lines = infile.readlines()
        infile.close()

        with open("FwRule.txt", "w") as outfile:
            for line in lines:
                line = base64.b64decode(line.encode('utf-8')).decode('utf-8')
                if not line.strip().endswith(rule_name):
                    line = base64.b64encode(line.encode('utf-8')).decode('utf-8') + "\n"
                    outfile.write(line)
        outfile.close()
    else:
        logging.info("Not running in administrator mode!")
        pass

# Modifying IP In Blacklist
def blacklist_ip(action, ip):
    if action == "rd":
        blacklists = []
        with open("blacklist.txt", "r") as file:
            lines = file.readlines()
        file.close()
        for line in lines:
            blacklists.append(line)
        return blacklists
    elif action == "add":
        add_firewall_rule(f"Block Malicious IP {ip}", "TCP", "in", "80", "block", ip)

        with open("blacklist.txt", "r") as infile:
            lines = infile.readlines()
        infile.close()
        with open("blacklist.txt", 'w') as file:
            for line in lines:
                if base64.b64decode(line.encode('utf-8')).decode('utf-8') != ip:
                    file.write(line)
                else:
                    continue
            ip = base64.b64encode(ip.encode('utf-8')).decode('utf-8') + "\n"
            file.write(ip)
    elif action == "del":
        delete_firewall_rule(f"Block Malicious IP {ip}")

        with open("blacklist.txt", "r") as infile:
            lines = infile.readlines()
        infile.close()
        with open("blacklist.txt", 'w') as outfile:
            for line in lines:
                line = base64.b64decode(line.encode('utf-8')).decode('utf-8')
                if line != ip:
                    line = base64.b64encode(line.encode('utf-8')).decode('utf-8') + "\n"
                    outfile.write(line)
        outfile.close()
    else:
        return

# Modifying IP In Whitelist
def whitelist_ip(action, ip):
    if action == "rd":
        whitelists = []
        with open("whitelist.txt", "r") as file:
            lines = file.readlines()
        file.close()
        for line in lines:
            whitelists.append(line)
        return whitelists
    elif action == "add":
        with open("whitelist.txt", "r") as infile:
            lines = infile.readlines()
        infile.close()
        with open("whitelist.txt", 'w') as file:
            for line in lines:
                if base64.b64decode(line.encode('utf-8')).decode('utf-8') != ip:
                    file.write(line)
                else:
                    continue
            ip = base64.b64encode(ip.encode('utf-8')).decode('utf-8') + "\n"
            file.write(ip)
    elif action == "del":
        with open("whitelist.txt", "r") as infile:
            lines = infile.readlines()
        infile.close()
        with open("whitelist.txt", 'w') as outfile:
            for line in lines:
                line = base64.b64decode(line.encode('utf-8')).decode('utf-8')
                if line != ip:
                    line = base64.b64encode(line.encode('utf-8')).decode('utf-8') + "\n"
                    outfile.write(line)
        outfile.close()
    else:
        return

# Use Current Time As Alert Log Name
def log_time():
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%Y%m%d_%H%M%S")
    log_name = "ids_log_" + formatted_time + ".txt"
    return log_name

# Get Alert Log Name
def get_log_name():
    global log_name
    return log_name