import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import base64
import ek_nidrs_system as ids

# Color Scheme
Bg_Color = "lavender"
Btn_Color = "lavender blush"
Unsaved_Color = "sandy brown"
Saved_Color = "DarkSeaGreen1"
Listbox_Color = "linen"
All_Font = ("Arial", 10)

def create_gui():
    root = tk.Tk()
    root.title("NIDRS System Control")

    # Frames for different functionalities
    frames = {
        "Home": tk.Frame(root),
        "Network Interfaces": tk.Frame(root),
        "Added Firewall Rules": tk.Frame(root),
        "Blacklist & Whitelist": tk.Frame(root),
        "Settings": tk.Frame(root)
    }

    # Initialize all frames
    for frame in frames.values():
        frame.grid(row=0, column=0, sticky='news')
        frame.config(bg=Bg_Color)

    # Function to raise a frame and load content if necessary
    def raise_frame(frame_name):
        frame = frames[frame_name]
        frame.tkraise()
        if frame_name == "Network Interfaces":
            load_interfaces()
        elif frame_name == "Added Firewall Rules":
            load_firewall_rules(fw_listbox)
        elif frame_name == "Blacklist & Whitelist":
            load_blacklist(bl_listbox)
            load_whitelist(wl_listbox)

    # Home Frame content
    home_label = tk.Label(frames["Home"], text="Welcome to EK NIDRS System")
    home_label.config(font=All_Font)
    home_label.config(bg=Bg_Color)
    home_label.pack(pady=20)

    # Snort Control Buttons in Home Frame
    def start_snort():
        def snort_thread():
            start_snort_button.config(state=tk.DISABLED)
            stop_snort_button.config(state=tk.NORMAL)
            messagebox.showinfo("Snort Control", "Snort is now running in background")
            ids.start_snort()
        threading.Thread(target=snort_thread).start()

    start_snort_button = tk.Button(frames["Home"], text="Start Snort", command=start_snort)
    start_snort_button.config(font=All_Font, height=2, width=16)
    start_snort_button.config(bg=Btn_Color)
    start_snort_button.pack(pady=20)

    def stop_snort():
        ids.stop_snort()
        messagebox.showinfo("Snort Control", "Snort has been stopped")
        start_snort_button.config(state=tk.NORMAL)
        stop_snort_button.config(state=tk.DISABLED)
        get_log()

    stop_snort_button = tk.Button(frames["Home"], text="Stop Snort", command=stop_snort, state=tk.DISABLED)
    stop_snort_button.config(font=All_Font, height=2, width=16)
    stop_snort_button.config(bg=Btn_Color)
    stop_snort_button.pack(pady=20)

    # Offline Detection Frame content
    def run_offline_detection():
        offline_file = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP Files", "*.pcap")])
        if offline_file:
            def detection_thread():
                ids.snort_offline(offline_file)
                detect_button.config(state=tk.NORMAL)
                get_log()
            messagebox.showinfo("Offline Detection", "Offline detection is now running, please wait patiently")
            detect_button.config(state=tk.DISABLED)
            threading.Thread(target=detection_thread).start()

    detect_button = tk.Button(frames["Home"], text="Offline Detection", command=run_offline_detection)
    detect_button.config(font=All_Font, height=2, width=16)
    detect_button.config(bg=Btn_Color)
    detect_button.pack(pady=20)

    # Getting Log Name
    def get_log():
        log_name = ids.get_log_name()
        message = (f"Detection Completed, you can view the log {log_name} for details")
        messagebox.showinfo(f"Detection Completed", message)

    # Network Interfaces Frame content
    interfaces_text = tk.Text(frames["Network Interfaces"])
    interfaces_text.config(bg=Bg_Color)
    interfaces_text.pack(fill=tk.BOTH, expand=True)

    def load_interfaces():
        interfaces_text.delete('1.0', tk.END)
        interfaces_text.insert(tk.END, ids.print_network_interfaces())
        interfaces_text.config(state=tk.DISABLED)

    # Settings Frame content
    def save_changes():
        email_validate = ids.validate_input(email_entry.get(), "receiver_email")
        if not email_validate == True:
            messagebox.showwarning("Warning", "Invalid email address, please try again!")
            return
        interface_validate = ids.validate_input(interface_entry.get(), "interface_num")
        if not interface_validate == True:
            messagebox.showwarning("Warning", "Invalid interface number, please try again!")
            return
        priority_validate = ids.validate_input(priority_entry.get(), "priority")
        if not priority_validate == True:
            messagebox.showwarning("Warning", "Invalid priority level, please try again!")
            return
        threshold_validate = ids.validate_input(threshold_entry.get(), "priority")
        if not threshold_validate == True:
            messagebox.showwarning("Warning", "Invalid threshold count, please try again!")
            return
        new_settings = {
            'snort_exe_path': snort_path_entry.get(),
            'snort_conf_path': snort_conf_entry.get(),
            'receiver_email': email_entry.get(),
            'interface_num': interface_entry.get(),
            'priority': priority_entry.get(),
            'threshold': threshold_entry.get()
        }

        # Only save if there were actual changes
        if new_settings != current_settings:
            for key, setting in new_settings.items():
                ids.change_setting(key, setting)

            current_settings.update(new_settings)
            messagebox.showinfo("Settings", "Settings updated successfully")

        # Change entry states to readonly
        for entry_widget in [snort_path_entry, snort_conf_entry, email_entry, interface_entry, priority_entry, threshold_entry]:
            entry_widget.config(state="readonly")
        for entry_widget in [snort_path_entry, snort_conf_entry, email_entry, interface_entry, priority_entry, threshold_entry]:
            entry_widget.config(readonlybackground=Saved_Color)

    current_settings = {
        'snort_exe_path': ids.read_setting("snort_exe_path"),
        'snort_conf_path': ids.read_setting("snort_conf_path"),
        'receiver_email': ids.read_setting("receiver_email"),
        "interface_num": ids.read_setting("interface_num"),
        "priority": ids.read_setting("priority"),
        "threshold": ids.read_setting("threshold")
    }

    # GUI Setup in Settings Frame
    def get_dir(file_type):
        if file_type == ".exe":
            file = filedialog.askopenfilename(title="Select snort.exe", filetypes=[("Snort Executable", "snort.exe")])
            if file:
                snort_path_entry.config(state=tk.NORMAL)
                snort_path_entry.delete(0, tk.END)
                file = file.replace("/", "\\")
                snort_path_entry.insert(0, file)
                snort_path_entry.config(state="readonly", readonlybackground=Unsaved_Color)
        elif file_type == ".conf":
            file = filedialog.askopenfilename(title="Select snort.conf", filetypes=[("Snort Configuration File", "snort.conf")])
            if file:
                snort_conf_entry.config(state=tk.NORMAL)
                snort_conf_entry.delete(0, tk.END)
                file = file.replace("/", "\\")
                snort_conf_entry.insert(0, file)
                snort_conf_entry.config(state="readonly", readonlybackground=Unsaved_Color)


    snort_path_label = tk.Label(frames["Settings"], text="snort.exe path :")
    snort_path_label.config(bg=Bg_Color)
    snort_path_label.grid(row=0, column=0, padx=10, pady=10)
    snort_path_entry = tk.Entry(frames["Settings"])
    snort_path_entry.insert(0, current_settings['snort_exe_path'])
    snort_path_entry.config(state="readonly")
    snort_path_entry.config(font=All_Font)
    snort_path_entry.grid(row=0, column=1)
    snort_path_change_button = tk.Button(frames["Settings"], text="Change", command=lambda: get_dir(".exe"))
    snort_path_change_button.config(bg=Btn_Color)
    snort_path_change_button.grid(row=0, column=2, padx=10, pady=10)

    snort_conf_label = tk.Label(frames["Settings"], text="snort.conf path :")
    snort_conf_label.config(bg=Bg_Color)
    snort_conf_label.grid(row=1, column=0, padx=10, pady=10)
    snort_conf_entry = tk.Entry(frames["Settings"])
    snort_conf_entry.insert(0, current_settings['snort_conf_path'])
    snort_conf_entry.config(state="readonly")
    snort_conf_entry.config(font=All_Font)
    snort_conf_entry.grid(row=1, column=1)
    snort_conf_change_button = tk.Button(frames["Settings"], text="Change", command=lambda: get_dir(".conf"))
    snort_conf_change_button.config(bg=Btn_Color)
    snort_conf_change_button.grid(row=1, column=2, padx=10, pady=10)

    email_label = tk.Label(frames["Settings"], text="Email Address :")
    email_label.config(bg=Bg_Color)
    email_label.grid(row=2, column=0, padx=10, pady=10)
    email_entry = tk.Entry(frames["Settings"])
    email_entry.insert(0, current_settings['receiver_email'])
    email_entry.config(state="readonly")
    email_entry.config(font=All_Font)
    email_entry.grid(row=2, column=1)
    email_entry_button = tk.Button(frames["Settings"], text="Change", command=lambda: email_entry.config(state="normal"))
    email_entry_button.config(bg=Btn_Color)
    email_entry_button.grid(row=2, column=2, padx=10, pady=10)

    interface_label = tk.Label(frames["Settings"], text="Interface Number :")
    interface_label.config(bg=Bg_Color)
    interface_label.grid(row=3, column=0, padx=10, pady=10)
    interface_entry = tk.Entry(frames["Settings"])
    interface_entry.insert(1, current_settings['interface_num'])
    interface_entry.config(state="readonly")
    interface_entry.config(font=All_Font)
    interface_entry.grid(row=3, column=1)
    interface_button = tk.Button(frames["Settings"], text="Change", command=lambda: interface_entry.config(state="normal"))
    interface_button.config(bg=Btn_Color)
    interface_button.grid(row=3, column=2, padx=10, pady=10)

    priority_label = tk.Label(frames["Settings"], text="Alert Priority [1-4] :")
    priority_label.config(bg=Bg_Color)
    priority_label.grid(row=4, column=0, padx=10, pady=10)
    priority_entry = tk.Entry(frames["Settings"])
    priority_entry.insert(1, current_settings['priority'])
    priority_entry.config(state="readonly")
    priority_entry.config(font=All_Font)
    priority_entry.grid(row=4, column=1)
    priority_button = tk.Button(frames["Settings"], text="Change", command=lambda: priority_entry.config(state="normal"))
    priority_button.config(bg=Btn_Color)
    priority_button.grid(row=4, column=2, padx=10, pady=10)

    threshold_label = tk.Label(frames["Settings"], text="Blacklist Threshold :")
    threshold_label.config(bg=Bg_Color)
    threshold_label.grid(row=5, column=0, padx=10, pady=10)
    threshold_entry = tk.Entry(frames["Settings"])
    threshold_entry.insert(1, current_settings['threshold'])
    threshold_entry.config(state="readonly")
    threshold_entry.config(font=All_Font)
    threshold_entry.grid(row=5, column=1)
    threshold_button = tk.Button(frames["Settings"], text="Change", command=lambda: threshold_entry.config(state="normal"))
    threshold_button.config(bg=Btn_Color)
    threshold_button.grid(row=5, column=2, padx=10, pady=10)

    save_button = tk.Button(frames["Settings"], text="Save Changes", command=save_changes)
    save_button.config(bg=Btn_Color)
    save_button.grid(row=6, column=1, padx=10, pady=10)

    # Firewall Log
    def load_firewall_rules(listbox):
        fw_listbox.delete(0, tk.END)
        with open("FwRule.txt", "r") as file:
            for line in file:
                rule_name = base64.b64decode(line.encode('utf-8')).decode('utf-8')
                # rule_name = line.split('=')[1].strip()
                fw_listbox.insert(tk.END, rule_name)
        file.close()
    
    def delete_selected_rule(listbox):
        selected_index = listbox.curselection()
        if selected_index:
            rule_name = listbox.get(selected_index[0])
            ids.delete_firewall_rule(rule_name)
            load_firewall_rules(listbox)
    
    fw_listbox = tk.Listbox(frames["Added Firewall Rules"])
    fw_listbox.config(bg=Listbox_Color)
    fw_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(frames["Added Firewall Rules"])
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    fw_listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=fw_listbox.yview)

    delete_button = tk.Button(frames["Added Firewall Rules"], text="Delete Selected", command=lambda: delete_selected_rule(fw_listbox))
    delete_button.config(bg=Btn_Color)
    delete_button.pack()

    # Blacklist & Whitelist
    def validate_ip(ip):
        return ids.validate_input(ip, "ip")
    
    def load_blacklist(listbox):
        bl_listbox.delete(0, tk.END)
        with open("blacklist.txt", "r") as file:
            for line in file:
                rule_name = base64.b64decode(line.encode('utf-8')).decode('utf-8')
                # rule_name = line.split('=')[1].strip()
                bl_listbox.insert(tk.END, rule_name)
        file.close()
    
    def add_blacklist():
        # Create a new top-level window
        add_window = tk.Toplevel()
        add_window.title("Add to Blacklist")

        # Label
        label = tk.Label(add_window, text="Enter IP Address:")
        label.pack(pady=10)

        # Entry widget for user to enter the IP address
        ip_entry = tk.Entry(add_window, width=20)
        ip_entry.pack(pady=5)

        def submit_bl():
            ip = ip_entry.get()
            if validate_ip(ip):
                ids.blacklist_ip("add", ip)
                load_blacklist(bl_listbox)
                # bl_listbox.insert(tk.END, ip)  # Update the GUI listbox
                add_window.destroy()
            else:
                tk.messagebox.showwarning("Warning", "Please enter a valid IP address.")
        
        # Button to submit the IP address
        submit_button = tk.Button(add_window, text="Add", command=submit_bl)
        submit_button.pack(pady=10)
        
    def blacklist_move(listbox):
        selected_index = listbox.curselection()
        if selected_index:
            ip = listbox.get(selected_index[0])
            ids.whitelist_ip("add", ip)
            ids.blacklist_ip("del", ip)
            load_blacklist(bl_listbox)
            load_whitelist(wl_listbox)

    def delete_selected_blacklist(listbox):
        selected_index = listbox.curselection()
        if selected_index:
            ip = listbox.get(selected_index[0])
            ids.blacklist_ip("del", ip)
            load_blacklist(bl_listbox)
    
    def load_whitelist(listbox):
        wl_listbox.delete(0, tk.END)  # Clear existing rules
        with open("whitelist.txt", "r") as file:
            for line in file:
                rule_name = base64.b64decode(line.encode('utf-8')).decode('utf-8')
                # rule_name = line.split('=')[1].strip()
                wl_listbox.insert(tk.END, rule_name)
        file.close()

    def add_whitelist():
        # Create a new top-level window
        add_window = tk.Toplevel()
        add_window.title("Add to Whitelist")

        # Label
        label = tk.Label(add_window, text="Enter IP Address:")
        label.pack(pady=10)

        # Entry widget for user to enter the IP address
        ip_entry = tk.Entry(add_window, width=20)
        ip_entry.pack(pady=5)

        def submit_wl():
            ip = ip_entry.get()
            if validate_ip(ip):
                ids.whitelist_ip("add", ip)
                load_whitelist(bl_listbox)
                add_window.destroy()
            else:
                tk.messagebox.showwarning("Warning", "Please enter a valid IP address.")
        
        # Button to submit the IP address
        submit_button = tk.Button(add_window, text="Add", command=submit_wl)
        submit_button.pack(pady=10)

    def whitelist_move(listbox):
        selected_index = listbox.curselection()
        if selected_index:
            ip = listbox.get(selected_index[0])
            ids.blacklist_ip("add", ip)
            ids.whitelist_ip("del", ip)
            load_blacklist(bl_listbox)
            load_whitelist(wl_listbox)

    def delete_selected_whitelist(listbox):
        selected_index = listbox.curselection()
        if selected_index:
            ip = listbox.get(selected_index[0])
            ids.whitelist_ip("del", ip)
            load_whitelist(wl_listbox)

    bw_frame = frames["Blacklist & Whitelist"]
    
    # Blacklist side
    bl_frame = tk.Frame(bw_frame)
    bl_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    bl_label = tk.Label(bl_frame, text="Blacklist", font=All_Font, bg=Bg_Color)
    bl_label.pack(side=tk.TOP, fill=tk.X)

    bl_listbox = tk.Listbox(bl_frame)
    bl_listbox.config(bg=Listbox_Color)
    bl_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    bl_scrollbar = tk.Scrollbar(bl_frame)
    bl_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    bl_listbox.config(yscrollcommand=bl_scrollbar.set)
    bl_scrollbar.config(command=bl_listbox.yview)

    add_bl_button = tk.Button(bl_frame, text="Add New", command=add_blacklist)
    add_bl_button.config(bg=Btn_Color)
    add_bl_button.pack(side=tk.TOP, fill=tk.X)

    bl_move_button = tk.Button(bl_frame, text="Move to Whitelist", command=lambda: blacklist_move(bl_listbox))
    bl_move_button.config(bg=Btn_Color)
    bl_move_button.pack(side=tk.TOP, fill=tk.X)

    delete_bl_button = tk.Button(bl_frame, text="Delete Selected", command=lambda: delete_selected_blacklist(bl_listbox))
    delete_bl_button.config(bg=Btn_Color)
    delete_bl_button.pack(side=tk.TOP, fill=tk.X)

    # Whitelist side
    wl_frame = tk.Frame(bw_frame)
    wl_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    wl_label = tk.Label(wl_frame, text="Whitelist", font=All_Font, bg=Bg_Color)
    wl_label.pack(side=tk.TOP, fill=tk.X)

    wl_listbox = tk.Listbox(wl_frame)
    wl_listbox.config(bg=Listbox_Color)
    wl_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    wl_scrollbar = tk.Scrollbar(wl_frame)
    wl_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    wl_listbox.config(yscrollcommand=wl_scrollbar.set)
    wl_scrollbar.config(command=wl_listbox.yview)

    add_wl_button = tk.Button(wl_frame, text="Add New", command=add_whitelist)
    add_wl_button.config(bg=Btn_Color)
    add_wl_button.pack(side=tk.TOP, fill=tk.X)

    wl_move_button = tk.Button(wl_frame, text="Move to Blacklist", command=lambda: whitelist_move(wl_listbox))
    wl_move_button.config(bg=Btn_Color)
    wl_move_button.pack(side=tk.TOP, fill=tk.X)

    delete_wl_button = tk.Button(wl_frame, text="Delete Selected", command=lambda: delete_selected_whitelist(wl_listbox))
    delete_wl_button.config(bg=Btn_Color)
    delete_wl_button.pack(side=tk.TOP, fill=tk.X)

    # Navigation buttons
    nav_frame = tk.Frame(root)
    nav_frame.grid(row=1, column=0, sticky='ew')
    nav_frame.config(bg=Bg_Color)

    for frame_name in frames:
        btn = tk.Button(nav_frame, text=frame_name, command=lambda fr=frame_name: raise_frame(fr))
        btn.config(font=All_Font, height=2, width=16)
        btn.config(bg=Btn_Color)
        btn.pack(side=tk.LEFT, expand=True)

    raise_frame("Home")
    root.mainloop()

create_gui()
