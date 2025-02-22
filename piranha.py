'''
piranha frontend
'''

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import backend
import logging

apt_groups = {}

TACTIC_MAPPING = {
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource-development",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact"
}

TACTIC_DISPLAY_NAMES = list(TACTIC_MAPPING.keys())


root = tk.Tk()
root.title("Piranha")
root.geometry("950x750")


tk.Label(root, text="Piranha T-Code Mapper", font=("Castellar", 16, "bold")).pack(pady=10)


selection_frame = tk.Frame(root)
selection_frame.pack(pady=10, padx=10, fill="x")


apt_frame = tk.Frame(selection_frame)
apt_frame.pack(side="left", padx=10, fill="both", expand=True)

tk.Label(apt_frame, text="Select APT(s):", font=("Arial", 12)).pack(side="top")


include_description = tk.BooleanVar(value=True)

desc_checkbox_frame = tk.Frame(root)
desc_checkbox_frame.pack(pady=5)
desc_checkbox = tk.Checkbutton(desc_checkbox_frame, text="Include T-Code Descriptions", variable=include_description, font=("Arial", 12))
desc_checkbox.pack(side="left")


use_enterprise = tk.BooleanVar(value=True)
use_mobile = tk.BooleanVar(value=False)
use_ics = tk.BooleanVar(value=False)



search_var = tk.StringVar()

def update_listbox(*args):
    global apt_groups
    selected_datasets = {
        "enterprise": use_enterprise.get(),
        "mobile": use_mobile.get(),
        "ics": use_ics.get()
    }

    mitre_data, _ = backend.load_mitre_data(selected_datasets)
    apt_groups = backend.get_apt_groups(mitre_data) if mitre_data else {}

    apt_listbox.delete(0, tk.END)

    for apt in sorted(apt_groups.keys()):
        apt_listbox.insert(tk.END, apt)
    search_term = search_var.get().lower()
    apt_listbox.delete(0, tk.END)
    
    for apt in sorted(apt_groups.keys()):
        if search_term in apt.lower():
            apt_listbox.insert(tk.END, apt)

search_entry = tk.Entry(apt_frame, textvariable=search_var, width=40, font=("Arial", 12))
search_entry.pack(side="top", pady=5)
search_var.trace_add("write", update_listbox)


apt_listbox_frame = tk.Frame(apt_frame)
apt_listbox_frame.pack()

apt_scrollbar = tk.Scrollbar(apt_listbox_frame, orient="vertical")
apt_listbox = tk.Listbox(apt_listbox_frame, selectmode="multiple", height=12, width=40, font=("Arial", 12), yscrollcommand=apt_scrollbar.set, exportselection=False)
apt_scrollbar.config(command=apt_listbox.yview)
apt_scrollbar.pack(side="right", fill="y")
apt_listbox.pack(side="left", padx=10)

update_listbox()

tactic_frame = tk.Frame(selection_frame)
tactic_frame.pack(side="left", padx=10, fill="both", expand=True)
tactic_label_frame = tk.Frame(tactic_frame)
tactic_label_frame.grid(row=0, column=0, sticky="ew")
tactic_label_frame.pack(fill="x")

tactic_label = tk.Label(tactic_label_frame, text="Select Tactic(s):", font=("Arial", 12)).pack(pady=5, anchor="center")
tactic_frame.columnconfigure(0, weight=1)

tactic_scrollbar = tk.Scrollbar(tactic_frame, orient="vertical")
tactic_listbox = tk.Listbox(tactic_frame, selectmode="multiple", height=12, width=40, font=("Arial", 12), yscrollcommand=tactic_scrollbar.set, exportselection=False)
tactic_scrollbar.config(command=tactic_listbox.yview)
tactic_scrollbar.pack(side="right", fill="y")
tactic_listbox.pack(side="left", padx=10)




dataset_frame = tk.Frame(root)
dataset_frame.pack(pady=5)

tk.Label(dataset_frame, text="Select Dataset(s):", font=("Arial", 12)).pack(side="top")

enterprise_checkbox = tk.Checkbutton(dataset_frame, text="Enterprise ATT&CK", variable=use_enterprise, font=("Arial", 10))
enterprise_checkbox.pack(side="left", padx=5)

mobile_checkbox = tk.Checkbutton(dataset_frame, text="Mobile ATT&CK", variable=use_mobile, font=("Arial", 10))
mobile_checkbox.pack(side="left", padx=5)

ics_checkbox = tk.Checkbutton(dataset_frame, text="ICS ATT&CK", variable=use_ics, font=("Arial", 10))
ics_checkbox.pack(side="left", padx=5)

for tactic in TACTIC_DISPLAY_NAMES:
    tactic_listbox.insert(tk.END, tactic)


tree_frame = tk.Frame(root)
tree_frame.pack(pady=10, fill="both", expand=True)

tree_scroll_y = tk.Scrollbar(tree_frame, orient="vertical")
tree_scroll_x = tk.Scrollbar(tree_frame, orient="horizontal")

columns = ["APT", "Category", "T-Code", "Dataset Source", "Description", "IOC", "Detection Tool"]
tree = ttk.Treeview(tree_frame, columns=columns, show="headings", yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

tree_scroll_y.config(command=tree.yview)
tree_scroll_x.config(command=tree.xview)
tree_scroll_y.pack(side="right", fill="y")
tree_scroll_x.pack(side="bottom", fill="x")

for col in columns:
    if col == "T-Code Description":
        tree.column(col, anchor="w", width=250)  
    elif col == "Dataset Source":
        tree.column(col, anchor="w", width=150)  
    else:
        tree.column(col, anchor="w", width=150)
    tree.heading(col, text=col)

tree.pack(fill="both", expand=True)

output_data = []

def generate_report():
    global output_data
    selected_apts = [apt_listbox.get(idx) for idx in apt_listbox.curselection()]
    selected_display_tactics = [tactic_listbox.get(idx) for idx in tactic_listbox.curselection()]
    
    selected_tactics = [TACTIC_MAPPING[tactic] for tactic in selected_display_tactics]
    include_desc = include_description.get()

 
    selected_datasets = {
        "enterprise": use_enterprise.get(),
        "mobile": use_mobile.get(),
        "ics": use_ics.get()
    }

    logging.info(f"Selected APTs: {selected_apts}")
    logging.info(f"Selected Tactics (Human-readable): {selected_display_tactics}")
    logging.info(f"Converted Tactics (JSON names): {selected_tactics}")
    logging.info(f"Include T-Code Descriptions: {include_desc}")
    logging.info(f"Selected Datasets: {selected_datasets}")

    if not selected_apts:
        messagebox.showerror("Error", "Please select at least one APT.")
        return

    if not selected_tactics:
        messagebox.showerror("Error", "Please select at least one tactic.")
        return

    if not any(selected_datasets.values()):
        messagebox.showerror("Error", "Please select at least one dataset.")
        return

    output_data = backend.get_apt_report(selected_apts, selected_tactics, include_desc, selected_datasets)

    if not output_data:
        logging.error("No data retrieved from backend.")
        messagebox.showerror("Error", "No data retrieved. Check the JSON file or tactic mappings.")
        return

    for row in tree.get_children():
        tree.delete(row)
    for data in output_data:
        tree.insert("", "end", values=data)



# Export to Excel Function
def export_to_excel():
    if not output_data:
        messagebox.showerror("Error", "No data to export. Generate a report first.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".xlsx",
                                             filetypes=[("Excel Files", "*.xlsx"), ("All Files", "*.*")])

    if file_path:
        include_desc = include_description.get()  
        backend.save_to_excel(output_data, file_path, include_desc) 
        messagebox.showinfo("Success", f"Data saved to {file_path}")



btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

generate_btn = tk.Button(btn_frame, text="Generate Report", command=generate_report, bg="blue", fg="white", font=("Arial", 12))
generate_btn.pack(side="left", padx=10)

export_btn = tk.Button(btn_frame, text="Export to Excel", command=export_to_excel, bg="green", fg="white", font=("Arial", 12))
export_btn.pack(side="left", padx=10)

root.mainloop()
