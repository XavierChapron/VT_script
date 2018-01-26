#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog
import json
import vt_scan
from tempfile import gettempdir
from os.path import join
from webbrowser import open as webopen


# Full path to the output log
log_path = join(gettempdir(), "vt_scan.html")

config_file = "vt_scan_config.txt"
config = {}


def load_config():
    config = {}
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
    except json.JSONDecodeError:
        print("JSON error")
    except FileNotFoundError:
        print("No config")
        save_config()
    return config


def save_config():
    with open(config_file, "w") as f:
        json.dump(config, f)


class simpleapp_tk(tk.Tk):
    def __init__(self, parent):
        tk.Tk.__init__(self, parent)
        self.parent = parent
        self.initialize()

    def initialize(self):
        self.grid()
        self.file_type = ""
        self.md5s_list = []
        self.results = {}

        self.apikey_string = tk.StringVar()
        self.apikey_string.set(config.get("apikey", "no apikey"))

        apikey_label = tk.Label(self, anchor="w", bg="white", fg="black", text="Apikey:")
        apikey_label.grid(column=0, row=0, columnspan=3, sticky='EW')

        self.apikey_entry = tk.Entry(self, textvariable=self.apikey_string)
        self.apikey_entry.grid(column=3, row=0, columnspan=10, sticky='EW')

        apikey_save_button = tk.Button(self, text="Save", command=self.apikey_save_OnButtonClick)
        apikey_save_button.grid(column=13, row=0, columnspan=5)

        file_dialog_button = tk.Button(self, text="Choose a file", command=self.file_dialog_OnButtonClick)
        file_dialog_button.grid(column=0, row=1)

        self.input_file_string = tk.StringVar()
        self.input_file_string.set("No file selected")
        input_file_label = tk.Label(self, textvariable=self.input_file_string,
                                    anchor="w", bg="white", fg="black")
        input_file_label.grid(column=1, row=1, columnspan=10, sticky='EW')

        run_button = tk.Button(self, text="Run VT Scan", command=self.run_OnButtonClick)
        run_button.grid(column=5, row=2, columnspan=5)

        self.grid_columnconfigure(0, weight=1)
        self.resizable(False, False)
        self.update()

    def apikey_save_OnButtonClick(self):
        config["apikey"] = self.apikey_entry.get()
        self.apikey_string.set(config.get("apikey", "no apikey"))
        save_config()

    def file_dialog_OnButtonClick(self):
        input_file = filedialog.askopenfile(title='Input file')
        if input_file:
            self.input_file_string.set(input_file.name)
            line_list = vt_scan.get_report_lines(self.input_file_string.get())
            self.file_type = vt_scan.get_file_type(line_list[0])
            self.md5s_list = vt_scan.find_md5_in_file(line_list, self.file_type)

    def run_OnButtonClick(self):
        try:
            if len(self.md5s_list) > 0:
                self.results = vt_scan.run_vt_analyse(self.md5s_list, self.apikey_string.get())

                # Create the output log
                vt_scan.save_results(log_path, self.input_file_string.get(), self.file_type, len(self.md5s_list), self.results)

                # Open the log
                webopen(log_path)

        except vt_scan.ScriptError as e:
            print("Catch an error:")
            print(e.message)


if __name__ == "__main__":
    config = load_config()
    print(config)
    app = simpleapp_tk(None)
    app.title('VT Scan GUI')
    app.mainloop()
