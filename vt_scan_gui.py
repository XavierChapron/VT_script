#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog
from tkinter import scrolledtext
import vt_scan
from tempfile import gettempdir
from webbrowser import open as webopen
from os.path import join, dirname, abspath
import sys


# Full path to the output log
log_path = join(gettempdir(), "vt_scan.html")

config_file_name = "vt_scan_config.txt"


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
        self.config_file = join(dirname(abspath(sys.argv[0])), config_file_name)

        self.apikey_string = tk.StringVar()

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

        self.console = scrolledtext.ScrolledText(undo=True)
        self.console.grid(column=0, row=8, columnspan=18)
        self.console.insert(tk.END, "Loading config...\n")
        try:
            self.config = vt_scan.load_config(self.config_file)
            self.console.insert(tk.END, "Config found:\n%s\n" % str(self.config))
        except vt_scan.ScriptError as e:
            self.console.insert(tk.END, "\n/!\\ ERROR: %s\n" % e.message)

        self.apikey_string.set(self.config.get("apikey", "no apikey"))

        self.grid_columnconfigure(0, weight=1)
        self.resizable(False, False)
        self.update()

    def apikey_save_OnButtonClick(self):
        self.config["apikey"] = self.apikey_entry.get()
        self.apikey_string.set(self.config.get("apikey", "no apikey"))
        vt_scan.save_config(self.config, self.config_file)
        self.console.insert(tk.END, "Config: Saving apikey into config file\n")

    def file_dialog_OnButtonClick(self):
        input_file = filedialog.askopenfile(title='Input file')
        if input_file:
            self.input_file_string.set(input_file.name)
            line_list = vt_scan.get_report_lines(self.input_file_string.get())
            self.file_type = vt_scan.get_file_type(line_list[0])
            self.md5s_list = vt_scan.find_md5_in_file(line_list, self.file_type)
            self.console.insert(tk.END, "\nOpening: %s\n" % input_file)
            self.console.insert(tk.END, "Found the file to be of type %s\n" % self.file_type)
            self.console.insert(tk.END, "Found %s MD5s\n" % len(self.md5s_list))

    def run_OnButtonClick(self):
        try:
            if len(self.md5s_list) > 0:
                try:
                    apikey = self.config["apikey"]
                except KeyError:
                    raise vt_scan.ScriptError("You should configure an apikey")
                self.results = vt_scan.run_vt_analyse(self.md5s_list, apikey)

                # Create the output log
                vt_scan.save_results(log_path, self.input_file_string.get(), self.file_type, len(self.md5s_list), self.results)

                # Open the log
                self.console.insert(tk.END, "\nScan complete, opening results\n")
                webopen(log_path)
            else:
                raise vt_scan.ScriptError("You have to choose a file with MD5s")

        except vt_scan.ScriptError as e:
            self.console.insert(tk.END, "\n/!\\ ERROR: %s\n" % e.message)


if __name__ == "__main__":
    app = simpleapp_tk(None)
    app.title('VT Scan GUI')
    app.mainloop()
