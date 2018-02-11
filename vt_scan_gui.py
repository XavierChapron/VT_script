#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog
from tkinter import scrolledtext
import vt_scan
from tempfile import gettempdir
from webbrowser import open as webopen
from os.path import join, dirname, abspath, expanduser
import sys


# Full path to the output log
log_path = join(gettempdir(), "vt_scan.html")

config_file_name = "vt_scan_config.txt"

app_w = 600
app_h = 400
cln_nb = 60
row_nb = 40
cln_w = app_w / cln_nb
row_h = app_h / row_nb


def c_to_x(column):
    return column * cln_w


def r_to_y(row):
    return row * row_h


class simpleapp_tk(tk.Tk):
    def __init__(self, parent):
        tk.Tk.__init__(self, parent)
        self.parent = parent
        self.initialize()

    def initialize(self):
        self.geometry("%sx%s" % (app_w, app_h))
        self.file_type = ""
        self.md5s_list = []
        self.results = {}
        self.config_file = join(dirname(abspath(expanduser(sys.argv[0]))), config_file_name)

        x_pos = 1
        y_pos = 1

        # Apikey widgets
        apikey_label = tk.Label(self, anchor="w", fg="black", text="Apikey:")
        apikey_label.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(6), height=r_to_y(2))
        x_pos += 6 + 1

        self.apikey_string = tk.StringVar()
        self.apikey_entry = tk.Entry(self, textvariable=self.apikey_string)
        self.apikey_entry.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(40), height=r_to_y(2))
        x_pos += 40 + 1

        apikey_save_button = tk.Button(self, text="Save", command=self.apikey_save_OnButtonClick)
        apikey_save_button.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(9), height=r_to_y(2))
        x_pos = 1
        y_pos += 2 + 1

        # Input file widgets
        apikey_label = tk.Label(self, anchor="w", fg="black", text="Input file:")
        apikey_label.place(x=c_to_x(x_pos), y=r_to_y(1 + 2 + 1), width=c_to_x(6), height=r_to_y(2))
        x_pos += 6 + 1

        self.input_file_string = tk.StringVar()
        self.input_file_string.set("No input file selected")
        input_file_label = tk.Label(self, textvariable=self.input_file_string,
                                    anchor="w", bg="white", fg="black")
        input_file_label.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(40), height=r_to_y(2))
        x_pos += 40 + 1

        self.file_dialog_button = tk.Button(self, text="Choose a file", command=self.file_dialog_OnButtonClick)
        self.file_dialog_button.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(9), height=r_to_y(2))
        x_pos = 1
        y_pos += 2 + 1

        # Run widget
        run_button = tk.Button(self, text="Run VT Scan", command=self.run_OnButtonClick)
        run_button.place(x=(app_w - c_to_x(15)) / 2, y=r_to_y(y_pos), width=c_to_x(15), height=r_to_y(2))
        y_pos += 2 + 1

        self.console = scrolledtext.ScrolledText(undo=True)
        self.console.place(x=0, y=r_to_y(y_pos), width=app_w, height=app_h - r_to_y(y_pos))
        self.console.insert(tk.END, "Loading config...\n")
        try:
            self.config = vt_scan.load_config(self.config_file)
            self.console.insert(tk.END, "Config found:\n%s\n" % str(self.config))
            self.console.see(tk.END)
        except vt_scan.ScriptWarning as e:
            self.config = vt_scan.load_config(self.config_file)
            self.console.insert(tk.END, "\n/!\\ WARNING: %s\n" % e.message)
            self.console.see(tk.END)
        except vt_scan.ScriptError as e:
            self.config = {}
            self.console.insert(tk.END, "\n/!\\ ERROR: %s\n" % e.message)
            self.console.see(tk.END)

        self.apikey_string.set(self.config.get("apikey", "no apikey"))

        self.resizable(False, False)

    def apikey_save_OnButtonClick(self):
        self.config["apikey"] = self.apikey_entry.get()
        self.apikey_string.set(self.config.get("apikey", "no apikey"))
        vt_scan.save_config(self.config, self.config_file)
        self.console.insert(tk.END, "Config: Saving apikey into config file\n")
        self.console.see(tk.END)

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
            self.console.see(tk.END)

    def run_OnButtonClick(self):
        try:
            if len(self.md5s_list) > 0:
                try:
                    apikey = self.config["apikey"]
                except KeyError:
                    self.apikey_entry.focus_set()
                    raise vt_scan.ScriptError("You should configure an apikey")
                self.results = vt_scan.run_vt_analyse(self.md5s_list, apikey)

                # Create the output log
                vt_scan.save_results(log_path, self.input_file_string.get(), self.file_type, len(self.md5s_list), self.results)

                # Open the log
                self.console.insert(tk.END, "\nScan complete, opening results\n")
                self.console.see(tk.END)
                webopen(log_path)
            else:
                self.file_dialog_button.focus_set()
                raise vt_scan.ScriptWarning("You have to choose a file containing MD5s")

        except vt_scan.ScriptWarning as e:
            self.console.insert(tk.END, "\n/!\\ WARNING: %s\n" % e.message)
            self.console.see(tk.END)

        except vt_scan.ScriptError as e:
            self.console.insert(tk.END, "\n/!\\ ERROR: %s\n" % e.message)
            self.console.see(tk.END)


if __name__ == "__main__":
    app = simpleapp_tk(None)
    app.title('VT Scan GUI')
    app.mainloop()
