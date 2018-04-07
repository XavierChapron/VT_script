#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog
from tkinter import scrolledtext
from vt_scan import get_string, ScriptWarning, ScriptError, load_config, save_config
from vt_scan import get_output_file, retrieve_apikey, get_file_type, run_vt_analyse
from vt_scan import find_md5_in_file, get_report_content, save_results, get_language_from_locale, VERSION
from vt_scan_constants import ErrorsCodes, config_file_name, VariousCodes
from webbrowser import open as webopen
from os.path import join, dirname, abspath, expanduser
import sys


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


def retrieve_config(config_file):
    language = get_language_from_locale()
    message = ""
    try:
        config = load_config(config_file)
        if "language" in config.keys():
            language = config["language"]
            return config, language, get_string(VariousCodes.config_found, language).format(config=config)
        else:
            message = get_string(VariousCodes.config_found, language).format(config=config)
            message += get_string(VariousCodes.config_file_no_language, language)
            return config, language, message

    except ScriptWarning as e:
        # Reload config as a default one is saved on ScriptWarning
        config = load_config(config_file)
        message = get_string(VariousCodes.warning, language).format(message=e.message(language))
        message += get_string(VariousCodes.config_file_no_language, language)
        return config, language, message

    except ScriptError as e:
        config = {}
        message = get_string(VariousCodes.error, language).format(message=e.message(language))
        message += get_string(VariousCodes.config_file_no_language, language)
        return config, language, message


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

        # Retrieve config, config message is handled when console is instantiated
        self.config, self.language, config_message = retrieve_config(self.config_file)

        x_pos = 1
        y_pos = 1

        # Apikey widgets
        apikey_label = tk.Label(self, anchor="w", fg="black", text=get_string(VariousCodes.apikey, self.language))
        apikey_label.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(6), height=r_to_y(2))
        x_pos += 6 + 1

        self.apikey_string = tk.StringVar()
        self.apikey_entry = tk.Entry(self, textvariable=self.apikey_string)
        self.apikey_entry.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(38), height=r_to_y(2))
        x_pos += 38 + 1

        apikey_save_button = tk.Button(self, text=get_string(VariousCodes.save, self.language), command=self.apikey_save_OnButtonClick)
        apikey_save_button.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(11), height=r_to_y(2))
        x_pos = 1
        y_pos += 2 + 1

        # Input file widgets
        apikey_label = tk.Label(self, anchor="w", fg="black", text=get_string(VariousCodes.input_file, self.language))
        apikey_label.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(6), height=r_to_y(2))
        x_pos += 6 + 1

        self.input_file_string = tk.StringVar()
        self.input_file_string.set(get_string(VariousCodes.no_file, self.language))
        input_file_label = tk.Label(self, textvariable=self.input_file_string,
                                    anchor="w", bg="white", fg="black")
        input_file_label.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(38), height=r_to_y(2))
        x_pos += 38 + 1

        self.file_dialog_button = tk.Button(self, text=get_string(VariousCodes.choose_file, self.language), command=self.file_dialog_OnButtonClick)
        self.file_dialog_button.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(11), height=r_to_y(2))
        x_pos = 1
        y_pos += 2 + 1

        # Save dir widget
        self.save_in_dir = tk.BooleanVar()
        dir_button = tk.Checkbutton(self, text=get_string(VariousCodes.save_in_dir, self.language), variable=self.save_in_dir,
                                    onvalue=True, offvalue=False, command=self.save_in_dir_OnToggle)
        dir_button.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(20), height=r_to_y(2))
        x_pos += 20 + 5

        # Language widget
        language_label = tk.Label(self, anchor="w", fg="black", text=get_string(VariousCodes.language, self.language))
        language_label.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(8), height=r_to_y(2))
        x_pos += 8 + 1

        self.language_object = tk.StringVar()
        # Only set radio button if the language was defined from the config
        if "language" in self.config.keys():
            self.language_object.set(self.language)
        language_en = tk.Radiobutton(self, text="EN", variable=self.language_object, value="en", command=self.lang_OnChange)
        language_en.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(5), height=r_to_y(2))
        x_pos += 5 + 1
        language_fr = tk.Radiobutton(self, text="FR", variable=self.language_object, value="fr", command=self.lang_OnChange)
        language_fr.place(x=c_to_x(x_pos), y=r_to_y(y_pos), width=c_to_x(5), height=r_to_y(2))
        x_pos += 5 + 1

        x_pos = 1
        y_pos += 2 + 1

        # Run widget
        run_button = tk.Button(self, text=get_string(VariousCodes.run_vt_scan, self.language), command=self.run_OnButtonClick)
        run_button.place(x=(app_w - c_to_x(15)) / 2, y=r_to_y(y_pos), width=c_to_x(15), height=r_to_y(2))
        y_pos += 2 + 1

        self.console = scrolledtext.ScrolledText(undo=True)
        self.console.place(x=0, y=r_to_y(y_pos), width=app_w, height=app_h - r_to_y(y_pos))

        # Load config
        self.console.insert(tk.END, get_string(VariousCodes.config_load, self.language))
        self.console.insert(tk.END, config_message)
        self.console.see(tk.END)
        self.apikey_string.set(self.config.get("apikey", ""))
        self.save_in_dir.set(self.config.get("save_in_dir", False))

        self.resizable(False, False)

    def apikey_save_OnButtonClick(self):
        try:
            self.config["apikey"] = retrieve_apikey({"apikey": self.apikey_entry.get()})
            self.apikey_string.set(self.config["apikey"])
            save_config(self.config, self.config_file)
            self.console.insert(tk.END, get_string(VariousCodes.config_save, self.language).format(property="apikey"))
            self.console.see(tk.END)
        except ScriptWarning as e:
            self.console.insert(tk.END, get_string(VariousCodes.warning, self.language).format(message=e.message(self.language)))
            self.console.see(tk.END)
            self.apikey_entry.focus_set()

    def save_in_dir_OnToggle(self):
        self.config["save_in_dir"] = self.save_in_dir.get()
        save_config(self.config, self.config_file)
        self.console.insert(tk.END, get_string(VariousCodes.config_save, self.language).format(property="Save in dir"))
        self.console.see(tk.END)

    def lang_OnChange(self):
        self.config["language"] = self.language_object.get()
        self.language = self.language_object.get()
        save_config(self.config, self.config_file)
        self.console.insert(tk.END, get_string(VariousCodes.config_save, self.language).format(property="Language"))
        self.console.see(tk.END)

    def file_dialog_OnButtonClick(self):
        input_file = filedialog.askopenfile(title='Input file')
        if input_file:
            self.input_file_string.set(input_file.name)
            report_content = get_report_content(self.input_file_string.get())
            line_list = report_content.split("\n")
            self.file_type = get_file_type(line_list[0])
            self.md5s_dict = find_md5_in_file(report_content, self.file_type)
            self.console.insert(tk.END, get_string(VariousCodes.file_opening, self.language).format(file=input_file.name))
            self.console.insert(tk.END, get_string(VariousCodes.file_type, self.language).format(type=self.file_type))
            self.console.insert(tk.END, get_string(VariousCodes.file_md5s_nb, self.language).format(nb_md5s=len(self.md5s_dict.keys())))
            self.console.see(tk.END)

    def run_OnButtonClick(self):
        try:
            if len(self.md5s_dict.keys()) > 0:
                self.results = run_vt_analyse(self.md5s_dict, retrieve_apikey(self.config), self.language)

                output_file = get_output_file(self.config, self.input_file_string.get())

                # Create the output log
                save_results(output_file, self.input_file_string.get(), self.file_type, self.md5s_dict, self.results, self.language)

                # Open the log
                self.console.insert(tk.END, get_string(VariousCodes.scan_complete, self.language))
                self.console.see(tk.END)
                webopen(output_file)
            else:
                self.file_dialog_button.focus_set()
                raise ScriptWarning(ErrorsCodes.input_file_no_md5)

        except ScriptWarning as e:
            self.console.insert(tk.END, get_string(VariousCodes.warning, self.language).format(message=e.message(self.language)))
            self.console.see(tk.END)

        except ScriptError as e:
            self.console.insert(tk.END, get_string(VariousCodes.error, self.language).format(message=e.message(self.language)))
            self.console.see(tk.END)


if __name__ == "__main__":
    app = simpleapp_tk(None)
    app.title('VT Scan GUI - version {version}'.format(version=VERSION))
    app.mainloop()
