# VT_script

**Author:** Xavier Chapron

## About
VT_script is composed of:
* A simple Python3 script using VirusTotal public API to analyse files using theirs md5sum.
* A GUI Python3 script to improve user experience, expecially on Windows.

You can find some usefull information about VirusTotal public API here: https://www.virustotal.com/en/documentation/public-api/

While theses scripts have been created to work on a Linux distribution or on Windows, they should also work on Mac Os X.

## Install

1. For Linux:
    Either clone the git repository, or download the zip file.
    Make sure that vt_scan.py and vt_scan_gui.py are set as executable file or use:

        chmod +x vt_scan.py
        chmod +x vt_scan_gui.py

2. For Windows:
    1. You can use it exactly as on Linux.
    2. Or you can download vt_scan.exe and vt_scan.reg.
        * Place the executable where you want them to stay.
        * Execute vt_scan.reg to create a registry key and open regedit to edit them:
        * Go to HKEY_CLASSES_ROOT\txtfile\shell\VT_Scan\command and edit the value to add the path to the executable.

3. For Both:
    You will need a VirusTotal public API key, that can be obtained on VirusTotal website if you create an account.
    You need to set this API key in vt_scan_config.txt file. To do that you can:
    * Edit manually the vt_scan_config.txt file, it must comply with JSON format.
    * Launch vt_scan_gui.py or vt_scan_gui.exe, enter you apikey in the corresponding input field and click on the "Save" button.

## Usage

1. For Linux:
    1. Use ./vt_scan_guy.py and follow the gui inner console recommendations.
    2. Use ./vt_scan.py with -h option to see the help.
    3. Use ./vt_scan.py with -f option to choose the file you want to scan.

2. For Windows:
    1. You can use it on a terminal simarly as on Linux.
    2. You can execute vt_scan_gui.exe and follow inner console recommendations.
    3. If you have created the registry key, you can right click on any text file and choose "Analyse with VT_Scan"

In any case, at the end of the scan, a web page should open with all the results.
