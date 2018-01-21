# VT_script

**Author:**Xavier Chapron

## About
VT_script is a simple python script using VirusTotal public API to analyse file using their md5.

You can find some usefull information about VirusTotal public API here: https://www.virustotal.com/en/documentation/public-api/

While this script has been created to work on a Linux distribution or on Windows, it should also work on Mac Os X.

## Install

1. For Linux:
    Either clone the git repository, or download the zip file.
    Be sure that vt_scan.py is set as an executable file or use:

        chmod +x vt_scan.py

    You will need a VirusTotal public API key, that can be obtained on VirusTotal website if you create an account.
    You need to set it in apikey.txt file.

2. For Windows:
    1. You can use it exactly as on Linux.
    2. Or you can download vt_scan.exe and vt_scan.reg.
        * Place the executable where you want it to stay.
        * Execute vt_scan.reg to create a registry key and open regedit to edit them:
            * Go to HKEY_CLASSES_ROOT\txtfile\shell\VT_Scan\command and edit the value to add the path to the executable and to your apikey file.

## Usage

1. For Linux:
    1. Use ./vt_scan.py -h to see the help.

    2. Use -f option to choose the file you want to scan, the default is the input.txt file in the current folder.

    3. Use -k option to specify the path to your VirusTotal API key file, or the script will use the value 'apikey.txt'

2. For Windows:
    1. You can use it exactly as on Linux.
    2. You can place in the same folder the executable, the input file name input.txt, the apikey file name apikey.txt.
        Then you can just execute vt_scan.exe
    3. If you have create the registry key, you can right click on any text file and choose "Analyse with VT_Scan"

In any case, at the end of the scan, a web page should be open with all the results.
