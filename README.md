# VT_script

**Author:**Xavier Chapron

## About
VT_script is a simple python script using VirusTotal public API to analyse file using their md5.

You can find some usefull information about VirusTotal public API here: https://www.virustotal.com/en/documentation/public-api/

While this script has been created to work on a Linux distribution, it has already been successfully test on Windows and should also work on Mac Os X.

## Install

Either clone the git repository, or download the zip file.
Be sure that vt_scan.py is set as an executable file or use::

    chmod +x vt_scan.py

You will need a VirusTotal public API key, that can be obtained on VirusTotal website if you create an account.
You can either write your API key directly in vt_scan.py line 13, or give it to the script with option -k.

You might consider to install Vim that is usefull in some case (see Usage)

## Usage

1. Use ./vt_scan.py -h to see the help::

        $ ./vt_scan.py -h
        Usage: vt_scan.py -f path_to_file [options]

        Options:
          -h, --help            show this help message and exit
          -f PATH_TO_FILE, --file=PATH_TO_FILE
                                file to use
          -v, --vim             use to change encoding with Vim
          -k APIKEY, --key=APIKEY
                                use to set your VT api key

2. Use -f option to choose the file you want to scan::

        $ ./vt_scan.py -f logs/ZHPDiag.txt
        The input file is detected as a ZHPDiag log
        Found 31 different md5s in logs/ZHPDiag.txt
        The analysis should take about 2 min
        [...]

3. Use -v option to use Vim to change encoding to utf-8.
    That is not necessary in most of the case, but it is with OTL file that have an encoding that I don't know by default.
    If you don't want to use Vim or just to install it, you can change the encoding of your log file with any other tool of your choice.

    Here is an example of it's use::
        $ ./vt_scan.py -f logs/OTL.Txt -v
        Vim successfully chnages the file encoding to utf-8.
        The input file is detected as a OTL log.
        Found 6 different md5s in logs/OTL.Txt.
        The analysis should take about 1 min.

4. Use -k option to use the specify your VirusTotal API key::

        $ ./vt_scan.py -f logs/OTL.Txt -k your_api_key_here
        The input file is detected as a OTL log.
        Found 6 different md5s in logs/OTL.Txt.
        The analysis should take about 1 min.
        Your apikey your_api_key_here seem to be refuse by VirusTotal.
