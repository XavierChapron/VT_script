#!/usr/bin/env python
# -*- coding: utf-8 -*-

from json import loads
from urllib import urlencode
from urllib2 import Request, urlopen, HTTPError, URLError
from time import sleep
from re import search
from os import system
from optparse import OptionParser
from os.path import join
from tempfile import gettempdir
from webbrowser import open as webopen


parser = OptionParser("usage: %prog -f path_to_file [options]")
parser.add_option("-f", "--file",
                  help="file to use",
                  action="store", default=None,
                  dest="path_to_file")
parser.add_option("-v", "--vim",
                  help="use to change encoding with Vim",
                  action="store_true", default=False,
                  dest="vim")
parser.add_option("-k", "--key",
                  help="use to set your VT api key",
                  action="store", default='',
                  dest="apikey")

(options, args) = parser.parse_args()


def get_file_type(first_line):
    "Search on the first_line to find some keyword helping identifying the file type"
    if "ZHPDiag" in first_line:
        return "ZHPDiag"
    if "OTL" in first_line:
        return "OTL"
    if "FRST" in first_line:
        return "FRST"
    return "RAW"


def search_on_vt(md5s, apikey):
    "Create a VT API request and return the answer"
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": md5s, "apikey": apikey}
    data = urlencode(parameters)
    req = Request(url, data)
    response = urlopen(req)
    return loads(response.read())


def run_vt_analyse(md5s_list, apikey, results, log_path):
    # Format the md5s_list for the request
    md5_request = ""
    for md5 in md5s_list:
        md5_request = md5_request + md5[0] + ", "
    md5_request = md5_request[:-2]

    # Get the request answer
    answer_list = None
    while answer_list is None:
        try:
            answer_list = search_on_vt(md5_request, apikey)
        except ValueError:
            answer_list = None
            print("### Error, VT refuse to answer, the script will retry in 10sec.")
            sleep(10)
        except HTTPError:
            print("Your apikey %s seem to be refuse by VirusTotal." % apikey)
            system("echo %s > %s" % (("Your apikey %s seem to be refuse by VirusTotal." % apikey), log_path))
            exit()
        except URLError:
            print("You should check your internet connexion")
            system("echo %s > %s" % ("You should check your internet connexion", log_path))
            exit()
        except URLError:
            print("You should check your Internet connexion")
            exit()

    # Analyse the answer
    if len(md5s_list) == 1:
        analyse_answer(answer_list, md5s_list, results)
    else:
        for answer in answer_list:
            analyse_answer(answer, md5s_list, results)


def analyse_answer(answer, md5s_list, results):
    # Check if VT have found the associate the file
    if answer.get("response_code", 0) == 0:
        md5 = answer.get("resource", "error")
        filename = get_filename_for_md5(md5, md5s_list)
        results["unknows"].append((filename, md5))

    else:
        # store the answer
        md5 = answer.get(u"md5", None).lower()
        filename = get_filename_for_md5(md5, md5s_list)
        positives = answer.get("positives", None)
        total = answer.get("total", None)
        url = "https://www.virustotal.com/latest-scan/" + md5
        result = (positives, total, url, filename)
        if positives:
            results["positives"].append(result)
        else:
            results["negatives"].append(result)


def get_filename_for_md5(md5, md5s_list):
    "Find the associate filename to a md5"
    for element in md5s_list:
        if element[0].lower() == md5.lower():
            return element[1]
    raise ValueError


def find_md5_in_file(path_to_file, file_type):
    "Find all md5 and the name of the associated file"
    md5s_dict = {}
    md5s_list = []
    with open(path_to_file, 'r') as f:
        for line in f:

            if file_type == "ZHPDiag":
                search_md5 = search('MD5.(' + r'[0-9a-fA-F]' * 32 + ')', line)
                if not search_md5:
                    continue
                md5 = search_md5.group(0).replace("MD5.", "")
            else:
                # Parse the line to find if there is a 32 hex number
                search_md5 = search('(' + r'[0-9a-fA-F]' * 32 + ')', line)
                if not search_md5:
                    continue
                md5 = search_md5.group(0)

            # Little hack to exclude CLSIDs
            md5_index = line.index(md5)
            if md5_index > 0 and line[md5_index - 1] == "{":
                continue

            md5 = md5.lower()

            if md5s_dict.get(md5, False):
                # We doesn't want to search multiples times for the same md5
                continue
            md5s_dict[md5] = True

            # Parse the line to find if there is a filename with format (roughly) \anything.anything
            search_filename = search(r'\\([\w\-\s]+\.\w+)', line)
            if search_filename:
                md5s_list.append((md5, search_filename.group(0)[1:]))
            else:
                md5s_list.append((md5, "'no filename'"))
    return md5s_list


def run(options):

    # Set your VT public API Key here
    apikey = ""

    # Full path to the output log
    log_path = join(gettempdir(), "vt_scan.html")

    # Get the input file
    if not options.path_to_file:
        try:
            with open("input.txt", 'r') as f:
                if f.readline():
                    path_to_file = "input.txt"
        except IOError:
            print('you must use an input file, save it as input.txt or use -f option in command line')
            system("echo %s > %s" % ('you must use an input file, save it as input.txt or use -f option in command line', log_path))
            exit()
    else:
        # We want to use by default the input file from command line
        path_to_file = options.path_to_file.replace("\n","")

    # Get the apikey
    if not options.apikey:
        if not apikey:
            try:
                with open("apikey.txt", 'r') as f:
                    apikey = f.readline().replace("\n", "").replace(" ", "").replace("\r", "")
                if not apikey:
                    print('you must use an apikey, set it in apikey.txt or use -k option in command line')
                    system("echo %s > %s" % ('you must use an apikey, set it in apikey.txt or use -k option in command line', log_path))
                    exit()
            except IOError:
                print('you must use an apikey, set it in apikey.txt or use -k option in command line')
                system("echo %s > %s" % ('you must use an apikey, set it in apikey.txt or use -k option in command line', log_path))
                exit()
    else:
        # We want to use by default the apikey from command line
        apikey = options.apikey

    # Change encoding with Vim if -v option used
    # Not working easily on Windows
    if options.vim:
        err = system("vim '+set fileencoding=utf-8' '+wq' %s" % path_to_file)
        if err != 0:
            print("There is an error while using Vim to force the file encoding to utf-8.")
            vim_success = False
        else:
            print("Vim successfully changes the file encoding to utf-8.")
            vim_success = True

    # Tell the user which API key will be used
    print("The script will use VT API key: '%s'" % apikey)

    # Remove issues with \n at the end of the filename
    print("The input file is %s" % path_to_file)

    # Detect the logFile type
    with open(path_to_file, 'r') as f:
        file_type = get_file_type(f.readline())
        print("The input file is detected as a %s log." % file_type)

    # Find the md5s in the file
    md5s_list = find_md5_in_file(path_to_file, file_type)
    if len(md5s_list) == 0:
        print(
          "Found 0 md5 in %s, if there is md5, convert the log file encoding to 'utf-8'."
          % path_to_file
        )
        system("echo %s > %s" % (("Found 0 md5 in %s, if there is md5, convert the log file encoding to 'utf-8'."
          % path_to_file), log_path))
        exit()
    print("Found %s different md5s in %s." % (len(md5s_list), path_to_file))

    # Search on VT for each md5 and store the results
    results = {"unknows": [], "negatives": [], "positives": []}
    run_vt_analyse(md5s_list, apikey, results, log_path)

    # Create the output log
    with open(log_path, 'w') as f:
        f.write("<h2>VT_Scan by Chapi:</h2></br>")
        f.write("The script will use VT API key: %s</br>" % apikey)
        f.write("The input file is <b>%s</b></br>" % path_to_file)
        if options.vim:
            if vim_success:
                f.write("Vim successfully changes the file encoding to utf-8.")
            else:
                f.write("There is an error while using Vim to force the file encoding to utf-8.")
        f.write("The input file is detected as a <b>%s</b> log.</br>" % file_type)
        f.write("Found <b>%s different md5s</b> in %s.</br>" % (len(md5s_list), path_to_file))

        f.write("<h4></br>VirusTotal nonzero detections (%s)</br></h4>" % len(results["positives"]))
        for result in results["positives"]:
            f.write('%s/%s for <a href=%s target="_blank">%s</a></br>' % result)

        f.write("<h4></br>VirusTotal unknown files (%s)</br></h4>" % len(results["unknows"]))
        for result in results["unknows"]:
            f.write("%s with md5:%s.</br>" % result)

        f.write("<h4></br>VirusTotal negative results (%s)</br></h4>" % len(results["negatives"]))
        for result in results["negatives"]:
            f.write('%s/%s for <a href=%s target="_blank">%s</a></br>' % result)

        f.write("</br></br>End of analysis.")

    print("### End of analysis.")

    # Open the log
    webopen(log_path)

run(options)
