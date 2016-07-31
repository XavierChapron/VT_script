#!/usr/bin/env python
# -*- coding: utf-8 -*-

from json import loads
from urllib import urlencode
from urllib2 import Request, urlopen, HTTPError
from time import sleep
from re import search
from os import system
from optparse import OptionParser

# Set your VT public API Key here
apikey = ""

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

if not options.path_to_file:
    parser.error('you must use "-f file_to_path"')


if not options.apikey:
    if not apikey:
        parser.error('you must set an apikey, either in command line or in vt_scan.py line 13')
else:
    # We want to use by default the apikey from command line
    apikey = options.apikey


def get_file_type(first_line):
    "Search on the first_line to find some keyword helping identifying the file type"
    if "ZHPDiag" in first_line:
        return "ZHPDiag"
    if "OTL" in first_line:
        return "OTL"
    if "FRST" in first_line:
        return "FRST"
    return "RAW"


def search_on_vt(md5s):
    "Create a VT API request and return the answer"
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": md5s, "apikey": apikey}
    data = urlencode(parameters)
    req = Request(url, data)
    response = urlopen(req)
    return loads(response.read())


def run_vt_analyse(md5s_list):
    # Format the md5s_list for the request
    md5_request = ""
    for md5 in md5s_list:
        md5_request = md5_request + md5[0] + ", "
    md5_request = md5_request[:-2]

    # Get the request answer
    answer_list = None
    while answer_list is None:
        try:
            answer_list = search_on_vt(md5_request)
        except ValueError:
            answer_list = None
            print("### Error, VT refuse to answer, the script will retry in 30sec.")
            sleep(30)
        except HTTPError:
            print("Your apikey %s seem to be refuse by VirusTotal." % apikey)
            exit()

    # Analyse the answer
    if len(md5s_list) == 1:
        analyse_answer(answer_list, md5s_list)
    else:
        for answer in answer_list:
            analyse_answer(answer, md5s_list)


def analyse_answer(answer, md5s_list):
    # Check if VT have found the associate the file
    if answer.get("response_code", 0) == 0:
        md5 = answer.get("resource", "error")
        filename = get_filename_for_md5(md5, md5s_list)
        print("VirusTotal seems to not know file: %s with md5:%s." % (filename, md5))

    else:
        # Print answer
        md5 = answer.get(u"md5", None).lower()
        filename = get_filename_for_md5(md5, md5s_list)
        positives = answer.get("positives", None)
        total = answer.get("total", None)
        url = "https://www.virustotal.com/latest-scan/" + md5
        print("%s/%s for %s, more info at %s" % (positives, total, filename, url))


def get_filename_for_md5(md5, md5s_list):
    "Find the associate filename to a md5"
    for element in md5s_list:
        if element[0].lower() == md5.lower():
            return element[1]
    raise ValueError


def find_md5_in_file(path_to_file):
    "Find all md5 and the name of the associated file"
    md5s_dict = {}
    md5s_list = []
    with open(path_to_file, 'r') as f:
        for line in f:

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
    # Tell the user which API key will be used
    print("The script will use VT API key: %s" % apikey)

    # Change encoding with Vim if -v option used
    if options.vim:
        err = system("vim '+set fileencoding=utf-8' '+wq' %s" % options.path_to_file)
        if err != 0:
            print("There is an error while using Vim to force the file encoding to utf-8.")
        else:
            print("Vim successfully chnages the file encoding to utf-8.")

    # Detect the logFile type
    with open(options.path_to_file, 'r') as f:
        file_type = get_file_type(f.readline())
        print("The input file is detected as a %s log." % file_type)

    # Find the md5s in the file
    md5s_list = find_md5_in_file(options.path_to_file)
    if len(md5s_list) == 0:
        print(
          "Found 0 md5 in %s, if there is md5, you should consider using the -v option or convert the log file encoding to 'utf-8'."
          % options.path_to_file
        )
        exit()
    print("Found %s different md5s in %s." % (len(md5s_list), options.path_to_file))
    print("The analysis should take about %s min." % int(len(md5s_list) / 16 + 1))

    # Search on VT for each md5 by group of 4
    while len(md5s_list) >= 4:
        run_vt_analyse(md5s_list[0:4])
        md5s_list = md5s_list[4:]

        # The VirusTotal public API allow 4 request each minute,
        # therefore we should wait 15sec between each request.
        sleep(15)
    run_vt_analyse(md5s_list)

    print("### End of analysis.")

run(options)
