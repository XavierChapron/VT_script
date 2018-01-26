#!/usr/bin/env python3

from json import loads
from urllib.parse import urlencode
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
from time import sleep
from re import search
from optparse import OptionParser
from os.path import join
from tempfile import gettempdir
from webbrowser import open as webopen


# Full path to the output log
log_path = join(gettempdir(), "vt_scan.html")

parser = OptionParser("usage: %prog -f path_to_file [options]")
parser.add_option("-f", "--file",
                  help="file to use",
                  action="store", default="input.txt",
                  dest="path_to_file")
parser.add_option("-k", "--key",
                  help="path to VT api key file",
                  action="store", default='apikey.txt',
                  dest="path_to_apikey")

(options, args) = parser.parse_args()


class ScriptError(Exception):
    def __init__(self, message):
        self.message = message


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
    data = data.encode('ascii')
    response = urlopen(url, data)
    return loads(response.read().decode('utf-8'))


def run_vt_analyse(md5s_list, apikey, results):
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
            raise ScriptError("### Error, VT refuses to answer, the script will retry in 10sec.")
            sleep(10)
        except HTTPError:
            raise ScriptError("Your apikey '%s' seems to be refused by VirusTotal." % apikey)
        except URLError:
            raise ScriptError("You should check your internet connection")

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
        result = (positives, total, url, filename, md5)
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


def find_md5_in_file(line_list, file_type):
    "Find all md5 and the name of the associated file"

    parsing_dict = {
        "ZHPDiag": ('MD5.' + r'[0-9a-fA-F]' * 32, "MD5.", r'\\[^\\\[]+\s\[', 1, -2),
        "OTL": ('MD5=' + r'[0-9a-fA-F]' * 32, "MD5=", r'\\[^\\]+$', 1, None),
        "FRST": ('\s' + r'[0-9a-fA-F]' * 32 + '\s*$', "", r'\\[^\\]+', 1, -33),
        "RAW": (r'[0-9a-fA-F]' * 32, "", r'\\[\w\-\s]+\.\w+', 1, None)
    }
    md5s_dict = {}
    md5s_list = []

    for line in line_list:
        filename = "'no filename'"
        parsing_tupple = parsing_dict.get(file_type, parsing_dict["RAW"])

        # Get md5 if md5
        search_md5 = search(parsing_tupple[0], line)
        if not search_md5:
            continue
        md5 = search_md5.group(0).replace(parsing_tupple[1], "")

        # Get filename if filename
        if file_type == "FRST":
            search_filename = search(parsing_tupple[2] + md5, line)
        else:
            search_filename = search(parsing_tupple[2], line)
        if search_filename:
            filename = search_filename.group(0)[parsing_tupple[3]:parsing_tupple[4]]

        # Format md5 and filename
        md5 = md5.lower().strip()
        filename = filename.replace("\n", "").replace("\r", "")

        # Remove already existing md5
        if md5s_dict.get(md5, False):
            continue

        # Add md5 and filename to the queue
        md5s_dict[md5] = True
        md5s_list.append((md5, filename))
    return md5s_list


def get_apikey(path_to_apikey, log_path):
    try:
        with open(path_to_apikey, 'r') as f:
            apikey = f.readline().strip()
    except IOError:
        raise ScriptError("Can't open: '%s', you must set an apikey file" % path_to_apikey)
    return apikey


def get_report_lines(path_to_file):
    # Handle issues with files encoding
    # OTL logs files comes formatted in utf-16-le encoding...
    try:
        with open(path_to_file, 'r') as f:
            content = f.read()
            if "\\x0" in repr(content):
                with open(path_to_file, 'r', encoding='utf-16-le') as f:
                    content = f.read()
    except UnicodeDecodeError:
        with open(path_to_file, 'r', encoding='utf-16-le') as f:
            content = f.read()
    except:
        raise ScriptError("Error while opening file: %s" % path_to_file)

    return content.split("\n")


def save_results(output_file, input_file, input_type, number_of_md5, results):
    with open(output_file, 'w') as f:
        f.write('<meta charset="UTF-8">\n')
        f.write('<style>\ntable, th, td {\n    border: 1px solid black;\n    border-collapse: collapse;\n}\nth, td {\n    padding: 5px;\n}\n</style>\n')

        f.write("<h2>VT_Scan by Chapi:</h2></br>\n")
        f.write("The input file is <b>%s</b></br>\n" % input_file)
        f.write("The input file is detected as a <b>%s</b> log.</br>\n" % input_type)
        f.write("Found <b>%s different md5s</b>.</br>\n" % number_of_md5)

        f.write("<h4></br>VirusTotal nonzero detections (%s)</br></h4>\n" % len(results["positives"]))
        f.write(' <table>\n  <tr>\n    <th>Result</th>\n    <th>Filename</th>\n    <th>MD5</th>\n  </tr>\n')
        for result in results["positives"]:
            f.write('<tr><td>%s/%s</td><td><a href=%s target="_blank">%s</a></td><td>%s</td></tr>\n' % result)
        f.write('</table>\n')

        f.write("<h4></br>VirusTotal unknown files (%s)</br></h4>\n" % len(results["unknows"]))
        f.write(' <table>\n  <tr>\n    <th>Filename</th>\n    <th>MD5</th>\n  </tr>\n')
        for result in results["unknows"]:
            f.write("<tr><td>%s</td><td>%s</td></tr>\n" % result)
        f.write('</table>\n')

        f.write("<h4></br>VirusTotal negative results (%s)</br></h4>\n" % len(results["negatives"]))
        f.write(' <table>\n  <tr>\n    <th>Result</th>\n    <th>Filename</th>\n    <th>MD5</th>\n  </tr>\n')
        for result in results["negatives"]:
            f.write('<tr><td>%s/%s</td><td><a href=%s target="_blank">%s</a></td><td>%s</td></tr>\n' % result)
        f.write('</table>\n')

        f.write("</br></br>\nEnd of analysis.")


def main(options):
    # Get the files paths
    input_file = options.path_to_file.strip()
    apikey_file = options.path_to_apikey.strip()
    output_file = log_path

    try:
        print("The input file is %s" % input_file)

        # Get the apikeys
        apikey = get_apikey(apikey_file, output_file)

        # Get the report lines
        line_list = get_report_lines(input_file)

        # Detect the logFile type
        file_type = get_file_type(line_list[0])
        print("The input file is detected as a %s log." % file_type)

        # Find the md5s in the file
        md5s_list = find_md5_in_file(line_list, file_type)
        md5_number = len(md5s_list)
        if md5_number == 0:
            print("Found 0 md5 in %s" % input_file)
            with open(output_file, 'w') as f:
                f.write("<h2>VT_Scan by Chapi:</h2></br>")
                f.write("Found <b>0 different md5s</b> in %s.</br>" % input_file)

        else:
            print("Found %s different md5s in %s." % (md5_number, input_file))

            # Search on VT for each md5 and store the results
            results = {"unknows": [], "negatives": [], "positives": []}
            run_vt_analyse(md5s_list, apikey, results)

            # Create the output log
            save_results(output_file, input_file, file_type, md5_number, results)

        print("### End of analysis.")

    except ScriptError as e:
        print("Catch an error:")
        print(e.message)
        with open(log_path, 'w') as f:
            f.write('<meta charset="UTF-8">\n')
            f.write(e.message)

    # Open the log
    webopen(log_path)


if __name__ == '__main__':
    main(options)
