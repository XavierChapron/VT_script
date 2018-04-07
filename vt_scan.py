#!/usr/bin/env python3

from json import loads
from urllib.parse import urlencode
from urllib.request import urlopen
from urllib.error import HTTPError, URLError
from time import sleep
from re import search, findall, DOTALL
from optparse import OptionParser
from os.path import join, dirname, abspath, basename, expanduser
from tempfile import gettempdir
from webbrowser import open as webopen
import json
import codecs
import sys
from vt_scan_constants import ErrorsCodes, ErrorsStrings, VariousCodes, config_file_name, default_config, VariousStrings
from locale import getdefaultlocale
from collections import OrderedDict

VERSION = "1.0.4"

BOM_UTF32_BE, BOM_UTF32_LE, BOM_UTF8, BOM_UTF16_BE, BOM_UTF16_LE, DEFAULT = range(6)
codec_bom = {
    BOM_UTF32_BE: codecs.BOM_UTF32_BE,
    BOM_UTF32_LE: codecs.BOM_UTF32_LE,
    BOM_UTF16_BE: codecs.BOM_UTF16_BE,
    BOM_UTF8: codecs.BOM_UTF8,
    BOM_UTF16_LE: codecs.BOM_UTF16_LE,
    DEFAULT: b''
}
codec_decoder = {
    BOM_UTF32_BE: 'utf_32_be',
    BOM_UTF32_LE: 'utf_32_le',
    BOM_UTF16_BE: 'utf_16_be',
    BOM_UTF8: 'utf_8',
    BOM_UTF16_LE: 'utf_16_le',
    DEFAULT: 'utf8'
}


def get_string(string_code, lang):
    return VariousStrings[lang][string_code]


class ScriptError(Exception):
    def __init__(self, code, parameters={}):
        self.code = code
        self.parameters = parameters

    def message(self, lang):
        return ErrorsStrings[lang][self.code].format(**self.parameters)


class ScriptWarning(Exception):
    def __init__(self, code, parameters={}):
        self.code = code
        self.parameters = parameters

    def message(self, lang):
        return ErrorsStrings[lang][self.code].format(**self.parameters)


def get_language_from_locale():
    if getdefaultlocale()[0] == "fr_FR":
        return 'fr'
    else:
        return 'en'


def load_config(config_file):
    config = default_config
    try:
        with open(config_file, "r") as f:
            config = json.load(f)

        if config.get('language', 'en') not in ["en", "fr"]:
            raise ScriptError(ErrorsCodes.config_file_bad_language, {"lang": config.get('language', 'en')})

    except json.JSONDecodeError:
        raise ScriptError(ErrorsCodes.config_file_corrupted, {"file": config_file})

    except FileNotFoundError:
        save_config(config, config_file)
        raise ScriptWarning(ErrorsCodes.config_file_none, {"file": config_file})

    return config


def save_config(config, config_file):
    with open(config_file, "w") as f:
        json.dump(config, f)


def get_output_file(config, input_file):
    input_file_name = basename(input_file).split(".")[0]
    input_file_dir = dirname(abspath(expanduser(input_file)))
    output_file_name = input_file_name + "_vt_scan.html"
    if config.get("save_in_dir", False):
        return join(input_file_dir, output_file_name)
    else:
        return join(gettempdir(), output_file_name)


def retrieve_apikey(config):
    try:
        apikey = config["apikey"]
    except KeyError:
        raise ScriptWarning(ErrorsCodes.apikey_invalid_none)

    if apikey == default_config["apikey"]:
        raise ScriptWarning(ErrorsCodes.apikey_invalid_default, {'apikey': apikey})

    for char in apikey.lower():
        if char not in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]:
            raise ScriptWarning(ErrorsCodes.apikey_invalid_char, {'apikey': apikey, 'char': char})

    if len(apikey) != 64:
        raise ScriptWarning(ErrorsCodes.apikey_invalid_lenght, {'apikey': apikey, 'lenght': len(apikey)})

    return apikey


def get_file_type(first_line):
    "Search on the first_line to find some keyword helping identifying the file type"

    if "ZHPDiag" in first_line:
        return "ZHPDiag"
    if "OTL" in first_line:
        return "OTL"
    if "SEAF" in first_line:
        return "SEAF"
    if "Farbar Recovery Scan Tool" in first_line:
        if "FRST" in first_line:
            return "FRST"
        else:
            return "FRST - additional"

    return "RAW"


def search_on_vt(md5s, apikey):
    "Create a VT API request and return the answer"
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": md5s, "apikey": apikey}
    data = urlencode(parameters)
    data = data.encode('ascii')
    response = urlopen(url, data)
    return loads(response.read().decode('utf-8'))


def run_vt_analyse(md5s_dict, apikey, language):
    md5s_list = list(md5s_dict.keys())

    # Create a different request for each group of 4 md5s
    md5s_groups_list = []
    i = 0
    while i + 4 < len(md5s_list):
        md5s_groups_list.append(md5s_list[i: i + 4])
        i += 4
    md5s_groups_list.append(md5s_list[i:])

    results = {"unknows": OrderedDict(), "negatives": OrderedDict(), "positives": OrderedDict()}

    # For each group, create a request, retrieve VT answer, then analyse the answer
    for md5s_group in md5s_groups_list:

        # Format the md5s_group for the request
        md5_request = ""
        for md5 in md5s_group:
            md5_request = md5_request + md5 + ", "
        md5_request = md5_request[:-2]

        # Get the request answer
        answer_list = None
        while answer_list is None:
            try:
                answer_list = search_on_vt(md5_request, apikey)
            except ValueError:
                answer_list = None
                print(get_string(VariousCodes.waiting_vt, language))
                sleep(10)
            except HTTPError:
                raise ScriptError(ErrorsCodes.apikey_refused, {'apikey': apikey})
            except URLError:
                raise ScriptError(ErrorsCodes.no_internet_connexion)

        # Analyse the answer
        if len(md5s_group) == 1:
            analyse_answer(answer_list, md5s_group, results)
        else:
            for answer in answer_list:
                analyse_answer(answer, md5s_group, results)

    return results


def analyse_answer(answer, md5s_list, results):
    # Check if VT have found the associate the file
    if answer.get("response_code", 0) == 0:
        md5 = answer.get("resource", "error").upper()
        results["unknows"][md5] = {}

    else:
        # store the answer
        md5 = answer.get("md5", '').upper()
        positives = answer.get("positives", None)
        total = answer.get("total", None)
        url = "https://www.virustotal.com/latest-scan/" + md5
        result = {
                 'positives': positives,
                 'total': total,
                 'url': url
                 }
        if positives:
            results["positives"][md5] = result
        else:
            results["negatives"][md5] = result


def find_md5_in_file(report, file_type):
    "Find all md5 and the name, dir and size of the associated file"

    if file_type == "ZHPDiag":
        return find_md5_in_zhpdiag(report)

    if file_type == "OTL":
        return find_md5_in_otl(report)

    if file_type == "SEAF":
        return find_md5_in_seaf(report)

    if file_type == "FRST - additional":
        return find_md5_in_frst_additional(report)

    return find_md5_in_raw(report)


def find_md5_in_zhpdiag(report):
    md5s_dict = OrderedDict()

    regexp = r'\[MD5.([0-9a-fA-F]{32})\].*? -- (.*?) \[(.*?)\]'

    matches = findall(regexp, report)
    for match in matches:
        md5s_dict[match[0].upper()] = []

    for match in matches:
        file_name = match[1].split("\\")[-1]
        file_dir = match[1][: -(len(file_name) + 1)]
        md5s_dict[match[0].upper()].append({
                                      'file_name': file_name,
                                      'file_dir': file_dir,
                                      'file_size': match[2]
                                   })

    return md5s_dict


def find_md5_in_otl(report):
    md5s_dict = OrderedDict()

    regexp = r'\[[0-9][0-9][0-9][0-9]/.*? \| ([0-9,]*) \| .*?\].*?MD5=([0-9a-fA-F]{32}) -- (.*?)\n'

    matches = findall(regexp, report)
    for match in matches:
        md5s_dict[match[1].upper()] = []

    for match in matches:
        file_name = match[2].split("\\")[-1]
        file_dir = match[2][: -(len(file_name) + 1)]
        md5s_dict[match[1].upper()].append({
                                      'file_name': file_name,
                                      'file_dir': file_dir,
                                      'file_size': match[0]
                                   })
    return md5s_dict


def find_md5_in_frst_additional(report):
    md5s_dict = OrderedDict()

    regexp = r'(.*?)\n\[.*?\] ([0-9]*) _____ \(.*?\) ([0-9a-fA-F]{32}) \['

    matches = findall(regexp, report)
    for match in matches:
        md5s_dict[match[2].upper()] = []

    for match in matches:
        file_name = match[0].split("\\")[-1]
        file_dir = match[0][: -(len(file_name) + 1)]
        md5s_dict[match[2].upper()].append({
                                      'file_name': file_name,
                                      'file_dir': file_dir,
                                      'file_size': match[1]
                                   })
    return md5s_dict


def find_md5_in_seaf(report):
    md5s_dict = OrderedDict()

    regexp = r'[0-9]*\. "(.*?)" \[.*?\| (.*?) ].*?Hash MD5: ([0-9a-fA-F]{32})'

    matches = findall(regexp, report, DOTALL)

    for match in matches:
        md5s_dict[match[2].upper()] = []

    for match in matches:
        file_name = match[0].split("\\")[-1]
        file_dir = match[0][: -(len(file_name) + 1)]
        md5s_dict[match[2].upper()].append({
                                      'file_name': file_name,
                                      'file_dir': file_dir,
                                      'file_size': match[1]
                                   })
    return md5s_dict


def find_md5_in_raw(report):
    md5s_dict = OrderedDict()
    matches = []

    for line in report.split("\n"):
        search_md5 = search(r'[0-9a-fA-F]{32}', line)
        if not search_md5:
            continue
        md5 = search_md5.group(0)

        search_file = search(r'.*[\w\-\s]+\.\w+', line)
        file = ''
        if search_file:
            file = search_file.group(0)

        matches.append((md5, file))

    for match in matches:
        md5s_dict[match[0].upper()] = []

    for match in matches:
        file_name = match[1].split("\\")[-1]
        file_dir = match[1][: -(len(file_name) + 1)]
        md5s_dict[match[0].upper()].append({
                                      'file_name': file_name,
                                      'file_dir': file_dir,
                                      'file_size' : ''
                                   })
    return md5s_dict


def get_report_content(path_to_file):
    try:
        with open(path_to_file, 'rb') as f:
            b_content = f.read()
    except FileNotFoundError:
        raise ScriptError(ErrorsCodes.input_file_not_found, {'file': path_to_file})

    decoder = None
    for codec in range(6):
        bom = codec_bom[codec]
        if bom == b_content[:len(bom)]:
            decoder = codecs.getdecoder(codec_decoder[codec])
            break

    if decoder == None:
        raise ScriptError(ErrorsCodes.input_file_read_error, {'file': path_to_file})

    try:
        content = decoder(b_content[len(bom):])[0]
    except:
        try:
            decoder = codecs.getdecoder('latin1')
            content = decoder(b_content[len(bom):])[0]
        except:
            raise ScriptError(ErrorsCodes.input_file_read_error, {'file': path_to_file})

    content = content.replace("\r", "")
    return content


def save_results(output_file, input_file, input_type, md5s_dict, results, language):
    number_of_md5 = len(md5s_dict.keys())

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('<meta charset="UTF-8">\n')
        f.write('<style>\ntable, th, td {\n    border: 1px solid black;\n    border-collapse: collapse;\n}\nth, td {\n    padding: 5px;\n}\n</style>\n')

        f.write("<h2>" + get_string(VariousCodes.vt_scan_title, language).format(version=VERSION) + "</h2></br>")
        f.write(get_string(VariousCodes.file_opening, language).format(file=input_file) + "</br>")
        f.write(get_string(VariousCodes.file_type, language).format(type=input_type) + "</br>")
        f.write(get_string(VariousCodes.file_md5s_nb, language).format(nb_md5s=number_of_md5) + "</br>")

        if number_of_md5 == 0:
            return

        # Check for duplicate without same name or size
        for md5, files in md5s_dict.items():
            if len(files) == 1:
                continue
            for file in files:
                if files[0]["file_name"] != file["file_name"] or files[0]["file_size"] != file["file_size"]:
                    f.write("</br><b/>" + get_string(VariousCodes.dup_warning, language).format(md5=md5) + "</b></br>")
                    break

        if len(results["positives"]) != 0:
            f.write("<h4></br>" + get_string(VariousCodes.vt_nonzero, language).format(nb=len(results["positives"])) + "</br></h4>\n")
            f.write(' <table>\n  <tr>\n    <th>')
            f.write(get_string(VariousCodes.result, language))
            f.write('</th>\n    <th>')
            f.write("MD5")
            f.write('</th>\n    <th>')
            f.write(get_string(VariousCodes.file, language))
            f.write('</th>\n    <th>')
            f.write(get_string(VariousCodes.folder, language))
            f.write('</th>\n    <th>')
            f.write(get_string(VariousCodes.size, language))
            f.write('</th>\n</tr>\n')
            for md5, result in results["positives"].items():
                report_md5 = md5s_dict[md5]
                result['md5'] = md5
                result['file_name'] = ""
                result['file_dir'] = ""
                result['file_size'] = ""
                for file in report_md5:
                    result['file_name'] += file['file_name'] + "</br>"
                    result['file_dir'] += file['file_dir'] + "</br>"
                    result['file_size'] += file['file_size'] + "</br>"
                f.write('<tr><td>{positives}/{total}</td><td><a href={url} target="_blank">{md5}</a></td><td>{file_name}</td><td>{file_dir}</td><td>{file_size}</td></tr>\n'.format(**result))
            f.write('</table>\n')

        if len(results["unknows"]) != 0:
            f.write("<h4></br>" + get_string(VariousCodes.vt_unknown, language).format(nb=len(results["unknows"])) + "</br></h4>\n")
            f.write(' <table>\n  <tr>\n    <th>')
            f.write("MD5")
            f.write('</th>\n    <th>')
            f.write(get_string(VariousCodes.file, language))
            f.write('</th>\n    <th>')
            f.write(get_string(VariousCodes.folder, language))
            f.write('</th>\n    <th>')
            f.write(get_string(VariousCodes.size, language))
            f.write('</th>\n</tr>\n')
            for md5, result in results["unknows"].items():
                report_md5 = md5s_dict[md5]
                result['md5'] = md5
                result['file_name'] = ""
                result['file_dir'] = ""
                result['file_size'] = ""
                for file in report_md5:
                    result['file_name'] += file['file_name'] + "</br>"
                    result['file_dir'] += file['file_dir'] + "</br>"
                    result['file_size'] += file['file_size'] + "</br>"
                f.write('<tr><td>{md5}</td><td>{file_name}</td><td>{file_dir}</td><td>{file_size}</td></tr>\n'.format(**result))
            f.write('</table>\n')

        if len(results["negatives"]) != 0:
            f.write("<h4></br>" + get_string(VariousCodes.vt_negative, language).format(nb=len(results["negatives"])) + "</br></h4>\n")
            f.write(' <table>\n  <tr>\n    <th>')
            f.write(get_string(VariousCodes.result, language))
            f.write('</th>\n    <th>')
            f.write("MD5")
            f.write('</th>\n    <th>')
            f.write(get_string(VariousCodes.file, language))
            f.write('</th>\n    <th>')
            f.write(get_string(VariousCodes.folder, language))
            f.write('</th>\n    <th>')
            f.write(get_string(VariousCodes.size, language))
            f.write('</th>\n</tr>\n')
            for md5, result in results["negatives"].items():
                report_md5 = md5s_dict[md5]
                result['md5'] = md5
                result['file_name'] = ""
                result['file_dir'] = ""
                result['file_size'] = ""
                for file in report_md5:
                    result['file_name'] += file['file_name'] + "</br>"
                    result['file_dir'] += file['file_dir'] + "</br>"
                    result['file_size'] += file['file_size'] + "</br>"
                f.write('<tr><td>{positives}/{total}</td><td><a href={url} target="_blank">{md5}</a></td><td>{file_name}</td><td>{file_dir}</td><td>{file_size}</td></tr>\n'.format(**result))
            f.write('</table>\n')

        f.write("</br></br>" + get_string(VariousCodes.scan_complete, language))


def main():
    parser = OptionParser("usage: %prog -f path_to_file [options]")
    parser.add_option("-f", "--file",
                      help="file to use",
                      action="store", default="input.txt",
                      dest="path_to_file")

    # Keep -k option for retro compatibility
    parser.add_option("-k", "--key",
                      help="Only used for retrocompatibility",
                      action="store",
                      dest="dummy")

    (options, args) = parser.parse_args()

    config = {}
    results = {}

    # Get the files paths
    input_file = options.path_to_file.strip()

    # Init output file to "/tmp/errors_vt_scan.html" and it's windows equivalent
    output_file = get_output_file({}, "errors.txt")

    # Retrieve language based on locale
    config["language"] = get_language_from_locale()

    print(get_string(VariousCodes.vt_scan_title, config["language"]).format(version=VERSION))
    try:
        # Load config
        config_file = join(dirname(abspath(expanduser(sys.argv[0]))), config_file_name)
        config = load_config(config_file)

        # Use locale language if no config language
        if "language" not in config.keys():
            config["language"] = get_language_from_locale()

        # Retrieve apikey and check its validity
        apikey = retrieve_apikey(config)

        # Get the report lines
        print(get_string(VariousCodes.file_opening, config["language"]).format(file=input_file))
        report_content = get_report_content(input_file)
        line_list = report_content.split("\n")

        # Detect the logFile type
        file_type = get_file_type(line_list[0])
        print(get_string(VariousCodes.file_type, config["language"]).format(type=file_type))

        output_file = get_output_file(config, input_file)

        # Find the md5s in the file
        md5s_list = find_md5_in_file(line_list, file_type)
        md5_number = len(md5s_list)
        print(get_string(VariousCodes.file_md5s_nb, config["language"]).format(nb_md5s=md5_number))
        if md5_number != 0:
            # Search on VT for each md5 and store the results
            results = run_vt_analyse(md5s_list, apikey, config["language"])

        # Create the output log
        save_results(output_file, input_file, file_type, md5_number, results, config["language"])

        print(get_string(VariousCodes.scan_complete, config["language"]))

    except ScriptError as e:
        error_message = get_string(VariousCodes.error, config["language"]).format(message=e.message(config["language"]))
        print(error_message)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('<meta charset="UTF-8">\n')
            f.write(error_message)

    except ScriptWarning as e:
        error_message = get_string(VariousCodes.warning, config["language"]).format(message=e.message(config["language"]))
        print(error_message)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('<meta charset="UTF-8">\n')
            f.write(error_message)

    # Open the log
    webopen(output_file)


if __name__ == '__main__':
    main()
