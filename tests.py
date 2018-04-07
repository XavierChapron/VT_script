import unittest
from vt_scan import get_report_content, get_file_type, ScriptError, ScriptWarning, retrieve_apikey, find_md5_in_file
from vt_scan_constants import ErrorsCodes, default_config


class Get_Report_Lines_Tests(unittest.TestCase):

    def test_utf8_unicode_bom_crlf(self):
        lines = get_report_content("logs/OTL.Txt").split("\n")
        self.assertEqual(len(lines), 547)
        self.assertEqual(lines[0], 'OTL logfile created on: 30/07/2016 12:26:10 - Run 1')
        self.assertEqual(lines[1], 'OTL by OldTimer - Version 3.2.69.0     Folder = C:\\Users\\Xavier\\Downloads')

        lines = get_report_content("logs/FRST.txt").split("\n")
        self.assertEqual(len(lines), 441)
        self.assertEqual(lines[0], "Résultats d'analyse de  Farbar Recovery Scan Tool (FRST) (x64) Version: 27-07-2016")
        self.assertEqual(lines[1], "Exécuté par Xavier (administrateur) sur XAVIER-WIN7 (30-07-2016 12:37:49)")

    def test_utf8_unicode_crlf(self):
        lines = get_report_content("logs/OTL_with_malware.txt").split("\n")
        self.assertEqual(len(lines), 304)
        self.assertEqual(lines[0], 'OTL logfile created on: 11/09/2016 21:16:10 - Run 2')
        self.assertEqual(lines[1], 'OTL by OldTimer - Version 3.2.69.0     Folder = C:\\Documents and Settings\\UserName\\Bureau')

    def test_utf16_le_crlf(self):
        lines = get_report_content("logs/ZHPDiag_utf-16-le.txt").split("\n")
        self.assertEqual(len(lines), 902)
        self.assertEqual(lines[0], '~ ZHPDiag v2018.1.5.5 Par Nicolas Coolman (2018/01/05)')
        self.assertEqual(lines[1], '~ Démarré par USERNAME (Administrator)  (2018/01/06 15:33:32)')

    def test_utf8_unicode_crlf(self):
        lines = get_report_content("logs/no_md5.txt").split("\n")
        self.assertEqual(len(lines), 7)
        self.assertEqual(lines[0], "~ ZHPDiag v2016.7.29.119 Par Nicolas Coolman (2016/07/29)")
        self.assertEqual(lines[1], "~ Démarré par Xavier (Administrator)  (2016/07/30 12:22:28)")

        lines = get_report_content("logs/short.txt").split("\n")
        self.assertEqual(len(lines), 9)
        self.assertEqual(lines[0], "~ ZHPDiag v2016.7.29.119 Par Nicolas Coolman (2016/07/29)")
        self.assertEqual(lines[1], "~ Démarré par Xavier (Administrator)  (2016/07/30 12:22:28)")

        lines = get_report_content("logs/ZHPDiag.txt").split("\n")
        self.assertEqual(len(lines), 388)
        self.assertEqual(lines[0], "~ ZHPDiag v2016.7.29.119 Par Nicolas Coolman (2016/07/29)")
        self.assertEqual(lines[1], "~ Démarré par Xavier (Administrator)  (2016/07/30 12:22:28)")

    def test_ascii(self):
        lines = get_report_content("logs/SystemLook.txt").split("\n")
        self.assertEqual(len(lines), 20)
        self.assertEqual(lines[0], 'SystemLook 30.07.11 by jpshortstuff')
        self.assertEqual(lines[1], 'Log created at 10:27 on 12/03/2017 by INTEL')

        lines = get_report_content("logs/raw.txt").split("\n")
        self.assertEqual(len(lines), 16)
        self.assertEqual(lines[0], 'RAW')
        self.assertEqual(lines[1], '8BED39E3C35D6A489438B8141717A559')

    def test_data(self):
        lines = get_report_content("logs/OTLpecustom.txt").split("\n")
        self.assertEqual(len(lines), 625)
        self.assertEqual(lines[0], 'OTL logfile created on: 2/26/2011 10:49:12 AM - Run')
        self.assertEqual(lines[1], 'OTLPE by OldTimer - Version 3.1.44.3     Folder = X:\Programs\OTLPE')

    def test_iso_8859(self):
        lines = get_report_content("logs/FRST_iso-8859.txt").split("\n")
        self.assertEqual(len(lines), 299)
        self.assertEqual(lines[0], "Résultats d'analyse de  Farbar Recovery Scan Tool (FRST) (x86) Version: 13.03.2018")
        self.assertEqual(lines[1], "Exécuté par Système sur MININT-PEGB47 (16-03-2018 19:17:01)")

    def test_no_file(self):
        with self.assertRaises(ScriptError) as error:
            get_report_content("no_file").split("\n")
        self.assertEqual(error.exception.code, ErrorsCodes.input_file_not_found)


class Get_File_Type_Tests(unittest.TestCase):
    def test_zhpdiag(self):
        file_type = get_file_type("~ ZHPDiag v2016.7.29.119 Par Nicolas Coolman (2016/07/29)")
        self.assertEqual(file_type, "ZHPDiag")

    def test_otl(self):
        file_type = get_file_type('OTL logfile created on: 2/26/2011 10:49:12 AM - Run')
        self.assertEqual(file_type, "OTL")

    def test_frst(self):
        file_type = get_file_type("Résultats d'analyse de  Farbar Recovery Scan Tool (FRST) (x64) Version: 27-07-2016")
        self.assertEqual(file_type, "FRST")

    def test_frst_additional(self):
        file_type = get_file_type("Farbar Recovery Scan Tool (x64) Version: 27.01.2018")
        self.assertEqual(file_type, "FRST - additional")

    def test_seaf(self):
        file_type = get_file_type("1. ========================= SEAF 1.0.1.0 - C_XX")
        self.assertEqual(file_type, "SEAF")

    def test_raw(self):
        file_type = get_file_type('SystemLook 30.07.11 by jpshortstuff')
        self.assertEqual(file_type, "RAW")

        file_type = get_file_type('RAW')
        self.assertEqual(file_type, "RAW")


class Check_Apikey_Format_Tests(unittest.TestCase):
    def test_valid(self):
        apikey = retrieve_apikey({"apikey": "A" * 64})
        self.assertEqual(apikey, "A" * 64)

    def test_none(self):
        with self.assertRaises(ScriptWarning) as error:
            retrieve_apikey({})
        self.assertEqual(error.exception.code, ErrorsCodes.apikey_invalid_none)

    def test_default(self):
        with self.assertRaises(ScriptWarning) as error:
            retrieve_apikey(default_config)
        self.assertEqual(error.exception.code, ErrorsCodes.apikey_invalid_default)

    def test_bad_char(self):
        with self.assertRaises(ScriptWarning) as error:
            retrieve_apikey({"apikey": "A" * 63 + "g"})
        self.assertEqual(error.exception.code, ErrorsCodes.apikey_invalid_char)

    def test_bad_lenght(self):
        with self.assertRaises(ScriptWarning) as error:
            retrieve_apikey({"apikey": "A" * 63})
        self.assertEqual(error.exception.code, ErrorsCodes.apikey_invalid_lenght)



class Find_MD5_In_File_Tests(unittest.TestCase):
    def test_zhpdiag(self):
        file_type = "ZHPDiag"
        content = get_report_content("logs/ZHPDiag.txt")
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(len(md5_dicts), 31)

        content = "[MD5.AC4C51EB24AA95B77F705AB159189E24] - 21/11/2010 - (.Microsoft Corporation - Explorateur Windows.) -- C:\Windows\Explorer.exe [2872320]  =>.Microsoft Corporation"
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(list(md5_dicts.keys()), ["AC4C51EB24AA95B77F705AB159189E24"])
        self.assertEqual(md5_dicts["AC4C51EB24AA95B77F705AB159189E24"], [{'file_name': 'Explorer.exe', 'file_dir': 'C:\Windows', 'file_size': '2872320'}])

    def test_otl(self):
        file_type = "OTL"
        content = get_report_content("logs/OTL.Txt")
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(len(md5_dicts), 6)

        content = get_report_content("logs/OTLpecustom.txt")
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(len(md5_dicts), 36)

        content = "[2010/11/21 05:24:25 | 002,616,320 | ---- | M] (Microsoft Corporation) MD5=40D777B7A95E00593EB1568C68514493 -- C:\Windows\SysWOW64\explorer.exe\n"
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(list(md5_dicts.keys()), ["40D777B7A95E00593EB1568C68514493"])
        self.assertEqual(md5_dicts["40D777B7A95E00593EB1568C68514493"], [{'file_name': 'explorer.exe', 'file_dir': 'C:\Windows\SysWOW64', 'file_size': '002,616,320'}])

    def test_frst(self):
        file_type = "FRST"
        content = get_report_content("logs/FRST.txt")
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(len(md5_dicts), 14)

        content = "C:\Windows\system32\drivers\dmvsc.sys 5DB085A8A6600BE6401F2B24EECB5415"
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(list(md5_dicts.keys()), ["5DB085A8A6600BE6401F2B24EECB5415"])
        self.assertEqual(md5_dicts["5DB085A8A6600BE6401F2B24EECB5415"], [{'file_name': 'dmvsc.sys', 'file_dir': 'C:\Windows\system32\drivers', 'file_size': ''}])

    def test_frst_additional(self):
        file_type = "FRST - additional"
        content = get_report_content("logs/FRST_additional.txt")
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(len(md5_dicts), 2)

        content = """C:\\_OTM\\MovedFiles\\01312018_101037\\C_Users\\USER\\Desktop\\kiscrack.exe
[2018-01-31 09:38][2018-01-31 09:38] 002903040 _____ (Microsoft Corporation) 77D770A3ADA662C0BAD69B8DB37C94D3 [Fichier non signé]"""
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(list(md5_dicts.keys()), ["77D770A3ADA662C0BAD69B8DB37C94D3"])
        self.assertEqual(md5_dicts["77D770A3ADA662C0BAD69B8DB37C94D3"], [{'file_name': 'kiscrack.exe', 'file_dir': 'C:\\_OTM\\MovedFiles\\01312018_101037\\C_Users\\USER\\Desktop', 'file_size': '002903040'}])

    def test_seaf(self):
        file_type = "SEAF"
        content = get_report_content("logs/SEAF.txt")
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(len(md5_dicts), 2)

        content = """23.
24. "C:\Windows\hh.exe" [ ARCHIVE | 17 Ko ]
25. TC: 14/07/2009,02:29:03 | TM: 14/07/2009,03:39:12 | DA: 14/07/2009,02:29:03
26.
27. Hash MD5: 3D0B9EA79BF1F828324447D84AA9DCE2
28."""
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(list(md5_dicts.keys()), ["3D0B9EA79BF1F828324447D84AA9DCE2"])
        self.assertEqual(md5_dicts["3D0B9EA79BF1F828324447D84AA9DCE2"], [{'file_name': 'hh.exe', 'file_dir': 'C:\Windows', 'file_size': '17 Ko'}])

    def test_raw(self):
        file_type = "RAW"
        content = get_report_content("logs/raw.txt")
        md5_dicts = find_md5_in_file(content, file_type)
        self.assertEqual(len(md5_dicts), 14)
