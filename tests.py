import unittest
from vt_scan import get_report_lines, get_file_type, ScriptError
from vt_scan_constants import ErrorsCodes


class Get_Report_Lines_Tests(unittest.TestCase):

    def test_utf8_unicode_bom_crlf(self):
        lines = get_report_lines("logs/OTL.Txt")
        self.assertEqual(len(lines), 547)
        self.assertEqual(lines[0], 'OTL logfile created on: 30/07/2016 12:26:10 - Run 1')
        self.assertEqual(lines[1], 'OTL by OldTimer - Version 3.2.69.0     Folder = C:\\Users\\Xavier\\Downloads')

        lines = get_report_lines("logs/FRST.txt")
        self.assertEqual(len(lines), 441)
        self.assertEqual(lines[0], "Résultats d'analyse de  Farbar Recovery Scan Tool (FRST) (x64) Version: 27-07-2016")
        self.assertEqual(lines[1], "Exécuté par Xavier (administrateur) sur XAVIER-WIN7 (30-07-2016 12:37:49)")

    def test_utf8_unicode_crlf(self):
        lines = get_report_lines("logs/OTL_with_malware.txt")
        self.assertEqual(len(lines), 304)
        self.assertEqual(lines[0], 'OTL logfile created on: 11/09/2016 21:16:10 - Run 2')
        self.assertEqual(lines[1], 'OTL by OldTimer - Version 3.2.69.0     Folder = C:\\Documents and Settings\\UserName\\Bureau')

    def test_utf16_le_crlf(self):
        lines = get_report_lines("logs/ZHPDiag_utf-16-le.txt")
        self.assertEqual(len(lines), 902)
        self.assertEqual(lines[0], '~ ZHPDiag v2018.1.5.5 Par Nicolas Coolman (2018/01/05)')
        self.assertEqual(lines[1], '~ Démarré par USERNAME (Administrator)  (2018/01/06 15:33:32)')

    def test_utf8_unicode_crlf(self):
        lines = get_report_lines("logs/no_md5.txt")
        self.assertEqual(len(lines), 7)
        self.assertEqual(lines[0], "~ ZHPDiag v2016.7.29.119 Par Nicolas Coolman (2016/07/29)")
        self.assertEqual(lines[1], "~ Démarré par Xavier (Administrator)  (2016/07/30 12:22:28)")

        lines = get_report_lines("logs/short.txt")
        self.assertEqual(len(lines), 9)
        self.assertEqual(lines[0], "~ ZHPDiag v2016.7.29.119 Par Nicolas Coolman (2016/07/29)")
        self.assertEqual(lines[1], "~ Démarré par Xavier (Administrator)  (2016/07/30 12:22:28)")

        lines = get_report_lines("logs/ZHPDiag.txt")
        self.assertEqual(len(lines), 388)
        self.assertEqual(lines[0], "~ ZHPDiag v2016.7.29.119 Par Nicolas Coolman (2016/07/29)")
        self.assertEqual(lines[1], "~ Démarré par Xavier (Administrator)  (2016/07/30 12:22:28)")

    def test_ascii(self):
        lines = get_report_lines("logs/SystemLook.txt")
        self.assertEqual(len(lines), 20)
        self.assertEqual(lines[0], 'SystemLook 30.07.11 by jpshortstuff')
        self.assertEqual(lines[1], 'Log created at 10:27 on 12/03/2017 by INTEL')

        lines = get_report_lines("logs/raw.txt")
        self.assertEqual(len(lines), 16)
        self.assertEqual(lines[0], 'RAW')
        self.assertEqual(lines[1], '8BED39E3C35D6A489438B8141717A559')

    def test_data(self):
        lines = get_report_lines("logs/OTLpecustom.txt")
        self.assertEqual(len(lines), 625)
        self.assertEqual(lines[0], 'OTL logfile created on: 2/26/2011 10:49:12 AM - Run')
        self.assertEqual(lines[1], 'OTLPE by OldTimer - Version 3.1.44.3     Folder = X:\Programs\OTLPE')

    def test_no_file(self):
        with self.assertRaises(ScriptError) as error:
            get_report_lines("no_file")
        self.assertEqual(error.exception.code, ErrorsCodes.input_file_not_found)


class Get_File_Type_Tests(unittest.TestCase):
    def test_zhpdiag(self):
        lines = get_report_lines("logs/ZHPDiag_utf-16-le.txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "ZHPDiag")

        lines = get_report_lines("logs/ZHPDiag.txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "ZHPDiag")

        lines = get_report_lines("logs/no_md5.txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "ZHPDiag")

        lines = get_report_lines("logs/short.txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "ZHPDiag")

    def test_otl(self):
        lines = get_report_lines("logs/OTL.Txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "OTL")

        lines = get_report_lines("logs/OTLpecustom.txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "OTL")

        lines = get_report_lines("logs/OTL_with_malware.txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "OTL")

    def test_frst(self):
        lines = get_report_lines("logs/FRST.txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "FRST")

    def test_raw(self):
        lines = get_report_lines("logs/SystemLook.txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "RAW")

        lines = get_report_lines("logs/raw.txt")
        type = get_file_type(lines[0])
        self.assertEqual(type, "RAW")
