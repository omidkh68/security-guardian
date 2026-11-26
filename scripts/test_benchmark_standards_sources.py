"""Offline source verifier boundary tests; publisher code never executes."""
import io
import unittest
import zipfile
import verify_standards_sources as v

class StandardsSourceTests(unittest.TestCase):
    def test_exact_cwe_edition_and_ids(self):
        data={'references':{'CWE:CWE-89':{'standard':'CWE','id':'CWE-89'}}}
        good=b'<Weakness_Catalog Version="5.0"><Weakness ID="89"/></Weakness_Catalog>'
        self.assertEqual(v.verify_cwe(data,good),1)
        for bad in (good.replace(b'5.0',b'4.20'),good.replace(b'89',b'90'),b'<!DOCTYPE x>'+good):
            with self.assertRaises(ValueError):v.verify_cwe(data,bad)
        def archive(name,raw):
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w') as f:f.writestr(name,raw)
            return output.getvalue()
        self.assertEqual(v.cwe_xml_from_zip(archive('cwec_v5.0.xml',good)),good)
        with self.assertRaises(ValueError):v.cwe_xml_from_zip(archive('cwec_v4.20.xml',good))

if __name__=='__main__':unittest.main()
