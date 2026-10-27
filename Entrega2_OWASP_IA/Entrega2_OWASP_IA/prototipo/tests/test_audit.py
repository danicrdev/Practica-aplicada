import json
import tempfile
import unittest
from pathlib import Path
from audit_owasp import cat_for,build,html_report,normalize,priority

class Tests(unittest.TestCase):
    def test_cwe_categories(self):
        self.assertEqual(cat_for('CWE-89'),'A05')
        self.assertEqual(cat_for('CWE-798'),'A04')
        self.assertEqual(cat_for('CWE-639'),'A01')
    def test_unknown_safe(self):
        self.assertIsNone(cat_for('sin regla','sin evidencia'))
    def test_priority(self):
        self.assertGreater(priority('High'),priority('Low'))
        self.assertEqual(priority('WARNING'),2)
        self.assertEqual(priority('ERROR'),3)
    def test_zap(self):
        data={'site':[{'alerts':[{'name':'SQL Injection','cweid':'89','riskdesc':'High','instances':[{'uri':'http://test.local'}]}]}]}
        self.assertEqual(len(normalize(data,'x')),1)
    def test_semgrep(self):
        data={'results':[{'check_id':'x','extra':{'message':'x','metadata':{'cwe':'CWE-79'}}}]}
        self.assertEqual(len(normalize(data,'x')),1)
    def test_report_review_and_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'f.json'
            p.write_text(json.dumps([{'title':'SQL Injection','cwe':'CWE-89','severity':'High'}]))
            first=build([str(p)],{},None)
            fid=first['findings'][0]['id']
            result=build([str(p)],{fid:'confirmado'},None)
            self.assertEqual(result['findings'][0]['status'],'confirmado')
            self.assertIn('sha256',result['metadata']['inputs'][0])
            self.assertIn('INFORME ACADÉMICO',html_report(result))
    def test_redaction(self):
        from audit_owasp import clean
        self.assertNotIn('abc123',clean('password=abc123'))

if __name__=='__main__':unittest.main()
