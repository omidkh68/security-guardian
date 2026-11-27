
"""Mapped identity reconciliation tests, not normative semantic review."""
import unittest
import standards_inventory as inv


class ReferenceInventoryTests(unittest.TestCase):
    def test_mobile_exact_identity_and_drift(self):
        row={'id':'MASVS-AUTH-1','path':'controls/MASVS-AUTH-1.md','blob_sha':'a'*40}
        ref={'standard':'MASVS','id':row['id'],'source_path':row['path'],'source_blob_sha':row['blob_sha']}
        data={'references':{'MASVS:MASVS-AUTH-1':ref}}
        inventory={'rows':[row],'crosswalk_ids_outside_inventory':[]}
        result=inv.validate_reference_inventory('MASVS',inventory,data)
        self.assertEqual(result['status'],'IDENTITIES_MATCHED')
        self.assertEqual(result['semantic_review'],'NOT_RUN')
        for key,value in [('path','other.md'),('blob_sha','b'*40)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                inv.validate_reference_inventory('MASVS',{**inventory,'rows':[{**row,key:value}]},data)
        with self.assertRaises(ValueError):
            inv.validate_reference_inventory('MASVS',{'rows':[],'crosswalk_ids_outside_inventory':[row['id']]},data)

    def test_wstg_preserves_publisher_conflict_and_missing_checklist_identity(self):
        a='WSTG-v42-INPV-13'
        b='WSTG-v42-INPV-99'
        data={'references':{k:{'standard':'WSTG','id':k} for k in (a,b)}}
        inventory={'rows':[{'id':a,'publisher_identity_conflict':True}],
                   'crosswalk_ids_outside_inventory':[b]}
        result=inv.validate_reference_inventory('WSTG',inventory,data)
        self.assertEqual(result['status'],'REVIEW_REQUIRED')
        self.assertEqual(result['publisher_identity_conflicts'],[a])
        self.assertEqual(result['outside_inventory'],[b])
        self.assertEqual(result['matched_identities'],1)

    def test_cwe_unknown_id_and_duplicate_fail(self):
        data={'references':{'CWE:89':{'standard':'CWE','id':'CWE-89'}}}
        row={'id':'CWE-89'}
        good={'rows':[row],'crosswalk_ids_outside_inventory':[]}
        self.assertEqual(inv.validate_reference_inventory('CWE',good,data)['validation_kind'],'IDENTIFIER_ONLY')
        for rows in ([],[row,row]):
            with self.assertRaises(ValueError):
                inv.validate_reference_inventory('CWE',{**good,'rows':rows},data)
