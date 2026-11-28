
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

    def test_mastg_pinned_method_metadata(self):
        raw=b'---\nid: MASTG-TEST-0251\nplatform: android\ntype: [dynamic, hooks, manual]\n---\nProcedure\n'
        ref={'id':'MASTG-TEST-0251','source_blob_sha':inv.s.git_blob(raw)}
        meta=inv.mastg_metadata(ref,raw)
        self.assertEqual(meta['publisher_type_tags'],['dynamic','hooks','manual'])
        self.assertEqual(meta['publisher_status'],'NOT_DECLARED')
        self.assertEqual(meta['execution_status'],'NOT_RUN')
        self.assertEqual(meta['automation_status'],'NOT_ASSESSED')
        self.assertTrue(meta['procedure_body_present'])
        for bad in (raw.replace(b'android',b'ios'),raw.replace(b'dynamic',b'static, dynamic'),
                    raw.replace(b'hooks, manual',b'hooks, hooks'),raw.replace(b'type:',b'id: other\ntype:')):
            with self.subTest(raw=bad),self.assertRaises(ValueError):
                inv.mastg_metadata({**ref,'source_blob_sha':inv.s.git_blob(bad)},bad)
        with self.assertRaises(ValueError):inv.mastg_metadata(ref,raw+b'changed')

    def test_mastg_mapped_metadata_does_not_imply_unmapped_review(self):
        raw=b'---\nid: MASTG-TEST-0251\nplatform: android\ntype: [dynamic, hooks, manual]\nstatus: placeholder\n---\n'
        ref={'standard':'MASTG','id':'MASTG-TEST-0251','source_path':'tests-beta/android/MASVS-PLATFORM/MASTG-TEST-0251.md','source_blob_sha':inv.s.git_blob(raw)}
        row={'id':ref['id'],'path':ref['source_path'],'blob_sha':ref['source_blob_sha'],'lifecycle':'NOT_INSPECTED'}
        other={'id':'MASTG-TEST-9999','lifecycle':'NOT_INSPECTED'}
        inventory={'rows':[row,other]}
        data={'references':{'MASTG:'+ref['id']:ref}}
        inv.annotate_mapped_mastg(inventory,data,lambda _:raw)
        self.assertEqual(row['publisher_metadata']['publisher_status'],'placeholder')
        self.assertFalse(row['publisher_metadata']['procedure_body_present'])
        self.assertEqual(other['lifecycle'],'NOT_INSPECTED')
        self.assertEqual(inventory['mapped_metadata_review']['inspected'],1)
        self.assertEqual(inventory['mapped_metadata_review']['not_inspected'],1)
        with self.assertRaises(ValueError):inv.annotate_mapped_mastg({'rows':[other]},data,lambda _:raw)
