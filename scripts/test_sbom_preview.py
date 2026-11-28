"""Artifact inventory tests; no network or archive extraction."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from verify_sbom_preview import archive_inventory, validate_manifest, validate_release_receipt


class PreviewInventoryTests(unittest.TestCase):
    def make(self, folder, entries):
        archive=Path(folder)/'preview.tgz'
        with tarfile.open(archive,'w:gz') as t:
            for name,data,kind in entries:
                member=tarfile.TarInfo(name)
                member.type=kind
                if kind==tarfile.REGTYPE:
                    member.size=len(data)
                    t.addfile(member,io.BytesIO(data))
                else:
                    member.linkname='outside'
                    t.addfile(member)
        return archive

    def test_exact_files_hashes_and_unknown_license(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            archive=self.make(tmp,[('package/package.json',b'{"name":"demo"}',tarfile.REGTYPE),
                                   ('package/scripts/demo.py',b'print(1)',tarfile.REGTYPE)])
            manifest,inventory=archive_inventory(archive)
            self.assertEqual(manifest['name'],'demo')
            self.assertEqual(inventory['file_count'],2)
            row=inventory['files'][1]
            self.assertEqual(row['path'],'scripts/demo.py')
            self.assertEqual(row['sha256'],hashlib.sha256(b'print(1)').hexdigest())
            self.assertEqual(row['license_concluded'],'NOASSERTION')

    def test_unsafe_members_and_duplicate_manifest(self):
        manifest=('package/package.json',b'{}',tarfile.REGTYPE)
        for entry in [manifest,('package/../outside',b'x',tarfile.REGTYPE),
                      ('outside/file',b'x',tarfile.REGTYPE),
                      ('package/link',b'',tarfile.SYMTYPE),
                      ('package//file',b'x',tarfile.REGTYPE)]:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(ValueError):
                    archive_inventory(self.make(tmp,[manifest,entry]))
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                archive_inventory(self.make(tmp,[('package/README.md',b'x',tarfile.REGTYPE)]))

    def test_release_manifest_and_receipt_are_bound_to_exact_bytes(self):
        import hashlib
        version='1.3.0'
        commit='a'*40
        manifest={'name':'@omidkh68/security-guardian','version':version,'private':False,
                  'contentPolicy':{'class':'dual-use'}}
        with tempfile.TemporaryDirectory() as tmp:
            archive=self.make(tmp,[('package/package.json',json.dumps(manifest).encode(),tarfile.REGTYPE),
                                   ('package/DISCLOSURE',b'defensive use',tarfile.REGTYPE)])
            actual,inventory=archive_inventory(archive)
            receipt={'kind':'TESTED_NPM_ARTIFACT','package':manifest['name'],'version':version,
                     'private':False,'source_commit':commit,'bytes':archive.stat().st_size,
                     'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}
            validate_release_receipt(receipt,archive,actual,inventory,version,commit)
            for k,v in [('sha256','0'*64),('bytes',0),('source_commit','b'*40),('private',True),('version','1.3.1'),('package','other'),('kind','other')]:
                with self.subTest(field=k), self.assertRaises(ValueError):
                    validate_release_receipt(dict(receipt,**{k:v}),archive,actual,inventory,version,commit)
            for k,v in [('private',True),('version','1.3.1'),('name','other'),('contentPolicy',{}),('dependencies',{'x':'1'})]:
                with self.subTest(manifest_field=k), self.assertRaises(ValueError):
                    validate_release_receipt(receipt,archive,dict(actual,**{k:v}),inventory,version,commit)
            with self.assertRaises(ValueError):
                validate_release_receipt(receipt,archive,actual,{'files':[]},version,commit)
            with self.assertRaises(ValueError):
                validate_manifest(actual)
            validate_manifest(dict(actual,private=True))
            with self.assertRaises(ValueError):
                validate_manifest(dict(actual,version='1.2.1'),'1.2.1')
