"""Artifact inventory tests; no network or archive extraction."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from verify_sbom_preview import archive_inventory


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
