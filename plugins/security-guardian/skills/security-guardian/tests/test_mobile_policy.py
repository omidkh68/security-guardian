"""Synthetic configuration checks; no device acceptance claim."""
import sys
from pathlib import Path
import plistlib
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import security_mobile_policy as policy

def manifest(value):
    return ('<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            '<uses-sdk android:minSdkVersion="'+value+'"/></manifest>').encode()

class MobilePolicyTests(unittest.TestCase):
    def test_android_floor_matches_and_below(self):
        for value,expected in [('28','CONFIGURATION_MEETS_POLICY'),('27','CONFIGURATION_BELOW_POLICY'),
                               ('${minSdk}','INCONCLUSIVE')]:
            with self.subTest(value=value):
                r=policy.check('android',manifest(value),28)
                self.assertEqual(r['status'],expected)
                self.assertEqual(r['runtime_verification'],'NOT_RUN')
                self.assertEqual(r['compliance'],'NOT_ASSESSED')
        self.assertEqual(policy.check('android',b'<manifest/>',28)['status'],'INCONCLUSIVE')

    def test_ios_numeric_version_and_binary_plist(self):
        for fmt in (plistlib.FMT_XML,plistlib.FMT_BINARY):
            raw=plistlib.dumps({'MinimumOSVersion':'16.10'},fmt=fmt)
            self.assertEqual(policy.check('ios',raw,'16.2')['status'],'CONFIGURATION_MEETS_POLICY')
            self.assertEqual(policy.check('ios',raw,'17.0')['status'],'CONFIGURATION_BELOW_POLICY')
        self.assertEqual(policy.check('ios',plistlib.dumps({}),'16.0')['status'],'INCONCLUSIVE')

    def test_malformed_input_and_invalid_policy(self):
        for platform,raw,floor in [('android',manifest('28'),True),
                                   ('android',b'<!DOCTYPE manifest><manifest/>',28),
                                   ('ios',plistlib.dumps({}),'latest'),
                                   ('android',b'x'*(policy.LIMIT+1),28)]:
            with self.subTest(platform=platform,floor=floor), self.assertRaises(ValueError):
                policy.check(platform,raw,floor)

    def test_output_does_not_echo_unrelated_metadata(self):
        raw=plistlib.dumps({'MinimumOSVersion':'16.0','secret':'PRIVATE_CANARY'})
        self.assertNotIn('PRIVATE_CANARY',str(policy.check('ios',raw,'16.0')))

    def test_xml_encoding_cannot_hide_entity_declarations(self):
        unsafe='<!DOCTYPE manifest [<!ENTITY api "28">]><manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk android:minSdkVersion="&api;"/></manifest>'
        for encoding in ('utf-8','utf-16','utf-16-le','utf-32'):
            with self.subTest(encoding=encoding),self.assertRaises(ValueError):
                policy.check('android',unsafe.encode(encoding),28)
        safe=manifest('28').decode()
        self.assertEqual(policy.check('android',safe.encode('utf-16'),28)['status'],'CONFIGURATION_MEETS_POLICY')
        unsafe_plist='<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE plist [<!ENTITY value "16.0">]><plist version="1.0"><dict><key>MinimumOSVersion</key><string>&value;</string></dict></plist>'
        with self.assertRaises(ValueError):
            policy.check('ios',unsafe_plist.encode('utf-16'),'16.0')
