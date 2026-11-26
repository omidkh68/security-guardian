"""Prevent accidental drift between English and complete Persian README.

Executable snippets and external links are identical; paired local guides may be localized.
Mermaid labels are translated while its graph edges remain unchanged.
This test skips in standalone Skill installations without the repository docs.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[5]
EN = ROOT / 'README.md'
FA = ROOT / 'README-FA.md'

FENCE = re.compile(r'^```([\w-]*)[ \t]*\n(.*?)^```[ \t]*$', re.M | re.S)
HEADING = re.compile(r'^(#{2,3}) .+$', re.M)
LINK = re.compile(r'\]\(([^)]+)\)')
EDGE = re.compile(r'^\s*([A-Z])\b.*?-->\s*([A-Z])\b', re.M)
ANCHOR = re.compile(r'<a id="([^"]+)"></a>')


@unittest.skipUnless(EN.is_file() and FA.is_file(),
                     "README translation parity applies to full repository checkouts")
class ReadmeParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.en = EN.read_text(encoding='utf-8')
        cls.fa = FA.read_text(encoding='utf-8')

    def test_section_hierarchy_and_examples(self):
        self.assertEqual(HEADING.findall(self.en), HEADING.findall(self.fa))
        en_blocks = FENCE.findall(self.en)
        fa_blocks = FENCE.findall(self.fa)
        self.assertEqual([language for language, _ in en_blocks],
                         [language for language, _ in fa_blocks])
        for (language, source), (_, translated) in zip(en_blocks, fa_blocks):
            if language == 'mermaid':
                self.assertEqual(EDGE.findall(source), EDGE.findall(translated))
            else:
                self.assertEqual(source, translated,
                                 f"Executable/example {language!r} block drift")

    def test_all_documentation_links_preserved(self):
        en_links = {link for link in LINK.findall(self.en) if not link.startswith('#')}
        fa_links = {link for link in LINK.findall(self.fa) if not link.startswith('#')}
        def counterpart(link):
            if link.endswith('.md') and not link.startswith(('https://','http://','mailto:')):
                paired=link[:-3]+'-FA.md'
                if (ROOT / paired).is_file():
                    return paired
            return link
        missing={link for link in en_links if link not in fa_links and counterpart(link) not in fa_links}
        self.assertFalse(missing, missing)
        for link in en_links | fa_links:
            if (not link.startswith(('#','https://','http://','mailto:'))
                    and not link.startswith('data:')):
                self.assertTrue((ROOT / link).is_file(),
                                f"Broken repository-relative README link: {link}")

    def test_persian_table_and_details_structure(self):
        self.assertEqual(sum(line.startswith('|') for line in self.en.splitlines()),
                         sum(line.startswith('|') for line in self.fa.splitlines()))
        for marker in ('<details>', '</details>', '<summary>', '</summary>'):
            self.assertEqual(self.en.count(marker), self.fa.count(marker))
        anchors=set(ANCHOR.findall(self.fa))
        for target in re.findall(r'\]\(#([a-z0-9-]+)\)', self.fa):
            self.assertIn(target, anchors,
                          f"Unresolved Persian README navigation anchor: {target}")
        self.assertNotIn(chr(167), self.fa)


if __name__ == '__main__':
    unittest.main()
