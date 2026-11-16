# Angular SSR JSON-LD script-boundary regression (review example)

**This is a proposed remediation guide, not a verified change to Azalee.**
The Azalee application source is not included in the public Security Guardian
repository or accessible to this GitHub integration. Apply and execute this
test in the **actual application repository** before claiming VERIFIED_FIXED.

## Root cause to verify

JSON-LD content can be valid JSON but unsafe when HTML-serialized directly
inside `<script type="application/ld+json">` if an attacker-controlled string
contains a literal `</script>` sequence. Escaping JavaScript string quotes
or replacing only `&` is insufficient for this script-ending sequence.

### Example defensive serialization (TypeScript)

```ts
export function stringifyJsonLdForHtml(data: unknown): string {
  return JSON.stringify(data)
    .replace(/</g, '\\u003c');
}
```

If the application uses `script.textContent = JSON.stringify(data)`,
use `stringifyJsonLdForHtml(data)` at that assignment. Ensure the application
does not unescape entities later, and preserve JSON validity for search engines.
Do not use `bypassSecurityTrustHtml` or unrelated sanitization as a substitute
for escaping at the correct SSR HTML serialization boundary.

### Regression conditions

- Construct a product name with an inert script-breakout marker:
  `</script><script data-sg-probe="x"></script>`.
- Render the actual Angular SSR response for that product.
- Assert that the marker **cannot** create a second script element in the
  final HTML and that the JSON-LD parses back to the original product name.
- Confirm the generated HTML does not contain the literal injected closing
  sequence and contains `\\u003c/script` in the serialized JSON-LD.
- Repeat with `<` in descriptions and category values, plus quotes, newlines,
  non-ASCII content and ordinary JSON-LD attributes.

An isolated helper unit test alone is **not** enough to prove SSR output is
safe. The HTML boundary test must use the final server-rendered response.

### Tracking contract

1. Start a new `fix` run in Azalee and reference existing
   `SG-ANG-01-742EC4AA600D` (or its active replacement after reclassification).
2. Change only the actual affected HTML serialization code.
3. Execute the SSR regression test and record its command and real PASS/FAIL
   evidence in a tracker `test` entry linked to the finding.
4. If any test cannot be run, record `FIXED_UNVERIFIED` with a reason.
5. Only set `VERIFIED_FIXED` after a linked successful test from the **same
   run** as the finding update, preserving the exact tested Git commit.

Never copy raw customer data or private scan reports into a public issue.
