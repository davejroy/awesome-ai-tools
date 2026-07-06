// Harness invoked by test_jcs.py to cross-check jcs.ts against jcs.py.
// Reads a JSON array of test inputs on stdin, writes a JSON array of
// canonical-bytes-as-hex on stdout. Requires Node >= 22.6 (type stripping)
// or that jcs.ts has been pre-compiled to jcs.js alongside it.
import { canonicalize } from "./jcs.ts";

let raw = "";
for await (const chunk of process.stdin) raw += chunk;

const inputs = JSON.parse(raw);
const results = inputs.map((value) => canonicalize(value).toString("hex"));

process.stdout.write(JSON.stringify(results));
