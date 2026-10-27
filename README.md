# push-claim-audit

Offline static auditing of documented device-notification delivery against Python source. Version 0.1.0; standard library only at runtime. Audited code is never executed. Environment files are never opened.

Install and run:

```sh
python3 -m pip install .
push-claim-audit /path/to/project --json
python3 -m push_claim_audit /path/to/project --verbose
python3 -m unittest discover
python3 -m build
```

The positional directory is required. Options: `--json`, `--verbose`, repeatable `--ignore <glob>` relative to the directory, `--fail-on {HIGH,MEDIUM}` (default HIGH), and `--version`. Exit 0 means PASS, 2 means a finding meets the threshold, and 1 means a usage or filesystem error. MEDIUM findings remain visible at the default threshold.

Root README.md and Markdown files below any docs path component supply claims. Fenced blocks are excluded; inline code counts. Matching is case insensitive, expands contractions, replaces hyphens, and joins lines within paragraphs. Negative spans are removed before affirmative matching. One finding per family is emitted, at most two.

## Limitations

Only the fixed affirmative and negative templates defined in `push_claim_audit/audit.py` count as claims; arbitrary paraphrases do not. The bare word “push”, titles, dependency names, and git commands do not qualify. SMS, email, inbound hooks, framed sockets, browser event streams, GraphQL, gRPC, and MQTT are separate channels.

Evidence requires a same-module Firebase message construction and send, a pywebpush call, or an imported APNs/OneSignal client construction followed by a direct send on the bound receiver or chained constructor. Imports resolve aliases. Attribute bindings such as self.client count. Intermediate method aliases and cross-module pairs do not count. This is a syntactic check, without control-flow, runtime reachability, credential validity, or delivery guarantees. Parse-invalid modules supply no evidence. Scope shadowing and reassignment are not modeled.

Production scanning excludes tests, test-named modules, fixtures, docs, examples, and symlinks. Evidence confined to tests yields MEDIUM for an affirmative production claim. A contradictory negative claim yields HIGH only when production evidence exists, including a negative claim in test documentation. An affirmative claim without source yields HIGH; an absence claim without source is consistent. JSON includes verdict, findings, claim paths, and evidence paths.
