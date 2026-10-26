# Verification evidence

Coverage has three separate meanings here: a core contract entry has a registered adapter, a cited scenario passed, and instrumented adapter code was reached. None establishes every possible behavior of a tool.

## Reproduce the CI gate

Install the constrained development dependencies, then run the commands in the README's **Verify a change** section. Commit the reviewed sources before reproducing CI's additional `--require-clean-evidence` flag. Local development may use a dirty checkout, but its contents must remain identical throughout testing and evidence validation. Plans and generated reports belong in ignored `temp/`. The checkout verification script loads its checker and catalog from checkout `src/`, so a stale installed verifier cannot bypass newer validation rules. The pytest run still exercises its configured adapter installation.

`--evidence-report` enables the root pytest plugin. It records collected node IDs, deselected cases, setup/call/teardown outcomes, collection failures, Python/platform and pytest/plugin versions, and source identities before and after the session. The identity includes the Git revision and a SHA-256 inventory of tracked and nonignored source files, with UTF-8 CRLF normalized to LF. Generated ignored reports do not alter that identity. Imported adapter Python and packaged data files must match the checkout at both ends; reinstall a noneditable development installation after source changes, or use an editable installation.

`scripts/check_coverage.py --test-evidence PATH` checks every catalog claim whose status is exercised. The gate accepts only unrestricted `tests/` collection under the default project configuration; positional subsets, keyword/marker filters, ignore/deselect settings, last-failed/stepwise modes, configuration overrides, explicit plugin overrides and `--runxfail` are refused. Each citation must resolve to collected cases and every matching case must pass all three phases. An unparameterized citation covers all matching parameterized cases. Skips, expected failures (including blank reasons), unexpected passes, incomplete runs, collection errors, changed sources and stale revisions fail the gate. A check without an execution receipt reports registration consistency only. CI uses the constrained plugin set; arbitrary third-party plugin filtering is outside this gate's assurance.

Coverage.py records the source digest as a measurement context. `--branch-coverage PATH` requires branch data and contexts matching the execution receipt, a complete inventory of adapter Python files, matching measured file contents, and aggregate totals equal to the per-file measurements. Both checkout and installed-package paths map explicitly to `src/genesismesh_mcp/`. Run this gate in the environment that produced the reports, while measured files remain available. The resolved JSON verification report includes SHA-256 digests of both input reports, the source identity, citation counts, and separate line/branch totals. These are CI-generated execution records; reviewing assertion relevance remains necessary.

Each matrix job uploads these files under `verification-<OS>-py<version>` for 14 days:

- `tests.json`: source identity, collection and outcomes;
- `branches.json`: reached/missing lines and branches, with source context;
- `junit.xml`: test-run diagnostics;
- `verification.json`: resolved contract mappings and checked evidence summary.

`--require-full-behavior` additionally checks the packaged `tool-evidence.json` ledger for all 284 registered tools and refuses any implemented contract entry without behavioral citations. Every positive citation must pass and invoke that tool's actual registered handler with schema-valid input and an observed successful result. A refused request alone cannot satisfy a positive claim. Every tool also needs a passing refusal citation. Reviewed domain-specific tamper, expiry and authorization cases supplement the per-tool disabled-profile tests where applicable.

The optional test observer fingerprints actual handler source, schema, profiles and core targets, and records only case/tool identifiers, phase, schema validity, returned/exception classification, refusal classification and transport-mock status. It records no arguments, result bodies or keys. Replacing the HTTP transport or substituting a decorated handler cannot qualify domain-success evidence. Teardown calls and calls from a previous test's late thread cannot qualify another test. Passing these checks still requires review of each assertion's relevance; this is a reproducible CI record, not an attestation against malicious test authors.

The final `full-coverage` CI job requires exactly the four distinct Linux/Windows and Python 3.12/3.14 reports. It rechecks each source-bound receipt, full behavior ledger, effective measurement configuration and input hashes against its successful per-job verification envelope, then unions observed statements and branch arcs. It retains every possible line/arc seen on any supported interpreter and requires **zero missing statements and zero missing branch arcs** across that matrix. Custom coverage exclusions and source suppression comments fail this gate. Individual platform totals remain in the reports; matrix-union completeness does not mean each platform exercises another operating system's branches. The final report is uploaded separately as `full-coverage-union`.

The reports cover the adapter package in the instrumented process and its threads. Separate stdio processes, process-loss/restart tests, the isolated wheel smoke and real model chat sessions establish functional behavior independently; their code execution is not merged into this branch report. Complete measured source coverage does not establish every possible behavior, deployment configuration or production hosting outcome.

## Independent core comparisons

The authority integration suite runs official MCP clients against disposable real HTTP authorities. Grant scenarios cover policy-envelope refusal, signed grant/token wire preservation, core admission-rule comparisons, successful and duplicate uploads, signature tampering, quarantined uses, chain continuation, bearer-signed token refresh, revocation and operator-tier denial. The exported store must pass the pinned core's offline verifier, and payload tampering must fail it.

Review scenarios check a real policy ALLOW and the actor/requester/decider separation enforced by the authority. The resulting review signature and embedded signed approvals are verified independently with core; altered verdicts and wrong audience pins fail the comparison. These tests record declared evidence and decisions. They do not perform an external secret operation or establish that a human independently approved it.

Only directly exercised contract rows gain citations. HTTP lifecycle coverage does not imply CLI file/process equivalence, and aliases do not automatically become separate verified scenarios. Runtime catalog/resource discovery remains available from a clean wheel without tests, pytest, coverage.py or a sibling core checkout.

`genesis-mesh://tool-evidence` exposes the reviewed scenario ledger from the installed wheel. Its citations describe the repository's test design; reading the resource does not establish that those tests ran on the installed machine. Use the source-bound CI artifacts for execution evidence.
