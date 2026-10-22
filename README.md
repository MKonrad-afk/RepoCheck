# RepoCheck 1.2

A Python desktop application for checking proposed files against verity of tests before pushing. The default flow is **add files → Check files → a clear verdict**. The app prepares its own test environment, uses the actual repository scripts, and never pushes anything.

## Start

For development in PyCharm (Python 3.11 or 3.12 recommended):

```bash
python -m pip install -r requirements.txt
python main.py
```

The requirements above are for running the Python GUI from source. Git, Gitleaks, OCR and the repository test dependencies are installed automatically into a separate app-owned runtime on the first **Check files**. No Homebrew, sudo or manual tool installation is needed for the default workflow.

First setup needs internet access, several minutes and approximately 2 GB of free disk space (the Linux integration test used about 1.4 GB including package caches). Subsequent checks reuse and verify that runtime. Network access is still needed to refresh the repository and its history.

## Normal workflow

1. Choose the existing profile. Use **Settings** to change its branch, or **+ Add** for another repository.
2. Add files or drop them into the table. A single filename is matched to its repository location if there is exactly one match. Folder contents retain their relative paths. Double-click the target path to change it.
3. Click **Check files**. Connection and tool preparation happen automatically if needed. No per-run confirmation appears.
4. Read the result:

| Verdict | Meaning |
| --- | --- |
| Ready to push — required local checks passed | Every required check in the supported adapter completed successfully. |
| Changes need fixing — do not push yet | At least one check reported a problem. |
| Check incomplete — do not push yet | Setup, execution or adapter coverage failed; no pass was issued. |

A ready verdict covers the exact selected repository snapshot and added file contents checked at that time. It is not a guarantee that a future GitHub run will pass, a security guarantee, or merge approval. GitHub still runs its own CI after a real push. The app does not inspect other unsubmitted edits in your local checkout or predict the eventual commit metadata.

## What Check files actually does

1. Refreshes the selected branch and pins the displayed commit.
2. Prepares and verifies private Python 3.12, Git, Gitleaks 8.24.2, Tesseract 5.5.3 with English data, Pillow, PyYAML and jsonschema.
3. Clones the public repository with its history into a temporary directory and checks out the pinned commit.
4. Copies the added files to their chosen paths. Originals remain untouched.
5. Stages those files and makes a **temporary local commit** if content changed. This commit is never pushed and the temporary checkout is deleted afterward.
6. Runs the repository's checks:

```text
python scripts/sanitize_export.py --check .
python scripts/sanitize_export.py --check-commits BASE..HEAD
python scripts/check_images.py --ocr --require-ocr .
python scripts/validate_syntax.py
python -m unittest discover -s tests -v
gitleaks git --redact --no-banner --log-opts=--all --config .gitleaks.toml .
```

The Gitleaks command uses the repository config when present and scans fetched history plus the temporary new commit. The new-changes sanitizer checks the temporary commit's diff. An unchanged file produces an empty range; the current tree and history are still checked.

These are the four groups in the lab's `checks.yml`: secret scan, leak check, image check, and syntax/unit tests. The adapter checks for the expected jobs and command signatures and refuses to issue a ready verdict when it does not recognize that recipe. It is a local adapter, not a GitHub Actions interpreter.

## Scope: public repositories

Public GitHub repositories can be connected without a token. The default **ready-to-push adapter currently targets the SOC Automation Lab recipe** above. It does not automatically understand every public repository's CI, language, services or dependencies. Unsupported recipes are reported as incomplete, never passed silently.

For other repositories, **Advanced** exposes independent generic checks and the known Python script paths. Full CI parity for another project requires a suitable adapter. This version does not automatically interpret Actions YAML, run arbitrary build matrices, start service containers, infer pytest/npm/build commands or install arbitrary repository requirements.

## Advanced mode

Use **Advanced** only when you want to run a subset. Individual selectors and **Basic / All / None** presets are available. Unselected checks do not execute and do not appear as skipped results. Selections are remembered per profile.

- Built-in text patterns: private keys, common GitHub/AWS token formats, credential assignments, webhook URLs, emails, home paths and public IPv4 addresses.
- Syntax: JSON, XML, YAML and Python; Python source is parsed without execution.
- Image metadata and OCR: separately selectable.
- Gitleaks file and remote-history scans.
- Known repository scripts and unittest.

Advanced mode uses installed/discoverable tools and its saved per-repository script permission. Use the default Check files flow for automatic managed preparation and the full required verdict. Partial advanced scans do not produce a ready-to-push verdict.

| Row status | Meaning |
| --- | --- |
| PASS | Check completed successfully. |
| WARN | A finding needs review. |
| FAIL | A check reported a problem. |
| ERROR | A test or operation failed to execute correctly. |
| BLOCKED | A selected advanced check could not run; the reason is shown. |
| N/A | No applicable files for a selected advanced check. |

## Execution permission and usage terms

Clicking **Check files** authorizes running the selected repository's validation code and tests with your staged files. The UI states this beside the button and the details remain available through **Usage terms**. There is no repetitive confirmation dialog.

Code executes with your user permissions and may access local files, environment variables or the network. A separate dependency environment and temporary checkout are **not a security sandbox**. Only check repositories and additions whose code you trust; use a disposable VM for stronger isolation. Automatic tool setup never disables TLS verification and does not execute downloaded bootstrap/Gitleaks binaries until their pinned SHA-256 checksums match.

Advanced mode has a separate opt-in permission in Repository settings, saved per canonical owner/repository across its profiles. It covers future code on that repository and can be revoked there. Changing to a different repository does not transfer that permission.

## Settings and data

- Profiles, selections and the private runtime live in the OS application-configuration directory, outside the source project. Application updates preserve them.
- The last successfully connected profile reconnects on startup. Choosing another profile connects it; Check files always refreshes its selected branch again before checking.
- No added file is uploaded. There is no push, commit-to-your-checkout, PR or merge feature.
- Reports contain target paths, repository identifiers and statuses, but no matched secret values or local source paths. Review names and paths before sharing.
- Raw command output is suppressed. Failures show available file locations and missing dependency names without reproducing secret-bearing source lines. Deeper troubleshooting may require running the documented command in a trusted local checkout.
- A failed first setup points to `runtime/setup.log` in the app configuration folder. If an interrupted setup leaves `setup.lock`, close other app instances before removing that stale lock.
- Public GitHub anonymous rate limits apply. Symlinks are rejected during staging. The initial snapshot has archive size/path limits. Built-in advanced scanning supports UTF-8 and limits files to 12 MiB; it is heuristic and has no built-in IPv6 detector. OCR can miss text; screenshots still require manual review.
- Commands run in a background thread with timeouts. There is no cancellation button in this version. Closing is blocked while work is active.

## Standalone distribution to colleagues

To avoid asking colleagues to install Python or pip packages, build on the target operating system:

```bash
python build_app.py
```

The build script creates its own packaging virtual environment and installs PyInstaller there. Output:

- macOS: `dist/RepoCheck.app`
- Windows: distribute the entire `dist/RepoCheck` folder containing `RepoCheck.exe`
- Linux: distribute the entire `dist/RepoCheck` folder
