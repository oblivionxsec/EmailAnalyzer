# Setup

The analyzer uses Python's standard library and runs offline.

```powershell
\.venv\Scripts\Activate.ps1
python -m unittest discover -s analyzer/tests
python -m analyzer.cli.main analyze samples/sample.eml --verbose
```

Optional local analyzers are listed in `requirements-local-tools.txt`. Install them into the project virtual environment with `python -m pip install -r requirements-local-tools.txt`; native tools such as ClamAV and YARA may require separate Windows installation steps. Run them with `--local-tools`:

```powershell
python -m analyzer.cli.main analyze samples/sample.eml --local-tools --verbose
```

Add `--yara-rules path\rules.yar` for a local YARA ruleset or `--clamav` when a local ClamAV daemon is running. Missing optional packages are reported in the JSON instead of stopping the core analysis.

The CLI writes `report.json` by default. Pass `-o path\to\report.json` to choose another destination. Copy that report to `viewer/report.json`, then serve the viewer because browsers block `fetch()` from `file://` pages:

```powershell
python -m http.server 8000 --directory viewer
```

Open `http://localhost:8000`. The same `viewer` directory can be deployed to GitHub Pages.

## API-key security

The downloaded viewer and GitHub Pages version are offline-only. They contain no VirusTotal API key and make no VirusTotal requests. Do not put `VT_API_KEY` in HTML, JavaScript, JSON reports, Git, or GitHub Pages.

VirusTotal enrichment, if added later, must run in a private local process such as the Python CLI. The key should be provided through the process environment or a local ignored secret store, and only the resulting report may be imported into the viewer. Anyone who downloads the viewer can inspect all client-side code, so a browser-held key must always be treated as public.

## Viewer workflow

The viewer has no Node.js or server-side dependency. It starts empty and analyzes the current file selected with **Load .eml / .json**. It can load multiple local `.json` reports or `.eml` files; reports remain in the current browser tab and can be switched from the case-file list. There is no static sample report loaded at startup, so uploading a changed file analyzes its current bytes.

The case-file panel accepts exported VirusTotal JSON for the person using the viewer. GitHub Pages never sends a key or calls the VirusTotal API. Run any authenticated lookup privately, then import the JSON result into the viewer.

The Python CLI remains the full-fidelity analyzer. Browser `.eml` intake is a lightweight review mode for static hosting; use the CLI for recursive archive extraction, MD5 generation, and complete rule analysis, then export the result:

```powershell
python -m analyzer.cli.main analyze path\message.eml -o viewer\report.json --extract-all
```
