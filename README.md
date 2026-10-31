# ThreatGraph

### Explainable DFIR & Threat Intelligence Correlation Platform

ThreatGraph is a Python-based investigation support platform designed to
ingest structured digital-forensic evidence, extract and normalize
indicators of compromise (IOCs), preserve evidence provenance, and
identify relationships between investigation samples.

It is intended as an analyst-support and academic cybersecurity project.
It does **not** execute malware or independently acquire disk images,
memory dumps, or raw network captures.

## Key capabilities

-   **Evidence ingestion:** imports supported TXT, LOG, CSV, and JSON
    evidence files.
-   **IOC extraction:** identifies supported indicators such as IPv4
    addresses, domains, URLs, file hashes, and file paths.
-   **Normalization:** canonicalizes supported indicators to make
    comparison and deduplication more consistent.
-   **Provenance tracking:** records the source file and evidence
    location associated with extracted indicators.
-   **Evidence integrity identification:** calculates SHA-256 hashes for
    imported files and uses them to identify duplicate imports within a
    sample.
-   **Cross-sample correlation:** finds indicators shared by multiple
    samples and ranks related sample pairs.
-   **Interactive investigation visualization:** displays relationships
    between samples and indicators.
-   **Structured export:** provides CSV/JSON exports for supported
    investigation data.

> Scope note: PCAP analysis summaries can be imported when represented
> as supported text/CSV/JSON evidence. Direct PCAP parsing is not
> currently implemented.

## Technology stack

-   Python
-   Streamlit
-   SQLite
-   Pandas
-   NetworkX / Graphviz (where used by the current application)
-   HTML, CSS, JavaScript and SVG for interactive graph presentation
-   pytest for automated tests

## Repository structure

The project is organized around the following core modules (adjust this
section if the final repository has a different layout):

``` text
ThreatGraph/
├── app.py
├── src/
│   ├── normalize.py
│   ├── extractors.py
│   ├── ingestion.py
│   ├── database.py
│   ├── pipeline.py
│   └── correlate.py
├── tests/
├── data/
├── requirements.txt
└── README.md
```

The SQLite database is created/used locally under `data/threatgraph.db`
by the application. Do not commit real or confidential investigation
evidence or a populated database to a public repository.

## Requirements

-   Python 3.10 or later is recommended (confirm against the project's
    tested Python version).
-   Git
-   Windows, macOS, or Linux
-   Internet access may be required to install Python dependencies.

## Run ThreatGraph locally

### 1. Clone the repository

``` bash
git clone https://github.com/Lahama09/ThreatGraph.git
cd ThreatGraph
```

### 2. Create and activate a virtual environment

**Windows PowerShell**

``` powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation for the current session:

``` powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux**

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

If `requirements.txt` is present:

``` bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If the repository does not yet contain a complete `requirements.txt`,
install the dependencies listed in the project's dependency file or ask
the project maintainer for the verified list. Do not guess package
versions for a reproducible setup.

### 4. Start the application

``` bash
streamlit run app.py
```

Streamlit will print a local URL, usually:

``` text
http://localhost:8501
```

Open that address in a browser.

### 5. Use the application

1.  Open **Import Evidence**.
2.  Enter a sample identifier and, optionally, a short description.
3.  Upload a supported TXT, LOG, CSV, or JSON evidence file within the
    configured file-size limit.
4.  Import the evidence and review the extraction/import summary.
5.  Explore extracted indicators in **IOC Explorer**.
6.  Review source locations in **Evidence Details**.
7.  Use **Correlation Graph** / the investigation graph views to inspect
    shared indicators and relationships.
8.  Export available results in CSV or JSON format.

Use synthetic, sanitized, or otherwise authorized evidence for
demonstrations. Do not upload confidential case material to an untrusted
or publicly hosted instance.

## Run the automated tests

From the project root, with the virtual environment active:

``` bash
python -m pytest -q
```

The development test run recorded for this project was **69 passing
tests**. Re-run the tests against the current checkout before relying on
that result.

## Safety and limitations

-   ThreatGraph is an investigation-support prototype, not a replacement
    for validated forensic acquisition or analysis tools.
-   It does not execute uploaded files.
-   It does not currently acquire disk images or memory dumps.
-   It does not currently parse raw PCAP files directly; supported
    analysis summaries may be imported as text, CSV, or JSON.
-   Results depend on the quality and completeness of the imported
    evidence and the extraction rules.
-   SHA-256 file hashing identifies file content; it does not by itself
    establish a complete legal chain of custody.
-   Do not treat an extracted IOC as malicious without contextual
    validation.
-   Use only evidence you are authorized to process.

## Project repository

[GitHub: Lahama09/ThreatGraph](https://github.com/Lahama09/ThreatGraph)

## Screenshots

Add current screenshots of the running application here, for example: -
Dashboard / Overview - Evidence import - IOC Explorer - Evidence Details
/ provenance - Correlation Graph - Export view

Suggested location: `docs/screenshots/`. Use sanitized sample data and
remove personal or confidential information before committing
screenshots.

## Author / project details

Add the final author, institution, course, supervisor, and academic-year
details here if required for the submission.
