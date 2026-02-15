# CSAF2MD
CSAF2MD is a tool that converts CSAF v2.0 JSON files into human-readable Markdown documents.

## Setup
Follow these steps to set up the CSAF2MD tool:

1. Open a terminal or command prompt
2. Navigate to the **csaf2md** directory in this repository
3. Install dependencies with **uv**:

```bash
uv sync
```

### Alternate Setup (pip + venv)
If you prefer not to use uv:

1. Create a virtual environment:

```bash
python -m venv .venv
```

2. Activate it:
* On Windows:

```bash
.\.venv\Scripts\activate
```

* On macOS/Linux:

```bash
source .venv/bin/activate
```

3. Install requirements:

```bash
pip install -r requirements.txt
```

## Usage

* By default, CSAF2MD prevents the use of discouraged or prohibited CWEs. To allow these CWEs, set the **BLOCK_BAD_CWES** flag to **FALSE** in **lib/env.py**.
* Place all CSAF JSON files to convert in the **input** directory.
* Run the script:
  * with uv: `uv run csaf2md.py`
  * with pip/venv: `python csaf2md.py`
* The resulting markdown advisory files are located in the **"output"** directory.
* If any conversion fails, the tool generates **csaf_fail_list.txt** listing the files that could not be converted in the current run of the script, including all generated errors.
* Any optional field considered standard for CISA's advisories but optional to Oasis-Open's standard are given the **INSERT_** tag in the resulting markdown file if not found in the CSAF.

## Validation & Integrity Checking
This tool checks CSAF contents against many of CISA's minimum advisory requirements and generates error messages when applicable. This tool should be used in tandem with CSAF validators that check strictly against the [Oasis-Open CSAF standard](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html).
