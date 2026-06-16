# CSAF2MD
CSAF2MD is a tool that converts CSAF v2.0 JSON files into human-readable Markdown documents.

## Setup
Follow these steps to set up the CSAF2MD tool:

1. Open a terminal or command prompt
2. Navigate to the **csaf2md** directory in this repository
3. (Optional but Recommended) Activate a Virtual Environment to isolate dependencies.
    1. Create the virtual environment.
    
    ```python -m venv .venv```
    
    2. Activate the virtual environment. 
      * On Windows:

      ```.\.venv\Scripts\activate```

      * On macOS/Linux:

      ```source .venv/bin/activate```
4. Install the tool's requirements.

```pip install -r requirements.txt```

## Usage

* By default, CSAF2MD prevents the use of discouraged or prohibited CWEs. To allow these CWEs, set the **BLOCK_BAD_CWES** flag to **FALSE** in **lib/env.py**.
* By default, CSAF2MD shows additional CISA CSAF Recommendations. To hide these recommendations, set the **SHOW_CISA_RECOMMENDATIONS** flag to **FALSE** in **lib/env.py**.
* Place all CSAF JSON files to convert in the **input** directory.
* Run the script: **csaf2md.py**.
* The resulting markdown advisory files are located in the **"output"** directory.
* If any conversion fails, the tool generates **csaf_fail_list.txt** listing the files that could not be converted in the current run of the script, including all generated errors.
* Any optional field considered standard for CISA's advisories but optional to Oasis-Open's standard are given the **INSERT_** tag in the resulting markdown file if not found in the CSAF.

## Validation & Integrity Checking
This tool checks CSAF contents against many of CISA's minimum advisory requirements and generates error messages when applicable. This tool should be used in tandem with CSAF validators that check strictly against the [Oasis-Open CSAF standard](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html).

# CISA REQ CHECK
CISAREQCHECK is a helper tool developed for CSAF2MD. This tool can be run stand-alone to check CSAFs against CISA's additional requirements and recommendations for CSAF security advisories.

## Usage
* Place all CSAF JSON files to check in the **input** directory.
* Run the script: **cisareqcheck.py**.
* For any CSAF that fails, the errors will be recorded in *csaf_fail_list.txt*.

## Summary of CISA Republication Requirements
CSAF Providers looking to republish their CSAFs under CISA should include the following:

* Document Note containing Company Headquarters
* Document Note containing Countries/Areas Deployed (where products are found)
* Document Note containing a list of Critical Infrastructure Sectors where the product is found
* Document Note containing an Advisory Summary (a summary of the potential impact of the risk of the vulnerabilities)
* Products defined in the product_tree with at least vendor/product_name/(product_version or product_version_range) details
* CVE
* CWE
* CVSS v3
* CVE description
* Remediation statement under each CVE
* SSVC vector string found in Vulnerability Notes