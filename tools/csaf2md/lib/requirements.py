import os
import json
from lib.product_helper import checkTreeGenerations
def __getSectors()->list[str]:
    '''Get Sectors
    Returns a list of the 16 Unitied States Critical Infrastructure Sectors

    Args:
        None
    Returns:
        sectors: list[str]
    '''
    sectors = [
        "Chemical",
        "Commercial Facilities",
        "Communications",
        "Critical Manufacturing",
        "Dams",
        "Defense Industrial Base",
        "Emergency Services",
        "Energy",
        "Financial Services",
        "Food and Agriculture",
        "Government Services and Facilities",
        "Healthcare and Public Health",
        "Information Technology",
        "Nuclear Reactors, Materials, and Waste",
        "Transportation Systems",
        "Water and Wastewater"
    ]
    return sectors
def __meets_minimum_requirements(csaf:dict,validation:bool=False)->tuple[bool,list[str]]:
    '''Meets Minimum Requirements
    Miniature validation function checking for CISA-defined minimum data requirements.

    Args:
        csaf:dict
        validation:bool
    Returns:
        valid:bool
        errors:list
    '''

    valid = True
    errors = []

    is_old_csaf = csaf.get("document",{}).get("csaf_version","") == "2.0"

    # Check Document
    if not csaf.get("document",{}):
        valid = False
        errors.append('Missing \"document\".')
    else:
        # Document Tracking ID
        if not csaf.get("document",{}).get("tracking",{}).get("id",""):
            valid = False
            errors.append("Missing \"document\"->\"tracking\"->\"id\".")
        # Document Tracking Revision History
        if not csaf.get("document",{}).get("tracking",{}).get("revision_history",[]):
            valid = False
            errors.append("Missing \"document\"->\"tracking\"->\"revision_history\".")
        # Document Title
        if not csaf.get("document",{}).get("title",""):
            valid = False
            errors.append("Missing \"document\"->\"title\".")
        # Document Publisher Name
        if not csaf.get("document",{}).get("publisher",{}).get("name",""):
            valid = False
            errors.append("Missing \"document\"->\"publisher\"->\"name\".")
        if validation: # Extra Checks
            # Document Language
            if not csaf.get("document",{}).get("lang",""):
                valid = False
                errors.append("Missing \"document\"->\"lang\".")
            else:
                if not "en" in csaf.get("document",{}).get("lang",""):
                    valid = False
                    errors.append("\"document\"->\"lang\" must contain the \'en\' language code or prefix.")
            # Document Acknowledgments
            if not csaf.get("document",{}).get("acknowledgments",[]):
                valid = False
                errors.append("Missing \"document\"->\"acknowledgments\".")
            else:
                for ack_index, ack in enumerate(csaf.get("document",{}).get("acknowledgments",[])):
                    has_summary = False
                    has_name_or_org = False

                    if "summary" in ack.keys():
                        has_summary = True
                    if "names" in ack.keys() or "organization" in ack.keys():
                        has_name_or_org = True

                    if not (has_name_or_org and has_summary):
                        valid = False
                        errors.append('\"document\"->\"acknowledgments\"['+str(ack_index)+']: Does not contain both a \"summary\" and either \"names\" or \"organization\".')
            # Document Notes
            if not csaf.get("document",{}).get("notes",[]):
                valid = False
                errors.append("Missing \"document\"->\"notes\".")
            else:
                has_adv_summary = False
                has_deployed = False
                has_headquarters = False
                has_sectors = False
                sectors_correct = True
                sector_list = __getSectors()
                sector_index = 0
                for note_index, note in enumerate(csaf.get("document",{}).get("notes",[])):
                    if note.get("title","") == "Advisory Summary" and note.get("category","") == "summary":
                        has_adv_summary = True
                    if note.get("title","") == "Countries/areas deployed" and note.get("category","") == "other":
                        has_deployed = True
                    if note.get("title","") == "Company headquarters location" and note.get("category","") == "other":
                        has_headquarters = True
                    if note.get("title","") == "Critical infrastructure sectors" and note.get("category","") == "other":
                        sector_index = note_index
                        has_sectors = True
                        adv_sectors = [item.strip() for item in note.get("text","").split(',')]
                        if any(item not in sector_list for item in adv_sectors):
                            sectors_correct = False

                if not has_adv_summary:
                    valid = False
                    errors.append('\"document\"->\"notes\"[]: Is missing a note with title \"Advisory Summary\" and category \"summary\".')
                if not has_deployed:
                    valid = False
                    errors.append('\"document\"->\"notes\"[]: Is missing a note with title \"Countries/areas deployed\" and category \"other\".')
                if not has_headquarters:
                    valid = False
                    errors.append('\"document\"->\"notes\"[]: Is missing a note with title \"Company headquarters location\" and category \"other\".')
                if not has_sectors:
                    valid = False
                    errors.append('\"document\"->\"notes\"[]: Is missing a note with title \"Critical infrastructure sectors\" and category \"other\".')
                if not sectors_correct:
                    valid = False
                    errors.append(f'\"document\"->\"notes\"[{sector_index}]: The sector list contains "{list(set(adv_sectors) - set(sector_list))}" which is not in CISA\'s critical infrastructure sectors.')
    # Check for Product Tree
    if not csaf.get("product_tree", {}):
        valid = False
        errors.append('Missing \"product_tree\".')
    elif validation: # Extra Checks
        if not csaf.get("product_tree", {}).get("branches",[]):
            valid = False
            errors.append('Missing \"product_tree\"->\"branches\".')
        else:
            # Check minimum generation
            minGeneration,gen_details = checkTreeGenerations(csaf['product_tree']['branches'])
            if minGeneration < 3:
                valid = False
                errors.append('\"product_tree\" has a branch that doesn\'t have the minimum number of generations: 3.')
            # Check that first generation is vendor, last generation is product_version or product_version_range
            for pid in gen_details.keys():
                pid_details = gen_details[pid]
                pid_details = dict(reversed(list(pid_details.items())))

                if not list(pid_details.keys())[0] == "vendor":
                    errors.append(f"\"product_tree\"->\"branches\"->PID: {pid} is missing \"vendor\" as its first branch generation.")
                if not(list(pid_details.keys())[-1] == "product_version" or list(pid_details.keys())[-1] == "product_version_range"):
                    errors.append(f"\"product_tree\"->\"branches\"->PID: {pid} is missing \"product_version\" or \"product_version_range\" as its final branch generation.")
                if not "product_name" in pid_details.keys():
                    errors.append(f"\"product_tree\"->\"branches\"->PID: {pid} is missing a \"product_name\" branch.")
        if errors:
            valid = False
    # Check for Vulnerability List
    if not csaf.get("vulnerabilities", []):
        valid = False
        errors.append('Missing \"vulnerabilities\".')
    else: # Vulnerabilities present
        known_affected_found = False
        for vuln_index, vuln in enumerate(csaf["vulnerabilities"]):
            # Check for CVEs
            if not "cve" in vuln.keys():
                valid = False
                errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing \"cve\".')
            # Check for CWE and CVSS Scores
            if is_old_csaf: # CSAF 2.0
                if not vuln.get("cwe", {}):
                    valid = False
                    errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing \"cwe\".')
                if not vuln.get("scores", []):
                    valid = False
                    errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing \"scores\".')
                else:
                    for sco in vuln["scores"]:
                        if not sco:
                            valid = False
                            errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Empty Score.')
                        elif not "cvss_v3" in sco.keys():
                            errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing CVSSv3 score.')

            else: # CSAF 2.1
                if not "cwes" in vuln.keys():
                    valid = False
                    errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing \"cwes\".')
                else:
                    for cwe in vuln["cwes"]:
                        if not cwe:
                            valid = False
                            errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Empty CWE.')
                if not vuln.get("metrics", []):
                    valid = False
                    errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing \"metrics\".')
                else:
                    v3_exists = False
                    for sco in vuln["metrics"]:
                        if not sco:
                            valid = False
                            errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Empty Metric')
                        elif "cvss_v3" in sco.get("content",{}).keys():
                            v3_exists = True
                    if not v3_exists:
                        errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing CVSSv3 score.')
            # Check for Vulnerability Description (notes)
            if not vuln.get("notes", []):
                valid = False
                errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing Vulnerability \"notes\".')
            elif validation:
                if len(vuln["notes"]) < 2:
                    valid = False
                    errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Two notes expected minimum. Must include both a description and an SSVC.')
                ssvc_found = False
                for note in vuln["notes"]:
                    if not note:
                        valid = False
                        errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Empty Vulnerability Note')
                    if note.get("category","") == "details" and ("SSVCv2" in note.get("text","") and "/E:" in note.get("text","") and "/A:" in note.get("text","") and "SSVC" == note.get("title","").upper()):
                        # Check for a minimum number of metrics
                        temp_note = note.get("text","")
                        if temp_note[-1] == "/":
                            temp_note = temp_note[:-1]
                        sections = temp_note.split("/")
                        if len(sections) >= 4 and ("T" in sections[-1] and "Z" in sections[-1]):
                            ssvc_found = True
                if not ssvc_found:
                    valid = False
                    errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing SSVC details note with proper title and minimum metrics (Exploitation, Automatable, Timestamp).')
            # Check for Remediations
            if not vuln.get("remediations", []):
                valid = False
                errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing \"remediations\".')
            else:
                for rem in vuln["remediations"]:
                    if not rem:
                        valid = False
                        errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Empty Remediation')
            # Check for Product Status
            if not vuln.get("product_status", {}):
                valid = False
                errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing Vulnerability \"product_status\".')
            else: # Check for Known Affected
                if (not vuln["product_status"].get("known_affected", []) and
                    not vuln["product_status"].get("first_affected", []) and
                    not vuln["product_status"].get("last_affected", [])):
                    valid = False
                    errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing Affected Products (\"known_affected\", \"first_affected\", or \"last_affected\").')
                if "known_affected" in vuln["product_status"].keys():
                    known_affected_found = True
        if validation and not known_affected_found:
            valid = False
            errors.append("Missing requirement: at least one \"known_affected\" product referenced in the CSAF.")
    return valid, errors
def meets_suggested_recommendations(csaf:dict)->tuple[bool,list[str]]:
    '''Meets Suggested Recommendations
    Miniature validation function checking for CISA-defined suggested data recommendations.

    Args:
        csaf:dict
    Returns:
        as_recommended:bool
        notes:list
    '''
    as_recommended = True
    notes = []

    is_old_csaf = csaf.get("document",{}).get("csaf_version","") == "2.0"

    # document.references[] self reference exists
    self_reference = False
    for reference in csaf['document'].get('references',[]):
        if reference.get('category','').lower().strip() == 'self':
            self_reference = True
    if not self_reference:
        as_recommended = False
        notes.append("Missing \"document\"->\"references\" reference with category 'self'.")

    # Check Vulnerability List

    statuspath = os.path.dirname(os.path.abspath(__file__)) + os.sep + 'cwe_status.json'

    with open(statuspath) as infile:
        cwe_status = json.load(infile)["status"]

    for vuln_index, vuln in enumerate(csaf["vulnerabilities"]):
        # vulnerabilities[].cwe – Vulnerability Mapping status
        if is_old_csaf: # handle the CSAF 2.0 case
            if "Allowed" not in cwe_status[vuln.get("cwe",{})["id"]]:
                as_recommended = False
                notes.append('\"vulnerabilities\"['+str(vuln_index)+']: CWE does not have \"Allowed\" status.')
        else:  # handle the CSAF 2.1 case
            for cwe_index, cwe in enumerate(vuln.get("cwes",[])):
                if "Allowed" not in cwe_status.get(cwe["id"],""):
                    as_recommended = False
                    notes.append('\"vulnerabilities\"['+str(vuln_index)+']: cwes['+str(cwe_index)+f'] {cwe["id"]} does not have \"Allowed\" status.')

        # vulnerabilities[].references[] – URL references
        cve_reference = False
        cwe_reference = False
        cvss3_reference = False
        cvss4_reference = False
        for reference in vuln.get('references',[]):
            if "www.cve.org/CVERecord?id=" in reference.get('url',''):
                cve_reference = True
            if "cwe.mitre.org/data/definitions/" in reference.get('url',''):
                cwe_reference = True
            if "www.first.org/cvss/calculator/3.1#CVSS:3.1" in reference.get('url',''):
                cvss3_reference = True
            if "www.first.org/cvss/calculator/4.0#CVSS:4.0" in reference.get('url',''):
                cvss4_reference = True
        if not cve_reference:
            as_recommended = False
            notes.append('\"vulnerabilities\"['+str(vuln_index)+']: References do not include a link to the CVE record.')
        if not cwe_reference:
            as_recommended = False
            notes.append('\"vulnerabilities\"['+str(vuln_index)+']: References do not include a link to the CWE definition.')
        if not cvss3_reference:
            as_recommended = False
            notes.append('\"vulnerabilities\"['+str(vuln_index)+']: References do not include a link to the CVSSv3 vector string.')
        if not cvss4_reference:
            as_recommended = False
            notes.append('\"vulnerabilities\"['+str(vuln_index)+']: References do not include a link to the CVSSv4 vector string.')

        # vulnerabilities[].notes[] – Additional SSVC metrics
        ssvc_additional_metrics = False
        for note in vuln.get('notes',[]):
            if "ssvc" in note.get('title','').lower().strip():
                temp_note = note.get("text","")
                if temp_note[-1] == "/":
                    temp_note = temp_note[:-1]
                sections = temp_note.split("/")
                if len(sections) > 4 and ("T" in sections[-1] and "Z" in sections[-1]):
                    ssvc_additional_metrics = True
        if not ssvc_additional_metrics:
            as_recommended = False
            notes.append('\"vulnerabilities\"['+str(vuln_index)+']: SSVC note does not include additional SSVC metrics.')


    return as_recommended, notes
