def meets_minimum_requirements(csaf):
    '''Meets Minimum Requirements
    Miniature validation function checking for CISA-defined minimum data requirements.

    Args:
        csaf:dict 
    Returns:
        valid:bool
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
    # Check for Product Tree
    if not csaf.get("product_tree", {}):
        valid = False
        errors.append('Missing \"product_tree\".')
    # Check for Vulnerability List
    if not csaf.get("vulnerabilities", []):
        valid = False
        errors.append('Missing \"vulnerabilities\".')
    else: # Vulnerabilities present
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
                    for sco in vuln["metrics"]:
                        if not sco:
                            valid = False
                            errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Empty Metric')
            # Check for Vulnerability Description (notes)
            if not vuln.get("notes", []):
                valid = False
                errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Missing Vulnerability \"notes\".')
            else:
                for note in vuln["notes"]:
                    if not note:
                        valid = False
                        errors.append('\"vulnerabilities\"['+str(vuln_index)+']: Empty Vulnerability Note')
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
    return valid, errors
