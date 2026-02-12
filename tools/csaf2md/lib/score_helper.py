from lib.list_helper import flatten
def getScores(vuln, csaf_version):
    '''Get Scores
    Grabs the CVSS scores for the given vulnerability.

    Args:
        vuln:dict, csaf_version:str
    Returns:
        highest_score_obj:dict, generic_scores:list, scores_objs:list
    '''
    errors = []
    # Grab Affected Products
    all_prods = []
    all_prods.append(vuln.get("product_status",{}).get("known_affected",[]))
    all_prods.append(vuln.get("product_status",{}).get("first_affected",[]))
    all_prods.append(vuln.get("product_status",{}).get("last_affected",[]))
    all_prods = flatten(all_prods)

    if not all_prods:
        errors.append(f"Vulnerability {vuln.get('cve','')} is missing affected products (\"known_affected\", \"first_affected\", or \"last_affected\").")

    # Keep track as to not store duplicate scores
    gen_strings = []
    scores_strs = []

    # Counters
    total_prods = len(all_prods)
    largest_size = 0
    high_score = 0.0
    
    # Prep Returns
    highest_score_obj = {}
    generic_scores = []
    scores_objs = []
    
    if csaf_version == "2.0": # CSAF 2.0
        scores = vuln["scores"]
        is_old_version = True
    else: # CSAF 2.1
        scores = vuln["metrics"]
        is_old_version = False
    # Get the score with the largest number of products
    for entry in scores:
        num_prods = len(entry["products"])

        if (num_prods > largest_size) and (not num_prods > total_prods):
            largest_size = num_prods
        if num_prods > total_prods:
            errors.append(f"Vulnerability {vuln.get('cve','')}: CVSS \"scores\" lists products that are not found in the vulnerability's list of affected products (\"known_affected\", \"first_affected\", or \"last_affected\").")

    # Collect scores (keep those pointing to max products separate from the rest)
    for entry in scores:
        num_prods = len(entry["products"])
        if is_old_version:
            keys = entry.keys()
            sc = entry
            score_dict = entry
        else:
            keys = entry["content"].keys()
            sc = entry["content"]
            score_dict = entry["content"].copy()
            score_dict['products'] = entry["products"].copy()
        if "cvss_v4" in keys:
            key = "cvss_v4"
        elif "cvss_v3" in keys:
            key = "cvss_v3"
        else:
            key = "cvss_v2"
        if num_prods == largest_size:
            if float(sc[key]["baseScore"]) > high_score:
                high_score = float(sc[key]["baseScore"])
                highest_score_obj = sc
            if str(score_dict) not in gen_strings:
                generic_scores.append(score_dict)
                gen_strings.append(str(score_dict))
        else:
            if str(score_dict) not in scores_strs:
                scores_objs.append(score_dict)
                scores_strs.append(str(score_dict))

        # Check that each CVSS score has minimum required fields
        for key in keys:
            if "cvss_" in key:
                try:
                    if ((not "version" in sc[key].keys()) or
                        (not "baseScore" in sc[key].keys()) or
                        (not "vectorString" in sc[key].keys())):
                        errors.append(f"Vulnerability {vuln.get('cve','')} CVSS Score is missing required fields (\"version\", \"baseScore\", or \"vectorString\").")
                except:
                    errors.append(f"CVSS Score not formatted correctly in Vulnerability {vuln.get('cve','')}.")
    # Validation Check that all Affected products are scored by CVSS
    for prod in all_prods:
        found = False
        for sco in scores:
            if prod in sco["products"]:
                found = True
        if not found:
            errors.append(f"Product PID {prod}, an affected product, is not scored for Vulnerability {vuln.get('cve','')}.")
    return highest_score_obj, generic_scores, scores_objs, errors
