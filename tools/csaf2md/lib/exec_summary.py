from lib.product_helper import getAffectedPIDs, findNameOfPID
def getHighestCVSS(csaf:dict)->tuple[float,int]:
    '''Get Highest CVSS Score
    Grab all the scores from the CSAF and keep the highest severity.

    Args:
        csaf:dict
    Returns:
        highscore:float, version:int
    '''
    known_versions = ["2", "3", "4"]
    known_versions.sort(reverse=True)
    scores = {}

    # Prepare score object and csaf score property name.
    for ver in known_versions:
        scores[ver] = []
    if csaf["document"]["csaf_version"] == "2.0":
        prop_name = "scores"
    else:
        prop_name = "metrics"

    # Loop through the vulnerabilities to grab the scores.
    for vuln in csaf["vulnerabilities"]:
        for metric in vuln.get(prop_name, []):
            if prop_name == "metrics": # CSAF 2.1
                if metric.get("content", {}):
                    for ver in known_versions:
                        if metric.get("content", {}).get(f"cvss_v{ver}", {}):
                            scores[ver].append(metric.get("content", {}).get(f"cvss_v{ver}", {}).get("baseScore", 0.0))
            else: # CSAF 2.0
                for ver in known_versions:
                    if metric.get(f"cvss_v{ver}", {}):
                        scores[ver].append(metric.get(f"cvss_v{ver}", {}).get("baseScore", 0.0))
    # Find Highest Score
    highest = {
        "2":0.0,
        "3":0.0,
        "4":0.0
    }
    for ver in known_versions:
        if scores.get(ver, []):
            temp = scores[ver]
            temp.sort(reverse=True)
            highest[ver] = temp[0]
    if highest["4"] == 0.0:
        if highest["3"] == 0.0:
            if highest["2"] == 0.0:
                return 0.0, 4 # Default: There are no scores
            else:
                return highest["2"], 2 # CVSS 2 score is only version available
        else:
            return highest["3"], 3 # CVSS 3 is highest version of scoring available
    else:
        return highest["4"], 4 # Highest score of CVSS 4 within the CSAF
def getAttention(csaf:dict)->tuple[str,list[str]]:
    '''Get Attention
    Generates correct string for Attention section of Executive Summary

    Args:
        csaf:dict
    Returns:
        att:str
        errors:list[str]
    '''
    attention_string = ""
    atten_flags = {
        "remote":False,
        "adjacent":False,
        "local":False,
        "physical":False,
        "low":False
    }

    version_str = csaf["document"]["csaf_version"]
    if version_str == "2.0":
        old_csaf=True
    else:
        old_csaf=False

    errors = []

    def checkFlags(index:int,score:dict)->tuple[str,dict]:
        '''Check the highest vector metrics for CVSS strings.'''
        error = ""
        flags = {
            "remote":False,
            "adjacent":False,
            "local":False,
            "physical":False,
            "low":False
        }
        vers = ""
        if "cvss_v4" in score.keys():
            vers = "v4"
        elif "cvss_v3" in score.keys():
            vers = "v3"
        else:
            vers = "v2"
        vector = score[f"cvss_{vers}"]["vectorString"]
        if not "AV:" in vector or not "AC:" in vector:
            error = f"\"vulnerabilities\"[{index}]: CVSS {vers} score \"vectorString\" is not structured correctly."
        else:
            if ("AV:N" in vector):
                flags["remote"]=True # remote
            elif ("AV:A" in vector):
                flags["adjacent"]=True # adjacent
            elif ("AV:L" in vector):
                flags["local"]=True # local
            elif ("AV:P" in vector):
                flags["physical"]=True # physical
            if ("AC:L" in vector):
                flags["low"]=True # low
        return error,flags

    for vuln_index, vuln in enumerate(csaf["vulnerabilities"]):
        # Collect Attack Vector and Attack Complexity metrics
        try:
            if old_csaf:
                score_list = vuln["scores"]
            else:
                score_list = vuln.get("metrics", [])
            for score in score_list:
                if old_csaf:
                    t_err,t_flags = checkFlags(vuln_index,score)
                else:
                    t_err,t_flags = checkFlags(vuln_index,score['content'])

                if t_err:
                    errors.append(t_err)

                for flag in t_flags.keys():
                    if t_flags[flag]:
                        atten_flags[flag]=True
        except:
            attention_string = "INSERT_ATTENTION"
            if old_csaf:
                errors.append(f"\"vulnerabilities\"[{vuln_index}]->\"scores\" are not structured correctly.")
            else:
                errors.append(f"\"vulnerabilities\"[{vuln_index}]->\"metrics\" are not structured correctly.")
    # Establish Attention string based on "worst" metrics
    if atten_flags["remote"]:
        attention_string += "Exploitable remotely"
    if atten_flags["low"]:
        if atten_flags["remote"]:
            attention_string += "/low attack complexity"
        else:
            attention_string += "Low Attack Complexity"
    if not atten_flags["remote"] and not atten_flags["low"]:
        if atten_flags["adjacent"]:
            attention_string += "Exploitable from adjacent network"
        elif atten_flags["local"]:
            attention_string += "Exploitable from a local network"
        elif atten_flags["physical"]:
            attention_string += "Exploitable with physical access"
    if attention_string == "":
        attention_string = "INSERT_ATTENTION"
        if old_csaf:
            errors.append("Some CVSS \"scores\" are missing Attack Vectors in the \"vectorString\".")
        else:
            errors.append("Some CVSS \"metrics\" are missing Attack Vectors in the \"vectorString\".")
    return attention_string, errors
def getVendor(csaf:dict)->str:
    '''Get Vendor List
    Get list of all vendors in the CSAF product tree branches

    Args:
        csaf:dict
    Returns:
        vendors:str
    '''
    vendors = ""
    vendor_list = []
    vendor_list_dedup = []

    # Recursive Vendor Branch Lookup
    def collectVendors(branch_head,ven_list)->None:
        '''Collect a list of all vendors within the CSAF's Product Tree'''
        if branch_head["category"] == "vendor":
            ven_list.append(branch_head["name"].strip())
        if "branches" in branch_head.keys():
            for branch in branch_head["branches"]:
                collectVendors(branch, ven_list)

    for vendor_branch in csaf.get("product_tree",{}).get("branches",[]):
        collectVendors(vendor_branch,vendor_list)

    # Dedup the vendor list
    vendor_list_dedup = list(set(vendor_list))

    # Concatenate the string
    vendors = ', '.join(vendor_list_dedup) if vendor_list_dedup else "INSERT_VENDOR"

    return vendors.strip()
def getEquipment(csaf:dict)->tuple[list[str],list[str]]:
    '''Get Equipment
    Grab affected product names from the advisory to list in the Equipment section.

    Args:
        csaf:dict
    Returns:
        names:list[str]
        errors:list[str]
    '''
    pid_list, aff_errs = getAffectedPIDs(csaf.get("vulnerabilities",[]))
    names = []
    errors = []
    if aff_errs:
        errors.append(aff_errs)
    for pid in pid_list:
        names.append(findNameOfPID(pid, csaf.get("product_tree",{}),errors,False,False))
    names = list(set(names))
    return names, errors
def getVulnNames(csaf:dict)->tuple[str,list[str]]:
    '''Get Vulnerability Names
    Grab all names of the vulnerability CWEs.

    Args:
        csaf:dict
    Returns:
        vuln_list:str
    '''
    vuln_list = ""

    version_str = csaf["document"]["csaf_version"]
    errors = []
    for vuln_index, vuln in enumerate(csaf.get("vulnerabilities",[])):
        if version_str == "2.0": # CSAF 2.0
            try:
                cwe = vuln["cwe"]["name"]
                if not cwe in vuln_list:
                    if not vuln_list == "":
                        vuln_list += ", "
                    vuln_list += cwe
            except:
                errors.append(f"\"vulnerabilities\"[{vuln_index}]: is missing a CWE \"name\".")
        else: # CSAF 2.1
            try:
                for cwe in vuln["cwes"]:
                    cwe_str = cwe["name"]
                    if not cwe_str in vuln_list:
                        if not vuln_list == "":
                            vuln_list += ", "
                        vuln_list += cwe_str
            except:
                errors.append(f"\"vulnerabilities\"[{vuln_index}]: is missing a CWE \"name\".")
    return vuln_list, errors
def getRiskEvaluation(csaf:dict)->tuple[str,list[str]]:
    '''Get Risk Evaluation
    Generate a Risk Evaluation statement based on CSAF notes.
    This function looks for specific language. If the specific
    language is not found, then Vulnerability Notes are concatenated
    together for the end user to see all together to easily
    summarize into a single statement.

    Args:
        csaf:dict
    Returns:
        risk_evaluation:str
    '''
    csaf_vulns = csaf['vulnerabilities']

    risk_evaluation = ""
    errors = []
    specific_note_found = False

    for note in csaf['document'].get('notes',[]):
        if (note.get("title","").lower().strip() == "advisory summary" and
            note.get("category","") == "summary"):
            re_text = note.get("text","")
            if re_text:
                return re_text,[]
        if note.get("title","").lower() == "risk evaluation" or note.get("title","").lower() == "advisory summary":
            specific_note_found = True
            risk_evaluation += note["text"] + "\n"
        elif note.get('title',"") == "Summary":
            if "Successful exploitation" in note['text']:
                text = note['text'].split("Successful exploitation")[1]
                text = "Successful exploitation " + text.strip()
                text = text.split('.')[0]
                risk_evaluation += text + '.' + "\n"
            elif "could allow" in note['text']:
                text = note['text'].split("could allow")[1]
                if len(csaf_vulns) > 1:
                    sub = "these vulnerabilities"
                else:
                    sub = "this vulnerability"
                text = "Successful exploitation of " + sub + " could allow " + text.strip()
                text = text.split('.')[0]
                risk_evaluation += text + '.' + "\n"

    if risk_evaluation == "":
        for v_index, vulnerability in enumerate(csaf_vulns):
            try:
                for note in vulnerability['notes']:
                    risk_evaluation += note["text"] + " " + "\n"
            except:
                errors.append(f"\"vulnerabilities\"[{v_index}]: Missing a description")
    prefix = "" if specific_note_found else "(INSERT_RISK_EVALUATION: Summarize the risk of exploitation. Review auto-filled text.) "
    risk_evaluation = prefix+risk_evaluation

    return risk_evaluation.strip(), errors
