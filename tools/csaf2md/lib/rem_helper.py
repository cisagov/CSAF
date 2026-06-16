from lib.product_helper import findNameOfPID, collectFullnameForPID, fpdBuilderForPID
def getVendorMitigations(csaf:dict, pid_list:list)->tuple[dict,list[str]]:
    '''Get Vendor Mitigations
    Build an object of vendor mitigations.

    Args:
        csaf:dict, pid_list:list
    Returns:
        remediations:dict
        errors:list
    '''
    errors = []
    mitigations = [] #all
    vulns = csaf["vulnerabilities"]
    cves = []
    remediations = {} #specific ties remediations to pids

    # Grabs all CVEs in the CSAF
    for vuln in vulns:
        cves.append(vuln["cve"])

    def buildMiti(rem:dict, pid_list:list, csaf:dict)->tuple[dict,list[str]]:
        '''Build Mitigation Object'''
        errors = []
        # Grab the sections of the product tree
        branches = csaf["product_tree"].get("branches", [])
        fpns = csaf["product_tree"].get("full_product_names", [])
        rels = csaf['product_tree'].get('relationships', [])
        ppaths = csaf['product_tree'].get('product_paths', [])
        groups = csaf['product_tree'].get('product_groups',[])

        # Setup mitigation object
        miti = {}
        miti["text"] = ""

        # Grab remediations's pids and gids
        prods = rem.get("product_ids",[])
        gids = rem.get('group_ids', [])

        # Build Product Group Names to include product names under group
        group_name_string = ""
        if gids:
            try:
                for gid in gids:
                    if groups:
                        for group in groups:
                            if gid == group['group_id']:
                                g_pids = group['product_ids']
                                group_name = ""
                                for g in g_pids:
                                    group_name = group_name+findNameOfPID(g, csaf['product_tree'],errors,include_versions=False,include_prefix=False)+', '
                                group_name = group_name.rstrip(', ').strip()
                                if group_name:
                                    if group_name_string:
                                        group_name_string += ', '
                                    group_name_string += '(Product Group: '+group_name+')'
                                break
            except:
                errors.append("\"product_tree\"->\"product_groups\" are not formatted correctly.")
        def buildRemDetails(pid:str,tree_branches:list,full_product_names:list,relationships:list,product_paths:list,tree:dict,details:dict)->list[str]:
            '''Builds the details of the Mitigation Object'''
            brd_errors = []
            if tree_branches: # FIRST CHECK Branches
                for branch_index, branch in enumerate(tree_branches):
                    try:
                        collectFullnameForPID(branch,pid,details)
                    except:
                        brd_errors.append(f"\"product_tree\"->\"branches\"[{branch_index}] is not formatted correctly.")
            if full_product_names: # SECOND CHECK FPNs
                for fpn_index, fpn in enumerate(full_product_names):
                    try:
                        if fpn["product_id"] == pid:
                            details[pid]=fpn["name"]
                            break
                    except:
                        brd_errors.append(f"\"product_tree\"->\"full_product_names\"[{fpn_index}] is not formatted correctly.")
            if relationships: # THIRD CHECK (v2.0 only) Relationships
                for rel_index, rel in enumerate(relationships):
                    try:
                        if rel['full_product_name']['product_id'] == pid:
                            details[pid]=findNameOfPID(pid,tree,brd_errors,include_versions=True,include_prefix=False)
                            break
                    except:
                        brd_errors.append(f"\"product_tree\"->\"relationships\"[{rel_index}]->\"full_product_name\" is not formatted correctly.")
            if product_paths: # FOURTH CHECK (v2.1 only) Product Paths
                for pp_index, ppath in enumerate(product_paths):
                    try:
                        if ppath['full_product_name']['product_id'] == pid:
                            details[pid]=findNameOfPID(pid,tree,brd_errors,include_versions=True,include_prefix=False)
                            break
                    except:
                        brd_errors.append(f"\"product_tree\"->\"product_paths\"[{pp_index}]->\"full_product_name\" is not formatted correctly.")
            return brd_errors

        if len(prods) == len(pid_list): # Remediation affects all affected products to the vulnerability
            if len(prods) == 1:
                prod_1_details = {}
                errors.extend(buildRemDetails(prods[0],branches,fpns,rels,ppaths,csaf['product_tree'],prod_1_details))

                if prods[0] in prod_1_details.keys():
                    miti["text"] = prod_1_details[prods[0]]+": "+rem["details"]
                else:
                    errors.append(f"PID {prods[0]} not found")
            else:
                miti["text"] = "All affected products: "+rem["details"]
        else: # Remediation affects a subset of the vulnerability's affected products
            for pid in prods:
                prod_dets = {}
                errors.extend(buildRemDetails(pid,branches,fpns,rels,ppaths,csaf['product_tree'],prod_dets))

                if pid in prod_dets.keys():
                    if not prod_dets[pid] in group_name_string: # Don't add in a duplicate name
                        miti["text"] = miti["text"] + prod_dets[pid] + ", "
                else:
                    errors.append(f"PID {pid} not found")
                    return {},errors
            # Remove trailing comma
            miti["text"] = miti["text"].rstrip(', ')
            if miti['text']:
                miti["text"] = miti["text"] + ": " + rem["details"]
            else:
                miti["text"] = rem["details"]

        if group_name_string:
            if miti['text'].strip() == rem['details']:
                miti['text'] = group_name_string+': '+miti['text']
            else:
                miti['text'] = group_name_string+', '+miti['text']

        if "url" in rem.keys():
            miti["url"] = rem["url"]
        return miti,errors
    #################
    def isDuplicateMiti(miti:dict, mitigations:list)->bool:
        '''Checks if mitigation is a duplicate'''
        seen = set()
        duplicate = False

        for m in mitigations:
            # Convert dictionary items to a frozenset for hashability
            single_miti = frozenset(m.items())
            seen.add(single_miti)
        hashable_mitis = frozenset(miti.items())
        if hashable_mitis in seen: # Check if miti dictionary exists already in list
            duplicate = True
        return duplicate
    for vuln_index, vuln in enumerate(csaf["vulnerabilities"]):
        try:
            for rem in vuln["remediations"]:
                miti, miti_errors = buildMiti(rem, pid_list, csaf)
                if miti_errors:
                    errors.append(miti_errors)
                if not isDuplicateMiti(miti, mitigations):
                    mitigations.append(miti)
        except:
            errors.append(f"\"vulnerabilities\"[{vuln_index}]->\"remediations\" are missing or incorrectly formatted.")
    for miti in mitigations:
        miti_cves = []
        for vuln in vulns:
            specific_mitis = []
            for rem in vuln["remediations"]:
                spec_miti, spec_err = buildMiti(rem,pid_list,csaf)
                if spec_err:
                    errors.append(spec_err)
                if spec_miti:
                    specific_mitis.append(spec_miti)
            if isDuplicateMiti(miti, specific_mitis):
                miti_cves.append(vuln["cve"])
        if sorted(miti_cves) == sorted(cves):
            if not ("all" in remediations.keys()):
                remediations["all"] = []
            remediations["all"].append(miti)
        else:
            key = " ".join(miti_cves)
            key = key.strip()
            key = key.replace(" ", ", ")
            if not (key in remediations.keys()):
                remediations[key] = []
            remediations[key].append(miti)

    return remediations, errors
def getFullProductDictionary(pid:str, tree:dict, fpd:dict={})->tuple[dict,list[str]]:
    '''Get Full Product Dictionary
    Builds a dictionary of just the Full Product Name Details of a pid.

    Args:
        pid:str, tree:dict, fpd:dict
    Returns:
        fpd:dict
        errors:list
    '''
    found_pid_in_branches = False
    errors = []
    # Search Branches in Product_Tree
    fpd, found_pid_in_branches, fpd_err = fpdBuilderForPID(pid, tree, fpd)
    if fpd_err:
        errors.append(fpd_err)
    if fpd == {} or not found_pid_in_branches:
        fpd = {}
        # Search Full Product Name List in Product_Tree
        for fpn_index, fpn in enumerate(tree.get('full_product_names', [])):
            try:
                if pid == fpn['product_id']:
                    fpd["full_product_name"]=fpn['name']
            except:
                errors.append(f"\"product_tree\"->\"full_product_names\"[{fpn_index}] is not formatted correctly.")
        # Search Relationships/Product_Paths in Product_Tree
        for rel_index, rel in enumerate(tree.get('relationships',[])):
            try:
                if pid == rel['full_product_name']['product_id']:
                    fpd['full_product_name']=rel['full_product_name']['name']
            except:
                errors.append(f"\"product_tree\"->\"relationships\"[{rel_index}]->\"full_product_name\" is not formatted correctly.")
        for pp_index, ppath in enumerate(tree.get('product_paths',[])):
            try:
                if pid == ppath['full_product_name']['product_id']:
                    fpd['full_product_name']=ppath['full_product_name']['name']
            except:
                errors.append(f"\"product_tree\"->\"product_paths\"[{pp_index}]->\"full_product_name\" is not formatted correctly.")
    return fpd, errors
def getFixedMitigations(csaf:dict)->tuple[list[str],list[str]]:
    '''Get Fixed Mitigations
    Grabs product names of those marked as "fixed" for each CVE.

    Args:
        csaf:dict
    Returns:
        fixed:list
        errors:list
    '''
    fixed = []
    errors = []
    for vuln in csaf["vulnerabilities"]:
        cve = vuln["cve"]
        fixed_pids = vuln["product_status"].get("fixed", [])
        if fixed_pids:
            for pid in fixed_pids:
                fpd,fpd_errs = getFullProductDictionary(pid, csaf["product_tree"])

                if fpd_errs:
                    errors.append(fpd_errs)
                if fpd == None or fpd == {}:
                    errors.append('ERROR: Issue in reading the PIDs of the CSAF')
                    return [],errors

                fixed_version = fpd.get("full_product_name", "").replace(fpd.get("vendor", ""), "").strip()
                if not fixed_version:
                    fixed_version = f"{fpd.get('product_name','')} {fpd.get('product_version','') if fpd.get('product_version', '') else fpd.get('product_version_range', '')}"
                if fixed_version:
                    fixed.append(f"{fixed_version} {'is a' if 'product_version' in fpd.keys() else 'are'} fixed {'version' if 'product_version' in fpd.keys() else 'versions'} for {cve}")
    return fixed, errors
