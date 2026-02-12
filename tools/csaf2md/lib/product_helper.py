from lib.list_helper import flatten
def getBranchNames(branch_head, pid, attr={}, errors=[]):
    '''Get Branch Names
    Recursive function for the CSAF Product Tree Branches.
    It loops through the branches to find the selected
    product ID (pid). Once found, it returns the names
    of every branch/generation from the top layer down
    to the pid.

    Args:
        branch_head:dict, pid:str, attr:dict
    Returns:
        found:bool
    '''
    found = False
    if "product" in branch_head.keys(): # Found a leaf node
        try:
            if pid == branch_head["product"]["product_id"]:
                found = True
        except:
            errors.append("ERROR in \"product_tree\"->\"branches\": Leaf Node doesn't have a \"product_id\".")
            return False
    if not found:
        if "branches" in branch_head.keys():
            for branch in branch_head["branches"]: # Loop through the next generation
                found = getBranchNames(branch, pid, attr, errors)

                if found: # Record details of generations above leaf
                    cat = branch_head["category"]
                    if cat == "product_name":
                        cat = "product"
                    elif cat == "product_version" or cat == "product_version_range":
                        cat = "version"
                    attr[cat]=branch_head["name"]
                    return found
    else: # Record leaf node details
        cat = branch_head["category"]
        if cat == "product_name":
            cat = "product"
        elif cat == "product_version" or cat == "product_version_range":
            cat = "version"
        attr[cat]=branch_head["name"]
    return found
def buildProdName(attr={},separator=True,include_versions=True):
    '''Build Prod Name
    Build a full product name string from branch names.

    Args:
        attr:dict, separator:bool
    Returns:
        name:str
    '''
    name = "* " # Markdown bullet for a bulleted list
    has_vers = True if "version" in attr.keys() else False
    first = True
    for ibute in attr.keys():
        if ibute == "version" and include_versions:
            if not first:
                if separator:
                    name = name.strip() + ": " + attr[ibute] + " "
                else:
                    name = name.strip() + " (" + attr[ibute] + ") "
                continue
            else:
                name += attr[ibute] + " "
        elif not ibute == "version":
            name += attr[ibute] + " "
        first = False
    if not has_vers and include_versions: # If no version is given for a product, all versions are assumed.
        if separator:
            name = name.strip() + ": vers:all/*"
        else:
            name = name.strip() + " (All versions)"
    return name.strip()
def findNameOfPID(pid:str, tree:dict, errors:list, include_versions=True, include_prefix=True):
    '''Find Name of PID
    Build a full product name string from any pid in the 
    CSAF product tree.

    Args:
        pid:str, tree:dict, include_versions:bool
    Returns:
        name:str
    '''
    name = ""
    attr = {}
    # FIRST CHECK: Check Branches for pid
    for branch in tree.get('branches', []):
        getBranchNames(branch,pid,attr,errors)
    if attr:
        attr = dict(reversed(list(attr.items())))
        if include_prefix:
            name = buildProdName(attr,include_versions=include_versions)
        else:
            name = buildProdName(attr, separator=False,include_versions=include_versions)[1:].strip()
        return name
    # SECOND CHECK: Check Full Product Name List for pid
    for fpn in tree.get('full_product_names',[]):
        if pid == fpn.get('product_id',""):
            if include_versions:
                if include_prefix:
                    name = "* "+fpn['name'].strip()+': All versions'
                else:
                    name = fpn['name'].strip()+' (All versions)'
                return name
            else:
                return fpn['name'].strip()
    # THIRD CHECK: Check Relationships for pid
    for rel_index, rel in enumerate(tree.get('relationships', [])):
        fpn_pid = ""
        try:
            fpn_pid = rel['full_product_name']['product_id']
        except:
            errors.append(f"\"product_tree\"->\"relationships\"[{rel_index}]->\"full_product_name\" is not constructed correctly.")
        if pid == fpn_pid:
            try:
                cat = rel['category']
                lid = rel['product_reference']
                l_name = findNameOfPID(lid, tree, errors, include_versions=include_versions, include_prefix=False)
                rid = rel['relates_to_product_reference']
                r_name = findNameOfPID(rid, tree, errors, include_versions=include_versions, include_prefix=False)

                if l_name == "" or r_name == "":
                    errors.append(f"\"full_product_name\"->\"name\" missing for {lid} or {rid}")

                combined_name = l_name.strip()+' '+cat.replace('_',' ')+' '+r_name.strip()
                if include_prefix:
                    name = "* "+combined_name+": All versions"
                else:
                    name = combined_name
                return name
            except:
                errors.append(f"\"product_tree\"->\"relationships\"[{rel_index}], with pid {pid}, is not constructed correctly.")
                return name

    return name
def getProducts(csaf, pid_list):
    '''Get Products
    Build a full bulleted list of products for the markdown.
    Also builds a reference prod_mapper to be used later if
    Product Impact section is needed.

    Args:
        csaf:dict, pid_list:list
    Returns:
        prods:list, prod_mapper:dict
    '''
    prods = []
    prod_mapper = {}
    errors = []

    # Grab all CVEs in the CSAF
    all_cves = getCVEList(csaf)

    # Helper function that adds specific CVEs to product string
    # if a pid isn't affected by every CVE in the CSAF.
    def appendCVEList(pid_cves):
        substr = ""
        for pv in pid_cves:
            if substr == "":
                substr = "("
            substr = substr + pv + ", "
        substr = substr.strip()
        if substr:
            if substr[-1] == ',':
                substr = substr[:-1]
            substr = substr + ')'
        if "()" in substr:
            substr = substr.replace("()","")
        return substr

    for pid in pid_list: #Branches
        p_name = ""
        impact_id=""

        # Find name of a product with pid
        p_name = findNameOfPID(pid,csaf["product_tree"],errors)

        # Build Prod Mapper - used for optional section "PRODUCT IMPACT" of markdown
        prod_mapper[pid] = {}
        
        attr = {}
        for branch in csaf["product_tree"].get("branches",[]):
            getBranchNames(branch,pid,attr,errors)
        
        if attr:
            attr = dict(reversed(list(attr.items())))
            for ibute in attr.keys():
                prod_mapper[pid][ibute]=attr[ibute]
                if not (ibute == "version"):
                    impact_id += attr[ibute] + " "
        else:
            impact_id = p_name[:p_name.rfind(":")]
        impact_id = impact_id.strip() + "; "
        prod_mapper[pid]["impact_id"]=impact_id

        # Add necessary unique CVEs to product name string
        pid_cves = getCVEPerProduct(pid, csaf)
        if not (len(pid_cves) == len(all_cves)):
            p_name += " " + appendCVEList(pid_cves)
        
        prods.append(p_name.strip())
   
    # Return product string list (Affected Product Section) and prod_mapper (Product Impact Section)
    return prods, prod_mapper, errors
def getCVEPerProduct(csafpid, csaf):
    '''Get CVE Per Product
    Returns a list of CVEs for which this pid is affected.

    Args:
        csafpid:str, csaf:dict
    Returns:
        cve_list:list
    '''
    cve_list = []
    for vuln in csaf["vulnerabilities"]:
        if ("cve" in vuln.keys() and 
            (csafpid in vuln["product_status"].get("known_affected",[]) or
             csafpid in vuln["product_status"].get("first_affected",[]) or 
             csafpid in vuln["product_status"].get("last_affected",[]))):
            cve_list.append(vuln["cve"])

    return cve_list
def getCVEList(csaf):
    '''Get CVE List
    Returns a list all CVEs listed in the CSAF.

    Args:
        csaf:dict
    Returns:
        cve_list:list
    '''
    cve_list = []
    for vuln in csaf["vulnerabilities"]:
        if "cve" in vuln.keys():
            cve_list.append(vuln["cve"])
    return cve_list
def getAffectedPIDs(vuln_list):
    '''Get Affected PIDs
    Returns a list of all affected PIDs under each vulnerability.

    Args:
        vuln_list:list 
    Returns:
        a deduped, single dimensional, list of PIDs
    '''
    affected_pids = []
    for vuln in vuln_list:
        affected_pids.append(vuln.get("product_status", {}).get("known_affected", []))
        affected_pids.append(vuln.get("product_status", {}).get("first_affected", []))
        affected_pids.append(vuln.get("product_status", {}).get("last_affected", []))
    if not affected_pids:
        return [], "Missing Affected Products (\"known_affected\", \"first_affected\", or \"last_affected\")."
    return list(set(flatten(affected_pids))), ""
def findAllPIDs(tree):
    '''Find All PIDs
    Returns a list of all PIDs created in the CSAF.

    Args:
        tree:dict
    Returns:
        pid_list:list
    '''
    pid_list = []
    # FIRST CHECK: Branches
    def searchBranch(branch_head, pidList):
        if "product" in branch_head.keys():
            pidList.append(branch_head["product"]["product_id"])
        else:
            for branch in branch_head["branches"]:
                searchBranch(branch, pidList)
    for branch in tree.get("branches",[]):
        searchBranch(branch,pid_list)
    # SECOND CHECK: FPNs
    for fpn in tree.get("full_product_names",[]):
        pid_list.append(fpn["product_id"])
    # THIRD CHECK: Relationships
    for rel in tree.get('relationships',[]):
        pid_list.append(rel['full_product_name']['product_id'])
    return pid_list