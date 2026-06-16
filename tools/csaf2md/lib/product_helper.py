from lib.list_helper import flatten
def getBranchNames(branch_head:dict, pid:str, attr:dict={}, errors:list=[], shorten_categories:bool=True)->bool:
    '''Get Branch Names
    Recursive function for the CSAF Product Tree Branches.
    It loops through the branches to find the selected
    product ID (pid). Once found, it returns the names
    of every branch/generation from the top layer down
    to the pid.

    Args:
        branch_head:dict
        pid:str
        attr:dict
        errors:list
        shorten_categories:bool
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
        for branch in branch_head.get("branches",[]): # Loop through the next generation
            found = getBranchNames(branch, pid, attr, errors, shorten_categories=shorten_categories)

            if found: # Record details of generations above leaf
                if shorten_categories:
                    cat = branch_head["category"]
                    if cat == "product_name":
                        cat = "product"
                    elif cat == "product_version" or cat == "product_version_range":
                        cat = "version"
                else:
                    cat = branch_head["category"]
                attr[cat]=branch_head["name"]
                return found
    else: # Record leaf node details
        if shorten_categories:
            cat = branch_head["category"]
            if cat == "product_name":
                cat = "product"
            elif cat == "product_version" or cat == "product_version_range":
                cat = "version"
        else:
            cat = branch_head["category"]
        attr[cat]=branch_head["name"]
    return found
def buildProdName(attr:dict={},separator:bool=True,include_versions:bool=True)->str:
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
def findNameOfPID(pid:str, tree:dict, errors:list, include_versions:bool=True, include_prefix:bool=True)->str:
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
    # THIRD CHECK: Check Relationships for pid (CSAF v2.0 only)
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
    # FOURTH CHECK: Check Product Paths for pid (CSAF v2.1 only)
    for pp_index, ppath in enumerate(tree.get('product_paths', [])):
        fpn_pid = ""
        try:
            fpn_pid = ppath['full_product_name']['product_id']
        except:
            errors.append(f"\"product_tree\"->\"product_paths\"[{pp_index}]->\"full_product_name\" is not constructed correctly.")
        if pid == fpn_pid:
            try:
                lid = ppath['beginning_product_reference']
                l_name = findNameOfPID(lid, tree, errors, include_versions=include_versions, include_prefix=False)
                subpaths = []
                for sub in ppath["subpaths"]:
                    cat = sub['category']
                    rid = sub['next_product_reference']
                    r_name = findNameOfPID(rid, tree, errors, include_versions=include_versions, include_prefix=False)
                    subpaths.append({
                        "category":cat,
                        "name":r_name,
                        "pid":rid
                    })

                if l_name == "":
                    errors.append(f"\"full_product_name\"->\"name\" missing for {lid}")

                combined_name = l_name.strip()
                for sub in subpaths:
                    if not sub["name"]:
                        rid = sub["pid"]
                        errors.append(f"\"full_product_name\"->\"name\" missing for {rid}")
                    else:
                        combined_name = combined_name+' '+sub["category"].replace("_"," ")+' '+sub["name"].strip()+", "

                combined_name = combined_name.strip().rstrip(",")

                if include_prefix:
                    name = "* "+combined_name+": All versions"
                else:
                    name = combined_name
                return name
            except:
                errors.append(f"\"product_tree\"->\"product_paths\"[{pp_index}], with pid {pid}, is not constructed correctly.")
                return name
    return name
def getProducts(csaf:dict, pid_list:list)->tuple[list[str],dict,list[str]]:
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

    def appendCVEList(pid_cves:list)->str:
        '''Adds specific CVEs to product string.'''     # if a pid isn't affected by every CVE in the CSAF.
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
def getCVEPerProduct(csafpid:str, csaf:dict)->list[str]:
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
def getCVEList(csaf:dict)->list[str]:
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
def getAffectedPIDs(vuln_list:list)->list[str]:
    '''Get Affected PIDs
    Returns a list of all affected PIDs under each vulnerability.

    Args:
        vuln_list:list
    Returns:
        a deduped, single dimensional, list of PIDs
    '''
    affected_pids = []
    for vuln in vuln_list:
        affected_pids.append(getAffectedPIDs_Vuln_Specific(vuln))
    if not affected_pids:
        return [], "Missing Affected Products (\"known_affected\", \"first_affected\", or \"last_affected\")."
    return list(set(flatten(affected_pids))), ""
def getAffectedPIDs_Vuln_Specific(vuln:dict,grab_all_affected:bool=True)->list[str]:
    '''Get Affected PID List (Vuln Specific)
    Returns a list of all PIDs Which are affected by a specific vulnerability.

    Args:
        branch_head:dict
        pidList:list
    Returns:
        pid_list:list
    '''
    affected_pids = []

    affected_pids.append(vuln.get("product_status", {}).get("known_affected", []))
    if grab_all_affected:
        affected_pids.append(vuln.get("product_status", {}).get("first_affected", []))
        affected_pids.append(vuln.get("product_status", {}).get("last_affected", []))

    affected_pids = list(set(flatten(affected_pids)))

    return affected_pids
def __getBranchPidList(branch_head:dict, pidList:list)->list[str]:
    '''Get Branch PID List
    Collect every PID within the product tree branches.

    Args:
        branch_head:dict
        pidList:list
    Returns:
        pid_list:list
    '''
    if "product" in branch_head.keys():
        pidList.append(branch_head["product"]["product_id"])
    else:
        for branch in branch_head["branches"]:
            __getBranchPidList(branch, pidList)
def findAllPIDs(tree:dict)->list[str]:
    '''Find All PIDs
    Returns a list of all PIDs created in the CSAF.

    Args:
        tree:dict
    Returns:
        pid_list:list
    '''
    pid_list = []
    # FIRST CHECK: Branches
    for branch in tree.get("branches",[]):
        __getBranchPidList(branch,pid_list)
    # SECOND CHECK: FPNs
    for fpn in tree.get("full_product_names",[]):
        pid_list.append(fpn["product_id"])
    # THIRD CHECK: Relationships (CSAF v2.0 only)
    for rel in tree.get('relationships',[]):
        pid_list.append(rel['full_product_name']['product_id'])
    return pid_list
    # THIRD CHECK: Product Paths (CSAF v2.1 only)
    for ppaths in tree.get('product_paths',[]):
        pid_list.append(ppaths['full_product_name']['product_id'])
    return pid_list
def collectFullnameForPID(branch_head:dict, pid:str, ret_details:dict={})->bool: # Saves the FPN name of the desired leaf node in tree branches
    '''Collect Fullname For PID
    Finds the Fullname for a particular PID

    Returns the Full Product Dictionary.

    Args:
        branch_head:dict
        pid:str
        ret_details:dict
    Returns:
        found:bool
    '''
    found = False
    if "product" in branch_head.keys():
        if pid == branch_head["product"]["product_id"]:
            found = True
        else:
            found = False
    if not found:
        if "branches" in branch_head.keys():
            for branch in branch_head["branches"]:
                found = collectFullnameForPID(branch, pid, ret_details)

                if found:
                    return found
    else:
        ret_details[pid]=branch_head["product"]["name"]
    return found
def fpdBuilderForPID(pid:str, tree:dict,fpd:dict={})->tuple[dict,bool,str]:
    '''FPD Builder For PID
    Finds the branch components for a particular PID

    Returns the Full Product Dictionary.

    Args:
        pid:str
        tree:dict
        fpd:dict
    Returns:
        fpd:dict
        pid_found:bool
        error:str
    '''
    pid_found = False
    def __searchBranch(branch_head, pid, fpd)->tuple[bool,dict]:
        '''Recursive function to traverse tree branches.'''
        found = False
        if branch_head.get("product",{}).get("product_id","") == pid:
            fpd[branch_head['category']] = branch_head['name']
            fpd['full_product_name'] = branch_head['product']['name']
            return True, fpd
        else:
            fpd[branch_head['category']] = branch_head['name']
            for branch in branch_head.get('branches',[]):
                found, fpd = __searchBranch(branch, pid, fpd)
                if found:
                    return found, fpd
        return found, fpd
    error = ""
    try:
        for branch in tree.get("branches",[]):
            pid_found, fpd = __searchBranch(branch, pid, fpd)
            if pid_found:
                break
    except:
        error = "\"product_tree\"->\"branches\" are not formatted correctly."
    return fpd, pid_found, error
def checkTreeGenerations(branches:list)->tuple[int,dict]:
    '''Check Tree Generations
    Calculated the minimum number of generations used in the product_tree.branches

    Returns the details of each branch for further checking.

    Args:
        branches:list
    Returns:
        min_generations:int
        gen_details:dict
    '''
    num_gens = []
    pid_list = []

    # Get list of pids within the product_tree.branches
    for branch in branches:
        __getBranchPidList(branch,pid_list)

    gen_details = {}
    for pid in pid_list:
        gen_details[pid] = {}
        for branch in branches:
            getBranchNames(branch,pid,gen_details[pid],shorten_categories=False)
    for pid in gen_details.keys():
        num_gens.append(len(gen_details[pid].keys()))
    return min(num_gens),gen_details
