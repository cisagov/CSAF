def checkBadCWEs(csaf:dict,cwe_status:dict)->bool:
    '''Check for Bad CWEs in the CSAF
    Process the contents of a CSAF to and check for bad CWEs.

    Args:
        csaf:dict,
        cwe_status:dict
    Returns:
        foundBadCWEs:bool
    '''

    CRED = '\033[91m'
    CEND = '\033[0m'

    foundBadCWEs = False
    def checkCWEStatus(cwe_id:str, adv_id:str, identifier:str)->bool:
        '''Checks the CWE-ID status according to the packaged CWE library version.'''
        for cwe_item in cwe_status['status'].keys():
            if cwe_id == cwe_item:
                if cwe_status['status'][cwe_item].lower() == 'prohibited' or cwe_status['status'][cwe_item].lower() == 'discouraged':
                    print(CRED+f"{adv_id}: {cwe_id} in vulnerability {identifier} is {cwe_status['status'][cwe_item].upper()}!!!!!"+CEND)
                    return True
        return False
    adv_id = csaf['document']['tracking']['id']
    for v_id, vuln in enumerate(csaf.get('vulnerabilities',[])):
        identifier = vuln.get("cve","")
        if not identifier:
            identifier = vuln.get("title","")
        if not identifier:
            identifier = f"[{v_id}]"
        # Check CWEs
        if csaf['document']['csaf_version'] == "2.0":
            cwe_id = vuln.get('cwe',{}).get('id',"")
            if checkCWEStatus(cwe_id,adv_id,identifier):
                foundBadCWEs = True
        else:
            for cwe in vuln.get("cwes",[]):
                cwe_id = cwe.get('id',"")
                if checkCWEStatus(cwe_id,adv_id,identifier):
                    foundBadCWEs = True
    return foundBadCWEs
