####################################################################
# Title: CSAF to Markdown - CISA Markdown Creator
# Author: Matthew Stradling, Israel Bentley
# Org: Idaho National Laboratory on behalf of 
#       Cybersecurity and Infrastructure Security Agency (CISA)
####################################################################
##########################
# Python Standard Library
##########################
from datetime import datetime
import os
import json
import re
import traceback
import ast
##########################
# MIT License
##########################
from mdutils.mdutils import MdUtils
from mdutils import Html

##########################
# Import Custom Files
##########################
from lib.env import *
from lib.exec_summary import *
from lib.list_helper import flatten
from lib.product_helper import *
from lib.rem_helper import *
from lib.score_helper import getScores
from lib.requirements import meets_minimum_requirements

# Styling for output
CGREEN = '\033[92m'
CRED = '\033[91m'
CEND = '\033[0m'

# Read files in from directory
workingdir = os.path.dirname(os.path.abspath(__file__))
inputdir = os.path.join(workingdir + os.sep + 'input')
outdir = os.path.join(workingdir + os.sep + 'output')

statuspath = workingdir + os.sep + 'lib' + os.sep + 'cwe_status.json'

with open(statuspath) as infile:
    cwe_status = json.load(infile)

def checkBadCWEs(csaf):
    '''Check for Bad CWEs in the CSAF
    Process the contents of a CSAF to and check for bad CWEs.

    Args:
        csaf:dict 
    Returns:
        foundBadCWEs:bool
    '''
    foundBadCWEs = False
    def checkCWEStatus(cwe_id:str, adv_id:str, identifier:str):
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
def processJson(in_csaf, out_md): 
    '''Process JSON
    Process the contents of a CSAF to generate a Markdown representation
    of the information.

    Args:
        in_csaf:str, out_md:str 
    Returns:
        None
    '''
    errors = []
    error_header = " failed with errors:"
    error_tail = "#"*4
    csaf_name = in_csaf.split(os.sep)[-1]
    try:
        with open(in_csaf, 'r', encoding="utf-8") as json_file:
            data = json.loads(json_file.read())
            data = ast.literal_eval(str(data).replace('\\n',' ').replace('\\r',''))
            can_process, temp_errs = meets_minimum_requirements(data)
            has_bad_cwes = checkBadCWEs(data)
            stop_conversion = has_bad_cwes and BLOCK_BAD_CWES
            if can_process and not stop_conversion:
                # Affected Pids will grab relationships, branches, and fpns that are marked as first/last/known affected.
                affected_pid_list, gap_err = getAffectedPIDs(data["vulnerabilities"])
                affected_pid_list = sorted(affected_pid_list)
                if gap_err:
                    errors.append(gap_err)

                mdFile = MdUtils(file_name=out_md)

                # Default Headers
                mdFile.new_header(level=2, title=data["document"]["tracking"]["id"].upper(), add_table_of_contents="n")
                mdFile.new_header(level=2, title=data["document"]["title"], add_table_of_contents="n")

                self_refs = []
                for ref in data['document'].get('references',[]):
                    if ref.get('category','') == 'self':
                        self_refs.append(ref)

                if self_refs:
                    mdFile.new_line(f"**[View Source]({self_refs[0]['url']})**")
                mdFile.new_line()
                
                # 1. Executive Summary
                mdFile.new_header(level=2, title='1. EXECUTIVE SUMMARY', add_table_of_contents="n")
                score, score_vers = getHighestCVSS(data)
                attention, attn_errors = getAttention(data)
                if attn_errors:
                    errors.append(attn_errors)
                vendors = getVendor(data)
                equip_list, equip_errs = getEquipment(data)
                if equip_errs:
                    errors.append("There are issues in the \"product_tree\".")
                equip = "(INSERT_EQUIPMENT_LIST) "+", ".join(equip_list)
                es_vulns, v_name_errors = getVulnNames(data)

                if v_name_errors:
                    errors.append(v_name_errors)

                if len(data["vulnerabilities"]) > 1:
                    es_v_head = "Vulnerabilities"
                else:
                    es_v_head = "Vulnerability"

                # Places highest CVSS score in executive summary
                if score_vers == 4:
                    es_head = f"* **CVSS v4 {score:.1f}**"
                elif score_vers == 3:
                    es_head = f"* **CVSS v3 {score:.1f}**"
                else:
                    es_head = f"* **CVSS v2 {score:.1f}**"

                es_list = [es_head,
                        "* **ATTENTION**: " + attention,
                        "* **Vendor**: " + vendors,
                        "* **Equipment**: " + equip,
                        "* **" + es_v_head + "**: " + es_vulns]
                mdFile.new_list(es_list)
                
                # 2. Risk Evaluation
                mdFile.new_header(level=2, title='2. RISK EVALUATION', add_table_of_contents="n")

                riskEval, risk_errs = getRiskEvaluation(data)
                mdFile.new_line(riskEval+"\n")
                if risk_errs:
                    errors.append(risk_errs)
                
                # 3. Technical Details
                mdFile.new_header(level=2, title='3. TECHNICAL DETAILS', add_table_of_contents="n")
                mdFile.new_header(level=3, title='3.1 AFFECTED PRODUCTS', add_table_of_contents="n")
                
                # 3.1 Products
                prods, prod_mapper, p_errors = getProducts(data, affected_pid_list)
                if p_errors:
                    errors.append(p_errors)
                mdFile.new_line(vendors + " reports that the following products are affected:")
                mdFile.new_line()
                mdFile.new_list(prods)
                
                # 3.2 Vulnerabilities
                mdFile.new_header(level=3, title='3.2 VULNERABILITY OVERVIEW', add_table_of_contents="n")

                count = 0
                impacts = {}
                csaf_version = data["document"]["csaf_version"]
                for vuln_index, vuln in enumerate(data["vulnerabilities"]):
                    has_prod_impact = False
                    highest_Score, generic_scores, cvss_scores, score_errors = getScores(vuln, csaf_version)
                    if score_errors:
                        errors.append(score_errors)
                    if len(cvss_scores) > 0:
                        has_prod_impact = True
                    # CWE Header for the Vulnerability
                    try:
                        if csaf_version == "2.0":
                            if "cwe" in vuln.keys():
                                cwe_id = vuln["cwe"]["id"].split("CWE-")[1]
                                mdFile.new_header(level=4, title="3.2."+str(count + 1)+" ["+vuln["cwe"]["name"].upper()+" "+vuln["cwe"]["id"]+"](https://cwe.mitre.org/data/definitions/"+cwe_id+".html)", add_table_of_contents="n")
                            else:
                                mdFile.new_header(level=4, title="3.2."+str(count + 1)+" ["+"UNKNOWN_CWE"+"](https://cwe.mitre.org/data/definitions/"+"XX"+".html)", add_table_of_contents="n")
                        else: #CSAF 2.1
                            if "cwes" in vuln.keys():
                                cwe_id = vuln["cwes"][0]["id"].split("CWE-")[1]
                                mdFile.new_header(level=4, title="3.2."+str(count + 1)+" ["+vuln["cwes"][0]["name"].upper()+" "+vuln["cwes"][0]["id"]+"](https://cwe.mitre.org/data/definitions/"+cwe_id+".html)", add_table_of_contents="n")
                            else:
                                mdFile.new_header(level=4, title="3.2."+str(count + 1)+" ["+"UNKNOWN_CWE"+"](https://cwe.mitre.org/data/definitions/"+"XX"+".html)", add_table_of_contents="n")
                    except:
                        errors.append(f"CWEs not formatted correctly for \"vulnerabilities\"[{vuln_index}].")
                    count += 1
                    # Vulnerability Description
                    description = ""
                    for note in vuln["notes"]:
                        if not description == "":
                            description += " "
                        if not ('summary' in note.get('title','').lower() or 'description' in note.get('title','').lower()):
                            description += note['title'].strip()+': '+note['text'].strip() if note.get('title','') else note['text'].strip()
                        else:
                            description += note["text"].strip()
                    description = description.replace("\n", "")
                    description = description.replace("\r", " ")
                    description = description.strip()
                    if not description:
                        errors.append(f"\"vulnerabilities\"[{vuln_index}] missing description.")
                    mdFile.new_line(description)

                    # Build Score Description
                    high = {
                        "2":{},
                        "3":{},
                        "4":{}
                    }
                    gens = {
                        "2":[],
                        "3":[],
                        "4":[]
                    }

                    # Generic Scores affect the highest number of the vuln's affected products
                    def organizeGenScores(gs:dict,cvss_index:str,cvss_key:str,high:dict,gens:dict):
                        gens[cvss_index].append(gs)
                        if not high[cvss_index]:
                            high[cvss_index] = gs.copy()
                        if gs[cvss_key]["baseScore"] > high[cvss_index][cvss_key]["baseScore"]:
                            high[cvss_index] = gs.copy()
                        return high, gens
                    for gen in generic_scores:
                        if "cvss_v4" in gen.keys():
                            high, gens = organizeGenScores(gen,"4","cvss_v4",high,gens)
                        if "cvss_v3" in gen.keys():
                            high, gens = organizeGenScores(gen,"3","cvss_v3",high,gens)
                        if "cvss_v2" in gen.keys():
                            high, gens = organizeGenScores(gen,"2","cvss_v2",high,gens)

                    # Write Score Paragraphs for the Vuln Section for the highest, generic score
                    gen_index = 0
                    printed_score = 0
                    def writeScoreParagraph(gen_index,version,high,cve):
                        if version == "2" or version == "3":
                            re_pattern = "(^.*?(A:.|$))"
                        else: # CVSS v4
                            re_pattern = "(^.*?(SA:.|$))"
                        cvss_vers = high[version][f"cvss_v{version}"]["version"]
                        vector = re.search(re_pattern,high[version][f"cvss_v{version}"]["vectorString"])
                        vector = vector.group()
                        baseScore = high[version][f"cvss_v{version}"]['baseScore']
                        if gen_index == 0:
                            scoring = "["+cve+"](https://www.cve.org/CVERecord?id="+cve+")"
                            scoring += f" has been assigned to this vulnerability. A CVSS v{cvss_vers} base score of {baseScore:.1f} has been calculated; the CVSS vector string is "
                            if version == "2":
                                scoring += "(["+vector+"](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?calculator))."
                            else:
                                scoring += "(["+vector+"](https://www.first.org/cvss/calculator/"
                                scoring += cvss_vers+"#"+vector+"))."
                        else:
                            scoring = f"A CVSS {cvss_vers} score has also been calculated for {vuln['cve']}. A base score of {baseScore:.1f} has been calculated; the CVSS vector string is "
                            scoring += "(["+vector+"](https://www.first.org/cvss/calculator/"
                            scoring += cvss_vers+"#"+vector+"))."
                        return scoring
                    try:
                        if gens["2"]:
                            scoring = writeScoreParagraph(gen_index,"2",high,vuln["cve"])
                            gen_index += 1
                            printed_score += 1
                            if printed_score <= 3:
                                mdFile.new_paragraph(scoring)
                        if gens["3"]:
                            scoring = writeScoreParagraph(gen_index,"3",high,vuln["cve"])
                            gen_index += 1
                            printed_score += 1
                            if printed_score <= 3:
                                mdFile.new_paragraph(scoring)
                        if gens["4"]:
                            scoring = writeScoreParagraph(gen_index,"4",high,vuln["cve"])
                            gen_index += 1
                            printed_score += 1                   
                            if printed_score <= 3:
                                mdFile.new_paragraph(scoring)
                        else:
                            scoring = "(INSERT_CVSS_v4_SCORE) A CVSS v4 score has also been calculated for [CVE-XXXX-XXXX](https://www.cve.org/CVERecord?id=CVE-XXXX-XXXX). A base score of INSERT_BASE_SCORE has been calculated; the CVSS vector string is ([CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N](https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N))."
                            mdFile.new_paragraph(scoring)
                    except:
                        errors.append(f"\"vulnerabilities\"[{vuln_index}] \"scores\" are not properly formatted.")
                    mdFile.new_line()
                    
                    gen_prod_specific = False
                    # Put the remaining scores in Product Specific Section
                    if (len(gens["2"]) > 1 or 
                        len(gens["3"]) > 1 or
                        len(gens["4"]) > 1):
                        gen_prod_specific = True
                    
                    # Setting up for Optional Section to include additional CVSS scores.
                    if has_prod_impact or gen_prod_specific:
                        impacts[vuln["cve"]] = {}
                        
                        # Collect scores that specify fewer products than the general scores.
                        for s in cvss_scores:
                            key = " ".join(s["products"])
                            key = key.strip()
                            key = key.replace(" ", ", ")
                            if not key in impacts[vuln["cve"]].keys():
                                impacts[vuln["cve"]][key] = {}
                            # Check for each CVSS version and save
                            if "cvss_v2" in s.keys():
                                impacts[vuln["cve"]][key]["cvss_v2"] = s["cvss_v2"]
                            if "cvss_v3" in s.keys():
                                impacts[vuln["cve"]][key]["cvss_v3"] = s["cvss_v3"]
                            if "cvss_v4" in s.keys():
                                impacts[vuln["cve"]][key]["cvss_v4"] = s["cvss_v4"]

                        if gen_prod_specific:
                            for vers in gens.keys():
                                for s in gens[vers]:
                                    key = " ".join(s["products"])
                                    key = key.strip()
                                    key = key.replace(" ", ", ")
                                    if not key in impacts[vuln["cve"]].keys():
                                        impacts[vuln["cve"]][key] = {}
                                    impacts[vuln["cve"]][key][f"cvss_v{vers}"] = s[f"cvss_v{vers}"]

                # Background
                if not impacts:
                    mdFile.new_header(level=3, title="3.3 BACKGROUND", add_table_of_contents="n")
                else: # Optional Product Impact section comes before background
                    mdFile.new_header(level=3, title="3.3 PRODUCT IMPACT", add_table_of_contents="n")
                    mdFile.new_line("Product-specific impact for an affected product vulnerable to the CVE:")
                    mdFile.new_line()
                    for imp_cve in impacts.keys():
                        mdFile.new_line("* "+imp_cve.strip())
                        for imp_score in impacts[imp_cve].keys():
                            imp_prods = imp_score.split(', ')
                            next_str = "\t* ("
                            for imp in imp_prods:
                                try:
                                    next_str = (next_str + 
                                                prod_mapper[imp]["impact_id"])
                                except:
                                    errors.append(f"Product PID {imp} has a CVSS score but is NOT among {imp_cve}'s affected products (\"known_affected\", \"first_affected\", or \"last_affected\").")
                            next_str = next_str[:-2] + "): "

                            # Write Product Impact Paragraphs
                            def writeImpactParagraph(impacts:dict,cve:str,score_key:str,prefix:str):
                                paragraph = {}
                                for key in impacts[cve][score_key].keys():
                                    substr = ""
                                    if key == "cvss_v2" or key == "cvss_v3":
                                        re_pattern = "(^.*?(A:.|$))"
                                    else: # v4
                                        re_pattern = "(^.*?(SA:.|$))"
                                    if "cvss_v" in key:
                                        cvss_vers = impacts[cve][score_key][key]["version"]
                                        vector = re.search(re_pattern,impacts[cve][score_key][key]["vectorString"])
                                        vector = vector.group()
                                        substr = f"A CVSS v{cvss_vers} base score of {impacts[cve][score_key][key]['baseScore']:.1f} has been calculated; the CVSS vector string is "
                                        if key == "cvss_v2":
                                            substr += "(["+vector+"](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?calculator))."
                                        else:
                                            substr += "(["+vector+"](https://www.first.org/cvss/calculator/"
                                            substr += cvss_vers+"#"+vector+"))."
                                    if substr:
                                        paragraph[key]=prefix+substr
                                return paragraph

                            try:
                                para = writeImpactParagraph(impacts,imp_cve,imp_score,next_str)
                                if "cvss_v2" in para.keys():
                                    mdFile.new_line(para["cvss_v2"])
                                if "cvss_v3" in para.keys():
                                    mdFile.new_line(para["cvss_v3"])
                                if "cvss_v4" in para.keys():
                                    mdFile.new_line(para["cvss_v4"])
                            except:
                                errors.append(f"Vulnerability {imp_cve} \"scores\" are incorrectly formatted.")

                    mdFile.new_line()
                    mdFile.new_header(level=3, title="3.4 BACKGROUND", add_table_of_contents="n")
                
                sectors = ""
                deployed = ""
                headquarters = ""
                for note in data['document'].get('notes',[]):
                    if note.get('title','').lower().strip() == 'critical infrastructure sectors':
                        sectors += note['text']
                    if note.get('title','').lower().strip() == 'countries/areas deployed':
                        deployed += note['text']
                    if note.get('title','').lower().strip() == 'company headquarters location':
                        headquarters += note['text']

                sectors = sectors if sectors else "INSERT_CI_SECTORS"
                deployed = deployed if deployed else "INSERT_COUNTRIES_DEPLOYED"
                headquarters = headquarters if headquarters else "INSERT_HQ"

                back = [
                    "* **CRITICAL INFRASTRUCTURE SECTORS:** "+sectors,
                    "* **COUNTRIES/AREAS DEPLOYED:** "+deployed,
                    "* **COMPANY HEADQUARTERS LOCATION:** "+headquarters
                ]
                mdFile.new_list(back)

                # Researcher
                if not impacts:
                    mdFile.new_header(level=3, title="3.4 RESEARCHER", add_table_of_contents="n")
                else:
                    mdFile.new_header(level=3, title="3.5 RESEARCHER", add_table_of_contents="n")
                
                if len(data["vulnerabilities"]) > 1:
                    v_fill = "these vulnerabilities"
                else:
                    v_fill = "this vulnerability"
                acks_found = False
                if "acknowledgments" in data["document"].keys():
                    acks_found = True
                for vuln in data.get("vulnerabilities",[]):
                    if vuln.get('acknowledgments',[]):
                        acks_found = True
                if not acks_found:
                    mdFile.new_line("(INSERT_ACKNOWLEDGMENT) "+data["document"]["publisher"]["name"]+" reported "+v_fill+".")
                else:
                    def writeAcknowledgment(ack:dict):
                        summary = False
                        single_ack = ""
                        if "names" in ack.keys():
                            for name in ack["names"]:
                                if not single_ack == "":
                                    single_ack += ", "
                                single_ack += name
                        if "organization" in ack.keys():
                            if not single_ack == "":
                                single_ack += " of "
                            single_ack += ack["organization"]
                        if "summary" in ack.keys():
                            single_ack += " " + ack["summary"]
                            summary = True
                        if not summary:
                            single_ack += " reported "+v_fill+".\n"
                        else:
                            single_ack += '\n'
                        return single_ack
                    acks = ""
                    for ack_index, ack in enumerate(data["document"].get("acknowledgments",[])):
                        try:
                            single_ack = writeAcknowledgment(ack)
                            if single_ack and not single_ack in acks:
                                if not acks == "":
                                    acks += "\n"
                                acks += single_ack
                        except:
                            errors.append(f"\"document\"->\"acknowledgments\"[{ack_index}] is formatted incorrectly.")
                    for vuln_index, vuln in enumerate(data.get('vulnerabilities',[])):
                        for ack_index, ack in enumerate(vuln.get("acknowledgments",[])):
                            try:
                                single_ack = writeAcknowledgment(ack)
                                if single_ack and not single_ack in acks:
                                    if not acks == "":
                                        acks += "\n"
                                    acks += single_ack
                            except:
                                errors.append(f"\"vulnerabilities\"[{vuln_index}]->\"acknowledgments\"[{ack_index}] is formatted incorrectly.")
                    mdFile.new_line(acks.strip())
                mdFile.new_line()

                # 4. Mitigations
                mdFile.new_header(level=2, title="4. MITIGATIONS", add_table_of_contents="n")

                # Grab all FPNs from PIDs and GIDs and include them in mitigation string.
                mapped_mitis, mapm_errs = getVendorMitigations(data, affected_pid_list)
                if mapm_errs:
                    errors.append(mapm_errs)
                fixed_mitis, fixed_errs = getFixedMitigations(data)

                if fixed_errs:
                    errors.append(fixed_errs)

                if "," in vendors:
                    multi = "have"
                else:
                    multi = "has"

                if mapped_mitis:#vendor_miti:
                    miti_head = vendors + " " + multi + " identified the following specific workarounds and mitigations users can apply to reduce risk:"

                    mdFile.new_line(miti_head)
                    mdFile.new_line()
                    # Vendor Mitigations affecting all affected products
                    def writeMitigationWithURL(ven:dict,product_key = ""):
                        last = ven["text"].split()[-2:]
                        max = ven["text"].rsplit(' ', 2)[0:1]

                        miti = "* "
                        if product_key:
                            miti += f"({key}) "
                        for m in max:
                            miti += m + " "
                        miti += "["
                        for l in last:
                            miti += l + " "
                        miti = miti.strip()
                        miti += "]("+ven["url"]+")"
                        return miti
                    if "all" in mapped_mitis.keys():
                        for ven in mapped_mitis["all"]:
                            if "url" in ven.keys():
                                mdFile.new_line(writeMitigationWithURL(ven))
                            else:
                                cleaned_miti = ven["text"].replace("\n\n", "\n * ")
                                mdFile.new_line("* " + cleaned_miti)
                    for key in mapped_mitis.keys():
                        if key != "all": # Specific Products
                            for ven in mapped_mitis[key]:
                                if "url" in ven.keys():
                                    mdFile.new_line(writeMitigationWithURL(ven,key))
                                else:
                                    mdFile.new_line("* ("+key+") " + ven["text"])
                # Fixed versions
                if fixed_mitis:
                    mdFile.new_line()
                    mdFile.new_line("The following product versions have been fixed:")
                    mdFile.new_line()
                    for fixed_version in fixed_mitis:
                        mdFile.new_line("- "+fixed_version)
                mdFile.new_line()
                try:
                    pub_name = data["document"]["publisher"]["name"]
                except:
                    errors.append("Missing CSAF \"publisher\"->\"name\".")
                    pub_name = ""
                self_refs = []
                try:
                    for ref in data['document']['references']:
                        if ref.get('category','') == 'self':

                            self_refs.append(ref)
                except:
                    errors.append("CSAF Missing \"document\"->\"references\".")
                ssa = data["document"]["tracking"]["id"]
                if self_refs:
                    ref_string = ""
                    for ref in self_refs:
                        if ref_string:
                            ref_string += ', '
                        ref_string += '['+ref['summary']+']('+ref['url']+')'
                    ref_string = ref_string.strip()
                    mdFile.new_line("For more information see the associated "+pub_name.strip()+" security advisory "+ssa+" "+ref_string+".")
                    
                ben2 = ""
                ben3 = ""

                if not "exploitable remotely" in attention.lower():
                    if len(data["vulnerabilities"]) > 1:
                        ben2 = "These vulnerabilities are not exploitable remotely."
                    else:
                        ben2 = "This vulnerability is not exploitable remotely."
                if not "low attack" in attention.lower():
                    if len(data["vulnerabilities"]) > 1:
                        ben3 = "These vulnerabilities have a high attack complexity."
                    else:
                        ben3 = "This vulnerability has a high attack complexity."

                totalben = ""

                if ben2:
                    totalben += ben2
                if ben3:
                    if ben2:
                        totalben += " " + ben3
                    else:
                        totalben += ben3
                mdFile.new_line()
                if totalben:
                    mdFile.new_line(totalben)
                    mdFile.new_line()
                # 5. Update History
                mdFile.new_header(level=2, title="5. UPDATE HISTORY", add_table_of_contents="n")

                def generateUpdateIndex(rev_number:int,index:str):
                    rev_number, mod = divmod(rev_number, 26)
                    index = chr(65 + mod) + index
                    if rev_number == 0:
                        return index
                    else:
                        return generateUpdateIndex(rev_number-1,index)

                for rev_index, rev in enumerate(data["document"]["tracking"]["revision_history"]):
                    if "T" in rev["date"]:
                        date = rev["date"].split("T")[0]
                    else:
                        date = rev["date"].split(" ")[0]

                    year = date.split("-")[0]
                    month = date.split("-")[1]
                    day = date.split("-")[2]

                    months = {
                        1:"January",
                        2:"February",
                        3:"March",
                        4:"April",
                        5:"May",
                        6:"June",
                        7:"July",
                        8:"August",
                        9:"September",
                        10:"October",
                        11:"November",
                        12:"December"
                    }

                    u_head = ""
                    pub_name = data["document"]["publisher"]["name"]

                    if rev_index == 0:
                        u_head = ": Initial Publication"
                    else:
                        u_head = ": Update " + generateUpdateIndex(rev_index-1,"")
                    if rev_index == 0:
                        u_line = "* "+months[int(month)]+" "+day+', '+year+u_head
                    else:
                        u_line = "* "+months[int(month)]+" "+day+', '+year+u_head+" - "+rev["summary"]
                    mdFile.new_line(u_line)
                errors = flatten(errors)
                if errors:
                    print(CRED+("#"*(len(csaf_name)+len(error_header)+len(error_tail*2)))+CEND)
                    print(CRED+error_tail+CEND+csaf_name+error_header+CRED+error_tail+CEND)
                    for err in errors:
                        print(CRED+"* "+CEND+err)
                    print(CRED+("#"*(len(csaf_name)+len(error_header)+len(error_tail*2)))+CEND)
                    with open(workingdir+os.sep+'csaf_fail_list.txt', 'a+') as failed:
                        failed.write(f"######## {csaf_name} ########\n")
                        for err in errors:
                            failed.write(err+"\n")
                else:
                    # Save
                    mdFile.create_md_file()
                    # Cleanup
                    with open(out_md, 'r') as mdres:
                        mdstr = mdres.read()
                        mdstr = mdstr[mdstr.find(f"## {data['document']['tracking']['id'].upper()}"):]
                        mdstr = mdstr.replace('## 3. TECHNICAL DETAILS\n\n### 3.1 AFFECTED PRODUCTS','## 3. TECHNICAL DETAILS\n### 3.1 AFFECTED PRODUCTS')
                        mdstr = mdstr.replace('### 3.2 VULNERABILITY OVERVIEW\n\n#### 3.2.1','### 3.2 VULNERABILITY OVERVIEW\n#### 3.2.1')
                        mdstr = mdstr.replace('## 5. UPDATE HISTORY\n  \n*','## 5. UPDATE HISTORY\n*')
                        mdstr = mdstr.replace('  ','')
                    with open(out_md, 'w') as mdres:
                        mdres.write(mdstr)
                    print(CGREEN+out_md.split(os.sep)[-1]+" saved successfully."+CEND)
            else:
                with open(workingdir+os.sep+'csaf_fail_list.txt', 'w') as failed:
                    msg = ""
                    if not can_process:
                        msg = data["document"]["tracking"]["id"] + ': does not meet minimum data requirements.'
                    if stop_conversion:
                        if msg:
                            msg += " "
                        msg += data["document"]["tracking"]["id"] + ': has discouraged or prohibited CWEs.'
                    failed.write(msg+"\n")
                    print(CRED+("#"*(len(csaf_name)+len(error_header)+len(error_tail*2)))+CEND)
                    print(CRED+error_tail+CEND+csaf_name+error_header+CRED+error_tail+CEND)
                    errors.append(msg)
                    for err in temp_errs:
                        errors.append(data["document"]["tracking"]["id"]+": "+err)
                    for err in errors:
                        print(CRED+"* "+CEND+err)
                        failed.write(f"######## {csaf_name} ########\n")
                        failed.write(err+"\n")
                    print(CRED+("#"*(len(csaf_name)+len(error_header)+len(error_tail*2)))+CEND)

    except Exception as e:
        print(CRED+"ERROR: " + str(e)+CEND)
        traceback.print_exc()
def main():
    '''Main
    Entry function of the program. Reads in CSAF files from input folder.

    Args:
        None
    Returns:
        None
    '''
    if not os.path.isdir(inputdir):
        print("Input Directory: " + inputdir + " does not exist")
        exit(0)

    if not os.path.isdir(outdir):
        os.mkdir(outdir)

    filenames = next(os.walk(inputdir), (None, None, []))[2]

    total_num = 0
    for f in filenames:
        if '.json' in f:
            total_num = total_num + 1
    current_elem = 1

    for file in filenames:
        if file.endswith('.json'):
            print("Currently On File: " +str(current_elem) + " Of "+ str(total_num) )
            output_name = file.replace(".json",".md")
            output_name = outdir + os.sep + output_name
            processJson(inputdir + os.sep + file, output_name)
            current_elem += 1

if __name__ == "__main__":
    main()