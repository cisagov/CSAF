####################################################################
# Title: CISA CSAF Requirements Checker - Helper to CSAF2MD
# Author: Matthew Stradling, Israel Bentley
# Org: Idaho National Laboratory on behalf of
#       Cybersecurity and Infrastructure Security Agency (CISA)
####################################################################
##########################
# Python Standard Library
##########################
import os
import json
import traceback
import ast

##########################
# Import Custom Files
##########################
from lib.requirements import __meets_minimum_requirements, meets_suggested_recommendations
from lib.cwe_helper import checkBadCWEs

# Styling for output
CGREEN = '\033[92m'
CRED = '\033[91m'
CEND = '\033[0m'
CWARN = '\033[96m'
CERR = '\033[93m'

# Read files in from directory
workingdir = os.path.dirname(os.path.abspath(__file__))
inputdir = os.path.join(workingdir + os.sep + 'input')

statuspath = workingdir + os.sep + 'lib' + os.sep + 'cwe_status.json'

with open(statuspath) as infile:
    cwe_status = json.load(infile)
def validateJson(in_csaf):
    '''Validate JSON
    Validate the CSAF against CISA's additional CSAF requirements.

    Args:
        in_csaf:str
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
            adv_id = data.get("document",{}).get("tracking",{}).get("id",csaf_name)
            can_process, temp_errs = __meets_minimum_requirements(data,True)
            if can_process:
                as_recommended, recommendations = meets_suggested_recommendations(data)
                # If valid, show any recommendations
                if not as_recommended:
                    print(CERR+"Optional recommendations for this CSAF include:"+CEND)
                    for recommendation in recommendations:
                        print(CWARN+recommendation+CEND)
            has_bad_cwes = checkBadCWEs(data,cwe_status)

            if can_process:
                print(CGREEN+adv_id+" validated against CISA additional CSAF requirements!"+CEND)
            else:
                with open(workingdir+os.sep+'csaf_fail_list.txt', 'a') as failed:
                    msg = ""
                    if not can_process:
                        msg = data["document"]["tracking"]["id"] + ': does not meet minimum data requirements.'
                    if has_bad_cwes:
                        if msg:
                            msg += " "
                        msg += data["document"]["tracking"]["id"] + ': has discouraged or prohibited CWEs.'
                    failed.write(msg+"\n")
                    print(CRED+("#"*(len(csaf_name)+len(error_header)+len(error_tail*2)))+CEND)
                    failed.write(("#"*(len(csaf_name)+len(error_header)+len(error_tail*2)))+"\n")
                    print(CRED+error_tail+CEND+csaf_name+error_header+CRED+error_tail+CEND)
                    failed.write(error_tail+csaf_name+error_header+error_tail+"\n")
                    errors.append(msg)
                    for err in temp_errs:
                        errmsg = data["document"]["tracking"]["id"]+": "+err
                        errors.append(errmsg)
                        failed.write(errmsg+"\n")
                        print(CRED+"* "+CEND+err)
                    print(CRED+("#"*(len(csaf_name)+len(error_header)+len(error_tail*2)))+CEND)
                    failed.write(("#"*(len(csaf_name)+len(error_header)+len(error_tail*2)))+"\n")

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

    filenames = next(os.walk(inputdir), (None, None, []))[2]

    total_num = 0
    for f in filenames:
        if '.json' in f:
            total_num = total_num + 1
    current_elem = 1

    for file in filenames:
        if file.endswith('.json'):
            print("Currently On File: " +str(current_elem) + " Of "+ str(total_num) )
            validateJson(inputdir + os.sep + file)
            current_elem += 1

if __name__ == "__main__":
    main()
