import json
import shutil
import sys
import os
import platform

import requests
import urllib.parse
import urllib3
import datetime
import traceback
import pathlib
import tabulate2
import colorama
import cmd2

import static

urllib3.disable_warnings()

def read_json_data(json_file):
    """ Will load the json file's variables in a python dictionary object
    :param json_file: The path of the JSON file
    :return: The dictionary object containing the variables
    """
    with open(json_file, 'r', encoding="utf-8") as c_file:
        json_data = json.load(c_file)
        return json_data


def load_var_from_dict(json_dict, json_key):
    """ Example usage is for loading the API key from the configuration.
    :param json_dict: Dictionary representing the JSON data
    :param json_key: JSON key to look for. Does not look recursively (only 1st level).
    :return: The Object corresponding to the provided JSON key
    """
    if json_key not in json_dict:
        return None
    else:
        return json_dict[json_key]


def print_logo_lines(logo_lines=static.LOGO):
    """ Prints the provided lines (list of strings) one by one.
    :param logo_lines: A list containing the lines for the tool logo
    """
    for line in logo_lines:
        print(line)


def get_userinput(prompt) -> str:
    """
    :param prompt: Prompt to display to the user when requesting input
    :return: Returns the value provided by the user (string). Can also return empty string ""
    """
    print(prompt,end="")
    user_input = input(": ")

    return user_input


def get_numeric_userinput(choices_list: list, prompt):
    """
    Returns the user input, if it is a single digit, otherwise it returns None
    :param choices_list: List of choices
    :param prompt: Prompt to display to the user when requesting input
    """
    try:
        choice = int(get_userinput(prompt))
        if choice not in [int(x) for x in choices_list]:
            print("{} Choice has to be a digit, as shown in the values of the table above.\n".format(static.PROMPT_ERROR))
            return None
    except ValueError as ve:
        print("{} Choice has to be a digit, as shown in the values of the table above.\n".format(static.PROMPT_ERROR))
        return None

    return choice


def is_valid_json_dict(json_string):
    """Check if a string is valid JSON and can be converted to a Python dictionary.
    :param json_string: A JSON string representation.
    :return: Returns True if the string is a valid JSON string and can be converted to a python dictionary
    """
    try:
        # Parse the JSON string
        result = json.loads(json_string)
        # Check if the result is a dictionary
        return isinstance(result, dict)
    except AttributeError:
        print("{} There was a problem with the provided JSON data.\n".format(static.PROMPT_ERROR))
        return False
    except json.JSONDecodeError:
        # If parsing fails, it's not valid JSON
        return False


def get_boolean_userinput(prompt):
    """
    Asks user to provide a Yes or No response.
    :param prompt: The prompt to show to the user when asking for input.
    :return: True of False, depending on what the user chose ('y' or 'n')
    """
    wrong_input_counter = 0
    while True:
        print(prompt,end="")
        user_input = input(" (Y/N): ").casefold()  # Make input case-insensitive
        if user_input == 'y':
            return True
        elif user_input == 'n':
            return False
        else:
            wrong_input_counter += 1
            if wrong_input_counter >= 3:
                print(colorama.Fore.LIGHTRED_EX + "[X] Only acceptable input is 'y' or 'n'. Case-insensitive." + colorama.Style.RESET_ALL)


def get_current_date() -> str:
    """
    :return: The current date (without timestamp)
    """
    return str(datetime.datetime.now()).split(" ")[0]


def ensure_dir_with_trailing_slash(dir_path):
    """ Method will ensure that directory will have a trailing slash.
    :param dir_path: The directory to normalise
    :return: A normalised path to ensure OS compatibility (e.g., Windows "\\", Posix "/")
    """
    dir_path = os.path.normpath(dir_path)
    if not dir_path.endswith(os.path.sep):
        dir_path += os.path.sep

    return dir_path


def ensure_filename_without_leading_slash(filename):
    """ Method will ensure that the filename will never have a leading slash
    :param filename: The filename to normalise
    :return: A normalised filename to ensure OS compatibility (e.g., Windows "\\", Posix "/")
    """
    filename = os.path.normpath(filename)
    filename = filename.lstrip(os.sep)

    return filename


def optional_create_directory_if_not_exists(dir_path):
    if not os.path.isdir(dir_path):
        print("{} The output directory does not exist.".format(static.PROMPT_ERROR))
        user_choice = get_boolean_userinput("{} Would you like to create it?".format(static.PROMPT_QUESTION))
        if user_choice:
            final_path = pathlib.Path(dir_path)
            try:
                final_path.mkdir(parents=True, exist_ok=True)
                print(static.PROMPT_OKPLUS + " Created directory successfully.")
            except Exception as e:
                print("{0} There was an error creating the directory: {1}".format(static.PROMPT_ERROR, e))
                sys.exit(-1)
        else:
            print(
                static.PROMPT_EXCLAMATION + " Please create the directory or change the log directory in the configuration file. Exiting.")
            sys.exit(0)


def initialise_log(log_dir, debug_enabled):
    """ Initialises the log file and the debug file. Creates it if it doesn't exist.
    :param log_dir: The directory where log files should be stored to.
    :param debug_enabled: Shows if debug is enabled in the config file
    :return: Returns a list containing the absolute path for the log file and the debug file.
    If debug is disabled, returns None for the second item of the list.
    """
    current_date = get_current_date()
    log_dir = ensure_dir_with_trailing_slash(log_dir)
    log_filename = "vulncaster_{}.csv".format(current_date)

    # if the specified directory does not exist, then ask the user to create it.
    optional_create_directory_if_not_exists(log_dir)

    # Get absolute path for log
    log_path = os.path.normpath(log_dir + log_filename)
    # Initialise debug path as None in case debug is not enabled in the config
    debug_file_path = None

    # Create an empty debug file by writing to it.
    if debug_enabled:
        debug_log_filename = "debug_{}.log".format(current_date)
        debug_file_path = os.path.normpath(log_dir + debug_log_filename)
        try:
            with open(debug_file_path, 'x') as df:
                df.write("")
        except FileExistsError:
            print(static.PROMPT_EXCLAMATION + " Debug File Exists: {}".format(debug_file_path))

    # Create the log file (csv format)
    try:
        with open(log_path, 'x') as f:
            f.write("Timestamp,Agent_ID,IP_Address,Plugin_ID,Recast_Type,Old_Severity,New_Severity,Expiration,Comment,API_User,L_Host,L_User\n")
    # If file exists, gracefully handle the error.
    except FileExistsError:
        print(static.PROMPT_EXCLAMATION + " Log File Exists: {}".format(log_path))


    return [log_path, debug_file_path]


def prepare_log_entry(uuid, ip, plugin_id, recast_type, old_severity, new_severity, expiration, comment, api_user, l_host, l_user):
    """
    Pre-processes values and prepares them to be added to a CSV file
    :return: A string that represents a CSV log entry (a single row)
    """
    # this is done to avoid breaking the CSV format
    comment = comment.replace(",", "[comma]")
    date_time = str(datetime.datetime.now()).split(".")[0]
    plugin_id =  str(plugin_id)
    old_severity = str(old_severity)
    new_severity = str(new_severity)

    # Calculate and convert the expiration into human-readable format
    if str(expiration) == str(static.PERMANENT_NO_EXPIRATION):
        future_exp_date = "Never"
    else:
        future_exp_date = datetime.date.today() + datetime.timedelta(days=expiration)
        future_exp_date = str(future_exp_date)

    log_objects = [
        date_time, uuid, ip, plugin_id, recast_type, static.SEVERITIES[old_severity],
        static.SEVERITIES[new_severity], future_exp_date, comment, api_user, l_host, l_user
    ]

    # concatenate all items in the list into a single string, separated by a comma (for CSV conversion)
    log_entry = ",".join(log_objects)
    log_entry += "\n"

    return log_entry


def prepare_debug_entry(desc, msg, http_status, api_endpoint):
    """
    Pre-processes values and prepares them to be added to a debug file
    :return: A string that represents a debug entry
    """
    datetime_str = str(datetime.datetime.today())
    debug_entry = "{0} | {1} | ENDPOINT: {2} | {3} | HTTP: {4}\n".format(
        datetime_str, desc, api_endpoint, msg, http_status
    )

    return debug_entry


def write_to_log(log_entries: list|None, log_path:str|None, debug_entry:str|None, debug_path:str|None):
    """ This method writes to the log or debug file, or both
    :param log_entries: A list containing multiple log file entries (lines). Can be None if there is nothing to log
    :param log_path: The path for the log files
    :param debug_entry: A string containing an entry in the debug file. Can be None if debug is disabled.
    :param debug_path: The path for the debug files. Can be None if debug is disabled.
    """
    if debug_path is not None:
        try:
            with open(debug_path, 'a') as f:
                f.write(debug_entry)
        except Exception as e:
            print(e)
            traceback.print_exc()
            sys.exit(-1)

    if log_entries is not None:
        try:
            with open(log_path, 'a') as f:
                f.writelines(log_entries)
        except PermissionError:
            print("\t\\_{0} Error when writing to \"{1}\". Can be caused when file is already open in another app.".format(static.PROMPT_ERROR, log_path))
            new_log_path = log_path.rstrip(".csv") + "_copy.csv"
            shutil.copy(log_path, new_log_path)
            print("\t\\_{0} Copying data to new log file \"{1}\". Merge them manually if you wish to.".format(static.PROMPT_EXCLAMATION, new_log_path))
            write_to_log(log_entries, new_log_path, debug_entry, debug_path)
        except Exception as e:
            print(e)
            traceback.print_exc()
            sys.exit(-1)


def get_cwd_path(cwd_name=None):
    """ This will get us the program's directory, even if we are frozen using py2exe
    :param cwd_name: Current working directory can be provided statically through this argument
    :return: The path that will be considered as the current working directory
    """
    if hasattr(sys, "frozen"):
        if cwd_name is None or cwd_name == "":
            cwd = os.path.dirname(sys.executable)
            return ensure_dir_with_trailing_slash(cwd)
        else:
            cwd = os.path.dirname(sys.executable) + "\\{}\\".format(cwd_name)
            return ensure_dir_with_trailing_slash(cwd)

    elif cwd_name is None or cwd_name == "":
        cwd = os.path.dirname(os.path.realpath(__file__))
        return ensure_dir_with_trailing_slash(cwd)

    cwd = os.path.dirname(os.path.realpath(__file__)) + "\\{}\\".format(cwd_name)
    return ensure_dir_with_trailing_slash(cwd)


# noinspection PyBroadException
def get_api_user_details(conf_dict, headers):
    """
    :param conf_dict: Dictionary with config data
    :param headers: Headers for communicating with the Tenable SC instance through API
    :return: Returns a requests.request object. It holds the currentUser details, as provided by the REST API.
    """
    url = conf_dict['api_endpoint']['url'] + conf_dict['api_endpoint']['apikey_validation']
    try:
        resp = requests.request(method='GET', url=url, headers=headers, verify=False)
    except Exception as e:
        print("{0} Whoops, something somewhere went wrong. Error message: {1}".format(static.PROMPT_ERROR, e))
        sys.exit(-1)

    return resp


def init_api_key(conf_dict, headers, apikey_key="x-apikey"):
    """ Will load the API key directly from the configuration file. Default parameters provided.
    :param conf_dict: The configuration passed as a python dictionary representation
    :param headers: The required headers for issuing an HTTP request to validate the API key
    :param apikey_key: The key for the API key value in the configuration dictionary/json
    :return:
    """

    def validate_api_key(apikey_value, attempts=0):
        """ If the API key is equal to None or the empty string, the user will be required to provide it on runtime.
        Example of API key format -> accesskey=cafe1a77e; secretkey=deadbeef
        :param attempts: The number of consecutive attempts to validate the API key
        :param apikey_value: The API key (can be None or "")
        :return: The actual API key - as provided in a configuration file or at runtime by the user
        """
        if apikey_value is None or apikey_value == "" or conf_dict['interactive_auth'] is True:
            apikey_value = str(input("Tenable SC API key: "))

        apikey_value = apikey_value.strip()
        apikey_value = apikey_value.rstrip(";")

        headers[apikey_key] = apikey_value

        print(static.PROMPT_EXCLAMATION + " Validating the API key...")
        resp = get_api_user_details(conf_dict, headers)

        # validate apikey by querying tenable sc. If status code is 400, try again. Other errors terminate the cmdloop
        if resp.status_code == 200:
            print(static.PROMPT_OKPLUS + " API key is valid." )
            return apikey_value

        elif 400 <= resp.status_code <= 499:
            print(
                static.PROMPT_ERROR + " Received a {} HTTP status code. Are you using the correct key?".format(
                    resp.status_code
                )
            )
            if attempts >= 3:
                print(
                    colorama.Fore.LIGHTWHITE_EX +
                    "\nInsanity is doing the same thing over and over again and expecting different results.\n- Albert Einstein" +
                    colorama.Style.RESET_ALL
                )
                sys.exit(0)

            return validate_api_key(None, attempts+1)

        else:
            print(
                static.PROMPT_ERROR + " Received a {} HTTP status code. Troubleshooting time! Enjoy :)".format(
                    resp.status_code
                )
            )
            sys.exit(0)

    loaded_key = load_var_from_dict(headers, apikey_key)
    api_key = validate_api_key(loaded_key)

    return api_key


def convert_url_to_payload(query_url, tenable_sc_host, offset_limit=15000, filter_key="filt") -> dict | None:
    """
    This method will take a Tenable SC / Tenable SC Plus analysis URL and convert it to an analysis
    POST request payload that can be used to query analysis results from the API.
    :type query_url: The Tenable SC URL (including all parameters) for the analysis module
    :param tenable_sc_host: The API endpoint URL from the configuration file
    :param offset_limit: Default is 15,000.
    :param filter_key: The "keyword" used by Tenable SC in the URL parameter (json array). This might never change.
    :return: POST request payload as a Python dictionary. Return None if not correct url
    """
    def populate_payload_template(offset: int, q_filter):
        """
        :param offset: The offset for the query payload
        :param q_filter: The filter extracted from the analysis URL
        :return: The populated query payload
        """
        payload_template = {"query":
                                {"name":"",
                                 "description":"",
                                 "context":"",
                                 "status":-1,
                                 "createdTime":0,
                                 "modifiedTime":0,
                                 "groups":[],
                                 "type":"vuln",
                                 "tool":"vulndetails",
                                 "sourceType":"cumulative",
                                 "startOffset":0,
                                 "endOffset":offset,
                                 "filters":q_filter,
                                 "vulnTool":"vulndetails"
                                 },"sourceType":"cumulative","columns":[],"type":"vuln"
                            }
        return payload_template

    # start converting
    print("")  # new line
    if not "vulnerabilities/cumulative" in query_url:
        print(static.PROMPT_EXCLAMATION + " You have not provided a URL for Cumulative Analysis. Are you querying mitigated vulns?")
        return None
    elif not query_url.startswith(tenable_sc_host):
        print(static.PROMPT_EXCLAMATION + " You need to use a valid URL or modify your configuration file.")
        print(static.PROMPT_EXCLAMATION + " Currently, you are using {}".format(tenable_sc_host))
        return None

    if not "/vulndetails/" in query_url:
        print(static.PROMPT_EXCLAMATION + " Not using 'Vulnerability Detail List'. Will convert query to 'vulndetails' automatically.")

    print(static.PROMPT_EXCLAMATION + " The default offset limit is {} results. Use the --limit flag to change it".format(offset_limit))

    # decode url if percent-encoded
    query_url = urllib.parse.unquote(query_url)

    # Find the position of the first '{'
    url_json_idx = query_url.find("{")
    url_json_ridx = query_url.rfind("}")
    json_str = query_url[url_json_idx:url_json_ridx+1]

    if not is_valid_json_dict(json_str):
        print("{} The URL does not seem to contain a valid JSON string. Please check the below string extracted from the URL you provided:".format(static.PROMPT_ERROR))
        print("\t\\_{}".format(json_str))

        return None

    url_json_data = json.loads(json_str)

    filter_name_key = "filterName"
    repository_filter_name = "repository"
    repository_filter_value = "value"

    # CONVERT REPOSITORIES FORMAT FROM THE WAY URL HANDLES IT, TO THE WAY API HANDLES IT
    # url_json_data[filter_key] returns a list of json objects
    for i in range(len(url_json_data[filter_key])):
        if filter_name_key in url_json_data[filter_key][i]:
            if url_json_data[filter_key][i][filter_name_key] == repository_filter_name:
                repositories_str = url_json_data[filter_key][i][repository_filter_value]
                repositories = repositories_str.split(",")
                repositories_list_of_dicts = []

                for repository_id in repositories:
                    repositories_list_of_dicts.append({'id': repository_id})

                url_json_data[filter_key][i][repository_filter_value] = repositories_list_of_dicts

                ## My bad, Tenable sucks. The below was done in reverse. We converted API -> URL instead of URL -> API
                # repositories = []
                # for value_dict in url_json_data[filter_key][i][repository_filter_value]:
                #     repositories.append(value_dict['id'])
                #
                # repositories_str = ",".join(repositories)
                # url_json_data[filter_key][i][repository_filter_value] = repositories_str
        
    query_payload = populate_payload_template(offset_limit, url_json_data[filter_key])
    return query_payload


def preprocess_recast_payload(agent_id, plugin_id, new_severity, comment, ip_addr, expire_in_days, repo_id) -> dict:
    """
    :param agent_id: The agent ID of the host to recast
    :param plugin_id: The plugin ID
    :param new_severity: The new severity to apply with the recast operation
    :param comment: The recast comment
    :param ip_addr: The IP address of the host to recast
    :param expire_in_days: The recast expiration time (in days)
    :param repo_id: The repository ID
    :return: A python dictionary with the JSON representation of a recast payload for a single vulnerability (plugin ID)
    """
    expire_in_days = int(expire_in_days)  # convert to integer
    if expire_in_days != static.PERMANENT_NO_EXPIRATION and expire_in_days > 0:
        dt = datetime.datetime.today() + datetime.timedelta(days=expire_in_days)
        ts = datetime.datetime.timestamp(dt)
        # convert to string and get rid of decimals
        str_ts = str(ts)
        str_ts = str_ts.split(".")[0]
    elif expire_in_days < static.PERMANENT_NO_EXPIRATION:
        print(static.PROMPT_ERROR + " The value provided for expiration ('{}') is invalid. Please provide the value is DAYS (i.e., 30).".format(expire_in_days))
        raise Exception
    else:
        # if -1 is used
        str_ts = expire_in_days

    # determine whether to use agent id or ip address
    if agent_id == "":
        uuid = ip_addr
        host_type = "ip"
    else:
        uuid = agent_id
        host_type = "uuid"

    recast_req = {
        "api": "/recastRiskRule",
        "method": "POST",
        "params":
            {
                "hostType": host_type,
                "hostValue": uuid,
                "plugin":{"id": plugin_id},
                "protocol": "any",
                "port": "any",
                "newSeverity":{"id": new_severity},
                "comments": comment,
                "repositories": [{"id": repo_id}],
                "expires": str_ts
            }
    }

    return recast_req


def exec_csv_export(payload_dict, analysis_url, headers, out_dir):
    """
    Downloads and exports a CSV file containing the vulnerabilities retrieved based on the provided Tenable SC URL
    :param payload_dict: The query (json represented as python dict)
    :param analysis_url: The 'analysis' API endpoint of Tenable SC
    :param headers: The HTTP headers
    :param out_dir: The output directory where the CSV file will be saved
    """
    def cleanup_value(value):
        new_val = value
        new_val = new_val.replace(",", "; ")
        new_val = new_val.replace("\t", " ")
        new_val = new_val.replace("  ", " ")
        new_val = new_val.replace("  ", " ")
        new_val = new_val.replace("\n", "{newline}")

        return new_val

    payload = json.dumps(payload_dict)

    q_resp = requests.request(method='POST', url=analysis_url, headers=headers, data=payload, verify=False)
    q_json_response = json.loads(q_resp.text)

    total_records = int(q_json_response["response"]["totalRecords"])
    ret_records = int(q_json_response["response"]["returnedRecords"])
    if ret_records < total_records:
        print("{0} The total records returned from the provided query are {1}. Fetching only the first {2} results.".format(static.PROMPT_EXCLAMATION, total_records, ret_records))


    vuln_results_dict = q_json_response["response"]["results"]

    rows = []
    vpr_headers = [
        "age_of_vuln", "cvssV3_impactScore", "exploit_code_maturity", "product_coverage",
        "threat_intensity_last_28", "threat_recency", "threat_sources_last_28"
    ]
    added_headers = False
    # WRITE VALUES

    for obj in vuln_results_dict:
        if added_headers is False:
            headers = ""
            # add each header into a string, so that it can be added as the first line of the CSV
            for header in obj:
                # split VPR into multiple headers
                if header == 'vprContext':
                    for h in vpr_headers:
                        headers += "{}, ".format(h)
                # or else just add the header
                else:
                    headers += "{}, ".format(header)

            headers = headers.rstrip(", ")
            # print(headers)
            headers += "\n"
            added_headers = True

        row_str = []

        for i in obj:
            row = ""

            if i == 'severity' or i == 'family' or i == 'repository':
                val = obj[i]['name']
                val = cleanup_value(val)
                row_str.append(val)

            elif i == 'pluginText':
                val = "Redacted"
                row_str.append(val)

            # VPR CONTEXT - NEED THIS AS SEPARATE COLUMNS
            elif i == 'vprContext':
                vpr_context_str = ""

                # because obj[i] is treated as an array of characters,
                # it can either be equal to "" or "[]"; so 0 or 2 characters.
                if len(obj[i]) <= 2:
                    for header in vpr_headers:
                        row_str.append("")
                else:
                    json_vpr = json.loads(obj[i])
                    for entry in json_vpr:
                        clean_val = cleanup_value(str(entry['value']))
                        row_str.append(clean_val)

            elif i == 'keyDrivers':
                key_driver_str = ""
                json_key_driver = json.loads(obj[i])
                for k in json_key_driver.keys():
                    entry_val = json_key_driver[k]
                    key_driver_str += "{0}: {1}; ".format(k, entry_val)
                key_driver_str = key_driver_str.rstrip("; ")
                # print(key_driver_str)
                val = key_driver_str
                val = cleanup_value(val)
                row_str.append(val)

            else:
                val = obj[i]
                val = cleanup_value(val)
                row_str.append(val)

            # print("{0}: {1}".format(i, obj[i]))  # USED FOR DEBUGGING

        row = ",".join(row_str)
        row += "\n"
        # print(row)
        rows.append(row)

    out_name = str(datetime.datetime.now())
    out_name = out_name.replace(":", "-")
    out_name = 'vulnerabilities_{}.csv'.format(out_name)

    # if output dir does not exist, create it
    out_dir = ensure_dir_with_trailing_slash(out_dir)
    optional_create_directory_if_not_exists(out_dir)
    out_file = out_dir + out_name
    try:
        with open(out_file, 'w+', encoding='utf-8') as of:
            print(static.PROMPT_OKPLUS + " Saving response as CSV...")
            of.write(headers)
            of.writelines(rows)
            print(static.PROMPT_OKPLUS + " Response saved in {}".format(out_file))
    except Exception as e:
        print(static.PROMPT_ERROR + " Could not write CSV file. Error: {}".format(e))


def exec_manual_recast(expire_in_days, new_severity, comment, req_payload, ignore_dict, analysis_url, recast_url, headers, log_path, debug_path, api_user, l_user, l_host):
    """
    Function will perform a manual recast based on the provided query parameters.
    :param expire_in_days: The expiration value for a RecastRule
    :param new_severity: The new severity to recast a vulnverability to
    :param comment: The Recast Comment to include
    :param req_payload: The query (json represented as python dict)
    :param ignore_dict: The lists for comments and plugins to be "ignored"/"warn the user of"
    :param analysis_url: The 'analysis' API endpoint of Tenable SC
    :param recast_url: The 'bulk' API endpoint of Tenable SC
    :param headers: The HTTP headers
    :param log_path: The absolute path for the log file
    :param debug_path: The absolute path for the debug file
    :param api_user: The username associated with the current API key
    :param l_user: The username on the machine running vulncaster
    :param l_host: The hostname of the machine running vulncaster
    """
    skip_validation = get_boolean_userinput("\n{} Would you like to skip validation checks? If you choose to NOT skip validation checks, every time there is a vulnerability that has been recasted before, you will be asked to manually approve its current recast.\n"
                                            "\\_Even if you do not skip now, you will have the option to skip later. Enter your choice".format(static.PROMPT_QUESTION))
    print("\n{} Sending analysis query.".format(static.PROMPT_OKPLUS))
    # list that holds the operations that will be called with the 'bulk' api
    operations = []
    operations_dict = {}

    payload = json.dumps(req_payload)

    q_resp = requests.request(method='POST', url=analysis_url, headers=headers, data=payload, verify=False)
    q_json_response = json.loads(q_resp.text)

    q_req_debug = prepare_debug_entry('QUERY REQUEST', payload, "n/a", analysis_url)
    q_resp_debug = prepare_debug_entry('QUERY RESPONSE', json.dumps(q_json_response), q_resp.status_code, analysis_url)

    write_to_log(None, None, q_req_debug, debug_path)
    write_to_log(None, None, q_resp_debug, debug_path)

    # check if all returned records are included
    total_records = int(q_json_response["response"]["totalRecords"])
    ret_records = int(q_json_response["response"]["returnedRecords"])

    if total_records > ret_records:
        print(static.PROMPT_ERROR + " Total records are more than returned records. Set the offset limit with '--limit'.")
        print("\t[!] Total records available: {}".format(total_records))
        print("\t[!] Total records returned: {}".format(ret_records))
        return

    remaining_records = ret_records
    # helps check how many vulns will actually be recasted
    loop_counter = ret_records
    vuln_results_dict = q_json_response["response"]["results"]

    ''' DEBUG
    print(vuln_results)
    sys.exit(0)
    DEBUG '''

    recast_type = "MANUAL"
    log_entries = []

    # WRITE VALUES
    for obj in vuln_results_dict:
        agent_id = None
        ip_addr = None
        plugin_id = None
        old_severity = None
        repo_id = None
        recast_risk = None  # string '0' or '1'
        recast_comment = None
        skip_vuln = False

        for i in obj:
            if i == "severity":
                val = obj[i]["id"]
                old_severity = val

            elif i == "repository":
                val = obj[i]["id"]
                repo_id = val

            elif i == "ip":
                ip_addr = obj[i]

            elif i == "pluginID":
                plugin_id = obj[i]

            elif i == "uuid":
                agent_id = obj[i]

            elif i == "recastRiskRuleComment":
                recast_comment = obj[i]

            elif i == "recastRisk":
                recast_risk = obj[i]

        host_id = "\"UUID: {}\"".format(agent_id) if agent_id != "" else "\"IP: {}\"".format(ip_addr)

        # if this has been recasted before, then check ignore list
        if recast_risk != '0' and not skip_validation:
            # check ignore list
            formatted_comment = colorama.Fore.LIGHTWHITE_EX + colorama.Style.BRIGHT + recast_comment + colorama.Style.RESET_ALL
            print(static.PROMPT_EXCLAMATION + " The vulnerability for host with {0} has been recasted before. The comment is: {1}".format(host_id, formatted_comment))
            if not get_boolean_userinput("\t\\_{0} Do you want to proceed and recast plugin '{1}' for host with {2}?".format(static.PROMPT_QUESTION, plugin_id, host_id)):
                skip_vuln = True
                remaining_records -= 1


        if plugin_id in ignore_dict['plugins'] and not skip_validation:
            print(static.PROMPT_EXCLAMATION + " This plugin ({}) is in the list of ignored plugins.".format(plugin_id))
            if not get_boolean_userinput("\t\\_{0} Do you want to proceed with the current recast for the host with {1}?".format(static.PROMPT_QUESTION, host_id)):
                skip_vuln = True
                remaining_records -= 1

        # VALIDATION CHECK PROMPTS
        loop_counter -= 1
        if not skip_validation:
            print(static.PROMPT_OKPLUS + " Validation for this vulnerability completed.")
            if loop_counter > 0:
                skip_validation = get_boolean_userinput("\t\\_{} Would you like to skip the rest of the validation checks?".format(static.PROMPT_QUESTION))

        # if ignore list comment is matched, we will not recast
        if skip_vuln:
            continue

        single_operation_payload = preprocess_recast_payload(
            agent_id, plugin_id, new_severity, comment, ip_addr, expire_in_days, repo_id
        )

        operations.append(single_operation_payload)
        log_entries.append(prepare_log_entry(agent_id,ip_addr,plugin_id,recast_type,old_severity,new_severity,expire_in_days,comment, api_user, l_host, l_user))


    if len(operations) < 1:
        print("\t\\_{} There were no applicable records.".format(static.PROMPT_OKPLUS))
        return
    else:
        print("\t\\_{0} {1} plugin(s) will be recasted.".format(static.PROMPT_OKPLUS, remaining_records))
        print("\t\\_{} Sending recast request.".format(static.PROMPT_OKPLUS))

    operations_dict["operations"] = operations
    operations_payload = json.dumps(operations_dict)

    recast_response = requests.request(method="POST", url=recast_url, headers=headers, data=operations_payload, verify=False)
    recast_json_response = json.dumps(recast_response.text)

    r_req_debug = prepare_debug_entry('RECAST REQUEST', operations_payload, "n/a", recast_url)
    write_to_log(None, None, r_req_debug, debug_path)

    r_resp_debug = prepare_debug_entry('RECAST RESPONSE', recast_json_response.replace("\\\"", "'"), recast_response.status_code, recast_url)

    if recast_response.status_code == 200:
        write_to_log(log_entries, log_path, r_resp_debug, debug_path)
        print("\t\\_{} Recast was successfully executed.".format(static.PROMPT_OKPLUS))
    else:
        rt = recast_json_response.replace("\\\"", "'")
        rt = rt.replace("\\\\n", " ")
        rt = rt.strip()
        print("\t\\_{0} The endpoint has responded with HTTP {1}: {2}".format(static.PROMPT_ERROR, recast_response.status_code, rt))
        write_to_log(None, None, r_resp_debug, debug_path)


def exec_recast_rules(rules_dict, ignore_dict, analysis_url, recast_url, headers, log_path, debug_path, api_user, l_user, l_host):
    """
    Runs all the recast rules as defined in the rules_dict.
    :param rules_dict: Contains the recast rules
    :param ignore_dict: Contains the ignore comments and plugins
    :param analysis_url: The 'analysis' API endpoint of Tenable SC
    :param recast_url: The 'bulk' API endpoint of Tenable SC
    :param headers: The HTTP headers
    :param log_path: The absolute path for the log file
    :param debug_path: The absolute path for the debug file
    :param api_user: The username associated with the current API key
    :param l_user: The username on the machine running vulncaster
    :param l_host: The hostname of the machine running vulncaster
    """
    for k, v in rules_dict.items():
        query_id = k
        expire_in_days = static.PERMANENT_NO_EXPIRATION
        comment = "RECAST RULE {}".format(query_id)
        new_severity = v['new_severity']

        print()  # fresh new line
        print(static.PROMPT_OKPLUS + " Querying analysis endpoint for {}".format(comment))
        # list that holds the operations that will be called with the 'bulk' api
        operations = []
        operations_dict = {}

        payload = json.dumps(v['req_payload'])

        query_response = requests.request(method='POST', url=analysis_url, headers=headers, data=payload, verify=False)
        query_json_response = json.loads(query_response.text)

        q_req_debug = prepare_debug_entry('QUERY REQUEST', payload, "n/a", analysis_url)
        q_resp_debug = prepare_debug_entry('QUERY RESPONSE', json.dumps(query_json_response), query_response.status_code, analysis_url)

        write_to_log(None, None, q_req_debug, debug_path)
        write_to_log(None, None, q_resp_debug, debug_path)

        # check if all returned records are included
        total_records = int(query_json_response["response"]["totalRecords"])
        ret_records = int(query_json_response["response"]["returnedRecords"])

        if total_records > ret_records:
            print("\t\\_{} Total records are more than returned records, please check if changes have been applied.".format(static.PROMPT_ERROR))
            print("\t\t\\_{0} Total records available: {1}".format(static.PROMPT_EXCLAMATION, total_records))
            print("\t\t\\_{0} Total records returned: {1}".format(static.PROMPT_EXCLAMATION, ret_records))
            sys.exit(-1)

        elif ret_records < 1:
            print("\t\\_{} No records were returned from the query.".format(static.PROMPT_EXCLAMATION))
            # sys.exit(1)
            # Since we are running multiple queries with every execution of the script, we need to continue instead of exit().
            continue

        remaining_records = ret_records
        vuln_results_dict = query_json_response["response"]["results"]

        ''' DEBUG
        print(vuln_results)
        sys.exit(0)
        DEBUG '''

        recast_type = "RULE"
        log_entries = []

        # WRITE VALUES
        for obj in vuln_results_dict:
            agent_id = None
            ip_addr = None
            plugin_id = None
            old_severity = None
            repo_id = None
            recast_risk = None  # string '0' or '1'
            recast_comment = None
            skip_vuln = False

            for i in obj:
                if i == "severity":
                    val = obj[i]["id"]
                    old_severity = val

                elif i == "repository":
                    val = obj[i]["id"]
                    repo_id = val

                elif i == "ip":
                    ip_addr = obj[i]

                elif i == "pluginID":
                    plugin_id = obj[i]

                elif i == "uuid":
                    agent_id = obj[i]

                elif i == "recastRiskRuleComment":
                    recast_comment = obj[i]

                elif i == "recastRisk":
                    recast_risk = obj[i]

            # if this has been recasted before, then check ignore list
            if recast_risk != 0:
                # check ignore list
                for ignore_string in ignore_dict['comments']:
                    if ignore_string.casefold() in recast_comment.casefold():
                        skip_vuln = True
                        remaining_records -= 1
                        break

            if plugin_id in ignore_dict['plugins']:
                skip_vuln = True
                remaining_records -= 1

            # if ignore list comment is matched, we will not recast
            if skip_vuln:
                continue

            single_operation_payload = preprocess_recast_payload(
                agent_id, plugin_id, new_severity, comment, ip_addr, expire_in_days, repo_id
            )

            operations.append(single_operation_payload)
            log_entries.append(prepare_log_entry(agent_id,ip_addr,plugin_id,recast_type,old_severity,new_severity,expire_in_days,comment, api_user, l_host, l_user))

        if len(operations) < 1:
            print("\t\\_{w} There were no applicable records.".format(w=static.PROMPT_EXCLAMATION))
            continue  # move on with loop
        else:
            if remaining_records == 1:
                returned_res_msg = "Returned 1 result."
            else:
                returned_res_msg = "Returned {} results.".format(remaining_records)
            print("\t\\_{w} {ret_res_msg}\n\t\\_{w} Sending recast request.".format(w=static.PROMPT_EXCLAMATION,ret_res_msg=returned_res_msg))

        operations_dict["operations"] = operations
        operations_payload = json.dumps(operations_dict)

        recast_response = requests.request(method="POST", url=recast_url, headers=headers, data=operations_payload, verify=False)
        recast_json_response = json.dumps(recast_response.text)

        r_req_debug = prepare_debug_entry('RECAST REQUEST', operations_payload, "n/a", recast_url)
        write_to_log(None, None, r_req_debug, debug_path)

        r_resp_debug = prepare_debug_entry('RECAST RESPONSE', recast_json_response.replace("\\\"", "'"), recast_response.status_code, recast_url)

        if recast_response.status_code == 200:
            write_to_log(log_entries, log_path, r_resp_debug, debug_path)
            print("\t\\_{} Recast rule has been successfully executed.".format(static.PROMPT_OKPLUS))
        else:
            rt = recast_json_response.replace("\\\"", "'")
            rt = rt.replace("\\\\n", " ")
            rt = rt.strip()
            print("\t\\_{0} The endpoint has responded with HTTP {1}: {2}".format(static.PROMPT_ERROR, recast_response.status_code, rt))
            write_to_log(None, None, r_resp_debug, debug_path)


def view_rules(rules_dict, rule_key):
    rule_headers = ["ID", "REPO IDs", "RECAST RISK", "CVSS v3", "VPR", "EXPLOIT", "ACR", "RECAST TO"]
    tab_list = []

    if rule_key == 0:  # ALL RULES SELECTED
        for k in rules_dict.keys():
            tab_rule_dict = get_tabulated_rule(rules_dict, k)
            entry = [
                k,
                tab_rule_dict["repositories_str"],
                tab_rule_dict["recast_risk"],
                tab_rule_dict["cvss_v3"],
                tab_rule_dict["vpr"],
                tab_rule_dict["exploit"],
                tab_rule_dict["acr"],
                tab_rule_dict["recast_to"]
            ]
            tab_list.append(entry)
    else:  # RULE KEY IS THE ACTUAL ID
        print()
        print("# RULE {}".format(rule_key))
        tab_rule_dict = get_tabulated_rule(rules_dict, rule_key)
        entry = [
            rule_key,
            tab_rule_dict["repositories_str"],
            tab_rule_dict["recast_risk"],
            tab_rule_dict["cvss_v3"],
            tab_rule_dict["vpr"],
            tab_rule_dict["exploit"],
            tab_rule_dict["acr"],
            tab_rule_dict["recast_to"]
        ]
        tab_list.append(entry)

    print(tabulate2.tabulate(tab_list,headers=rule_headers, tablefmt="pretty"))
    print()


def get_tabulated_rule(rules_dict, rule_key):
    filters_dict = rules_dict[rule_key]['req_payload']['query']['filters']

    repositories_str = "*"
    recast_risk = "*"
    cvss_v3 = "*"
    vpr = "*"
    exploit = "*"
    acr = "*"
    recast_to = static.SEVERITIES[str(rules_dict[rule_key]['new_severity'])]

    for obj in filters_dict:
        if obj['id'] == "repository":
            repository_ids = []
            for v in obj['value']:
                repository_ids.append(v['id'])
            repositories_str = ",".join(repository_ids)

        # RecastRisk
        elif obj['id'] == "recastRiskStatus":
            if obj['value'] == "recast":
                recast_risk = "YES"
            elif obj['value'] == "notRecast":
                recast_risk = "NO"

        elif obj['id'] == "cvssV3BaseScore":
            cvss_v3 = obj['value']

        elif obj['id'] == "vprScore":
            vpr = obj['value']

        elif obj['id'] == "exploitAvailable":
            exploit = obj['value']

        elif obj['id'] == "assetCriticalityRating":
            acr = obj['value']

    tab_rule_dict = {
        "repositories_str": repositories_str,
        "recast_risk": recast_risk,
        "cvss_v3": cvss_v3,
        "vpr": vpr,
        "exploit": exploit,
        "acr": acr,
        "recast_to": recast_to
    }

    return tab_rule_dict


def get_rule_id_from_rules(rules_dict, prompt):
    rule_id = get_userinput(prompt)

    while rule_id.casefold() not in [x.casefold() for x in rules_dict.keys()]:
        print("\t\\_{} This rule ID does not exist in your rules config file.\n".format(static.PROMPT_ERROR))
        rule_id = get_userinput("{} Provide an existing rule ID".format(static.PROMPT_EXCLAMATION))

    return rule_id


def get_new_rule(rules_dict, tenable_sc_host):
    new_rule_id = get_userinput("{} Enter ID/Name for the new rule".format(static.PROMPT_EXCLAMATION))

    while new_rule_id.casefold() in [x.casefold() for x in rules_dict.keys()]:
        print("\t\\_{} This rule ID/Name already exists.\n".format(static.PROMPT_ERROR))
        new_rule_id = get_userinput("{} Provide a unique name".format(static.PROMPT_EXCLAMATION))

    new_rule_dict = generate_rule_dict_entry(new_rule_id, tenable_sc_host)

    return new_rule_dict


def generate_rule_dict_entry(rule_id, tenable_sc_host):
    print(colorama.Fore.LIGHTYELLOW_EX)
    print("# SEVERITIES TABLE")
    print(tabulate2.tabulate([["VALUE","TRANSLATES TO"],["4","CRITICAL"],["3","HIGH"],["2","MEDIUM"],["1","LOW"],["0","INFO"]],headers="firstrow",tablefmt="pretty"))
    print(colorama.Style.RESET_ALL)  # new line

    recast_severity = get_numeric_userinput(static.SEVERITIES.keys(), "{} Enter severity to \"recast to\" in rule (0 - 4)".format(static.PROMPT_EXCLAMATION))

    print()

    analysis_query_url = get_userinput("{} Tenable SC URL to apply for the new rule".format(static.PROMPT_EXCLAMATION))

    # max offset limit is 15000. Change manually in code if needed (function parameter of convert_url_to_payload)
    new_rule_payload = convert_url_to_payload(analysis_query_url, tenable_sc_host)

    rule_dict = {
        rule_id: {
            "new_severity": recast_severity,
            "id": rule_id,
            "req_payload": new_rule_payload
        }
    }

    return rule_dict




class VulncasterApp(cmd2.Cmd):
    def __init__(self):
        history_filename = ensure_filename_without_leading_slash("config/history.dat")
        super().__init__(persistent_history_file=get_cwd_path()+history_filename, persistent_history_length=1000)

        # print(colorama.Back.WHITE)

        # Disabled commands
        self.disable_command('run_script','disabled by PS')
        self.disable_command('macro','disabled by PS')
        # self.disable_command('set','disabled by PS')
        self.disable_command('shortcuts','disabled by PS')
        self.disable_command('edit','disabled by PS')
        self.disable_command('run_pyscript','disabled by PS')

        # Hidden but functioning normally
        self.hidden_commands.append('alias')
        self.hidden_commands.append('quit')
        self.hidden_commands.append('exit')
        self.hidden_commands.append('stop')
        self.hidden_commands.append('help')
        self.hidden_commands.append('history')
        self.hidden_commands.append('set')

        print_logo_lines()
        print("\nType 'help' or '?' to list commands. Type 'help <command>' to view command-specific help messages\n")

        # Get CWD and configuration file path
        self.cwd = get_cwd_path()
        self.conf_file = self.cwd + ensure_filename_without_leading_slash("config/config.json")
        self.ignore_file = self.cwd + ensure_filename_without_leading_slash("config/ignore_lists.json")
        self.rules_file = self.cwd + ensure_filename_without_leading_slash("config/recast_rules.json")

        # Output directory that holds exports (e.g., CSV files)
        self.output_dir = ensure_dir_with_trailing_slash(self.cwd + "output")
        # holds all configuration variables
        self.conf_dict = read_json_data(self.conf_file)
        # holds all comments and plugins to ignore when recasting
        self.ignore_dict = read_json_data(self.ignore_file)
        # holds all the rules
        self.rules_dict = read_json_data(self.rules_file)

        self.ignored_plugins = self.ignore_dict['plugins']
        self.ignored_comments = self.ignore_dict['comments']
        self.log_dir = self.conf_dict['log_dir']
        self.debug_enabled = self.conf_dict['debug']

        self.analysis_url = self.conf_dict['api_endpoint']['url'] + self.conf_dict['api_endpoint']['analysis']
        self.recast_url = self.conf_dict['api_endpoint']['url'] + self.conf_dict['api_endpoint']['bulk']

        # if returned value from load_var_from_json() is None, then use a default value
        self.prompt = (load_var_from_dict(self.conf_dict, "prompt") or "Vulncaster >> ")

        self.headers = self.conf_dict['api_endpoint']['headers']
        # Validates the API key before setting it
        self.api_key_value = init_api_key(self.conf_dict, self.headers)
        self.headers['x-apikey'] = self.api_key_value

        api_user_details_response = get_api_user_details(self.conf_dict, self.headers)
        api_user_details_response_dict = json.loads(api_user_details_response.text)
        self.api_user_details_dict = api_user_details_response_dict['response']
        self.api_username = self.api_user_details_dict['username']

        self.local_hostname = platform.node()
        self.local_username = os.getlogin()

        self.print_session_info()

    # =========================== CMD2 METHODS =============================== #
    # same as built-in quit
    @staticmethod
    def do_exit(arg):
        """Exit the application."""
        return True

    # same as built-in quit
    @staticmethod
    def do_stop(arg):
        """Exit the application."""
        return True

    def complete_show_logs(self, text, line, begidx, endidx):
        """Custom completer for the show_logs command.
        This method is automatically called by the Cmd2 main loop and does not have to be explicitly called.
        When a user enters the 'show_logs' command, using <tab> will automatically list all files/dirs in the
        directory specified in the 'log_dir' key of the configuration file.
        """
        ## alternative implementation, in case you want to extend functionality
        # excluded_keywords = ["debug", "readme"]
        # all_files = [f for f in os.listdir(self.log_dir) if f.startswith(text)]
        # files = []
        # for file in all_files:
        #     for taboo in excluded_keywords:
        #         if not file.startswith(taboo.casefold()):
        #             files.append(file)
        # return files

        files = [f for f in os.listdir(self.log_dir) if f.startswith(text) and not f.startswith("debug".casefold())]
        return files

    def print_session_info(self):
        username = self.api_username
        email = self.api_user_details_dict['email']
        if email == "":
            email = "N/A"
        role = self.api_user_details_dict['role']['name']


        print()  # new line
        self.pwarning("# API USER INFO")
        self.pwarning(tabulate2.tabulate([["USERNAME","EMAIL","ROLE"],[username,email,role]],headers="firstrow",tablefmt="pretty"))
        print()  # new line

    # ============================ RELOAD CONFIGURATION FILE ============================== #
    # reload_parser = cmd2.Cmd2ArgumentParser()
    # @cmd2.with_argparser(reload_parser)
    def do_reload_config(self, args):
        """
        Reloads all configuration parameters from config.json, as well as recast rules and ignore_lists
        """

        # CWD should be the same, main loop is still running.
        # The temp variables are kept in case the user doesn't want to reload them
        api_key_temp = self.headers['x-apikey']

        self.conf_dict = read_json_data(self.conf_file)
        # holds all comments and plugins to ignore when recasting
        self.ignore_dict = read_json_data(self.ignore_file)

        self.ignored_plugins = self.ignore_dict['plugins']
        self.ignored_comments = self.ignore_dict['comments']
        self.log_dir = self.conf_dict['log_dir']
        self.debug_enabled = self.conf_dict['debug']

        self.analysis_url = self.conf_dict['api_endpoint']['url'] + self.conf_dict['api_endpoint']['analysis']
        self.recast_url = self.conf_dict['api_endpoint']['url'] + self.conf_dict['api_endpoint']['bulk']

        # if returned value from load_var_from_json() is None, then use a default value
        self.prompt = (load_var_from_dict(self.conf_dict, "prompt") or "Vulncaster >> ")

        self.headers = self.conf_dict['api_endpoint']['headers']

        if not get_boolean_userinput("{0} Do you want to keep using the API key for user '{1}'?".format(static.PROMPT_QUESTION, self.api_username)):
            # Validates the API key before setting it
            self.api_key_value = init_api_key(self.conf_dict, self.headers)
            self.headers['x-apikey'] = self.api_key_value

            # Get the details of the user account initiating the API calls. Might be used in the future for debugging.
            api_user_details_response = get_api_user_details(self.conf_dict, self.headers)
            api_user_details_response_dict = json.loads(api_user_details_response.text)
            self.api_user_details_dict = api_user_details_response_dict['response']
            self.api_username = self.api_user_details_dict['username']

            self.print_session_info()

        else:
            self.headers['x-apikey'] = api_key_temp
            # api username and apidetails are already loaded from the init method. They are not being reset above.

    # ============================ EXPORT CSV ============================== #
    # Parser for running recast rules
    exp_csv_parser = cmd2.Cmd2ArgumentParser()
    exp_csv_parser.add_argument("--limit", type=int, required=False, help="Manually set the limit of returned results.")
    @cmd2.with_argparser(exp_csv_parser)
    def do_export_csv(self, args):
        print("")
        analysis_query_url = get_userinput("Tenable SC cumulative vulnerabilities URL")
        req_payload = convert_url_to_payload(analysis_query_url, self.conf_dict['api_endpoint']['url'], offset_limit=args.limit) if args.limit else convert_url_to_payload(analysis_query_url, self.conf_dict['api_endpoint']['url'])

        if req_payload is None:
            self.perror("[!] Cancelling manual recast.")
        else:
            exec_csv_export(req_payload, self.analysis_url, self.headers, self.output_dir)

    # ============================ MANUAL RECAST  ============================== #
    # Parser for running recast rules
    manual_recast_parser = cmd2.Cmd2ArgumentParser()
    manual_recast_parser.add_argument("--limit", type=int, required=False, help="Manually set the limit of returned results.")
    @cmd2.with_argparser(manual_recast_parser)
    def do_manual_recast(self, args):
        log_path, debug_path = initialise_log(self.log_dir, self.debug_enabled)

        print()  # new line

        analysis_query_url = get_userinput("Tenable SC cumulative vulnerabilities URL")
        req_payload = convert_url_to_payload(analysis_query_url, self.conf_dict['api_endpoint']['url'], offset_limit=args.limit) if args.limit else convert_url_to_payload(analysis_query_url, self.conf_dict['api_endpoint']['url'])

        if req_payload is None:
            self.perror("[!] Cancelling manual recast.")
        else:
            print("\n")
            self.pwarning("# SEVERITIES TABLE")
            self.pwarning(tabulate2.tabulate([["VALUE","TRANSLATES TO"],["4","CRITICAL"],["3","HIGH"],["2","MEDIUM"],["1","LOW"],["0","INFO"]],headers="firstrow",tablefmt="pretty"))

            print()  # new line
            recast_severity = get_numeric_userinput(static.SEVERITIES.keys(), "Enter new severity (0 - 4)")
            if recast_severity is None:
                return

            print()  # new line
            self.pwarning("# EXPIRATION DAYS EXAMPLE")
            self.pwarning(
                tabulate2.tabulate([
                    ["VALUE","TRANSLATES TO","EXPIRES ON (YYYY-MM-DD)"],
                    ["-1","NEVER EXPIRES","NEVER"],
                    ["365","1 YEAR", str(datetime.date.today() + datetime.timedelta(days=365))],
                    ["2","2 DAYS",str(datetime.date.today() + datetime.timedelta(days=2))]
                ],
                    headers="firstrow",tablefmt="pretty"
                )
            )
            print()  # new line
            exp_in_days = get_userinput("Enter expiration time. Provide the value in number of days")

            print()  # new line
            self.pwarning("# COMMENT FOR MANUAL RECAST")
            user_comment = get_userinput("Enter your comment for this recast")
            comment = "MANUAL RECAST: {}".format(user_comment)

            if exp_in_days == str(static.PERMANENT_NO_EXPIRATION):
                exp_date = "NEVER"
            else:
                exp_date = datetime.date.today() + datetime.timedelta(days=int(exp_in_days))
                exp_date = str(exp_date)

            print()
            self.pwarning("# RECAST INFORMATION PROVIDED")
            severity_key = str(recast_severity)
            confirmation_table = [
                ["RECAST EXPIRES",exp_date],
                ["NEW SEVERITY",static.SEVERITIES[severity_key]],
                ["COMMENT",user_comment]
            ]
            self.pwarning(tabulate2.tabulate(confirmation_table))

            if not get_boolean_userinput("{} Is the above recast information provided correct? Answering yes will proceed with the recast.".format(static.PROMPT_QUESTION)):
                self.perror("[!] Please re-run the command to enter new details.")
                return

            exec_manual_recast(int(exp_in_days), int(recast_severity), comment, req_payload, self.ignore_dict, self.analysis_url, self.recast_url, self.headers, log_path, debug_path, self.api_username, self.local_username, self.local_hostname)
            print()  # new line

    # ============================ RUN ALL RECAST RULES ============================== #
    # Parser for running recast rules
    recast_rules_parser = cmd2.Cmd2ArgumentParser()
    # maybe-do-later recast_rules_parser.add_argument("-v", "--verbose", help="Increases the verbosity") This can print more
    # maybe-do-later be able to run a specific recast rule by providing -rid <rule id> as a param
    @cmd2.with_argparser(recast_rules_parser)
    def do_run_recast_rules(self, args):
        """Runs the recast rules defined in 'config/recast_rules.json'"""
        log_path, debug_path = initialise_log(self.log_dir, self.debug_enabled)

        # run the rules
        exec_recast_rules(
            self.rules_dict, self.ignore_dict, self.analysis_url, self.recast_url, self.headers,
            log_path, debug_path, self.api_username, self.local_username, self.local_hostname
        )

    # ============================ SHOW LOG FILES ============================== #
    # maybe-do-later show minimum logs or full logs from specific file (specific day)
    # maybe-do-later provide flag for viewing all logs or up to a limit, starting from oldest or newest
    @cmd2.with_argument_list
    def do_show_logs(self, arglist):
        """
        Pretty-print log files based on filename
        """
        if not arglist or len(arglist) != 1:
            self.perror("[X]: Only a filename is required. Type 'show_logs' and press <TAB> to show available log files.")
            return

        logfile = self.log_dir + arglist[0]
        with open(logfile, 'r', encoding="utf-8") as csv:
            csv_lines = csv.readlines()
            csv_lines[0] = "#," + csv_lines[0]

        self.pwarning("[!] Some data has been trimmed/removed. View the actual log file for full data.\n")

        # headers = colorama.Fore.LIGHTCYAN_EX + colorama.Style.BRIGHT + csv_lines[0] + colorama.Fore.RESET + colorama.Style.RESET_ALL
        # tabulate_lines = [headers.split(",")[:-3]]
        tabulate_lines = [csv_lines[0].split(",")[:-3]]

        for i in range(1, len(csv_lines)):
            new_line = csv_lines[i].strip()
            new_line = "{},".format(i) + new_line
            tabulated = new_line.split(",")[:-3]
            tabulated[-1] = tabulated[-1][:30] + "[...]"
            tabulate_lines.append(tabulated)

        self.poutput(tabulate2.tabulate(tabulate_lines,headers="firstrow",tablefmt="grid",maxcolwidths=[10]))

    # ============================ PRINT FILE PATHS ============================== #
    def do_print_file_paths(self, args):
        """
        Prints the absolute file paths of the configuration and log files.
        """
        print()
        self.poutput("LOG DIRECTORY: {}".format(self.log_dir))
        self.poutput("CONFIG FILE: {}".format(self.conf_file))
        self.poutput("IGNORE LISTS FILE: {}".format(self.ignore_file))
        self.poutput("RECAST RULES FILE: {}".format(self.rules_file))
        print()

    # ============================ MANAGE RECAST RULES ============================== #
    # noinspection DuplicatedCode
    def do_rule_management(self, args):
        """
        Create, Modify or Delete Recast Rules
        """
        def overwrite_rules_config():
            """
            Will back up the current rules configuration file and update the main rules file to include the new changes.
            It does not require arguments to be passed, because it is operating directly on the variables in the Class' scope
            """
            # make a backup of old rules
            bak_tstamp = str(datetime.datetime.now())
            bak_tstamp = bak_tstamp.replace(":", "-")
            bak_tstamp = bak_tstamp.replace(" ", "_")
            bak_tstamp = "_".join(bak_tstamp.split(".")[:-1])

            backup_name = "_bak_{}.json".format(bak_tstamp)
            rules_backup_file = self.rules_file.rstrip(".json")
            rules_backup_file = str(rules_backup_file) + backup_name

            print()
            self.poutput("{} Creating rules backup file...".format(static.PROMPT_EXCLAMATION))
            shutil.copy(self.rules_file, rules_backup_file)
            self.poutput("\t\\_{0} Done. Wrote to \"{1}\"".format(static.PROMPT_OKPLUS, rules_backup_file))

            print()
            self.poutput("{} Overwriting main rules file...".format(static.PROMPT_EXCLAMATION))
            # overwrite existing file
            with open(self.rules_file, "w+") as f:
                f.write(json.dumps(self.rules_dict, indent=2))
            self.poutput("\t\\_{} Done.".format(static.PROMPT_OKPLUS))
            print()


        self.poutput("\nChoose one of the options below.")
        self.pwarning("# MANAGE RECAST RULES")
        self.pwarning(tabulate2.tabulate(
            [["#", "ACTION"], ["1", "VIEW RULES"], ["2", "REPLACE RULE"], ["3", "DELETE RULE"], ["4", "ADD NEW RULE"]],
            headers="firstrow", tablefmt="pretty"))

        print()
        action = get_numeric_userinput([1,2,3,4], "Choose action (1 - 4)")

        print()
        choose_prompt = "Choose rule"

        if action is None:
            return

        # Show
        elif action == 1:
            # Show option for each rule
            rule_ids = [["1", "SHOW ALL RULES"]]
            # create a list that contains all the option indices e.g., [1,2,3,4,5,6,7....]
            counter = 2
            for rule_id in self.rules_dict.keys():
                rule_ids.append([counter, "RULE {}".format(rule_id)])
                counter += 1

            self.pwarning(tabulate2.tabulate(rule_ids, headers=["#", "RULE ID"], tablefmt="pretty"))

            choice_idx_list = list(range(1, len(rule_ids) + 1))
            view_action = int(get_numeric_userinput(choice_idx_list, choose_prompt))

            if view_action > 1:
                chosen_id = rule_ids[view_action - 1][-1]  # gets the last/second item from the list, which is the rule id
                rule_k = chosen_id.lstrip("RULE ")
            else:
                chosen_id = 0
                rule_k = chosen_id

            view_rules(self.rules_dict, rule_k)

        # replaces a rule with new rule
        elif action == 2:
            prompt = "{} Enter ID of the rule to modify".format(static.PROMPT_EXCLAMATION)
            user_provided_id = get_rule_id_from_rules(self.rules_dict, prompt)
            rule_key = "VULNCASTER BY PSOUTZIS"

            # get the key by looping all keys, to ensure case sensitivity of original rule
            for k in self.rules_dict.keys():
                if user_provided_id.casefold() == k.casefold():
                    rule_key = k
                    break

            new_rule_dict = generate_rule_dict_entry(rule_key, self.conf_dict['api_endpoint']['url'])

            # Show rule to delete in CLI
            print()
            self.pwarning("# RULE TO EDIT")
            rule_headers = ["ID", "REPO IDs", "RECAST RISK", "CVSS v3", "VPR", "EXPLOIT", "ACR", "RECAST TO"]
            tab_rule_dict = get_tabulated_rule(self.rules_dict, rule_key)
            self.pwarning(tabulate2.tabulate(
                [
                    [
                        rule_key,
                        tab_rule_dict["repositories_str"],
                        tab_rule_dict["recast_risk"],
                        tab_rule_dict["cvss_v3"],
                        tab_rule_dict["vpr"],
                        tab_rule_dict["exploit"],
                        tab_rule_dict["acr"],
                        tab_rule_dict["recast_to"]
                    ]
                ],headers=rule_headers, tablefmt="pretty")
            )

            print()
            self.pwarning("# NEW RULE")
            tab_rule_dict = get_tabulated_rule(new_rule_dict, rule_key)
            self.pwarning(tabulate2.tabulate(
                [
                    [
                        rule_key,
                        tab_rule_dict["repositories_str"],
                        tab_rule_dict["recast_risk"],
                        tab_rule_dict["cvss_v3"],
                        tab_rule_dict["vpr"],
                        tab_rule_dict["exploit"],
                        tab_rule_dict["acr"],
                        tab_rule_dict["recast_to"]
                    ]
                ],headers=rule_headers, tablefmt="pretty")
            )

            print()

            proceed = get_boolean_userinput("{0} Are you sure you want to replace rule \"{1}\"".format(static.PROMPT_QUESTION, rule_key))

            if proceed:
                self.rules_dict[rule_key] = new_rule_dict[rule_key]
                overwrite_rules_config()
            else:
                self.poutput("\t\\_{} Cancelling rule deletion.\n".format(static.PROMPT_ERROR))

        # deletes an existing rule
        elif action == 3:
            prompt = "{} Enter ID of the rule to delete".format(static.PROMPT_EXCLAMATION)
            user_provided_id = get_rule_id_from_rules(self.rules_dict, prompt)
            rule_key = "VULNCASTER BY PSOUTZIS"

            # get the key by looping all keys, to ensure case sensitivity of original rule
            for k in self.rules_dict.keys():
                if user_provided_id.casefold() == k.casefold():
                    rule_key = k
                    break

            # Show rule to delete in CLI
            print()
            self.pwarning("# RULE TO DELETE")
            rule_headers = ["ID", "REPO IDs", "RECAST RISK", "CVSS v3", "VPR", "EXPLOIT", "ACR", "RECAST TO"]

            tab_rule_dict = get_tabulated_rule(self.rules_dict, rule_key)
            self.pwarning(tabulate2.tabulate(
            [
                [
                    rule_key,
                    tab_rule_dict["repositories_str"],
                    tab_rule_dict["recast_risk"],
                    tab_rule_dict["cvss_v3"],
                    tab_rule_dict["vpr"],
                    tab_rule_dict["exploit"],
                    tab_rule_dict["acr"],
                    tab_rule_dict["recast_to"]
                ]
            ],headers=rule_headers, tablefmt="pretty")
            )

            proceed = get_boolean_userinput("{0} Are you sure you want to delete rule \"{1}\"".format(static.PROMPT_QUESTION, rule_key))

            if proceed:
                del self.rules_dict[rule_key]
                overwrite_rules_config()
            else:
                self.poutput("\t\\_{} Cancelling rule deletion.\n".format(static.PROMPT_ERROR))

        # adds new rule
        elif action == 4:
            new_rule = get_new_rule(self.rules_dict, self.conf_dict['api_endpoint']['url'])
            new_key = list(new_rule.keys())[0]  # get first key, as it is the only item in dictionary

            self.rules_dict[new_key] = new_rule[new_key]

            overwrite_rules_config()



# MAIN
main_instance = VulncasterApp()
main_instance.cmdloop()