# Tested with Python 3.10
import json
import os
import boto3
import urllib3
import urllib   #Required for urlencode
from datetime import datetime, timezone, timedelta
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
UCI = True
CLOUD_VENDOR_SYSDIG = "aws"     # Only AWS for now (Pls note that Sysdig aws name is "aws")
CLOUD_VENDOR_NSKP = "Amazon"    # Only AWS for now (Pls note that Netskope aws name is "Amazon")
TIMEOUT_TIME = 15
SECTOKEN_HEADER = "secToken"

# Load system vars from environment
config = {
    'sysdig_url': os.environ['sysdig_url'],
    'sysdig_token': os.environ['sysdig_token'],
    'netskope_url': os.environ['netskope_url'],
    'netskope_token': os.environ['netskope_token'],
    'lambda_sec_token': os.environ['securityToken'],
    'aws_snsarn': os.environ['aws_snsarn'], 
}

http = urllib3.PoolManager(cert_reqs='CERT_NONE') # Do it secure with http = urllib3.PoolManager(ca_certs='/path/to/certfile')

# To be customized by the customer according to his policies/rules
# Tip: Add stateful detections high-confidence impacts over standalone events.
# netskp field is required to match sysdig events with the expected string to be found in netskope logs (* means wildcard)
sysdig_findings = [
    {"name":"Create Password for User", "penalty": 150, "netskp":"iam"},
    {"name":"Delete Bucket Public Access Block", "penalty":350, "netskp":"s3"},
    {"name":"Register Domain", "penalty":250, "netskp":"route53"},
    {"name":"Delete Detector", "penalty":250, "netskp":"guardduty"},
    {"name":"CloudTrail Trail Deleted", "penalty":250, "netskp":"cloudtrail"},
    {"name":"CloudTrail Logging Disabled", "penalty":250, "netskp":"cloudtrail"},
    {"name":"AWS Suspicious IP Inbound Request", "penalty":1000, "netskp":"aws"},
    {"name":"Put Bucket ACL for AllUsers", "penalty":350, "netskp":"s3"},
    {"name":"Deactivate MFA for Root User", "penalty":600, "netskp":"iam"},
    {"name":"Delete WAF Rule Group", "penalty":250, "netskp":"firewall"},
]

def lambda_handler(event, context):
    #checkHttpSecToken(event['headers']) # Enable for enhanced security
    print("Processing Sysdig Notification")
    # Extract Sysdig notification
    eventName, userName = extractEventFromSysdigWebhook(event)
    print(f"Sysdig notification > Event {eventName} identified")
    # Interpret Sysdig notification
    sysdigEventRisk, ntskpNeedle = identifySysdigRiskyEvt(eventName)
    # Find out if the identity is operating from an employee laptop
    trustedDevice = ntskpValidateEmployeeActivity(userName, ntskpNeedle)
    if trustedDevice:
        print("TRUSTED DEVICE (Deduced from comparing Sysdig alert with Netskope employee logs)")
    else:
        print("UNTRUSTED DEVICE (Couldn't match Sysdig alert with Netskope any recent employee log)")

    compromisedId = False
    msg = "No actions performed"

    if sysdigEventRisk > 0:
        # Check Sysdig CIEM intel
        compromisedId = findCompromisedSysdigCIEM(sysdigCIEMRequest(CLOUD_VENDOR_SYSDIG, userName.split("@")[0]))
    
        if trustedDevice:
            # Trusted device doing risky stuff could mean hijacking or dangerous employee. Ggenerating an UCI impact, defined in the script and  increased with Sysdig CIEM risk rating
            print(f"Calculating UCI impact")
            sysdigEventRisk = 1000 if compromisedId else sysdigEventRisk      # Add Compromised-Identity Risk
            print(f"UCI impact calculated, {sysdigEventRisk} points for {userName}")

            print("Reaching out Netskope UCI API")
            status, msg = netskopeSubmitUCIImpact(CLOUD_VENDOR_SYSDIG, sysdigEventRisk, userName, eventName)
            # We could optionally prefer using SCIM to directly block the user in Netskope
            # status, msg = netskopeSCIMblockUser(userName)    

        else:
            # Untrusted device
            # Alert: Potentially dangerous outsider. It can't be blocked by Netskope as he accessed from an untrusted device. 
            msg = "Sending email alert: outsider or untrusted device generating risky activity in the cloud"
            print(msg)
            body = f'Alert, \n\nAn outsider is performing risky operations in the cloud fro an untrusted device.\nUser: {userName}\nCloud: {CLOUD_VENDOR_SYSDIG}\nOperation: {eventName}\n\nRegards,\nSysdig integration | Lambda Function'
            sns_client = boto3.client('sns')
            res = sns_client.publish(
                TopicArn = config['aws_snsarn'],
                Subject = f'Sysdig-Netskope Cloud Alert - {userName} in {CLOUD_VENDOR_SYSDIG}',
                Message = str(body)
                )
    else:           
        print (f"The event severity/risk of the event will not produce any impact or alert")     

    return {
        'statusCode': 200,
        'body': msg
    }

def checkHttpSecToken(headers):
    if (SECTOKEN_HEADER not in str(headers)) or (config['lambda_sec_token'] != event['headers'][SECTOKEN_HEADER]):
        raise ValueError(f"Missing or invalid token: '{SECTOKEN_HEADER}'")


def sysdigCIEMRequest(cloudProvider, userName):
    url = f"https://{config['sysdig_url']}/api/cloud/v2/users?provider={cloudProvider}&kind=user&actorName={userName}"
    
    req_headers = {
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + config['sysdig_token'],
    }

    response = http.request('GET', url, headers=req_headers)
    if not httpRespHandler(response, "Sysdig-CIEM-Request"): 
        return None
    
    return json.loads(response.data)

def netskopeSubmitUCIImpact(source, score, user, event):
    url = f"https://{config['netskope_url']}/api/v2/incidents/user/uciimpact"
    
    req_headers = {
        'Content-Type': 'application/json',
        'Netskope-Api-Token': config['netskope_token'],
    }

    currTime = datetime.now(timezone.utc)
    currTimestampMiliseconds = currTime.timestamp() * 1000

    reason = f"Sysdig detected risk : {event}"
    #reason = f"Sysdig detected risk : Put Bucket ACL for AllUsers"

    data = json.dumps({
        'reason': reason,
        'score': score,
        'source': source,
        'timestamp': currTimestampMiliseconds,
        'user': user
    })
    
    response = http.request('POST', url, headers=req_headers, body=data, timeout=TIMEOUT_TIME)
    if not httpRespHandler(response, "Nestkope-submit-UCI-impact"): 
        return None

    responseData = json.loads(response.data)    
        
    return response.status, responseData


def netskopeSCIMFetchUser(user):
    url = f"https://{config['netskope_url']}/api/v2/scim/Users?startIndex=1&count=25&filter=userName+eq+{user}"
    req_headers = {
        'Content-Type': 'application/json',
        'Netskope-Api-Token': config['netskope_token'],
    }
    response = http.request('GET', url, headers=req_headers, timeout=TIMEOUT_TIME)
    if not httpRespHandler(response, "Nestkope-SCIM-fetch-user"): 
        return None
    
    print(f"SCIM user {user} found")
    
    return json.loads(response.data)


def netskopeSCIMgetGroup(group):
    url = f"https://{config['netskope_url']}/api/v2/scim/Groups?filter=displayName+eq+{group}"
    req_headers = {
        'Content-Type': 'application/json',
        'Netskope-Api-Token': config['netskope_token'],
    }

    response = http.request('GET', url, headers=req_headers, timeout=TIMEOUT_TIME)
    if not httpRespHandler(response, "Nestkope-SCIM-get-group"): 
        return None
    
    print(f"SCIM group {group} found")
    
    return json.loads(response.data)


def netskopeSCIMaddUserToGroup(user, group):
    
    url = f"https://{config['netskope_url']}/api/v2/scim/Groups/{group}"
    req_headers = {
        'Content-Type': 'application/json',
        'Netskope-Api-Token': config['netskope_token'],
    }

    data = json.dumps({
        "Operations": [
            {
            "op": "add",
            "path": "members",
            "value": {
                "value": {
                "value": user
                }
            }
            }
        ],
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        ]
    })

    response = http.request('PATCH', url, headers=req_headers, body=data, timeout=TIMEOUT_TIME)
    if not httpRespHandler(response, "Nestkope-SCIM-add-user-to-group"): 
        return None
        
    print(f"SCIM Blacklist result: {response.status}")

    return response.status


def netskopeSCIMblockUser(user):
    netskopeBlockGroup = "aws_blocked_investigation"

    user = netskopeSCIMFetchUser(user)

    try:
        userId = user['Resources'][0]['id']
    except Exception as e:
        return "User not found in Netskope SCIM API"

    group = netskopeSCIMgetGroup(netskopeBlockGroup)

    try:
        groupId = group['Resources'][0]['id']
    except Exception as e:
        return "Group not found in Netskope SCIM API"

    if netskopeSCIMaddUserToGroup(userId, groupId): 
        message = f"Success: User {user} added to the group {netskopeBlockGroup} for investigation"
    else:
        message = f"Error adding user {user} to the group {netskopeBlockGroup}"

    return status, message


def identifySysdigRiskyEvt(eventRuleName):
    for finding in sysdig_findings:
        if finding['name'] == eventRuleName:
            # eventRuleName found
            return finding['penalty'], finding['netskp']
    # If not found
    return 0, ""   


def extractEventFromSysdigWebhook(event):
    try:
        # Use get() method for safer nested dictionary access
        entities = event.get('entities', [{}])
        if not entities:
            return None, None
        
        policy_events = entities[0].get('policyEvents', [{}])
        if not policy_events:
            return None, None
        
        first_policy_event = policy_events[0]
        
        # Extract rule name and user name with defaults
        rule_name = first_policy_event.get('ruleName')
        user_name = first_policy_event.get('fields', {}).get('aws.user', '')
        
        # Optional logging
        if rule_name:
            print(f"Rule Name Detected: {rule_name}")
        if user_name:
            print(f"AWS User Detected: {user_name}")
        
        return rule_name, user_name
    
    except Exception as e:
        print(f"An error occurred while processing the webhook: {e}")
        return None, None


def findCompromisedSysdigCIEM(CIEMResponse):
    try:
        # Use get() method for safer dictionary access with default values
        user_data = CIEMResponse.get('data', [{}])[0]
        
        # Check compromised state
        compromised_state = user_data.get('compromisedState', {}).get('id', 'not-compromised')
        compromised_identity = compromised_state != 'not-compromised'
        
        return compromised_identity
    
    except Exception as e:
        print(f"An error occurred while processing Sysdig CIEM response: {e}")
        return 0, False


def ntskpValidateEmployeeActivity(awsUser, ntskpNeedle):
    """
    Confirm either Sysdig detected events
        have been triggered by an employee trusted device for Netskope response
    OR 
        have nothing to do with a trusted device (stolen credentials or bad practices)
    """

    timeStart = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    timeEnd = int(datetime.now(timezone.utc).timestamp())
    query = f"(user eq '{awsUser}')"
    params = {
        "limit": 2000,
        "starttime": timeStart,
        "endtime": timeEnd,
        "query": query
    }

    url = f"https://{config['netskope_url']}/api/v2/events/data/application?{urllib.parse.urlencode(params)}"
    req_headers = {
        'Content-Type': 'application/json',
        'Netskope-Api-Token': config['netskope_token'],
    }

    response = http.request('GET', url, headers=req_headers, timeout=TIMEOUT_TIME)
    if not httpRespHandler(response, "Nestkope-validate-employee-activity"): 
        return None
    
    # print("REQUEST Timestart: " + str(timeStart) + " TimeEnd: " + str(timeEnd))
    # print(format(response.data))
    
    ntskpEvents = json.loads(response.data)
    cloudactivityFound = False
    nkEvtCount = 0
    sysdigEventFound = False
    for ntskpEvent in ntskpEvents['result']:
        nkEvtCount += 1
        if ntskpEvent['appsuite'] == CLOUD_VENDOR_NSKP :
            # Find out if the user has done cloud activity according to Netskope
            if cloudactivityFound == False:
                print(f"Netskope detected recent activity form the user {awsUser} in the cloud")
            cloudactivityFound = True
            # Find out if any of the cloud logs from Netskope match with the sysdig finding
            if (ntskpNeedle == "*" or
                ntskpNeedle in ntskpEvent["app"] or
                ntskpNeedle in ntskpEvent["url"] or 
                ntskpNeedle in ntskpEvent["dom"]):
                    sysdigEventFound = True
                    print(f"Match: It is probably a trusted Device. Sysdig risky event matched with Netskope event list")
                    break

    if sysdigEventFound == False:
        print(f"Cannot match sysdig detected event with the employee device: Evidence of untrusted device.")

    return sysdigEventFound

def httpRespHandler(response, breakpoint):
    if not response.status >= 200 and not response.status <= 206:
        print(f"Communication ERROR at {breakpoint}")
        print("HTTP response:", response.status, response.data )
        return False
    return True
