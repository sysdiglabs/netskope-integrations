# Sysdig Lambda Webhook handler


## Instructions

### Configure the script
Configure the array `sysdig_findings`:
- Set `sysdig_findings.penalty` with the desired UCI penalty values (default values are just references).
- Fine tune `sysdig_findings.netskp` with the appropriate Netskope needles strings to match findings between Sysdig and Netskope.
- Add new elements to the array to increase the coverage.  

   ```
      sysdig_findings = [
         {"name":"Delete Bucket Public Access Block", "penalty":350, "netskp":"s3"},
         ...
      ]
   ```

### Deploy the script 
1. IAM
   1. Roles > Create Role
   2. Trusted entity type: AWS Service, Service or use case: Lambda
   3. Select these two AWS managed policies: AmazonS3ReadOnlyAccess and AmazonSNSFullAccess
   4. 
2. SNS
   1. Create a new topic, select Standard
   2. Annotate the ARN for later
   3. Create subscription with the desired e-mail address to receive alerts (confirm subscription e-mail)
3. Lambda
   1. Create the Lambda function
   2. Set environment variables
   3. Annotate the Lambda HTTP endpoint and create Sysdig Notifications (webhooks) to trigger it.
4. Environment variables   

      ```
         netskope_token="<NETSKOPE-TOKEN>"
         netskope_url="<NETSKOPE-API-URL>"
         sysdig_token="<SYSDIG-TOKEN>"
         sysdig_url="<SYSDIG-URL>"
         securityToken="<LAMBDA-TOKEN-OPTIONAL>"
         snsarn="<TOPIC-ARN>"
      ```

## Sample commands for local testing

`python-lambda-local -t 15 -f lambda_handler lambda_function.py events/detect-aws-s3-versioning-disabled.json`

`python-lambda-local -t 15 -f lambda_handler lambda_function.py events/aws-cloudtrail-deleted.json`

# Architecture

## Diagram

```mermaid
graph TD
    A[Process Sysdig Notification] --> B[Analyze Webhook: Is a Risky Event?]
    B -->|Risky Event Found| C[Validate Employee Activity with Netskope Logs]
    B -->|Event Not in Risk list| Q[Return No Actions Performed]
    C -->|A Trusted Device originated the events| F[Check Sysdig CIEM Intelligence]
    C -->|An Untrusted Device originated the events| E[Send Email Alert via SNS]

    F -->|Event risk + CIEM compromised state| G[Calculate UCI Impact]
    G -->H[Submit UCI Impact to Netskope]

    E--> Q[End]
    H --> Q

    Q[End]
```

## How a trusted device is identified?

The `sysdig_findings` array contains not only the CDR events from Sysdig that we consider specially risky, but also the strings that hook those Sysdig findings with Netskope SASE user logs (under development at this moment).
If the Netskope API show events that match with the hook fields, the script will consider that the CDR event was originated from a trusted device. Please note that the level of evidence is not perfect but enough to motivate an investigation with high confidency.
