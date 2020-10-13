#! /usr/bin/env node

'use strict'

var fs = require('fs');
var os = require('os');
var aws = require('aws-sdk');
var colors = require('colors');
var { spawnSync } = require('child_process');
var cognito = require('./includes/cognito.js');

var core;
var workspace;

var workspace_core = {
	last_workspace: null,
	defaults: {
		username: "",
		password: "",
		authflow: "USER_SRP_AUTH",
		attributes: null
	}
};

var provider_template = {
	appclientid: "",
	identity_token: "",
	url: ""
};

var credential_template = {
	AccessKeyId: "",
	SecretKey: "",
	SessionToken: "",
	Expiration: ""
};

var workspace_template = {
	cognito: {
		user: {
			name: "",
			password: "",
			authflow: "USER_SRP_AUTH",
			attributes: null
		},
		clientid: "",
		userpoolid: "",
		identitypoolid: "",
		pool_allows_registration: false,
		identity_allows_unauthenticated: false
	},
	providers: {
		unauthenticated: provider_template,
		amazon: provider_template,
		cognito_idp: provider_template,
		developer: provider_template,
		google: provider_template
	},
	credentials: {
		unauthenticated: credential_template,
		amazon: credential_template,
		cognito_idp: credential_template,
		developer: credential_template,
		google: credential_template
	},
	identities: {
		unauthenticated: {},
		amazon: {},
		cognito_idp: {},
		developer: {},
		google: {}
	},
	last_provider: null
};

const loadCore = (argv) => {
	if (!fs.existsSync(os.homedir() + "/.hirogen/")) {
		fs.mkdirSync(os.homedir() + "/.hirogen/");
	}

	if (fs.existsSync(os.homedir() + "/.hirogen/_workspaces.json")) {
		core = JSON.parse(fs.readFileSync(os.homedir() + "/.hirogen/_workspaces.json"));
	} else {
		core = workspace_core;
	}

	if (!argv.workspace) {
		argv.workspace = core.last_workspace;
	}
};

const loadWorkspace = (argv) => {
	if (argv.workspace == null) {
		argv.workspace = "hirogen";
	}

	// Load everything into argv:
	var workspace_path = os.homedir() + "/.hirogen/" + argv.workspace + ".json";
	if (fs.existsSync(workspace_path)) {
		workspace = JSON.parse(fs.readFileSync(workspace_path));

		argv.clientid = argv.clientid || workspace.cognito.clientid;
		argv.userpoolid = argv.userpoolid || workspace.cognito.userpoolid;
		argv.identitypoolid = argv.identitypoolid || workspace.cognito.identitypoolid;

		if (argv.provider || workspace.last_provider) {
			argv.provider = argv.provider || workspace.last_provider;

			argv.url = argv.url || workspace.providers[argv.provider].url;
			argv.appclientid = argv.appclientid || workspace.providers[argv.provider].appclientid;
			argv.identity_token = argv.identity_token || workspace.providers[argv.provider].identity_token;

			argv.access_key_id = workspace.credentials[argv.provider].AccessKeyId;
			argv.secret_access_key = workspace.credentials[argv.provider].SecretKey;
			argv.session_token = workspace.credentials[argv.provider].SessionToken;
			argv.expiration = workspace.credentials[argv.provider].Expiration;
		}

		argv.username = argv.username || workspace.cognito.user.name || core.defaults.username;
		argv.password = argv.password || workspace.cognito.user.password || core.defaults.password;
		argv.authflow = argv.authflow || workspace.cognito.user.authflow || core.defaults.authflow;
		argv.attributes = argv.attributes || workspace.cognito.user.attributes || core.defaults.attributes;

	} else {
		workspace = workspace_template;
		console.log(("[+] Creating new empty workspace [" + argv.workspace + "]").blue);
	}
};

function saveWorkspace(argv) {
	core.last_workspace = argv.workspace;
	fs.writeFileSync(os.homedir() + "/.hirogen/_workspaces.json", JSON.stringify(core));

	var workspace_path = os.homedir() + "/.hirogen/" + argv.workspace + ".json";
	workspace.cognito.clientid = argv.clientid || workspace.cognito.clientid;
	workspace.cognito.userpoolid = argv.userpoolid || workspace.cognito.userpoolid;
	workspace.cognito.identitypoolid = argv.identitypoolid || workspace.cognito.identitypoolid;

	if (argv.provider) {
		workspace.last_provider = argv.provider;

		workspace.providers[argv.provider].url = argv.url || workspace.providers[argv.provider].url;
		workspace.providers[argv.provider].appclientid = argv.appclientid || workspace.providers[argv.provider].appclientid;
		workspace.providers[argv.provider].identity_token = argv.identity_token || workspace.providers[argv.provider].identity_token;

		workspace.credentials[argv.provider].AccessKeyId = argv.access_key_id || workspace.credentials[argv.provider].AccessKeyId;
		workspace.credentials[argv.provider].SecretKey = argv.secret_access_key || workspace.credentials[argv.provider].SecretKey;
		workspace.credentials[argv.provider].SessionToken = argv.session_token || workspace.credentials[argv.provider].SessionToken;
	}

	fs.writeFileSync(workspace_path, JSON.stringify(workspace));
}

var yargs = require('yargs')
	.usage("Usage: $0 <command> [options]")
	.command("*", "RTFM is hard", (yargs) => {
		yargs
	}, (argv) => {
		
		console.log("[~] RTFM is hard".rainbow);
	})
	.command('core', "Displays the Hirogen Core", (yargs) => {

	}, (argv) => {
		console.log(JSON.stringify(core, null, 4).blue);
	}, [loadCore])
	.command('use <workspace>', "Sets the active workspace", (yargs) => {

	}, (argv) => {
		console.log(("[+] Workspace [" + argv.workspace + "] set as active").green);
		saveWorkspace(argv);
	}, [loadCore, loadWorkspace])
	.command('show [workspace]', "Outputs the given workspace", (yargs) => {

	}, (argv) => {
		console.log(JSON.stringify(workspace, null, 4).blue);
	}, [loadCore, loadWorkspace])
	.command('set-default <attribute> <value>', "Specify default Cognito attribute values", (yargs) => {

	}, (argv) => {

		if (!core.defaults.hasOwnProperty(argv.attribute)) {
			console.log(("[-] Permitted attributes are: " + JSON.stringify(Object.keys(core.defaults))).red)
			return false;
		}

		core.defaults[argv.attribute] = argv.value;
		fs.writeFileSync(os.homedir() + "/.hirogen/_workspaces.json", JSON.stringify(core));
		console.log(("[+] Set default " + argv.attribute + " to [" + argv.value + "]").blue);
	}, [loadCore])
	.command("check-clientid [clientid] [userpoolid] [workspace]", "Checks the configuration of a provided Cognito AppClientId", (yargs) => {
		yargs
		.usage('hirogen check-clientid [clientid] [userpoolid] [workspace]')
	}, (argv) => {

		expect(argv, [
			"userpoolid",
			"clientid"
		]);
		
		argv.region = argv.userpoolid.split("_")[0];

		new Promise((success, failure) => {
			cognito.signUp(argv.clientid, argv.region, 'a', 'aaaaaa', null).then((data) => {
				return Promise.resolve(handleSignUpResponse(err));
			}, (err) => {
				return Promise.resolve(handleSignUpResponse(err));
			}).then((status) => {
				if (status.exists) {
					if (status.canRegister) {
						console.log(("[+] This clientId allows direct registration!").green);
					} else {
						console.log(("[*] This clientId exists, but does not allow direct registration :(").blue);
					}

					workspace.cognito.userpoolid = argv.userpoolid.toString();
					workspace.cognito.clientid = argv.clientid.toString();
					workspace.cognito.pool_allows_registration = status.canRegister;

					saveWorkspace(argv);

				} else {
					console.log(("[-] This clientId wasn't found. You may have the wrong user pool id").red);
				}

			}, (e) => {
				console.log(("ClientId check failure: " + e));
			});
		});
	}, [loadCore, loadWorkspace])
	.command("get-unauthenticated [identitypoolid] [workspace]", "Retrieves Unauthenticated AWS Cognito credentials", (yargs) => {
		yargs
		.usage("hirogen get-unauthenticated [identitypoolid]")
	}, async (argv) => {

		expect(argv, [
			"identitypoolid"
		]);

		cognito.getCredentialsForIdentity(argv.identitypoolid, null, null).then((data) => {
			workspace.cognito.identitypoolid = argv.identitypoolid;
			workspace.cognito.identity_allows_unauthenticated = true;

			workspace.identities['unauthenticated'] = data.identity;

			argv.access_key_id = data.credentials.AccessKeyId;
			argv.secret_access_key = data.credentials.SecretKey;
			argv.session_token = data.credentials.SessionToken;
			argv.provider = 'unauthenticated';


			console.log(("[+] Credentials received. Your new identity is:\n".green))
			console.log(JSON.stringify(data.identity, null, 4).blue);
			console.log("");

			saveWorkspace(argv);

		}, (err) => {
			var parts = err.split(': ');
			switch (parts[1]) {
				case "ResourceNotFoundException":
					console.log(("[-] " + parts[2]).red)
				break;

				case "NotAuthorizedException":
					console.log(("[*] Identity Pool exists, but unauthenticated credentials are not supported.").blue);

					workspace.cognito.identitypoolid = argv.identitypoolid;
					workspace.cognito.identity_allows_unauthenticated = false;
					saveWorkspace(argv);
				break;

				default:
					console.log(("[-] Unknown error: " + err).red);
				break;
			}
		});
	}, [loadCore, loadWorkspace])
	.command("as <provider>", "Proxy an AWS CLI Command with credentials from the given provider.", (yargs) => {
		yargs
		.usage('hirogen as <credential provider> [CLI Command]\ne.g. hirogen as cognito_idp sts get-caller-identity')
	}, (argv) => {
		
		if (exportCredentials(argv)) {
			var shell = spawnSync("aws", process.argv.splice(4));

			if (shell.error) {
				console.log(("[-] Error executing AWS CLI command: " + error).red)
			}

			if (shell.stderr.toString() != "") {
				console.log(shell.stderr.toString());
			} else {
				console.log(shell.stdout.toString());
			}
		}

		// console.log(("[+] Spawned a shell as [" + workspace + "] [" + provider + "]"));
	}, [loadCore, loadWorkspace])
	.command("register-user [username] [password] [attributes]", "Register a new account with a Cognito User Pool", (yargs) => {
		yargs
		.usage('hirogen register-user [username] [password] [attributes]')
	}, (argv) => {
		
		if (!expect(argv, [
			"clientid",
			"userpoolid",
			"username",
			"password"
		])) {
			return false;
		}

		if (!argv.attributes) {
			var attributes = null;
		} else {
			var attributes = parseAttributes(JSON.parse(argv.attributes));
		}

		var region = argv.userpoolid.split("_")[0];

		return cognito.signUp(argv.clientid, region, argv.username, argv.password, attributes).then((data) => {
			console.log(("[+] Registration appears to have been successful. Subscriber: " + data.UserSub).green);

			workspace.cognito.user = {
				name: argv.username.toString(),
				password: argv.password.toString(),
				authflow: "",
				attributes: attributes,
				subscriber: data.UserSub
			}

			argv.provider = "cognito_idp";
			saveWorkspace(argv);

			if (!data.UserConfirmed) {
				console.log(("[*] You must validate your registration before you can log in. Use 'confirm-user' once you receive your code.").blue);
			} else {
				console.log(("[+] You've been auto-verified! Use 'login-user' to get creds!").green);
			}
		}).catch((e) => {
			console.log(("Registration failed; " + e));
		});
	}, [loadCore, loadWorkspace])
	.command("confirm-user <confirmationcode>", "Verify a registered identity with a supplied confirmation code", (yargs) => {
		yargs
		.usage('hirogen confirm-user <confirmationcode>')
	}, (argv) => {
		
		if (!expect(argv, [
			"clientid",
			"userpoolid",
			"username"
		])) {
			return false;
		}

		var region = argv.userpoolid.split("_")[0];

		return cognito.confirmSignUp(argv.clientid, region, argv.username, argv.confirmationcode.toString()).then((data) => {
			console.log(("[+] Verification successful. You can now use 'login-user'").green);
		}).catch((e) => {
			console.log(("[-] Verification failed; " + e).red);
		});
	}, [loadCore, loadWorkspace])
	.command("login-user [authflow]", "Log into Cognito as the specified user", (yargs) => {
		yargs
		.usage('hirogen login-user [ USER_SRP_AUTH | USER_PASSWORD_AUTH ]')
	}, (argv) => {

		if (!expect(argv, [
			"clientid",
			"userpoolid",
			"username",
			"password",
			"authflow"
		])) {
			return false;
		}

		var region = argv.userpoolid.split("_")[0];

		return cognito.initiateAuth(argv.clientid, argv.userpoolid, argv.username, argv.password, argv.authflow).then((data) => {
			console.log(("[+] Login successful.").green);
			
			workspace.providers.cognito_idp.access_token = data.AuthenticationResult.AccessToken;
			workspace.providers.cognito_idp.refresh_token = data.AuthenticationResult.RefreshToken;

			argv.identity_token = data.AuthenticationResult.IdToken;
			
			argv.expiration = Date.now() + (data.AuthenticationResult.expires * 1000);
			argv.provider = "cognito_idp";

			saveWorkspace(argv);

		}, (e) => {
			console.log(("[-] Login failed; " + JSON.stringify(e)).red);
		});
	}, [loadCore, loadWorkspace])
	.command("login-provider <provider> <appclientid> [url]", "Generate a federated identity token with the supplied provider", (yargs) => {
		yargs
		.option("redirect-uri", {
			alias: 'r',
			type: 'string',
			description: 'The redirect URI to pass to the provider'
		})
		.option("domain", {
			alias: 'd',
			type: 'string',
			description: 'The redirect URI to pass to the provider'
		})
		.usage('hirogen login-provider <google|amazon|facebook> <provider_appid> [url]')
	}, async (argv) => {
		
		if (['google', 'amazon', 'cognito', 'facebook', 'twitter'].indexOf(argv.provider) < 0) {
			console.log(("Invalid provider specified."));
			return false;
		}

		var url = (!argv.url) ? null : argv.url.toString();
		var domain = (typeof argv.domain == "undefined") ? null : argv.domain.toString();
		var redirecturi = (typeof argv['redirect-uri'] == "undefined") ? null : argv['redirect-uri'].toString();
		var provider = argv.provider.toString();
		var appclientid = argv.appclientid.toString();

		var token = null;
		if (url === null){
			switch (argv.provider) {
				case 'google':
					token = await cognito.getGoogleTokenForClient(appclientid, redirecturi, domain);

					argv.appclientid = appclientid;
					argv.identity_token = token;

					saveWorkspace(argv);
				break;

				default: 
					console.log("[-] This provider is either unsupported or requires a URL".red);
				break;
			}
		} else {
			switch (argv.provider) {
				case 'amazon':
					token = await cognito.getLWATokenAtPage(appclientid, url);
					token = JSON.parse(token);

					argv.appclientid = appclientid;
					argv.identity_token = token;
					argv.expiration = Date.now() + (token.expires_in * 1000);
					argv.url = url;

					saveWorkspace(argv);

				break;

				case 'google':
					token = await cognito.getGoogleTokenAtPage(appclientid, url);

					argv.appclientid = appclientid;
					argv.identity_token = token;

					saveWorkspace(argv);
				break;

				default: 
					console.log("[-] This provider is either unsupported or requires that a URL not be supplied".red);
				break;
			}
		}

		if (token != null) {
			console.log(("[+] Got " + argv.provider + " token").green);
		}
	}, [loadCore, loadWorkspace])
	.command("get-credentials [provider] [identitypoolid]", "Retrieves AWS credentials using idtokens from a given provider", (yargs) => {
		yargs
		.option("custom_provider", {
			alias: 'c',
			type: 'string',
			description: 'A custom provider URL to use when requesting credentials'
		})
		.usage("hirogen get-credentals [provider] [identitypoolid]")
	}, async (argv) => {

		if (!expect(argv, [
			"identitypoolid",
			"provider",
			"identity_token"
		])) {
			return false;
		}

		if (argv.provider == "cognito_idp") {
			if (!expect(argv, [
				"userpoolid"
			])) {
				return false;
			}
		}
		
		if (['google', 'amazon', 'cognito_idp', 'facebook', 'twitter'].indexOf(argv.provider) < 0) {
			console.log(("Invalid provider specified."));
			return false;
		}

		var providers = {
			"google": "accounts.google.com",
			"facebook": "graph.facebook.com",
			"amazon": "www.amazon.com",
			"twitter": "api.twitter.com",
			"digits": "www.digits.com"
		};

		var provider = argv.provider.toString();

		if (provider == "cognito_idp") {
			
			var region = argv.userpoolid.split("_")[0];
			var provider_id = "cognito-idp." + region + ".amazonaws.com/" + argv.userpoolid;
		} else {
			var provider_id = providers[provider];
		}

		cognito.getCredentialsForIdentity(argv.identitypoolid, provider_id, argv.identity_token).then((data) => {
			argv.identitypoolid = argv.identitypoolid;
			
			workspace.identities[provider] = data.identity;
			
			argv.access_key_id = data.credentials.AccessKeyId;
			argv.secret_access_key = data.credentials.SecretKey;
			argv.session_token = data.credentials.SessionToken;

			console.log(("[+] Credentials received. Your new identity is:\n".green));
			console.log(JSON.stringify(data.identity, null, 4).blue);
			console.log("");

			saveWorkspace(argv);

		}, (e) => {
			console.log(("[-] Error retrieving credentials: " + e).red);
		});
	}, [loadCore, loadWorkspace])
	.command("test-credentials [provider]", "Performs a rudimentary permissiosn check with the credentials from a given provider.", (yargs) => {
		yargs
		.usage("hirogen test-credentials [provider]")
	}, async (argv) => {

		if (!expect(argv, [
			"provider"
		])) {
			return false;
		}

		exportCredentials(argv);

		console.log(("[*] Testing credentials for provider [" + argv.provider + "]").blue);
		console.log("  -------------------------------".blue)
		testCredentials().then((results) => {
			Object.keys(results).sort().forEach(function(e) {
				if (results[e] == true) {
					console.log(("[+] " + e).green);
				} else {
					console.log(("[-] " + e).red);
				}
			});

			console.log("  -------------------------------".blue);
		});

	}, [loadCore, loadWorkspace])
	.option('appclientid', {
		type: 'string',
		description: 'The app client id for non-Cognito providers.'
	})
	.option('url', {
		type: 'string',
		description: 'The URL to obtain a non-Cognito provider identity token from.'
	})
	.option('password', {
		type: 'string',
		description: 'The password to log into a user pool with.'
	})
	.option('username', {
		type: 'string',
		description: 'The username to log into a user pool with.'
	})
	.option('authflow', {
		type: 'string',
		description: 'Can be USER_SRP_AUTH or USER_PASSWORD_AUTH.'
	})
	.option('clientid', {
		type: 'string',
		description: 'The Cognito Client ID to use for registration or login.'
	})
	.option('identitypoolid', {
		type: 'string',
		description: 'The Cogntio Identity Pool ID to obtain credentials from.'
	})
	.option('provider', {
		type: 'string',
		description: 'The federated identity provider to log in via.'
	})
	.option('userpoolid', {
		type: 'string',
		description: 'The Cognito User Pool ID to use for registration or login.'
	})
	.option('workspace', {
		type: 'string',
		description: 'The workspace to work from.'
	})
	.help('help')
	.argv;

function handleSignUpResponse(response) {
	switch (String.prototype.split.apply(response, [':'])[0]) {
		case "ResourceNotFoundException":
			return {"exists": false, "canRegister": false};
		break;

		case "NotAuthorizedException":
			return {"exists": true, "canRegister": false};
		break;

		case "InvalidParameterException":
			return {"exists": true, "canRegister": true};
		break;

		case "InvalidPasswordException":
			return {"exists": true, "canRegister": true};
		break;

		case "UsernameExistsException":
			return {"exists": true, "canRegister": true};
		break;

		case "InvalidLambdaResponseException":
			return {"exists": true, "canRegister": true};
		break;

		default:
			console.log(("Unknown response from ClientId SignUp: ", response));
			return {"exists": false, "canRegister": false};
		break;
	}
}

function expect(argv, fields) {
	var provides = {
		appclientid: "login-provider <provider> <appclientid> [url]",
		identity_token: "login-provider <provider> <appclientid> [url]",
		clientid: "check-clientid <clientid> <userpoolid>",
		userpoolid: "check-clientid <clientid> <userpoolid>",
		identitypoolid: "get-unauthenticated <identitypoolid>",
		username: "set-default",
		password: "set-default",
		attributes: "set-default"
	};

	var success = true;
	fields.forEach(function(f) {
		if (argv[f]) {
			return true;
		}

		success = false;
		if (provides.hasOwnProperty(f)) {
			console.log(("[-] --" + f + " is required. Consider the command " + provides[f] + " to populate the workspace.").blue);
		} else {
			console.log(("[-] --" + f + " is required.").red);
		}
	});

	return success;
}

function exportCredentials(argv) {
	if (!argv.access_key_id || !argv.secret_access_key || !argv.session_token) {
		console.log(("[-] No credentials are available for the specified provider").red);
		return false;
	}

	if (new Date(argv.expiration) < new Date()) {
		console.log(("[-] Credentials are expired.").red);
		return false;
	}

	process.env.AWS_ACCESS_KEY_ID = argv.access_key_id;
	process.env.AWS_SECRET_ACCESS_KEY = argv.secret_access_key;
	process.env.AWS_SESSION_TOKEN = argv.session_token;

	aws.config.update({
		credentials: new aws.Credentials({
			accessKeyId: argv.access_key_id,
			secretAccessKey: argv.secret_access_key,
			sessionToken: argv.session_token
		})
	});

	return true;
}

function parseAttributes(attributes) {
	var response = [];
	Object.keys(attributes).forEach(function(e) {
		response.push({
			Name: e,
			Value: attributes[e]
		});
	});

	return response;
}

function testCredentials() {
	var promises = [];
	var results = {};

	return new Promise((test_results, derp) => {

		/*--	S3 Tests 	--*/

		var s3 = new aws.S3({region: "us-west-2"});
		promises.push(new Promise((success, failure) => {
			var test_name = "s3_ArbitraryRead";

			s3.getObject({
				Bucket: "hirogen-crossaccount-read-test",
				Key: "read.txt"
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		promises.push(new Promise((success, failure) => {
			var test_name = "s3_ArbitraryListObjects";

			s3.listObjects({
				Bucket: "hirogen-crossaccount-read-test",
				MaxKeys: 2
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		promises.push(new Promise((success, failure) => {
			var test_name = "s3_ArbitaryWrite";

			s3.putObject({
				Body: "test",
				Bucket: "hirogen-crossaccount-read-test",
				Key: "write.txt"
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		promises.push(new Promise((success, failure) => {
			var test_name = "s3_ListBuckets";

			s3.listBuckets({}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));


		/*-- DDB Tests --*/

		var ddb = new aws.DynamoDB({region: "us-west-2"});
		promises.push(new Promise((success, failure) => {
			var test_name = "ddb_ListTables";

			ddb.listTables({
				Limit: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));


		/*-- IAM Tests --*/

		var iam = new aws.IAM({region: "us-west-2"});
		promises.push(new Promise((success, failure) => {
			var test_name = "iam_ListUsers";

			iam.listUsers({
				MaxItems: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		promises.push(new Promise((success, failure) => {
			var test_name = "iam_ListRoles";

			iam.listRoles({
				MaxItems: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		
		/*-- EC2 Tests --*/

		var ec2 = new aws.EC2({region: "us-west-2"});
		promises.push(new Promise((success, failure) => {
			var test_name = "ec2_DescribeInstances";

			ec2.describeInstances({
				MaxResults: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		promises.push(new Promise((success, failure) => {
			var test_name = "ec2_DescribeVPCEndpoints";

			ec2.describeVpcEndpoints({
				MaxResults: 1
			}, function(err, data) {
				if (err) {
					results[test_name] = false;
					return success(false);
				}

				results[test_name] = true;
				return success(true)
			});
		}));

		Promise.all(promises).then(() => {
			return test_results(results);
		})
	});

}