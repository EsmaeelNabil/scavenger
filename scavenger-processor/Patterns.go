package main

import regexp "github.com/wasilibs/go-re2"


type RegexPattern struct {
	Name        string
	Regex       *regexp.Regexp
	Description string
	Confidence  string
}

var secretPatterns = []RegexPattern{
	// 1. AWS CREDENTIALS
	{
		Name:        "AWS Access Key",
		Regex:       regexp.MustCompile(`(?i)(?:aws_access|aws_key|access_key|aws_id).*?[=: "']+AKIA[0-9A-Z]{16}`),
		Description: "AWS Access Key ID",
		Confidence:  "high",
	},
	{
		Name:        "AWS Secret Key",
		Regex:       regexp.MustCompile(`(?i)(?:aws|secret|access).*?['"=: ]+([a-zA-Z0-9/+]{40})(?:['")\s]|$)`),
		Description: "AWS Secret Access Key",
		Confidence:  "high",
	},
	{
		Name:        "AWS Secret Key Context",
		Regex:       regexp.MustCompile(`(?i)AWSSECRETKEY|AWSSECRET|SECRET_?ACCESS_?KEY|SECRET_?KEY[=: "']+([a-zA-Z0-9/+]{40})`),
		Description: "AWS Secret Access Key with explicit context",
		Confidence:  "high",
	},
	{
		Name:        "AWS Account ID",
		Regex:       regexp.MustCompile(`(?i)(?:aws|amazon)[^a-zA-Z0-9](?:account|acct)[^a-zA-Z0-9](?:id|number|no)[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']?([0-9]{12})["']?`),
		Description: "AWS Account ID",
		Confidence:  "medium",
	},
	{
		Name:        "AWS Session Token",
		Regex:       regexp.MustCompile(`(?i)aws[^a-zA-Z0-9]session[^a-zA-Z0-9]token[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']([a-zA-Z0-9/+=]{16,}?)["']`),
		Description: "AWS Session Token",
		Confidence:  "medium",
	},
	{
		Name:        "AWS MWS Key",
		Regex:       regexp.MustCompile(`(?i)amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		Description: "Amazon Marketplace Web Service Key",
		Confidence:  "high",
	},
	{
		Name:        "AWS ARN",
		Regex:       regexp.MustCompile(`(?i)arn:aws:[a-zA-Z0-9\-]+:[a-z]{2}-[a-z]+-[0-9]:[0-9]{12}:[a-zA-Z0-9\-]+`),
		Description: "AWS Resource Name (potentially sensitive)",
		Confidence:  "medium",
	},
	// 2. GOOGLE CLOUD CREDENTIALS
	{
		Name:        "Google API Key",
		Regex:       regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{33,38}`),
		Description: "Google API Key",
		Confidence:  "high",
	},
	{
		Name:        "Google OAuth Client ID",
		Regex:       regexp.MustCompile(`(?i)[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com`),
		Description: "Google OAuth Client ID",
		Confidence:  "high",
	},
	{
		Name:        "Google OAuth Access Token",
		Regex:       regexp.MustCompile(`(?i)ya29\.[0-9A-Za-z\-_]+`),
		Description: "Google OAuth Access Token",
		Confidence:  "high",
	},
	{
		Name:        "Google Cloud Private Key ID",
		Regex:       regexp.MustCompile(`(?i)"private_key_id": "([a-f0-9]{32,}?)"`),
		Description: "Google Cloud Private Key ID from service account JSON file",
		Confidence:  "high",
	},
	{
		Name:        "Firebase URL",
		Regex:       regexp.MustCompile(`(?i)firebase\.(?:database|firestore)\.url['"]?\s*[=:]\s*['"]https://[a-zA-Z0-9\-]+\.firebaseio\.com/?['"]`),
		Description: "Firebase Database URL",
		Confidence:  "medium",
	},
	{
		Name:        "GCP Service Account Key",
		Regex:       regexp.MustCompile(`(?i)"type": "service_account".*"project_id": "[a-zA-Z0-9\-]+".*"private_key"`),
		Description: "Google Cloud Service Account Key File",
		Confidence:  "high",
	},

	// 3. MICROSOFT AZURE CREDENTIALS
	{
		Name:        "Azure Storage Account Key",
		Regex:       regexp.MustCompile(`(?i)(?:azure|ms).*(?:storage|account).*(?:key|secret)['"]?\s*[=:]\s*['"]([a-zA-Z0-9+/=]{88})['"]`),
		Description: "Azure Storage Account Key",
		Confidence:  "high",
	},
	{
		Name:        "Azure Connection String",
		Regex:       regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{88};`),
		Description: "Azure Storage Connection String",
		Confidence:  "high",
	},
	{
		Name:        "Azure SQL Connection String",
		Regex:       regexp.MustCompile(`(?i)Server=tcp:[^,;]+,1433;Initial Catalog=[^,;]+;Persist Security Info=False;User ID=[^,;]+;Password=[^,;]+;`),
		Description: "Azure SQL Database Connection String",
		Confidence:  "high",
	},
	{
		Name:        "Azure Tenant ID",
		Regex:       regexp.MustCompile(`(?i)tenant[_\-]?id['\"]?\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]`),
		Description: "Azure Tenant ID",
		Confidence:  "medium",
	},
	{
		Name:        "Azure Client ID",
		Regex:       regexp.MustCompile(`(?i)client[_\-]?id['\"]?\s*[:=]\s*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]`),
		Description: "Azure Client ID / Application ID",
		Confidence:  "medium",
	},
	{
		Name:        "Azure Client Secret",
		Regex:       regexp.MustCompile(`(?i)client[_\-]?secret['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.~]{16,64})['\"]`),
		Description: "Azure Client Secret",
		Confidence:  "high",
	},

	// 4. DATABASE CREDENTIALS & CONNECTION STRINGS
	{
		Name:        "MySQL Connection String",
		Regex:       regexp.MustCompile(`(?i)mysql:\/\/[a-zA-Z0-9_-]+:[a-zA-Z0-9_\-\+\/%]+@[a-zA-Z0-9_\-.]+:[0-9]+\/[a-zA-Z0-9_-]+`),
		Description: "MySQL connection string",
		Confidence:  "high",
	},
	{
		Name:        "PostgreSQL Connection String",
		Regex:       regexp.MustCompile(`(?i)postgres(?:ql)?:\/\/[a-zA-Z0-9_-]+:[a-zA-Z0-9_\-\+\/%]+@[a-zA-Z0-9_\-.]+:[0-9]+\/[a-zA-Z0-9_-]+`),
		Description: "PostgreSQL connection string",
		Confidence:  "high",
	},
	{
		Name:        "MongoDB Connection String",
		Regex:       regexp.MustCompile(`(?i)mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[a-zA-Z0-9.-]+(?:\:[0-9]+)?\/[a-zA-Z0-9-]+`),
		Description: "MongoDB connection string",
		Confidence:  "high",
	},
	{
		Name:        "JDBC Connection String",
		Regex:       regexp.MustCompile(`(?i)jdbc:(?:mysql|postgresql|oracle|sqlserver):\/\/[a-zA-Z0-9\-._]+(?::[0-9]+)?\/[a-zA-Z0-9\-._]+\?user=[a-zA-Z0-9\-._]+&password=[^&]+`),
		Description: "JDBC connection string with credentials",
		Confidence:  "high",
	},
	{
		Name:        "Redis Connection String",
		Regex:       regexp.MustCompile(`(?i)redis:\/\/[^:]+:[^@]+@[a-zA-Z0-9\-.]+:[0-9]+`),
		Description: "Redis connection string with credentials",
		Confidence:  "high",
	},
	{
		Name:        "Oracle Connection String",
		Regex:       regexp.MustCompile(`(?i)(?:Data Source|Server)=[^;]+;(?:User ID|Username)=[^;]+;Password=[^;]+;`),
		Description: "Oracle connection string",
		Confidence:  "high",
	},
	{
		Name:        "SQL Server Connection String",
		Regex:       regexp.MustCompile(`(?i)Server=[^;]+;Database=[^;]+;User(?:\s)?Id=[^;]+;Password=[^;]+;`),
		Description: "SQL Server connection string",
		Confidence:  "high",
	},

	// 5. API KEYS & SERVICE CREDENTIALS
	{
		Name:        "Generic API Key",
		Regex:       regexp.MustCompile(`(?i)(?:"|\s|=|:)(?:api[_-]?key|apikey|api_token|auth[_-]?token)['":\s]*([A-Za-z0-9_\-]{16,64})`),
		Description: "Generic API key",
		Confidence:  "medium",
	},
	{
		Name:        "YouTube API Key",
		Regex:       regexp.MustCompile(`(?i)(?:INNERTUBE_API_KEY|VOZ_API_KEY|LINK_API_KEY)["':=]\s*["']([A-Za-z0-9_\-]{30,45})["']`),
		Description: "YouTube API Key",
		Confidence:  "high",
	},
	{
		Name:        "Stripe API Key",
		Regex:       regexp.MustCompile(`(?i)(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,34}`),
		Description: "Stripe API key",
		Confidence:  "high",
	},
	{
		Name:        "Twilio API Key",
		Regex:       regexp.MustCompile(`(?i)SK[0-9a-fA-F]{32}`),
		Description: "Twilio API Key",
		Confidence:  "high",
	},
	{
		Name:        "Twilio Account SID",
		Regex:       regexp.MustCompile(`(?i)AC[a-zA-Z0-9]{32}`),
		Description: "Twilio Account SID",
		Confidence:  "high",
	},
	{
		Name:        "Twilio Auth Token",
		Regex:       regexp.MustCompile(`(?i)(?:twilio|TW)[^a-zA-Z0-9](?:token|secret)[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']([a-zA-Z0-9]{32})["']`),
		Description: "Twilio Auth Token",
		Confidence:  "high",
	},
	{
		Name:        "SendGrid API Key",
		Regex:       regexp.MustCompile(`(?i)SG\.[a-zA-Z0-9_\-\.]{52}`),
		Description: "SendGrid API Key",
		Confidence:  "high",
	},
	{
		Name:        "MailChimp API Key",
		Regex:       regexp.MustCompile(`(?i)[0-9a-f]{32}-us[0-9]{1,2}`),
		Description: "MailChimp API Key",
		Confidence:  "medium",
	},
	{
		Name:        "Mailgun API Key",
		Regex:       regexp.MustCompile(`(?i)key-[0-9a-zA-Z]{32}`),
		Description: "Mailgun API Key",
		Confidence:  "high",
	},
	{
		Name:        "PayPal Client ID",
		Regex:       regexp.MustCompile(`(?i)client_id[=:]["']A[a-zA-Z0-9_\-\.]{16,32}["']`),
		Description: "PayPal Client ID",
		Confidence:  "medium",
	},
	{
		Name:        "PayPal Secret",
		Regex:       regexp.MustCompile(`(?i)(?:paypal|PP)[^a-zA-Z0-9](?:secret|password)[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']([a-zA-Z0-9_\-]{32,64})["']`),
		Description: "PayPal Secret",
		Confidence:  "high",
	},

	// 6. VERSION CONTROL & DEVELOPMENT TOKENS
	{
		Name:        "GitHub Token",
		Regex:       regexp.MustCompile(`(?i)(?:github|gh)[_\-\s](?:token|key|pat)[_\-\s]*[=:]\s*["']([a-zA-Z0-9_]{35,40})["']`),
		Description: "GitHub token or personal access token",
		Confidence:  "high",
	},
	{
		Name:        "GitHub OAuth",
		Regex:       regexp.MustCompile(`(?i)(?:github|gh)[_\-\s]oauth[_\-\s]*[=:]\s*["']([a-z0-9]{20,22})["']`),
		Description: "GitHub OAuth Access Token",
		Confidence:  "high",
	},
	{
		Name:        "GitHub App Token",
		Regex:       regexp.MustCompile(`(?i)ghs_[a-zA-Z0-9_]{36,39}`),
		Description: "GitHub App Token",
		Confidence:  "high",
	},
	{
		Name:        "GitLab Token",
		Regex:       regexp.MustCompile(`(?i)(?:gitlab|gl)[_\-\s](?:token|key|pat)[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-]{20,64})["']`),
		Description: "GitLab Personal Access Token",
		Confidence:  "high",
	},
	{
		Name:        "Bitbucket Token",
		Regex:       regexp.MustCompile(`(?i)(?:bitbucket|bb)[_\-\s](?:token|key|pat)[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-]{20,64})["']`),
		Description: "Bitbucket Access Token",
		Confidence:  "high",
	},
	{
		Name:        "Circle CI Token",
		Regex:       regexp.MustCompile(`(?i)circle[_\-\s]ci[_\-\s]token[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-]{40,64})["']`),
		Description: "Circle CI Token",
		Confidence:  "high",
	},
	{
		Name:        "Travis CI Token",
		Regex:       regexp.MustCompile(`(?i)travis[_\-\s](?:api)?[_\-\s]token[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-]{20,64})["']`),
		Description: "Travis CI API Token",
		Confidence:  "high",
	},
	{
		Name:        "Docker Hub Token",
		Regex:       regexp.MustCompile(`(?i)docker[_\-\s]hub[_\-\s](?:token|key|pat)[_\-\s]*[=:]\s*["']([a-zA-Z0-9]{20,64})["']`),
		Description: "Docker Hub Access Token",
		Confidence:  "high",
	},

	// 7. SOCIAL MEDIA & COMMUNICATION TOKENS
	{
		Name:        "Slack Token",
		Regex:       regexp.MustCompile(`(?i)xox[pbar]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}`),
		Description: "Slack API token",
		Confidence:  "high",
	},
	{
		Name:        "Slack Webhook",
		Regex:       regexp.MustCompile(`(?i)https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
		Description: "Slack Webhook URL",
		Confidence:  "high",
	},
	{
		Name:        "Discord Token",
		Regex:       regexp.MustCompile(`(?i)(?:discord|discordapp)(?:\.com|bot)[^a-zA-Z0-9]*token[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']([a-zA-Z0-9_\-.]{59,64})["']`),
		Description: "Discord Bot Token",
		Confidence:  "high",
	},
	{
		Name:        "Discord Webhook",
		Regex:       regexp.MustCompile(`(?i)https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_\-]{68}`),
		Description: "Discord Webhook URL",
		Confidence:  "high",
	},
	{
		Name:        "Facebook App ID",
		Regex:       regexp.MustCompile(`(?i)(?:facebook|fb)(?:\.com)?[^a-zA-Z0-9]*(?:client|app)(?:[_\-\s]?id)[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']([0-9]{13,17})["']`),
		Description: "Facebook App ID",
		Confidence:  "medium",
	},
	{
		Name:        "Facebook Secret",
		Regex:       regexp.MustCompile(`(?i)(?:facebook|fb)(?:\.com)?[^a-zA-Z0-9]*(?:secret|app[_\-\s]?secret)[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']([a-f0-9]{32})["']`),
		Description: "Facebook App Secret",
		Confidence:  "high",
	},
	{
		Name:        "Twitter API Key",
		Regex:       regexp.MustCompile(`(?i)(?:twitter|tweet)(?:\.com)?[^a-zA-Z0-9]*(?:api[_\-\s]?key|consumer[_\-\s]?key)[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']([a-zA-Z0-9]{20,25})["']`),
		Description: "Twitter API Key",
		Confidence:  "high",
	},
	{
		Name:        "Twitter API Secret",
		Regex:       regexp.MustCompile(`(?i)(?:twitter|tweet)(?:\.com)?[^a-zA-Z0-9]*(?:api[_\-\s]?secret|consumer[_\-\s]?secret)[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']([a-zA-Z0-9]{35,50})["']`),
		Description: "Twitter API Secret",
		Confidence:  "high",
	},
	{
		Name:        "Twitter Access Token",
		Regex:       regexp.MustCompile(`(?i)(?:twitter|tweet)(?:\.com)?[^a-zA-Z0-9]*access[_\-\s]?token[^a-zA-Z0-9]*[=:][^a-zA-Z0-9]*["']([0-9]{18,25}-[a-zA-Z0-9]{32,50})["']`),
		Description: "Twitter Access Token",
		Confidence:  "high",
	},

	// 8. AUTHENTICATION & AUTHORIZATION TOKENS
	{
		Name:        "JWT Token",
		Regex:       regexp.MustCompile(`(?i)eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}`),
		Description: "JWT Token",
		Confidence:  "medium",
	},
	{
		Name:        "OAuth Token",
		Regex:       regexp.MustCompile(`(?i)(?:oauth|refresh)[_-]?token['":\s]*=?['":\s]*([0-9a-zA-Z\._\-]{30,150})`),
		Description: "OAuth or refresh token",
		Confidence:  "medium",
	},
	{
		Name:        "Authorization Header",
		Regex:       regexp.MustCompile(`(?i)authorization:\s*(?:bearer|basic|token)\s+([a-zA-Z0-9._\-+/=]{5,})`),
		Description: "Authorization header with token",
		Confidence:  "high",
	},
	{
		Name:        "Basic Auth",
		Regex:       regexp.MustCompile(`(?i)(?:basic\s)?[a-zA-Z0-9_\-:\.]+:[a-zA-Z0-9_\-:\.]+@[a-zA-Z0-9_\-\.]+`),
		Description: "Basic authentication credentials",
		Confidence:  "high",
	},
	{
		Name:        "Authentication Token",
		Regex:       regexp.MustCompile(`(?i)["']?(?:auth|authentication|token|secret|key|credentials)[_-]?(?:token|key|secret)?["']?[\s]*[=:]\s*["']([a-zA-Z0-9_\-\.=+/]{16,64})["']`),
		Description: "Generic authentication token or key",
		Confidence:  "medium",
	},
	{
		Name:        "Session Token",
		Regex:       regexp.MustCompile(`(?i)(?:session)[_\-\s]?(?:token|key|secret|id)[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-\.=+/]{16,128})["']`),
		Description: "Session token or key",
		Confidence:  "medium",
	},

	// 9. CRYPTOGRAPHIC KEYS & CERTIFICATES
	{
		Name:        "Private Key",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN[ A-Z]+ PRIVATE KEY-----[A-Za-z0-9+/\s=]+-----END[ A-Z]+ PRIVATE KEY-----`),
		Description: "Private key material",
		Confidence:  "high",
	},
	{
		Name:        "RSA Private Key",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+/\s=]+-----END RSA PRIVATE KEY-----`),
		Description: "RSA private key",
		Confidence:  "high",
	},
	{
		Name:        "SSH Private Key",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN (?:DSA|RSA|EC|OPENSSH) PRIVATE KEY-----[A-Za-z0-9+/\s=]+-----END (?:DSA|RSA|EC|OPENSSH) PRIVATE KEY-----`),
		Description: "SSH private key",
		Confidence:  "high",
	},
	{
		Name:        "PGP Private Key",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----[A-Za-z0-9+/\s=]+-----END PGP PRIVATE KEY BLOCK-----`),
		Description: "PGP private key block",
		Confidence:  "high",
	},
	{
		Name:        "Certificate",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN CERTIFICATE-----[A-Za-z0-9+/\s=]+-----END CERTIFICATE-----`),
		Description: "Certificate",
		Confidence:  "medium",
	},
	{
		Name:        "Certificate Thumbprint",
		Regex:       regexp.MustCompile(`(?i)(?:certificate|cert|thumbprint|fingerprint)[_\-\s]?(?:thumbprint|fingerprint)?[=:]\s*["']([a-fA-F0-9:]{40,})["']`),
		Description: "Certificate thumbprint or fingerprint",
		Confidence:  "medium",
	},
	{
		Name:        "Encryption Key",
		Regex:       regexp.MustCompile(`(?i)(?:encryption|crypto)[_\-\s]?(?:key|secret)[_\-\s]*[=:]\s*["']([a-zA-Z0-9+/=]{16,})["']`),
		Description: "Encryption key",
		Confidence:  "high",
	},

	// 10. PASSWORD & SECRETS
	{
		Name:        "Password Field",
		Regex:       regexp.MustCompile(`(?i)["']?(?:password|passwd|pwd|secret)["']?[\s]*[:=]\s*["']([^"']{3,})["']`),
		Description: "Hardcoded password in code",
		Confidence:  "medium",
	},
	{
		Name:        "Password Parameter",
		Regex:       regexp.MustCompile(`(?i)[?&](?:password|passwd|pwd)=([^&"']{3,})`),
		Description: "Password in URL parameter",
		Confidence:  "high",
	},
	{
		Name:        "Password Assignment",
		Regex:       regexp.MustCompile(`(?i)(?:password|passwd|pwd|credentials)[_\-\s]*=\s*["']([^"']{3,})["']`),
		Description: "Password assignment in code or config",
		Confidence:  "high",
	},
	{
		Name:        "Generic Secret",
		Regex:       regexp.MustCompile(`(?i)(?:secret|token|key)[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-\.=+/]{8,})["']`),
		Description: "Generic secret, token, or key",
		Confidence:  "medium",
	},
	{
		Name:        "Hard-coded Credentials",
		Regex:       regexp.MustCompile(`(?i)["']?(?:username|user|usr|uid)["']?[\s]*[:=]\s*["']([^"']{3,})["'][\s,]+["']?(?:password|passwd|pwd)["']?[\s]*[:=]\s*["']([^"']{3,})["']`),
		Description: "Hard-coded username and password pair",
		Confidence:  "high",
	},

	// 11. CLOUD PLATFORM-SPECIFIC CREDENTIALS
	{
		Name:        "Heroku API Key",
		Regex:       regexp.MustCompile(`(?i)heroku[_\-\s]?(?:api)?[_\-\s]?key[_\-\s]*[=:]\s*["']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']`),
		Description: "Heroku API Key",
		Confidence:  "high",
	},
	{
		Name:        "Digital Ocean Token",
		Regex:       regexp.MustCompile(`(?i)digitalocean[_\-\s]?(?:token|key|pat)[_\-\s]*[=:]\s*["']([a-zA-Z0-9]{64})["']`),
		Description: "Digital Ocean Personal Access Token",
		Confidence:  "high",
	},
	{
		Name:        "Netlify Access Token",
		Regex:       regexp.MustCompile(`(?i)netlify[_\-\s]?(?:token|key|pat)[_\-\s]*[=:]\s*["']((?:[a-zA-Z0-9]{8}-){4}[a-zA-Z0-9]{8})["']`),
		Description: "Netlify Access Token",
		Confidence:  "high",
	},
	{
		Name:        "Slack Webhook",
		Regex:       regexp.MustCompile(`(?i)https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
		Description: "Slack Webhook URL",
		Confidence:  "high",
	},
	{
		Name:        "CloudFlare API Key",
		Regex:       regexp.MustCompile(`(?i)cloudflare[_\-\s]?(?:api)?[_\-\s]?key[_\-\s]*[=:]\s*["']([a-zA-Z0-9_]{37})["']`),
		Description: "CloudFlare API Key",
		Confidence:  "high",
	},
	{
		Name:        "CloudFlare Token",
		Regex:       regexp.MustCompile(`(?i)cloudflare[_\-\s]?token[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-.]{22})["']`),
		Description: "CloudFlare API Token",
		Confidence:  "high",
	},
	{
		Name:        "Firebase Database URL",
		Regex:       regexp.MustCompile(`(?i)https://[a-zA-Z0-9_-]+\.firebaseio\.com`),
		Description: "Firebase Database URL",
		Confidence:  "medium",
	},

	// 12. PACKAGE MANAGER & BUILD TOOL TOKENS
	{
		Name:        "NPM Token",
		Regex:       regexp.MustCompile(`(?i)(?:npm_[a-z0-9_]+|npmToken)[=:]\s*["']([a-zA-Z0-9_\-\.=+/]{40,100})["']`),
		Description: "NPM authentication token",
		Confidence:  "medium",
	},
	{
		Name:        "RubyGems API Key",
		Regex:       regexp.MustCompile(`(?i)rubygems[_\-\s]?(?:api)?[_\-\s]?key[_\-\s]*[=:]\s*["']([a-zA-Z0-9]{20,60})["']`),
		Description: "RubyGems API Key",
		Confidence:  "high",
	},
	{
		Name:        "PyPI Token",
		Regex:       regexp.MustCompile(`(?i)(?:PYPI|python)[_\-\s]?(?:api)?[_\-\s]?token[_\-\s]*[=:]\s*["'](pypi-[A-Za-z0-9_\-\.=+/]{50,250})["']`),
		Description: "PyPI API Token",
		Confidence:  "high",
	},
	{
		Name:        "Maven Repository Token",
		Regex:       regexp.MustCompile(`(?i)(?:maven|mvn)[_\-\s]?(?:repo|repository)?[_\-\s]?(?:token|key|password)[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-\.=+/]{20,})["']`),
		Description: "Maven Repository Access Token",
		Confidence:  "medium",
	},
	{
		Name:        "NuGet API Key",
		Regex:       regexp.MustCompile(`(?i)nuget[_\-\s]?(?:api)?[_\-\s]?key[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-\/=+]{40,60})["']`),
		Description: "NuGet API Key",
		Confidence:  "high",
	},

	// 13. ANALYTICS & MONITORING SERVICES
	{
		Name:        "Google Analytics Key",
		Regex:       regexp.MustCompile(`(?i)UA-[0-9]{5,}-[0-9]{1,}`),
		Description: "Google Analytics Tracking ID",
		Confidence:  "medium",
	},
	{
		Name:        "Google Analytics 4",
		Regex:       regexp.MustCompile(`(?i)G-[A-Z0-9]{10}`),
		Description: "Google Analytics 4 Measurement ID",
		Confidence:  "medium",
	},
	{
		Name:        "New Relic License Key",
		Regex:       regexp.MustCompile(`(?i)newrelic[_\-\s]?(?:license)?[_\-\s]?key[_\-\s]*[=:]\s*["']([a-z0-9]{40})["']`),
		Description: "New Relic License Key",
		Confidence:  "high",
	},
	{
		Name:        "Sentry DSN",
		Regex:       regexp.MustCompile(`(?i)https://[a-zA-Z0-9]{32}@(?:sentry|o[0-9]+)\.(?:ingest\.)?sentry\.io/[0-9]+`),
		Description: "Sentry DSN URL",
		Confidence:  "high",
	},
	{
		Name:        "DataDog API Key",
		Regex:       regexp.MustCompile(`(?i)datadog[_\-\s]?(?:api)?[_\-\s]?key[_\-\s]*[=:]\s*["']([a-zA-Z0-9]{32})["']`),
		Description: "DataDog API Key",
		Confidence:  "high",
	},
	{
		Name:        "Mixpanel Token",
		Regex:       regexp.MustCompile(`(?i)mixpanel[_\-\s]?(?:token|key)[_\-\s]*[=:]\s*["']([a-zA-Z0-9]{32})["']`),
		Description: "Mixpanel Token",
		Confidence:  "high",
	},

	// 14. MESSAGING & NOTIFICATION SERVICES
	{
		Name:        "PubNub Key",
		Regex:       regexp.MustCompile(`(?i)pubnub[_\-\s]?(?:publish|subscribe)?[_\-\s]?key[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-]{20,})["']`),
		Description: "PubNub API Key",
		Confidence:  "high",
	},
	{
		Name:        "Firebase Messaging Key",
		Regex:       regexp.MustCompile(`(?i)firebase[_\-\s]?messaging[_\-\s]?(?:server)?[_\-\s]?key[_\-\s]*[=:]\s*["'](AAAA[a-zA-Z0-9_\-:]{100,})["']`),
		Description: "Firebase Cloud Messaging Server Key",
		Confidence:  "high",
	},
	{
		Name:        "OneSignal API Key",
		Regex:       regexp.MustCompile(`(?i)onesignal[_\-\s]?(?:api)?[_\-\s]?key[_\-\s]*[=:]\s*["']([a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})["']`),
		Description: "OneSignal API Key",
		Confidence:  "high",
	},

	// 15. CONFIGURATION & SECRETS STORAGE
	{
		Name:        "HashiCorp Vault Token",
		Regex:       regexp.MustCompile(`(?i)(?:vault|hashicorp)[_\-\s]?token[_\-\s]*[=:]\s*["']((?:s|hvs)\.(?:[a-zA-Z0-9_\-\.=+/]{24,}))["']`),
		Description: "HashiCorp Vault Token",
		Confidence:  "high",
	},
	{
		Name:        "AWS KMS Master Key",
		Regex:       regexp.MustCompile(`(?i)aws[_\-\s]?kms[_\-\s]?(?:master)?[_\-\s]?key[_\-\s]*[=:]\s*["']([a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})["']`),
		Description: "AWS KMS Master Key ID",
		Confidence:  "high",
	},
	{
		Name:        "AWS Parameter Store Path",
		Regex:       regexp.MustCompile(`(?i)/aws/reference/secretsmanager/[a-zA-Z0-9_\-/]+`),
		Description: "AWS Parameter Store Path to Secret",
		Confidence:  "medium",
	},

	// 16. PLATFORM SPECIFIC PATTERNS
	{
		Name:        "iOS Distribution Certificate",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN CERTIFICATE-----\s+[a-zA-Z0-9+/\s=]+\s+-----END CERTIFICATE-----.*?(?:ios|apple).*?distribution`),
		Description: "iOS Distribution Certificate",
		Confidence:  "high",
	},
	{
		Name:        "iOS Provisioning Profile",
		Regex:       regexp.MustCompile(`(?i)(?:iOS|Apple).*?(?:team|provisioning).*?ID.*?([A-Z0-9]{10})`),
		Description: "iOS Team/Provisioning ID",
		Confidence:  "medium",
	},
	{
		Name:        "Android Keystore Password",
		Regex:       regexp.MustCompile(`(?i)(?:android|keystore)[_\-\s]?(?:key|store)?[_\-\s]?(?:password|pwd)[_\-\s]*[=:]\s*["']([^"']{3,})["']`),
		Description: "Android Keystore Password",
		Confidence:  "high",
	},
	{
		Name:        "Google Play Service Key",
		Regex:       regexp.MustCompile(`(?i)["']type["']\s*[:=]\s*["']service_account["'].*?["']private_key["']\s*[:=]\s*["']-----BEGIN PRIVATE KEY-----[^"]+-----END PRIVATE KEY-----["']`),
		Description: "Google Play Service Account Key",
		Confidence:  "high",
	},

	// 17. ORIGIN TRIAL TOKENS AND SPECIFIC WEB PATTERNS
	{
		Name:        "Origin Trial Token",
		Regex:       regexp.MustCompile(`(?i)origin-trial[" ]content=["']([A-Za-z0-9+/]+={0,2})["']`),
		Description: "Origin trial token from meta tag",
		Confidence:  "medium",
	},
	{
		Name:        "Website Validation Token",
		Regex:       regexp.MustCompile(`(?i)(?:google|facebook|twitter|linkedin|pinterest|yandex|bing|brave|domain)[_\-\s]?(?:site|domain)?[_\-\s]?verification[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-]{10,})["']`),
		Description: "Website Domain Verification Token",
		Confidence:  "medium",
	},
	{
		Name:        "Web Config Connection String",
		Regex:       regexp.MustCompile(`(?i)<connectionStrings>.*?<add.*?connectionString=["'](.*?)["'].*?</connectionStrings>`),
		Description: "Connection string in web.config",
		Confidence:  "high",
	},

	// 18. IoT & SMART DEVICE SECRETS
	{
		Name:        "IoT Hub Connection",
		Regex:       regexp.MustCompile(`(?i)HostName=[^;]+\.azure-devices\.net;SharedAccessKeyName=[^;]+;SharedAccessKey=[a-zA-Z0-9+/=]{40,}`),
		Description: "Azure IoT Hub Connection String",
		Confidence:  "high",
	},
	{
		Name:        "MQTT Credentials",
		Regex:       regexp.MustCompile(`(?i)mqtt[_\-\s]?(?:username|password|credentials)[_\-\s]*[=:]\s*["']([^"']{3,})["']`),
		Description: "MQTT Username or Password",
		Confidence:  "medium",
	},

	// 19. ENVIRONMENT VARIABLE PATTERNS
	{
		Name:        "Environment Secrets",
		Regex:       regexp.MustCompile(`(?i)export\s+(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|PWD)[_A-Z0-9]*=["']([^"']{8,})["']`),
		Description: "Secret in environment variable export",
		Confidence:  "high",
	},
	{
		Name:        "Dotenv Secrets",
		Regex:       regexp.MustCompile(`(?i)(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|PWD)[_A-Z0-9]*=["']?([^"'\s]{8,})["']?`),
		Description: "Secret in .env file",
		Confidence:  "high",
	},

	// 20. ADDITIONAL YAML & JSON CONFIGURATION PATTERNS
	{
		Name:        "YAML Secret",
		Regex:       regexp.MustCompile(`(?i)(?:secret|password|token|key|credential|auth):\s*["']?([^"'\s]{8,})["']?`),
		Description: "Secret in YAML configuration",
		Confidence:  "medium",
	},
	{
		Name:        "JSON Secret",
		Regex:       regexp.MustCompile(`(?i)"(?:secret|password|token|key|credential|auth)"\s*:\s*"([^"]{8,})"`),
		Description: "Secret in JSON configuration",
		Confidence:  "medium",
	},

	// 21. HARDWARE & DEVICE SPECIFIC SECRETS
	{
		Name:        "Hardware Serial Number",
		Regex:       regexp.MustCompile(`(?i)(?:serial[_\-\s]?number|device[_\-\s]?id)[_\-\s]*[=:]\s*["']([A-Z0-9]{6,20})["']`),
		Description: "Hardware Serial Number",
		Confidence:  "low",
	},
	{
		Name:        "MAC Address",
		Regex:       regexp.MustCompile(`(?i)(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}`),
		Description: "MAC Address",
		Confidence:  "low",
	},

	// 22. CUSTOM APPLICATION PATTERN EXAMPLES
	{
		Name:        "Custom Application ID",
		Regex:       regexp.MustCompile(`(?i)(?:app|application)[_\-\s]?id[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-\.]{8,64})["']`),
		Description: "Custom Application ID",
		Confidence:  "low",
	},
	{
		Name:        "Custom Auth Token",
		Regex:       regexp.MustCompile(`(?i)(?:authorization|auth)[_\-\s]?token[_\-\s]*[=:]\s*["']([a-zA-Z0-9_\-\.=+/]{16,256})["']`),
		Description: "Custom Application Auth Token",
		Confidence:  "medium",
	},

	// 23. ADDITIONAL ENCODING FORMATS
	{
		Name:        "Base64 Encoded Secret",
		Regex:       regexp.MustCompile(`(?i)(?:secret|password|token|key|credential|auth)[_\-\s]*[=:]\s*["']([A-Za-z0-9+/]{40,}={0,2})["']`),
		Description: "Base64 encoded secret",
		Confidence:  "medium",
	},
	{
		Name:        "Hex Encoded Secret",
		Regex:       regexp.MustCompile(`(?i)(?:secret|password|token|key|credential|hash)[_\-\s]*[=:]\s*["']([a-f0-9]{32,})["']`),
		Description: "Hex encoded secret or hash",
		Confidence:  "medium",
	},
	// Time patterns
	{
		Name:        "Times",
		Regex:       regexp.MustCompile(`\d{1,2}:\d{2} ?(?:[ap]\.?m\.?)?|\d[ap]\.?m\.?`),
		Description: "Time patterns like 12:30 pm",
		Confidence:  "high",
	},
	//// Phone number patterns
	//{
	//	Name:        "Phone Numbers",
	//	Regex:       regexp.MustCompile(`((?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-])|(?<![\d-])(?:\(\+?\d{2}\)|\+?\d{2})\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-]))`),
	//	Description: "Phone number patterns",
	//	Confidence:  "high",
	//},
	{
		Name:        "Phone Numbers with Extensions",
		Regex:       regexp.MustCompile(`((?:(?:\+?1\s*(?:[.-]\s*)?)?(?:\(\s*(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|(?:[2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?(?:[2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?(?:[0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(?:\d+)?))`),
		Description: "Phone numbers with extensions",
		Confidence:  "high",
	},
	// Email patterns
	{
		Name:        "Email Addresses",
		Regex:       regexp.MustCompile(`([a-z0-9!#$%&'*+\/=?^_\x60{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)`),
		Description: "Email addresses",
		Confidence:  "high",
	},
	{
		Name:        "Email Addresses - Alternative",
		Regex:       regexp.MustCompile(`\b[a-z0-9._%+\-—|]+@[a-z0-9.\-—|]+\.[a-z|]{2,6}\b`),
		Description: "Alternative email address pattern",
		Confidence:  "high",
	},
	{
		Name:        "Email - 3",
		Regex:       regexp.MustCompile(`\b[\w\-+.]+@+\w+.+[A-z]{3}`),
		Description: "Third email pattern variation",
		Confidence:  "high",
	},
	{
		Name:        "PO Boxes",
		Regex:       regexp.MustCompile(`P\.? ?O\.? Box \d+`),
		Description: "Post office box addresses",
		Confidence:  "high",
	},
	{
		Name:        "Visa Credit Card",
		Regex:       regexp.MustCompile(`4[0-9]{15}`),
		Description: "Visa credit card numbers",
		Confidence:  "high",
	},
	{
		Name:        "American Express Credit Card",
		Regex:       regexp.MustCompile(`3[47][0-9]{13}`),
		Description: "American Express credit card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Credit Card - 2",
		Regex:       regexp.MustCompile(`4[0-9]{12}(?:[0-9]{3})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12} |3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}`),
		Description: "Various credit card formats",
		Confidence:  "high",
	},
	{
		Name:        "Credit Card - 3",
		Regex:       regexp.MustCompile(`\b((4\d{3}|5[1-5]\d{2}|2\d{3}|3[47]\d{1,2})[\s\-]?\d{4,6}[\s\-]?\d{4,6}?([\s\-]\d{3,4})?(\d{3})?)\b`),
		Description: "Credit card with separators",
		Confidence:  "high",
	},
	// Specific card brands
	{
		Name:        "Amex Card",
		Regex:       regexp.MustCompile(`\b3[47][0-9]{13}\b`),
		Description: "American Express card numbers",
		Confidence:  "high",
	},
	{
		Name:        "BCGlobal",
		Regex:       regexp.MustCompile(`\b(6541|6556)[0-9]{12}\b`),
		Description: "BC Global card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Carte Blanche Card",
		Regex:       regexp.MustCompile(`\b389[0-9]{11}\b`),
		Description: "Carte Blanche card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Diners Club Card",
		Regex:       regexp.MustCompile(`\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b`),
		Description: "Diners Club card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Discover Card",
		Regex:       regexp.MustCompile(`\b65[4-9][0-9]{13}|64[4-9][0-9]{13}|6011[0-9]{12}|(622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9][0-9]|9[01][0-9]|92[0-5])[0-9]{10})\b`),
		Description: "Discover card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Insta Payment Card",
		Regex:       regexp.MustCompile(`\b63[7-9][0-9]{13}\b`),
		Description: "Insta Payment card numbers",
		Confidence:  "high",
	},
	{
		Name:        "JCB Card",
		Regex:       regexp.MustCompile(`\b(?:2131|1800|35\d{3})\d{11}\b`),
		Description: "JCB card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Korean Local Card",
		Regex:       regexp.MustCompile(`\b9[0-9]{15}\b`),
		Description: "Korean Local card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Laser Card",
		Regex:       regexp.MustCompile(`\b(6304|6706|6709|6771)[0-9]{12,15}\b`),
		Description: "Laser card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Maestro Card",
		Regex:       regexp.MustCompile(`\b(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}\b`),
		Description: "Maestro card numbers",
		Confidence:  "high",
	},
	{
		Name:        "MasterCard",
		Regex:       regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b`),
		Description: "MasterCard numbers",
		Confidence:  "high",
	},
	{
		Name:        "Solo Card",
		Regex:       regexp.MustCompile(`\b(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}\b`),
		Description: "Solo card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Switch Card",
		Regex:       regexp.MustCompile(`\b(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]`),
		Description: "Switch card numbers",
		Confidence:  "high",
	},
	{
		Name:        "Visa Cards",
		Regex:       regexp.MustCompile(`4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`),
		Description: "Visa card numbers with separators",
		Confidence:  "high",
	},
	{
		Name:        "Master Cards",
		Regex:       regexp.MustCompile(`5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`),
		Description: "Master card numbers with separators",
		Confidence:  "high",
	},
	// National identity numbers
	{
		Name:        "Argentina National Identity (DNI) Number",
		Regex:       regexp.MustCompile(`\d{2}\.\d{3}\.\d{3}`),
		Description: "Argentina National Identity (DNI) Number",
		Confidence:  "high",
	},
	{
		Name:        "Canada Passport ID",
		Regex:       regexp.MustCompile(`\b[\w]{2}[\d]{6}\b`),
		Description: "Canada Passport ID",
		Confidence:  "high",
	},
	{
		Name:        "Croatia Vat ID card number",
		Regex:       regexp.MustCompile(`\bHR\d{11}\b`),
		Description: "Croatia VAT ID card number",
		Confidence:  "high",
	},
	{
		Name:        "Czech Republic Vat ID card number",
		Regex:       regexp.MustCompile(`\bCZ\d{8,10}\b`),
		Description: "Czech Republic VAT ID card number",
		Confidence:  "high",
	},
	{
		Name:        "Denmark Personal ID number",
		Regex:       regexp.MustCompile(`\b\d{10}|\d{6}[-\s]\d{4}\b`),
		Description: "Denmark Personal ID number",
		Confidence:  "high",
	},
	{
		Name:        "France National ID card (CNI)",
		Regex:       regexp.MustCompile(`\b\d{12}\b`),
		Description: "France National ID card (CNI)",
		Confidence:  "high",
	},
	{
		Name:        "France Social Security Number (INSEE)",
		Regex:       regexp.MustCompile(`\b\d{13}|\d{13}\s\d{2}\b`),
		Description: "France Social Security Number (INSEE)",
		Confidence:  "high",
	},
	{
		Name:        "France Passport ID",
		Regex:       regexp.MustCompile(`\b\d{2}11\d{5}\b`),
		Description: "France Passport ID",
		Confidence:  "high",
	},
	{
		Name:        "Germany ID card number",
		Regex:       regexp.MustCompile(`\bl\d{8}\b`),
		Description: "Germany ID card number",
		Confidence:  "high",
	},
	{
		Name:        "Germany Passport ID",
		Regex:       regexp.MustCompile(`\b[cfghjk]\d{3}\w{5}\d\b`),
		Description: "Germany Passport ID",
		Confidence:  "high",
	},
	{
		Name:        "Germany Driver's License ID",
		Regex:       regexp.MustCompile(`\b[\d\w]\d{2}[\d\w]{6}\d[\d\w]\b`),
		Description: "Germany Driver's License ID",
		Confidence:  "high",
	},
	{
		Name:        "Ireland Personal Public Service (PPS) Number",
		Regex:       regexp.MustCompile(`\b\d{7}\w{1,2}\b`),
		Description: "Ireland Personal Public Service (PPS) Number",
		Confidence:  "high",
	},
	{
		Name:        "Netherlands Citizen's Service (BSN) number",
		Regex:       regexp.MustCompile(`\b\d{8}|\d{3}[-\.\s]\d{3}[-\.\s]\d{3}\b`),
		Description: "Netherlands Citizen's Service (BSN) number",
		Confidence:  "high",
	},
	{
		Name:        "Poland National ID (PESEL)",
		Regex:       regexp.MustCompile(`\b\d{11}\b`),
		Description: "Poland National ID (PESEL)",
		Confidence:  "high",
	},
	{
		Name:        "Portugal Citizen Card Number",
		Regex:       regexp.MustCompile(`\d{9}[\w\d]{2}|\d{8}-\d[\d\w]{2}\d`),
		Description: "Portugal Citizen Card Number",
		Confidence:  "high",
	},
	{
		Name:        "Spain Social Security Number (SSN)",
		Regex:       regexp.MustCompile(`\b\d{2}\/?\d{8}\/?\d{2}\b`),
		Description: "Spain Social Security Number (SSN)",
		Confidence:  "high",
	},
	{
		Name:        "Spain Social Security Number (SSN) - 2",
		Regex:       regexp.MustCompile(`\b\d{3}[ -.]\d{2}[ -.]\d{4}\b`),
		Description: "Spain Social Security Number (SSN) - Alternative format",
		Confidence:  "high",
	},
	{
		Name:        "Sweden Passport ID",
		Regex:       regexp.MustCompile(`\b\d{8}\b`),
		Description: "Sweden Passport ID",
		Confidence:  "high",
	},
	{
		Name:        "United Kingdom Passport ID",
		Regex:       regexp.MustCompile(`\b\d{9}\b`),
		Description: "United Kingdom Passport ID",
		Confidence:  "high",
	},
	{
		Name:        "United Kingdom Driver's license ID",
		Regex:       regexp.MustCompile(`\b[\w9]{5}\d{6}[\w9]{2}\d{5}\b`),
		Description: "United Kingdom Driver's license ID",
		Confidence:  "high",
	},
	{
		Name:        "United Kingdom National Health Service (NHS) number",
		Regex:       regexp.MustCompile(`\b\d{3}\s\d{3}\s\d{4}\b`),
		Description: "United Kingdom National Health Service (NHS) number",
		Confidence:  "high",
	},
	{
		Name:        "UK Drivers License Numbers",
		Regex:       regexp.MustCompile(`[A-Z]{5}\d{6}[A-Z]{2}\d{1}[A-Z]{2}`),
		Description: "UK Drivers License Numbers",
		Confidence:  "high",
	},
	{
		Name:        "UK Passport Number",
		Regex:       regexp.MustCompile(`\d{10}GB[RP]\d{7}[UMF]{1}\d{9}`),
		Description: "UK Passport Number",
		Confidence:  "high",
	},
	// License and identification
	{
		Name:        "Driver's License Number (simplified)",
		Regex:       regexp.MustCompile(`^[A-Z]{2}-\d{6}$`),
		Description: "Simplified Driver's License Number pattern",
		Confidence:  "high",
	},
	{
		Name:        "Passport Number (simplified) - 3",
		Regex:       regexp.MustCompile(`^[A-Z]\d{7}$`),
		Description: "Simplified Passport Number pattern",
		Confidence:  "high",
	},
	{
		Name:        "California Drivers License",
		Regex:       regexp.MustCompile(`^[A-Z]{1}\d{7}$`),
		Description: "California Drivers License format",
		Confidence:  "high",
	},
	// OTP (One-Time Password)
	{
		Name:        "OTP",
		Regex:       regexp.MustCompile(`^[0-9]{6}$`),
		Description: "One Time Password (OTP) 6-digit code",
		Confidence:  "high",
	},
	// Technology patterns
	{
		Name:        "IPv4",
		Regex:       regexp.MustCompile(`(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`),
		Description: "IPv4 address",
		Confidence:  "high",
	},
	{
		Name:        "MAC Addresses",
		Regex:       regexp.MustCompile(`(([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2}))`),
		Description: "MAC addresses",
		Confidence:  "high",
	},
	// Financial patterns
	{
		Name:        "Prices",
		Regex:       regexp.MustCompile(`[$]\s?[+-]?[0-9]{1,3}(?:(?:,?[0-9]{3}))*(?:\.[0-9]{1,2})?`),
		Description: "Price amounts with dollar sign",
		Confidence:  "high",
	},
	{
		Name:        "Bitcoin Addresses",
		Regex:       regexp.MustCompile(`(^|[^a-km-zA-HJ-NP-Z0-9])([13][a-km-zA-HJ-NP-Z0-9]{26,33})($|[^a-km-zA-HJ-NP-Z0-9])`),
		Description: "Bitcoin addresses",
		Confidence:  "high",
	},
	{
		Name:        "IBAN Numbers",
		Regex:       regexp.MustCompile(`[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z\d]?){0,16}`),
		Description: "International Bank Account Numbers",
		Confidence:  "high",
	},
	// Hashes
	{
		Name:        "MD5 Hashes",
		Regex:       regexp.MustCompile(`[0-9a-fA-F]{32}`),
		Description: "MD5 hash values",
		Confidence:  "high",
	},
	{
		Name:        "SHA1 Hashes",
		Regex:       regexp.MustCompile(`[0-9a-fA-F]{40}`),
		Description: "SHA1 hash values",
		Confidence:  "high",
	},
	{
		Name:        "SHA256 Hashes",
		Regex:       regexp.MustCompile(`[0-9a-fA-F]{64}`),
		Description: "SHA256 hash values",
		Confidence:  "high",
	},
	// ISBN numbers
	{
		Name:        "ISBN13",
		Regex:       regexp.MustCompile(`(?:[\d]-?){12}[\dxX]`),
		Description: "ISBN-13 book numbers",
		Confidence:  "high",
	},
	{
		Name:        "ISBN10",
		Regex:       regexp.MustCompile(`(?:[\d]-?){9}[\dxX]`),
		Description: "ISBN-10 book numbers",
		Confidence:  "high",
	},
	// Repository patterns
	{
		Name:        "Git Repos",
		Regex:       regexp.MustCompile(`((git|ssh|http(s)?)|(git@[\w\.]+))(:(\/\/)?)([\w\.@\:/\-~]+)(\.git)(\/?)`),
		Description: "Git repository URLs",
		Confidence:  "high",
	},
	// Date patterns
	{
		Name:        "Date of Birth",
		Regex:       regexp.MustCompile(`^\d{2}/\d{2}/\d{4}$|^\d{4}-\d{2}-\d{2}$`),
		Description: "Date of birth in MM/DD/YYYY or YYYY-MM-DD format",
		Confidence:  "high",
	},
	{
		Name:        "Date of Birth - 2",
		Regex:       regexp.MustCompile(`^([1-9]|[12][0-9]|3[01])(/?\.-?-?\s?)(0[1-9]|1[12])(/?\.?-?\s?)(19[0-9][0-9]|20[0][0-9]|20[1][0-8])$`),
		Description: "Date of birth with various separators",
		Confidence:  "high",
	},
	// Color codes
	{
		Name:        "Hex Colors",
		Regex:       regexp.MustCompile(`(#[0-9a-fA-F]{8}|#(?:[0-9a-fA-F]{3}){1,2})\b`),
		Description: "Hexadecimal color codes",
		Confidence:  "high",
	},
	// Other identification patterns
	{
		Name:        "Blood Type",
		Regex:       regexp.MustCompile(`^(A|B|AB|O)[-+]$`),
		Description: "Blood type (A+, B-, etc.)",
		Confidence:  "high",
	},
	{
		Name:        "Tax Number",
		Regex:       regexp.MustCompile(`^[0-9]{10}$`),
		Description: "Tax identification number (10 digits)",
		Confidence:  "high",
	},
	{
		Name:        "Bitcoin Address",
		Regex:       regexp.MustCompile(`^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$`),
		Description: "Bitcoin wallet address",
		Confidence:  "high",
	},

	// AWS-related patterns
	{
		Name:        "AWS API Key",
		Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Description: "AWS API Key",
		Confidence:  "high",
	},
	{
		Name:        "AWS ARN",
		Regex:       regexp.MustCompile(`arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:.+`),
		Description: "AWS Amazon Resource Name",
		Confidence:  "high",
	},
	{
		Name:        "AWS Access Key ID Value",
		Regex:       regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		Description: "AWS Access Key ID pattern",
		Confidence:  "high",
	},
	{
		Name:        "AWS AppSync GraphQL Key",
		Regex:       regexp.MustCompile(`da2-[a-z0-9]{26}`),
		Description: "AWS AppSync GraphQL Key",
		Confidence:  "high",
	},
	{
		Name:        "AWS S3 Bucket",
		Regex:       regexp.MustCompile(`s3://[0-9a-z._/-]+`),
		Description: "AWS S3 Bucket URL",
		Confidence:  "high",
	},
	{
		Name:        "AWS cred file info",
		Regex:       regexp.MustCompile(`(aws_access_key_id|aws_secret_access_key)`),
		Description: "AWS credentials file",
		Confidence:  "high",
	},
	{
		Name:        "AWS - 1",
		Regex:       regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`),
		Description: "AWS Access Key ID pattern variants",
		Confidence:  "high",
	},

	// API and Auth Tokens
	{
		Name:        "Facebook Access Token",
		Regex:       regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
		Description: "Facebook Access Token",
		Confidence:  "high",
	},
	{
		Name:        "GitHub",
		Regex:       regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b)`),
		Description: "GitHub Token",
		Confidence:  "high",
	},
	{
		Name:        "GitHub App Token",
		Regex:       regexp.MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`),
		Description: "GitHub App Token",
		Confidence:  "high",
	},
	{
		Name:        "GitHub OAuth Access Token",
		Regex:       regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
		Description: "GitHub OAuth Access Token",
		Confidence:  "high",
	},
	{
		Name:        "GitHub Personal Access Token",
		Regex:       regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		Description: "GitHub Personal Access Token",
		Confidence:  "high",
	},
	{
		Name:        "GitHub Refresh Token",
		Regex:       regexp.MustCompile(`ghr_[0-9a-zA-Z]{76}`),
		Description: "GitHub Refresh Token",
		Confidence:  "high",
	},
	{
		Name:        "GitLab v2",
		Regex:       regexp.MustCompile(`\b(glpat-[a-zA-Z0-9\-=_]{20,22})\b`),
		Description: "GitLab Personal Access Token",
		Confidence:  "high",
	},
}


