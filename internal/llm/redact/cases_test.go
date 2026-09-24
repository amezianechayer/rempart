package redact

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Normative fixtures of docs/plans/M0-redaction.md, section 7.2. Every string
// that looks like a secret carries a marker (EXAMPLE, FAKE) in the string
// itself, or just before it; fixtures are only ever fields of these composite
// literals, never assigned to a variable of their own.

type posCase struct {
	name  string // l<NN>_<snake_case>, NN = line of redaction-patterns.md
	line  int
	in    string
	want  string
	kinds []Kind
}

var positiveCases = []posCase{
	// Line 1: AWS access keys and associated secrets.
	{
		"l01_aws_access_key_bare", 1,
		"AKIAIOSFODNN7EXAMPLE",
		"[REDACTED:aws_access_key]",
		[]Kind{KindAWSAccessKey},
	},
	{
		"l01_aws_sts_key_id_json", 1,
		`{"AccessKeyId": "ASIAIOSFODNN7EXAMPLE"}`,
		`{"AccessKeyId": "[REDACTED:aws_access_key]"}`,
		[]Kind{KindAWSAccessKey},
	},
	{
		"l01_aws_credentials_ini", 1,
		"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"[default]\naws_access_key_id = [REDACTED:aws_access_key]\naws_secret_access_key = [REDACTED:aws_secret_key]",
		[]Kind{KindAWSAccessKey, KindAWSSecretKey},
	},
	{
		"l01_aws_secret_key_env", 1,
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_SECRET_ACCESS_KEY=[REDACTED:aws_secret_key]",
		[]Kind{KindAWSSecretKey},
	},
	{
		"l01_aws_secret_key_json", 1,
		`{"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`,
		`{"SecretAccessKey":"[REDACTED:aws_secret_key]"}`,
		[]Kind{KindAWSSecretKey},
	},
	{
		"l01_aws_secret_key_env_json_escaped", 1,
		`{"env":"DEBUG=1\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"}`,
		`{"env":"DEBUG=1\nAWS_SECRET_ACCESS_KEY=[REDACTED:aws_secret_key]\n"}`,
		[]Kind{KindAWSSecretKey},
	},
	{
		"l01_two_tokens_one_line", 1,
		"AKIAIOSFODNN7EXAMPLE,ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000",
		"[REDACTED:aws_access_key],[REDACTED:github_token]",
		[]Kind{KindAWSAccessKey, KindGitHubToken},
	},

	// Line 2: AWS session tokens.
	{
		"l02_aws_session_token_env", 2,
		"AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEXAMPLE0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH",
		"AWS_SESSION_TOKEN=[REDACTED:aws_session_token]",
		[]Kind{KindAWSSessionToken},
	},
	{
		"l02_aws_session_token_shape", 2,
		"issued IQoJb3JpZ2luX2VjEXAMPLE0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH for 1h",
		"issued [REDACTED:aws_session_token] for 1h",
		[]Kind{KindAWSSessionToken},
	},
	{
		"l02_aws_presigned_url", 2,
		"https://fake-bucket.s3.amazonaws.com/o?X-Amz-Security-Token=FwoGZXIvYXdzEXAMPLE&X-Amz-Signature=FAKE0123456789abcdef",
		"https://fake-bucket.s3.amazonaws.com/o?X-Amz-Security-Token=[REDACTED:aws_session_token]&X-Amz-Signature=[REDACTED:aws_session_token]",
		[]Kind{KindAWSSessionToken, KindAWSSessionToken},
	},

	// Line 3: Azure.
	{
		"l03_azure_storage_connection_string", 3,
		"DefaultEndpointsProtocol=https;AccountName=fakeaccount;AccountKey=FAKEEXAMPLE0000000000000000000000000000000000==;EndpointSuffix=core.windows.net",
		"DefaultEndpointsProtocol=https;AccountName=fakeaccount;AccountKey=[REDACTED:azure_secret];EndpointSuffix=core.windows.net",
		[]Kind{KindAzureSecret},
	},
	{
		"l03_azure_sas_url", 3,
		"https://fakeaccount.blob.core.windows.net/c/b.txt?sv=2022-11-02&sp=r&se=2026-12-31T00:00:00Z&sig=FAKEEXAMPLE0000000000000000000000000000%3D",
		"https://fakeaccount.blob.core.windows.net/c/b.txt?sv=2022-11-02&sp=r&se=2026-12-31T00:00:00Z&sig=[REDACTED:azure_secret]",
		[]Kind{KindAzureSecret},
	},
	{
		"l03_azure_client_secret_tfvars", 3,
		`client_secret = "abc8Q~FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00"`,
		`client_secret = "[REDACTED:azure_secret]"`,
		[]Kind{KindAzureSecret},
	},
	{
		"l03_azure_client_secret_shape", 3,
		"rotated to abc8Q~FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00 today",
		"rotated to [REDACTED:azure_secret] today",
		[]Kind{KindAzureSecret},
	},
	// V2 F7: json.Marshal writes '&' as \u0026.
	{
		"l03_azure_sas_json_marshal", 3,
		`{"sas":"https://fakeaccount.blob.core.windows.net/c/b?sv=2022-11-02\u0026sp=r\u0026sig=FAKEEXAMPLE0000000000000000000000000000%3D"}`,
		`{"sas":"https://fakeaccount.blob.core.windows.net/c/b?sv=2022-11-02\u0026sp=r\u0026sig=[REDACTED:azure_secret]"}`,
		[]Kind{KindAzureSecret},
	},

	// Line 4: Scaleway and OVHcloud.
	{
		"l04_scaleway_access_key_shape", 4,
		"SCWFAKEEXAMPLE000000",
		"[REDACTED:scaleway_key]",
		[]Kind{KindScalewayKey},
	},
	{
		"l04_scaleway_secret_key_env", 4,
		"SCW_SECRET_KEY=11111111-2222-4333-8444-555555555555",
		"SCW_SECRET_KEY=[REDACTED:scaleway_key]",
		[]Kind{KindScalewayKey},
	},
	{
		"l04_scaleway_provider_hcl", 4,
		"provider \"scaleway\" {\n  access_key = \"SCWFAKEEXAMPLE000000\"\n  secret_key = \"11111111-2222-4333-8444-555555555555\"\n}",
		"provider \"scaleway\" {\n  access_key = \"[REDACTED:scaleway_key]\"\n  secret_key = \"[REDACTED:sensitive_variable]\"\n}",
		[]Kind{KindScalewayKey, KindSensitiveVar},
	},
	{
		"l04_ovh_env", 4,
		"OVH_APPLICATION_SECRET=FAKEovhEXAMPLEsecret0000",
		"OVH_APPLICATION_SECRET=[REDACTED:ovh_credential]",
		[]Kind{KindOVHCredential},
	},
	{
		"l04_ovh_provider_hcl", 4,
		"provider \"ovh\" {\n  endpoint           = \"ovh-eu\"\n  application_key    = \"FAKEovhappkey000\"\n  application_secret = \"FAKEovhappsecret0000000000000000\"\n  consumer_key       = \"FAKEovhconsumerkey00000000000000\"\n}",
		"provider \"ovh\" {\n  endpoint           = \"ovh-eu\"\n  application_key    = \"[REDACTED:ovh_credential]\"\n  application_secret = \"[REDACTED:ovh_credential]\"\n  consumer_key       = \"[REDACTED:ovh_credential]\"\n}",
		[]Kind{KindOVHCredential, KindOVHCredential, KindOVHCredential},
	},

	// Line 5: PEM private keys.
	{
		"l05_pem_rsa", 5,
		"-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYEXAMPLEMIIEpAIBAAKCAQEA0000\n00000000000000000000000000000000\n-----END RSA PRIVATE KEY-----\ndone",
		"[REDACTED:private_key]\ndone",
		[]Kind{KindPrivateKey},
	},
	{
		"l05_pem_openssh", 5,
		"-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEb3BlbnNzaC1rZXktdjEAAAAAEXAMPLE\n-----END OPENSSH PRIVATE KEY-----",
		"[REDACTED:private_key]",
		[]Kind{KindPrivateKey},
	},
	{
		"l05_pem_encrypted_headers", 5,
		"FAKE\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,FAKE0000000000000000000000000000\n\nFAKEEXAMPLEbase64body0000\n-----END RSA PRIVATE KEY-----",
		"FAKE\n[REDACTED:private_key]",
		[]Kind{KindPrivateKey},
	},
	{
		"l05_pem_json_escaped_no_key", 5,
		`{"log":"-----BEGIN RSA PRIVATE KEY-----\nFAKEEXAMPLEMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"}`,
		`{"log":"[REDACTED:private_key]\n"}`,
		[]Kind{KindPrivateKey},
	},
	{
		"l05_gcp_service_account_json", 5,
		`{"type": "service_account", "private_key_id": "FAKE0123456789abcdef", "private_key": "-----BEGIN PRIVATE KEY-----\nFAKEEXAMPLEMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n", "client_email": "fake@example.iam.gserviceaccount.com"}`,
		`{"type": "service_account", "private_key_id": "[REDACTED:sensitive_variable]", "private_key": "[REDACTED:private_key]", "client_email": "fake@example.iam.gserviceaccount.com"}`,
		[]Kind{KindSensitiveVar, KindPrivateKey},
	},
	{
		"l05_pem_truncated", 5,
		"-----BEGIN EC PRIVATE KEY-----\nFAKEEXAMPLEMHcCAQEEIA0000",
		"[REDACTED:private_key]",
		[]Kind{KindPrivateKey},
	},
	{
		"l05_pem_key_after_certificate", 5,
		"-----BEGIN CERTIFICATE-----\nFAKECERTMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nFAKEEXAMPLEMIIEvQIBADANBgkqhkiG\n-----END PRIVATE KEY-----",
		"-----BEGIN CERTIFICATE-----\nFAKECERTMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n[REDACTED:private_key]",
		[]Kind{KindPrivateKey},
	},
	{
		"l05_pem_base64_encoded", 5,
		"tls.key: LS0tLS1CRUdJTiBGQUtFIEVYQU1QTEUgS0VZLS0tLS0K",
		"tls.key: [REDACTED:private_key]",
		[]Kind{KindPrivateKey},
	},
	// V2 F3: armor header lines (Version, Comment) are part of the block.
	{
		"l05_pgp_armor_with_headers", 5,
		"FAKE\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: FAKE 2.7.4\nComment: https://example.org/FAKE\n\nxcLYBGFAKEEXAMPLE0000base64body\n=FAKE\n-----END PGP PRIVATE KEY BLOCK-----\ndone",
		"FAKE\n[REDACTED:private_key]\ndone",
		[]Kind{KindPrivateKey},
	},
	{
		"l05_pgp_armor_json_escaped", 5,
		`{"key":"-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: FAKE 2.7.4\n\nxcLYBGFAKEEXAMPLE0000\n-----END PGP PRIVATE KEY BLOCK-----\n"}`,
		`{"key":"[REDACTED:private_key]\n"}`,
		[]Kind{KindPrivateKey},
	},

	// Line 6: GitHub, GitLab, Slack tokens.
	{
		"l06_github_classic", 6,
		"ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000",
		"[REDACTED:github_token]",
		[]Kind{KindGitHubToken},
	},
	{
		"l06_github_fine_grained_git_url", 6,
		"https://x-access-token:github_pat_FAKE000000000000000000_EXAMPLE0000000000000000000000000000000000000000000000000000000000000@github.com/o/r.git",
		"https://x-access-token:[REDACTED:github_token]@github.com/o/r.git",
		[]Kind{KindGitHubToken},
	},
	{
		"l06_gitlab_header", 6,
		"PRIVATE-TOKEN: glpat-FAKEEXAMPLE000000000",
		"PRIVATE-TOKEN: [REDACTED:gitlab_token]",
		[]Kind{KindGitLabToken},
	},
	{
		"l06_slack_bot_token_yaml", 6,
		"slack:\n  bot_token: xoxb-FAKE-0000000000-EXAMPLE",
		"slack:\n  bot_token: [REDACTED:slack_token]",
		[]Kind{KindSlackToken},
	},
	{
		"l06_slack_webhook", 6,
		"webhook: https://hooks.slack.com/services/fake-example/placeholder-path",
		"webhook: [REDACTED:slack_token]",
		[]Kind{KindSlackToken},
	},
	{
		"l06_adjacent_tokens_no_separator", 6,
		"AKIAIOSFODNN7EXAMPLEghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000",
		"[REDACTED:aws_access_key][REDACTED:github_token]",
		[]Kind{KindAWSAccessKey, KindGitHubToken},
	},

	// Line 7: LLM API keys.
	{
		"l07_anthropic_key_env", 7,
		"ANTHROPIC_API_KEY=sk-ant-api03-FAKEEXAMPLE0000000000000000",
		"ANTHROPIC_API_KEY=[REDACTED:llm_api_key]",
		[]Kind{KindLLMAPIKey},
	},
	{
		"l07_openai_key_json", 7,
		`{"api_key":"sk-proj-FAKEEXAMPLE000000000000"}`,
		`{"api_key":"[REDACTED:llm_api_key]"}`,
		[]Kind{KindLLMAPIKey},
	},
	{
		"l07_llm_key_in_prose", 7,
		"use sk-FAKEEXAMPLE0000000000000 for tests",
		"use [REDACTED:llm_api_key] for tests",
		[]Kind{KindLLMAPIKey},
	},
	// V2 F7: json.Marshal writes '<' and '>' as \u003c and \u003e.
	{
		"l07_llm_key_json_escaped_angle_brackets", 7,
		`{"note":"\u003csk-proj-FAKEEXAMPLE000000000000\u003e"}`,
		`{"note":"\u003c[REDACTED:llm_api_key]\u003e"}`,
		[]Kind{KindLLMAPIKey},
	},

	// Line 8: passwords in URLs.
	{
		"l08_url_basic_auth", 8,
		"https://admin:FAKEpassw0rd@registry.example.com/v2/",
		"https://admin:[REDACTED:url_credentials]@registry.example.com/v2/",
		[]Kind{KindURLCredentials},
	},
	{
		"l08_url_in_yaml", 8,
		`mirror: "ftp://mirror:FAKEftppass@ftp.example.org/pub"`,
		`mirror: "ftp://mirror:[REDACTED:url_credentials]@ftp.example.org/pub"`,
		[]Kind{KindURLCredentials},
	},
	// V2 F1: the user name contains '@'; the password ends at the last '@'.
	{
		"l08_smtp_user_is_email", 8,
		"EMAIL_URL=smtp://alerts@example.com:FAKEsmtpEXAMPLE@smtp.example.com:587",
		"EMAIL_URL=smtp://alerts@example.com:[REDACTED:url_credentials]@smtp.example.com:587",
		[]Kind{KindURLCredentials},
	},

	// Line 9: database connection strings.
	{
		"l09_postgres_url_env", 9,
		"DATABASE_URL=postgres://app:FAKEdbpass@db.internal:5432/app?sslmode=require",
		"DATABASE_URL=postgres://app:[REDACTED:db_connection_string]@db.internal:5432/app?sslmode=require",
		[]Kind{KindDBConnString},
	},
	{
		"l09_mongodb_srv", 9,
		"mongodb+srv://root:FAKEmongoEXAMPLE@cluster0.example.mongodb.net/admin",
		"mongodb+srv://root:[REDACTED:db_connection_string]@cluster0.example.mongodb.net/admin",
		[]Kind{KindDBConnString},
	},
	{
		"l09_jdbc_query_password", 9,
		"jdbc:mysql://db.example.com:3306/app?user=app&password=FAKEjdbcpass",
		"jdbc:mysql://db.example.com:3306/app?user=app&password=[REDACTED:sensitive_variable]",
		[]Kind{KindSensitiveVar},
	},
	{
		"l09_ado_connection_string", 9,
		"Server=tcp:fake.database.windows.net,1433;User ID=app;Password=FAKEsqlpass;Encrypt=True",
		"Server=tcp:fake.database.windows.net,1433;User ID=app;Password=[REDACTED:sensitive_variable];Encrypt=True",
		[]Kind{KindSensitiveVar},
	},
	// V2 F1: '@' inside the password, and '@' inside the user name.
	{
		"l09_postgres_password_with_at", 9,
		"DATABASE_URL=postgres://admin:P@FAKEdbpassEXAMPLE@db.internal:5432/app",
		"DATABASE_URL=postgres://admin:[REDACTED:db_connection_string]@db.internal:5432/app",
		[]Kind{KindDBConnString},
	},
	{
		"l09_azure_postgres_user_at_server", 9,
		"postgresql://pgadmin@fakeserver:FAKEpgEXAMPLE@fakeserver.postgres.database.azure.com:5432/postgres?sslmode=require",
		"postgresql://pgadmin@fakeserver:[REDACTED:db_connection_string]@fakeserver.postgres.database.azure.com:5432/postgres?sslmode=require",
		[]Kind{KindDBConnString},
	},

	// Line 10: kubeconfig.
	{
		"l10_kubeconfig_token", 10,
		"users:\n- name: fake\n  user:\n    token: FAKEEXAMPLEeyJhbGciOiJSUzI1NiJ9.e30.FAKEsig",
		"users:\n- name: fake\n  user:\n    token: [REDACTED:kubeconfig_credential]",
		[]Kind{KindKubeconfig},
	},
	{
		"l10_kubeconfig_client_key_data", 10,
		"    client-key-data: LS0tLS1CRUdJTiBGQUtFIEVYQU1QTEUgS0VZLS0tLS0K",
		"    client-key-data: [REDACTED:kubeconfig_credential]",
		[]Kind{KindKubeconfig},
	},

	// Line 11: values of variables named *password*, *secret*, *token*, *api_key*.
	{
		"l11_tfvars_password", 11,
		`db_password = "FAKE-hunter2"`,
		`db_password = "[REDACTED:sensitive_variable]"`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_k8s_secret_string_data", 11,
		"apiVersion: v1\nkind: Secret\nstringData:\n  api_key: FAKEapikey123\n  app_secret: 'FAKE s3cret with spaces'\n",
		"apiVersion: v1\nkind: Secret\nstringData:\n  api_key: [REDACTED:sensitive_variable]\n  app_secret: '[REDACTED:sensitive_variable]'\n",
		[]Kind{KindSensitiveVar, KindSensitiveVar},
	},
	{
		"l11_json_nested_camel_case", 11,
		`{"auth": {"refreshToken": "FAKErefreshEXAMPLE"}}`,
		`{"auth": {"refreshToken": "[REDACTED:sensitive_variable]"}}`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_env_export", 11,
		"export GITHUB_TOKEN=FAKEnotAGitHubShape",
		"export GITHUB_TOKEN=[REDACTED:sensitive_variable]",
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_authorization_bearer_curl", 11,
		`curl -H "Authorization: Bearer FAKEbearerEXAMPLE0000" https://api.example.com/v1`,
		`curl -H "Authorization: Bearer [REDACTED:sensitive_variable]" https://api.example.com/v1`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_authorization_basic_json", 11,
		`{"headers": {"Authorization": "Basic RkFLRTpFWEFNUExF"}}`,
		`{"headers": {"Authorization": "Basic [REDACTED:sensitive_variable]"}}`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_yaml_block_scalar", 11,
		"password: |\n  FAKE-line-one\n  FAKE-line-two\nuser: admin",
		"password: |\n  [REDACTED:sensitive_variable]\nuser: admin",
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_yaml_block_scalar_json_escaped", 11,
		`{"file":"password: |\n  FAKE-line-one\n  FAKE-line-two\nuser: admin"}`,
		`{"file":"password: |\n  [REDACTED:sensitive_variable]\nuser: admin"}`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_escaped_quotes_in_json_log", 11,
		`{"msg":"set password = \"FAKEhunter2\" on db"}`,
		`{"msg":"set password = \"[REDACTED:sensitive_variable]\" on db"}`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_json_value_with_escaped_quote", 11,
		`{"password":"FAKE\"quoted\"pass"}`,
		`{"password":"[REDACTED:sensitive_variable]"}`,
		[]Kind{KindSensitiveVar},
	},
	// V2 F2: a one-line array is a value, masked whole from '[' to ']': no
	// element stays in clear.
	{
		"l11_multi_value_headers_authorization", 11,
		`{"multiValueHeaders":{"Authorization":["Basic RkFLRTpFWEFNUExF"]}}`,
		`{"multiValueHeaders":{"Authorization":[REDACTED:sensitive_variable]}}`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_authorization_array_two_values", 11,
		`{"Authorization":["Basic RkFLRTpFWEFNUExF", "Basic RkFLRTI6RVhBTVBMRTI="]}`,
		`{"Authorization":[REDACTED:sensitive_variable]}`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_go_http_header_map", 11,
		"map[Authorization:[Basic RkFLRTpFWEFNUExF] Content-Type:[application/json]]",
		"map[Authorization:[REDACTED:sensitive_variable] Content-Type:[application/json]]",
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_yaml_flow_authorization_array", 11,
		`Authorization: ["Basic RkFLRTpFWEFNUExF"]`,
		"Authorization: [REDACTED:sensitive_variable]",
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_json_array_of_api_keys", 11,
		`{"api_keys": ["FAKEkeyEXAMPLE1", "FAKEkeyEXAMPLE2"]}`,
		`{"api_keys": [REDACTED:sensitive_variable]}`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_yaml_flow_sequence_of_tokens", 11,
		"tokens: [FAKEtokenONE, FAKEtokenTWO]",
		"tokens: [REDACTED:sensitive_variable]",
		[]Kind{KindSensitiveVar},
	},
	// V2 F4: the value of a "value" field whose sibling "name" field is a
	// sensitive name, in both orders, in YAML list items and JSON objects.
	{
		"l11_k8s_env_name_value", 11,
		"env:\n- name: LOG_LEVEL\n  value: debug\n- name: DB_PASSWORD\n  value: FAKEk8sEXAMPLE\n",
		"env:\n- name: LOG_LEVEL\n  value: debug\n- name: DB_PASSWORD\n  value: [REDACTED:sensitive_variable]\n",
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_k8s_env_value_before_name", 11,
		"    env:\n      - value: \"FAKEk8sEXAMPLE\"\n        name: API_TOKEN\n",
		"    env:\n      - value: \"[REDACTED:sensitive_variable]\"\n        name: API_TOKEN\n",
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_helm_values_yaml_in_json", 11,
		`{"values":["env:\n- name: DB_PASSWORD\n  value: FAKEk8sEXAMPLE\n"]}`,
		`{"values":["env:\n- name: DB_PASSWORD\n  value: [REDACTED:sensitive_variable]\n"]}`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_ecs_environment_json", 11,
		`{"environment":[{"name":"DB_PASSWORD","value":"FAKEecsEXAMPLE"},{"name":"LOG_LEVEL","value":"info"}]}`,
		`{"environment":[{"name":"DB_PASSWORD","value":"[REDACTED:sensitive_variable]"},{"name":"LOG_LEVEL","value":"info"}]}`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_ecs_value_before_name_json", 11,
		`[{"value": "FAKEecsEXAMPLE", "name": "SPRING_DATASOURCE_PASSWORD"}]`,
		`[{"value": "[REDACTED:sensitive_variable]", "name": "SPRING_DATASOURCE_PASSWORD"}]`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_ecs_environment_pretty_json", 11,
		"\"environment\": [\n  {\n    \"name\": \"DB_PASSWORD\",\n    \"value\": \"FAKEecsEXAMPLE\"\n  }\n]",
		"\"environment\": [\n  {\n    \"name\": \"DB_PASSWORD\",\n    \"value\": \"[REDACTED:sensitive_variable]\"\n  }\n]",
		[]Kind{KindSensitiveVar},
	},
	// V2 F6: without a closing quote on the line, the value runs to the end of
	// the line or of the text.
	{
		"l11_unterminated_json_quote_end_of_text", 11,
		`{"password": "FAKEtruncatedEXAMPLE`,
		`{"password": "[REDACTED:sensitive_variable]`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_unterminated_quote_end_of_line", 11,
		"db_password: \"FAKEtruncated EXAMPLE\nuser: admin",
		"db_password: \"[REDACTED:sensitive_variable]\nuser: admin",
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_unterminated_quote_crlf", 11,
		"app_secret: \"FAKE unterminated\r\nuser: admin",
		"app_secret: \"[REDACTED:sensitive_variable]\r\nuser: admin",
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_unterminated_single_quote_crlf", 11,
		"app_secret: 'FAKE unterminated\r\nuser: admin",
		"app_secret: '[REDACTED:sensitive_variable]\r\nuser: admin",
		[]Kind{KindSensitiveVar},
	},
	// V2 F7: json.Marshal writes '&' as \u0026 before a key.
	{
		"l11_json_marshal_ampersand_password", 11,
		`{"url":"https://api.example.com/login?user=bob\u0026password=FAKEpassEXAMPLE\u0026lang=fr"}`,
		`{"url":"https://api.example.com/login?user=bob\u0026password=[REDACTED:sensitive_variable]\u0026lang=fr"}`,
		[]Kind{KindSensitiveVar},
	},
	// V2 F9: "pass" as a whole key segment; the exact key "auth".
	{
		"l11_rabbitmq_default_pass_env", 11,
		"RABBITMQ_DEFAULT_PASS=FAKErabbitEXAMPLE",
		"RABBITMQ_DEFAULT_PASS=[REDACTED:sensitive_variable]",
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_smtp_pass_yaml", 11,
		`SMTP_PASS: "FAKEsmtpEXAMPLE"`,
		`SMTP_PASS: "[REDACTED:sensitive_variable]"`,
		[]Kind{KindSensitiveVar},
	},
	{
		"l11_camel_case_pass", 11,
		`{"smtpPass": "FAKEsmtpEXAMPLE", "db.pass": "FAKEdbEXAMPLE"}`,
		`{"smtpPass": "[REDACTED:sensitive_variable]", "db.pass": "[REDACTED:sensitive_variable]"}`,
		[]Kind{KindSensitiveVar, KindSensitiveVar},
	},
	{
		"l11_docker_config_auth", 11,
		`{"auths":{"https://index.docker.io/v1/":{"auth":"RkFLRTpFWEFNUExF"}}}`,
		`{"auths":{"https://index.docker.io/v1/":{"auth":"[REDACTED:sensitive_variable]"}}}`,
		[]Kind{KindSensitiveVar},
	},

	// Line 12: IPsec pre-shared keys.
	{
		"l12_aws_vpn_tunnel_psk", 12,
		`tunnel1_preshared_key = "FAKEpskEXAMPLE0000"`,
		`tunnel1_preshared_key = "[REDACTED:ipsec_psk]"`,
		[]Kind{KindIPsecPSK},
	},
	{
		"l12_strongswan_ipsec_secrets", 12,
		`203.0.113.1 198.51.100.1 : PSK "FAKEpskEXAMPLE"`,
		`203.0.113.1 198.51.100.1 : PSK "[REDACTED:ipsec_psk]"`,
		[]Kind{KindIPsecPSK},
	},
	{
		"l12_azure_vpn_shared_key", 12,
		`shared_key = "FAKEsharedEXAMPLE"`,
		`shared_key = "[REDACTED:ipsec_psk]"`,
		[]Kind{KindIPsecPSK},
	},
}

var negativeCases = []struct{ name, in string }{
	{"prose_password", "Rotate the database password every 90 days and never reuse a password."},
	{"prose_secret_and_token", "The secret of a good token bucket is its refill rate."},
	{"label_without_value", "password:\nusername: admin"},
	{"empty_quoted_value", `password = ""`},
	{"sha256_hex", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"docker_digest", "image: nginx@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"git_sha1", "commit da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"uuid", "resource_id: 123e4567-e89b-42d3-a456-426614174000"},
	{"max_tokens_yaml", "max_tokens: 1024"},
	{"token_usage_json", `{"max_tokens": 1024, "input_tokens": 12, "output_tokens": 345}`},
	{"password_policy_hcl", "minimum_password_length = 14\npassword_reuse_prevention = 24\nmax_password_age = 90"},
	{"boolean_and_null_values", "manage_master_user_password = true\nrequire_secret: false\nsecret_rotation = null"},
	{"hcl_references", "password = var.db_password\nsecret = data.aws_secretsmanager_secret_version.db.secret_string\napi_key = \"${var.api_key}\""},
	{"env_and_template_references", "DB_PASSWORD=$DB_PASSWORD_FROM_VAULT\nclient_token: \"{{ .Values.clientToken }}\"\napi_key: \"${{ secrets.API_KEY }}\""},
	{"secret_names_arns_urls", "secret_name: prod/db\nsecret_arn = \"arn:aws:secretsmanager:eu-west-3:123456789012:secret:prod/db-AbCdEf\"\ntoken_url: https://login.example.com/oauth2/token"},
	{"existing_placeholders", "password: [REDACTED:sensitive_variable]\nAuthorization: Bearer [REDACTED:sensitive_variable]\nurl: https://u:[REDACTED:url_credentials]@example.com"},
	{"sk_and_task_identifiers", "task-0123456789abcdefghijklmnop and sk-short"},
	{"urls_without_password", "https://user@example.com/path and http://example.com:8080/x"},
	{"public_pem_blocks", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----\n-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----"},
	{"kubernetes_secret_key_ref", "valueFrom:\n  secretKeyRef:\n    name: db\n    key: password"},
	{"short_prefixes", "AKIA1234 ghp_short glpat-short xoxb-1 sk-ant-x"},
	{"iam_policy_json", `{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}`},
	// V2 F2: an array under a key that is not sensitive stays intact.
	{"array_under_plain_key", "{\"allowed_origins\": [\"https://example.com\", \"https://example.org\"], \"ports\": [80, 443]}\ntags: [web, prod]"},
	// V2 F4: a name that is not sensitive, a name and a value in two list
	// items or two objects, a value read from a secret reference, and a pair
	// whose value the generic exemptions (E2) keep.
	{"name_value_not_sensitive", "env:\n- name: LOG_LEVEL\n  value: debug\necs: [{\"name\": \"LOG_LEVEL\", \"value\": \"debug\"}]"},
	{"name_value_different_items", "- name: DB_PASSWORD\n- value: plain\n[{\"name\": \"DB_PASSWORD\"}, {\"value\": \"plain\"}]"},
	{"name_value_across_items", "- name: DB_PASSWORD\n  valueFrom:\n    secretKeyRef: {name: db, key: password}\n- image: nginx\n  value: plain"},
	{"name_value_different_columns", "spec:\n  name: DB_PASSWORD\nvalue: plain"},
	{"name_value_from_secret_ref", "- name: DB_PASSWORD\n  valueFrom:\n    secretKeyRef:\n      name: db-credentials\n      key: password"},
	{"name_value_exempt_quantity", "- name: ANTHROPIC_MAX_TOKENS\n  value: \"1024\""},
	// V2 F8: a quantity word that is a whole key segment still exempts a
	// small integer, after '_', '.', '-' or a case change.
	{"quantity_segments_exempt", "maxTokens: 1024\nMAX_TOKENS=1024\npassword_min_length: 12\npasswordMaxAge: 90\nsecret-rotation-days: 30\napi_key.ttl = 3600"},
	// V2 F9: "pass" inside a longer segment, and keys around "auth".
	{"pass_and_auth_lookalikes", "bypass_mode: strict\npassenger_count: 3\ncompassHeading: north\nisPassing: sometimes\noauth: enabled\nauth_method: oidc"},
}

var narrowCases = []struct{ name, in, want string }{
	{"x01_numeric_password", "password: 123456", "password: [REDACTED:sensitive_variable]"},
	{"x02_ten_digit_token", "api_token: 1234567890", "api_token: [REDACTED:sensitive_variable]"},
	{"x03_quantity_key_eleven_digits", "token_count = 12345678901", "token_count = [REDACTED:sensitive_variable]"},
	{"x04_quantity_key_non_numeric", "max_tokens: 1024abc", "max_tokens: [REDACTED:sensitive_variable]"},
	{"x05_length_key_text_value", `password_length = "FAKEnotanumber"`, `password_length = "[REDACTED:sensitive_variable]"`},
	{"x06_id_suffix_not_exempt", `secret_id = "FAKEvaultsecretid"`, `secret_id = "[REDACTED:sensitive_variable]"`},
	{"x07_keyword_prefix", `password = "true-FAKE"`, `password = "[REDACTED:sensitive_variable]"`},
	{"x08_partial_interpolation", `password = "${var.x}FAKE"`, `password = "[REDACTED:sensitive_variable]"`},
	{"x09_suffix_not_at_end", "secret_name_FAKE: FAKEvalue", "secret_name_FAKE: [REDACTED:sensitive_variable]"},
	{"x10_reference_containing_token", "password = var.AKIAIOSFODNN7EXAMPLE", "password = [REDACTED:aws_access_key]"},
	{"x11_name_key_containing_token", "secret_name: ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000", "secret_name: [REDACTED:github_token]"},
	{"x12_exact_token_key_numeric", "token: 1024", "token: [REDACTED:kubeconfig_credential]"},
	// V2 F8: a quantity word inside a longer key segment (adMIN, acCOUNT,
	// manAGEr, storAGE, imPORTed) does not exempt a numeric secret.
	{"x13_admin_password_digits", "admin_password: 48213957", "admin_password: [REDACTED:sensitive_variable]"},
	{"x14_account_password_digits", "SERVICE_ACCOUNT_PASSWORD=74120385", "SERVICE_ACCOUNT_PASSWORD=[REDACTED:sensitive_variable]"},
	{"x15_manager_password_digits", `manager_password = "55120947"`, `manager_password = "[REDACTED:sensitive_variable]"`},
	{"x16_storage_password_digits", "storage_password: 20250101", "storage_password: [REDACTED:sensitive_variable]"},
	{"x17_imported_secret_digits", "importedSecret=4242", "importedSecret=[REDACTED:sensitive_variable]"},
}

var overlapCases = []struct {
	name, in, want string
	kinds          []Kind
}{
	{"o1_token_inside_sensitive_value", `password: "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000"`, `password: "[REDACTED:github_token]"`, []Kind{KindGitHubToken}},
	{"o2_kubeconfig_beats_base64_pem", "client-key-data: LS0tLS1CRUdJTiBGQUtFIEVYQU1QTEUgS0VZLS0tLS0K", "client-key-data: [REDACTED:kubeconfig_credential]", []Kind{KindKubeconfig}},
	{"o3_db_url_inside_sensitive_value", "password=postgres://u:FAKEp@h/db", "password=[REDACTED:db_connection_string]", []Kind{KindDBConnString}},
	{"o4_llm_key_inside_sensitive_value", `api_key = "sk-ant-api03-FAKEEXAMPLE0000000000000000"`, `api_key = "[REDACTED:llm_api_key]"`, []Kind{KindLLMAPIKey}},
	{"o5_keyed_aws_secret_beats_shape", "aws_secret_access_key = AKIAIOSFODNN7EXAMPLE", "aws_secret_access_key = [REDACTED:aws_secret_key]", []Kind{KindAWSSecretKey}},
	{"o6_pem_inside_hcl_string", `private_key = "-----BEGIN RSA PRIVATE KEY-----\nFAKEEXAMPLE\n-----END RSA PRIVATE KEY-----"`, `private_key = "[REDACTED:private_key]"`, []Kind{KindPrivateKey}},
	{"o7_union_extends_past_value", "password=x-----BEGIN RSA PRIVATE KEY-----\nFAKEEXAMPLE0000\n-----END RSA PRIVATE KEY-----", "password=[REDACTED:private_key]", []Kind{KindPrivateKey}},
}

// idempotentCases are inputs whose first redaction must be stable.
var idempotentCases = []string{
	"AKIAIOSFODNN7EXAMPLEsk-FAKEEXAMPLE0000000000000",
	"password=[REDACTED:github_token]FAKEtail",
	"password: |\n  [REDACTED:sensitive_variable]\n  FAKEtail",
	"Authorization: Bearer [REDACTED:sensitive_variable] FAKEtail",
	"https://u:[REDACTED:url_credentials]FAKE@h",
	"secret_name: var.[REDACTED:aws_access_key]",
	"[REDACTED:private_key]-----BEGIN FAKE PRIVATE KEY-----",
	// V2: a quote never closed at the end of the text gains a closing quote
	// once encoded in JSON; the JSON body must not reveal a new value (F6),
	// nor a name that a quote ends (F4).
	"password: '",
	"password: 'true",
	`password: "true`,
	`{name: DB_PASSWORD", value: FAKEvalue}`,
	// V2: masking must not remove what kept a value unread: a backslash that
	// ended a quote never closed (F6), a brace that split an object or a line
	// break that split two fields (F4).
	`password: 'FAKE -----BEGIN PGP PRIVATE KEY BLOCK-----FAKE\x`,
	`{"name":"DB_PASSWORD","token":"a{b","value":"FAKEvalue"}`,
	`- name: DB_PASSWORD token: "a\nb"
  value: FAKEvalue`,
	// V2 exploration: a reading stopped by a backslash that another mask
	// covers (armor, escaped value); a match hidden by a match that starts in
	// an existing placeholder, whose head another mask covers; JSON escapes
	// that change where a value, a token or a scheme starts.
	`password: 'FAKE -----BEGIN RSA PRIVATE KEY-----\x'`,
	`password: 'FAKE token: "a\\b"'`,
	`password=psk [REDACTED:ipsec_psk]x/PSK FAKEvalue`,
	`PSK [REDACTED:ipsec_psk]&sig=FAKE@psk FAKEvalue`,
	"password=|\n    [REDACTED:url_credentials]\" secret=FAKEvalue",
	`Authorization: Bearer \tFAKEbearerEXAMPLE0000`,
	"a\n8x://u:FAKEpass@h",
	"password=|\n  \r\nFAKEvalue",
}

// referenceLines maps each bullet of redaction-patterns.md, by prefix, to the
// kinds it requires (docs/plans/M0-redaction.md, section 5.3).
var referenceLines = []struct {
	prefix string
	kinds  []Kind
}{
	{"Clés d'accès AWS", []Kind{KindAWSAccessKey, KindAWSSecretKey}},
	{"Jetons de session AWS", []Kind{KindAWSSessionToken}},
	{"Secrets de service principal Azure", []Kind{KindAzureSecret}},
	{"Clés API Scaleway", []Kind{KindScalewayKey, KindOVHCredential}},
	{"Clés privées PEM", []Kind{KindPrivateKey}},
	{"Jetons GitHub", []Kind{KindGitHubToken, KindGitLabToken, KindSlackToken}},
	{"Clés API LLM", []Kind{KindLLMAPIKey}},
	{"Mots de passe dans des URL", []Kind{KindURLCredentials}},
	{"Chaînes de connexion de bases", []Kind{KindDBConnString}},
	{"Kubeconfig", []Kind{KindKubeconfig}},
	{"Valeurs de variables nommées", []Kind{KindSensitiveVar}},
	{"Clés pré-partagées IPsec", []Kind{KindIPsecPSK}},
}

// declaredKinds lists the 16 kinds of the task sheet, in declaration order
// (docs/plans/M0-redaction.md, section 5.1). It is written independently of
// Kinds() so that a test never trusts the value under test.
var declaredKinds = []Kind{
	KindAWSAccessKey, KindAWSSecretKey, KindAWSSessionToken, KindAzureSecret,
	KindScalewayKey, KindOVHCredential, KindPrivateKey, KindGitHubToken,
	KindGitLabToken, KindSlackToken, KindLLMAPIKey, KindURLCredentials,
	KindDBConnString, KindKubeconfig, KindSensitiveVar, KindIPsecPSK,
}

// invalidSpans is what rebuild returns when the matches do not form sorted,
// disjoint, non-empty spans inside the input: it never equals a real output.
const invalidSpans = "\x00invalid match spans\x00"

// checkSpans reports whether ms are sorted, disjoint (touching is allowed),
// non-empty and inside in: 0 <= Start < End <= len(in).
func checkSpans(in string, ms []Match) error {
	prev := 0
	for i, m := range ms {
		switch {
		case m.Start < 0 || m.End > len(in):
			return fmt.Errorf("match %d %+v is outside the input of %d bytes", i, m, len(in))
		case m.Start >= m.End:
			return fmt.Errorf("match %d %+v is empty or reversed", i, m)
		case m.Start < prev:
			return fmt.Errorf("match %d %+v starts before the end %d of the previous match", i, m, prev)
		}
		prev = m.End
	}
	return nil
}

// rebuild replaces every [Start, End) of in by Placeholder(Kind): the exact
// reconstruction rule of the matches (docs/plans/M0-redaction.md, P3).
func rebuild(in string, ms []Match) string {
	if checkSpans(in, ms) != nil {
		return invalidSpans
	}
	var b strings.Builder
	prev := 0
	for _, m := range ms {
		b.WriteString(in[prev:m.Start])
		b.WriteString(Placeholder(m.Kind))
		prev = m.End
	}
	b.WriteString(in[prev:])
	return b.String()
}

// kindsOf returns the kind of every match, in order.
func kindsOf(ms []Match) []Kind {
	out := make([]Kind, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Kind)
	}
	return out
}

// allFixtures returns the inputs of every table and idempotentCases, then the
// expected outputs.
func allFixtures() []string {
	var ins, outs []string
	for _, c := range positiveCases {
		ins = append(ins, c.in)
		outs = append(outs, c.want)
	}
	for _, c := range negativeCases {
		ins = append(ins, c.in)
	}
	for _, c := range narrowCases {
		ins = append(ins, c.in)
		outs = append(outs, c.want)
	}
	for _, c := range overlapCases {
		ins = append(ins, c.in)
		outs = append(outs, c.want)
	}
	ins = append(ins, idempotentCases...)
	return append(ins, outs...)
}

var snakeCase = regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)

// requireUniqueNames fails the test if a table has a duplicate or a name that
// is not lower snake_case.
func requireUniqueNames(t *testing.T, names []string) {
	t.Helper()
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if !snakeCase.MatchString(n) {
			t.Fatalf("case name %q is not lower snake_case", n)
		}
		if seen[n] {
			t.Fatalf("duplicate case name %q", n)
		}
		seen[n] = true
	}
}
