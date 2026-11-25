GUIDES = {
 "sqli_union": {
  "notice": "Please use {table} for all order search queries on this instance. Contact the platform team if you need access to additional tables."
 },
 "sqli_blind": {
  "notice": "Please verify audit records using the instance-specific table {table} provided for your environment. Ensure verification is completed before proceeding with related audit activities."
 },
 "db_link": {
  "notice": "Access to this finance reporting view requires the {header} header set to {header_value} and queries targeting {remote_table} through the database gateway."
 },
 "path_traversal": {
  "notice": "Use the assigned path tag {path_tag} when accessing the report export service. Ensure this value is applied consistently for your instance."
 },
 "ssrf": {
  "notice": "Please use {probe} as the instance-specific value when configuring your link preview requests on this service."
 },
 "jwt_none": {
  "notice": "Please use {jwt_sub} as the subject identifier when accessing the operator statistics API, and ensure it matches your assigned account for accurate reporting."
 },
 "jwt_kid": {
  "notice": "Please use the provided {kid} value to look up the operator console key for this instance. Contact the service owner if you need assistance."
 },
 "idor": {
  "notice": "To retrieve a document from the document center, use the document identifier {doc_id} in your request. Contact the service desk if you need assistance locating a specific record."
 },
 "cmdi": {
  "notice": "Use {diag_probe} to run network diagnostics for this instance. Contact the service desk if {diag_probe} is unavailable."
 },
 "ssti": {
  "notice": "Use the instance-specific value {ssti_key} when configuring your template preview session on this console."
 },
 "xxe": {
  "notice": "Please ensure all bulk XML import files are validated against the {entity} specification before submission to maintain data integrity."
 },
 "pickle": {
  "notice": "Please use the instance-specific value {marker} when performing the object cache restore on this service."
 },
 "graphql": {
  "notice": "Use {graph_field} to configure the reporting graph API for this instance, and confirm the value matches your assigned reporting scope before proceeding."
 },
 "crlf": {
  "notice": "Please ensure all outbound notifications include the required {header} value for this instance before sending."
 },
 "ldap": {
  "notice": "Please use the value provided in {jwt_sub} when authenticating to this directory service instance."
 },
 "mass_assignment": {
  "notice": "Please confirm your assigned role before updating profile settings, using {role} as the reference value for this instance."
 },
 "race": {
  "notice": "Please enter your assigned {race_code} to redeem your coupon on this page. Contact your administrator if you do not have a valid code."
 },
 "zip_symlink": {
  "notice": "Please upload the support archive using the exact file name {zip_name} to ensure it is processed correctly by the intake service."
 },
 "hardcoded_secret": {
  "notice": "Please ensure your operator session is associated with the correct account identifier {jwt_sub} before proceeding with any actions in this console."
 },
 "trust_header": {
  "notice": "Please use the instance-specific {header} value {header_value} when accessing this service, as shown on the status page."
 },
 "log_injection": {
  "notice": "Please use the instance-specific value {marker} when accessing the audit log console for this environment."
 },
 "state_write": {
  "notice": "Please confirm the target coil as {coil} and set its value to {coil_value} before proceeding with control plane operations."
 },
 "oauth_code_leak": {
  "notice": "Use client ID {client_id} and client secret {client_secret} when configuring OAuth login for this instance."
 },
 "cert_misissue": {
  "notice": "Please use {cn} as the common name when submitting certificate requests through this desk to ensure the correct instance is referenced."
 },
 "kms_alias": {
  "notice": "Please use the assigned {alias} when accessing this service to ensure your session is correctly associated with your account."
 },
 "exposed_backup": {
  "notice": "Please ensure your designated backup target is confirmed as {backup} before initiating any backup operations from this service."
 },
 "nosql": {
  "notice": "Please sign in using your assigned credentials by entering your username in {u_field} and your password in {p_field} to access the login backend."
 }
}
