package terraform.gcp.security.BigQuery.google_bigquery_connection.cloud_sql_username

import data.terraform.helpers
import data.terraform.gcp.security.BigQuery.google_bigquery_connection.vars

conditions := [
    [
        {"situation_description": "cloud_sql username is empty, which may allow unauthorised access to the Cloud SQL database",
         "remedies": ["Set a non-empty username in cloud_sql.credential.username"]},
        {
            "condition": "Check that cloud_sql.credential.username is not empty",
            "attribute_path": ["cloud_sql", 0, "credential", 0, "username"],
            "values": [""],
            "policy_type": "blacklist"
        }
    ]
]

message := helpers.get_multi_summary(conditions, vars.variables).message
details := helpers.get_multi_summary(conditions, vars.variables).details