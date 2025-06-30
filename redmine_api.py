
import requests
from utils import (
    log_error,
    REDMINE_URL,
    REDMINE_TRACKER_ID,
    REDMINE_STATUS_ID,
    AFFECTED_VERSION_FIELD_ID,
    write_report_entry,
    decode_base64_env,

)

# Redmine API key (Base64-encoded) is loaded from .env
REDMINE_API_KEY = decode_base64_env("REDMINE_API_KEY")
HEADERS = {
    "X-Redmine-API-Key": REDMINE_API_KEY,
    "Content-Type": "application/json"
}

def search_cve_in_redmine(cve_id):
    url = f"{REDMINE_URL}/issues.json"
    params = {"subject": f"~{cve_id}"}
    response = requests.get(url, headers=HEADERS, params=params)
    if response.status_code < 200 or response.status_code > 299:
        log_error(f"Redmine search failed for {cve_id}: {response.status_code}")
        return []
    return response.json().get("issues", [])

def get_affected_versions_from_issue(issue_data):
    custom_fields = issue_data.get("custom_fields", [])
    affected_field = next((f for f in custom_fields if f["id"] == AFFECTED_VERSION_FIELD_ID), None)
    if not affected_field:
        log_error(f"Issue #{issue_data.get('id', 'UNKNOWN')} has no 'affected_version' field")
        return []
    value = affected_field.get("value", [])
    return [value] if isinstance(value, str) else value

def create_redmine_issue(subject, description, version, project_id):
    url = f"{REDMINE_URL}/issues.json"
    payload = {
        "issue": {
            "project_id": project_id,
            "tracker_id": REDMINE_TRACKER_ID,
            "status_id": REDMINE_STATUS_ID,
            "subject": subject,
            "description": description,
            "custom_fields": [
                {"id": AFFECTED_VERSION_FIELD_ID, "value": [str(version)]},
                {"id": 38, "value": "SOUPs"}  # if field 38 is still needed
            ]
        }
    }
    response = requests.post(url, headers=HEADERS, json=payload)
    if response.status_code < 200 or response.status_code > 299:
        log_error(f"Failed to create issue for {subject}: {response.status_code} - {response.text}")

def update_issue_versions(issue_id, new_version_id, issue_data, report_file_path, version_name_from_sbom):
    current_versions = []

    for cf in issue_data.get("custom_fields", []):
        if cf["id"] == AFFECTED_VERSION_FIELD_ID:
            value = cf["value"]
            if isinstance(value, list):
                current_versions.extend([str(v) for v in value])
            elif isinstance(value, str):
                current_versions.append(value)

    if str(new_version_id) in current_versions:
        return False

    updated_versions = list(set(current_versions + [str(new_version_id)]))

    payload = {
        "issue": {
            "custom_fields": [{
                "id": AFFECTED_VERSION_FIELD_ID,
                "value": updated_versions
            }]
        }
    }

    response = requests.put(
        f"{REDMINE_URL}/issues/{issue_id}.json",
        headers=HEADERS,
        json=payload
    )

    if 200 <= response.status_code < 300:
        write_report_entry(
            f"→ Added affected version '{version_name_from_sbom}' to existing issue #{issue_id}",
            report_file_path
        )
        return True
    else:
        log_error(f"Failed to update issue #{issue_id}: {response.status_code} – {response.text}")
        return False

def get_versions_for_project(project_identifier):
    url = f"{REDMINE_URL}/projects/{project_identifier}/versions.json"
    response = requests.get(url, headers=HEADERS)
    if response.status_code < 200 or response.status_code > 299:
        log_error(f"Failed to fetch versions for project '{project_identifier}': {response.status_code}")
        return []
    versions = response.json().get("versions", [])
    return [
        {"id": v["id"], "name": v["name"]}
        for v in versions if "id" in v and "name" in v
    ]

def get_redmine_projects():
    url = f"{REDMINE_URL}/projects.json?limit=100"
    response = requests.get(url, headers=HEADERS)
    if response.status_code < 200 or response.status_code > 299:
        log_error(f"Failed to fetch Redmine projects: {response.status_code}")
        return []
    return response.json().get("projects", [])
