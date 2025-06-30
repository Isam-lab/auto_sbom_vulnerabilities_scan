import os
import base64
from datetime import datetime
from dotenv import load_dotenv
from typing import Any, Optional
import requests
import json

# load .env (Base64-encoded)
load_dotenv()

# === Base64 decoding for env variables ===
def decode_base64_env(var_name: str) -> str | None:
    encoded = os.getenv(var_name)
    if encoded:
        try:
            return base64.b64decode(encoded).decode("utf-8")
        except Exception:
            return None
    return None

# === Redmine configuration from Base64 ===
NVD_API_KEY = decode_base64_env("NVD_API_KEY")
REDMINE_API_KEY = decode_base64_env("REDMINE_API_KEY")
REDMINE_URL = decode_base64_env("REDMINE_URL")
REDMINE_TRACKER_ID = int(decode_base64_env("REDMINE_TRACKER_ID") or "1")
REDMINE_STATUS_ID = int(decode_base64_env("REDMINE_STATUS_ID") or "1")
AFFECTED_VERSION_FIELD_ID = int(decode_base64_env("AFFECTED_VERSION_FIELD_ID") or "1")
SBOM_FOLDER_PATH = decode_base64_env("SBOM_FOLDER_PATH")

# === Redmine HTTP-Header ===
HEADERS = {
    "X-Redmine-API-Key": REDMINE_API_KEY,
    "Content-Type": "application/json"
}

# === Error logging ===
def log_error(message: Any) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("error.log", "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {str(message)}\n")

# === Path for report files ===
def get_report_file_path(project_name: str, project_version: str) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d - %H-%M-%S")
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    report_dir = os.path.join(desktop_path, "Report_folder")
    os.makedirs(report_dir, exist_ok=True)
    filename = f"{project_name} - {project_version} - {timestamp}.txt"
    return os.path.join(report_dir, filename)

# === Append report entry ===
def write_report_entry(content: str, report_file_path: str) -> None:
    try:
        with open(report_file_path, "a", encoding="utf-8") as f:
            f.write(content + "\n")
    except Exception as e:
        print(f"[ERROR] Could not write to report: {e}")

# === Find responsible contacts for project ===
def get_recipients_for_project(project_name: str, contacts_file: str = "project_contacts.json") -> list[str]:
    try:
        with open(contacts_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get(project_name, [])
    except Exception as e:
        log_error(f"Error reading project contacts: {e}")
        return []

# === Determine custom field ID by name ===
def get_custom_field_id_by_name(field_name: str) -> Optional[int]:
    url = f"{REDMINE_URL}/custom_fields.json"
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code < 200 or response.status_code > 299:
            log_error(f"Failed to fetch custom fields: {response.status_code}")
            return None
        fields = response.json().get("custom_fields", [])
        for field in fields:
            if field.get("name") == field_name:
                return field.get("id")
    except Exception as e:
        log_error(f"Error during custom field lookup: {str(e)}")
    return None

# === Get project ID by identifier ===
def get_project_id_by_identifier(identifier: str) -> Optional[int]:
    url = f"{REDMINE_URL}/projects/{identifier}.json"
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code < 200 or response.status_code > 299:
            log_error(f"Failed to get project ID for identifier '{identifier}': {response.status_code}")
            return None
        return response.json().get("project", {}).get("id")
    except Exception as e:
        log_error(f"Error while fetching project ID for '{identifier}': {str(e)}")
        return None

# === Retrieve versions for a project ===
def get_versions_for_project(project_identifier: str) -> list:
    url = f"{REDMINE_URL}/projects/{project_identifier}/versions.json"
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code < 200 or response.status_code > 299:
            log_error(f"Failed to fetch versions for project '{project_identifier}': {response.status_code}")
            return []
        versions = response.json().get("versions", [])
        return [
            {"id": v["id"], "name": v["name"]}
            for v in versions if "id" in v and "name" in v
        ]
    except Exception as e:
        log_error(f"Error while fetching versions for project '{project_identifier}': {str(e)}")
        return []

# === Search for CVEs in Redmine ===
def search_cve_in_redmine(cve_id: str) -> list:
    url = f"{REDMINE_URL}/issues.json"
    params = {"subject": f"~{cve_id}"}
    try:
        response = requests.get(url, headers=HEADERS, params=params)
        if response.status_code < 200 or response.status_code > 299:
            log_error(f"Redmine search failed for {cve_id}: {response.status_code}")
            return []
        return response.json().get("issues", [])
    except Exception as e:
        log_error(f"Error while searching for CVE {cve_id}: {str(e)}")
        return []
