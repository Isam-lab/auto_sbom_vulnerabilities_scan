from sbom_parser import (
    parse_sbom,
    get_project_info,
    get_contact_email,
    validate_sbom_structure,
    load_sbom_file_paths_from_json
)
from nvd_api import query_cves_by_cpe, fuzzy_search_cpe
from redmine_api import (
    search_cve_in_redmine,
    create_redmine_issue,
    update_issue_versions,
    get_versions_for_project,
    get_redmine_projects
)
from utils import write_report_entry, get_report_file_path, REDMINE_URL
from smtp import send_final_report_email

from datetime import datetime
import os


def resolve_redmine_ids(project_name_from_sbom, project_version_from_sbom):
    redmine_projects = get_redmine_projects()
    if not redmine_projects:
        return None, None, "[ERROR] Could not retrieve Redmine projects."

    matching_project = next(
        (p for p in redmine_projects if p["name"].strip().lower() == project_name_from_sbom.strip().lower()),
        None
    )
    if not matching_project:
        return None, None, f"[ERROR] No matching project in Redmine for SBOM name: '{project_name_from_sbom}'"

    project_id = matching_project["id"]
    redmine_versions = get_versions_for_project(project_id)
    if not redmine_versions:
        return None, None, "[ERROR] No Redmine versions found."

    affected_version_id = next((v["id"] for v in redmine_versions if v["name"] == project_version_from_sbom), None)
    if not affected_version_id:
        return None, None, f"[ERROR] No version match in Redmine for: {project_version_from_sbom}"

    return affected_version_id, project_id, None


def handle_component(component, affected_version_id, project_id, report_file, html_issues, cpe_conflicts, processed_cve_versions, project_version_from_sbom):
    cves = []
    selected_cpe = None
    unchanged_cves = []
    updated_cves = []
    created_cves = []

    if component["cpe"]:
        selected_cpe = component["cpe"]
        cves = query_cves_by_cpe(selected_cpe)
    else:
        matches = fuzzy_search_cpe(component["name"], component["version"])
        if matches:
            if len(matches) > 1:
                cpe_conflicts.append(f"{component['name']} {component['version']}")
                content = f"\n[Component] {component['name']} {component['version']}\n"
                content += "Multiple CPEs found:\n" + "\n".join(f"- {cpe}" for cpe in matches)
                write_report_entry(content, report_file)
                return
            selected_cpe = matches[0]
            cves = query_cves_by_cpe(selected_cpe)

    if not selected_cpe:
        write_report_entry(
            f"\n[Component] {component['name']} {component['version']}\nNo valid CPE found.",
            report_file
        )
        return

    if not cves:
        write_report_entry(
            f"\n[Component] {component['name']} {component['version']}\nCPE: {selected_cpe}\nNo CVEs found.",
            report_file
        )
        return

    write_report_entry(
        f"\n[Component] {component['name']} {component['version']}\nCPE: {selected_cpe}",
        report_file
    )

    for cve in cves:
        cve_id = cve["id"]
        key = f"{cve_id}::{affected_version_id}"
        if key in processed_cve_versions:
            continue

        processed_cve_versions.add(key)

        subject = f"{component['name']} {cve_id}"
        description = cve["description"]
        existing = search_cve_in_redmine(cve_id)
        if existing:
            issue_id = existing[0]["id"]
            updated = update_issue_versions(issue_id, affected_version_id, existing[0], report_file, project_version_from_sbom)
            if updated:
                updated_cves.append(cve_id)
                html_issues.append(
                    f'<p>Updated issue <a href="{REDMINE_URL}/issues/{issue_id}">#{issue_id}</a></p>'
                )
            else:
                unchanged_cves.append(cve_id)
        else:
            create_redmine_issue(subject, description, affected_version_id, project_id)
            html_issues.append(
                f'<p>Created new issue <a href="{REDMINE_URL}/issues?subject=~{cve_id}">{cve_id}</a></p>'
            )
            write_report_entry(f"Created new issue for {cve_id}", report_file)
            created_cves.append(cve_id)

    if unchanged_cves and not (updated_cves or created_cves):
        write_report_entry("No updates/changes were needed", report_file)


def main():
    sbom_files = load_sbom_file_paths_from_json()
    if not sbom_files:
        print("[ERROR] No SBOM files found in project_sbom_folders.json.")
        return

    for sbom_file in sbom_files:
        validation_error = validate_sbom_structure(sbom_file)
        if validation_error:
            project_name = "UnknownProject"
            project_version = "UnknownVersion"
            report_file = get_report_file_path(project_name, project_version)
            if os.path.exists(report_file):
                os.remove(report_file)
            write_report_entry(
                f"[ERROR] SBOM validation failed for {sbom_file}:\n{validation_error}",
                report_file
            )
            recipient_list = get_contact_email(project_name) or ["isam.Al-Shehabi@iq-image.com"]
            for recipient_email in recipient_list:
                send_final_report_email(
                    project_name=project_name,
                    version=project_version,
                    report_file_path=report_file,
                    recipient_email=recipient_email,
                    html_issues=[],
                    cpe_conflicts=[],
                    malformed_error=validation_error,
                    redmine_error=None
                )
            continue

        project_name, project_version = get_project_info(sbom_file)
        if not project_name or not project_version:
            report_file = get_report_file_path("UnknownProject", "UnknownVersion")
            if os.path.exists(report_file):
                os.remove(report_file)
            write_report_entry(
                f"[ERROR] Missing project name or version in SBOM: {sbom_file}",
                report_file
            )
            recipient_list = get_contact_email("UnknownProject") or ["isam.Al-Shehabi@iq-image.com"]
            for recipient_email in recipient_list:
                send_final_report_email(
                    project_name="UnknownProject",
                    version="UnknownVersion",
                    report_file_path=report_file,
                    recipient_email=recipient_email,
                    html_issues=[],
                    cpe_conflicts=[],
                    malformed_error="Missing project name or version in SBOM",
                    redmine_error=None
                )
            continue

        report_file = get_report_file_path(project_name, project_version)
        if os.path.exists(report_file):
            os.remove(report_file)

        header = f"SBOM Scan Report – {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        header += "=" * 40 + f"\nProject: {project_name} (Version: {project_version})\n"
        write_report_entry(header, report_file)

        affected_version_id, project_id, error = resolve_redmine_ids(project_name, project_version)
        if error:
            write_report_entry(error, report_file)
            recipient_list = get_contact_email(project_name) or ["isam.Al-Shehabi@iq-image.com"]
            for recipient_email in recipient_list:
                send_final_report_email(
                    project_name=project_name,
                    version=project_version,
                    report_file_path=report_file,
                    recipient_email=recipient_email,
                    html_issues=[],
                    cpe_conflicts=[],
                    malformed_error=None,
                    redmine_error=error
                )
            continue

        components = parse_sbom(sbom_file)
        html_issues = []
        cpe_conflicts = []
        processed_cve_versions = set()

        for component in components:
            handle_component(
                component, affected_version_id, project_id,
                report_file, html_issues,
                cpe_conflicts, processed_cve_versions,
                project_version
            )

        recipient_list = get_contact_email(project_name) or ["isam.Al-Shehabi@iq-image.com"]
        for recipient_email in recipient_list:
            send_final_report_email(
                project_name=project_name,
                version=project_version,
                report_file_path=report_file,
                recipient_email=recipient_email,
                html_issues=html_issues,
                cpe_conflicts=cpe_conflicts,
                malformed_error=None,
                redmine_error=None
            )


if __name__ == "__main__":
    main()
