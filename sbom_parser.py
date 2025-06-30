import xml.etree.ElementTree as ET
import re
import json
import os


def get_namespace(element):
    """
    Extract the XML namespace from the root element.
    This is needed to properly access tags with namespace prefixes.
    """
    match = re.match(r'\{.*\}', element.tag)
    return match.group(0) if match else ''

def parse_sbom(file_path):
    """
    Parse the SBOM XML and extract all components with their name, version, and CPE.

    Args:
        file_path: Path to the SBOM XML file.

    Returns:
        A list of dictionaries with component info:
        [{"name": ..., "version": ..., "cpe": ...}, ...]
    """
    tree = ET.parse(file_path)
    root = tree.getroot()
    ns = get_namespace(root)

    components_elem = root.find(f"{ns}components")
    if components_elem is None:
        return []

    components = []
    for comp in components_elem.findall(f"{ns}component"):
        name = comp.findtext(f"{ns}name", default="").strip()
        version = comp.findtext(f"{ns}version", default="").strip()
        cpe = comp.findtext(f"{ns}cpe", default="").strip()

        if name and version:
            components.append({
                "name": name,
                "version": version,
                "cpe": cpe if cpe else None
            })

    return components

def get_project_info(file_path):
    """
    Extract the project name and version from the SBOM's <metadata><component> section.

    Args:
        file_path: Path to the SBOM XML file.

    Returns:
        Tuple of (project_name, project_version) or (None, None) if not found.
    """
    tree = ET.parse(file_path)
    root = tree.getroot()
    ns = get_namespace(root)

    component = root.find(f"{ns}metadata/{ns}component")
    if component is not None:
        name = component.findtext(f"{ns}name", default="").strip()
        version = component.findtext(f"{ns}version", default="").strip()
        return name or None, version or None
    return None, None

def get_contact_email(project_name: str):
    try:
        json_path = os.path.join(os.path.dirname(__file__), "project_contacts.json")
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Vergleiche Case-insensitive
        for key in data:
            if key.strip().lower() == project_name.strip().lower():
                return data[key]
    except Exception as e:
        print(f"[ERROR] Could not read project contacts: {e}")
    return None

def validate_sbom_structure(file_path: str) -> str | None:
    """
    Validates SBOM structure: checks for required fields and well-formed XML.

    Returns:
        str: Error message if invalid, None if valid.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        ns = {'bom': 'http://cyclonedx.org/schema/bom/1.4'}

        name = root.find(".//bom:metadata/bom:component/bom:name", ns)
        version = root.find(".//bom:metadata/bom:component/bom:version", ns)
        components = root.findall(".//bom:components/bom:component", ns)

        if name is None or name.text is None or not name.text.strip():
            return "Missing project name in SBOM metadata."
        if version is None or version.text is None or not version.text.strip():
            return "Missing project version in SBOM metadata."
        if not components:
            return "No components found in SBOM file."

    except ET.ParseError as e:
        return f"Invalid XML format: {e}"

    return None

def load_sbom_file_paths_from_json(json_filename="project_sbom_folders.json") -> list[str]:
    """
    Loads a JSON file located in the same folder as the script that imports this function.
    """
    base_path = os.path.dirname(os.path.abspath(__file__))  # directory of sbom_parser.py
    json_path = os.path.join(base_path, json_filename)

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load SBOM paths from JSON: {e}")
        return []
