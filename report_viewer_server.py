#!/usr/bin/env python3
"""
Vulnerability Report Viewer - Python Web Application
A Flask-based web application for viewing and analyzing kernel driver vulnerability reports.
"""

import os
import json
import hashlib
import io
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from flask import Flask, render_template, request, jsonify, send_from_directory

try:
    import pefile
except ImportError:
    pefile = None

try:
    from werkzeug.utils import secure_filename
except ImportError:
    secure_filename = None

try:
    from pe_analyzer import check_driver_imports, check_driver_signature
except Exception as exc:
    check_driver_imports = None
    check_driver_signature = None
    PE_ANALYZER_IMPORT_ERROR = str(exc)
else:
    PE_ANALYZER_IMPORT_ERROR = None

app = Flask(__name__)
app.config['SECRET_KEY'] = 'faliexplorer-report-viewer'
app.config['UPLOAD_FOLDER'] = 'temp_uploads'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global storage for loaded reports
loaded_reports = {}
uploaded_driver_paths = {}
uploaded_blocklist_paths = []
driver_search_index = None
blocklist_cache = {}

DRIVER_EXTENSIONS = {'.sys', '.dll', '.exe'}
BLOCKLIST_EXTENSIONS = {'.xml'}
MICROSOFT_BLOCKLIST_ENV = 'FALIEXPLORER_BLOCKLIST'
MICROSOFT_BLOCKLIST_URL = 'https://aka.ms/VulnerableDriverBlockList'
MICROSOFT_BLOCKLIST_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
MICROSOFT_BLOCKLIST_RETRY_SECONDS = 60 * 60
MICROSOFT_BLOCKLIST_DOWNLOAD_TIMEOUT_SECONDS = 10
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100

microsoft_blocklist_resolution = {
    'status': 'Not resolved',
    'source': MICROSOFT_BLOCKLIST_URL,
    'cached': False,
    'paths': [],
    'error': '',
    'attempted_at': 0,
}

VULNERABILITY_CLASS_PATTERNS = (
    ('Memory mapping', ('map physical memory', 'mmmapiospace', 'zwmapviewofsection')),
    ('Arbitrary memory access', ('read/write controllable', 'arbitrary read', 'arbitrary write', 'controllable address')),
    ('Port I/O', ('arbitrary in', 'arbitrary out', 'i/o port', 'io port')),
    ('MSR access', ('rdmsr', 'wrmsr', 'msr register')),
    ('Null dereference', ('null pointer', 'null dereference')),
    ('Process control', ('terminate process', 'lookup process', 'process')),
    ('Object access', ('open object', 'object')),
    ('Memory safety', ('double free', 'overflow', 'use after free')),
)

HVCI_RISK_IMPORTS = [
    'ExAllocatePool',
    'ExAllocatePoolWithTag',
    'ExAllocatePoolWithQuota',
    'MmAllocateContiguousMemory',
    'MmAllocateContiguousMemorySpecifyCache',
    'MmMapLockedPages',
    'MmMapLockedPagesSpecifyCache',
    'MmProtectMdlSystemAddress',
    'ZwAllocateVirtualMemory',
    'ZwProtectVirtualMemory',
]


def _safe_basename(filename):
    """Return a browser-upload-safe basename while tolerating webkitdirectory paths."""
    normalized = (filename or '').replace('\\', '/')
    basename = PurePosixPath(normalized).name
    if secure_filename:
        safe = secure_filename(basename)
        return safe or basename or 'uploaded_file'
    return basename or 'uploaded_file'


def _report_key(filename):
    """Use a route-safe, human-readable key for report tabs and API lookups."""
    return _safe_basename(filename)


def _classify_vulnerability(vuln):
    text = ' '.join([
        str(vuln.get('vulnerability_type', '')),
        str(vuln.get('access_type', '')),
        str(vuln.get('description', '')),
    ]).lower()

    for class_name, needles in VULNERABILITY_CLASS_PATTERNS:
        if any(needle in text for needle in needles):
            return class_name
    return 'Other'


def _extract_rip_from_state(state_value):
    match = re.search(r'@\s*(0x[0-9a-fA-F]+)', str(state_value or ''))
    return match.group(1) if match else ''


def _normalize_vulnerability(vuln):
    normalized = {
        'timestamp': vuln.get('timestamp') or datetime.now().isoformat(),
        'vulnerability_type': vuln.get('vulnerability_type') or vuln.get('title') or 'Unknown',
        'access_type': vuln.get('access_type') or vuln.get('description') or '',
        'ioctl': vuln.get('ioctl') or vuln.get('eval', {}).get('IoControlCode') or '',
        'rip': vuln.get('rip') or _extract_rip_from_state(vuln.get('state')),
        'additional_info': vuln.get('additional_info') or {},
        'address_info': vuln.get('address_info') or {},
    }

    if not normalized['address_info'] and isinstance(vuln.get('others'), dict):
        normalized['address_info'] = vuln.get('others')

    if not normalized['additional_info']:
        additional_info = {}
        for key in ('parameters', 'eval'):
            value = vuln.get(key)
            if value:
                additional_info[key] = value
        normalized['additional_info'] = additional_info

    normalized['vulnerability_class'] = vuln.get('vulnerability_class') or _classify_vulnerability(normalized)
    return normalized


def _normalize_report_data(data, filename):
    """Accept both viewer reports and raw FALIExplorer .sys.json files."""
    if not isinstance(data, dict):
        data = {}

    basic = data.get('basic') if isinstance(data.get('basic'), dict) else {}
    basic_path = basic.get('path') or data.get('driver_path') or data.get('path')
    driver_name = (
        data.get('driver_name')
        or (Path(str(basic_path)).stem if basic_path else None)
        or Path(_safe_basename(filename)).stem.replace('_report', '')
    )

    raw_vulnerabilities = data.get('vulnerabilities')
    if raw_vulnerabilities is None:
        raw_vulnerabilities = data.get('vuln', [])

    vulnerabilities = [
        _normalize_vulnerability(vuln)
        for vuln in raw_vulnerabilities
        if isinstance(vuln, dict)
    ]

    normalized = dict(data)
    normalized['driver_name'] = driver_name
    normalized['generated_at'] = data.get('generated_at') or datetime.now().isoformat()
    normalized['total_vulnerabilities'] = len(vulnerabilities)
    normalized['vulnerabilities'] = vulnerabilities
    return normalized


def _register_driver_path(driver_path):
    path = Path(driver_path)
    if not path.suffix.lower() in DRIVER_EXTENSIONS:
        return

    uploaded_driver_paths[path.name.lower()] = str(path)
    uploaded_driver_paths[path.stem.lower()] = str(path)


def _register_uploaded_policy(policy_path):
    path = str(policy_path)
    if path not in uploaded_blocklist_paths:
        uploaded_blocklist_paths.append(path)
    blocklist_cache.clear()


def _save_uploaded_binary(file_storage):
    basename = _safe_basename(file_storage.filename)
    digest = hashlib.sha256((file_storage.filename or basename).encode('utf-8')).hexdigest()[:12]
    upload_dir = Path(app.config['UPLOAD_FOLDER']) / 'drivers'
    upload_dir.mkdir(parents=True, exist_ok=True)
    destination = upload_dir / f'{digest}_{basename}'
    file_storage.save(destination)
    _register_driver_path(destination)
    return str(destination)


def _save_uploaded_blocklist(file_storage):
    basename = _safe_basename(file_storage.filename)
    digest = hashlib.sha256((file_storage.filename or basename).encode('utf-8')).hexdigest()[:12]
    upload_dir = Path(app.config['UPLOAD_FOLDER']) / 'blocklists'
    upload_dir.mkdir(parents=True, exist_ok=True)
    destination = upload_dir / f'{digest}_{basename}'
    file_storage.save(destination)
    _register_uploaded_policy(destination)
    return str(destination)


def _candidate_driver_names(report_name, report_data):
    names = []
    for value in (
        report_data.get('driver_name'),
        Path(_safe_basename(report_name)).stem.replace('_report', ''),
    ):
        if value:
            value = str(value)
            names.extend([value, Path(value).stem])

    basic = report_data.get('basic') if isinstance(report_data.get('basic'), dict) else {}
    for key in ('driver_path', 'path', 'file_path', 'binary_path'):
        value = report_data.get(key) or basic.get(key)
        if value:
            path = Path(str(value))
            names.extend([path.name, path.stem, str(value)])

    seen = set()
    for name in names:
        key = str(name).lower()
        if key and key not in seen:
            seen.add(key)
            yield str(name)


def _build_driver_search_index():
    global driver_search_index
    if driver_search_index is not None:
        return driver_search_index

    index = {}
    root = Path.cwd()
    skip_dirs = {'.git', '__pycache__'}
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in skip_dirs]
        for filename in files:
            path = Path(current_root) / filename
            if path.suffix.lower() not in DRIVER_EXTENSIONS:
                continue
            index.setdefault(path.name.lower(), str(path))
            index.setdefault(path.stem.lower(), str(path))

    index.update(uploaded_driver_paths)
    driver_search_index = index
    return index


def _resolve_driver_path(report_name, report_data):
    basic = report_data.get('basic') if isinstance(report_data.get('basic'), dict) else {}
    explicit_paths = [
        report_data.get('driver_path'),
        report_data.get('path'),
        report_data.get('file_path'),
        report_data.get('binary_path'),
        basic.get('path'),
    ]

    for value in explicit_paths:
        if not value:
            continue
        path = Path(str(value))
        candidates = [path]
        if not path.is_absolute():
            candidates.append(Path.cwd() / path)
        for candidate in candidates:
            if candidate.exists() and candidate.suffix.lower() in DRIVER_EXTENSIONS:
                return str(candidate)

    index = _build_driver_search_index()
    for name in _candidate_driver_names(report_name, report_data):
        for key in (name.lower(), Path(name).name.lower(), Path(name).stem.lower()):
            if key in uploaded_driver_paths:
                return uploaded_driver_paths[key]
            if key in index:
                return index[key]

    return None


def _file_hashes(path):
    hashes = {
        'sha256': hashlib.sha256(),
        'sha1': hashlib.sha1(),
        'md5': hashlib.md5(),
    }
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            for hasher in hashes.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest().lower() for name, hasher in hashes.items()}


def _driver_imports(path):
    imports = {
        'available': False,
        'total_imports': 0,
        'library_count': 0,
        'libraries': [],
        'by_library': [],
        'flat': [],
        'error': '',
    }

    if pefile is None:
        imports['error'] = 'pefile is not installed.'
        return imports

    try:
        pe = pefile.PE(path, fast_load=False)
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            pe.parse_data_directories([
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
            ])

        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
            library = entry.dll.decode(errors='replace') if isinstance(entry.dll, bytes) else str(entry.dll)
            functions = []
            for imported_symbol in entry.imports:
                if imported_symbol.name:
                    function_name = imported_symbol.name.decode(errors='replace')
                elif imported_symbol.ordinal is not None:
                    function_name = f'ordinal_{imported_symbol.ordinal}'
                else:
                    function_name = 'unnamed_import'
                functions.append(function_name)
                imports['flat'].append(f'{library}!{function_name}')

            imports['by_library'].append({
                'library': library,
                'functions': sorted(set(functions), key=str.lower),
                'count': len(functions),
            })
        pe.close()
    except Exception as exc:
        imports['error'] = str(exc)
        return imports

    imports['available'] = True
    imports['by_library'].sort(key=lambda item: item['library'].lower())
    imports['libraries'] = [item['library'] for item in imports['by_library']]
    imports['library_count'] = len(imports['libraries'])
    imports['flat'] = sorted(set(imports['flat']), key=str.lower)
    imports['total_imports'] = len(imports['flat'])
    return imports


def _pe_version_info(path):
    info = {}
    if pefile is None:
        return info

    try:
        pe = pefile.PE(path, fast_load=False)
        if hasattr(pe, 'FileInfo'):
            for file_info in pe.FileInfo:
                entries = file_info if isinstance(file_info, list) else [file_info]
                for entry in entries:
                    if getattr(entry, 'Key', b'') == b'StringFileInfo':
                        for string_table in entry.StringTable:
                            for key, value in string_table.entries.items():
                                decoded_key = key.decode(errors='ignore') if isinstance(key, bytes) else str(key)
                                decoded_value = value.decode(errors='ignore') if isinstance(value, bytes) else str(value)
                                info[decoded_key] = decoded_value
        if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
            fixed = pe.VS_FIXEDFILEINFO[0]
            info['FixedFileVersion'] = '.'.join(str(part) for part in (
                fixed.FileVersionMS >> 16,
                fixed.FileVersionMS & 0xffff,
                fixed.FileVersionLS >> 16,
                fixed.FileVersionLS & 0xffff,
            ))
        pe.close()
    except Exception:
        return info

    return info


def _classify_signature(sig_info):
    if PE_ANALYZER_IMPORT_ERROR:
        return 'Unavailable'
    if not sig_info.get('is_signed'):
        status = sig_info.get('status', '')
        if 'No Embedded Signature' in status:
            return 'No embedded signature (may be catalog-signed)'
        return 'Unsigned or unknown'
    if sig_info.get('is_whql'):
        return 'WHQL / Microsoft hardware-signed'
    if sig_info.get('is_ev'):
        return 'Extended Validation (EV)'
    return 'Embedded Authenticode'


def _signature_metadata(driver_path):
    if check_driver_signature is None:
        return {
            'available': False,
            'signature_type': 'Unavailable',
            'status': PE_ANALYZER_IMPORT_ERROR or 'pe_analyzer is unavailable',
        }

    sig_info = check_driver_signature(driver_path)
    sig_info['available'] = True
    sig_info['signature_type'] = _classify_signature(sig_info)
    return sig_info


def _blocklist_cache_dir():
    cache_dir = Path(app.config['UPLOAD_FOLDER']) / 'blocklists' / 'microsoft'
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _cached_microsoft_blocklist_paths():
    cache_dir = _blocklist_cache_dir()
    return sorted(path for path in cache_dir.glob('*.xml') if path.is_file())


def _cache_is_fresh(paths):
    if not paths:
        return False
    newest_mtime = max(path.stat().st_mtime for path in paths)
    return time.time() - newest_mtime < MICROSOFT_BLOCKLIST_CACHE_TTL_SECONDS


def _write_downloaded_blocklist_xml(content, final_url):
    cache_dir = _blocklist_cache_dir()
    extracted_paths = []

    for old_xml in cache_dir.glob('*.xml'):
        try:
            old_xml.unlink()
        except OSError:
            pass

    if zipfile.is_zipfile(io.BytesIO(content)):
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            xml_entries = [
                entry for entry in archive.infolist()
                if not entry.is_dir() and Path(entry.filename).suffix.lower() == '.xml'
            ]
            preferred_entries = [
                entry for entry in xml_entries
                if 'driver' in Path(entry.filename).name.lower() or 'sipolicy' in Path(entry.filename).name.lower()
            ] or xml_entries

            for index, entry in enumerate(preferred_entries):
                filename = _safe_basename(entry.filename) or f'microsoft_blocklist_{index}.xml'
                target = cache_dir / filename
                target.write_bytes(archive.read(entry))
                extracted_paths.append(target)
    else:
        filename = _safe_basename(Path(urllib.parse.urlparse(final_url).path).name)
        if not filename.lower().endswith('.xml'):
            filename = 'MicrosoftRecommendedDriverBlockRules.xml'
        target = cache_dir / filename
        target.write_bytes(content)
        extracted_paths.append(target)

    return extracted_paths


def _resolve_microsoft_blocklist_at_runtime():
    """Download and cache Microsoft's recommended vulnerable driver blocklist XML."""
    global microsoft_blocklist_resolution

    cached_paths = _cached_microsoft_blocklist_paths()
    last_attempt = microsoft_blocklist_resolution.get('attempted_at') or 0
    recent_failure = (
        microsoft_blocklist_resolution.get('error')
        and time.time() - last_attempt < MICROSOFT_BLOCKLIST_RETRY_SECONDS
    )
    if recent_failure and not _cache_is_fresh(cached_paths):
        microsoft_blocklist_resolution['paths'] = [str(path) for path in cached_paths]
        microsoft_blocklist_resolution['cached'] = bool(cached_paths)
        return cached_paths

    if _cache_is_fresh(cached_paths):
        microsoft_blocklist_resolution = {
            'status': 'Using cached Microsoft blocklist XML',
            'source': MICROSOFT_BLOCKLIST_URL,
            'cached': True,
            'paths': [str(path) for path in cached_paths],
            'error': '',
            'attempted_at': last_attempt,
        }
        return cached_paths

    try:
        attempted_at = time.time()
        request = urllib.request.Request(
            MICROSOFT_BLOCKLIST_URL,
            headers={'User-Agent': 'FALIExplorer report viewer'},
        )
        with urllib.request.urlopen(request, timeout=MICROSOFT_BLOCKLIST_DOWNLOAD_TIMEOUT_SECONDS) as response:
            content = response.read()
            final_url = response.geturl()

        downloaded_paths = _write_downloaded_blocklist_xml(content, final_url)
        if downloaded_paths:
            microsoft_blocklist_resolution = {
                'status': 'Downloaded Microsoft blocklist XML',
                'source': final_url,
                'cached': False,
                'paths': [str(path) for path in downloaded_paths],
                'error': '',
                'attempted_at': attempted_at,
            }
            blocklist_cache.clear()
            return downloaded_paths

        raise ValueError('Downloaded package did not contain XML policies.')
    except (OSError, ValueError, urllib.error.URLError, zipfile.BadZipFile) as exc:
        microsoft_blocklist_resolution = {
            'status': 'Microsoft blocklist download failed; using stale cache' if cached_paths else 'Microsoft blocklist download failed',
            'source': MICROSOFT_BLOCKLIST_URL,
            'cached': bool(cached_paths),
            'paths': [str(path) for path in cached_paths],
            'error': str(exc),
            'attempted_at': time.time(),
        }
        return cached_paths


def _policy_candidate_paths():
    candidates = []

    env_value = os.environ.get(MICROSOFT_BLOCKLIST_ENV, '')
    for raw_path in env_value.split(os.pathsep):
        if raw_path:
            candidates.append(Path(raw_path))

    candidates.extend(Path(path) for path in uploaded_blocklist_paths)

    common_names = [
        'MicrosoftRecommendedDriverBlockRules.xml',
        'RecommendedDriverBlockRules.xml',
        'RecommendedDriverBlockList.xml',
        'VulnerableDriverBlockList.xml',
        'SiPolicy.xml',
        'SiPolicy_Enforced.xml',
    ]
    for directory in (Path.cwd(), Path.cwd() / 'reports', Path.cwd() / app.config['UPLOAD_FOLDER']):
        for name in common_names:
            candidates.append(directory / name)

    resolved_candidates = []
    seen = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except Exception:
            continue
        key = str(resolved).lower()
        if key not in seen and resolved.exists() and resolved.suffix.lower() in BLOCKLIST_EXTENSIONS:
            seen.add(key)
            resolved_candidates.append(resolved)

    if not resolved_candidates:
        for candidate in _resolve_microsoft_blocklist_at_runtime():
            try:
                resolved = candidate.resolve()
            except Exception:
                continue
            key = str(resolved).lower()
            if key not in seen and resolved.exists() and resolved.suffix.lower() in BLOCKLIST_EXTENSIONS:
                seen.add(key)
                resolved_candidates.append(resolved)

    for resolved in resolved_candidates:
        yield resolved


def _normalize_hash_value(value):
    cleaned = re.sub(r'[^0-9a-fA-F]', '', value or '').lower()
    if len(cleaned) in (32, 40, 64):
        return cleaned
    return ''


def _element_tag(element):
    return element.tag.rsplit('}', 1)[-1].lower()


def _element_attrs(element):
    return {
        key.rsplit('}', 1)[-1].lower(): value
        for key, value in element.attrib.items()
    }


def _blocklist_rule_from_attrs(policy_name, attrs, source):
    friendly_name = attrs.get('friendlyname') or attrs.get('name') or attrs.get('id') or 'Deny rule'
    friendly_name_hashes = [
        token.lower()
        for token in re.findall(r'(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})(?![0-9A-Fa-f])', friendly_name)
    ]
    return {
        'policy': policy_name,
        'friendly_name': friendly_name,
        'rule_source': source,
        'hash': _normalize_hash_value(attrs.get('hash', '')),
        'hash_kind': _classify_policy_hash_kind(friendly_name),
        'friendly_name_hashes': friendly_name_hashes,
        'file_name': attrs.get('filename', ''),
        'minimum_file_version': attrs.get('minimumfileversion', ''),
        'maximum_file_version': attrs.get('maximumfileversion', ''),
        'signer_id': attrs.get('signerid', ''),
        'signer_name': attrs.get('signername', ''),
    }


def _classify_policy_hash_kind(friendly_name):
    lowered = (friendly_name or '').lower()
    if 'page sha256' in lowered:
        return 'page_sha256'
    if 'page sha1' in lowered:
        return 'page_sha1'
    if 'sha256' in lowered:
        return 'policy_sha256'
    if 'sha1' in lowered:
        return 'policy_sha1'
    return 'policy_hash'


def _load_blocklist_rules(policy_path):
    policy_path = Path(policy_path)
    cache_key = str(policy_path.resolve())
    mtime = policy_path.stat().st_mtime
    cached = blocklist_cache.get(cache_key)
    if cached and cached.get('mtime') == mtime:
        return cached['rules']

    rules = []
    try:
        root = ET.parse(policy_path).getroot()
    except Exception:
        return []

    elements = list(root.iter())
    file_attributes = {}
    signers = {}

    for element in elements:
        tag = _element_tag(element)
        attrs = _element_attrs(element)
        element_id = attrs.get('id')
        if not element_id:
            continue

        if tag == 'fileattrib':
            file_attributes[element_id] = attrs
        elif tag == 'signer':
            signer_name = attrs.get('name') or attrs.get('friendlyname') or element_id
            for child in element:
                child_attrs = _element_attrs(child)
                if child_attrs.get('value'):
                    signer_name = f'{signer_name} ({child_attrs["value"]})'
                    break
            signers[element_id] = signer_name

    for element in elements:
        tag = _element_tag(element)
        attrs = _element_attrs(element)
        if tag == 'deny':
            rule = _blocklist_rule_from_attrs(policy_path.name, attrs, 'deny')
            if rule['hash'] or rule['file_name']:
                rules.append(rule)
            continue

        if tag != 'deniedsigner':
            continue

        signer_id = attrs.get('signerid', '')
        for child in element.iter():
            if _element_tag(child) != 'fileattribref':
                continue
            ref_attrs = _element_attrs(child)
            referenced_attrs = dict(file_attributes.get(ref_attrs.get('ruleid', ''), {}))
            if not referenced_attrs:
                continue
            referenced_attrs['signerid'] = signer_id
            referenced_attrs['signername'] = signers.get(signer_id, signer_id)
            rule = _blocklist_rule_from_attrs(policy_path.name, referenced_attrs, 'denied_signer_file_attribute')
            if rule['hash'] or rule['file_name']:
                rules.append(rule)

    blocklist_cache[cache_key] = {'mtime': mtime, 'rules': rules}
    return rules


def _match_blocklist(driver_path, hashes, version_info):
    policies = list(_policy_candidate_paths())
    if not policies:
        binary_policy = Path(os.environ.get('WINDIR', r'C:\Windows')) / 'System32' / 'CodeIntegrity' / 'driversipolicy.p7b'
        return {
            'status': 'Microsoft blocklist unavailable',
            'is_blocklisted': None,
            'matches': [],
            'policies_checked': [],
            'note': (
                'No Microsoft WDAC blocklist XML was available after runtime resolution. '
                f'The resolver tried {MICROSOFT_BLOCKLIST_URL}; set {MICROSOFT_BLOCKLIST_ENV} only if you need an offline override.'
            ),
            'installed_binary_policy_present': binary_policy.exists(),
            'runtime_resolution': microsoft_blocklist_resolution,
        }

    driver_names = {
        Path(driver_path).name.lower(),
        version_info.get('OriginalFilename', '').lower(),
        version_info.get('InternalName', '').lower(),
    }
    driver_names.discard('')

    matches = []
    for policy in policies:
        for rule in _load_blocklist_rules(policy):
            rule_hash = rule.get('hash')
            if rule_hash and rule_hash in hashes.values():
                matches.append({
                    **rule,
                    'match_type': 'policy_hash',
                    'matched_hash': rule_hash,
                    'matched_hash_source': rule.get('hash_kind', 'policy_hash'),
                })
                continue

            friendly_name_hashes = rule.get('friendly_name_hashes') or []
            matched_friendly_hash = next((value for value in friendly_name_hashes if value in hashes.values()), None)
            if matched_friendly_hash:
                matches.append({
                    **rule,
                    'match_type': 'friendly_name_file_hash',
                    'matched_hash': matched_friendly_hash,
                    'matched_hash_source': 'plain_file_hash_in_friendly_name',
                })
                continue

            rule_file = rule.get('file_name', '').lower()
            if rule_file and rule_file in driver_names:
                matches.append({**rule, 'match_type': 'file_name'})

    exact_matches = [
        match for match in matches
        if match.get('match_type') in {'policy_hash', 'friendly_name_file_hash'}
    ]
    possible_matches = [match for match in matches if match.get('match_type') == 'file_name']

    if exact_matches:
        match_sources = sorted({match.get('match_type') for match in exact_matches})
        status = 'Blocked by Microsoft vulnerable driver blocklist'
        if match_sources == ['friendly_name_file_hash']:
            status += ' (plain file hash in rule name)'
        is_blocklisted = True
    elif possible_matches:
        status = 'Possible blocklist match by file name'
        is_blocklisted = None
    else:
        status = 'No match in checked Microsoft blocklist XML'
        is_blocklisted = False

    return {
        'status': status,
        'is_blocklisted': is_blocklisted,
        'matches': matches,
        'policies_checked': [str(path) for path in policies],
        'note': (
            'The XML Hash attribute is a WDAC policy/page hash. Some Microsoft rules also embed the '
            'plain file hash in FriendlyName; those hashes are checked too. File-name matches remain '
            'possible matches because WDAC rules can also include signer and version conditions.'
        ),
        'runtime_resolution': microsoft_blocklist_resolution,
    }


def _match_blocklist_by_report_name(report_name, report_data):
    """Fallback when the driver binary is unavailable; filename matches are advisory only."""
    policies = list(_policy_candidate_paths())
    if not policies:
        return {
            'status': 'Microsoft blocklist unavailable',
            'is_blocklisted': None,
            'matches': [],
            'policies_checked': [],
            'note': (
                'Driver binary was not found, and no Microsoft WDAC blocklist XML was available '
                'after runtime resolution.'
            ),
            'runtime_resolution': microsoft_blocklist_resolution,
        }

    candidate_names = set()
    for name in _candidate_driver_names(report_name, report_data):
        path = Path(name)
        candidate_names.add(path.name.lower())
        candidate_names.add(path.stem.lower())
        if not path.suffix:
            candidate_names.add(f'{path.name}.sys'.lower())
    candidate_names.discard('')

    matches = []
    for policy in policies:
        for rule in _load_blocklist_rules(policy):
            rule_file = rule.get('file_name', '').lower()
            if rule_file and rule_file in candidate_names:
                matches.append({**rule, 'match_type': 'report_file_name'})

    if matches:
        status = 'Possible blocklist match by report name'
        is_blocklisted = None
    else:
        status = 'No file-name match in Microsoft blocklist; binary unavailable'
        is_blocklisted = False

    return {
        'status': status,
        'is_blocklisted': is_blocklisted,
        'matches': matches,
        'policies_checked': [str(path) for path in policies],
        'note': (
            'The driver binary was not found, so only report/file-name matching was possible. '
            'Upload or keep the .sys in the workspace for definitive hash matching.'
        ),
        'runtime_resolution': microsoft_blocklist_resolution,
    }


def _section_name(section):
    return section.Name.rstrip(b'\x00').decode(errors='replace')


def _section_for_rva(pe, rva):
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= rva < end:
            return section
    return None


def _hvci_static_check(driver_path, signature_info, blocklist_info):
    result = {
        'status': 'Unknown',
        'loadable_with_hvci': None,
        'confidence': 'static',
        'issues': [],
        'warnings': [],
        'checks': {},
        'runtime_verification': (
            'Use Driver Verifier code integrity checks, test on a memory-integrity-enabled system, '
            'or run the HLK HyperVisor Code Integrity Readiness Test for a definitive answer.'
        ),
    }

    if pefile is None:
        result['status'] = 'pefile unavailable'
        result['issues'].append('Cannot parse PE headers because pefile is not installed.')
        return result

    try:
        pe = pefile.PE(driver_path, fast_load=False)
    except Exception as exc:
        result['status'] = 'Invalid PE'
        result['issues'].append(f'Unable to parse driver PE headers: {exc}')
        result['loadable_with_hvci'] = False
        return result

    try:
        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
        result['checks']['section_alignment'] = hex(section_alignment)
        if section_alignment % 0x1000 != 0:
            result['issues'].append('SectionAlignment is not page aligned (0x1000 multiple).')

        wx_sections = []
        for section in pe.sections:
            characteristics = section.Characteristics
            if characteristics & IMAGE_SCN_MEM_EXECUTE and characteristics & IMAGE_SCN_MEM_WRITE:
                wx_sections.append(_section_name(section))
        result['checks']['writable_executable_sections'] = wx_sections
        if wx_sections:
            result['issues'].append('Executable and writable PE sections: ' + ', '.join(wx_sections))

        import_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
        iat_section = _section_for_rva(pe, import_directory.VirtualAddress) if import_directory.VirtualAddress else None
        if iat_section is not None:
            iat_section_name = _section_name(iat_section)
            result['checks']['iat_section'] = iat_section_name
            if iat_section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                result['issues'].append(f'IAT is located in executable section {iat_section_name}.')

        dll_characteristics = getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0)
        nx_compat = bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        result['checks']['nx_compat'] = nx_compat
        if not nx_compat:
            result['warnings'].append('NX_COMPAT flag is not set; catalog/runtime checks may still be needed.')
    finally:
        pe.close()

    if blocklist_info.get('is_blocklisted') is True:
        result['issues'].append('The driver matched the Microsoft vulnerable driver blocklist.')
    elif blocklist_info.get('is_blocklisted') is None and blocklist_info.get('matches'):
        result['warnings'].append('The driver has a possible Microsoft blocklist file-name match.')

    if not signature_info.get('is_signed'):
        result['warnings'].append('No embedded Authenticode signature was found; catalog signing cannot be verified here.')

    if check_driver_imports is not None:
        imports = check_driver_imports(driver_path, HVCI_RISK_IMPORTS)
        risky_imports = [name for name, found in imports.items() if found]
        result['checks']['hvci_risk_imports'] = risky_imports
        if risky_imports:
            result['warnings'].append('Imports APIs that may require runtime HVCI review: ' + ', '.join(risky_imports))

    if result['issues']:
        result['status'] = 'Not loadable with HVCI / Code Integrity as checked'
        result['loadable_with_hvci'] = False
    elif signature_info.get('is_signed'):
        result['status'] = 'Likely HVCI-loadable; static checks passed'
        result['loadable_with_hvci'] = True
    else:
        result['status'] = 'Static HVCI layout checks passed; signature remains unknown'
        result['loadable_with_hvci'] = None

    return result


def _analyze_driver_metadata(report_name, report_data):
    driver_path = _resolve_driver_path(report_name, report_data)
    metadata = {
        'driver_path': driver_path,
        'driver_file': Path(driver_path).name if driver_path else None,
        'signature': {
            'available': False,
            'signature_type': 'Unknown',
            'status': 'Driver file not found',
        },
        'hashes': {},
        'version_info': {},
        'imports': {
            'available': False,
            'total_imports': 0,
            'library_count': 0,
            'libraries': [],
            'by_library': [],
            'flat': [],
            'error': 'Driver file not found',
        },
        'microsoft_blocklist': {
            'status': 'Driver binary unavailable',
            'is_blocklisted': None,
            'matches': [],
            'policies_checked': [],
        },
        'hvci': {
            'status': 'Unknown',
            'loadable_with_hvci': None,
            'issues': ['Driver file not found; upload the .sys/.dll alongside the report or keep it in the workspace.'],
            'warnings': [],
            'checks': {},
        },
    }

    if not driver_path:
        metadata['microsoft_blocklist'] = _match_blocklist_by_report_name(report_name, report_data)
        return metadata

    try:
        metadata['hashes'] = _file_hashes(driver_path)
    except Exception as exc:
        metadata['hash_error'] = str(exc)

    metadata['version_info'] = _pe_version_info(driver_path)
    metadata['imports'] = _driver_imports(driver_path)
    metadata['signature'] = _signature_metadata(driver_path)
    metadata['microsoft_blocklist'] = _match_blocklist(driver_path, metadata['hashes'], metadata['version_info'])
    metadata['hvci'] = _hvci_static_check(driver_path, metadata['signature'], metadata['microsoft_blocklist'])
    return metadata


def _enrich_report(report_name, data):
    data = _normalize_report_data(data, report_name)
    data['driver_metadata'] = _analyze_driver_metadata(report_name, data)
    return data


def _refresh_report_metadata(report_name):
    """Refresh metadata for already-loaded reports after blocklist/cache changes."""
    report = loaded_reports.get(report_name)
    if not report:
        return None
    report['driver_metadata'] = _analyze_driver_metadata(report_name, report)
    return report


def _report_summary(report_name, data):
    vulnerabilities = data.get('vulnerabilities', [])
    return {
        'report_name': report_name,
        'driver_name': data.get('driver_name'),
        'total_vulnerabilities': len(vulnerabilities),
        'vulnerability_types': sorted({vuln.get('vulnerability_type', 'Unknown') for vuln in vulnerabilities}),
        'vulnerability_classes': sorted({vuln.get('vulnerability_class', 'Other') for vuln in vulnerabilities}),
        'driver_metadata': data.get('driver_metadata', {}),
    }

@app.route('/')
def index():
    """Main page with report viewer interface."""
    return render_template('index.html')

@app.route('/api/load_single_report', methods=['POST'])
def load_single_report():
    """Load a single JSON report file."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if Path(file.filename).suffix.lower() != '.json':
            return jsonify({'error': 'File must be a JSON file'}), 400

        # Read, normalize, enrich, and store JSON.
        content = file.read().decode('utf-8')
        data = json.loads(content)

        report_name = _report_key(file.filename)
        loaded_reports[report_name] = _enrich_report(report_name, data)

        return jsonify({
            'success': True,
            'report_name': report_name,
            'data': loaded_reports[report_name],
            'summary': _report_summary(report_name, loaded_reports[report_name])
        })

    except json.JSONDecodeError as e:
        return jsonify({'error': f'Invalid JSON file: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Error loading file: {str(e)}'}), 500

@app.route('/api/load_directory', methods=['POST'])
def load_directory():
    """Load all JSON reports from a directory."""
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400

        files = request.files.getlist('files')
        json_files = [f for f in files if Path(f.filename).suffix.lower() == '.json']
        driver_files = [f for f in files if Path(f.filename).suffix.lower() in DRIVER_EXTENSIONS]
        blocklist_files = [f for f in files if Path(f.filename).suffix.lower() in BLOCKLIST_EXTENSIONS]

        if not json_files:
            return jsonify({'error': 'No JSON files found'}), 400

        loaded_reports_data = {}
        summaries = {}
        errors = []

        for file in driver_files:
            try:
                _save_uploaded_binary(file)
            except Exception as e:
                errors.append(f'Error saving driver {file.filename}: {str(e)}')

        for file in blocklist_files:
            try:
                _save_uploaded_blocklist(file)
            except Exception as e:
                errors.append(f'Error saving blocklist {file.filename}: {str(e)}')

        for file in json_files:
            try:
                content = file.read().decode('utf-8')
                data = json.loads(content)
                report_name = _report_key(file.filename)
                loaded_reports[report_name] = _enrich_report(report_name, data)
                loaded_reports_data[report_name] = loaded_reports[report_name]
                summaries[report_name] = _report_summary(report_name, loaded_reports[report_name])
            except Exception as e:
                errors.append(f'Error loading {file.filename}: {str(e)}')

        return jsonify({
            'success': True,
            'loaded_reports': loaded_reports_data,
            'summaries': summaries,
            'errors': errors if errors else None
        })

    except Exception as e:
        return jsonify({'error': f'Error loading directory: {str(e)}'}), 500

@app.route('/api/get_report/<path:report_name>')
def get_report(report_name):
    """Get a specific report data."""
    if report_name not in loaded_reports:
        return jsonify({'error': 'Report not found'}), 404

    return jsonify(_refresh_report_metadata(report_name))

@app.route('/api/get_reports_list')
def get_reports_list():
    """Get list of all loaded reports."""
    return jsonify({
        'reports': list(loaded_reports.keys()),
        'count': len(loaded_reports),
        'summaries': {
            name: _report_summary(name, _refresh_report_metadata(name) or report)
            for name, report in loaded_reports.items()
        }
    })

@app.route('/api/remove_report/<path:report_name>', methods=['DELETE'])
def remove_report(report_name):
    """Remove a report from memory."""
    if report_name in loaded_reports:
        del loaded_reports[report_name]
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Report not found'}), 404

@app.route('/api/clear_all_reports', methods=['DELETE'])
def clear_all_reports():
    """Clear all loaded reports."""
    global driver_search_index
    loaded_reports.clear()
    uploaded_driver_paths.clear()
    uploaded_blocklist_paths.clear()
    driver_search_index = None
    return jsonify({'success': True})

@app.route('/api/search_reports', methods=['POST'])
def search_reports():
    """Search across all loaded reports."""
    data = request.get_json()
    query = data.get('query', '').lower()
    vuln_type_filter = data.get('vuln_type', '')
    vuln_class_filter = data.get('vuln_class', '')
    access_type_filter = data.get('access_type', '')

    results = {}

    for report_name, report_data in loaded_reports.items():
        filtered_vulns = []
        for vuln in report_data.get('vulnerabilities', []):
            # Apply filters
            matches_query = not query or (
                query in vuln.get('ioctl', '').lower() or
                query in vuln.get('rip', '').lower() or
                query in vuln.get('vulnerability_type', '').lower() or
                query in vuln.get('access_type', '').lower()
            )

            matches_vuln_type = not vuln_type_filter or vuln.get('vulnerability_type') == vuln_type_filter
            matches_vuln_class = not vuln_class_filter or vuln.get('vulnerability_class') == vuln_class_filter
            matches_access_type = not access_type_filter or vuln.get('access_type') == access_type_filter

            if matches_query and matches_vuln_type and matches_vuln_class and matches_access_type:
                filtered_vulns.append(vuln)

        if filtered_vulns:
            results[report_name] = {
                'driver_name': report_data.get('driver_name'),
                'total_matches': len(filtered_vulns),
                'vulnerabilities': filtered_vulns
            }

    return jsonify(results)

@app.route('/api/vulnerability_classes')
def get_vulnerability_classes():
    """Get vulnerability classes across loaded reports for multi-driver filtering."""
    class_counts = {}
    matching_reports = {}

    for report_name, report_data in loaded_reports.items():
        report_classes = set()
        for vuln in report_data.get('vulnerabilities', []):
            class_name = vuln.get('vulnerability_class', 'Other')
            class_counts[class_name] = class_counts.get(class_name, 0) + 1
            report_classes.add(class_name)
        for class_name in report_classes:
            matching_reports.setdefault(class_name, []).append(report_name)

    return jsonify({
        'classes': sorted(class_counts.keys()),
        'class_counts': class_counts,
        'matching_reports': matching_reports,
    })

@app.route('/api/filter_reports_by_class')
def filter_reports_by_class():
    """Return loaded reports containing a vulnerability class."""
    class_name = request.args.get('class', '')
    matches = {}

    for report_name, report_data in loaded_reports.items():
        vulnerabilities = report_data.get('vulnerabilities', [])
        if not class_name or any(vuln.get('vulnerability_class') == class_name for vuln in vulnerabilities):
            matches[report_name] = _report_summary(report_name, report_data)

    return jsonify({
        'class': class_name,
        'count': len(matches),
        'reports': matches,
    })

@app.route('/api/get_statistics/<path:report_name>')
def get_statistics(report_name):
    """Get statistics for a specific report."""
    if report_name not in loaded_reports:
        return jsonify({'error': 'Report not found'}), 404

    data = _refresh_report_metadata(report_name)
    vulns = data.get('vulnerabilities', [])

    # Calculate statistics
    vuln_types = {}
    access_types = {}
    vuln_classes = {}

    for vuln in vulns:
        vuln_type = vuln.get('vulnerability_type', 'Unknown')
        access_type = vuln.get('access_type', 'Unknown')
        vuln_class = vuln.get('vulnerability_class', 'Other')

        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        access_types[access_type] = access_types.get(access_type, 0) + 1
        vuln_classes[vuln_class] = vuln_classes.get(vuln_class, 0) + 1

    stats = {
        'total_vulnerabilities': len(vulns),
        'unique_vuln_types': len(vuln_types),
        'unique_vuln_classes': len(vuln_classes),
        'unique_access_types': len(access_types),
        'vuln_types_breakdown': vuln_types,
        'vuln_classes_breakdown': vuln_classes,
        'access_types_breakdown': access_types,
        'generated_at': data.get('generated_at'),
        'driver_name': data.get('driver_name'),
        'driver_metadata': data.get('driver_metadata', {})
    }

    return jsonify(stats)

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files."""
    return send_from_directory('static', filename)

def create_templates():
    """Create the HTML templates directory and files."""
    templates_dir = 'templates'
    static_dir = 'static'

    os.makedirs(templates_dir, exist_ok=True)
    os.makedirs(static_dir, exist_ok=True)

    # Create base template
    base_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Vulnerability Report Viewer{% endblock %}</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            padding: 25px;
            margin-bottom: 20px;
        }

        .btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 25px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }

        .btn:hover {
            background: #764ba2;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        .btn-secondary {
            background: #6c757d;
        }

        .btn-secondary:hover {
            background: #5a6268;
        }

        .btn-danger {
            background: #dc3545;
        }

        .btn-danger:hover {
            background: #c82333;
        }

        .form-group {
            margin-bottom: 15px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #333;
        }

        .form-control {
            width: 100%;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 5px;
            font-size: 1em;
        }

        .form-control:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 5px rgba(102, 126, 234, 0.3);
        }

        .alert {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }

        .alert-error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }

        .alert-success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }

        .alert-info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            overflow-x: auto;
            flex-wrap: wrap;
        }

        .tab {
            background: white;
            border: 2px solid #ddd;
            padding: 12px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .tab:hover {
            border-color: #667eea;
            color: #667eea;
        }

        .tab.active {
            background: #667eea;
            color: white;
            border-color: #667eea;
        }

        .tab .close-btn {
            margin-left: 10px;
            cursor: pointer;
            opacity: 0.7;
        }

        .tab .close-btn:hover {
            opacity: 1;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
            text-align: center;
        }

        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }

        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }

        .vulnerabilities-list {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }

        .vuln-item {
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .vuln-item:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border-color: #667eea;
        }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .vuln-type {
            font-weight: bold;
            font-size: 1.1em;
            color: #333;
        }

        .vuln-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .badge-type {
            background: #e3f2fd;
            color: #1976d2;
        }

        .badge-access {
            background: #f3e5f5;
            color: #7b1fa2;
        }

        .vuln-body {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-bottom: 10px;
        }

        .vuln-field {
            padding: 10px;
            background: #f5f5f5;
            border-radius: 5px;
            border-left: 3px solid #667eea;
        }

        .vuln-field-label {
            font-weight: 600;
            color: #666;
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .vuln-field-value {
            font-family: 'Courier New', monospace;
            color: #333;
            word-break: break-all;
            font-size: 0.95em;
        }

        .timestamp {
            font-size: 0.85em;
            color: #999;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #999;
        }

        .empty-state h2 {
            margin-bottom: 10px;
            color: #666;
        }

        .filter-section {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .filter-input {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 0.95em;
        }

        .filter-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 5px rgba(102, 126, 234, 0.3);
        }

        .breakdown-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .breakdown-card {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #ddd;
        }

        .breakdown-title {
            font-weight: 600;
            color: #333;
            margin-bottom: 10px;
        }

        .breakdown-item {
            padding: 8px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
        }

        .breakdown-item:last-child {
            border-bottom: none;
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .hidden {
            display: none !important;
        }

        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }

            .control-group {
                flex-direction: column;
            }

            .file-input-group {
                flex-direction: column;
            }

            .vuln-body {
                grid-template-columns: 1fr;
            }

            .filter-section {
                flex-direction: column;
                align-items: stretch;
            }
        }
    </style>
    {% block head %}{% endblock %}
</head>
<body>
    {% block content %}{% endblock %}

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>"""

    # Create index template
    index_template = """{% extends "base.html" %}

{% block title %}Vulnerability Report Viewer{% endblock %}

{% block content %}
<div class="container">
    <div class="header">
        <h1>🔐 Vulnerability Report Viewer</h1>
        <p>Analyze and view kernel driver vulnerability analysis reports</p>
    </div>

    <div id="alertContainer"></div>

    <div class="card">
        <h2 style="margin-bottom: 20px; color: #333;"><i class="fas fa-upload"></i> Load Reports</h2>

        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
            <div style="flex: 1; min-width: 300px;">
                <h3 style="margin-bottom: 15px; color: #555;">Load Single Report</h3>
                <form id="singleFileForm" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="singleFile">Select JSON Report File:</label>
                        <input type="file" id="singleFile" name="file" accept=".json" class="form-control" required>
                    </div>
                    <button type="submit" class="btn">
                        <i class="fas fa-file-upload"></i> Load Report
                    </button>
                </form>
            </div>

            <div style="flex: 1; min-width: 300px;">
                <h3 style="margin-bottom: 15px; color: #555;">Load Reports Directory</h3>
                <form id="directoryForm" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="directoryFiles">Select Directory with JSON Reports:</label>
                        <input type="file" id="directoryFiles" name="files" webkitdirectory directory multiple accept=".json" class="form-control" required>
                    </div>
                    <button type="submit" class="btn">
                        <i class="fas fa-folder-open"></i> Load Directory
                    </button>
                </form>
            </div>
        </div>

        <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee;">
            <button id="clearAllBtn" class="btn btn-danger">
                <i class="fas fa-trash"></i> Clear All Reports
            </button>
        </div>
    </div>

    <div id="tabsContainer" class="tabs hidden"></div>

    <div id="statsContainer" class="hidden"></div>

    <div id="filterSection" class="hidden"></div>

    <div id="vulnerabilitiesContainer" class="hidden"></div>
</div>
{% endblock %}

{% block scripts %}
<script>
let currentReport = null;

$(document).ready(function() {
    // Load single file form
    $('#singleFileForm').on('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);

        showAlert('Loading report...', 'info');
        $('#singleFileForm button').prop('disabled', true).html('<span class="loading"></span> Loading...');

        $.ajax({
            url: '/api/load_single_report',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    addReportTab(response.report_name);
                    selectReport(response.report_name);
                    showAlert(`Successfully loaded ${response.report_name}`, 'success');
                } else {
                    showAlert(response.error, 'error');
                }
            },
            error: function(xhr) {
                showAlert('Error loading report: ' + xhr.responseJSON.error, 'error');
            },
            complete: function() {
                $('#singleFileForm button').prop('disabled', false).html('<i class="fas fa-file-upload"></i> Load Report');
            }
        });
    });

    // Load directory form
    $('#directoryForm').on('submit', function(e) {
        e.preventDefault();
        const formData = new FormData(this);

        showAlert('Loading directory...', 'info');
        $('#directoryForm button').prop('disabled', true).html('<span class="loading"></span> Loading...');

        $.ajax({
            url: '/api/load_directory',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                if (response.success) {
                    Object.keys(response.loaded_reports).forEach(reportName => {
                        addReportTab(reportName);
                    });

                    if (Object.keys(response.loaded_reports).length > 0) {
                        const firstReport = Object.keys(response.loaded_reports)[0];
                        selectReport(firstReport);
                    }

                    let message = `Successfully loaded ${Object.keys(response.loaded_reports).length} reports`;
                    if (response.errors && response.errors.length > 0) {
                        message += `. Errors: ${response.errors.join(', ')}`;
                    }
                    showAlert(message, 'success');
                } else {
                    showAlert(response.error, 'error');
                }
            },
            error: function(xhr) {
                showAlert('Error loading directory: ' + xhr.responseJSON.error, 'error');
            },
            complete: function() {
                $('#directoryForm button').prop('disabled', false).html('<i class="fas fa-folder-open"></i> Load Directory');
            }
        });
    });

    // Clear all reports
    $('#clearAllBtn').on('click', function() {
        if (confirm('Are you sure you want to clear all loaded reports?')) {
            $.ajax({
                url: '/api/clear_all_reports',
                type: 'DELETE',
                success: function() {
                    $('#tabsContainer').addClass('hidden').empty();
                    $('#statsContainer').addClass('hidden').empty();
                    $('#filterSection').addClass('hidden').empty();
                    $('#vulnerabilitiesContainer').addClass('hidden').empty();
                    currentReport = null;
                    showAlert('All reports cleared', 'success');
                },
                error: function(xhr) {
                    showAlert('Error clearing reports: ' + xhr.responseJSON.error, 'error');
                }
            });
        }
    });
});

function addReportTab(reportName) {
    const tabsContainer = $('#tabsContainer');
    tabsContainer.removeClass('hidden');

    // Check if tab already exists
    if ($(`#tab-${reportName.replace(/[^a-zA-Z0-9]/g, '_')}`).length > 0) {
        return;
    }

    const tabId = `tab-${reportName.replace(/[^a-zA-Z0-9]/g, '_')}`;
    const tab = $(`
        <div class="tab" id="${tabId}" onclick="selectReport('${reportName}')">
            <span>${reportName}</span>
            <span class="close-btn" onclick="event.stopPropagation(); removeReport('${reportName}')">×</span>
        </div>
    `);
    tabsContainer.append(tab);
}

function selectReport(reportName) {
    // Update active tab
    $('.tab').removeClass('active');
    const tabId = `tab-${reportName.replace(/[^a-zA-Z0-9]/g, '_')}`;
    $(`#${tabId}`).addClass('active');

    currentReport = reportName;
    loadReportData(reportName);
}

function removeReport(reportName) {
    $.ajax({
        url: `/api/remove_report/${encodeURIComponent(reportName)}`,
        type: 'DELETE',
        success: function() {
            const tabId = `tab-${reportName.replace(/[^a-zA-Z0-9]/g, '_')}`;
            $(`#${tabId}`).remove();

            if (currentReport === reportName) {
                const remainingTabs = $('.tab');
                if (remainingTabs.length > 0) {
                    const firstTab = remainingTabs.first();
                    const firstReportName = firstTab.find('span:first').text();
                    selectReport(firstReportName);
                } else {
                    $('#statsContainer').addClass('hidden').empty();
                    $('#filterSection').addClass('hidden').empty();
                    $('#vulnerabilitiesContainer').addClass('hidden').empty();
                    currentReport = null;
                }
            }
            showAlert(`Removed ${reportName}`, 'success');
        },
        error: function(xhr) {
            showAlert('Error removing report: ' + xhr.responseJSON.error, 'error');
        }
    });
}

function loadReportData(reportName) {
    // Load statistics
    $.get(`/api/get_statistics/${encodeURIComponent(reportName)}`, function(stats) {
        displayStats(stats);
    });

    // Load full report data for filtering
    $.get(`/api/get_report/${encodeURIComponent(reportName)}`, function(data) {
        displayFilters(data);
        displayVulnerabilities(data);
    });
}

function displayStats(stats) {
    const container = $('#statsContainer');
    container.removeClass('hidden');

    let html = `
        <div class="alert alert-info">
            <strong>Driver:</strong> ${stats.driver_name} |
            <strong>Generated:</strong> ${new Date(stats.generated_at).toLocaleString()}
        </div>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-value">${stats.total_vulnerabilities}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Vulnerability Types</div>
                <div class="stat-value">${stats.unique_vuln_types}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Unique Access Types</div>
                <div class="stat-value">${stats.unique_access_types}</div>
            </div>
        </div>

        <div class="breakdown-grid">
            <div class="breakdown-card">
                <div class="breakdown-title">By Vulnerability Type</div>
                ${Object.entries(stats.vuln_types_breakdown).map(([type, count]) =>
                    `<div class="breakdown-item"><span>${type}</span><span style="font-weight: bold;">${count}</span></div>`
                ).join('')}
            </div>
            <div class="breakdown-card">
                <div class="breakdown-title">By Access Type</div>
                ${Object.entries(stats.access_types_breakdown).map(([type, count]) =>
                    `<div class="breakdown-item"><span>${type}</span><span style="font-weight: bold;">${count}</span></div>`
                ).join('')}
            </div>
        </div>
    `;

    container.html(html);
}

function displayFilters(data) {
    const container = $('#filterSection');
    container.removeClass('hidden');

    const vulnTypes = [...new Set(data.vulnerabilities.map(v => v.vulnerability_type))];
    const accessTypes = [...new Set(data.vulnerabilities.map(v => v.access_type))];

    let html = `
        <div class="filter-section">
            <label style="font-weight: 600;">Filters:</label>
            <input type="text" class="filter-input" id="searchInput" placeholder="Search by IOCTL, RIP, or type..." onkeyup="applyFilters()">
            <select class="filter-input" id="vulnTypeFilter" onchange="applyFilters()">
                <option value="">All Vulnerability Types</option>
                ${vulnTypes.map(type => `<option value="${type}">${type}</option>`).join('')}
            </select>
            <select class="filter-input" id="accessTypeFilter" onchange="applyFilters()">
                <option value="">All Access Types</option>
                ${accessTypes.map(type => `<option value="${type}">${type}</option>`).join('')}
            </select>
        </div>
    `;

    container.html(html);
}

function applyFilters() {
    if (!currentReport) return;

    const searchText = $('#searchInput').val().toLowerCase();
    const vulnTypeFilter = $('#vulnTypeFilter').val();
    const accessTypeFilter = $('#accessTypeFilter').val();

    $.get(`/api/get_report/${encodeURIComponent(currentReport)}`, function(data) {
        const filteredVulns = data.vulnerabilities.filter(vuln => {
            const matchesSearch = !searchText ||
                vuln.ioctl.toLowerCase().includes(searchText) ||
                vuln.rip.toLowerCase().includes(searchText) ||
                vuln.vulnerability_type.toLowerCase().includes(searchText) ||
                vuln.access_type.toLowerCase().includes(searchText);

            const matchesVulnType = !vulnTypeFilter || vuln.vulnerability_type === vulnTypeFilter;
            const matchesAccessType = !accessTypeFilter || vuln.access_type === accessTypeFilter;

            return matchesSearch && matchesVulnType && matchesAccessType;
        });

        displayVulnerabilities({...data, vulnerabilities: filteredVulns});
    });
}

function displayVulnerabilities(data) {
    const container = $('#vulnerabilitiesContainer');
    container.removeClass('hidden');

    if (data.vulnerabilities.length === 0) {
        container.html('<div class="empty-state"><h2>No vulnerabilities found</h2><p>Try adjusting your filters</p></div>');
        return;
    }

    let html = `<div class="vulnerabilities-list">
        <h2 style="margin-bottom: 20px; color: #333;"><i class="fas fa-bug"></i> Vulnerabilities (${data.vulnerabilities.length})</h2>
    `;

    data.vulnerabilities.forEach((vuln, index) => {
        html += `
            <div class="vuln-item">
                <div class="vuln-header">
                    <span class="vuln-type">#${index + 1}</span>
                    <span class="vuln-badge badge-type">${vuln.vulnerability_type}</span>
                    <span class="vuln-badge badge-access">${vuln.access_type}</span>
                </div>
                <div class="vuln-body">
                    <div class="vuln-field">
                        <div class="vuln-field-label">IOCTL</div>
                        <div class="vuln-field-value">${vuln.ioctl}</div>
                    </div>
                    <div class="vuln-field">
                        <div class="vuln-field-label">RIP (Instruction Pointer)</div>
                        <div class="vuln-field-value">${vuln.rip}</div>
                    </div>
                    ${Object.entries(vuln.address_info).map(([key, value]) =>
                        `<div class="vuln-field">
                            <div class="vuln-field-label">${key}</div>
                            <div class="vuln-field-value">${value}</div>
                        </div>`
                    ).join('')}
                </div>
                ${Object.keys(vuln.additional_info).length > 0 ? `
                    <div style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #eee;">
                        <details>
                            <summary style="font-weight: 600; color: #666; cursor: pointer;">Additional Information</summary>
                            <pre style="margin-top: 10px; padding: 10px; background: #f9f9f9; border-radius: 5px; overflow-x: auto; font-size: 0.9em;">${JSON.stringify(vuln.additional_info, null, 2)}</pre>
                        </details>
                    </div>
                ` : ''}
                <div class="timestamp" style="margin-top: 10px;">
                    Found: ${new Date(vuln.timestamp).toLocaleString()}
                </div>
            </div>
        `;
    });

    html += '</div>';
    container.html(html);
}

function showAlert(message, type) {
    const alertClass = type === 'error' ? 'alert-error' : type === 'success' ? 'alert-success' : 'alert-info';
    const alertHtml = `<div class="alert ${alertClass}">${message}</div>`;
    $('#alertContainer').html(alertHtml);

    // Auto-hide success and info alerts after 5 seconds
    if (type === 'success' || type === 'info') {
        setTimeout(() => {
            $('#alertContainer').empty();
        }, 5000);
    }
}
</script>
{% endblock %}"""

    # Write templates
    with open(os.path.join(templates_dir, 'base.html'), 'w') as f:
        f.write(base_template)

    with open(os.path.join(templates_dir, 'index.html'), 'w') as f:
        f.write(index_template)

    print(f"Created templates in {templates_dir}/")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Vulnerability Report Viewer - Python Web Application')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    # Create templates if they don't exist
    if not os.path.exists('templates'):
        create_templates()

    print("🚀 Starting Vulnerability Report Viewer...")
    print(f"📱 Open your browser to: http://{args.host}:{args.port}")
    print("📁 Upload JSON reports from the 'reports/' directory")
    print("🔄 Press Ctrl+C to stop the server")

    app.run(host=args.host, port=args.port, debug=args.debug)
