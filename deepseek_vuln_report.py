#!/usr/bin/env python3
"""
IDA + DeepSeek vulnerability report generation.

This module is intentionally separate from the Flask server so the slow,
tool-heavy work stays isolated from the viewer code.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


DEEPSEEK_API_URL = 'https://api.deepseek.com/chat/completions'
DEFAULT_DEEPSEEK_MODEL = 'deepseek-reasoner'
DEFAULT_IDA_TIMEOUT_SECONDS = 20 * 60
DEFAULT_DEEPSEEK_TIMEOUT_SECONDS = 5 * 60
DEFAULT_MAX_XREF_DEPTH = 8
DEFAULT_MAX_CALLERS_PER_FUNCTION = 24


class VulnerabilityReportError(RuntimeError):
    """Raised when the report cannot be generated."""


IDA_DECOMPILER_SCRIPT = r'''
import json
import os
import sys

import idaapi
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import idautils
import idc


def to_hex(value):
    if value is None:
        return ''
    return '0x%x' % int(value)


def parse_int(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def strip_tags(value):
    try:
        return ida_lines.tag_remove(str(value))
    except Exception:
        return str(value)


def function_name(func_ea):
    name = ida_name.get_name(func_ea) or idc.get_func_name(func_ea) or ''
    return name or ('sub_%x' % func_ea)


def disassemble_function(func):
    lines = []
    for ea in idautils.FuncItems(func.start_ea):
        disasm = idc.generate_disasm_line(ea, 0) or ''
        lines.append('%s: %s' % (to_hex(ea), strip_tags(disasm)))
    return '\n'.join(lines)


def find_entry_functions():
    entries = set()
    for func_ea in idautils.Functions():
        name = function_name(func_ea).lower()
        if name in ('driverentry', '_driverentry') or 'driverentry' in name:
            entries.add(func_ea)

    for index in range(idc.get_entry_qty()):
        ordinal = idc.get_entry_ordinal(index)
        ea = idc.get_entry(ordinal)
        func = ida_funcs.get_func(ea)
        if func:
            entries.add(func.start_ea)

    return entries


def get_callers(func_ea, max_callers):
    callers = []
    seen = set()
    for ref_ea in idautils.CodeRefsTo(func_ea, 0):
        caller = ida_funcs.get_func(ref_ea)
        if not caller:
            continue
        caller_ea = caller.start_ea
        if caller_ea == func_ea or caller_ea in seen:
            continue
        seen.add(caller_ea)
        callers.append(caller_ea)
        if len(callers) >= max_callers:
            break
    return callers


def resolve_rip(rip_value):
    rip = parse_int(rip_value)
    if rip is None:
        return None, []

    imagebase = idaapi.get_imagebase()
    candidates = [rip]
    if rip < imagebase:
        candidates.append(imagebase + rip)
    if imagebase and rip >= imagebase:
        candidates.append(rip - imagebase)

    tried = []
    for ea in candidates:
        if ea in tried:
            continue
        tried.append(ea)
        func = ida_funcs.get_func(ea)
        if func:
            return ea, tried

    return None, tried


def decompile_function(func_ea, cache):
    key = to_hex(func_ea)
    if key in cache:
        return cache[key]

    func = ida_funcs.get_func(func_ea)
    record = {
        'start_ea': key,
        'end_ea': '',
        'name': function_name(func_ea),
        'decompiled': False,
        'pseudocode': '',
        'disassembly': '',
        'error': '',
    }

    if not func:
        record['error'] = 'Function not found'
        cache[key] = record
        return record

    record['start_ea'] = to_hex(func.start_ea)
    record['end_ea'] = to_hex(func.end_ea)
    record['name'] = function_name(func.start_ea)

    try:
        if ida_hexrays.init_hexrays_plugin():
            cfunc = ida_hexrays.decompile(func)
            record['pseudocode'] = '\n'.join(
                strip_tags(line.line) for line in cfunc.get_pseudocode()
            )
            record['decompiled'] = True
        else:
            record['error'] = 'Hex-Rays decompiler is not available'
    except Exception as exc:
        record['error'] = str(exc)

    if not record['pseudocode']:
        record['disassembly'] = disassemble_function(func)

    cache[to_hex(func.start_ea)] = record
    return record


def caller_paths_to_entry(start_func_ea, entry_functions, max_depth, max_callers):
    paths = []
    queue = [[start_func_ea]]
    visited_states = set()

    while queue and len(paths) < 32:
        path = queue.pop(0)
        current = path[-1]
        state = tuple(path)
        if state in visited_states:
            continue
        visited_states.add(state)

        if current in entry_functions or len(path) > max_depth:
            paths.append(path)
            continue

        callers = get_callers(current, max_callers)
        callers = [caller for caller in callers if caller not in path]
        if not callers:
            paths.append(path)
            continue

        for caller in callers:
            queue.append(path + [caller])

    return paths


def main():
    idaapi.auto_wait()

    if len(idc.ARGV) < 2:
        raise RuntimeError('Missing IDA job JSON path')

    job_path = idc.ARGV[1]
    with open(job_path, 'r', encoding='utf-8') as handle:
        job = json.load(handle)

    output_path = job['output_path']
    vulnerabilities = job.get('vulnerabilities', [])
    max_depth = int(job.get('max_xref_depth', 8))
    max_callers = int(job.get('max_callers_per_function', 24))
    imagebase = idaapi.get_imagebase()
    entries = find_entry_functions()
    function_cache = {}
    vuln_results = []

    for index, vuln in enumerate(vulnerabilities):
        rip = vuln.get('rip') or vuln.get('address_info', {}).get('return address')
        resolved_ea, tried = resolve_rip(rip)
        result = {
            'index': index,
            'rip': rip,
            'resolved_ea': to_hex(resolved_ea) if resolved_ea is not None else '',
            'tried_eas': [to_hex(ea) for ea in tried],
            'function_ea': '',
            'function_name': '',
            'caller_paths_to_entry': [],
            'error': '',
        }

        if resolved_ea is None:
            result['error'] = 'Could not resolve RIP to an IDA function'
            vuln_results.append(result)
            continue

        func = ida_funcs.get_func(resolved_ea)
        if not func:
            result['error'] = 'Resolved address is not inside a function'
            vuln_results.append(result)
            continue

        result['function_ea'] = to_hex(func.start_ea)
        result['function_name'] = function_name(func.start_ea)
        decompile_function(func.start_ea, function_cache)

        paths = caller_paths_to_entry(func.start_ea, entries, max_depth, max_callers)
        for path in paths:
            path_records = []
            for func_ea in path:
                decompile_function(func_ea, function_cache)
                path_records.append({
                    'ea': to_hex(func_ea),
                    'name': function_name(func_ea),
                    'is_driver_entry': func_ea in entries,
                })
            result['caller_paths_to_entry'].append(path_records)

        vuln_results.append(result)

    output = {
        'ida_database': idc.get_idb_path(),
        'input_file': idc.get_input_file_path(),
        'imagebase': to_hex(imagebase),
        'driver_entry_functions': [
            {'ea': to_hex(ea), 'name': function_name(ea)}
            for ea in sorted(entries)
        ],
        'vulnerabilities': vuln_results,
        'functions': function_cache,
    }

    with open(output_path, 'w', encoding='utf-8') as handle:
        json.dump(output, handle, indent=2, sort_keys=True)

    idaapi.qexit(0)


try:
    main()
except Exception as exc:
    fallback = {'error': str(exc)}
    try:
        if len(idc.ARGV) >= 2:
            with open(idc.ARGV[1], 'r', encoding='utf-8') as handle:
                job = json.load(handle)
            with open(job['output_path'], 'w', encoding='utf-8') as handle:
                json.dump(fallback, handle, indent=2)
    finally:
        idaapi.qexit(1)
'''


def generate_deepseek_vulnerability_report(
    report_name,
    report_data,
    driver_path,
    output_dir='generated_reports',
    ida_path=None,
    deepseek_api_key=None,
    deepseek_model=None,
    deepseek_base_url=None,
    ida_timeout_seconds=DEFAULT_IDA_TIMEOUT_SECONDS,
    deepseek_timeout_seconds=DEFAULT_DEEPSEEK_TIMEOUT_SECONDS,
    max_xref_depth=DEFAULT_MAX_XREF_DEPTH,
    max_callers_per_function=DEFAULT_MAX_CALLERS_PER_FUNCTION,
):
    """Generate an IDA-backed DeepSeek vulnerability report."""
    driver = Path(driver_path)
    if not driver.exists():
        raise VulnerabilityReportError(f'Driver binary not found: {driver_path}')

    vulnerabilities = report_data.get('vulnerabilities') or []
    if not vulnerabilities:
        raise VulnerabilityReportError('Report has no vulnerabilities to analyze.')

    api_key = deepseek_api_key or os.environ.get('DEEPSEEK_API_KEY')
    if not api_key:
        raise VulnerabilityReportError('Set DEEPSEEK_API_KEY before generating a DeepSeek report.')

    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    ida_result = run_ida_decompilation(
        driver,
        vulnerabilities,
        output_root,
        ida_path=ida_path,
        timeout_seconds=ida_timeout_seconds,
        max_xref_depth=max_xref_depth,
        max_callers_per_function=max_callers_per_function,
    )

    context = build_analysis_context(report_name, report_data, driver, ida_result)
    deepseek = request_deepseek_report(
        context,
        api_key=api_key,
        model=deepseek_model or os.environ.get('DEEPSEEK_MODEL') or DEFAULT_DEEPSEEK_MODEL,
        base_url=deepseek_base_url or os.environ.get('DEEPSEEK_API_URL') or DEEPSEEK_API_URL,
        timeout_seconds=deepseek_timeout_seconds,
    )

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_stem = ''.join(ch if ch.isalnum() or ch in ('-', '_') else '_' for ch in Path(report_name).stem)
    json_path = output_root / f'{safe_stem}_{timestamp}_deepseek_report.json'
    markdown_path = output_root / f'{safe_stem}_{timestamp}_deepseek_report.md'

    final_report = {
        'generated_at': datetime.now().isoformat(),
        'report_name': report_name,
        'driver_path': str(driver),
        'driver_name': report_data.get('driver_name') or driver.stem,
        'source_report': report_data,
        'ida': ida_result,
        'analysis_context': context,
        'deepseek': deepseek,
        'output_files': {
            'json': str(json_path),
            'markdown': str(markdown_path),
        },
    }

    json_path.write_text(json.dumps(final_report, indent=2, sort_keys=True), encoding='utf-8')
    markdown_path.write_text(render_markdown_report(final_report), encoding='utf-8')

    return {
        'generated_at': final_report['generated_at'],
        'report_name': report_name,
        'driver_name': final_report['driver_name'],
        'driver_path': str(driver),
        'vulnerabilities_analyzed': len(vulnerabilities),
        'unique_functions_decompiled': len((ida_result.get('functions') or {})),
        'deepseek_model': deepseek.get('model'),
        'deepseek_summary': deepseek.get('content', ''),
        'output_files': final_report['output_files'],
        'ida_database': ida_result.get('ida_database', ''),
    }


def resolve_ida_path(explicit_path=None):
    candidates = [
        explicit_path,
        os.environ.get('FALIEXPLORER_IDA_PATH'),
        os.environ.get('IDA_PATH'),
        os.environ.get('IDA64_PATH'),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate))

    for executable in ('idat64', 'idat', 'ida64', 'ida'):
        found = shutil.which(executable)
        if found:
            return found

    raise VulnerabilityReportError(
        'IDA executable not found. Set FALIEXPLORER_IDA_PATH to idat64/idat/ida64/ida.'
    )


def run_ida_decompilation(
    driver_path,
    vulnerabilities,
    output_root,
    ida_path=None,
    timeout_seconds=DEFAULT_IDA_TIMEOUT_SECONDS,
    max_xref_depth=DEFAULT_MAX_XREF_DEPTH,
    max_callers_per_function=DEFAULT_MAX_CALLERS_PER_FUNCTION,
):
    ida_executable = resolve_ida_path(ida_path)
    jobs_dir = output_root / 'ida_jobs'
    jobs_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix='ida_report_', dir=str(jobs_dir)) as temp_dir:
        temp_path = Path(temp_dir)
        script_path = temp_path / 'ida_decompile_job.py'
        job_path = temp_path / 'job.json'
        ida_output_path = temp_path / 'ida_output.json'

        script_path.write_text(IDA_DECOMPILER_SCRIPT, encoding='utf-8')
        job = {
            'output_path': str(ida_output_path),
            'vulnerabilities': vulnerabilities,
            'max_xref_depth': max_xref_depth,
            'max_callers_per_function': max_callers_per_function,
        }
        job_path.write_text(json.dumps(job, indent=2), encoding='utf-8')

        command = [
            ida_executable,
            '-A',
            f'-S{script_path} {job_path}',
            str(driver_path),
        ]
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        if not ida_output_path.exists():
            raise VulnerabilityReportError(
                'IDA did not produce decompilation output. '
                f'exit={completed.returncode}, stderr={completed.stderr[-2000:]}'
            )

        try:
            ida_result = json.loads(ida_output_path.read_text(encoding='utf-8'))
        except json.JSONDecodeError as exc:
            raise VulnerabilityReportError(f'IDA produced invalid JSON: {exc}') from exc

        if completed.returncode != 0 or ida_result.get('error'):
            raise VulnerabilityReportError(
                'IDA decompilation failed: '
                f"{ida_result.get('error') or completed.stderr[-2000:] or completed.stdout[-2000:]}"
            )

        ida_result['ida_executable'] = ida_executable
        ida_result['ida_stdout_tail'] = completed.stdout[-4000:]
        ida_result['ida_stderr_tail'] = completed.stderr[-4000:]
        return ida_result


def build_analysis_context(report_name, report_data, driver_path, ida_result):
    functions = ida_result.get('functions') or {}
    context_vulns = []

    for ida_vuln in ida_result.get('vulnerabilities') or []:
        index = ida_vuln.get('index')
        source_vuln = {}
        if isinstance(index, int) and index < len(report_data.get('vulnerabilities', [])):
            source_vuln = report_data['vulnerabilities'][index]

        path_function_eas = []
        for path in ida_vuln.get('caller_paths_to_entry') or []:
            for item in path:
                ea = item.get('ea')
                if ea and ea not in path_function_eas:
                    path_function_eas.append(ea)

        context_vulns.append({
            'index': index,
            'source': source_vuln,
            'rip_resolution': {
                'rip': ida_vuln.get('rip'),
                'resolved_ea': ida_vuln.get('resolved_ea'),
                'function_ea': ida_vuln.get('function_ea'),
                'function_name': ida_vuln.get('function_name'),
                'error': ida_vuln.get('error'),
            },
            'caller_paths_to_driver_entry': ida_vuln.get('caller_paths_to_entry') or [],
            'related_functions': [
                function_reference(functions.get(ea) or {})
                for ea in path_function_eas
            ],
        })

    return {
        'report_name': report_name,
        'driver_name': report_data.get('driver_name') or driver_path.stem,
        'driver_path': str(driver_path),
        'generated_at': report_data.get('generated_at'),
        'total_vulnerabilities': len(report_data.get('vulnerabilities') or []),
        'driver_metadata': report_data.get('driver_metadata') or {},
        'driver_entry_functions': ida_result.get('driver_entry_functions') or [],
        'imagebase': ida_result.get('imagebase'),
        'vulnerabilities': context_vulns,
        'unique_decompiled_functions': [
            function_summary(function_record)
            for function_record in functions.values()
        ],
    }


def function_summary(function_record):
    pseudocode = function_record.get('pseudocode') or ''
    disassembly = function_record.get('disassembly') or ''
    return {
        'start_ea': function_record.get('start_ea', ''),
        'end_ea': function_record.get('end_ea', ''),
        'name': function_record.get('name', ''),
        'decompiled': function_record.get('decompiled', False),
        'error': function_record.get('error', ''),
        'pseudocode': pseudocode,
        'disassembly': disassembly if not pseudocode else '',
    }


def function_reference(function_record):
    return {
        'start_ea': function_record.get('start_ea', ''),
        'end_ea': function_record.get('end_ea', ''),
        'name': function_record.get('name', ''),
        'decompiled': function_record.get('decompiled', False),
        'error': function_record.get('error', ''),
    }


def request_deepseek_report(context, api_key, model, base_url, timeout_seconds):
    messages = [
        {
            'role': 'system',
            'content': (
                'You are a senior Windows kernel driver vulnerability reviewer. '
                'Use the FALIExplorer finding details, IDA pseudocode, and caller xrefs '
                'to decide whether each finding is likely exploitable, needs manual '
                'review, or is likely a false positive. Be precise and cite function '
                'names, IOCTLs, RIPs, and data-flow evidence from the provided context.'
            ),
        },
        {
            'role': 'user',
            'content': (
                'Create a vulnerability triage report. Include an executive summary, '
                'per-vulnerability verdicts, evidence, false-positive reasoning, '
                'exploitability notes, and recommended next reverse-engineering steps.\n\n'
                + json.dumps(context, indent=2, sort_keys=True)
            ),
        },
    ]
    body = json.dumps({
        'model': model,
        'messages': messages,
        'temperature': 0.1,
    }).encode('utf-8')
    request = urllib.request.Request(
        base_url,
        data=body,
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'FALIExplorer report generator',
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode('utf-8', errors='replace')
        raise VulnerabilityReportError(f'DeepSeek API returned HTTP {exc.code}: {detail}') from exc
    except urllib.error.URLError as exc:
        raise VulnerabilityReportError(f'DeepSeek API request failed: {exc}') from exc

    choices = payload.get('choices') or []
    content = ''
    if choices:
        content = (choices[0].get('message') or {}).get('content') or ''

    return {
        'model': payload.get('model') or model,
        'content': content,
        'raw_response': payload,
    }


def render_markdown_report(final_report):
    deepseek_content = final_report.get('deepseek', {}).get('content') or 'No DeepSeek content returned.'
    ida = final_report.get('ida') or {}
    lines = [
        f"# DeepSeek Vulnerability Report: {final_report.get('driver_name', 'Unknown')}",
        '',
        f"- Generated: {final_report.get('generated_at', '')}",
        f"- Source report: {final_report.get('report_name', '')}",
        f"- Driver: `{final_report.get('driver_path', '')}`",
        f"- IDA database: `{ida.get('ida_database', '')}`",
        f"- Unique functions decompiled: {len(ida.get('functions') or {})}",
        '',
        '## DeepSeek Analysis',
        '',
        deepseek_content,
        '',
        '## IDA Function Inventory',
        '',
    ]

    for function in (ida.get('functions') or {}).values():
        lines.extend([
            f"### {function.get('name', 'unknown')} ({function.get('start_ea', '')})",
            '',
            f"- Decompiled: {function.get('decompiled', False)}",
            f"- Error: {function.get('error', '') or 'None'}",
            '',
        ])

    return '\n'.join(lines).rstrip() + '\n'
