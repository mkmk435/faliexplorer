#!/usr/bin/env python3
"""
Vulnerability Report Viewer - Python Web Application
A Flask-based web application for viewing and analyzing kernel driver vulnerability reports.
"""

import os
import json
import glob
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'faliexplorer-report-viewer'
app.config['UPLOAD_FOLDER'] = 'temp_uploads'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Global storage for loaded reports
loaded_reports = {}

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

        if not file.filename.endswith('.json'):
            return jsonify({'error': 'File must be a JSON file'}), 400

        # Read and parse JSON
        content = file.read().decode('utf-8')
        data = json.loads(content)

        # Store in memory
        report_name = file.filename
        loaded_reports[report_name] = data

        return jsonify({
            'success': True,
            'report_name': report_name,
            'data': data
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
        json_files = [f for f in files if f.filename.endswith('.json')]

        if not json_files:
            return jsonify({'error': 'No JSON files found'}), 400

        loaded_reports_data = {}
        errors = []

        for file in json_files:
            try:
                content = file.read().decode('utf-8')
                data = json.loads(content)
                loaded_reports[file.filename] = data
                loaded_reports_data[file.filename] = data
            except Exception as e:
                errors.append(f'Error loading {file.filename}: {str(e)}')

        return jsonify({
            'success': True,
            'loaded_reports': loaded_reports_data,
            'errors': errors if errors else None
        })

    except Exception as e:
        return jsonify({'error': f'Error loading directory: {str(e)}'}), 500

@app.route('/api/get_report/<report_name>')
def get_report(report_name):
    """Get a specific report data."""
    if report_name not in loaded_reports:
        return jsonify({'error': 'Report not found'}), 404

    return jsonify(loaded_reports[report_name])

@app.route('/api/get_reports_list')
def get_reports_list():
    """Get list of all loaded reports."""
    return jsonify({
        'reports': list(loaded_reports.keys()),
        'count': len(loaded_reports)
    })

@app.route('/api/remove_report/<report_name>', methods=['DELETE'])
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
    loaded_reports.clear()
    return jsonify({'success': True})

@app.route('/api/search_reports', methods=['POST'])
def search_reports():
    """Search across all loaded reports."""
    data = request.get_json()
    query = data.get('query', '').lower()
    vuln_type_filter = data.get('vuln_type', '')
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
            matches_access_type = not access_type_filter or vuln.get('access_type') == access_type_filter

            if matches_query and matches_vuln_type and matches_access_type:
                filtered_vulns.append(vuln)

        if filtered_vulns:
            results[report_name] = {
                'driver_name': report_data.get('driver_name'),
                'total_matches': len(filtered_vulns),
                'vulnerabilities': filtered_vulns
            }

    return jsonify(results)

@app.route('/api/get_statistics/<report_name>')
def get_statistics(report_name):
    """Get statistics for a specific report."""
    if report_name not in loaded_reports:
        return jsonify({'error': 'Report not found'}), 404

    data = loaded_reports[report_name]
    vulns = data.get('vulnerabilities', [])

    # Calculate statistics
    vuln_types = {}
    access_types = {}

    for vuln in vulns:
        vuln_type = vuln.get('vulnerability_type', 'Unknown')
        access_type = vuln.get('access_type', 'Unknown')

        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        access_types[access_type] = access_types.get(access_type, 0) + 1

    stats = {
        'total_vulnerabilities': len(vulns),
        'unique_vuln_types': len(vuln_types),
        'unique_access_types': len(access_types),
        'vuln_types_breakdown': vuln_types,
        'access_types_breakdown': access_types,
        'generated_at': data.get('generated_at'),
        'driver_name': data.get('driver_name')
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