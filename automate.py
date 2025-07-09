#!/usr/bin/env python3

import subprocess
import argparse
import os
from datetime import datetime
import concurrent.futures
import json
import logging
import sys
import jinja2  # pip install jinja2

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("webapp_recon.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

def run_command(command, output_file, timeout=300):
    """Run shell command with timeout, save stdout+stderr."""
    logging.info(f"Running command: {' '.join(command)}")
    try:
        with open(output_file, 'w') as f:
            subprocess.run(command, stdout=f, stderr=subprocess.STDOUT, timeout=timeout, check=True)
        logging.info(f"Saved output to {output_file}")
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout expired: {' '.join(command)}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed ({e.returncode}): {' '.join(command)}")
    return False

def parse_nmap(nmap_file):
    open_ports = 0
    try:
        with open(nmap_file) as f:
            for line in f:
                if "open" in line and "/tcp" in line:
                    open_ports += 1
    except Exception as e:
        logging.error(f"Error parsing nmap output: {e}")
    return {"open_ports": open_ports}

def parse_dirsearch(dirsearch_file):
    paths_found = 0
    try:
        with open(dirsearch_file) as f:
            for line in f:
                if line.startswith("200") or line.startswith("301") or line.startswith("302"):
                    paths_found += 1
    except Exception as e:
        logging.error(f"Error parsing dirsearch output: {e}")
    return {"valid_paths": paths_found}

def parse_nikto(nikto_file):
    vuln_count = 0
    try:
        with open(nikto_file) as f:
            for line in f:
                if "OSVDB" in line or "Vulnerability" in line:
                    vuln_count += 1
    except Exception as e:
        logging.error(f"Error parsing nikto output: {e}")
    return {"potential_vulns": vuln_count}

def parse_amass(amass_file):
    count = 0
    try:
        with open(amass_file) as f:
            count = sum(1 for _ in f)
    except Exception as e:
        logging.error(f"Error parsing amass output: {e}")
    return {"subdomains": count}

def parse_wfuzz(wfuzz_file):
    results = 0
    try:
        with open(wfuzz_file) as f:
            results = sum(1 for line in f if "404" not in line)
    except Exception as e:
        logging.error(f"Error parsing wfuzz output: {e}")
    return {"fuzz_results": results}

def generate_html_report(data, output_dir):
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>Recon Report for {{ target }}</title>
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body>
      <h1>Recon Report for {{ target }}</h1>
      <p>Scan Date: {{ scan_date }}</p>

      <h2>Summary</h2>
      <ul>
        <li>Nmap Open Ports: {{ data.nmap.open_ports }}</li>
        <li>Dirsearch Valid Paths: {{ data.dirsearch.valid_paths }}</li>
        <li>Nikto Potential Vulnerabilities: {{ data.nikto.potential_vulns }}</li>
        <li>Amass Subdomains: {{ data.amass.subdomains }}</li>
        <li>Wfuzz Fuzz Results: {{ data.wfuzz.fuzz_results }}</li>
      </ul>

      <h2>Charts</h2>
      <canvas id="chart" width="400" height="200"></canvas>
      <script>
        const ctx = document.getElementById('chart').getContext('2d');
        const chart = new Chart(ctx, {
          type: 'bar',
          data: {
            labels: ['Open Ports', 'Valid Paths', 'Vulnerabilities', 'Subdomains', 'Fuzz Results'],
            datasets: [{
              label: 'Counts',
              data: [
                {{ data.nmap.open_ports }},
                {{ data.dirsearch.valid_paths }},
                {{ data.nikto.potential_vulns }},
                {{ data.amass.subdomains }},
                {{ data.wfuzz.fuzz_results }}
              ],
              backgroundColor: 'rgba(54, 162, 235, 0.7)'
            }]
          },
          options: {
            scales: {
              y: {
                beginAtZero: true
              }
            }
          }
        });
      </script>
    </body>
    </html>
    """

    template = jinja2.Template(template_str)
    html_content = template.render(target=data['target'], scan_date=data['scan_date'], data=data['results'])
    report_file = os.path.join(output_dir, 'report.html')
    with open(report_file, 'w') as f:
        f.write(html_content)
    logging.info(f"HTML report generated at {report_file}")

def run_tool(tool, target, output_dir):
    """Run individual tool, returns parsed data or None"""
    try:
        if tool == 'nmap':
            out_file = os.path.join(output_dir, 'nmap_scan.txt')
            if run_command(['nmap', '-sV', '-oN', out_file, target], out_file):
                return ('nmap', parse_nmap(out_file))
        elif tool == 'dirsearch':
            out_file = os.path.join(output_dir, 'dirsearch.txt')
            if run_command(['dirsearch', '-u', f'https://{target}', '-e', 'php,html,js', '-t', '50', '-o', out_file], out_file):
                return ('dirsearch', parse_dirsearch(out_file))
        elif tool == 'nikto':
            out_file = os.path.join(output_dir, 'nikto.txt')
            if run_command(['nikto', '-h', f'https://{target}', '-output', out_file], out_file):
                return ('nikto', parse_nikto(out_file))
        elif tool == 'amass':
            out_file = os.path.join(output_dir, 'amass_subdomains.txt')
            if run_command(['amass', 'enum', '-d', target, '-o', out_file], out_file):
                return ('amass', parse_amass(out_file))
        elif tool == 'sqlmap':
            sqlmap_dir = os.path.join(output_dir, 'sqlmap')
            os.makedirs(sqlmap_dir, exist_ok=True)
            if run_command(['sqlmap', '-u', f'https://{target}', '--batch', '--level=1', '--risk=1', f'--output-dir={sqlmap_dir}'],
                           os.path.join(sqlmap_dir, 'sqlmap_output.txt')):
                return ('sqlmap', {"scan_completed": True})
        elif tool == 'wfuzz':
            wordlist = '/usr/share/wfuzz/wordlists/common-params.txt'
            out_file = os.path.join(output_dir, 'wfuzz_params.txt')
            if not os.path.exists(wordlist):
                logging.warning(f"Wfuzz wordlist not found: {wordlist}, skipping.")
                return ('wfuzz', {"skipped": True})
            if run_command(['wfuzz', '-c', '-z', f'file,{wordlist}', '--hc', '404', f'https://{target}/FUZZ'], out_file):
                return ('wfuzz', parse_wfuzz(out_file))
    except Exception as e:
        logging.error(f"Error running {tool}: {e}")
    return (tool, {"error": True})

def main():
    parser = argparse.ArgumentParser(description="Powerful Automated Web Recon Tool")
    parser.add_argument('-t', '--target', required=True, help='Target domain or IP')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('-m', '--modules', default='nmap,dirsearch,nikto,amass,sqlmap,wfuzz',
                        help='Comma separated list of tools to run')
    args = parser.parse_args()

    target = args.target
    output_dir = args.output or f"recon_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_dir, exist_ok=True)

    tools = [t.strip() for t in args.modules.split(',')]

    logging.info(f"Starting recon on {target} with tools: {tools}")
    logging.info(f"Output directory: {output_dir}")

    results = {}

    # Run tools concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tools)) as executor:
        future_to_tool = {executor.submit(run_tool, tool, target, output_dir): tool for tool in tools}

        for future in concurrent.futures.as_completed(future_to_tool):
            tool = future_to_tool[future]
            try:
                tool_name, data = future.result()
                results[tool_name] = data
                logging.info(f"Completed {tool_name} scan")
            except Exception as exc:
                logging.error(f"{tool} generated an exception: {exc}")

    summary_data = {
        "target": target,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": results
    }

    # Save raw JSON results
    json_path = os.path.join(output_dir, "results.json")
    with open(json_path, "w") as jf:
        json.dump(summary_data, jf, indent=2)
    logging.info(f"Saved JSON results to {json_path}")

    # Generate HTML report
    generate_html_report(summary_data, output_dir)

    logging.info("Recon complete!")

if __name__ == "__main__":
    main()
