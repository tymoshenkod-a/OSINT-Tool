import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import whois
import socket
import nmap
from datetime import datetime


class OSINTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT & Cyber Intelligence Tool")
        self.root.geometry("900x700")

        # Налаштування стилів
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Courier New', 10))
        self.style.configure('TButton', font=('Courier New', 10))
        self.style.configure('TNotebook.Tab', font=('Courier New', 10, 'bold'))

        # Створення вкладок
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)

        # Вкладка OSINT
        self.osint_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.osint_frame, text='OSINT Tools')
        self.setup_osint_tab()

        # Вкладка CVE Analysis
        self.cve_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cve_frame, text='CVE Analysis')
        self.setup_cve_tab()

        # Вкладка Report
        self.report_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.report_frame, text='Report Generator')
        self.setup_report_tab()

        # Статус бар
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief='sunken')
        self.status_bar.pack(fill='x')
        self.update_status("Ready")

    def update_status(self, message):
        self.status_var.set(f"Status: {message}")
        self.root.update_idletasks()

    def setup_osint_tab(self):
        # Domain Info Секція
        domain_frame = ttk.LabelFrame(self.osint_frame, text="Domain Information", padding=10)
        domain_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(domain_frame, text="Domain:").grid(row=0, column=0, sticky='w')
        self.domain_entry = ttk.Entry(domain_frame, width=40)
        self.domain_entry.grid(row=0, column=1, padx=5)

        ttk.Button(domain_frame, text="Get Info", command=self.get_domain_info).grid(row=0, column=2, padx=5)

        self.domain_result = tk.Text(domain_frame, height=10, width=80, wrap='word')
        self.domain_result.grid(row=1, column=0, columnspan=3, pady=5)

        # IP Analysis Секція
        ip_frame = ttk.LabelFrame(self.osint_frame, text="IP Analysis", padding=10)
        ip_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(ip_frame, text="IP Address:").grid(row=0, column=0, sticky='w')
        self.ip_entry = ttk.Entry(ip_frame, width=40)
        self.ip_entry.grid(row=0, column=1, padx=5)

        ttk.Button(ip_frame, text="Scan Ports", command=self.scan_ports).grid(row=0, column=2, padx=5)

        self.port_result = tk.Text(ip_frame, height=10, width=80, wrap='word')
        self.port_result.grid(row=1, column=0, columnspan=3, pady=5)

    def setup_cve_tab(self):
        # CVE Search Секція
        cve_frame = ttk.LabelFrame(self.cve_frame, text="CVE Search", padding=10)
        cve_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(cve_frame, text="CVE ID (e.g., CVE-2023-1234):").grid(row=0, column=0, sticky='w')
        self.cve_entry = ttk.Entry(cve_frame, width=40)
        self.cve_entry.grid(row=0, column=1, padx=5)

        ttk.Button(cve_frame, text="Search CVE", command=self.search_cve).grid(row=0, column=2, padx=5)

        self.cve_result = tk.Text(cve_frame, height=15, width=80, wrap='word')
        self.cve_result.grid(row=1, column=0, columnspan=3, pady=5)

        # Vulnerability Assessment Секція
        vuln_frame = ttk.LabelFrame(self.cve_frame, text="Software Vulnerability Check", padding=10)
        vuln_frame.pack(fill='x', padx=5, pady=5)

        ttk.Label(vuln_frame, text="Software Name:").grid(row=0, column=0, sticky='w')
        self.software_entry = ttk.Entry(vuln_frame, width=30)
        self.software_entry.grid(row=0, column=1, padx=5)

        ttk.Label(vuln_frame, text="Version:").grid(row=0, column=2, sticky='w')
        self.version_entry = ttk.Entry(vuln_frame, width=15)
        self.version_entry.grid(row=0, column=3, padx=5)

        ttk.Button(vuln_frame, text="Check Vulnerabilities", command=self.check_software_vuln).grid(row=0, column=4, padx=5)

        self.vuln_result = tk.Text(vuln_frame, height=10, width=80, wrap='word')
        self.vuln_result.grid(row=1, column=0, columnspan=5, pady=5)

    def setup_report_tab(self):
        report_frame = ttk.LabelFrame(self.report_frame, text="Report Options", padding=10)
        report_frame.pack(fill='both', expand=True, padx=5, pady=5)

        ttk.Label(report_frame, text="Report Title:").grid(row=0, column=0, sticky='w')
        self.report_title = ttk.Entry(report_frame, width=40)
        self.report_title.grid(row=0, column=1, padx=5, pady=5, sticky='w')

        ttk.Label(report_frame, text="Report Type:").grid(row=1, column=0, sticky='w')
        self.report_type = ttk.Combobox(report_frame,
                                        values=["Full Report", "Domain Analysis", "Vulnerability Assessment"])
        self.report_type.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        self.report_type.current(0)

        ttk.Button(report_frame, text="Generate Report", command=self.generate_report).grid(row=2, column=0, columnspan=2, pady=10)

        self.report_display = tk.Text(report_frame, height=20, width=80, wrap='word')
        self.report_display.grid(row=3, column=0, columnspan=2, pady=5)

        ttk.Button(report_frame, text="Save Report", command=self.save_report).grid(row=4, column=0, pady=5)
        ttk.Button(report_frame, text="Clear", command=self.clear_report).grid(row=4, column=1, pady=5)

    def get_domain_info(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name")
            return

        try:
            self.update_status(f"Fetching WHOIS data for {domain}...")
            domain_info = whois.whois(domain)

            try:
                ip_address = socket.gethostbyname(domain)
            except socket.gaierror:
                ip_address = "Could not resolve IP"

            result = f"=== Domain Information for {domain} ===\n"
            result += f"IP Address: {ip_address}\n\n"
            result += "WHOIS Information:\n"

            for key, value in domain_info.items():
                if not key.startswith('_') and value:
                    if isinstance(value, list):
                        value = ', '.join(str(v) for v in value)
                    result += f"{key}: {value}\n"

            self.domain_result.delete(1.0, tk.END)
            self.domain_result.insert(tk.END, result)
            self.update_status(f"Successfully retrieved domain info for {domain}")

        except Exception as e:
            self.update_status("Error fetching domain info")
            messagebox.showerror("Error", f"Failed to get domain information: {str(e)}")

    def is_valid_ip(self, ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True

    def scan_ports(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address")
            return

        try:
            self.update_status(f"Scanning ports for {ip}...")

            if not self.is_valid_ip(ip):
                messagebox.showerror("Error", "Invalid IPv4 address")
                return

            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-F')

            result = f"=== Port Scan Results for {ip} ===\n\n"

            if ip in nm.all_hosts():
                host = nm[ip]
                result += f"Host Status: {host.state()}\n\n"

                for proto in host.all_protocols():
                    result += f"Protocol: {proto.upper()}\n"
                    ports = host[proto].keys()
                    sorted_ports = sorted(ports)

                    for port in sorted_ports:
                        port_info = host[proto][port]
                        result += f"Port: {port}\tState: {port_info['state']}\tService: {port_info['name']}\n"
            else:
                result += "No open ports found or host is down\n"

            self.port_result.delete(1.0, tk.END)
            self.port_result.insert(tk.END, result)
            self.update_status(f"Port scan completed for {ip}")

        except Exception as e:
            self.update_status("Error during port scan")
            messagebox.showerror("Error", f"Failed to scan ports: {str(e)}")

    def search_cve(self):
        cve_id = self.cve_entry.get().strip().upper()
        if not cve_id.startswith('CVE-'):
            messagebox.showerror("Error", "Please enter a valid CVE ID (e.g., CVE-2023-1234)")
            return

        try:
            self.update_status(f"Searching for {cve_id}...")
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url)

            if response.status_code == 200:
                data = response.json()

                if 'vulnerabilities' in data and data['vulnerabilities']:
                    cve_data = data['vulnerabilities'][0]['cve']

                    result = f"=== {cve_id} Details ===\n\n"
                    result += f"Published: {cve_data.get('published', 'N/A')}\n"
                    result += f"Last Modified: {cve_data.get('lastModified', 'N/A')}\n\n"

                    # Описи
                    descriptions = cve_data.get('descriptions', [])
                    for desc in descriptions:
                        if desc['lang'] == 'en':
                            result += f"Description: {desc['value']}\n\n"

                    # Метрики
                    metrics = cve_data.get('metrics', {})
                    if metrics:
                        result += "Metrics:\n"
                        for metric_type, metric_data in metrics.items():
                            for item in metric_data:
                                result += f"- {metric_type}:\n"
                                if 'cvssData' in item:
                                    cvss = item['cvssData']
                                    result += f"  Base Score: {cvss.get('baseScore', 'N/A')}\n"
                                    result += f"  Severity: {cvss.get('baseSeverity', 'N/A')}\n"
                                    result += f"  Vector: {cvss.get('vectorString', 'N/A')}\n"

                    self.cve_result.delete(1.0, tk.END)
                    self.cve_result.insert(tk.END, result)
                    self.update_status(f"Successfully retrieved {cve_id} details")
                else:
                    messagebox.showinfo("Info", f"No details found for {cve_id}")
            else:
                messagebox.showerror("Error", f"Failed to fetch CVE data. Status code: {response.status_code}")
                self.update_status("Error fetching CVE data")

        except Exception as e:
            self.update_status("Error during CVE search")
            messagebox.showerror("Error", f"Failed to search CVE: {str(e)}")

    def check_software_vuln(self):
        software = self.software_entry.get().strip()
        version = self.version_entry.get().strip()

        if not software or not version:
            messagebox.showerror("Error", "Please enter both software name and version")
            return

        try:
            self.update_status(f"Checking vulnerabilities for {software} {version}...")

            # Пошуковий запит до NVD API
            query = f"{software} {version}"
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"

            # Відправка запиту к API
            response = requests.get(url)
            result = f"=== Vulnerability Assessment for {software} {version} ===\n\n"

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []

                # Отримуємо CVE з відповіді
                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities']:
                        cve_id = vuln['cve']['id']
                        description = next(
                            (desc['value'] for desc in vuln['cve']['descriptions']
                             if desc['lang'] == 'en'), "No description available"
                        )
                        vulnerabilities.append(f"{cve_id}: {description}")

                # Формуємо результат
                if vulnerabilities:
                    result += f"Found {len(vulnerabilities)} vulnerabilities:\n"
                    for vuln in vulnerabilities:
                        result += f"- {vuln}\n"
                    result += "\nRecommendation: Update to the latest version immediately."
                else:
                    result += "No known vulnerabilities found.\n"
                    result += "Recommendation: Ensure you're using the latest stable version."

            else:
                result += "Error: Failed to fetch vulnerability data"

            self.vuln_result.delete(1.0, tk.END)
            self.vuln_result.insert(tk.END, result)
            self.update_status(f"Check completed for {software} {version}")

        except Exception as e:
            self.update_status("Error during vulnerability check")
            messagebox.showerror("Error", f"Failed to check vulnerabilities: {str(e)}")

    def generate_report(self):
        report_title = self.report_title.get().strip() or "OSINT and Vulnerability Report"
        report_type = self.report_type.get()

        try:
            self.update_status("Generating report...")

            report = f"=== {report_title} ===\n"
            report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += f"Report Type: {report_type}\n\n"

            if report_type in ["Full Report", "Domain Analysis"]:
                domain = self.domain_entry.get().strip()
                if domain:
                    report += "=== Domain Information ===\n"
                    report += self.domain_result.get(1.0, tk.END) + "\n"
                else:
                    report += "=== Domain Information ===\nNo domain data available\n\n"

                ip = self.ip_entry.get().strip()
                if ip:
                    report += "=== Port Scan Results ===\n"
                    report += self.port_result.get(1.0, tk.END) + "\n"
                else:
                    report += "=== Port Scan Results ===\nNo IP scan data available\n\n"

            if report_type in ["Full Report", "Vulnerability Assessment"]:
                cve = self.cve_entry.get().strip()
                if cve:
                    report += "=== CVE Details ===\n"
                    report += self.cve_result.get(1.0, tk.END) + "\n"
                else:
                    report += "=== CVE Details ===\nNo CVE data available\n\n"

                software = self.software_entry.get().strip()
                if software:
                    report += "=== Vulnerability Assessment ===\n"
                    report += self.vuln_result.get(1.0, tk.END) + "\n"
                else:
                    report += "=== Vulnerability Assessment ===\nNo software assessment data available\n\n"

            report += "\n=== Recommendations ===\n"
            report += "1. Keep all software updated to the latest stable versions\n"
            report += "2. Regularly monitor for new security advisories\n"
            report += "3. Implement proper firewall rules based on port scan results\n"
            report += "4. Consider using security monitoring tools for continuous assessment\n"

            self.report_display.delete(1.0, tk.END)
            self.report_display.insert(tk.END, report)
            self.update_status("Report generated successfully")

        except Exception as e:
            self.update_status("Error generating report")
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")

    def save_report(self):
        report_text = self.report_display.get(1.0, tk.END)
        if not report_text.strip():
            messagebox.showerror("Error", "No report content to save")
            return

        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
                title="Save Report"
            )

            if file_path:
                with open(file_path, 'w') as f:
                    f.write(report_text)
                self.update_status(f"Report saved to {file_path}")
                messagebox.showinfo("Success", "Report saved successfully")

        except Exception as e:
            self.update_status("Error saving report")
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")

    def clear_report(self):
        self.report_display.delete(1.0, tk.END)
        self.update_status("Report cleared")


if __name__ == "__main__":
    root = tk.Tk()
    app = OSINTApp(root)
    root.mainloop()