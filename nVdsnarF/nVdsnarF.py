#!/usr/bin/env python3
from __future__ import annotations

import json, re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Union

import typer
from colorama import Fore, Style, init as colorama_init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(add_completion=False)
colorama_init()
console = Console()

BANNER = f"""{Fore.CYAN}
#################################################################
#                                                               #
#       ____   ____ .____________                  ___________  #
#    ___\\   \\ /   /_| _/   _____/ ____ _____ ______\\_   _____/  #
#   /    \\   Y   / __ |\\_____  \\ /     \\__   \\_  __ \\    __)    #
#  |   |  \\     / /_/ |/        \\   |  \\/ __ \\|  | \\/     \\     #
#  |___|  /\\___/\\____ /_______  /___|  (____  /__|  \\___  /     #
#       \\/           \\/       \\/     \\/     \\/          \\/      #
#                                                               #
#################################################################
{Style.RESET_ALL}
nVdSnarF - XML + NVD JSON 2.0 edition
Author: www.github.com/Pau00
"""

# ----------------------------- Data model -----------------------------

@dataclass
class Finding:
    cve: str
    published: str
    modified: str
    severity: str
    cvss_score: str
    vendor: str
    product: str
    versions: List[str]
    description: str
    refs: List[str]
    source_format: str  # "XML" or "NVD_JSON_2.0"

Matcher = Callable[[str], bool]

# ----------------------------- Matching -----------------------------

def make_matcher(exact: str, contains: str, regex: str, field: str, case_sensitive: bool) -> Optional[Matcher]:
    flags = 0 if case_sensitive else re.IGNORECASE
    if regex:
        try:
            rx = re.compile(regex, flags)
        except re.error as e:
            raise typer.BadParameter(f"Invalid {field} regex: {e}") from e
        return lambda v: bool(rx.search(v or ""))
    if contains:
        if case_sensitive:
            return lambda v: contains in (v or "")
        needle = contains.lower()
        return lambda v: needle in (v or "").lower()
    if exact:
        return lambda v: (v or "") == exact
    return None

# ----------------------------- Severity color + legend -----------------------------

def severity_style(sev: str, score: str = "") -> str:
    s = (sev or "").strip().lower()
    if s == "critical": return "bold red"
    if s == "high": return "red"
    if s in ("medium", "moderate"): return "yellow"
    if s == "low": return "green"
    try:
        sc = float(score)
        if sc >= 9: return "bold red"
        if sc >= 7: return "red"
        if sc >= 4: return "yellow"
        return "green"
    except Exception:
        return "white"

def render_severity_legend() -> None:
    console.print()
    console.print("[bold]Severity Legend:[/bold] [bold red]Critical[/bold red]  [red]High[/red]  [yellow]Medium[/yellow]  [green]Low[/green]")

# ----------------------------- File detection + header gist -----------------------------

def sniff_format(path: Path) -> str:
    # Fast peek: only read a small prefix (avoids loading huge files)
    with path.open("rb") as f:
        head = f.read(8192)
    s = head.lstrip()
    if not s: return "UNKNOWN"
    if s.startswith(b"<"): return "XML"
    if s[:1] in (b"{", b"["):
        try:
            d = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            return "NVD_JSON_2.0" if isinstance(d, dict) and "vulnerabilities" in d and ("format" in d or "version" in d) else "JSON"
        except Exception:
            return "JSON"
    return "UNKNOWN"

def print_header_gist(fmt: str, path: Path, data_or_root: Union[Dict, ET.Element]) -> None:
    if fmt == "NVD_JSON_2.0" and isinstance(data_or_root, dict):
        d = data_or_root
        console.print(Panel(
            "\n".join([
                f"[bold]File:[/bold] {path}",
                f"[bold]Format:[/bold] {d.get('format','')}  [bold]Version:[/bold] {d.get('version','')}",
                f"[bold]Timestamp:[/bold] {d.get('timestamp','')}",
                f"[bold]StartIndex:[/bold] {d.get('startIndex','')}  [bold]ResultsPerPage:[/bold] {d.get('resultsPerPage','')}  [bold]TotalResults:[/bold] {d.get('totalResults','')}",
                f"[bold]Vulnerabilities array:[/bold] {len(d.get('vulnerabilities') or [])}",
            ]),
            title="Input Summary", expand=False
        ))
        return
    if fmt == "XML" and isinstance(data_or_root, ET.Element):
        root = data_or_root
        console.print(Panel(
            "\n".join([
                f"[bold]File:[/bold] {path}",
                "[bold]Format:[/bold] XML",
                f"[bold]Root tag:[/bold] {root.tag}",
                f"[bold]CVE entries:[/bold] {len(root.findall('.//entry[@type=\"CVE\"]'))}",
            ]),
            title="Input Summary", expand=False
        ))
        return
    console.print(Panel(f"[bold]File:[/bold] {path}\n[bold]Format:[/bold] {fmt}", title="Input Summary", expand=False))

# ----------------------------- XML helpers -----------------------------

def strip_ns(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root

def txt(el: Optional[ET.Element]) -> str:
    return (el.text or "").strip() if el is not None else ""

def extract_versions_xml(prod: ET.Element, version: str) -> List[str]:
    nodes = prod.findall(f"./vers[@num='{version}']") if version else prod.findall("./vers[@num]")
    return [n.attrib.get("num","").strip() for n in nodes if n.attrib.get("num")]

def extract_refs_xml(entry: ET.Element) -> List[str]:
    seen, out = set(), []
    for r in entry.findall("./refs/ref"):
        u = (r.attrib.get("url") or "").strip()
        if u and u not in seen:
            seen.add(u); out.append(u)
    return out

def search_findings_xml(
    root: ET.Element,
    vendor_exact: str = "", product_exact: str = "", version: str = "",
    vendor_contains: str = "", product_contains: str = "",
    vendor_regex: str = "", product_regex: str = "",
    case_sensitive: bool = False,
) -> List[Finding]:
    vmatch = make_matcher(vendor_exact, vendor_contains, vendor_regex, "vendor", case_sensitive)
    pmatch = make_matcher(product_exact, product_contains, product_regex, "product", case_sensitive)

    out: List[Finding] = []
    for entry in root.findall(".//entry[@type='CVE']"):
        prods = entry.findall("./vuln_soft/prod")
        if not prods: continue

        desc = txt(entry.find("./desc/descript[@source='cve']"))
        refs = extract_refs_xml(entry)

        for p in prods:
            vend = p.attrib.get("vendor","") or ""
            prod = p.attrib.get("name","") or ""
            if vmatch and not vmatch(vend): continue
            if pmatch and not pmatch(prod): continue

            vers = extract_versions_xml(p, version)
            if version and not vers: continue

            out.append(Finding(
                cve=entry.attrib.get("name",""),
                published=entry.attrib.get("published",""),
                modified=entry.attrib.get("modified",""),
                severity=str(entry.attrib.get("severity","")).upper(),
                cvss_score=str(entry.attrib.get("CVSS_score", entry.attrib.get("CVSS_base_score",""))),
                vendor=vend, product=prod, versions=vers,
                description=desc, refs=refs,
                source_format="XML",
            ))
    return out

# ----------------------------- NVD JSON 2.0 helpers -----------------------------

def load_json(path: Path) -> Dict:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))

def pick_description_json(cve: Dict, lang: str = "en") -> str:
    for d in (cve.get("descriptions") or []):
        if d.get("lang") == lang and d.get("value"): return str(d["value"]).strip()
    for d in (cve.get("descriptions") or []):
        if d.get("value"): return str(d["value"]).strip()
    return ""

def extract_refs_json(cve: Dict) -> List[str]:
    seen, out = set(), []
    for r in (cve.get("references") or []):
        u = (r.get("url") or "").strip()
        if u and u not in seen:
            seen.add(u); out.append(u)
    return out

def iter_cpe_matches(node: Dict) -> Iterable[Dict]:
    for m in (node.get("cpeMatch") or []):
        if isinstance(m, dict): yield m
    for child in (node.get("children") or []):
        if isinstance(child, dict): yield from iter_cpe_matches(child)

def extract_cpes_json(cve: Dict) -> List[str]:
    seen, out = set(), []
    for cfg in (cve.get("configurations") or []):
        for node in (cfg.get("nodes") or []):
            if not isinstance(node, dict): continue
            for m in iter_cpe_matches(node):
                crit = (m.get("criteria") or "").strip()
                if crit.startswith("cpe:2.3:") and crit not in seen:
                    seen.add(crit); out.append(crit)
    return out

def parse_cpe23(cpe: str) -> Optional[Tuple[str, str, str]]:
    if not cpe.startswith("cpe:2.3:"): return None
    parts = cpe.split(":")
    return (parts[3] or "", parts[4] or "", parts[5] or "") if len(parts) >= 6 else None

def pick_best_metric_json(cve: Dict) -> Tuple[str, str]:
    metrics = cve.get("metrics") or {}
    for m in (metrics.get("cvssMetricV31") or []):
        if m.get("type") == "Primary" and (m.get("source","").lower() == "nvd@nist.gov"):
            cvss = m.get("cvssData") or {}
            sc = cvss.get("baseScore")
            if isinstance(sc, (int, float)):
                return f"{sc:.1f}", str(cvss.get("baseSeverity","")).upper()

    best_score: Optional[float] = None
    best_sev = ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in (metrics.get(key) or []):
            cvss = m.get("cvssData") or {}
            sc = cvss.get("baseScore")
            if not isinstance(sc, (int, float)): continue
            if best_score is None or float(sc) > best_score:
                best_score = float(sc)
                best_sev = str(cvss.get("baseSeverity") or m.get("baseSeverity") or "").upper()
    return (f"{best_score:.1f}", best_sev) if best_score is not None else ("", "")

def search_findings_json(
    data: Dict,
    vendor_exact: str = "", product_exact: str = "", version: str = "",
    vendor_contains: str = "", product_contains: str = "",
    vendor_regex: str = "", product_regex: str = "",
    case_sensitive: bool = False,
) -> List[Finding]:
    vmatch = make_matcher(vendor_exact, vendor_contains, vendor_regex, "vendor", case_sensitive)
    pmatch = make_matcher(product_exact, product_contains, product_regex, "product", case_sensitive)

    out: List[Finding] = []
    want_filter = any([vendor_exact, product_exact, version, vendor_contains, product_contains, vendor_regex, product_regex])

    for item in (data.get("vulnerabilities") or []):
        cve = (item or {}).get("cve") or {}
        cve_id = cve.get("id") or ""
        if not cve_id: continue

        tuples = [t for t in (parse_cpe23(c) for c in extract_cpes_json(cve)) if t]
        matched: List[Tuple[str, str, str]] = []
        for vend, prod, ver in tuples:
            if vmatch and not vmatch(vend): continue
            if pmatch and not pmatch(prod): continue
            if version and ver != version: continue
            matched.append((vend, prod, ver))

        if want_filter and not matched: continue

        score, sev = pick_best_metric_json(cve)
        desc = pick_description_json(cve, "en")
        refs = extract_refs_json(cve)

        dv = dp = ""
        vers: List[str] = []
        if matched:
            dv, dp, _ = matched[0]
            vers = sorted({v for _, _, v in matched if v and v not in ("*", "-", "NA")})

        out.append(Finding(
            cve=cve_id,
            published=cve.get("published","") or "",
            modified=cve.get("lastModified","") or "",
            severity=sev, cvss_score=score,
            vendor=dv, product=dp, versions=vers,
            description=desc, refs=refs,
            source_format="NVD_JSON_2.0",
        ))
    return out

# ----------------------------- Output -----------------------------

def render_table(findings: List[Finding], show_legend: bool = True) -> None:
    t = Table(title="nVdSnarF Results", show_lines=False)
    for col, style, overflow in [
        ("CVE", "bold", None),
        ("Severity", None, None),
        ("CVSS", None, None),
        ("Vendor", None, None),
        ("Product", None, None),
        ("Versions", None, None),
        ("Published", None, None),
        ("Modified", None, None),
        ("Description", None, "fold"),
    ]:
        t.add_column(col, style=style or "", overflow=overflow or "ellipsis")

    for f in findings:
        st = severity_style(f.severity, f.cvss_score)
        t.add_row(
            f.cve,
            f"[{st}]{f.severity or 'N/A'}[/{st}]",
            f"[{st}]{f.cvss_score or 'N/A'}[/{st}]",
            f.vendor, f.product,
            ", ".join(f.versions) if f.versions else "",
            f.published, f.modified,
            f.description,
        )

    console.print(t)
    console.print(f"[magenta]Matches:[/magenta] {len(findings)}")
    if show_legend: render_severity_legend()

def dump_json(findings: List[Finding], out: Optional[Path], jsonl: bool) -> None:
    if out: out.parent.mkdir(parents=True, exist_ok=True)
    if jsonl:
        payload = "\n".join(json.dumps(asdict(f), ensure_ascii=False, separators=(",", ":")) for f in findings) + ("\n" if findings else "")
    else:
        payload = json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2) + "\n"
    if out:
        out.write_text(payload, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {len(findings)} record(s) to {out}")
    else:
        print(payload, end="")

# ----------------------------- CLI -----------------------------

@app.command()
def search(
    file: Path = typer.Option(..., "-f", "--file", exists=True, readable=True, help="Input file (XML or NVD JSON 2.0)"),
    vendor: str = typer.Option("", "-v", "--vendor", help="Exact vendor match (XML prod@vendor OR JSON CPE vendor)"),
    product: str = typer.Option("", "-p", "--product", help="Exact product match (XML prod@name OR JSON CPE product)"),
    version: str = typer.Option("", "-n", "--version", help="Exact version match (XML vers@num OR JSON CPE version)"),
    vendor_contains: str = typer.Option("", "--vendor-contains", help="Substring match for vendor"),
    product_contains: str = typer.Option("", "--product-contains", help="Substring match for product"),
    vendor_regex: str = typer.Option("", "--vendor-regex", help="Regex match for vendor"),
    product_regex: str = typer.Option("", "--product-regex", help="Regex match for product"),
    case_sensitive: bool = typer.Option(False, "--case-sensitive", help="Make contains/regex case-sensitive"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Disable banner"),
    no_legend: bool = typer.Option(False, "--no-legend", help="Disable severity legend footer"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON array output"),
    jsonl_out: bool = typer.Option(False, "--jsonl", help="Emit JSONL output"),
    out: Optional[Path] = typer.Option(None, "--out", help="Write JSON/JSONL to file (else stdout)"),
) -> None:
    if not no_banner: typer.echo(BANNER)
    if json_out and jsonl_out:
        console.print("[red]Choose only one:[/red] --json OR --jsonl"); raise typer.Exit(2)
    if not any([vendor, product, version, vendor_contains, product_contains, vendor_regex, product_regex]):
        console.print("[red]Provide at least one filter (exact/contains/regex/version).[/red]"); raise typer.Exit(2)

    fmt = sniff_format(file)
    if fmt == "XML":
        root = strip_ns(ET.parse(str(file)).getroot())
        print_header_gist("XML", file, root)
        findings = search_findings_xml(root, vendor, product, version, vendor_contains, product_contains, vendor_regex, product_regex, case_sensitive)
    elif fmt == "NVD_JSON_2.0":
        data = load_json(file)
        print_header_gist("NVD_JSON_2.0", file, data)
        findings = search_findings_json(data, vendor, product, version, vendor_contains, product_contains, vendor_regex, product_regex, case_sensitive)
    else:
        console.print(f"[red]Unsupported/unknown input format for file:[/red] {file}"); raise typer.Exit(2)

    if not json_out and not jsonl_out:
        render_table(findings, show_legend=not no_legend)
    else:
        dump_json(findings, out=out, jsonl=jsonl_out)

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo(BANNER)
        typer.echo("Examples:")
        typer.echo("  python3 nVdSnarF.py search -f nvdcve-modified.xml -v siemens -p hinet_lp")
        typer.echo("  python3 nVdSnarF.py search -f nvd.json --vendor-contains code --product-contains chat")
        raise typer.Exit(0)

if __name__ == "__main__":
    app()
