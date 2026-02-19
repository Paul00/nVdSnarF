
---

````markdown
# nVdSnarF

```text
#################################################################
#                                                               #
#       ____   ____ .____________                  ___________  #
#    ___\   \ /   /_| _/   _____/ ____ _____ ______\_   _____/  #
#   /    \   Y   / __ |\_____  \ /     \__   \_  __ \    __)    #
#  |   |  \     / /_/ |/        \   |  \/ __ \|  | \/     \     #
#  |___|  /\___/\____ /_______  /___|  (____  /__|  \___  /     #
#       \/           \/       \/     \/     \/          \/      #
#                                                               #
#################################################################
````

**nVdSnarF** is a fast, flexible CVE search utility for **NVD XML** and **NVD JSON 2.0** vulnerability feeds, built as a Python CLI with rich table output, advanced matching, and export options.
Author: **[www.github.com/Pau00](http://www.github.com/Pau00)**

---

## 🔍 Supported Input

* 📌 **NVD XML** (legacy NVD feeds)
* 📌 **NVD JSON 2.0** (modern NVD formats with `vulnerabilities` array)
* Auto-detection of format with summary header prior to search

---

## 🚀 Features

* Exact, substring, and regex matching on **vendor** and **product**
* Optional **version** filtering
* Case-insensitive (default) or **case-sensitive** matching
* Rich console table with **severity coloring**
* Export results to **JSON** or **JSONL**
* Optional severity legend
* Unified schema for XML + JSON data

---

## 🛠️ Installation

```bash
git clone https://github.com/Pau00/nVdSnarF.git
cd nVdSnarF

python3 -m venv venv
source venv/bin/activate

pip install -U pip
pip install typer rich colorama
```

---

## 📥 Usage

### Basic XML Search

```bash
python3 nVdSnarF.py search -f nvdcve-2025.xml -v siemens -p simatic
```

### JSON 2.0 Search

```bash
python3 nVdSnarF.py search -f nvd.json --vendor-contains code --product-regex "chat|inventory"
```

### Version Match

```bash
python3 nVdSnarF.py search -f nvd.json -v code -p chat_system -n 1.0
```

---

## 📊 Output Options

* **Default**: Rich table with CVE, severity, CVSS, vendor, product, versions, published/modified dates, and description
* **JSON**:

```bash
--json
```

* **JSON Lines**:

```bash
--jsonl
```

* **Write to file**:

```bash
--out results.jsonl
```

---

## 💡 Filters

* `--vendor`, `--product` — exact match
* `--vendor-contains`, `--product-contains` — substring
* `--vendor-regex`, `--product-regex` — regex
* `--case-sensitive` — toggle case sensitivity

Example:

```bash
python3 nVdSnarF.py search -f nvd.json --vendor-contains siem --product-regex ".*s7.*"
```

---

## 📋 Sample Output

```
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ CVE           ┃ Severity ┃ CVSS  ┃ Vendor   ┃ Product          ┃ Versions   ┃ Published     ┃ Modified      ┃ Description ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
┃ CVE-2025-0168 ┃ [red]HIGH[/red]    ┃ [red]7.5[/red]  ┃ code   ┃ job_recruitment   ┃ 1.0        ┃ 2025-01-01   ┃ 2025-02-25   ┃ SQL injection…┃
...
└───────────────┴──────────┴───────┴──────────┴──────────────────┴────────────┴──────────────┴──────────────┴─────────────┘
```

---

## ➿ How Matches Work

Matching applies **across any supplied CPE values** for JSON 2.0 or `<prod vendor=… name=…>` for XML — so multiple CPE entries won’t be missed.

---

## ⚠️ Tips & Gotchas

* If you get **zero matches**, try `--vendor-contains` + `--product-contains` first.
* XML filters are matched against node attributes exactly unless using `--contains` or `--regex`.
* JSON 2.0 CPE parsing relies on common 2.3 CPE fields.

---

## 🧠 Internals

* Parses NVD JSON `configurations` to extract CPE tuples
* Picks best CVSS score (NVD primary v3.1 if available, else highest)
* Grouping and filters done in-memory for flexible querying
* Exportable results fit modern security pipelines

---

## 📦 Export Schema

Each finding is structured like:

```json
{
  "cve": "CVE-2025-0168",
  "published": "2025-01-01T14:15:23.590",
  "modified": "2025-02-25T21:26:07.113",
  "severity": "HIGH",
  "cvss_score": "7.5",
  "vendor": "code",
  "product": "job_recruitment",
  "versions": ["1.0"],
  "description": "A vulnerability …",
  "refs": ["https://…","https://…"],
  "source_format": "NVD_JSON_2.0"
}
```

---

## 📚 Contribution

Contributions are welcome!
Feel free to file issues, suggest improvements, or submit pull requests.

---

## ⚖️ License

MIT License — Use it, change it, and make it yours. ([GitHub][1])

---

