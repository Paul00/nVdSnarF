# nVdSnarF

```
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
```

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

nVdSnarF - XML + NVD JSON 2.0 edition
Author: www.github.com/Pau00

╭───────────────────── Input Summary ─────────────────────╮
│ File: nvdcve-2.0-2026.json                              │
│ Format: NVD_CVE  Version: 2.0                           │
│ Timestamp: 2026-02-18T03:00:00.4990529                  │
│ StartIndex: 0  ResultsPerPage: 3627  TotalResults: 3627 │
│ Vulnerabilities array: 3627                             │
╰─────────────────────────────────────────────────────────╯
                                                                                                                               nVdSnarF Results                                                                                                                                
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CVE            ┃ Severity ┃ CVSS ┃ Vendor   ┃ Product ┃ Versions ┃ Published               ┃ Modified                ┃ Description                                                                                                                                          ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2026-22028 │ MEDIUM   │ 6.1  │ preactjs │ preact  │          │ 2026-01-08T15:15:44.853 │ 2026-01-12T18:58:38.207 │ Preact, a lightweight web development framework, JSON serialization protection to prevent Virtual DOM elements from being constructed from arbitrary │
│                │          │      │          │         │          │                         │                         │ JSON. A regression introduced in Preact 10.26.5 caused this protection to be softened. In applications where values from JSON payloads are assumed   │
│                │          │      │          │         │          │                         │                         │ to be strings and passed unmodified to Preact as children, a specially-crafted JSON payload could be constructed that would be incorrectly treated   │
│                │          │      │          │         │          │                         │                         │ as a valid VNode. When this chain of failures occurs it can result in HTML injection, which can allow arbitrary script execution if not mitigated by │
│                │          │      │          │         │          │                         │                         │ CSP or other means. Applications using affected Preact versions are vulnerable if they meet all of the following conditions: first, pass unmodified, │
│                │          │      │          │         │          │                         │                         │ unsanitized values from user-modifiable data sources (APIs, databases, local storage, etc.) directly into the render tree; second assume these       │
│                │          │      │          │         │          │                         │                         │ values are strings but the data source could return actual JavaScript objects instead of JSON strings; and third, the data source either fails to    │
│                │          │      │          │         │          │                         │                         │ perform type sanitization AND blindly stores/returns raw objects interchangeably with strings, OR is compromised (e.g., poisoned local storage,      │
│                │          │      │          │         │          │                         │                         │ filesystem, or database). Versions 10.26.10, 10.27.3, and 10.28.2 patch the issue. The patch versions restore the previous strict equality checks    │
│                │          │      │          │         │          │                         │                         │ that prevent JSON-parsed objects from being treated as valid VNodes. Other mitigations are available for those who cannot immediately upgrade.       │
│                │          │      │          │         │          │                         │                         │ Validate input types, cast or validate network data, sanitize external data, and use Content Security Policy (CSP).                                  │
└────────────────┴──────────┴──────┴──────────┴─────────┴──────────┴─────────────────────────┴─────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
Matches: 1

Severity Legend: Critical  High  Medium  Low
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

## 🙏 Credits

Crafted with care by [Paul00](https://github.com/Paul00)

---

## ⚖️ License

MIT License – do whatever you want, just don’t claim you wrote it 😉

---

