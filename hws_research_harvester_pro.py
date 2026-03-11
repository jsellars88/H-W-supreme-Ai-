#!/usr/bin/env python3
"""
hws_research_harvester_pro.py

Holmes & Watson Supreme AI™ — Curated Public Research Harvester
Professionalized v3.1

Features:
- Topic-first, source-restricted harvesting
- Robots.txt + rate-limit aware
- Canonical URL normalization
- SQLite metadata index
- JSON evidence capsules
- URL + content-hash deduplication
- arXiv-aware harvesting and BibTeX generation
- PubMed search adapter
- Subtopic tagging
- Provenance preservation
- Vault reindexing
- Markdown table-of-contents generation
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sqlite3
import time
import urllib.robotparser
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote_plus, urlencode, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

try:
    import PyPDF2

    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

# =============================================================================
# CONFIG
# =============================================================================

EXTRACTOR_VERSION = "3.1"
USER_AGENT = (
    "HWS-ResearchBot/3.1 (public academic/regulatory research indexing; respects robots.txt)"
)

TOPICS: dict[str, list[str]] = {
    "omnineuro_agentic_ai": [
        "agentic ai",
        "llm agents",
        "multi-agent systems",
        "safe eval agent",
        "llm security taxonomy",
        "trism ai",
        "nist ai rmf",
        "owasp llm",
        "autonomous ai",
        "agent orchestration",
        "ai governance",
        "constitutional ai",
        "prompt injection",
        "llm red teaming",
    ],
    "omnibots_safety": [
        "robot safety",
        "industrial robot safety",
        "human robot interaction safety",
        "iso 10218",
        "ansi r15.06",
        "ul 4600",
        "functional safety",
        "collaborative robot",
        "cobot safety",
        "robot risk assessment",
        "iec 61508",
        "iso 13849",
        "safety-rated control",
    ],
    "omnisim_isaac": [
        "isaac lab",
        "isaac sim",
        "robotics simulation",
        "newton physics engine",
        "sim-to-real",
        "omniverse robot",
        "reinforcement learning robotics",
        "digital twin robot",
        "physics-based simulation",
        "gpu robotics sim",
    ],
    "aero_policy": [
        "faa bvlos",
        "part 108",
        "drone policy",
        "unmanned aircraft rulemaking",
        "uas regulation",
        "remote id drone",
        "beyond visual line of sight",
        "advanced air mobility",
        "evtol certification",
    ],
    "omnimedic_bio": [
        "gpu medical imaging",
        "beamforming ultrasound",
        "rehabilitation robotics",
        "graphene neuromodulation",
        "wetware computing",
        "bioelectronic interfaces",
        "brain computer interface",
        "neural prosthetics",
        "closed loop neuromodulation",
        "surgical robotics safety",
        "ai medical device regulation",
        "clinical ai decision support",
        "exoskeleton rehabilitation",
    ],
    "governance_standards": [
        "enisa ai",
        "nist ai rmf",
        "eu ai act",
        "iso 42001",
        "ai risk management",
        "algorithmic accountability",
        "ai audit",
        "trustworthy ai",
        "model card",
        "gdpr ai",
    ],
}

SUBTOPICS: dict[str, list[str]] = {
    "prompt_injection": ["prompt injection", "jailbreak", "indirect prompt injection"],
    "red_teaming": ["red teaming", "adversarial testing", "safety eval", "eval agent"],
    "robot_safety_case": ["ul 4600", "safety case", "functional safety", "hazard analysis"],
    "sim_to_real": ["sim-to-real", "domain randomization", "synthetic training", "digital twin"],
    "bvlos_rulemaking": ["faa bvlos", "part 108", "remote id", "uas regulation"],
    "medical_imaging": ["beamforming", "ultrasound", "radiology", "medical imaging"],
    "neurotech": ["brain computer interface", "neuromodulation", "neural prosthetics", "bci"],
    "compliance": ["eu ai act", "iso 42001", "nist ai rmf", "algorithmic accountability"],
}

VAULT_PATHS: dict[str, str] = {
    "omnineuro_agentic_ai": "Guardian Vault X / OmniNeuro / Agentic-AI",
    "omnibots_safety": "Guardian Vault X / OmniBots / Safety-Standards",
    "omnisim_isaac": "Guardian Vault X / OmniSim-Isaac",
    "aero_policy": "Guardian Vault X / Aero-Policy",
    "omnimedic_bio": "Guardian Vault X / OmniBio / OmniMedic",
    "governance_standards": "Guardian Vault X / Governance / Standards",
}

ALLOWED_DOMAINS = {
    "arxiv.org",
    "export.arxiv.org",
    "pubmed.ncbi.nlm.nih.gov",
    "www.ncbi.nlm.nih.gov",
    "nih.gov",
    "www.nih.gov",
    "nist.gov",
    "www.nist.gov",
    "csrc.nist.gov",
    "nvlpubs.nist.gov",
    "enisa.europa.eu",
    "www.enisa.europa.eu",
    "owasp.org",
    "faa.gov",
    "www.faa.gov",
    "rgl.faa.gov",
    "developer.nvidia.com",
    "docs.isaacsim.omniverse.nvidia.com",
    "isaac-sim.github.io",
    "ul.org",
    "www.ul.org",
    "standards.ieee.org",
    "ieeexplore.ieee.org",
    "www.iso.org",
    "regulations.gov",
    "www.regulations.gov",
    "cset.georgetown.edu",
    "hai.stanford.edu",
    "aiindex.stanford.edu",
    "partnershiponai.org",
    "www.partnershiponai.org",
    "digital-strategy.ec.europa.eu",
    "ec.europa.eu",
    "whitehouse.gov",
    "www.whitehouse.gov",
    "www.osha.gov",
    "osha.gov",
}
ALLOWED_SUFFIXES = (".edu", ".gov")

RATE_LIMITS: dict[str, float] = {
    "arxiv.org": 3.0,
    "export.arxiv.org": 3.0,
    "pubmed.ncbi.nlm.nih.gov": 2.0,
    "nist.gov": 2.0,
    "enisa.europa.eu": 2.0,
    "faa.gov": 2.0,
    "default": 3.0,
}

SEED_URLS: dict[str, list[str]] = {
    "omnineuro_agentic_ai": [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf",
        "https://arxiv.org/abs/2309.00986",
        "https://arxiv.org/abs/2401.13601",
    ],
    "omnibots_safety": [
        "https://www.nist.gov/el/intelligent-systems-division-73500/robotic-systems-safety",
        "https://www.osha.gov/robotics",
        "https://ul.org/research/robotics-automation/robotics-safety-research",
    ],
    "omnisim_isaac": [
        "https://developer.nvidia.com/isaac-sim",
        "https://arxiv.org/abs/2301.04195",
        "https://arxiv.org/abs/2401.09965",
    ],
    "aero_policy": [
        "https://www.faa.gov/uas/advanced_operations/beyond_visual_line_of_sight",
        "https://www.faa.gov/regulations_policies/rulemaking/recently_published",
        "https://www.regulations.gov/docket/FAA-2023-1238",
    ],
    "omnimedic_bio": [
        "https://www.ncbi.nlm.nih.gov/pmc/articles/PMC9741991/",
        "https://arxiv.org/abs/2303.10130",
        "https://arxiv.org/abs/2402.05421",
    ],
    "governance_standards": [
        "https://www.enisa.europa.eu/publications/enisa-artificial-intelligence-cybersecurity-challenges",
        "https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf",
        "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ],
}

MIN_TOPIC_SCORE = 2
MAX_TEXT_CHARS = 50000
MAX_PDF_PAGES = 12

# =============================================================================
# DATA MODELS
# =============================================================================


@dataclass
class EvidenceCapsule:
    capsule_id: str
    canonical_url: str
    original_url: str
    final_url: str
    topic: str
    subtopics: list[str]
    vault_path: str
    title: str
    domain: str
    fetched_at: str
    retrieval_method: str
    extractor_version: str
    content_type: str
    http_status: int
    summary: str
    raw_text: str
    keywords: list[str]
    topic_scores: dict[str, int]
    sha256: str
    source_query: str = ""
    topic_hint: str = ""
    content_length: int = 0
    is_pdf: bool = False
    arxiv_id: str = ""
    doi: str = ""
    bibtex: str = ""
    headers_subset: dict[str, str] = field(default_factory=dict)
    error_msg: str = ""
    status: str = "ok"


# =============================================================================
# HELPERS
# =============================================================================


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def sanitize_text(text: str) -> str:
    text = re.sub(r"\$.*?\$", " ", text)
    text = re.sub(r"\\[a-zA-Z]+\{.*?\}", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_TEXT_CHARS]


def summarize_text(text: str, max_sentences: int = 5) -> str:
    clean = sanitize_text(text)
    if not clean:
        return ""

    sentences = re.split(r"(?<=[.!?])\s+", clean)
    if len(sentences) <= max_sentences:
        return " ".join(sentences)[:1200]

    scored: list[tuple[int, str]] = []
    for sent in sentences[:40]:
        score = len(sent.split())
        lower = sent.lower()
        if "abstract" in lower:
            score += 5
        if any(p in lower for p in ("we propose", "this paper", "this work")):
            score += 4
        if any(p in lower for p in ("results", "method", "approach")):
            score += 3
        scored.append((score, sent))

    best = [s for _, s in sorted(scored, key=lambda x: x[0], reverse=True)[:max_sentences]]
    summary = " ".join(best).strip()
    return (summary or clean[:1200])[:1200]


def generate_subtopics(text: str) -> list[str]:
    lower = text.lower()
    return [name for name, kws in SUBTOPICS.items() if any(kw in lower for kw in kws)][:8]


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    filtered = [
        (k, v)
        for k, v in query_pairs
        if not k.lower().startswith("utm_") and k.lower() not in {"fbclid", "gclid"}
    ]
    normalized = parsed._replace(query=urlencode(filtered), fragment="")
    return urlunparse(normalized)


def extract_arxiv_id(url: str) -> str:
    m = re.search(r"arxiv\.org/(?:abs|pdf)/([0-9]{4}\.[0-9]{4,5})(?:\.pdf)?", url)
    return m.group(1) if m else ""


def canonicalize_arxiv_url(url: str) -> str:
    arxiv_id = extract_arxiv_id(url)
    return f"https://arxiv.org/abs/{arxiv_id}" if arxiv_id else normalize_url(url)


def canonical_url(url: str) -> str:
    if "arxiv.org" in url:
        return canonicalize_arxiv_url(url)
    return normalize_url(url)


def is_allowed_url(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        if host in ALLOWED_DOMAINS:
            return True
        if any(host.endswith("." + d) for d in ALLOWED_DOMAINS):
            return True
        if any(host.endswith(sfx) for sfx in ALLOWED_SUFFIXES):
            return True
        return False
    except Exception:
        return False


def extract_doi(text: str) -> str:
    m = re.search(r"\b10\.\d{4,9}/[-._;()/:A-Z0-9]+\b", text, re.I)
    return m.group(0) if m else ""


def generate_bibtex(capsule: EvidenceCapsule) -> str:
    year = capsule.fetched_at[:4] if capsule.fetched_at else time.strftime("%Y")
    key = f"{capsule.topic}_{capsule.capsule_id[:8]}"

    if capsule.arxiv_id:
        return (
            f"@misc{{{key},\n"
            f"  title = {{{capsule.title}}},\n"
            f"  howpublished = {{arXiv:{capsule.arxiv_id}}},\n"
            f"  archivePrefix = {{arXiv}},\n"
            f"  eprint = {{{capsule.arxiv_id}}},\n"
            f"  year = {{{year}}},\n"
            f"  url = {{{capsule.canonical_url}}}\n"
            f"}}"
        )

    if capsule.doi:
        return (
            f"@misc{{{key},\n"
            f"  title = {{{capsule.title}}},\n"
            f"  doi = {{{capsule.doi}}},\n"
            f"  url = {{{capsule.canonical_url}}},\n"
            f"  year = {{{year}}}\n"
            f"}}"
        )

    return (
        f"@misc{{{key},\n"
        f"  title = {{{capsule.title}}},\n"
        f"  howpublished = {{\\url{{{capsule.canonical_url}}}}},\n"
        f"  note = {{Accessed: {capsule.fetched_at}}},\n"
        f"  year = {{{year}}}\n"
        f"}}"
    )


# =============================================================================
# ROBOTS + RATE LIMIT
# =============================================================================


class RobotsCache:
    def __init__(self) -> None:
        self._cache: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    def allowed(self, url: str, user_agent: str = USER_AGENT) -> bool:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain not in self._cache:
            robots_url = f"{parsed.scheme}://{domain}/robots.txt"
            rp = urllib.robotparser.RobotFileParser()
            rp.set_url(robots_url)
            try:
                rp.read()
                self._cache[domain] = rp
            except Exception:
                self._cache[domain] = None

        rp = self._cache[domain]
        if rp is None:
            return False
        return rp.can_fetch(user_agent, url)


class RateLimiter:
    def __init__(self) -> None:
        self._last: dict[str, float] = {}

    def wait(self, url: str) -> None:
        domain = urlparse(url).netloc.lower()
        limit = RATE_LIMITS.get("default", 3.0)
        for key, value in RATE_LIMITS.items():
            if key != "default" and domain.endswith(key):
                limit = value
                break

        last = self._last.get(domain, 0.0)
        elapsed = time.time() - last
        if elapsed < limit:
            time.sleep(limit - elapsed)
        self._last[domain] = time.time()


# =============================================================================
# SQLITE INDEX
# =============================================================================


class VaultIndex:
    def __init__(self, db_path: str) -> None:
        self.db = sqlite3.connect(db_path)
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS capsules (
                capsule_id TEXT PRIMARY KEY,
                canonical_url TEXT UNIQUE,
                sha256 TEXT UNIQUE,
                topic TEXT,
                title TEXT,
                path TEXT,
                fetched_at TEXT
            )
            """
        )
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS harvest_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_url TEXT,
                canonical_url TEXT,
                status TEXT,
                note TEXT,
                harvested_at TEXT
            )
            """
        )
        self.db.commit()

    def seen_url(self, canonical: str) -> str | None:
        row = self.db.execute(
            "SELECT capsule_id FROM capsules WHERE canonical_url = ?",
            (canonical,),
        ).fetchone()
        return row[0] if row else None

    def seen_hash(self, sha256: str) -> str | None:
        row = self.db.execute(
            "SELECT capsule_id FROM capsules WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        return row[0] if row else None

    def add_capsule(self, capsule: EvidenceCapsule, path: str) -> None:
        self.db.execute(
            """
            INSERT INTO capsules (capsule_id, canonical_url, sha256, topic, title, path, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                capsule.capsule_id,
                capsule.canonical_url,
                capsule.sha256,
                capsule.topic,
                capsule.title,
                path,
                capsule.fetched_at,
            ),
        )
        self.db.commit()

    def rebuild_from_vault(self, vault_dir: str) -> int:
        self.db.execute("DELETE FROM capsules")
        count = 0
        for file in Path(vault_dir).rglob("*.json"):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                if "capsule_id" not in data or "topic" not in data:
                    continue
                self.db.execute(
                    """
                    INSERT OR REPLACE INTO capsules
                    (capsule_id, canonical_url, sha256, topic, title, path, fetched_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data.get("capsule_id"),
                        data.get("canonical_url"),
                        data.get("sha256"),
                        data.get("topic"),
                        data.get("title"),
                        str(file),
                        data.get("fetched_at"),
                    ),
                )
                count += 1
            except Exception:
                continue
        self.db.commit()
        return count

    def log(self, original_url: str, canonical: str, status: str, note: str = "") -> None:
        self.db.execute(
            """
            INSERT INTO harvest_log (original_url, canonical_url, status, note, harvested_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (original_url, canonical, status, note, utc_now()),
        )
        self.db.commit()

    def close(self) -> None:
        self.db.close()


# =============================================================================
# COLLECTOR
# =============================================================================


class Collector:
    HEADERS = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/pdf,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def __init__(self, timeout: int = 20, enforce_robots: bool = True) -> None:
        self._timeout = timeout
        self._robots = RobotsCache()
        self._rate = RateLimiter()
        self._enforce_robots = enforce_robots
        self._session = requests.Session()
        self._session.headers.update(self.HEADERS)

    def fetch(self, url: str) -> tuple[requests.Response | None, str]:
        if not is_allowed_url(url):
            return None, f"domain not in allowlist: {urlparse(url).netloc}"

        if self._enforce_robots and not self._robots.allowed(url):
            return None, f"blocked by robots.txt or robots unavailable: {url}"

        self._rate.wait(url)

        try:
            resp = self._session.get(url, timeout=self._timeout, allow_redirects=True)
            if resp.status_code == 200:
                return resp, ""
            return None, f"HTTP {resp.status_code}"
        except requests.exceptions.Timeout:
            return None, "timeout"
        except requests.exceptions.ConnectionError as exc:
            return None, f"connection error: {exc}"
        except Exception as exc:
            return None, str(exc)

    def extract(self, resp: requests.Response) -> tuple[str, str, bool]:
        content_type = resp.headers.get("Content-Type", "").lower()
        is_pdf = "pdf" in content_type or resp.url.lower().endswith(".pdf")
        if is_pdf and PDF_SUPPORT:
            return self._extract_pdf(resp)
        return self._extract_html(resp)

    def _extract_html(self, resp: requests.Response) -> tuple[str, str, bool]:
        try:
            soup = BeautifulSoup(resp.content, "html.parser")
            for tag in soup(["script", "style", "noscript", "nav", "footer", "header", "aside"]):
                tag.decompose()

            title = soup.title.string.strip() if soup.title and soup.title.string else resp.url
            body = (
                soup.find("article")
                or soup.find("main")
                or soup.find("div", {"id": "content"})
                or soup.find("div", {"class": "content"})
                or soup.body
                or soup
            )
            text = " ".join(body.stripped_strings) if body else ""
            return title, sanitize_text(text), False
        except Exception as exc:
            return resp.url, f"[html extraction error: {exc}]", False

    def _extract_pdf(self, resp: requests.Response) -> tuple[str, str, bool]:
        try:
            reader = PyPDF2.PdfReader(io.BytesIO(resp.content))
            title = resp.url
            if reader.metadata and reader.metadata.get("/Title"):
                title = str(reader.metadata.get("/Title")).strip()

            pages: list[str] = []
            for page in reader.pages[:MAX_PDF_PAGES]:
                pages.append(page.extract_text() or "")
            text = sanitize_text("\n".join(pages))
            return title, text, True
        except Exception as exc:
            return resp.url, f"[pdf extraction error: {exc}]", True


# =============================================================================
# CLASSIFIER
# =============================================================================


class Classifier:
    def score(self, text: str) -> dict[str, int]:
        lower = text.lower()
        return {topic: sum(1 for kw in kws if kw.lower() in lower) for topic, kws in TOPICS.items()}

    def classify(self, text: str) -> tuple[str | None, list[str], dict[str, int]]:
        scores = self.score(text)
        best_topic = max(scores, key=lambda k: scores[k])
        best_score = scores[best_topic]

        if best_score < MIN_TOPIC_SCORE:
            return None, [], scores

        lower = text.lower()
        matched = [kw for kw in TOPICS[best_topic] if kw.lower() in lower]
        return best_topic, matched, scores


# =============================================================================
# SEARCH ADAPTERS
# =============================================================================


def search_arxiv(query: str, n: int = 5) -> list[str]:
    try:
        url = (
            "https://export.arxiv.org/search/?searchtype=all"
            f"&query={quote_plus(query)}&start=0&max_results={n}"
        )
        time.sleep(3)
        resp = requests.get(url, timeout=20, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        urls: list[str] = []
        for node in soup.find_all("p", class_="list-title"):
            anchor = node.find("a")
            if anchor and anchor.get("href") and "arxiv.org" in anchor["href"]:
                urls.append(anchor["href"])
        return urls[:n]
    except Exception:
        return []


def search_pubmed(query: str, n: int = 5) -> list[str]:
    try:
        url = f"https://pubmed.ncbi.nlm.nih.gov/?term={quote_plus(query)}"
        time.sleep(2)
        resp = requests.get(url, timeout=20, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            return []
        soup = BeautifulSoup(resp.text, "html.parser")
        urls: list[str] = []
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"]
            if re.match(r"^/\d+/?$", href):
                urls.append("https://pubmed.ncbi.nlm.nih.gov" + href)
        deduped = list(dict.fromkeys(urls))
        return deduped[:n]
    except Exception:
        return []


# =============================================================================
# VAULT
# =============================================================================


class EvidenceVault:
    def __init__(
        self, vault_dir: str = "guardian_vault_x", db_path: str = "guardian_vault_x.sqlite"
    ) -> None:
        self._dir = Path(vault_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index = VaultIndex(db_path)

    def store(self, capsule: EvidenceCapsule) -> tuple[bool, str]:
        existing_url = self._index.seen_url(capsule.canonical_url)
        if existing_url:
            return False, existing_url

        existing_hash = self._index.seen_hash(capsule.sha256)
        if existing_hash:
            return False, existing_hash

        sub = (
            capsule.vault_path.replace("Guardian Vault X / ", "")
            .replace(" / ", "/")
            .replace(" ", "_")
        )
        dest = self._dir / sub
        dest.mkdir(parents=True, exist_ok=True)

        fpath = dest / f"{capsule.topic}_{capsule.capsule_id}.json"
        fpath.write_text(
            json.dumps(asdict(capsule), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self._index.add_capsule(capsule, str(fpath))
        return True, str(fpath)

    def log(self, original_url: str, canonical: str, status: str, note: str = "") -> None:
        self._index.log(original_url, canonical, status, note)

    def rebuild_index(self) -> int:
        return self._index.rebuild_from_vault(str(self._dir))

    def search(self, query: str, topic: str | None = None) -> list[dict[str, Any]]:
        q = query.lower()
        results: list[dict[str, Any]] = []
        for file in self._dir.rglob("*.json"):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                if "capsule_id" not in data or "topic" not in data:
                    continue
                if topic and data.get("topic") != topic:
                    continue
                haystack = (
                    data.get("title", "")
                    + " "
                    + data.get("summary", "")
                    + " "
                    + " ".join(data.get("keywords", []))
                    + " "
                    + " ".join(data.get("subtopics", []))
                ).lower()
                if q in haystack:
                    results.append(
                        {
                            "capsule_id": data.get("capsule_id"),
                            "topic": data.get("topic"),
                            "title": data.get("title"),
                            "url": data.get("canonical_url") or data.get("url"),
                            "fetched_at": data.get("fetched_at"),
                            "subtopics": data.get("subtopics", []),
                            "summary": data.get("summary", "")[:200],
                            "path": str(file),
                        }
                    )
            except Exception:
                continue
        return results

    def stats(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        total = 0
        for file in self._dir.rglob("*.json"):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                if "topic" not in data:
                    continue
                t = data.get("topic", "unknown")
                counts[t] = counts.get(t, 0) + 1
                total += 1
            except Exception:
                continue
        return {"total": total, "by_topic": counts, "vault_dir": str(self._dir)}

    def close(self) -> None:
        self._index.close()


# =============================================================================
# VAULT INDEXER
# =============================================================================


class VaultIndexer:
    def __init__(self, vault_dir: str = "guardian_vault_x") -> None:
        self._dir = Path(vault_dir)

    def generate(self, output_path: str | None = None) -> str:
        sections: dict[str, list[dict[str, Any]]] = {}

        for file in sorted(self._dir.rglob("*.json")):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
                if "capsule_id" not in data or "topic" not in data:
                    continue
                topic = data.get("topic", "unknown")
                sections.setdefault(topic, []).append(data)
            except Exception:
                continue

        lines: list[str] = [
            "# Guardian Vault X - Evidence Index",
            "",
            f"*Generated: {utc_now()}*",
            "",
            f"**Total capsules:** {sum(len(v) for v in sections.values())}",
            "",
            "---",
            "",
            "## Contents",
            "",
        ]

        for topic in sorted(sections.keys()):
            vault_path = VAULT_PATHS.get(topic, topic)
            count = len(sections[topic])
            lines.append(f"- [{vault_path}](#{topic}) ({count})")

        lines += ["", "---", ""]

        for topic in sorted(sections.keys()):
            vault_path = VAULT_PATHS.get(topic, topic)
            capsules = sections[topic]
            lines += [
                f"## {vault_path}",
                "",
                f"*{len(capsules)} capsule(s)*",
                "",
                "| Title | URL | Subtopics | arXiv | Date |",
                "|-------|-----|-----------|-------|------|",
            ]
            for c in sorted(capsules, key=lambda x: x.get("fetched_at", ""), reverse=True):
                title = (c.get("title") or "")[:60].replace("|", "/")
                url = c.get("canonical_url") or c.get("url") or ""
                subtopics = ", ".join(c.get("subtopics", [])[:3]) or "-"
                arxiv_id = c.get("arxiv_id") or "-"
                date = (c.get("fetched_at") or "")[:10]
                url_md = f"[link]({url})" if url else "-"
                lines.append(f"| {title} | {url_md} | {subtopics} | {arxiv_id} | {date} |")

            lines += ["", ""]

        md = "\n".join(lines)

        if output_path:
            Path(output_path).write_text(md, encoding="utf-8")

        return md


# =============================================================================
# HARVESTER
# =============================================================================


class Harvester:
    def __init__(
        self,
        vault_dir: str = "guardian_vault_x",
        db_path: str = "guardian_vault_x.sqlite",
        verbose: bool = True,
    ) -> None:
        self._collector = Collector()
        self._classifier = Classifier()
        self._vault = EvidenceVault(vault_dir=vault_dir, db_path=db_path)
        self._verbose = verbose
        self._stats = {"fetched": 0, "stored": 0, "skipped": 0, "errors": 0}

    def _log(self, msg: str) -> None:
        if self._verbose:
            print(msg)

    @property
    def vault(self) -> EvidenceVault:
        return self._vault

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def _make_capsule(
        self,
        original_url: str,
        resp: requests.Response,
        title: str,
        text: str,
        topic: str,
        keywords: list[str],
        scores: dict[str, int],
        is_pdf: bool,
        topic_hint: str = "",
        source_query: str = "",
    ) -> EvidenceCapsule:
        canon = canonical_url(original_url)
        final_url = normalize_url(resp.url)
        content_type = resp.headers.get("Content-Type", "")
        digest = sha256_text(text)
        arxiv_id = extract_arxiv_id(final_url or original_url)
        subtopics = generate_subtopics(text)
        doi = extract_doi(text)

        capsule = EvidenceCapsule(
            capsule_id=digest[:16],
            canonical_url=canon,
            original_url=original_url,
            final_url=final_url,
            topic=topic,
            subtopics=subtopics,
            vault_path=VAULT_PATHS[topic],
            title=title or original_url,
            domain=urlparse(final_url or original_url).netloc.lower(),
            fetched_at=utc_now(),
            retrieval_method="pdf" if is_pdf else "html",
            extractor_version=EXTRACTOR_VERSION,
            content_type=content_type,
            http_status=resp.status_code,
            summary=summarize_text(text),
            raw_text=text,
            keywords=keywords[:20],
            topic_scores=scores,
            sha256=digest,
            source_query=source_query,
            topic_hint=topic or "",
            content_length=len(text),
            is_pdf=is_pdf,
            arxiv_id=arxiv_id,
            doi=doi,
            headers_subset={
                "content-type": resp.headers.get("Content-Type", ""),
                "content-length": resp.headers.get("Content-Length", ""),
                "last-modified": resp.headers.get("Last-Modified", ""),
                "etag": resp.headers.get("ETag", ""),
            },
        )
        capsule.bibtex = generate_bibtex(capsule)
        return capsule

    def harvest_url(
        self,
        url: str,
        topic: str | None = None,
        force_topic: bool = False,
        source_query: str = "",
    ) -> EvidenceCapsule | None:
        self._log(f"  → {url}")
        original_url = url

        if "arxiv.org/abs/" in url:
            arxiv_id = extract_arxiv_id(url)
            if arxiv_id:
                url = f"https://arxiv.org/pdf/{arxiv_id}.pdf"
                self._log(f"    ↳ arXiv PDF escalation: {url}")

        canon = canonical_url(original_url)
        resp, err = self._collector.fetch(url)
        if not resp:
            self._log(f"    ✗ {err}")
            self._vault.log(original_url, canon, "error", err)
            self._stats["errors"] += 1
            return None

        self._stats["fetched"] += 1
        title, text, is_pdf = self._collector.extract(resp)

        if not text.strip():
            self._log("    ✗ empty text")
            self._vault.log(original_url, canon, "skipped", "empty text")
            self._stats["skipped"] += 1
            return None

        if force_topic and topic:
            best_topic = topic
            scores = self._classifier.score(text)
            keywords = [kw for kw in TOPICS[topic] if kw.lower() in text.lower()]
        else:
            best_topic, keywords, scores = self._classifier.classify(text)
            if topic and not best_topic and scores.get(topic, 0) >= 1:
                best_topic = topic
                keywords = [kw for kw in TOPICS[topic] if kw.lower() in text.lower()]

        if not best_topic:
            self._log("    ✗ no topic match above threshold")
            self._vault.log(original_url, canon, "skipped", "no topic match")
            self._stats["skipped"] += 1
            return None

        capsule = self._make_capsule(
            original_url=original_url,
            resp=resp,
            title=title,
            text=text,
            topic=best_topic,
            keywords=keywords,
            scores=scores,
            is_pdf=is_pdf,
            topic_hint=topic or "",
            source_query=source_query,
        )

        stored, path = self._vault.store(capsule)
        if stored:
            self._stats["stored"] += 1
            self._vault.log(original_url, capsule.canonical_url, "stored", path)
            self._log(f"    ✓ [{best_topic}] {title[:60]} → {path}")
        else:
            self._stats["skipped"] += 1
            self._vault.log(original_url, capsule.canonical_url, "duplicate", path)
            self._log(f"    ⟳ duplicate: {title[:60]}")

        return capsule if stored else None

    def harvest_topic(self, topic: str, limit: int = 5) -> list[EvidenceCapsule]:
        self._log(f"\n{'=' * 70}")
        self._log(f"  TOPIC: {topic}")
        self._log(f"  VAULT: {VAULT_PATHS[topic]}")
        self._log(f"{'=' * 70}")

        results: list[EvidenceCapsule] = []

        seeds = SEED_URLS.get(topic, [])[:limit]
        self._log(f"\n  [Seeds: {len(seeds)}]")
        for url in seeds:
            cap = self.harvest_url(url, topic=topic, force_topic=True, source_query=f"seed:{topic}")
            if cap:
                results.append(cap)

        if len(results) < limit and TOPICS.get(topic):
            query = TOPICS[topic][0]
            self._log(f"\n  [arXiv search: '{query}']")
            for url in search_arxiv(query, n=limit - len(results) + 2):
                if len(results) >= limit:
                    break
                cap = self.harvest_url(url, topic=topic, source_query=query)
                if cap:
                    results.append(cap)

            # PubMed is most useful for bio/medical topic lanes
            if topic == "omnimedic_bio" and len(results) < limit:
                self._log(f"\n  [PubMed search: '{query}']")
                for url in search_pubmed(query, n=limit - len(results) + 2):
                    if len(results) >= limit:
                        break
                    cap = self.harvest_url(url, topic=topic, source_query=query)
                    if cap:
                        results.append(cap)

        return results

    def harvest_all(self, limit_per_topic: int = 3) -> list[EvidenceCapsule]:
        out: list[EvidenceCapsule] = []
        for topic in TOPICS:
            out.extend(self.harvest_topic(topic, limit=limit_per_topic))
        return out

    def harvest_search(self, query: str, topic: str | None = None) -> list[EvidenceCapsule]:
        self._log(f"\n  [arXiv search: '{query}']")
        out: list[EvidenceCapsule] = []
        for url in search_arxiv(query, n=5):
            cap = self.harvest_url(url, topic=topic, source_query=query)
            if cap:
                out.append(cap)
        return out

    def close(self) -> None:
        self._vault.close()


# =============================================================================
# REPORTS
# =============================================================================


def print_report(vault: EvidenceVault) -> None:
    stats = vault.stats()
    print(f"\n{'=' * 70}")
    print("  GUARDIAN VAULT X - EVIDENCE REPORT")
    print(f"{'=' * 70}")
    print(f"  Total capsules : {stats['total']}")
    print(f"  Vault dir      : {stats['vault_dir']}")
    print()
    for topic, count in sorted(stats["by_topic"].items()):
        print(f"  {count:>4}  {VAULT_PATHS.get(topic, topic)}")
    print(f"{'=' * 70}\n")


# =============================================================================
# CLI
# =============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HWS Research Harvester Pro v3.1 - Guardian Vault X ingestor"
    )
    parser.add_argument("--topic", choices=list(TOPICS.keys()), help="Harvest a specific topic")
    parser.add_argument("--all", action="store_true", help="Harvest all topics")
    parser.add_argument("--url", type=str, help="Harvest a specific URL")
    parser.add_argument("--search", type=str, help="Search arXiv for a query")
    parser.add_argument("--report", action="store_true", help="Print vault report")
    parser.add_argument("--find", type=str, help="Search vault for a term")
    parser.add_argument("--index", action="store_true", help="Generate Markdown TOC")
    parser.add_argument(
        "--reindex", action="store_true", help="Rebuild SQLite index from vault JSON"
    )
    parser.add_argument("--limit", type=int, default=5, help="Max items per topic")
    parser.add_argument("--vault", type=str, default="guardian_vault_x", help="Vault directory")
    parser.add_argument("--db", type=str, default="guardian_vault_x.sqlite", help="SQLite index")
    parser.add_argument("--out", type=str, default=None, help="Output path for --index")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args()

    harvester = Harvester(vault_dir=args.vault, db_path=args.db, verbose=not args.quiet)

    try:
        if args.report:
            print_report(harvester.vault)
            return

        if args.reindex:
            count = harvester.vault.rebuild_index()
            print(f"Rebuilt SQLite index from vault JSON -> {count} capsule(s)")
            return

        if args.index:
            indexer = VaultIndexer(vault_dir=args.vault)
            out_path = args.out or "guardian_vault_index.md"
            md = indexer.generate(output_path=out_path)
            print(f"Index written -> {out_path}")
            if not args.quiet:
                print(md[:1200] + "\n..." if len(md) > 1200 else md)
            return

        if args.find:
            results = harvester.vault.search(args.find, topic=args.topic)
            print(f"\nSearch '{args.find}' -> {len(results)} results")
            for r in results:
                print(f"  - [{r['topic']}] {r['title'][:70]}")
                print(f"    {r['url']}")
                if r.get("subtopics"):
                    print(f"    subtopics: {', '.join(r['subtopics'])}")
                print(f"    {r['summary'][:140]}...")
                print()
            return

        start = time.time()

        if args.url:
            harvester.harvest_url(args.url, topic=args.topic, force_topic=bool(args.topic))
        elif args.search:
            harvester.harvest_search(args.search, topic=args.topic)
        elif args.topic:
            harvester.harvest_topic(args.topic, limit=args.limit)
        elif args.all:
            harvester.harvest_all(limit_per_topic=args.limit)
        else:
            parser.print_help()
            return

        elapsed = time.time() - start
        s = harvester.stats
        print(f"\n{'-' * 70}")
        print(
            f"Fetched: {s['fetched']}  Stored: {s['stored']}  "
            f"Skipped: {s['skipped']}  Errors: {s['errors']}  ({elapsed:.1f}s)"
        )
        print_report(harvester.vault)

    finally:
        harvester.close()


if __name__ == "__main__":
    main()
