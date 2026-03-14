#!/usr/bin/env python3
"""
Document Forensics Tool
Analyse forensique de documents DOCX et PDF.
Extrait les métadonnées, détecte les anomalies et génère des rapports multilingues.
"""

import argparse
import glob
import locale
import os
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

import pikepdf
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


# ─── i18n ─────────────────────────────────────────────────────────────────────

LANG_DIR = Path(__file__).parent / "lang"
_translations: dict = {}


def load_translations(lang: str) -> dict:
    """Charge les traductions pour une langue donnée."""
    global _translations
    lang_file = LANG_DIR / f"{lang}.yml"
    if not lang_file.exists():
        available = [f.stem for f in LANG_DIR.glob("*.yml")]
        console.print(f"[red]Langue « {lang} » non disponible. Langues disponibles : {', '.join(available)}[/red]")
        console.print(f"[yellow]Utilisation du français par défaut.[/yellow]")
        lang_file = LANG_DIR / "fr.yml"
    with open(lang_file, encoding="utf-8") as f:
        _translations = yaml.safe_load(f)
    return _translations


def t(key: str, **kwargs) -> str:
    """Récupère une traduction par clé (notation pointée) et formate avec kwargs."""
    keys = key.split(".")
    val = _translations
    for k in keys:
        if isinstance(val, dict):
            # Chercher la clé telle quelle, ou en bool (YAML yes/no → True/False)
            if k in val:
                val = val[k]
            elif k == "yes" and True in val:
                val = val[True]
            elif k == "no" and False in val:
                val = val[False]
            else:
                return key  # Fallback: retourner la clé
        else:
            return key
    if isinstance(val, str) and kwargs:
        return val.format(**kwargs)
    return str(val) if not isinstance(val, (dict, list)) else key


def detect_system_language() -> str:
    """Détecte la langue du système."""
    try:
        lang_env = os.environ.get("LANG", "") or os.environ.get("LANGUAGE", "") or locale.getdefaultlocale()[0] or ""
        lang_code = lang_env.split("_")[0].lower()
        if lang_code and (LANG_DIR / f"{lang_code}.yml").exists():
            return lang_code
    except Exception:
        pass
    return "fr"


# ─── Namespaces XML Office ────────────────────────────────────────────────────

NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "dcmitype": "http://purl.org/dc/dcmitype/",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "w14": "http://schemas.microsoft.com/office/word/2010/wordml",
    "w15": "http://schemas.microsoft.com/office/word/2012/wordml",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}


# ─── DOCX Analysis ───────────────────────────────────────────────────────────


def analyze_docx(filepath: str) -> dict:
    """Analyse complète d'un fichier DOCX via ses données XML internes."""
    info = {"fichier": os.path.basename(filepath), "chemin": filepath, "type": "DOCX"}

    with zipfile.ZipFile(filepath) as z:
        info["fichiers_archive"] = z.namelist()
        info["nb_fichiers"] = len(z.namelist())

        if "docProps/core.xml" in z.namelist():
            core = ET.fromstring(z.read("docProps/core.xml"))
            info["createur"] = _xml_text(core, "dc:creator")
            info["dernier_modificateur"] = _xml_text(core, "cp:lastModifiedBy")
            info["revision"] = _xml_text(core, "cp:revision")
            info["date_creation"] = _xml_text(core, "dcterms:created")
            info["date_modification"] = _xml_text(core, "dcterms:modified")
            info["titre"] = _xml_text(core, "dc:title")
            info["sujet"] = _xml_text(core, "dc:subject")
            info["mots_cles"] = _xml_text(core, "cp:keywords")
            info["description"] = _xml_text(core, "dc:description")

        if "docProps/app.xml" in z.namelist():
            app = ET.fromstring(z.read("docProps/app.xml"))
            info["application"] = _xml_text(app, "Application", ns="ep")
            info["version_app"] = _xml_text(app, "AppVersion", ns="ep")
            info["modele"] = _xml_text(app, "Template", ns="ep")
            info["temps_edition_min"] = _xml_text(app, "TotalTime", ns="ep")
            info["pages"] = _xml_text(app, "Pages", ns="ep")
            info["mots"] = _xml_text(app, "Words", ns="ep")
            info["caracteres"] = _xml_text(app, "Characters", ns="ep")
            info["paragraphes"] = _xml_text(app, "Paragraphs", ns="ep")
            info["lignes"] = _xml_text(app, "Lines", ns="ep")
            info["securite_doc"] = _xml_text(app, "DocSecurity", ns="ep")
            info["societe"] = _xml_text(app, "Company", ns="ep")

        if "word/settings.xml" in z.namelist():
            settings_xml = z.read("word/settings.xml").decode("utf-8")
            settings = ET.fromstring(settings_xml)

            rsids = []
            rsids_elem = settings.find(".//w:rsids", NS)
            if rsids_elem is not None:
                for child in rsids_elem:
                    val = child.get(f"{{{NS['w']}}}val")
                    if val:
                        rsids.append(val)
            info["rsids"] = rsids
            info["nb_rsids"] = len(rsids)

            for prefix, nskey in [("w14", "w14"), ("w15", "w15")]:
                did = settings.find(f".//{prefix}:docId", NS)
                if did is not None:
                    val = did.get(f"{{{NS[nskey]}}}val")
                    if val:
                        info[f"doc_id_{prefix}"] = val

        if "word/document.xml" in z.namelist():
            doc_xml = z.read("word/document.xml").decode("utf-8")
            info["modifications_suivies_insertions"] = len(re.findall(r"<w:ins ", doc_xml))
            info["modifications_suivies_suppressions"] = len(re.findall(r"<w:del ", doc_xml))
            auteurs_rev = set(re.findall(r'w:author="([^"]+)"', doc_xml))
            info["auteurs_revisions"] = list(auteurs_rev)

        medias = [f for f in z.namelist() if f.startswith("word/media/")]
        info["medias"] = medias
        info["nb_medias"] = len(medias)

        tailles = {}
        for zi in z.infolist():
            tailles[zi.filename] = zi.file_size
        info["tailles_internes"] = tailles

        if "word/_rels/document.xml.rels" in z.namelist():
            rels = ET.fromstring(z.read("word/_rels/document.xml.rels"))
            liens_ext = []
            for rel in rels:
                mode = rel.get("TargetMode", "")
                if mode == "External":
                    liens_ext.append({
                        "type": rel.get("Type", "").split("/")[-1],
                        "cible": rel.get("Target", ""),
                    })
            info["liens_externes"] = liens_ext

    info["taille_fichier"] = os.path.getsize(filepath)
    return info


def _xml_text(root: ET.Element, tag: str, ns: str = None) -> str:
    """Extrait le texte d'un tag XML avec gestion des namespaces."""
    if ns:
        elem = root.find(f"{{{NS[ns]}}}{tag}")
    else:
        elem = root.find(tag, NS)
    if elem is not None and elem.text:
        return elem.text.strip()
    return ""


# ─── PDF Analysis ────────────────────────────────────────────────────────────


def analyze_pdf(filepath: str) -> dict:
    """Analyse forensique d'un fichier PDF via ses métadonnées."""
    info = {"fichier": os.path.basename(filepath), "chemin": filepath, "type": "PDF"}
    info["taille_fichier"] = os.path.getsize(filepath)

    with pikepdf.open(filepath) as pdf:
        info["nb_pages"] = len(pdf.pages)
        info["version_pdf"] = str(pdf.pdf_version)

        docinfo = pdf.docinfo
        mapping = {
            "/Title": "titre",
            "/Author": "auteur",
            "/Subject": "sujet",
            "/Creator": "createur_logiciel",
            "/Producer": "producteur",
            "/CreationDate": "date_creation",
            "/ModDate": "date_modification",
            "/Keywords": "mots_cles",
        }
        for pdf_key, fr_key in mapping.items():
            val = docinfo.get(pdf_key, "")
            if val:
                raw = str(val)
                if "date" in fr_key.lower():
                    dt = parse_pdf_date(raw)
                    info[fr_key] = dt.strftime("%d/%m/%Y à %H:%M:%S") if dt else raw
                    info[fr_key + "_brut"] = raw
                else:
                    info[fr_key] = raw

        if pdf.open_metadata() is not None:
            try:
                with pdf.open_metadata() as meta:
                    xmp_raw = str(meta)
                    info["xmp_brut"] = xmp_raw[:2000] if len(xmp_raw) > 2000 else xmp_raw
            except Exception:
                pass

        info["objets_totaux"] = len(pdf.objects)

        nb_images = 0
        for page in pdf.pages:
            resources = page.get("/Resources", {})
            xobjects = resources.get("/XObject", {})
            if hasattr(xobjects, "keys"):
                for key in xobjects.keys():
                    obj = xobjects[key]
                    if hasattr(obj, "get") and obj.get("/Subtype") == "/Image":
                        nb_images += 1
        info["nb_images"] = nb_images
        info["chiffre"] = pdf.is_encrypted

    return info


def parse_pdf_date(date_str: str) -> datetime | None:
    """Parse une date PDF (format D:YYYYMMDDHHmmSS)."""
    if not date_str:
        return None
    m = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", date_str)
    if m:
        return datetime(
            int(m.group(1)), int(m.group(2)), int(m.group(3)),
            int(m.group(4)), int(m.group(5)), int(m.group(6)),
            tzinfo=timezone.utc,
        )
    return None


def parse_iso_date(date_str: str) -> datetime | None:
    """Parse une date ISO 8601."""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return None


# ─── Anomaly Detection ───────────────────────────────────────────────────────


def _extract_date_from_filename(filename: str) -> datetime | None:
    """Extrait une date du nom de fichier."""
    name = re.sub(r"\.(docx|pdf|xlsx|pptx)$", "", filename, flags=re.IGNORECASE)
    patterns = [
        (r"(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{4})", "dmy"),
        (r"(\d{4})[.\-/](\d{1,2})[.\-/](\d{1,2})", "ymd"),
        (r"(\d{2})(\d{2})(\d{4})", "dmy_compact"),
        (r"(\d{4})(\d{2})(\d{2})", "ymd_compact"),
    ]
    for pattern, fmt in patterns:
        m = re.search(pattern, name)
        if m:
            try:
                if fmt in ("dmy", "dmy_compact"):
                    d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
                else:
                    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
                if 1 <= d <= 31 and 1 <= mo <= 12 and 1900 <= y <= 2100:
                    return datetime(y, mo, d, tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def detect_anomalies(analyses: list[dict]) -> list[dict]:
    """Détecte les anomalies et incohérences entre les documents."""
    anomalies = []

    # ── Vérification date du nom de fichier vs métadonnées ──
    for a in analyses:
        date_nom = _extract_date_from_filename(a["fichier"])
        if not date_nom:
            continue
        a["date_nom_fichier"] = date_nom

        if a["type"] == "DOCX":
            date_mod = parse_iso_date(a.get("date_modification", ""))
            date_crea = parse_iso_date(a.get("date_creation", ""))
        else:
            date_mod = parse_pdf_date(a.get("date_modification_brut", a.get("date_modification", "")))
            date_crea = parse_pdf_date(a.get("date_creation_brut", a.get("date_creation", "")))

        date_reelle = date_mod or date_crea
        if date_reelle:
            delta_jours = abs((date_reelle.date() - date_nom.date()).days)
            if delta_jours > 7:
                severite = t("severity.haute") if delta_jours > 90 else t("severity.moyenne")
                direction = t("anomalies.filename_date.modified_after") if date_reelle > date_nom else t("anomalies.filename_date.modified_before")
                anomalies.append({
                    "type": t("anomalies.filename_date.type"),
                    "severite": severite,
                    "document": a["fichier"],
                    "detail": t("anomalies.filename_date.detail",
                        filename_date=date_nom.strftime("%d/%m/%Y"),
                        real_date=date_reelle.strftime("%d/%m/%Y"),
                        days=delta_jours,
                        direction=direction,
                    ),
                })

    # Grouper par paires DOCX/PDF
    pairs = defaultdict(dict)
    for a in analyses:
        base = re.sub(r"\.(docx|pdf)$", "", a["fichier"], flags=re.IGNORECASE)
        pairs[base][a["type"]] = a

    for base, docs in pairs.items():
        if "DOCX" in docs and "PDF" in docs:
            docx = docs["DOCX"]
            pdf = docs["PDF"]

            docx_mod = parse_iso_date(docx.get("date_modification", ""))
            pdf_mod = parse_pdf_date(pdf.get("date_modification_brut", pdf.get("date_modification", "")))

            if docx_mod and pdf_mod:
                diff = abs((pdf_mod - docx_mod).total_seconds())
                if diff > 3600:
                    anomalies.append({
                        "type": t("anomalies.timeline.type"),
                        "severite": t("severity.haute") if diff > 86400 else t("severity.moyenne"),
                        "document": base,
                        "detail": t("anomalies.timeline.detail",
                            duration=_format_duration(diff),
                            docx_date=docx_mod.strftime("%d/%m/%Y %H:%M"),
                            pdf_date=pdf_mod.strftime("%d/%m/%Y %H:%M"),
                        ),
                    })

            creator = pdf.get("createur_logiciel", "")
            if "scanner" in creator.lower() or "scan" in creator.lower():
                anomalies.append({
                    "type": t("anomalies.process.type"),
                    "severite": t("severity.info"),
                    "document": base,
                    "detail": t("anomalies.process.detail", creator=creator),
                })

    # Analyse inter-documents
    docx_analyses = [a for a in analyses if a["type"] == "DOCX"]

    if len(docx_analyses) > 1:
        dates_creation = set(a.get("date_creation", "") for a in docx_analyses)
        if len(dates_creation) == 1 and dates_creation != {""}:
            date_val = dates_creation.pop()
            anomalies.append({
                "type": t("anomalies.common_template.type"),
                "severite": t("severity.info"),
                "document": t("anomalies.all_docx"),
                "detail": t("anomalies.common_template.detail", date=date_val),
            })

        createurs = set(a.get("createur", "") for a in docx_analyses)
        if len(createurs) == 1 and createurs != {""}:
            anomalies.append({
                "type": t("anomalies.author.type"),
                "severite": t("severity.info"),
                "document": t("anomalies.all_docx"),
                "detail": t("anomalies.author.detail", creator=createurs.pop()),
            })

        for a in docx_analyses:
            temps = int(a.get("temps_edition_min", "0") or "0")
            revisions = int(a.get("revision", "0") or "0")
            if revisions > 0 and temps > 0:
                min_par_rev = temps / revisions
                if min_par_rev < 1:
                    anomalies.append({
                        "type": t("anomalies.editing_pace.type"),
                        "severite": t("severity.moyenne"),
                        "document": a["fichier"],
                        "detail": t("anomalies.editing_pace.detail",
                            pace=min_par_rev, revisions=revisions, time=temps),
                    })

        # RSIDs partagés (résumé groupé)
        rsid_sets = {}
        for a in docx_analyses:
            if "rsids" in a:
                rsid_sets[a["fichier"]] = set(a["rsids"])

        if len(rsid_sets) > 1:
            all_sets = list(rsid_sets.values())
            rsid_commun_global = all_sets[0]
            for s in all_sets[1:]:
                rsid_commun_global = rsid_commun_global & s

            if rsid_commun_global:
                pcts = []
                for nom, s in rsid_sets.items():
                    pcts.append(f"{nom}: {len(rsid_commun_global)}/{len(s)} ({len(rsid_commun_global)/len(s)*100:.0f}%)")
                anomalies.append({
                    "type": t("anomalies.shared_rsid.type"),
                    "severite": t("severity.info"),
                    "document": t("anomalies.all_docx"),
                    "detail": f"{len(rsid_commun_global)} " + t("anomalies.shared_rsid.detail",
                        count=len(rsid_sets), details="; ".join(pcts)),
                })

            fichiers = list(rsid_sets.keys())
            for i in range(len(fichiers)):
                for j in range(i + 1, len(fichiers)):
                    communs = rsid_sets[fichiers[i]] & rsid_sets[fichiers[j]]
                    extra = communs - rsid_commun_global
                    if extra:
                        anomalies.append({
                            "type": t("anomalies.extra_rsid.type"),
                            "severite": t("severity.moyenne"),
                            "document": f"{fichiers[i]} ↔ {fichiers[j]}",
                            "detail": t("anomalies.extra_rsid.detail", count=len(extra)),
                        })

        # Chronologie d'édition
        mods = []
        for a in docx_analyses:
            dt = parse_iso_date(a.get("date_modification", ""))
            if dt:
                mods.append((a["fichier"], dt))
        mods.sort(key=lambda x: x[1])
        if mods:
            total_span = (mods[-1][1] - mods[0][1]).total_seconds()
            if total_span > 0 and total_span < 7200:
                anomalies.append({
                    "type": t("anomalies.batch_editing.type"),
                    "severite": t("severity.info"),
                    "document": t("anomalies.all_docx"),
                    "detail": t("anomalies.batch_editing.detail",
                        duration=_format_duration(total_span),
                        start=mods[0][1].strftime("%H:%M"),
                        end=mods[-1][1].strftime("%H:%M"),
                        date=mods[0][1].strftime("%d/%m/%Y"),
                    ),
                })

    return anomalies


def _format_duration(seconds: float) -> str:
    """Formate une durée en texte lisible."""
    if seconds < 60:
        return t("duration.seconds", n=int(seconds))
    elif seconds < 3600:
        return t("duration.minutes", n=int(seconds // 60))
    elif seconds < 86400:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return t("duration.hours", h=h, m=m)
    else:
        j = int(seconds // 86400)
        key = "duration.days_plural" if j > 1 else "duration.days"
        return t(key, n=j)


# ─── Text Report ─────────────────────────────────────────────────────────────


def generate_report(analyses: list[dict], anomalies: list[dict], output_path: str | None = None):
    """Génère un rapport forensique complet."""
    lines = []
    lines.append("=" * 80)
    lines.append(t("report.title").upper())
    lines.append(f"{t('report.date_label')} : {datetime.now().strftime('%d/%m/%Y à %H:%M')}")
    lines.append(f"{t('report.docs_analyzed')} : {len(analyses)}")
    lines.append("=" * 80)

    # ── Section 1 ──
    lines.append("")
    lines.append("━" * 80)
    lines.append(f"1. {t('sections.inventory').upper()}")
    lines.append("━" * 80)

    for a in sorted(analyses, key=lambda x: x["fichier"]):
        lines.append(f"\n  ▸ {a['fichier']}")
        lines.append(f"    {t('fields.type')} : {a['type']} | {t('fields.size')} : {_format_size(a['taille_fichier'])}")
        if a["type"] == "DOCX":
            lines.append(f"    {t('fields.original_creator')} : {a.get('createur', t('fields.na'))}")
            lines.append(f"    {t('fields.last_modifier')} : {a.get('dernier_modificateur', t('fields.na'))}")
            lines.append(f"    {t('fields.creation_date')} : {_format_date(a.get('date_creation', ''))}")
            lines.append(f"    {t('fields.modification_date')} : {_format_date(a.get('date_modification', ''))}")
            lines.append(f"    {t('fields.revision')} : {a.get('revision', t('fields.na'))}")
            lines.append(f"    {t('fields.editing_time')} : {a.get('temps_edition_min', t('fields.na'))} {t('fields.minutes')}")
            lines.append(f"    {t('fields.application')} : {a.get('application', t('fields.na'))} v{a.get('version_app', '?')}")
            lines.append(f"    {t('fields.template')} : {a.get('modele', t('fields.na'))}")
            lines.append(f"    {t('fields.pages')} : {a.get('pages', '?')} | {t('fields.words')} : {a.get('mots', '?')}")
            lines.append(f"    {t('fields.rsid_sessions')} : {a.get('nb_rsids', 0)}")
            lines.append(f"    {t('fields.embedded_media')} : {a.get('nb_medias', 0)}")
            if a.get("doc_id_w14"):
                lines.append(f"    {t('fields.doc_id')} (w14) : {a.get('doc_id_w14')}")
            if a.get("doc_id_w15"):
                lines.append(f"    {t('fields.doc_id')} (w15) : {a.get('doc_id_w15')}")
            if a.get("liens_externes"):
                lines.append(f"    {t('fields.external_links')} : {len(a['liens_externes'])}")
                for lien in a["liens_externes"]:
                    lines.append(f"      - [{lien['type']}] {lien['cible']}")
        elif a["type"] == "PDF":
            lines.append(f"    {t('fields.pdf_version')} : {a.get('version_pdf', t('fields.na'))}")
            lines.append(f"    {t('fields.pages')} : {a.get('nb_pages', '?')}")
            lines.append(f"    {t('fields.creator_software')} : {a.get('createur_logiciel', t('fields.na'))}")
            lines.append(f"    {t('fields.producer')} : {a.get('producteur', t('fields.na'))}")
            lines.append(f"    {t('fields.creation_date')} : {a.get('date_creation', t('fields.na'))}")
            lines.append(f"    {t('fields.modification_date')} : {a.get('date_modification', t('fields.na'))}")
            lines.append(f"    {t('fields.images')} : {a.get('nb_images', 0)}")
            lines.append(f"    {t('fields.encrypted')} : {t('fields.yes') if a.get('chiffre') else t('fields.no')}")
            lines.append(f"    {t('fields.pdf_objects')} : {a.get('objets_totaux', '?')}")

    # ── Section 2 : Analyse croisée DOCX ──
    docx_analyses = [a for a in analyses if a["type"] == "DOCX"]
    if docx_analyses:
        lines.append("")
        lines.append("━" * 80)
        lines.append(f"2. {t('sections.cross_analysis').upper()}")
        lines.append("━" * 80)

        lines.append(f"\n  {t('cross.common_creator')} : " +
                     ", ".join(set(a.get("createur", "") for a in docx_analyses)))
        lines.append(f"  {t('cross.modifiers')} : " +
                     ", ".join(set(a.get("dernier_modificateur", "") for a in docx_analyses)))

        lines.append(f"\n  {t('cross.editing_timeline')} :")
        mods = []
        for a in docx_analyses:
            dt = parse_iso_date(a.get("date_modification", ""))
            if dt:
                mods.append((a["fichier"], dt, a.get("revision", "?"), a.get("temps_edition_min", "?")))
        mods.sort(key=lambda x: x[1])
        for i, (nom, dt, rev, temps) in enumerate(mods, 1):
            lines.append(f"    {i}. {dt.strftime('%d/%m/%Y %H:%M')} — {nom}")
            lines.append(f"       {t('fields.revision')} {rev} | {t('cross.cumulated_editing')} : {temps} min")

    # ── Section 3 : Comparaison DOCX ↔ PDF ──
    pairs = defaultdict(dict)
    for a in analyses:
        base = re.sub(r"\.(docx|pdf)$", "", a["fichier"], flags=re.IGNORECASE)
        pairs[base][a["type"]] = a

    has_pairs = any(len(v) == 2 for v in pairs.values())
    if has_pairs:
        lines.append("")
        lines.append("━" * 80)
        lines.append(f"3. {t('sections.comparison').upper()}")
        lines.append("━" * 80)

        for base in sorted(pairs.keys()):
            docs = pairs[base]
            if "DOCX" not in docs or "PDF" not in docs:
                continue
            docx = docs["DOCX"]
            pdf = docs["PDF"]
            lines.append(f"\n  ▸ {base}")

            docx_mod = parse_iso_date(docx.get("date_modification", ""))
            pdf_create = parse_pdf_date(pdf.get("date_creation_brut", pdf.get("date_creation", "")))

            lines.append(f"    {t('comparison.docx_modified_on')} : {docx_mod.strftime('%d/%m/%Y %H:%M') if docx_mod else t('fields.na')}")
            lines.append(f"    {t('comparison.pdf_created_on')} :     {pdf_create.strftime('%d/%m/%Y %H:%M') if pdf_create else t('fields.na')}")

            if docx_mod and pdf_create:
                diff = (pdf_create - docx_mod).total_seconds()
                if diff >= 0:
                    lines.append(f"    {t('comparison.delay_docx_pdf')} : {_format_duration(diff)}")
                else:
                    lines.append(f"    ⚠ {t('comparison.pdf_created_before', duration=_format_duration(abs(diff)))}")

            lines.append(f"    {t('comparison.pdf_method_label')} : {pdf.get('createur_logiciel', t('fields.na'))}")
            lines.append(f"    {t('comparison.pdf_producer_label')} : {pdf.get('producteur', t('fields.na'))}")

    # ── Section 4 : Anomalies ──
    lines.append("")
    lines.append("━" * 80)
    lines.append(f"4. {t('sections.anomalies').upper()}")
    lines.append("━" * 80)

    sev_haute = t("severity.haute")
    sev_moyenne = t("severity.moyenne")
    sev_info = t("severity.info")

    if not anomalies:
        lines.append(f"\n  {t('anomalies.no_anomalies')}")
    else:
        sev_order = {sev_haute: 0, sev_moyenne: 1, sev_info: 2}
        anomalies_sorted = sorted(anomalies, key=lambda x: sev_order.get(x["severite"], 3))

        for a in anomalies_sorted:
            icon = {sev_haute: "🔴", sev_moyenne: "🟡", sev_info: "🔵"}.get(a["severite"], "⚪")
            lines.append(f"\n  {icon} [{a['severite']}] {a['type']}")
            lines.append(f"     {t('anomalies.documents_label')} : {a['document']}")
            detail = a["detail"]
            while len(detail) > 70:
                cut = detail[:70].rfind(" ")
                if cut == -1:
                    cut = 70
                lines.append(f"     {detail[:cut]}")
                detail = detail[cut:].lstrip()
            if detail:
                lines.append(f"     {detail}")

    # ── Section 5 : Conclusions ──
    lines.append("")
    lines.append("━" * 80)
    lines.append(f"5. {t('sections.conclusions').upper()}")
    lines.append("━" * 80)

    conclusions = _generate_conclusions(analyses, anomalies)
    for c in conclusions:
        lines.append(f"\n  • {c}")

    # ── Section 6 : Glossaire ──
    glossary = _translations.get("glossary", [])
    if glossary:
        lines.append("")
        lines.append("━" * 80)
        lines.append(f"6. {t('sections.glossary').upper()}")
        lines.append("━" * 80)

        for entry in glossary:
            lines.append(f"\n  {entry['term']}")
            mots = entry["definition"].split()
            ligne = "    "
            for mot in mots:
                if len(ligne) + len(mot) + 1 > 76:
                    lines.append(ligne)
                    ligne = "    " + mot
                else:
                    ligne += (" " if ligne.strip() else "") + mot
            if ligne.strip():
                lines.append(ligne)

    lines.append("")
    lines.append("=" * 80)
    lines.append(t("report.end"))
    lines.append("=" * 80)

    report = "\n".join(lines)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"\n[green]{t('report.title')} → {output_path}[/green]")

    return report


def _generate_conclusions(analyses: list[dict], anomalies: list[dict]) -> list[str]:
    """Génère des conclusions automatiques."""
    conclusions = []
    docx_analyses = [a for a in analyses if a["type"] == "DOCX"]
    pdf_analyses = [a for a in analyses if a["type"] == "PDF"]

    createurs = set(a.get("createur", "") for a in docx_analyses if a.get("createur"))
    dates_creation = set(a.get("date_creation", "") for a in docx_analyses if a.get("date_creation"))
    if len(createurs) == 1 and len(dates_creation) == 1:
        conclusions.append(t("conclusions.common_template",
            creator=createurs.pop(), date=_format_date(dates_creation.pop())))

    scanners = set(a.get("createur_logiciel", "") for a in pdf_analyses if "scan" in a.get("createur_logiciel", "").lower())
    if scanners:
        conclusions.append(t("conclusions.scan_workflow", scanners=", ".join(scanners)))

    modificateurs = set(a.get("dernier_modificateur", "") for a in docx_analyses if a.get("dernier_modificateur"))
    if len(modificateurs) == 1:
        conclusions.append(t("conclusions.single_modifier", modifier=modificateurs.pop()))

    mods = []
    for a in docx_analyses:
        dt = parse_iso_date(a.get("date_modification", ""))
        if dt:
            mods.append(dt)
    if mods:
        mods.sort()
        span = (mods[-1] - mods[0]).total_seconds()
        if span < 7200:
            conclusions.append(t("conclusions.batch_session", duration=_format_duration(span)))

    sev_haute = t("severity.haute")
    hautes = [a for a in anomalies if a["severite"] == sev_haute]
    if hautes:
        conclusions.append(t("conclusions.high_anomalies", count=len(hautes)))
    else:
        conclusions.append(t("conclusions.no_critical"))

    return conclusions


def _format_size(size_bytes: int) -> str:
    """Formate une taille en octets."""
    if size_bytes < 1024:
        return f"{size_bytes} o"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} Ko"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} Mo"


def _format_date(iso_date: str) -> str:
    """Formate une date ISO en format lisible."""
    dt = parse_iso_date(iso_date)
    if dt:
        return dt.strftime("%d/%m/%Y à %H:%M")
    return iso_date or t("fields.na")


# ─── PDF Report ──────────────────────────────────────────────────────────────


def generate_pdf_report(analyses: list[dict], anomalies: list[dict], output_path: str):
    """Génère un rapport forensique au format PDF."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table as RLTable, TableStyle,
    )

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()

    s_title = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=20, spaceAfter=6, textColor=colors.HexColor("#1a1a2e"))
    s_subtitle = ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#666666"), spaceAfter=16)
    s_heading = ParagraphStyle("SectionHeading", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1a1a2e"), spaceBefore=18, spaceAfter=8, borderWidth=1, borderColor=colors.HexColor("#1a1a2e"), borderPadding=4)
    s_subheading = ParagraphStyle("SubHeading", parent=styles["Heading3"], fontSize=10, textColor=colors.HexColor("#333333"), spaceBefore=10, spaceAfter=4)
    s_body = ParagraphStyle("BodyText2", parent=styles["Normal"], fontSize=9, leading=13, spaceAfter=4)
    s_field = ParagraphStyle("FieldLabel", parent=styles["Normal"], fontSize=8.5, leading=12, leftIndent=12, textColor=colors.HexColor("#333333"))
    s_alert_haute = ParagraphStyle("AlertHaute", parent=styles["Normal"], fontSize=9, leading=13, leftIndent=12, backColor=colors.HexColor("#fde8e8"), borderWidth=0.5, borderColor=colors.HexColor("#e53e3e"), borderPadding=6, spaceBefore=6, spaceAfter=4)
    s_alert_moyenne = ParagraphStyle("AlertMoyenne", parent=styles["Normal"], fontSize=9, leading=13, leftIndent=12, backColor=colors.HexColor("#fefce8"), borderWidth=0.5, borderColor=colors.HexColor("#d69e2e"), borderPadding=6, spaceBefore=6, spaceAfter=4)
    s_alert_info = ParagraphStyle("AlertInfo", parent=styles["Normal"], fontSize=9, leading=13, leftIndent=12, backColor=colors.HexColor("#ebf4ff"), borderWidth=0.5, borderColor=colors.HexColor("#3182ce"), borderPadding=6, spaceBefore=6, spaceAfter=4)
    s_conclusion = ParagraphStyle("Conclusion", parent=styles["Normal"], fontSize=9.5, leading=14, leftIndent=12, spaceBefore=4, spaceAfter=4, bulletIndent=0, bulletFontSize=10)

    story = []

    # ── Header ──
    story.append(Paragraph(t("report.title"), s_title))
    story.append(Paragraph(
        f"{t('report.date_label')} : {datetime.now().strftime('%d/%m/%Y à %H:%M')}  |  "
        f"{t('report.docs_analyzed')} : {len(analyses)}", s_subtitle))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1a1a2e")))

    # ── Section 1 ──
    story.append(Paragraph(f"1. {t('sections.summary')}", s_heading))

    header = [t("fields.file"), t("fields.type"), t("fields.size"), t("fields.creator_or_software"), t("fields.modification_date"), t("cross.revision_label")]
    table_data = [header]
    for a in sorted(analyses, key=lambda x: x["fichier"]):
        nom = a["fichier"]
        if len(nom) > 40:
            nom = nom[:37] + "..."
        if a["type"] == "DOCX":
            table_data.append([nom, "DOCX", _format_size(a["taille_fichier"]), a.get("createur", ""), _format_date(a.get("date_modification", "")), a.get("revision", "")])
        else:
            table_data.append([nom, "PDF", _format_size(a["taille_fichier"]), a.get("createur_logiciel", "")[:30], a.get("date_creation", ""), str(a.get("nb_pages", ""))])

    tbl = RLTable(table_data, repeatRows=1, hAlign="LEFT")
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5), ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("LEADING", (0, 0), (-1, -1), 10),
        ("ALIGN", (2, 0), (2, -1), "RIGHT"), ("ALIGN", (5, 0), (5, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(tbl)

    # ── Section 2 : Detail ──
    story.append(Paragraph(f"2. {t('sections.detail')}", s_heading))

    for a in sorted(analyses, key=lambda x: x["fichier"]):
        story.append(Paragraph(f"<b>{a['fichier']}</b>", s_subheading))
        if a["type"] == "DOCX":
            fields = [
                (t("fields.original_creator"), a.get("createur", t("fields.na"))),
                (t("fields.last_modifier"), a.get("dernier_modificateur", t("fields.na"))),
                (t("fields.creation_date"), _format_date(a.get("date_creation", ""))),
                (t("fields.modification_date"), _format_date(a.get("date_modification", ""))),
                (t("fields.revision"), a.get("revision", t("fields.na"))),
                (t("fields.editing_time"), f"{a.get('temps_edition_min', t('fields.na'))} {t('fields.minutes')}"),
                (t("fields.application"), f"{a.get('application', t('fields.na'))} v{a.get('version_app', '?')}"),
                (t("fields.template"), a.get("modele", t("fields.na"))),
                (t("fields.pages_words"), f"{a.get('pages', '?')} {t('fields.pages_unit')}, {a.get('mots', '?')} {t('fields.words_unit')}"),
                (t("fields.rsid_sessions"), str(a.get("nb_rsids", 0))),
                (t("fields.embedded_media"), str(a.get("nb_medias", 0))),
            ]
            if a.get("doc_id_w15"):
                fields.append((t("fields.doc_id"), a.get("doc_id_w15", "")))
        else:
            fields = [
                (t("fields.pdf_version"), a.get("version_pdf", t("fields.na"))),
                (t("fields.pages"), str(a.get("nb_pages", "?"))),
                (t("fields.creator_software"), a.get("createur_logiciel", t("fields.na"))),
                (t("fields.producer"), a.get("producteur", t("fields.na"))),
                (t("fields.creation_date"), a.get("date_creation", t("fields.na"))),
                (t("fields.modification_date"), a.get("date_modification", t("fields.na"))),
                (t("fields.images"), str(a.get("nb_images", 0))),
                (t("fields.encrypted"), t("fields.yes") if a.get("chiffre") else t("fields.no")),
            ]

        field_data = [[Paragraph(f"<b>{k}</b>", s_field), Paragraph(v, s_field)] for k, v in fields]
        ft = RLTable(field_data, colWidths=[4.5 * cm, 12 * cm], hAlign="LEFT")
        ft.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#e0e0e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ft)
        story.append(Spacer(1, 4 * mm))

    # ── Section 3 : Cross analysis ──
    docx_analyses = [a for a in analyses if a["type"] == "DOCX"]
    if docx_analyses:
        story.append(Paragraph(f"3. {t('sections.cross_analysis')}", s_heading))

        createurs = ", ".join(set(a.get("createur", "") for a in docx_analyses))
        modificateurs = ", ".join(set(a.get("dernier_modificateur", "") for a in docx_analyses))
        story.append(Paragraph(
            f"<b>{t('cross.common_creator')} :</b> {createurs} &nbsp;|&nbsp; "
            f"<b>{t('cross.modifiers')} :</b> {modificateurs}", s_body))

        story.append(Paragraph(f"<b>{t('cross.editing_timeline')} :</b>", s_body))
        mods = []
        for a in docx_analyses:
            dt = parse_iso_date(a.get("date_modification", ""))
            if dt:
                mods.append((a["fichier"], dt, a.get("revision", "?"), a.get("temps_edition_min", "?")))
        mods.sort(key=lambda x: x[1])

        chrono_data = [["#", "Date", t("comparison.document"), t("cross.revision_label"), t("cross.edition_label")]]
        for i, (nom, dt, rev, temps) in enumerate(mods, 1):
            short_nom = nom if len(nom) <= 45 else nom[:42] + "..."
            chrono_data.append([str(i), dt.strftime("%d/%m/%Y %H:%M"), short_nom, str(rev), f"{temps} min"])

        ct = RLTable(chrono_data, repeatRows=1, hAlign="LEFT")
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8), ("LEADING", (0, 0), (-1, -1), 11),
            ("ALIGN", (0, 0), (0, -1), "CENTER"), ("ALIGN", (3, 0), (4, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ct)

    # ── Section 4 : Comparison ──
    pairs = defaultdict(dict)
    for a in analyses:
        base = re.sub(r"\.(docx|pdf)$", "", a["fichier"], flags=re.IGNORECASE)
        pairs[base][a["type"]] = a

    has_pairs = any(len(v) == 2 for v in pairs.values())
    if has_pairs:
        story.append(Paragraph(f"4. {t('sections.comparison')}", s_heading))

        comp_data = [[t("comparison.document"), t("comparison.docx_modified"), t("comparison.pdf_created"), t("comparison.delay"), t("comparison.pdf_method")]]
        for base in sorted(pairs.keys()):
            docs = pairs[base]
            if "DOCX" not in docs or "PDF" not in docs:
                continue
            docx = docs["DOCX"]
            pdf = docs["PDF"]
            docx_mod = parse_iso_date(docx.get("date_modification", ""))
            pdf_create = parse_pdf_date(pdf.get("date_creation_brut", pdf.get("date_creation", "")))
            delai = ""
            if docx_mod and pdf_create:
                diff = (pdf_create - docx_mod).total_seconds()
                delai = _format_duration(abs(diff))
                if diff < 0:
                    delai = f"(-{delai})"
            short_base = base if len(base) <= 35 else base[:32] + "..."
            comp_data.append([
                short_base,
                docx_mod.strftime("%H:%M") if docx_mod else t("fields.na"),
                pdf_create.strftime("%H:%M") if pdf_create else t("fields.na"),
                delai,
                pdf.get("createur_logiciel", t("fields.na"))[:25],
            ])

        cpt = RLTable(comp_data, repeatRows=1, hAlign="LEFT")
        cpt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5), ("LEADING", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (3, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(cpt)

    # ── Section 5 : Anomalies ──
    section_num = 5 if has_pairs else 4
    story.append(Paragraph(f"{section_num}. {t('sections.anomalies')}", s_heading))

    sev_haute = t("severity.haute")
    sev_moyenne = t("severity.moyenne")
    sev_info = t("severity.info")

    if not anomalies:
        story.append(Paragraph(t("anomalies.no_anomalies"), s_body))
    else:
        sev_order = {sev_haute: 0, sev_moyenne: 1, sev_info: 2}
        style_map = {sev_haute: s_alert_haute, sev_moyenne: s_alert_moyenne, sev_info: s_alert_info}
        color_map = {sev_haute: "#e53e3e", sev_moyenne: "#d69e2e", sev_info: "#3182ce"}

        for a in sorted(anomalies, key=lambda x: sev_order.get(x["severite"], 3)):
            color = color_map.get(a["severite"], "#666")
            text = (
                f'<font color="{color}"><b>● [{a["severite"]}] {a["type"]}</b></font><br/>'
                f'<font size="8"><b>{t("anomalies.documents_label")} :</b> {a["document"]}</font><br/>'
                f'<font size="8">{a["detail"]}</font>'
            )
            story.append(Paragraph(text, style_map.get(a["severite"], s_body)))

    # ── Section 6 : Conclusions ──
    section_num += 1
    story.append(Paragraph(f"{section_num}. {t('sections.conclusions')}", s_heading))

    conclusions = _generate_conclusions(analyses, anomalies)
    for c in conclusions:
        story.append(Paragraph(f"• {c}", s_conclusion))

    # ── Section 7 : Glossary ──
    glossary = _translations.get("glossary", [])
    if glossary:
        section_num += 1
        story.append(Paragraph(f"{section_num}. {t('sections.glossary')}", s_heading))

        s_glossaire_terme = ParagraphStyle("GlossaireTerm", parent=styles["Normal"], fontSize=9.5, leading=13, spaceBefore=8, spaceAfter=2, textColor=colors.HexColor("#1a1a2e"), fontName="Helvetica-Bold")
        s_glossaire_def = ParagraphStyle("GlossaireDef", parent=styles["Normal"], fontSize=8.5, leading=12, leftIndent=12, spaceAfter=4, textColor=colors.HexColor("#444444"))

        for entry in glossary:
            story.append(Paragraph(entry["term"], s_glossaire_terme))
            story.append(Paragraph(entry["definition"], s_glossaire_def))

    # ── Footer ──
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Paragraph(
        f'<font size="7" color="#999999">'
        f'{t("report.generated_by")} — {datetime.now().strftime("%d/%m/%Y %H:%M")}'
        f"</font>", styles["Normal"]))

    doc.build(story)
    console.print(f"[green]{t('report.title')} (PDF) → {output_path}[/green]")


# ─── Rich Console Output ─────────────────────────────────────────────────────


def print_rich_report(analyses: list[dict], anomalies: list[dict]):
    """Affiche un rapport riche dans le terminal."""
    console.print()
    console.print(Panel(f"[bold]{t('report.title').upper()}[/bold]", style="bold blue", expand=False))

    table = Table(title=t("sections.summary"), show_lines=True)
    table.add_column(t("fields.file"), style="cyan", max_width=45)
    table.add_column(t("fields.type"), style="bold")
    table.add_column(t("fields.size"), justify="right")
    table.add_column(t("fields.creator"), style="yellow")
    table.add_column(t("fields.modification_date"), style="green")
    table.add_column(t("fields.revisions"), justify="center")

    for a in sorted(analyses, key=lambda x: x["fichier"]):
        if a["type"] == "DOCX":
            table.add_row(a["fichier"], a["type"], _format_size(a["taille_fichier"]), a.get("createur", ""), _format_date(a.get("date_modification", "")), a.get("revision", ""))
        else:
            table.add_row(a["fichier"], a["type"], _format_size(a["taille_fichier"]), a.get("createur_logiciel", ""), a.get("date_creation", ""), str(a.get("nb_pages", "")))

    console.print(table)

    sev_haute = t("severity.haute")
    sev_moyenne = t("severity.moyenne")
    sev_info = t("severity.info")

    if anomalies:
        console.print()
        anomaly_table = Table(title=t("sections.anomalies"), show_lines=True)
        anomaly_table.add_column("Sév.", style="bold", width=8)
        anomaly_table.add_column(t("fields.type"), style="cyan", width=18)
        anomaly_table.add_column(t("anomalies.documents_label"), width=25)
        anomaly_table.add_column("Détail", max_width=50)

        sev_order = {sev_haute: 0, sev_moyenne: 1, sev_info: 2}
        for a in sorted(anomalies, key=lambda x: sev_order.get(x["severite"], 3)):
            sev_style = {sev_haute: "bold red", sev_moyenne: "yellow", sev_info: "blue"}.get(a["severite"], "")
            anomaly_table.add_row(Text(a["severite"], style=sev_style), a["type"], a["document"], a["detail"])
        console.print(anomaly_table)


# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    # Pre-parse --lang to load translations before argparse uses them
    lang = "fr"
    for i, arg in enumerate(os.sys.argv):
        if arg == "--lang" and i + 1 < len(os.sys.argv):
            lang = os.sys.argv[i + 1]
            break
    else:
        lang = detect_system_language()

    load_translations(lang)

    parser = argparse.ArgumentParser(description=t("cli.description"))
    parser.add_argument("chemin", nargs="?", default="docs", help=t("cli.path_help"))
    parser.add_argument("-o", "--output", help=t("cli.output_help"))
    parser.add_argument("--pdf", help=t("cli.pdf_help"))
    parser.add_argument("--lang", default=lang, help=t("cli.lang_help"))
    parser.add_argument("--no-rich", action="store_true", help=t("cli.no_rich_help"))
    args = parser.parse_args()

    # Reload if --lang was parsed differently
    if args.lang != lang:
        load_translations(args.lang)

    path = args.chemin
    files = []
    if os.path.isdir(path):
        files.extend(glob.glob(os.path.join(path, "**/*.docx"), recursive=True))
        files.extend(glob.glob(os.path.join(path, "**/*.pdf"), recursive=True))
    elif os.path.isfile(path):
        files.append(path)
    else:
        console.print(f"[red]{t('cli.error_path', path=path)}[/red]")
        return

    if not files:
        console.print(f"[red]{t('cli.error_no_files', path=path)}[/red]")
        return

    console.print(f"\n[bold]{t('cli.analyzing', count=len(files))}[/bold]\n")

    analyses = []
    for f in sorted(files):
        ext = os.path.splitext(f)[1].lower()
        try:
            if ext == ".docx":
                analyses.append(analyze_docx(f))
                console.print(f"  [green]✓[/green] {os.path.basename(f)}")
            elif ext == ".pdf":
                analyses.append(analyze_pdf(f))
                console.print(f"  [green]✓[/green] {os.path.basename(f)}")
        except Exception as e:
            console.print(f"  [red]✗[/red] {os.path.basename(f)} — {e}")

    anomalies = detect_anomalies(analyses)

    if not args.no_rich:
        print_rich_report(analyses, anomalies)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.dirname(path) if os.path.isfile(path) else path

    output = args.output or os.path.join(output_dir, f"rapport_forensique_{timestamp}.txt")
    generate_report(analyses, anomalies, output)

    pdf_output = args.pdf or os.path.join(output_dir, f"rapport_forensique_{timestamp}.pdf")
    generate_pdf_report(analyses, anomalies, pdf_output)


if __name__ == "__main__":
    main()
