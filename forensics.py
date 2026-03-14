#!/usr/bin/env python3
"""
Document Forensics Tool
Analyse forensique de documents DOCX et PDF.
Extrait les métadonnées, détecte les anomalies et génère des rapports en français.
"""

import argparse
import glob
import os
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

import pikepdf
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ─── Glossaire ────────────────────────────────────────────────────────────────

GLOSSAIRE = [
    (
        "RSID (Revision Save ID)",
        "Identifiant unique généré automatiquement par Microsoft Word à chaque "
        "session de sauvegarde. Chaque fois qu'un utilisateur ouvre un document, "
        "le modifie et le sauvegarde, un nouveau RSID est ajouté. L'analyse des "
        "RSID permet de retracer l'historique d'édition du document et de "
        "déterminer si deux documents partagent une origine commune (copiés "
        "depuis le même fichier source).",
    ),
    (
        "Métadonnées Dublin Core (core.xml)",
        "Ensemble de propriétés standardisées stockées dans le fichier interne "
        "core.xml d'un document Office. Comprend le créateur original, le dernier "
        "modificateur, les dates de création et modification, le numéro de "
        "révision, le titre et les mots-clés. Ces données sont souvent "
        "invisibles pour l'utilisateur mais constituent une trace forensique "
        "précieuse.",
    ),
    (
        "Propriétés étendues (app.xml)",
        "Métadonnées techniques stockées dans app.xml : application utilisée "
        "(ex. Microsoft Word), version, modèle de base (template), temps "
        "d'édition cumulé, nombre de pages, mots, caractères et paragraphes. "
        "Le temps d'édition est le total cumulé de toutes les sessions "
        "d'ouverture du document.",
    ),
    (
        "Numéro de révision",
        "Compteur incrémenté par Word à chaque sauvegarde du document. "
        "Un numéro élevé par rapport au temps d'édition peut indiquer des "
        "sauvegardes fréquentes ou automatiques. Ce chiffre permet d'estimer "
        "le nombre de fois où le document a été ouvert et modifié.",
    ),
    (
        "Temps d'édition (TotalTime)",
        "Durée cumulée, en minutes, pendant laquelle le document a été ouvert "
        "dans l'application. Ce temps s'additionne à travers toutes les "
        "sessions d'édition depuis la création du fichier. Attention : il "
        "inclut aussi le temps d'inactivité si le document reste ouvert.",
    ),
    (
        "ID document (w14 / w15)",
        "Identifiant unique attribué au document par Word. Le w14 (Word 2010+) "
        "est un identifiant hexadécimal court. Le w15 (Word 2012+) est un GUID "
        "complet. Quand deux fichiers partagent le même ID, cela prouve qu'ils "
        "ont été copiés depuis le même fichier source — l'identifiant n'est "
        "attribué qu'une seule fois, lors de la première création.",
    ),
    (
        "Modèle (Template)",
        "Le fichier modèle (.dotm ou .dotx) utilisé comme base pour créer le "
        "document. « Normal.dotm » est le modèle par défaut de Word. Un modèle "
        "personnalisé peut indiquer l'utilisation d'un gabarit d'entreprise.",
    ),
    (
        "XMP (Extensible Metadata Platform)",
        "Standard Adobe de métadonnées embarquées dans les fichiers PDF. "
        "Contient des informations similaires au Dublin Core (auteur, dates, "
        "logiciel) dans un format XML. Certains logiciels ajoutent des "
        "métadonnées supplémentaires dans le bloc XMP.",
    ),
    (
        "Producteur PDF (Producer)",
        "Logiciel ayant généré le fichier PDF final. Distinct du « Créateur » "
        "(Creator) qui est le logiciel d'origine. Par exemple, un document "
        "scanné aura comme Creator le logiciel du scanner et comme Producer "
        "le système d'exploitation qui a assemblé le PDF (ex. macOS Quartz "
        "PDFContext).",
    ),
    (
        "Créateur PDF (Creator)",
        "Logiciel ou périphérique ayant initialement produit le contenu. "
        "Pour un scan, c'est le modèle du scanner. Pour un export depuis "
        "Word, c'est « Microsoft Word ». Cette information permet de "
        "déterminer le procédé de fabrication du PDF.",
    ),
    (
        "Objets PDF",
        "Éléments constitutifs internes d'un fichier PDF : pages, polices, "
        "images, annotations, formulaires, etc. Un nombre élevé d'objets "
        "peut indiquer un document complexe ou modifié plusieurs fois. "
        "Chaque modification incrémentale ajoute de nouveaux objets.",
    ),
]


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
        # Liste de tous les fichiers dans l'archive
        info["fichiers_archive"] = z.namelist()
        info["nb_fichiers"] = len(z.namelist())

        # core.xml — métadonnées Dublin Core
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

        # app.xml — propriétés de l'application
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

        # settings.xml — RSIDs, identifiants de document
        if "word/settings.xml" in z.namelist():
            settings_xml = z.read("word/settings.xml").decode("utf-8")
            settings = ET.fromstring(settings_xml)

            # RSIDs (Revision Save IDs)
            rsids = []
            rsids_elem = settings.find(".//w:rsids", NS)
            if rsids_elem is not None:
                for child in rsids_elem:
                    val = child.get(f"{{{NS['w']}}}val")
                    if val:
                        rsids.append(val)
            info["rsids"] = rsids
            info["nb_rsids"] = len(rsids)

            # Document IDs
            for prefix, nskey in [("w14", "w14"), ("w15", "w15")]:
                did = settings.find(f".//{prefix}:docId", NS)
                if did is not None:
                    val = did.get(f"{{{NS[nskey]}}}val")
                    if val:
                        info[f"doc_id_{prefix}"] = val

        # document.xml — suivi des modifications
        if "word/document.xml" in z.namelist():
            doc_xml = z.read("word/document.xml").decode("utf-8")
            info["modifications_suivies_insertions"] = len(
                re.findall(r"<w:ins ", doc_xml)
            )
            info["modifications_suivies_suppressions"] = len(
                re.findall(r"<w:del ", doc_xml)
            )

            # Auteurs des révisions
            auteurs_rev = set(re.findall(r'w:author="([^"]+)"', doc_xml))
            info["auteurs_revisions"] = list(auteurs_rev)

        # Médias embarqués
        medias = [f for f in z.namelist() if f.startswith("word/media/")]
        info["medias"] = medias
        info["nb_medias"] = len(medias)

        # Tailles des fichiers internes
        tailles = {}
        for zi in z.infolist():
            tailles[zi.filename] = zi.file_size
        info["tailles_internes"] = tailles

        # Relations (liens externes, etc.)
        if "word/_rels/document.xml.rels" in z.namelist():
            rels = ET.fromstring(z.read("word/_rels/document.xml.rels"))
            liens_ext = []
            for rel in rels:
                mode = rel.get("TargetMode", "")
                if mode == "External":
                    liens_ext.append(
                        {
                            "type": rel.get("Type", "").split("/")[-1],
                            "cible": rel.get("Target", ""),
                        }
                    )
            info["liens_externes"] = liens_ext

    # Taille du fichier
    info["taille_fichier"] = os.path.getsize(filepath)

    return info


def _xml_text(root: ET.Element, tag: str, ns: str = None) -> str:
    """Extrait le texte d'un tag XML avec gestion des namespaces."""
    if ns:
        elem = root.find(f"{{{NS[ns]}}}{tag}")
    else:
        # Try with namespace prefix
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

        # Métadonnées du dictionnaire /Info
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
                # Convertir les dates PDF en format lisible
                if "date" in fr_key.lower():
                    dt = parse_pdf_date(raw)
                    info[fr_key] = dt.strftime("%d/%m/%Y à %H:%M:%S") if dt else raw
                    info[fr_key + "_brut"] = raw
                else:
                    info[fr_key] = raw

        # XMP metadata
        if pdf.open_metadata() is not None:
            try:
                with pdf.open_metadata() as meta:
                    xmp_raw = str(meta)
                    info["xmp_brut"] = xmp_raw[:2000] if len(xmp_raw) > 2000 else xmp_raw
            except Exception:
                pass

        # Analyse de la structure
        info["objets_totaux"] = len(pdf.objects)

        # Détection d'images
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

        # Chiffrement
        info["chiffre"] = pdf.is_encrypted

    return info


def parse_pdf_date(date_str: str) -> datetime | None:
    """Parse une date PDF (format D:YYYYMMDDHHmmSS)."""
    if not date_str:
        return None
    m = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", date_str)
    if m:
        return datetime(
            int(m.group(1)),
            int(m.group(2)),
            int(m.group(3)),
            int(m.group(4)),
            int(m.group(5)),
            int(m.group(6)),
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
    """Extrait une date du nom de fichier. Supporte plusieurs formats courants."""
    # Retirer l'extension
    name = re.sub(r"\.(docx|pdf|xlsx|pptx)$", "", filename, flags=re.IGNORECASE)

    patterns = [
        # DD.MM.YYYY ou DD-MM-YYYY ou DD/MM/YYYY
        (r"(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{4})", "dmy"),
        # YYYY-MM-DD ou YYYY.MM.DD
        (r"(\d{4})[.\-/](\d{1,2})[.\-/](\d{1,2})", "ymd"),
        # DDMMYYYY (8 chiffres consécutifs)
        (r"(\d{2})(\d{2})(\d{4})", "dmy_compact"),
        # YYYYMMDD
        (r"(\d{4})(\d{2})(\d{2})", "ymd_compact"),
    ]

    for pattern, fmt in patterns:
        m = re.search(pattern, name)
        if m:
            try:
                if fmt == "dmy":
                    d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
                elif fmt == "ymd":
                    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
                elif fmt == "dmy_compact":
                    d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
                elif fmt == "ymd_compact":
                    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
                else:
                    continue
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

        # Récupérer les dates réelles selon le type
        if a["type"] == "DOCX":
            date_mod = parse_iso_date(a.get("date_modification", ""))
            date_crea = parse_iso_date(a.get("date_creation", ""))
        else:
            date_mod = parse_pdf_date(a.get("date_modification_brut", a.get("date_modification", "")))
            date_crea = parse_pdf_date(a.get("date_creation_brut", a.get("date_creation", "")))

        # Comparer avec la date de modification (la plus pertinente)
        date_reelle = date_mod or date_crea
        if date_reelle:
            # Comparer uniquement les dates (pas les heures)
            delta_jours = abs((date_reelle.date() - date_nom.date()).days)
            if delta_jours > 7:
                severite = "HAUTE" if delta_jours > 90 else "MOYENNE"
                anomalies.append(
                    {
                        "type": "DATE NOM DE FICHIER",
                        "severite": severite,
                        "document": a["fichier"],
                        "detail": (
                            f"La date dans le nom du fichier ({date_nom.strftime('%d/%m/%Y')}) "
                            f"ne correspond pas à la date réelle de modification "
                            f"({date_reelle.strftime('%d/%m/%Y')}). "
                            f"Écart de {delta_jours} jours. "
                            f"{'Le document a été modifié bien après la date indiquée dans son nom.' if date_reelle > date_nom else 'Le document a été modifié avant la date indiquée dans son nom.'}"
                        ),
                    }
                )

    # Grouper par paires DOCX/PDF (même nom de base)
    pairs = defaultdict(dict)
    for a in analyses:
        base = re.sub(r"\.(docx|pdf)$", "", a["fichier"], flags=re.IGNORECASE)
        pairs[base][a["type"]] = a

    for base, docs in pairs.items():
        if "DOCX" in docs and "PDF" in docs:
            docx = docs["DOCX"]
            pdf = docs["PDF"]

            # Comparer les dates
            docx_mod = parse_iso_date(docx.get("date_modification", ""))
            pdf_mod = parse_pdf_date(pdf.get("date_modification", ""))

            if docx_mod and pdf_mod:
                diff = abs((pdf_mod - docx_mod).total_seconds())
                if diff > 3600:  # Plus d'une heure d'écart
                    anomalies.append(
                        {
                            "type": "CHRONOLOGIE",
                            "severite": "HAUTE" if diff > 86400 else "MOYENNE",
                            "document": base,
                            "detail": (
                                f"Écart de {_format_duration(diff)} entre la modification du DOCX "
                                f"({docx_mod.strftime('%d/%m/%Y %H:%M')}) et la création du PDF "
                                f"({pdf_mod.strftime('%d/%m/%Y %H:%M')})"
                            ),
                        }
                    )

            # PDF scanné vs DOCX numérique
            creator = pdf.get("createur_logiciel", "")
            if "scanner" in creator.lower() or "scan" in creator.lower():
                anomalies.append(
                    {
                        "type": "PROCÉDÉ",
                        "severite": "INFO",
                        "document": base,
                        "detail": (
                            f"Le PDF provient d'un scan ({creator}) alors que le DOCX est un "
                            f"document numérique natif. Le document a probablement été imprimé "
                            f"puis re-scanné (perte de traçabilité numérique)."
                        ),
                    }
                )

    # Analyse inter-documents
    docx_analyses = [a for a in analyses if a["type"] == "DOCX"]

    if len(docx_analyses) > 1:
        # Même date de création pour tous les DOCX
        dates_creation = set(a.get("date_creation", "") for a in docx_analyses)
        if len(dates_creation) == 1 and dates_creation != {""}:
            date_val = dates_creation.pop()
            anomalies.append(
                {
                    "type": "MODÈLE COMMUN",
                    "severite": "INFO",
                    "document": "Tous les DOCX",
                    "detail": (
                        f"Tous les documents DOCX partagent la même date de création "
                        f"({date_val}), indiquant qu'ils proviennent du même modèle de base."
                    ),
                }
            )

        # Même créateur original
        createurs = set(a.get("createur", "") for a in docx_analyses)
        if len(createurs) == 1 and createurs != {""}:
            anomalies.append(
                {
                    "type": "AUTEUR",
                    "severite": "INFO",
                    "document": "Tous les DOCX",
                    "detail": (
                        f"Tous les documents ont le même créateur original : "
                        f"« {createurs.pop()} ». Ils proviennent du même modèle."
                    ),
                }
            )

        # Analyse du temps d'édition vs nombre de révisions
        for a in docx_analyses:
            temps = int(a.get("temps_edition_min", "0") or "0")
            revisions = int(a.get("revision", "0") or "0")
            if revisions > 0 and temps > 0:
                min_par_rev = temps / revisions
                if min_par_rev < 1:
                    anomalies.append(
                        {
                            "type": "RYTHME D'ÉDITION",
                            "severite": "MOYENNE",
                            "document": a["fichier"],
                            "detail": (
                                f"Moins d'une minute par révision ({min_par_rev:.1f} min/rév.) "
                                f"— {revisions} révisions en {temps} minutes. "
                                f"Possibilité de sauvegardes automatiques ou édition par script."
                            ),
                        }
                    )

        # RSIDs partagés entre documents (résumé groupé)
        rsid_sets = {}
        for a in docx_analyses:
            if "rsids" in a:
                rsid_sets[a["fichier"]] = set(a["rsids"])

        if len(rsid_sets) > 1:
            # Calculer l'intersection globale
            all_sets = list(rsid_sets.values())
            rsid_commun_global = all_sets[0]
            for s in all_sets[1:]:
                rsid_commun_global = rsid_commun_global & s

            if rsid_commun_global:
                pcts = []
                for nom, s in rsid_sets.items():
                    pcts.append(f"{nom}: {len(rsid_commun_global)}/{len(s)} ({len(rsid_commun_global)/len(s)*100:.0f}%)")

                anomalies.append(
                    {
                        "type": "RSID PARTAGÉS",
                        "severite": "INFO",
                        "document": "Tous les DOCX",
                        "detail": (
                            f"{len(rsid_commun_global)} identifiants de session d'édition (RSID) "
                            f"sont communs à l'ensemble des {len(rsid_sets)} documents. "
                            f"Cela confirme qu'ils proviennent tous du même fichier source "
                            f"(copie successive du modèle). "
                            f"Détail : {'; '.join(pcts)}."
                        ),
                    }
                )

            # Identifier les paires avec des RSIDs partagés au-delà du noyau commun
            fichiers = list(rsid_sets.keys())
            for i in range(len(fichiers)):
                for j in range(i + 1, len(fichiers)):
                    communs = rsid_sets[fichiers[i]] & rsid_sets[fichiers[j]]
                    extra = communs - rsid_commun_global
                    if extra:
                        anomalies.append(
                            {
                                "type": "RSID SUPPLÉMENTAIRES",
                                "severite": "MOYENNE",
                                "document": f"{fichiers[i]} ↔ {fichiers[j]}",
                                "detail": (
                                    f"{len(extra)} RSID supplémentaires partagés au-delà du "
                                    f"noyau commun. Ces documents ont probablement été copiés "
                                    f"l'un de l'autre (pas directement du modèle)."
                                ),
                            }
                        )

        # Chronologie d'édition
        mods = []
        for a in docx_analyses:
            dt = parse_iso_date(a.get("date_modification", ""))
            if dt:
                mods.append((a["fichier"], dt))
        mods.sort(key=lambda x: x[1])
        if mods:
            total_span = (mods[-1][1] - mods[0][1]).total_seconds()
            if total_span > 0 and total_span < 7200:  # Moins de 2h pour tout faire
                anomalies.append(
                    {
                        "type": "CHRONOLOGIE",
                        "severite": "INFO",
                        "document": "Tous les DOCX",
                        "detail": (
                            f"Tous les documents ont été modifiés dans un intervalle de "
                            f"{_format_duration(total_span)} "
                            f"(de {mods[0][1].strftime('%H:%M')} à {mods[-1][1].strftime('%H:%M')} "
                            f"le {mods[0][1].strftime('%d/%m/%Y')}), "
                            f"suggérant une session d'édition en lot."
                        ),
                    }
                )

    return anomalies


def _format_duration(seconds: float) -> str:
    """Formate une durée en texte lisible."""
    if seconds < 60:
        return f"{int(seconds)} secondes"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h{m:02d}"
    else:
        j = int(seconds // 86400)
        return f"{j} jour{'s' if j > 1 else ''}"


# ─── Report Generation ───────────────────────────────────────────────────────


def generate_report(analyses: list[dict], anomalies: list[dict], output_path: str | None = None):
    """Génère un rapport forensique complet en français."""
    lines = []
    lines.append("=" * 80)
    lines.append("RAPPORT D'ANALYSE FORENSIQUE DOCUMENTAIRE")
    lines.append(f"Date du rapport : {datetime.now().strftime('%d/%m/%Y à %H:%M')}")
    lines.append(f"Nombre de documents analysés : {len(analyses)}")
    lines.append("=" * 80)

    # ── Section 1 : Résumé des documents ──
    lines.append("")
    lines.append("━" * 80)
    lines.append("1. INVENTAIRE DES DOCUMENTS")
    lines.append("━" * 80)

    for a in sorted(analyses, key=lambda x: x["fichier"]):
        lines.append(f"\n  ▸ {a['fichier']}")
        lines.append(f"    Type : {a['type']} | Taille : {_format_size(a['taille_fichier'])}")
        if a["type"] == "DOCX":
            lines.append(f"    Créateur : {a.get('createur', 'N/A')}")
            lines.append(f"    Dernier modificateur : {a.get('dernier_modificateur', 'N/A')}")
            lines.append(f"    Date de création : {_format_date(a.get('date_creation', ''))}")
            lines.append(f"    Date de modification : {_format_date(a.get('date_modification', ''))}")
            lines.append(f"    Révision n° : {a.get('revision', 'N/A')}")
            lines.append(f"    Temps d'édition : {a.get('temps_edition_min', 'N/A')} minutes")
            lines.append(f"    Application : {a.get('application', 'N/A')} v{a.get('version_app', '?')}")
            lines.append(f"    Modèle : {a.get('modele', 'N/A')}")
            lines.append(f"    Pages : {a.get('pages', '?')} | Mots : {a.get('mots', '?')}")
            lines.append(f"    Sessions d'édition (RSID) : {a.get('nb_rsids', 0)}")
            lines.append(f"    Médias embarqués : {a.get('nb_medias', 0)}")
            if a.get("doc_id_w14"):
                lines.append(f"    ID document (w14) : {a.get('doc_id_w14')}")
            if a.get("doc_id_w15"):
                lines.append(f"    ID document (w15) : {a.get('doc_id_w15')}")
            if a.get("liens_externes"):
                lines.append(f"    Liens externes : {len(a['liens_externes'])}")
                for lien in a["liens_externes"]:
                    lines.append(f"      - [{lien['type']}] {lien['cible']}")
        elif a["type"] == "PDF":
            lines.append(f"    Version PDF : {a.get('version_pdf', 'N/A')}")
            lines.append(f"    Pages : {a.get('nb_pages', '?')}")
            lines.append(f"    Créateur (logiciel) : {a.get('createur_logiciel', 'N/A')}")
            lines.append(f"    Producteur : {a.get('producteur', 'N/A')}")
            lines.append(f"    Date de création : {a.get('date_creation', 'N/A')}")
            lines.append(f"    Date de modification : {a.get('date_modification', 'N/A')}")
            lines.append(f"    Nombre d'images : {a.get('nb_images', 0)}")
            lines.append(f"    Chiffré : {'Oui' if a.get('chiffre') else 'Non'}")
            lines.append(f"    Objets PDF : {a.get('objets_totaux', '?')}")

    # ── Section 2 : Analyse croisée DOCX ──
    docx_analyses = [a for a in analyses if a["type"] == "DOCX"]
    if docx_analyses:
        lines.append("")
        lines.append("━" * 80)
        lines.append("2. ANALYSE CROISÉE DES FICHIERS DOCX")
        lines.append("━" * 80)

        # Tableau de synthèse
        lines.append("\n  Créateur original commun : " +
                     ", ".join(set(a.get("createur", "") for a in docx_analyses)))
        lines.append("  Modificateurs : " +
                     ", ".join(set(a.get("dernier_modificateur", "") for a in docx_analyses)))

        lines.append("\n  Chronologie d'édition :")
        mods = []
        for a in docx_analyses:
            dt = parse_iso_date(a.get("date_modification", ""))
            if dt:
                mods.append((a["fichier"], dt, a.get("revision", "?"), a.get("temps_edition_min", "?")))
        mods.sort(key=lambda x: x[1])
        for i, (nom, dt, rev, temps) in enumerate(mods, 1):
            lines.append(f"    {i}. {dt.strftime('%d/%m/%Y %H:%M')} — {nom}")
            lines.append(f"       Révision {rev} | Temps d'édition cumulé : {temps} min")

    # ── Section 3 : Comparaison DOCX ↔ PDF ──
    pairs = defaultdict(dict)
    for a in analyses:
        base = re.sub(r"\.(docx|pdf)$", "", a["fichier"], flags=re.IGNORECASE)
        pairs[base][a["type"]] = a

    has_pairs = any(len(v) == 2 for v in pairs.values())
    if has_pairs:
        lines.append("")
        lines.append("━" * 80)
        lines.append("3. COMPARAISON DOCX ↔ PDF (par document)")
        lines.append("━" * 80)

        for base in sorted(pairs.keys()):
            docs = pairs[base]
            if "DOCX" not in docs or "PDF" not in docs:
                continue
            docx = docs["DOCX"]
            pdf = docs["PDF"]
            lines.append(f"\n  ▸ {base}")

            docx_mod = parse_iso_date(docx.get("date_modification", ""))
            pdf_create = parse_pdf_date(pdf.get("date_creation", ""))

            lines.append(f"    DOCX modifié le : {docx_mod.strftime('%d/%m/%Y %H:%M') if docx_mod else 'N/A'}")
            lines.append(f"    PDF créé le :     {pdf_create.strftime('%d/%m/%Y %H:%M') if pdf_create else 'N/A'}")

            if docx_mod and pdf_create:
                diff = (pdf_create - docx_mod).total_seconds()
                if diff >= 0:
                    lines.append(f"    Délai DOCX → PDF : {_format_duration(diff)}")
                else:
                    lines.append(f"    ⚠ Le PDF a été créé AVANT la dernière modification DOCX ({_format_duration(abs(diff))} avant)")

            lines.append(f"    Méthode PDF : {pdf.get('createur_logiciel', 'N/A')}")
            lines.append(f"    Producteur PDF : {pdf.get('producteur', 'N/A')}")

    # ── Section 4 : Anomalies et alertes ──
    lines.append("")
    lines.append("━" * 80)
    lines.append("4. ANOMALIES ET ALERTES")
    lines.append("━" * 80)

    if not anomalies:
        lines.append("\n  Aucune anomalie détectée.")
    else:
        sev_order = {"HAUTE": 0, "MOYENNE": 1, "INFO": 2}
        anomalies_sorted = sorted(anomalies, key=lambda x: sev_order.get(x["severite"], 3))

        for i, a in enumerate(anomalies_sorted, 1):
            icon = {"HAUTE": "🔴", "MOYENNE": "🟡", "INFO": "🔵"}.get(a["severite"], "⚪")
            lines.append(f"\n  {icon} [{a['severite']}] {a['type']}")
            lines.append(f"     Document(s) : {a['document']}")
            # Wrap detail text
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
    lines.append("5. CONCLUSIONS")
    lines.append("━" * 80)

    conclusions = _generate_conclusions(analyses, anomalies)
    for c in conclusions:
        lines.append(f"\n  • {c}")

    # ── Section 6 : Glossaire ──
    lines.append("")
    lines.append("━" * 80)
    lines.append("6. GLOSSAIRE DES TERMES TECHNIQUES")
    lines.append("━" * 80)

    for terme, definition in GLOSSAIRE:
        lines.append(f"\n  {terme}")
        # Wrap à 74 caractères
        mots = definition.split()
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
    lines.append("FIN DU RAPPORT")
    lines.append("=" * 80)

    report = "\n".join(lines)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"\n[green]Rapport enregistré : {output_path}[/green]")

    return report


def _generate_conclusions(analyses: list[dict], anomalies: list[dict]) -> list[str]:
    """Génère des conclusions automatiques basées sur l'analyse."""
    conclusions = []
    docx_analyses = [a for a in analyses if a["type"] == "DOCX"]
    pdf_analyses = [a for a in analyses if a["type"] == "PDF"]

    # Origine commune
    createurs = set(a.get("createur", "") for a in docx_analyses if a.get("createur"))
    dates_creation = set(a.get("date_creation", "") for a in docx_analyses if a.get("date_creation"))
    if len(createurs) == 1 and len(dates_creation) == 1:
        conclusions.append(
            f"Tous les fichiers DOCX proviennent d'un modèle unique créé par "
            f"« {createurs.pop()} » le {_format_date(dates_creation.pop())}. "
            f"Les documents ont ensuite été personnalisés individuellement."
        )

    # Workflow détecté
    scanners = set(a.get("createur_logiciel", "") for a in pdf_analyses if "scan" in a.get("createur_logiciel", "").lower())
    if scanners:
        conclusions.append(
            f"Les fichiers PDF ont été produits par numérisation ({', '.join(scanners)}). "
            f"Le workflow est : édition DOCX → impression → signature manuscrite → scan PDF. "
            f"Ce processus introduit une rupture dans la chaîne de traçabilité numérique."
        )

    # Modificateur unique
    modificateurs = set(a.get("dernier_modificateur", "") for a in docx_analyses if a.get("dernier_modificateur"))
    if len(modificateurs) == 1:
        conclusions.append(
            f"Une seule personne (« {modificateurs.pop()} ») a effectué les modifications "
            f"sur l'ensemble des documents DOCX."
        )

    # Session d'édition
    mods = []
    for a in docx_analyses:
        dt = parse_iso_date(a.get("date_modification", ""))
        if dt:
            mods.append(dt)
    if mods:
        mods.sort()
        span = (mods[-1] - mods[0]).total_seconds()
        if span < 7200:
            conclusions.append(
                f"L'ensemble des modifications DOCX a été réalisé en une seule session "
                f"de travail ({_format_duration(span)})."
            )

    # Alertes hautes
    hautes = [a for a in anomalies if a["severite"] == "HAUTE"]
    if hautes:
        conclusions.append(
            f"{len(hautes)} anomalie(s) de sévérité haute détectée(s) nécessitant "
            f"une investigation approfondie."
        )
    elif not any(a["severite"] == "HAUTE" for a in anomalies):
        conclusions.append(
            "Aucune anomalie critique détectée. Les métadonnées sont globalement "
            "cohérentes avec un processus de production documentaire standard."
        )

    return conclusions


def _format_size(size_bytes: int) -> str:
    """Formate une taille en octets en texte lisible."""
    if size_bytes < 1024:
        return f"{size_bytes} o"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} Ko"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} Mo"


def _format_date(iso_date: str) -> str:
    """Formate une date ISO en format français."""
    dt = parse_iso_date(iso_date)
    if dt:
        return dt.strftime("%d/%m/%Y à %H:%M")
    return iso_date or "N/A"


# ─── PDF Report ──────────────────────────────────────────────────────────────


def generate_pdf_report(analyses: list[dict], anomalies: list[dict], output_path: str):
    """Génère un rapport forensique au format PDF."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()

    # Styles personnalisés
    s_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        spaceAfter=6,
        textColor=colors.HexColor("#1a1a2e"),
    )
    s_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#666666"),
        spaceAfter=16,
    )
    s_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#1a1a2e"),
        spaceBefore=18,
        spaceAfter=8,
        borderWidth=1,
        borderColor=colors.HexColor("#1a1a2e"),
        borderPadding=4,
    )
    s_subheading = ParagraphStyle(
        "SubHeading",
        parent=styles["Heading3"],
        fontSize=10,
        textColor=colors.HexColor("#333333"),
        spaceBefore=10,
        spaceAfter=4,
    )
    s_body = ParagraphStyle(
        "BodyText2",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        spaceAfter=4,
    )
    s_field = ParagraphStyle(
        "FieldLabel",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        leftIndent=12,
        textColor=colors.HexColor("#333333"),
    )
    s_alert_haute = ParagraphStyle(
        "AlertHaute",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        leftIndent=12,
        backColor=colors.HexColor("#fde8e8"),
        borderWidth=0.5,
        borderColor=colors.HexColor("#e53e3e"),
        borderPadding=6,
        spaceBefore=6,
        spaceAfter=4,
    )
    s_alert_moyenne = ParagraphStyle(
        "AlertMoyenne",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        leftIndent=12,
        backColor=colors.HexColor("#fefce8"),
        borderWidth=0.5,
        borderColor=colors.HexColor("#d69e2e"),
        borderPadding=6,
        spaceBefore=6,
        spaceAfter=4,
    )
    s_alert_info = ParagraphStyle(
        "AlertInfo",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        leftIndent=12,
        backColor=colors.HexColor("#ebf4ff"),
        borderWidth=0.5,
        borderColor=colors.HexColor("#3182ce"),
        borderPadding=6,
        spaceBefore=6,
        spaceAfter=4,
    )
    s_conclusion = ParagraphStyle(
        "Conclusion",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=14,
        leftIndent=12,
        spaceBefore=4,
        spaceAfter=4,
        bulletIndent=0,
        bulletFontSize=10,
    )

    story = []

    # ── En-tête ──
    story.append(Paragraph("Rapport d'analyse forensique documentaire", s_title))
    story.append(
        Paragraph(
            f"Date du rapport : {datetime.now().strftime('%d/%m/%Y à %H:%M')}  |  "
            f"Documents analysés : {len(analyses)}",
            s_subtitle,
        )
    )
    story.append(
        HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1a1a2e"))
    )

    # ── Section 1 : Tableau récapitulatif ──
    story.append(Paragraph("1. Synthèse des documents", s_heading))

    header = ["Fichier", "Type", "Taille", "Créateur / Logiciel", "Modification", "Rév."]
    table_data = [header]
    for a in sorted(analyses, key=lambda x: x["fichier"]):
        nom = a["fichier"]
        # Tronquer les noms longs
        if len(nom) > 40:
            nom = nom[:37] + "..."
        if a["type"] == "DOCX":
            table_data.append([
                nom,
                "DOCX",
                _format_size(a["taille_fichier"]),
                a.get("createur", ""),
                _format_date(a.get("date_modification", "")),
                a.get("revision", ""),
            ])
        else:
            table_data.append([
                nom,
                "PDF",
                _format_size(a["taille_fichier"]),
                a.get("createur_logiciel", "")[:30],
                a.get("date_creation", ""),
                str(a.get("nb_pages", "")),
            ])

    t = Table(table_data, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("LEADING", (0, 0), (-1, -1), 10),
        ("ALIGN", (2, 0), (2, -1), "RIGHT"),
        ("ALIGN", (5, 0), (5, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)

    # ── Section 2 : Détail par document ──
    story.append(Paragraph("2. Détail des métadonnées", s_heading))

    for a in sorted(analyses, key=lambda x: x["fichier"]):
        story.append(Paragraph(f"<b>{a['fichier']}</b>", s_subheading))

        if a["type"] == "DOCX":
            fields = [
                ("Créateur original", a.get("createur", "N/A")),
                ("Dernier modificateur", a.get("dernier_modificateur", "N/A")),
                ("Date de création", _format_date(a.get("date_creation", ""))),
                ("Date de modification", _format_date(a.get("date_modification", ""))),
                ("Révision", a.get("revision", "N/A")),
                ("Temps d'édition", f"{a.get('temps_edition_min', 'N/A')} minutes"),
                ("Application", f"{a.get('application', 'N/A')} v{a.get('version_app', '?')}"),
                ("Modèle", a.get("modele", "N/A")),
                ("Pages / Mots", f"{a.get('pages', '?')} pages, {a.get('mots', '?')} mots"),
                ("Sessions d'édition (RSID)", str(a.get("nb_rsids", 0))),
                ("Médias embarqués", str(a.get("nb_medias", 0))),
            ]
            if a.get("doc_id_w15"):
                fields.append(("ID document", a.get("doc_id_w15", "")))
        else:
            fields = [
                ("Version PDF", a.get("version_pdf", "N/A")),
                ("Pages", str(a.get("nb_pages", "?"))),
                ("Créateur (logiciel)", a.get("createur_logiciel", "N/A")),
                ("Producteur", a.get("producteur", "N/A")),
                ("Date de création", a.get("date_creation", "N/A")),
                ("Date de modification", a.get("date_modification", "N/A")),
                ("Images", str(a.get("nb_images", 0))),
                ("Chiffré", "Oui" if a.get("chiffre") else "Non"),
            ]

        # Rendu sous forme de mini-tableau compact
        field_data = [[f"<b>{k}</b>", v] for k, v in fields]
        ft = Table(
            [[Paragraph(r[0], s_field), Paragraph(r[1], s_field)] for r in field_data],
            colWidths=[4.5 * cm, 12 * cm],
            hAlign="LEFT",
        )
        ft.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 1.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#e0e0e0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ft)
        story.append(Spacer(1, 4 * mm))

    # ── Section 3 : Analyse croisée ──
    docx_analyses = [a for a in analyses if a["type"] == "DOCX"]
    if docx_analyses:
        story.append(Paragraph("3. Analyse croisée des fichiers DOCX", s_heading))

        createurs = ", ".join(set(a.get("createur", "") for a in docx_analyses))
        modificateurs = ", ".join(set(a.get("dernier_modificateur", "") for a in docx_analyses))
        story.append(Paragraph(
            f"<b>Créateur original commun :</b> {createurs} &nbsp;|&nbsp; "
            f"<b>Modificateurs :</b> {modificateurs}",
            s_body,
        ))

        story.append(Paragraph("<b>Chronologie d'édition :</b>", s_body))
        mods = []
        for a in docx_analyses:
            dt = parse_iso_date(a.get("date_modification", ""))
            if dt:
                mods.append((a["fichier"], dt, a.get("revision", "?"), a.get("temps_edition_min", "?")))
        mods.sort(key=lambda x: x[1])

        chrono_data = [["#", "Date", "Document", "Rév.", "Édition"]]
        for i, (nom, dt, rev, temps) in enumerate(mods, 1):
            short_nom = nom if len(nom) <= 45 else nom[:42] + "..."
            chrono_data.append([
                str(i),
                dt.strftime("%d/%m/%Y %H:%M"),
                short_nom,
                str(rev),
                f"{temps} min",
            ])

        ct = Table(chrono_data, repeatRows=1, hAlign="LEFT")
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 11),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (3, 0), (4, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(ct)

    # ── Section 4 : Comparaison DOCX ↔ PDF ──
    pairs = defaultdict(dict)
    for a in analyses:
        base = re.sub(r"\.(docx|pdf)$", "", a["fichier"], flags=re.IGNORECASE)
        pairs[base][a["type"]] = a

    has_pairs = any(len(v) == 2 for v in pairs.values())
    if has_pairs:
        story.append(Paragraph("4. Comparaison DOCX / PDF", s_heading))

        comp_data = [["Document", "DOCX modifié", "PDF créé", "Délai", "Méthode PDF"]]
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
                docx_mod.strftime("%H:%M") if docx_mod else "N/A",
                pdf_create.strftime("%H:%M") if pdf_create else "N/A",
                delai,
                pdf.get("createur_logiciel", "N/A")[:25],
            ])

        cpt = Table(comp_data, repeatRows=1, hAlign="LEFT")
        cpt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("LEADING", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (3, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(cpt)

    # ── Section 5 : Anomalies ──
    section_num = 5 if has_pairs else 4
    story.append(Paragraph(f"{section_num}. Anomalies et alertes", s_heading))

    if not anomalies:
        story.append(Paragraph("Aucune anomalie détectée.", s_body))
    else:
        sev_order = {"HAUTE": 0, "MOYENNE": 1, "INFO": 2}
        for a in sorted(anomalies, key=lambda x: sev_order.get(x["severite"], 3)):
            style_map = {"HAUTE": s_alert_haute, "MOYENNE": s_alert_moyenne, "INFO": s_alert_info}
            icon = {"HAUTE": "●", "MOYENNE": "●", "INFO": "●"}.get(a["severite"], "○")
            color = {"HAUTE": "#e53e3e", "MOYENNE": "#d69e2e", "INFO": "#3182ce"}.get(a["severite"], "#666")
            text = (
                f'<font color="{color}"><b>{icon} [{a["severite"]}] {a["type"]}</b></font><br/>'
                f'<font size="8"><b>Document(s) :</b> {a["document"]}</font><br/>'
                f'<font size="8">{a["detail"]}</font>'
            )
            story.append(Paragraph(text, style_map.get(a["severite"], s_body)))

    # ── Section 6 : Conclusions ──
    section_num += 1
    story.append(Paragraph(f"{section_num}. Conclusions", s_heading))

    conclusions = _generate_conclusions(analyses, anomalies)
    for c in conclusions:
        story.append(Paragraph(f"• {c}", s_conclusion))

    # ── Section 7 : Glossaire ──
    section_num += 1
    story.append(Paragraph(f"{section_num}. Glossaire des termes techniques", s_heading))

    s_glossaire_terme = ParagraphStyle(
        "GlossaireTerm",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=13,
        spaceBefore=8,
        spaceAfter=2,
        textColor=colors.HexColor("#1a1a2e"),
        fontName="Helvetica-Bold",
    )
    s_glossaire_def = ParagraphStyle(
        "GlossaireDef",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=12,
        leftIndent=12,
        spaceAfter=4,
        textColor=colors.HexColor("#444444"),
    )

    for terme, definition in GLOSSAIRE:
        story.append(Paragraph(terme, s_glossaire_terme))
        story.append(Paragraph(definition, s_glossaire_def))

    # ── Pied de page ──
    story.append(Spacer(1, 1 * cm))
    story.append(
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"))
    )
    story.append(
        Paragraph(
            f'<font size="7" color="#999999">'
            f"Rapport généré automatiquement par Document Forensics — "
            f'{datetime.now().strftime("%d/%m/%Y %H:%M")}'
            f"</font>",
            styles["Normal"],
        )
    )

    doc.build(story)
    console.print(f"[green]Rapport PDF enregistré : {output_path}[/green]")


# ─── Rich Console Output ─────────────────────────────────────────────────────


def print_rich_report(analyses: list[dict], anomalies: list[dict]):
    """Affiche un rapport riche dans le terminal."""
    console.print()
    console.print(
        Panel(
            "[bold]ANALYSE FORENSIQUE DOCUMENTAIRE[/bold]",
            style="bold blue",
            expand=False,
        )
    )

    # Tableau des documents
    table = Table(title="Documents analysés", show_lines=True)
    table.add_column("Fichier", style="cyan", max_width=45)
    table.add_column("Type", style="bold")
    table.add_column("Taille", justify="right")
    table.add_column("Créateur", style="yellow")
    table.add_column("Modification", style="green")
    table.add_column("Révisions", justify="center")

    for a in sorted(analyses, key=lambda x: x["fichier"]):
        if a["type"] == "DOCX":
            table.add_row(
                a["fichier"],
                a["type"],
                _format_size(a["taille_fichier"]),
                a.get("createur", ""),
                _format_date(a.get("date_modification", "")),
                a.get("revision", ""),
            )
        else:
            table.add_row(
                a["fichier"],
                a["type"],
                _format_size(a["taille_fichier"]),
                a.get("createur_logiciel", ""),
                a.get("date_creation", ""),
                str(a.get("nb_pages", "")),
            )

    console.print(table)

    # Anomalies
    if anomalies:
        console.print()
        anomaly_table = Table(title="Anomalies détectées", show_lines=True)
        anomaly_table.add_column("Sév.", style="bold", width=8)
        anomaly_table.add_column("Type", style="cyan", width=18)
        anomaly_table.add_column("Document(s)", width=25)
        anomaly_table.add_column("Détail", max_width=50)

        sev_order = {"HAUTE": 0, "MOYENNE": 1, "INFO": 2}
        for a in sorted(anomalies, key=lambda x: sev_order.get(x["severite"], 3)):
            sev_style = {"HAUTE": "bold red", "MOYENNE": "yellow", "INFO": "blue"}.get(
                a["severite"], ""
            )
            anomaly_table.add_row(
                Text(a["severite"], style=sev_style),
                a["type"],
                a["document"],
                a["detail"],
            )
        console.print(anomaly_table)


# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Analyse forensique de documents Office et PDF"
    )
    parser.add_argument(
        "chemin",
        nargs="?",
        default="docs",
        help="Dossier ou fichier à analyser (défaut: docs/)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Chemin du fichier de rapport texte",
    )
    parser.add_argument(
        "--pdf",
        help="Chemin du fichier de rapport PDF",
    )
    parser.add_argument(
        "--no-rich",
        action="store_true",
        help="Désactiver l'affichage enrichi (tableaux, couleurs)",
    )
    args = parser.parse_args()

    # Collecter les fichiers
    path = args.chemin
    files = []
    if os.path.isdir(path):
        files.extend(glob.glob(os.path.join(path, "**/*.docx"), recursive=True))
        files.extend(glob.glob(os.path.join(path, "**/*.pdf"), recursive=True))
    elif os.path.isfile(path):
        files.append(path)
    else:
        console.print(f"[red]Erreur : chemin introuvable : {path}[/red]")
        return

    if not files:
        console.print(f"[red]Aucun fichier DOCX ou PDF trouvé dans {path}[/red]")
        return

    console.print(f"\n[bold]Analyse de {len(files)} fichier(s)...[/bold]\n")

    # Analyser chaque fichier
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

    # Détecter les anomalies
    anomalies = detect_anomalies(analyses)

    # Affichage riche
    if not args.no_rich:
        print_rich_report(analyses, anomalies)

    # Nom de base horodaté pour les rapports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.dirname(path) if os.path.isfile(path) else path

    # Rapport texte
    output = args.output or os.path.join(output_dir, f"rapport_forensique_{timestamp}.txt")
    generate_report(analyses, anomalies, output)

    # Rapport PDF
    pdf_output = args.pdf or os.path.join(output_dir, f"rapport_forensique_{timestamp}.pdf")
    generate_pdf_report(analyses, anomalies, pdf_output)


if __name__ == "__main__":
    main()
