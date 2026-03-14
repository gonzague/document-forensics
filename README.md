# Document Forensics

Outil d'analyse forensique de documents Office (DOCX) et PDF. Extrait les métadonnées internes, détecte les anomalies et génère des rapports détaillés en français.

## Fonctionnalités

### Analyse DOCX (via XML interne)
- **Métadonnées Dublin Core** (core.xml) : créateur, modificateur, dates de création/modification, numéro de révision
- **Propriétés étendues** (app.xml) : application, version, modèle, temps d'édition cumulé, statistiques (pages, mots, caractères)
- **RSID** (Revision Save IDs) : identifiants de sessions d'édition pour tracer l'historique et détecter les copies
- **Identifiants de document** (w14/w15) : preuve de copie entre fichiers
- **Médias embarqués**, liens externes, suivi des modifications

### Analyse PDF (via métadonnées)
- Dictionnaire `/Info` : auteur, créateur, producteur, dates
- Métadonnées XMP
- Structure : nombre d'objets, images, chiffrement
- Détection du procédé de fabrication (export numérique vs scan)

### Détection d'anomalies
- **Date du nom de fichier** : compare la date dans le nom du fichier avec les dates réelles des métadonnées
- **Chronologie DOCX / PDF** : détecte les écarts temporels entre modification DOCX et création PDF
- **Modèle commun** : identifie les documents issus du même fichier source
- **RSID partagés** : analyse les sessions d'édition communes entre documents
- **Procédé de fabrication** : signale les PDF scannés à partir de documents numériques natifs
- **Session d'édition en lot** : détecte les modifications groupées sur un court intervalle

### Rapports
- **Terminal** : tableaux riches avec couleurs (via Rich)
- **Texte** : rapport complet en `.txt`
- **PDF** : rapport professionnel mis en page avec tableaux, alertes colorées et glossaire

## Installation

```bash
git clone https://github.com/gonzague/document-forensics.git
cd document-forensics
uv sync
```

## Utilisation

```bash
# Analyser un dossier (par défaut : docs/)
uv run python forensics.py chemin/vers/dossier/

# Spécifier le fichier de sortie
uv run python forensics.py chemin/vers/dossier/ -o mon_rapport.txt

# Spécifier le chemin du rapport PDF
uv run python forensics.py chemin/vers/dossier/ --pdf mon_rapport.pdf

# Analyser un seul fichier
uv run python forensics.py document.docx

# Désactiver l'affichage terminal enrichi
uv run python forensics.py chemin/ --no-rich
```

## Exemple de rapport

Le rapport généré contient les sections suivantes :

1. **Synthèse des documents** : tableau récapitulatif de tous les fichiers analysés
2. **Détail des métadonnées** : informations complètes pour chaque document
3. **Analyse croisée des fichiers DOCX** : chronologie d'édition, créateurs communs
4. **Comparaison DOCX / PDF** : délais entre modification et numérisation
5. **Anomalies et alertes** : classées par sévérité (haute, moyenne, info)
6. **Conclusions** : synthèse automatique des constats
7. **Glossaire** : explication des termes techniques (RSID, Dublin Core, XMP, etc.)

### Niveaux de sévérité

| Niveau | Signification |
|--------|---------------|
| HAUTE | Incohérence majeure nécessitant une investigation |
| MOYENNE | Écart notable à examiner |
| INFO | Constat informatif, comportement attendu |

## Cas d'usage

- **Audit documentaire** : vérifier la cohérence des métadonnées d'un lot de documents
- **Investigation** : détecter des falsifications ou antidatages
- **Conformité** : s'assurer que les documents suivent le workflow attendu
- **Due diligence** : analyser l'historique de production de documents contractuels

## Dépendances

- [pikepdf](https://github.com/pikepdf/pikepdf) : analyse des métadonnées PDF
- [python-docx](https://github.com/python-openxml/python-docx) : lecture de fichiers DOCX
- [ReportLab](https://www.reportlab.com/) : génération de rapports PDF
- [Rich](https://github.com/Textualize/rich) : affichage terminal enrichi

## Licence

MIT
