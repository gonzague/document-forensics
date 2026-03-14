# Document Forensics

Outil d'analyse forensique de documents Office (DOCX) et PDF. Extrait les metadonnees internes, detecte les anomalies et genere des rapports detailles en francais.

## Fonctionnalites

### Analyse DOCX (via XML interne)
- **Metadonnees Dublin Core** (core.xml) : createur, modificateur, dates de creation/modification, numero de revision
- **Proprietes etendues** (app.xml) : application, version, modele, temps d'edition cumule, statistiques (pages, mots, caracteres)
- **RSID** (Revision Save IDs) : identifiants de sessions d'edition pour tracer l'historique et detecter les copies
- **Identifiants de document** (w14/w15) : preuve de copie entre fichiers
- **Medias embarques**, liens externes, suivi des modifications

### Analyse PDF (via metadonnees)
- Dictionnaire `/Info` : auteur, createur, producteur, dates
- Metadonnees XMP
- Structure : nombre d'objets, images, chiffrement
- Detection du procede de fabrication (export numerique vs scan)

### Detection d'anomalies
- **Date du nom de fichier** : compare la date dans le nom du fichier avec les dates reelles des metadonnees
- **Chronologie DOCX / PDF** : detecte les ecarts temporels entre modification DOCX et creation PDF
- **Modele commun** : identifie les documents issus du meme fichier source
- **RSID partages** : analyse les sessions d'edition communes entre documents
- **Procede de fabrication** : signale les PDF scannes a partir de documents numeriques natifs
- **Session d'edition en lot** : detecte les modifications groupees sur un court intervalle

### Rapports
- **Terminal** : tableaux riches avec couleurs (via Rich)
- **Texte** : rapport complet en `.txt`
- **PDF** : rapport professionnel mis en page avec tableaux, alertes colorees et glossaire

## Installation

```bash
git clone https://github.com/gonzague/document-forensics.git
cd document-forensics
uv sync
```

## Utilisation

```bash
# Analyser un dossier (par defaut : docs/)
uv run python forensics.py chemin/vers/dossier/

# Specifier le fichier de sortie
uv run python forensics.py chemin/vers/dossier/ -o mon_rapport.txt

# Specifier le chemin du rapport PDF
uv run python forensics.py chemin/vers/dossier/ --pdf mon_rapport.pdf

# Analyser un seul fichier
uv run python forensics.py document.docx

# Desactiver l'affichage terminal enrichi
uv run python forensics.py chemin/ --no-rich
```

## Exemple de rapport

Le rapport genere contient les sections suivantes :

1. **Synthese des documents** : tableau recapitulatif de tous les fichiers analyses
2. **Detail des metadonnees** : informations completes pour chaque document
3. **Analyse croisee des fichiers DOCX** : chronologie d'edition, createurs communs
4. **Comparaison DOCX / PDF** : delais entre modification et numerisation
5. **Anomalies et alertes** : classees par severite (haute, moyenne, info)
6. **Conclusions** : synthese automatique des constats
7. **Glossaire** : explication des termes techniques (RSID, Dublin Core, XMP, etc.)

### Niveaux de severite

| Niveau | Signification |
|--------|---------------|
| HAUTE | Incoherence majeure necessitant une investigation |
| MOYENNE | Ecart notable a examiner |
| INFO | Constat informatif, comportement attendu |

## Cas d'usage

- **Audit documentaire** : verifier la coherence des metadonnees d'un lot de documents
- **Investigation** : detecter des falsifications ou antidatages
- **Conformite** : s'assurer que les documents suivent le workflow attendu
- **Due diligence** : analyser l'historique de production de documents contractuels

## Dependances

- [pikepdf](https://github.com/pikepdf/pikepdf) : analyse des metadonnees PDF
- [python-docx](https://github.com/python-openxml/python-docx) : lecture de fichiers DOCX
- [ReportLab](https://www.reportlab.com/) : generation de rapports PDF
- [Rich](https://github.com/Textualize/rich) : affichage terminal enrichi

## Licence

MIT
