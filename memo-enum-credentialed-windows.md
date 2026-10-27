# Mémo — Énumération credentialed depuis Windows

> Pendant Windows de [l'énum credentialed Linux](memo-enum-credentialed-linux.md).
> Hôte d'attaque Windows (ex. `MS01`), creds de domaine valides. Domaine : `INLANEFREIGHT.LOCAL`, DC = `ACADEMY-EA-DC01`.
> **Objectif** : misconfig / permissions (lateral & vertical movement), vue d'ensemble (trusts intra/inter-forêt),
> pillage des partages. Certaines trouvailles sont **informatives** (à mettre en annexe du rapport), pas que des chemins d'attaque.
> 💡 Les outils **natifs** (module AD PowerShell) sont plus **furtifs** que de déposer un outil sur l'hôte.

---

## 1. Module ActiveDirectory PowerShell (natif, furtif)

147 cmdlets d'admin AD. À importer avant usage.

```powershell
Get-Module                       # modules dispo (repérer Git, scripts admin custom...)
Import-Module ActiveDirectory    # charger le module AD
```

| Cmdlet | Rôle |
|--------|------|
| `Get-ADDomain` | Infos domaine : **DomainSID**, functional level, **ChildDomains**, forest, PDC... |
| `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` | Comptes avec **SPN** → cibles **Kerberoasting**. |
| `Get-ADTrust -Filter *` | **Trusts** : direction, intra/inter-forêt (`IntraForest`, `ForestTransitive`), type. |
| `Get-ADGroup -Filter * \| select name` | Tous les groupes. |
| `Get-ADGroup -Identity "Backup Operators"` | Détail d'un groupe (SID, scope...). |
| `Get-ADGroupMember -Identity "Backup Operators"` | Membres d'un groupe (ex. `backupagent` → chemin vers domain takeover). |

---

## 2. PowerView (PowerShell, situational awareness)

Issu de **PowerSploit** (déprécié) ; version maintenue par **BC-Security** (Empire 4). Dans `C:\Tools`.

```powershell
cd C:\Tools\
Import-Module .\PowerView.ps1
```

**Fonctions clés :**

| Fonction | Rôle |
|----------|------|
| `Get-Domain` / `Get-DomainController` | Objet AD du domaine / liste des DC. |
| `Get-DomainUser -Identity <user>` | Infos user (memberof, pwdlastset, admincount, UAC...). |
| `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName` | Users avec **SPN** (Kerberoasting). |
| `Get-DomainGroup` / `Get-DomainGroupMember -Identity "Domain Admins" -Recurse` | Groupes ; **`-Recurse`** = membership **imbriqué** (ex. `Secadmins` dans `Domain Admins`). |
| `Get-DomainTrustMapping` | Mappe **tous les trusts** vus (direction, `WITHIN_FOREST` / `FOREST_TRANSITIVE`). |
| `Test-AdminAccess -ComputerName <host>` | Teste si on est **admin local** sur un hôte (`IsAdmin: True`). |
| `Find-DomainUserLocation` / `Find-LocalAdminAccess` | Où un user est connecté / où on est admin local. |
| `Find-InterestingDomainShareFile` / `Find-DomainShare` | Partages & fichiers intéressants. |
| `Find-InterestingDomainAcl` | ACL avec droits de modif sur objets non-built-in. |
| `Get-DomainForeignUser` / `Get-DomainForeignGroupMember` | Users/membres **hors** de leur domaine (abus de trust). |
| `Export-PowerViewCSV` / `ConvertTo-SID` / `Get-DomainSPNTicket` | Export CSV / nom→SID / ticket Kerberos SPN. |

---

## 3. SharpView (.NET port de PowerView)

Utile si **PowerShell durci/bloqué** ou pour éviter PS. Mêmes fonctions que PowerView.

```powershell
.\SharpView.exe Get-DomainUser -Help          # lister les arguments d'une méthode
.\SharpView.exe Get-DomainUser -Identity forend
```

---

## 4. Snaffler (chasse aux creds dans les partages)

Récupère la liste des hôtes → énumère partages & dossiers lisibles → **chasse les fichiers sensibles**
(mdp, clés SSH, configs). À lancer depuis un hôte **joint au domaine** / contexte user de domaine.

```powershell
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```
- `-s` = afficher en console · `-d` domaine · `-o` logfile · `-v data` = verbosité (n'affiche que les résultats).
- Produit **beaucoup** de données → toujours **sortir en fichier**, laisser tourner, revenir dessus.
- **Code couleur** par criticité : `{Red}` (très sensible : `.key`, `.mdf`, `.sqldump`, `.keychain`), `{Green}` (partage), `{Black}`.
- Sortie brute utile à fournir au client (prioriser les partages à verrouiller).

---

## 5. SharpHound + BloodHound (GUI Windows)

**SharpHound** = collecteur C# (équivalent Windows de bloodhound-python).

```powershell
.\SharpHound.exe --help
.\SharpHound.exe -c All --zipfilename ILFREIGHT     # collecte toutes les méthodes → .zip
```
- `-c All` méthodes de collecte · `--stealth` (préférer DCOnly) · `-s` toute la forêt · `-f` filtre LDAP.

**Ingestion :** lancer `bloodhound` (CMD/PowerShell) → `Upload Data` → choisir le `.zip` → attendre 100%.
- Creds neo4j par défaut : **`neo4j` / `HTB_@cademy_stdnt!`**.

**Requêtes pré-faites utiles (onglet Analysis) :**
- `Find Shortest Paths To Domain Admins` → chemins d'escalade.
- `Find Computers with Unsupported Operating Systems` → OS legacy (Win7/2008, MS08-067...). ⚠️ vérifier s'ils sont **live** et prudence (hôtes fragiles).
- `Find Computers where Domain Users are Local Admin` → hôtes où **tout** user est admin local = win facile.
- Requêtes custom en **Cypher** (Raw Query).

> 📝 **Hygiène d'engagement** : documenter chaque fichier transféré (où, sur quel hôte), et **nettoyer** en fin de mission.

---

## 6. À retenir

| Besoin | Outil / commande |
|--------|------------------|
| Énum native furtive | Module **ActiveDirectory** (`Get-ADDomain`, `Get-ADUser`, `Get-ADGroup...`) |
| Infos domaine + SID + child domains | `Get-ADDomain` |
| Trusts | `Get-ADTrust -Filter *` / `Get-DomainTrustMapping` |
| Users avec SPN (Kerberoast) | `Get-ADUser -Filter {SPN -ne $null}` / `Get-DomainUser -SPN` |
| Membership imbriqué (DA) | `Get-DomainGroupMember -Identity "Domain Admins" -Recurse` |
| Suis-je admin local ? | `Test-AdminAccess -ComputerName <host>` → `(Pwn3d!)` côté CME |
| PowerShell bloqué | **SharpView** (`.exe`) |
| Chasse creds dans partages | **Snaffler** (`-s -d <dom> -o <log> -v data`), lire les `{Red}` |
| Collecte BloodHound (Windows) | **SharpHound** `-c All --zipfilename <nom>` → GUI (neo4j) |
| Requête star | `Find Shortest Paths To Domain Admins` |
| Cheat sheet syntaxe | **WADComs** |

> Suite : enquêter en **Living Off The Land** quand on ne peut pas importer d'outils (shell restreint, hôte managé sans Internet).
