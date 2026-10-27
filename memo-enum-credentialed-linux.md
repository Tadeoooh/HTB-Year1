# Mémo — Énumération credentialed depuis Linux

> Contexte : foothold obtenu → on creuse le domaine avec un **compte de domaine low-priv**.
> Hôte d'attaque : **ATTACK01** (Parrot), SSH en `htb-student`. Domaine : `INLANEFREIGHT.LOCAL`, DC = `172.16.5.5`.
> Creds du lab : **`forend : Klmcargo2`**.
> ⚠️ **Prérequis commun** : la plupart de ces outils exigent des **creds de domaine valides**
> (mdp clair, **hash NTLM**, ou SYSTEM sur un hôte joint). On vise le **DC** car il détient toute la base du domaine.
> On vise : users, computers, groupes, GPO, ACL, trusts, sessions.
> 💾 **Toujours sauvegarder les sorties dans des fichiers** (reporting + réutilisation par d'autres outils).

---

## 1. CrackMapExec (CME / désormais NetExec)

Couteau suisse AD (s'appuie sur **Impacket** + **PowerSploit**). Protocoles : `mssql`, `smb`, `ssh`, `winrm`.
> `crackmapexec -h`, puis aide par protocole : `crackmapexec smb -h`.

**Flags clés (SMB) :** `-u <user>` · `-p <pass>` (ou `-H <hash>` pour PtH) · `<cible>` · `-d <domaine>` / `--local-auth`.

```bash
# Énum des users du domaine (+ badPwdCount → utile pour spraying ciblé anti-lockout)
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users

# Énum des groupes du domaine (+ membercount)
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

# Users connectés sur un autre hôte (ici le file server)
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

# Partages + niveau d'accès (READ/WRITE)
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

# Spider d'un partage → fichiers lisibles (JSON dans /tmp/cme_spider_plus/<ip>)
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```

| Point                       | Détail                                                                 |
|-----------------------------|------------------------------------------------------------------------|
| `--users`                   | Liste users + **`badPwdCount`** (filtrer `>0` pour éviter le lockout).  |
| `--groups`                  | Liste groupes + `membercount` → repérer `Domain Admins`, `Executives`, IT admins. |
| `--loggedon-users`          | Qui est connecté → cible pour vol de creds en mémoire (ex. DA connecté).|
| **`(Pwn3d!)`**              | Après l'auth = notre user est **admin local** sur l'hôte.              |
| `--shares`                  | Partages non standard (`Department Shares`, `ZZZ_archive`) = à fouiller.|
| `-M spider_plus`            | Sortie JSON `/tmp/cme_spider_plus/<ip>.json` (chercher `web.config`, scripts, mdp). |
| `--sam`/`--lsa`/`--ntds`    | Dump secrets si admin.                                                  |
| `-x` / `-X`                 | Exécuter commande cmd / PowerShell.                                     |

> ⚠️ Préfixer les commandes de `sudo`.

---

## 2. SMBMap — énum des partages SMB

Lister partages + permissions + contenu, télécharger/uploader, exécuter des commandes.

```bash
# Accès et permissions sur les partages du DC
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

# Listing récursif des répertoires d'un partage (dossiers seulement)
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```
- `-H` = hôte cible, `-R` = récursif, `--dir-only` = dossiers seulement.
- Accès `READ` par défaut sur `IPC$`, `NETLOGON`, `SYSVOL` ; les partages **non standard** sont les plus intéressants.

---

## 3. rpcclient — MS-RPC / Samba

Énumère (et peut modifier) les objets AD. Possible en **NULL session** (non authentifié) si le domaine l'autorise.

```bash
rpcclient -U "" -N 172.16.5.5        # session NULL (unauth)
rpcclient -U forend 172.16.5.5       # authentifié
```
```
rpcclient $> enumdomusers           # tous les users + RID
rpcclient $> queryuser 0x457        # détails d'un user par RID (ici htb-student)
```

**RID (Relative Identifier)** : identifiant unique (hex) combiné au **SID** du domaine pour former le SID complet de l'objet.
- SID domaine + RID = SID unique de l'objet.
- `htb-student` : RID `0x457` = **1111** décimal.
- **Administrator** intégré : RID **`0x1f4` = 500** (toujours, partout). `guest` = 501, `krbtgt` = 502.

---

## 4. Impacket (psexec.py / wmiexec.py)

Toolkit Python d'interaction/exploitation des protocoles Windows. Exemple avec `wley : transporter@4`
(hash cracké via Responder plus tôt, **admin local** sur `ACADEMY-EA-FILE`).

```bash
# Shell SYSTEM : upload d'un .exe sur ADMIN$ → service via RPC/SCM → named pipe
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125

# Shell semi-interactif via WMI : pas de fichier déposé, moins de logs, tourne EN TANT QUE wley (pas SYSTEM)
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

| Outil         | Exécution                | Contexte | Furtivité                                         |
|---------------|--------------------------|----------|---------------------------------------------------|
| `psexec.py`   | service + ADMIN$ + SCM   | **SYSTEM** | Plus bruyant (fichier déposé, service créé).     |
| `wmiexec.py`  | WMI, semi-interactif     | user     | Plus discret (0 fichier), mais **Event ID 4688** (new process, `cmd.exe`) à chaque commande. |

> Prérequis : creds d'un user **admin local** sur la cible.

---

## 5. Windapsearch — énum LDAP (Python)

Dans `/opt/windapsearch/`. Dump users/groups/computers + requêtes ciblées.

```bash
# Membres de Domain Admins
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

# Users privilégiés (recherche RÉCURSIVE des membres imbriqués) → très utile en reporting
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```
- `-U` users · `-G` groups · `-C` computers · `--da` domain admins · **`-PU`** privileged users (nested).
- `-PU` révèle les privilèges excessifs via **appartenance imbriquée** (groupes privilégiés dans différentes langues).

---

## 6. BloodHound.py — collecte + graph d'attaque

Ingestor Python (requiert Impacket, ldap3, dnspython) → pas besoin d'un hôte Windows. Collecte users, groupes,
computers, membership, GPO, ACL, trusts, admin local, sessions, RDP/WinRM... → **chemins d'attaque** graphiques.

```bash
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```
- `-ns` = nameserver (le DC) · `-d` domaine · **`-c all`** = toutes les méthodes de collecte.
- Sortie : `<date>_users.json`, `_groups.json`, `_computers.json`, `_domains.json`... dans le CWD.

**Charger dans la GUI :**
```bash
zip -r ilfreight_bh.zip *.json     # regrouper les JSON
sudo neo4j start                   # démarrer la base
bloodhound                         # lancer la GUI (via freerdp) → bouton "Upload Data"
```
- Creds neo4j par défaut : **`neo4j` / `HTB_@cademy_stdnt!`**.
- Requête star : **`Find Shortest Paths To Domain Admins`** (onglet Analysis). Requêtes custom en **Cypher**.

> ⚠️ Même depuis l'hôte d'attaque, la collecte déclenche probablement des alertes en environnement bien protégé.

---

## 7. À retenir

| Besoin                              | Outil / commande                                                        |
|-------------------------------------|-------------------------------------------------------------------------|
| Users + badPwdCount                 | `cme smb <DC> -u <u> -p <p> --users`                                    |
| Groupes + membercount               | `cme smb <DC> ... --groups`                                             |
| Qui est connecté / admin local      | `cme smb <hôte> ... --loggedon-users` → **`(Pwn3d!)`**                  |
| Partages + perms                    | `cme ... --shares` / `smbmap -u .. -p .. -d .. -H <DC>`                 |
| Fouiller un partage                 | `cme ... -M spider_plus --share '<nom>'` → `/tmp/cme_spider_plus/`      |
| Users/RID (même en NULL session)    | `rpcclient -U "" -N <DC>` → `enumdomusers` / `queryuser <RID>`          |
| RID Administrator intégré           | **0x1f4 = 500** (toujours)                                              |
| Shell SYSTEM (admin local)          | `psexec.py dom/user:'pass'@<ip>`                                        |
| Shell discret (WMI)                 | `wmiexec.py dom/user:'pass'@<ip>` (⚠️ Event ID 4688)                    |
| Domain/privileged admins (nested)   | `windapsearch.py --dc-ip <DC> -u u@dom -p p --da` / `-PU`               |
| Graph / chemins vers DA             | `bloodhound-python -u .. -p .. -ns <DC> -d <dom> -c all` → GUI (neo4j)  |
| Cheat sheet syntaxe                 | **WADComs**                                                             |
