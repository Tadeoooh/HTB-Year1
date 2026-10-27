# Mémo — Password Spraying & récupération de la Password Policy

> Contexte : pentest interne, boîte grise. Souvent lancé **en parallèle** du poisoning
> (cf. [LLMNR/NBT-NS Linux](memo-llmnr-nbtns-poisoning.md)). **Objectif** : identifiants valides.

---

## 0. Overview (l'essentiel)

- **1 mot de passe commun** testé sur **une longue liste d'users** (≠ brute force).
- Procéder par **vagues** avec un **délai** entre chaque → éviter les lockouts.
- Lockout typique : **5 essais** / auto-unlock **30 min** (parfois 3, ou unlock **manuel**).
- Sources d'users : OSINT, LinkedIn, métadonnées PDF, `jsmith.txt` (~40-60 % des comptes).
- **Règle d'or** : récupérer la **password policy AVANT** de spray (sinon 1-2 essais max, >1h d'écart).

---

## 1. Password Policy — depuis Linux, **avec identifiants**

### CrackMapExec
```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```
→ `Minimum password length`, `Account Lockout Threshold`, `Reset Account Lockout Counter`, etc.

---

## 2. Password Policy — depuis Linux, **sans identifiants**

### a) SMB NULL Session (rpcclient)
Session anonyme → listing users/groupes/machines + policy. Souvent dû à de **vieux DC migrés** en place.

```bash
rpcclient -U "" -N 172.16.5.5
```
```
rpcclient $> querydominfo     # infos domaine → confirme l'accès NULL
rpcclient $> getdompwinfo     # récupère la policy
min_password_length: 8
password_properties: 0x00000001  → DOMAIN_PASSWORD_COMPLEX
```

### b) enum4linux / enum4linux-ng
```bash
enum4linux -P 172.16.5.5                  # -P = password policy
enum4linux-ng -P 172.16.5.5 -oA ilfreight # -oA = export JSON + YAML
```
> `enum4linux` = wrapper autour de la suite Samba (`nmblookup`, `net`, `rpcclient`, `smbclient`).
> `enum4linux-ng` = réécriture Python, sortie plus claire + export `-oA` (JSON/YAML).

| Outil        | Ports                                          |
|--------------|------------------------------------------------|
| nmblookup    | 137/UDP                                        |
| nbtstat      | 137/UDP                                        |
| net          | 139/TCP, 135/TCP, UDP/TCP 135 + 49152-65535    |
| rpcclient    | 135/TCP                                        |
| smbclient    | 445/TCP                                        |

### c) LDAP Anonymous Bind (ldapsearch)
Legacy (bloqué par défaut depuis Windows Server 2003, mais parfois réactivé par erreur).
```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```
→ `minPwdLength: 8`, `lockoutThreshold: 5`, `pwdProperties: 1` (complexité activée).
> ⚠️ `-h` déprécié dans les versions récentes → utiliser `-H`.

---

## 3. Password Policy — depuis Windows

### a) net.exe (intégré — utile si on ne peut pas transférer d'outils)
```cmd
net accounts
```
→ `Minimum password length`, `Lockout threshold`, `Lockout duration`, `Maximum password age`…

### b) PowerView
```powershell
import-module .\PowerView.ps1
Get-DomainPolicy
```
→ même info que `net accounts` + confirme `PasswordComplexity=1`.
> Autres outils Windows : CrackMapExec (porté), SharpMapExec, SharpView.
> Choix selon furtivité / AV-EDR / restrictions sur l'hôte.

### SMB NULL session depuis Windows (moins courant)
```cmd
net use \\DC01\ipc$ "" /u:""      :: session null
```
Erreurs d'auth utiles à reconnaître :
| Erreur       | Signification                                   |
|--------------|-------------------------------------------------|
| System error 1331 | Compte **désactivé**                       |
| System error 1326 | **Mauvais** user/mot de passe              |
| System error 1909 | Compte **verrouillé** (lockout policy)     |

---

## 4. Analyser la policy (exemple INLANEFREIGHT)

- **Min length 8** → mots de passe faibles probables (`Welcome1`). De plus en plus d'orga : 10-14.
- **Lockout threshold 5** → on peut tenter **2-3 sprays** (safe) toutes les **31 min**.
- **Lockout duration 30 min** → unlock auto (⚠️ parfois unlock **manuel** par admin).
- **Complexité activée** → 3/4 parmi maj/min/chiffre/spécial (`Welcome1` passe = faible quand même).
- **Ne JAMAIS verrouiller de compte.**

### Policy par défaut d'un nouveau domaine (souvent jamais changée)
| Politique                        | Valeur par défaut |
|----------------------------------|-------------------|
| Enforce password history         | 24 jours          |
| Maximum password age             | 42 jours          |
| Minimum password age             | 1 jour            |
| Minimum password length          | 7                 |
| Complexité                       | Activée           |
| Reversible encryption            | Désactivée        |
| Account lockout threshold        | 0 (pas de lockout)|
| Lockout duration / reset counter | Non défini        |

---

## 5. Construire la liste d'users cibles

Prérequis au spray : une liste d'**users valides**. Quatre voies :
1. **SMB NULL session** → liste complète des users du DC.
2. **LDAP anonymous bind** → requête LDAP anonyme.
3. **Kerbrute** + wordlist (`statistically-likely-usernames`, ou `linkedin2username`).
4. **Identifiants valides** (fournis, ou obtenus via Responder / un premier spray).

> ⚠️ **Toujours garder un log** : comptes ciblés, DC utilisé, heure, date, mot(s) de passe tentés.
> → évite les doublons et permet de cross-checker avec le client en cas de lockout/alerte.

### a) SMB NULL session → liste d'users
```bash
# enum4linux : -U = users, puis nettoyage pour 1 user par ligne
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# rpcclient : commande enumdomusers après bind anonyme
rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers
```

### b) CrackMapExec `--users` (le plus pratique)
```bash
crackmapexec smb 172.16.5.5 --users                    # anonyme
crackmapexec smb 172.16.5.5 -u htb-student -p 'Academy_student_AD!' --users  # avec creds
```
- Affiche en plus **`badpwdcount`** (tentatives ratées) → **écarter** les comptes proches du lockout.
- **`baddpwdtime`** = dernière tentative ratée → voir si le compteur est près d'être reset.
- ⚠️ Multi-DC : `badpwdcount` est maintenu **par DC** → sommer, ou interroger le **PDC Emulator**.

### c) LDAP anonymous → users
```bash
# ldapsearch avec filtre
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" \
  | grep sAMAccountName: | cut -f2 -d" "

# windapsearch : -u "" = bind anonyme, -U = users uniquement
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

### d) Kerbrute — énumération via Kerberos Pre-Auth
```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```
- **Rapide + furtif** : ne génère **pas** l'event **4625** (logon failure).
- Principe : TGT sans pré-auth → `PRINCIPAL UNKNOWN` = user invalide ; prompt pré-auth = **valide**.
- L'**énumération** ne cause **pas** de lockout… mais le **spray** via Kerbrute **compte** les échecs → prudence.
- ⚠️ Génère l'event **4768** (TGT requested) si le logging Kerberos est activé → détectable en SIEM.

---

## 6. À retenir

| Point                              | Commande / valeur                              |
|------------------------------------|------------------------------------------------|
| Linux + creds (policy)             | `crackmapexec smb <DC> -u .. -p .. --pass-pol` |
| Linux, NULL session (policy)       | `rpcclient -U "" -N <DC>` → `getdompwinfo`     |
| Linux, énum large (policy)         | `enum4linux-ng -P <DC> -oA out`                |
| Linux, LDAP anonymous (policy)     | `ldapsearch -H ... -x -b "DC=..,DC=.." ...`    |
| Windows intégré (policy)           | `net accounts`                                 |
| Windows PowerView (policy)         | `Get-DomainPolicy`                             |
| NULL session Windows               | `net use \\DC\ipc$ "" /u:""`                   |
| Users via NULL session             | `enum4linux -U` / `rpcclient` → `enumdomusers` |
| Users + badpwdcount                | `crackmapexec smb <DC> --users`                |
| Users via LDAP anon                | `ldapsearch ... objectclass=user` / `windapsearch -u "" -U` |
| Users via Kerbrute (furtif)        | `kerbrute userenum -d <dom> --dc <DC> <liste>` |
| Fenêtre de spray safe (thr. 5)     | 2-3 essais / ~31 min                           |
| Events à connaître                 | 4625 (logon fail), 4768 (TGT), évités/générés  |
