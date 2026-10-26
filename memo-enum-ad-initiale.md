# Mémo — Énumération initiale du domaine AD (Partie technique & outils)

> Contexte : pentest interne, boîte grise, non évasif. Hôte d'attaque Linux dans le réseau,
> sans identifiants. Plage cible : `172.16.5.0/23`. Domaine : `INLANEFREIGHT.LOCAL`.
> **Objectif** : obtenir un premier point d'appui (compte de domaine valide / hash NTLM / shell SYSTEM).

---

## 0. Règles de base

- **Tout documenter**, sauvegarder chaque scan dans un fichier.
- Nmap : toujours `-oA` (exports `.nmap` / `.gnmap` / `.xml`).
- Captures réseau : toujours garder le `.pcap` (relecture + rapport).
- Comprendre un scan **avant** de le lancer (NSE peut planter un hôte fragile).
- Legacy / exploitation → **accord écrit du client** d'abord.

---

## 1. Points de données à collecter

| Donnée            | But                                                              |
|-------------------|-----------------------------------------------------------------|
| Utilisateurs AD   | Cibles pour password spraying                                   |
| Machines jointes  | DC, serveurs de fichiers, SQL, web, Exchange                    |
| Services clés     | Kerberos 88, NetBIOS 139, LDAP 389/636, DNS 53, SMB 445, GC 3268|
| Hôtes vulnérables | Gains rapides (OS legacy → EternalBlue, MS08-067…)              |

---

## 2. Phase passive — écouter sans envoyer

### Wireshark (GUI)
```bash
sudo -E wireshark
```
- ARP → révèle les hôtes vivants (ex. `172.16.5.5`, `.25`, `.50`, `.100`, `.125`).
- MDNS → révèle des noms d'hôtes (ex. `ACADEMY-EA-WEB01.local`).

### tcpdump (sans GUI)
```bash
sudo tcpdump -i ens224                    # écoute live
sudo tcpdump -i ens224 -w capture.pcap    # sauvegarde pour analyse Wireshark
```
> Alternatives : net-creds, NetMiner, et `pktmon.exe` (intégré Windows 10+).

### Responder (mode Analyse)
```bash
sudo responder -I ens224 -A
```
- `-I` : interface — `-A` : **mode Analyse** (écoute LLMNR/NBT-NS/MDNS, **sans empoisonner**).
- Révèle des hôtes/noms DNS supplémentaires → compléter la liste cible.

---

## 3. Phase active — valider

### fping — balayage ICMP du /23
```bash
fping -asgq 172.16.5.0/23
```
| Flag | Rôle                                   |
|------|----------------------------------------|
| `a`  | Affiche seulement les hôtes vivants    |
| `s`  | Statistiques en fin de scan            |
| `g`  | Génère les cibles depuis le CIDR       |
| `q`  | Silencieux (pas de résultat par IP)    |

➡️ Produit la liste d'IP vivantes → l'injecter dans `hosts.txt`.

### Nmap — énumération détaillée
```bash
sudo nmap -v -A -iL hosts.txt -oA /home/htb-student/Documents/host-enum
```
- `-A` : scan agressif (versions, OS, scripts NSE, traceroute).
- `-iL hosts.txt` : liste d'hôtes en entrée.
- `-oA` : export multi-format (à systématiser).

**Champs utiles dans la sortie :**
- `ssl-cert` → `Subject:` / `commonName` / `Subject Alternative Name` (nom du host).
- `rdp-ntlm-info` → `DNS_Computer_Name`, `NetBIOS_Domain_Name`.
- `smb-os-discovery` → OS, FQDN, Forest name.
- `ms-sql-info` / `ms-sql-ntlm-info` → version SQL Server, nom NetBIOS.

**Scans ciblés pratiques :**
```bash
sudo nmap -A -p 636 172.16.5.5            # lire le commonName du certificat LDAPS
sudo nmap -Pn -sV -p 1433 --script ms-sql-info 172.16.5.0/23 -oA sql_scan
grep -i "2019\|15.00.2000" full_scan.nmap # retrouver une version SQL précise
```

---

## 4. Énumération des utilisateurs — Kerbrute

### Installation (compilation multi-plateforme)
```bash
sudo git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
make help          # options de build
sudo make all      # compile Linux/Windows/Mac (x86 + x64) dans dist/
sudo mv dist/kerbrute_linux_amd64 /usr/local/bin/kerbrute   # ajout au PATH
```

### Énumération
```bash
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```
- `-d` : domaine — `--dc` : IP du contrôleur de domaine — `-o` : fichier de sortie.
- **Furtif** : échec de pré-auth Kerberos → souvent pas de log/alerte.
- ⚠️ Un échec compte comme un login raté → **risque de lockout** (userenum n'envoie pas de mdp, donc sûr).
- Wordlists : `jsmith.txt` / `jsmith2.txt` (dépôt Insidetrust).

---

## 5. Accès SYSTEM (NT AUTHORITY\SYSTEM)

SYSTEM sur une machine jointe ≈ compte de domaine (usurpe le compte machine).

**Voies d'obtention :**
- Exploits distants : MS08-067, EternalBlue, BlueKeep.
- Abus de service SYSTEM / privilège `SeImpersonate` → Juicy Potato (OS anciens).
- LPE locale (ex. 0-day Task Scheduler Win10).
- Admin local + **PsExec** → `cmd` SYSTEM.

**Ce qu'on peut faire ensuite :**
- Énumérer le domaine (BloodHound, PowerView).
- Kerberoasting / ASREPRoasting.
- Inveigh (hashes Net-NTLMv2) / relais SMB.
- Token impersonation, attaques ACL.

---

## 6. Récap des ports AD à reconnaître

| Port       | Service                          |
|------------|----------------------------------|
| 53         | DNS                              |
| 88         | Kerberos                         |
| 135        | MSRPC                            |
| 139 / 445  | NetBIOS / SMB                    |
| 389 / 636  | LDAP / LDAPS                     |
| 464        | kpasswd                          |
| 3268 / 3269| Global Catalog (LDAP / LDAPS)    |
| 3389       | RDP                              |

---

## 7. Checklist rapide

- [ ] Écoute passive (Wireshark/tcpdump) → hôtes ARP/MDNS
- [ ] Responder `-A` → hôtes supplémentaires
- [ ] `fping -asgq` → liste d'IP vivantes → `hosts.txt`
- [ ] `nmap -A -iL hosts.txt -oA` → services, OS, DC, legacy
- [ ] Repérer le DC + hôtes critiques + OS obsolètes
- [ ] Kerbrute userenum → liste d'utilisateurs valides
- [ ] Tout noter + sauvegarder les fichiers de scan
