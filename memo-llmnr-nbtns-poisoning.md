# Mémo — Empoisonnement LLMNR / NBT-NS depuis Linux (Partie technique & outils)

> Contexte : pentest interne, position anonyme sur le réseau client, hôte d'attaque Linux.
> Domaine : `INLANEFREIGHT.LOCAL`. Plage cible : `172.16.5.0/23`.
> **Objectif** : capturer des hashes NetNTLMv1/v2 sur le réseau, les cracker hors ligne
> et obtenir des identifiants en clair → premier point d'appui dans le domaine.

---

## 0. Principe de l'attaque (MITM)

- **LLMNR** et **NBT-NS** = méthodes de résolution de noms *de secours* quand le DNS échoue.
  - LLMNR : basé sur le format DNS, résolution sur le lien local → **UDP 5355**.
  - NBT-NS : identifie les systèmes par leur nom NetBIOS → **UDP 137**.
  - Ordre : DNS échoue → LLMNR → si échec → NBT-NS.
- **Le défaut** : quand LLMNR/NBT-NS sont utilisés, **n'importe quel hôte du réseau peut répondre**.
- On se fait passer pour la source de résolution légitime → la victime nous envoie une
  **requête d'authentification** avec son user + un **hash NetNTLMv2**.
- Ce hash est ensuite **cracké hors ligne** (ou relayé via SMB Relay, cf. module Lateral Movement).
- LLMNR/NBNS spoofing + **absence de signature SMB** → souvent accès admin sur des hôtes du domaine.

### Déroulé type
1. Un hôte veut joindre `\\print01.inlanefreight.local` mais tape `\\printer01...` (faute de frappe).
2. Le DNS répond : hôte inconnu.
3. L'hôte **broadcast** sur le réseau local : « qui connaît `printer01` ? ».
4. **Nous (Responder)** répondons : « c'est moi ».
5. L'hôte nous envoie une requête d'auth avec username + hash NTLMv2.
6. On crack le hash hors ligne (ou SMB Relay si conditions réunies).

---

## 1. Outils d'empoisonnement

| Outil      | Description                                                              |
|------------|--------------------------------------------------------------------------|
| Responder  | Outil dédié : empoisonne LLMNR, NBT-NS, MDNS (Python, Linux + `.exe`).   |
| Inveigh    | Plateforme MITM cross-platform (C# + PowerShell legacy).                 |
| Metasploit | Scanners et modules de spoofing intégrés.                                |

**Protocoles attaquables** (Responder & Inveigh) : LLMNR, DNS, MDNS, NBNS, DHCP, ICMP,
HTTP(S), SMB, LDAP, WebDAV, Proxy Auth.
**Responder en plus** : MSSQL, DCE-RPC, FTP, POP3, IMAP, SMTP.

---

## 2. Responder — options clés

```bash
responder -h
```

| Flag              | Rôle                                                                       |
|-------------------|----------------------------------------------------------------------------|
| `-I eth0`         | Interface réseau (obligatoire ; `ALL` = toutes).                           |
| `-A`              | **Mode Analyse** : écoute sans empoisonner (fly on the wall).              |
| `-w`              | Lance le **serveur proxy WPAD rogue** (très efficace en grande entreprise).|
| `-f`              | **Fingerprint** l'OS/version de l'hôte qui a émis la requête.              |
| `-r`              | Répond aux requêtes netbios wredir (⚠️ peut casser des choses sur le réseau). |
| `-d`              | Répond aux requêtes de suffixe de domaine netbios (⚠️ idem).               |
| `-F` / `-P`       | Force l'auth NTLM/Basic / l'auth proxy (⚠️ peut déclencher un prompt login). |
| `-v`              | Verbeux (beaucoup de sortie ; utile en cas de souci).                      |

- Combo courant : `-wf` (WPAD + fingerprint).
- `-w` capture les requêtes HTTP des users lançant IE avec « détection auto » activée.

---

## 3. Responder en action

```bash
sudo responder -I ens224          # écoute + répond avec les réglages par défaut
```

- **Toujours en sudo/root.** Lancer dans un **tmux** et laisser tourner un moment
  pendant qu'on fait d'autres tâches d'énumération → maximise le nombre de hashes.
- Ports à garder libres sur l'hôte d'attaque :
  `UDP 137/138/53, UDP/TCP 389, TCP 1433, UDP 1434, TCP 80/135/139/445/21/3141/25/110/587/3128,`
  `Multicast UDP 5355 et 5353`.
- Les serveurs rogue (ex. SMB) se désactivent dans `Responder.conf`.

---

## 4. Logs & format des hashes

- Répertoire : `/usr/share/responder/logs`.
- Un fichier **par hôte / protocole** :
  format `(MODULE)-(HASH_TYPE)-(CLIENT_IP).txt` → ex. `SMB-NTLMv2-SSP-172.16.5.25`.
- Un hash affiché à la console + stocké dans son fichier (sauf mode `-v`).
- Aussi stocké dans une base **SQLite** (configurable dans `Responder.conf`, dans `/usr/share/responder`).

```
Analyzer-Session.log        SMB-NTLMv2-SSP-172.16.5.200.txt
HTTP-NTLMv2-172.16.5.200.txt  SMB-NTLMv2-SSP-172.16.5.25.txt
Poisoners-Session.log       SMB-NTLMv2-SSP-172.16.5.50.txt
```

---

## 5. Cracking hors ligne — Hashcat

```bash
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```

| Élément     | Détail                                                                 |
|-------------|------------------------------------------------------------------------|
| `-m 5600`   | Mode **NetNTLMv2** (le hash typique capturé par Responder).            |
| Entrée      | Fichier contenant le hash.                                             |
| Wordlist    | `rockyou.txt`.                                                         |

- NetNTLMv2 : **cracking lent** même sur GPU → mots de passe longs/complexes = difficile/impossible.
- ⚠️ **NetNTLMv2 ≠ pass-the-hash** : inutilisable tel quel → on est *obligé* de cracker hors ligne.
- NTLMv1 et autres types : consulter la page **Hashcat example hashes** pour trouver le bon mode.
- Alternative : **John the Ripper**.

**Exemple** : hash de `FOREND` cracké → mot de passe `Klmcargo2` (domaine tolérait les mdp faibles de 8 car.).

---

## 6. Après capture — stratégie

- Collecter **un max** de hashes (dans la fenêtre d'assessment) mais ne pas perdre de temps
  à cracker des comptes qui ne feront pas avancer vers l'objectif.
- Un hash cracké (ex. `FOREND`) = point d'appui pour l'énumération **en position créditée**.
- Suites possibles : énumération BloodHound/PowerView, Kerberoasting, ASREPRoasting,
  password spraying, SMB Relay.

---

## 7. À retenir

| Point                         | Valeur                                            |
|-------------------------------|---------------------------------------------------|
| LLMNR                         | UDP 5355                                           |
| NBT-NS                        | UDP 137                                            |
| MDNS                          | UDP 5353                                           |
| Hash capturé (typique)        | NetNTLMv2                                          |
| Mode Hashcat NetNTLMv2        | `-m 5600`                                          |
| Pass-the-hash sur NetNTLMv2 ? | ❌ Non → crack hors ligne obligatoire             |
| Mode écoute seule             | `responder -I <iface> -A`                         |
| Lancement empoisonnement      | `sudo responder -I <iface>` (dans un tmux)        |
