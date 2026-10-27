# Mémo — Empoisonnement LLMNR / NBT-NS depuis Windows (Inveigh)

> Contexte : hôte d'attaque **Windows** (box fournie par le client, ou pivot après compromission
> d'un hôte en admin local). Domaine : `INLANEFREIGHT.LOCAL`.
> **Objectif** : même but que Responder côté Linux → capturer des hashes NetNTLMv1/v2
> pour les cracker hors ligne. Outil : **Inveigh** (équivalent Windows de Responder).
> Suite logique de [l'empoisonnement depuis Linux](memo-llmnr-nbtns-poisoning.md).

---

## 0. Inveigh en bref

- Rôle identique à Responder, mais écrit en **PowerShell** (legacy) et **C#** (maintenu).
- Écoute IPv4 **et IPv6**, protocoles : LLMNR, DNS, mDNS, NBNS, DHCPv6, ICMPv6,
  HTTP(S), SMB, LDAP, WebDAV, Proxy Auth.
- Fourni dans `C:\Tools` sur la box d'attaque du lab (versions PS + exe compilée).
- **Deux versions :**
  - **PowerShell** (`Inveigh.ps1`) = version d'origine, **plus maintenue**.
  - **C# / InveighZero** (`Inveigh.exe`) = version **maintenue** par l'auteur → à privilégier.

---

## 1. Version PowerShell

```powershell
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters   # lister tous les paramètres
```

### Lancement (spoofing LLMNR + NBNS, sortie console + fichier)
```powershell
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

| Paramètre         | Rôle                                                        |
|-------------------|-------------------------------------------------------------|
| `Y` (1er, positionnel) | Active le spoofing LLMNR.                              |
| `-NBNS Y`         | Active le spoofing NBT-NS.                                   |
| `-ConsoleOutput Y`| Affiche en direct dans la console.                          |
| `-FileOutput Y`   | Écrit les captures dans des fichiers (`Output Directory`).  |

- Au démarrage : affiche les spoofers activés (LLMNR, DNS), les captures SMB/HTTP/HTTPS, etc.
- `Stop-Inveigh` pour arrêter.
- ⚠️ Nécessite des **privilèges élevés** (`Elevated Privilege Mode = Enabled`).

---

## 2. Version C# (InveighZero) — à privilégier

À compiler via Visual Studio (bonne pratique) ; une `.exe` prête est déjà dans `C:\Tools`.

```powershell
.\Inveigh.exe          # lancement avec les options par défaut
```

### Lecture des options au démarrage
- `[+]` devant une option = **activée** par défaut (ex. LLMNR, DNS, HTTP, SMB, LDAP).
- `[ ]` devant une option = **désactivée** (ex. mDNS, NBNS, HTTPS, DHCPv6) → aucune réponse envoyée.

### Console interactive
- **ESC** = entrer / sortir de la console interactive pendant qu'Inveigh tourne.
- Donne accès aux hashes capturés, permet de stopper l'outil, etc.
- `HELP` = liste des commandes.

| Commande console       | Rôle                                                       |
|------------------------|------------------------------------------------------------|
| `GET NTLMV2`           | Tous les hashes NTLMv2 capturés (+ filtre possible).       |
| `GET NTLMV2UNIQUE`     | **Un hash NTLMv2 par utilisateur** (le plus utile à cracker).|
| `GET NTLMV2USERNAMES`  | Liste des users capturés + IP/host source (cibles d'énum). |
| `GET NTLMV1` / `...UNIQUE` | Idem pour NTLMv1.                                       |
| `GET CLEARTEXT`        | Identifiants en clair capturés.                            |
| `GET LOG`              | Entrées de log (+ filtre).                                 |
| `RESUME`               | Reprendre l'affichage temps réel.                          |
| `STOP`                 | Arrêter Inveigh.                                            |

> `GET NTLMV2UNIQUE` → copier chaque hash dans un fichier, puis cracker avec Hashcat `-m 5600`
> (ou John `--format=netntlmv2`), exactement comme côté Responder.
> `GET NTLMV2USERNAMES` sert à **choisir quels comptes valent la peine** d'être crackés.

---

## 3. Remédiation (à conseiller au client)

> MITRE ATT&CK : **T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay.
> ⚠️ Changements à **tester prudemment** avant déploiement massif (risque de casser la résolution).

**Désactiver LLMNR (via GPO) :**
`Computer Configuration → Administrative Templates → Network → DNS Client`
→ activer **« Turn OFF Multicast Name Resolution »**.

**Désactiver NBT-NS (pas de GPO directe → par hôte) :**
`Panneau de config → Centre Réseau → Modifier les paramètres de la carte`
→ propriétés de la carte → IPv4 → Avancé → onglet **WINS** → **Disable NetBIOS over TCP/IP**.

**Script PowerShell (startup) pour désactiver NBT-NS en masse :**
```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose }
```
- À pousser via GPO (Startup Script), hébergé sur le partage **SYSVOL** :
  `\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts`
- Appliqué aux OU ciblées → s'exécute au **reboot** (ou redémarrage de la carte réseau).

**Autres mitigations :** filtrer le trafic LLMNR/NetBIOS, activer la **signature SMB**
(contre le relais NTLM), IDS/IPS réseau, **segmentation** pour isoler les hôtes qui en ont besoin.

---

## 4. Détection

- **Honeypot de résolution** : injecter des requêtes LLMNR/NBT-NS vers des hôtes **inexistants**
  sur différents sous-réseaux → toute **réponse** = probable attaquant qui spoofe.
- Surveiller le trafic sur **UDP 5355** (LLMNR) et **UDP 137** (NBT-NS).
- Surveiller les **Event IDs 4697** et **7045** (installation de service).
- Surveiller la clé registre `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`
  → valeur DWORD `EnableMulticast` = **0** signifie LLMNR désactivé.

---

## 5. À retenir

| Point                          | Valeur                                            |
|--------------------------------|---------------------------------------------------|
| Équivalent Windows de Responder| **Inveigh** (PowerShell legacy / C# maintenu)     |
| Version à privilégier          | C# → `Inveigh.exe`                                |
| Lancement PS                   | `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y` |
| Lancement C#                   | `.\Inveigh.exe`                                   |
| Console interactive (C#)       | touche **ESC**                                    |
| Voir hashes à cracker          | `GET NTLMV2UNIQUE`                                |
| Voir les comptes capturés      | `GET NTLMV2USERNAMES`                             |
| Crack ensuite                  | Hashcat `-m 5600` / John `--format=netntlmv2`     |
| MITRE ATT&CK                   | T1557.001                                         |
| Prérequis                      | privilèges élevés sur l'hôte Windows              |
