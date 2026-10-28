# Mémo — Énumération des ACL (PowerView & BloodHound)

> Suite du [primer ACL Abuse](memo-acl-abuse-primer.md). On énumère les ACE abusables depuis un user qu'on contrôle,
> puis on remonte la chaîne. Domaine : `INLANEFREIGHT.LOCAL`. Point de départ : user **`wley`** (hash cracké via Responder plus tôt).
> 💡 **Énumération ciblée** > énumération large : partir d'un objet qu'on contrôle et suivre le fil.

---

## 1. Pourquoi ne PAS énumérer large

```powershell
Find-InterestingDomainAcl        # renvoie une TONNE de données → ingérable en mission time-boxée
```
→ On fait plutôt du **ciblé** à partir du SID d'un user qu'on contrôle.

---

## 2. Énumération ciblée avec PowerView

```powershell
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid wley                    # SID du user de départ
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
- On filtre sur **`SecurityIdentifier`** = le SID → « qui a ce droit sur quel objet ».
- ⚠️ Lent (1-2 min en lab, bien plus en prod réelle).
- **Sans** `-ResolveGUIDs` : `ObjectAceType` affiche un **GUID** illisible (ex. `00299570-246d-11d0-a768-00aa006e0529`).

### Résoudre les GUIDs
```powershell
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
→ `ObjectAceType` devient lisible, ex. **`User-Force-Change-Password`**.

> Résolution manuelle d'un GUID (si besoin / outil bloqué) — à lancer dans une **nouvelle session PS** (sinon conflit PowerView) :
> ```powershell
> $guid = "00299570-246d-11d0-a768-00aa006e0529"
> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,DistinguishedName,rightsGuid | ?{$_.rightsGuid -eq $guid} | fl
> # → Name : User-Force-Change-Password
> ```

### Correspondance ObjectAceType ↔ droit abusable
Le champ `ObjectAceType` (une fois `-ResolveGUIDs` passé) donne le **nom** de l'extended right, qui ne matche pas toujours le nom « parlé » du droit :

| `ObjectAceType` (sortie PowerView) | Droit / abus |
|---|---|
| `User-Force-Change-Password` | **ForceChangePassword** → reset mdp (`Set-DomainUserPassword`) |
| `Self-Membership` | **AddSelf** → s'auto-ajouter à un groupe (`Add-DomainGroupMember`) |
| `DS-Replication-Get-Changes` (+ `-In-Filtered-Set`) | droits **DCSync** |
| *(vide / `All`)* | droit générique : `GenericAll`, `GenericWrite`, `WriteDacl`... lu dans `ActiveDirectoryRights` |

> ⚠️ Piège lab : la question « ObjectAceType, format **Word-Word** » attend `Self-Membership` (= AddSelf), **pas** `User-Force-Change-Password` (4 mots).

---

## 3. Méthode 100 % native (Get-Acl + Get-ADUser)

Utile si PowerView indisponible/bloqué sur le système client (se démarquer des autres).
```powershell
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt

foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {
  get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}
}
```
→ Donne les objets sur lesquels `wley` a des droits (puis résoudre le GUID comme ci-dessus). ⚠️ Beaucoup plus lent que PowerView.

---

## 4. La chaîne d'attaque (exemple du module)

| Étape | Qui | Droit | Sur | Action |
|-------|-----|-------|-----|--------|
| 0 | — | (hash cracké) | `wley` | point de départ |
| 1 | `wley` | **User-Force-Change-Password** | `damundsen` | reset le mdp de damundsen |
| 2 | `damundsen` | **GenericWrite** | groupe **Help Desk Level 1** | s'ajouter au groupe |
| 3 | Help Desk Level 1 | *nested dans* | **Information Technology** | hérite des droits du groupe parent |
| 4 | Information Technology | **GenericAll** | `adunn` | reset pwd / modif membership / **Kerberoasting ciblé** |
| 5 | `adunn` | **DS-Replication-Get-Changes** (+ `-In-Filtered-Set`) | objet domaine | → **DCSync** |

Commandes clés de la remontée :
```powershell
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2}

Get-DomainGroup -Identity "Help Desk Level 1" | select memberof    # repérer le nesting → Information Technology

$itgroupsid = Convert-NameToSid "Information Technology"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid}

$adunnsid = Convert-NameToSid adunn
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid}
```

> 💡 **Nested groups** : un membre du groupe A hérite de **tous** les droits des groupes dans lesquels A est imbriqué.
> C'est le cœur de la chaîne (Help Desk L1 → Information Technology).

---

## 5. Énumération avec BloodHound (bien plus rapide)

Uploader les données SharpHound, puis :
- Poser `wley` comme **starting node** → onglet **Node Info** → **Outbound Control Rights**.
- **First Degree Object Control** = droits directs (ici `ForceChangePassword` sur `damundsen`).
- **Transitive Object Control** = toute la chaîne d'ACL (les 16 objets remontés à la main plus haut).
- **Clic droit sur une arête (edge) → Help** : infos sur le droit, outils/commandes d'abus, **considérations OPSEC**, références externes.
- Requêtes pré-faites → confirmer que `adunn` a les droits **DCSync** (`GetChanges` / `GetChangesAll`).

---

## 6. À retenir

| Besoin | Commande / action |
|--------|-------------------|
| ❌ À éviter (trop large) | `Find-InterestingDomainAcl` |
| SID d'un user | `Convert-NameToSid <user>` |
| ACL ciblées sur un SID | `Get-DomainObjectACL -Identity * \| ? {$_.SecurityIdentifier -eq $sid}` |
| Rendre les droits lisibles | ajouter **`-ResolveGUIDs`** |
| GUID → nom (natif) | `Get-ADObject -SearchBase "CN=Extended-Rights,..."` |
| Sans PowerView | `Get-Acl "AD:\..."` + `Get-ADUser` dans un `foreach` |
| Repérer le nesting | `Get-DomainGroup -Identity <grp> \| select memberof` |
| Vue rapide + chemins | **BloodHound** → Node Info → Outbound Control Rights |
| GUID reset pwd | `00299570-246d-11d0-a768-00aa006e0529` = **User-Force-Change-Password** |
| adunn → domaine | **DS-Replication-Get-Changes** = **DCSync** |
