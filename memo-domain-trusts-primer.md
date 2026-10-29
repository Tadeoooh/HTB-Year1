# Mémo — Domain Trusts (primer)

> Les trusts lient les systèmes d'auth de deux domaines/forêts → un user d'un domaine peut accéder aux ressources d'un autre.
> Souvent mal configurés (M&A, filiales, MSP) → **chemins d'attaque inattendus**. Il arrive de Kerberoaster un domaine *externe* et d'obtenir un compte admin sur le domaine principal.
> Clé : **si on ne peut pas s'authentifier à travers le trust, pas d'énum ni d'attaque possible.**
> Lab : `INLANEFREIGHT.LOCAL` (root) ⇄ `LOGISTICS.INLANEFREIGHT.LOCAL` (child) et ⇄ `FREIGHTLOGISTICS.LOCAL` (forêt externe).

---

## 1. Types de trust

| Type | Description |
|------|-------------|
| **Parent-child** | 2+ domaines d'une même forêt ; trust **bidirectionnel transitif** (child ⇄ parent). |
| **Cross-link** | Trust entre domaines enfants pour accélérer l'auth. |
| **External** | Trust **non-transitif** entre 2 domaines de forêts séparées (pas déjà liées par un forest trust). Utilise le **SID filtering**. |
| **Tree-root** | Trust bidirectionnel transitif entre le root d'une forêt et un nouveau tree root (créé par design). |
| **Forest** | Trust transitif entre 2 roots de forêts. |
| **ESAE** | Bastion forest dédié à l'administration de l'AD. |

## 2. Propriétés d'un trust

**Transitivité :**
- **Transitif** : le trust s'étend aux objets que le domaine de confiance approuve. (A→B et B→C transitif ⇒ A fait confiance à C.) → forest, tree-root, parent-child, cross-link.
- **Non-transitif** : seul le domaine lui-même est approuvé, pas les child suivants. → typique external/custom.
- 📦 Analogie : transitif = toute la maison (forêt) peut signer le colis ; non-transitif = seul toi peux signer.

**Direction :**
- **One-way** : les users du domaine **trusted** accèdent aux ressources du domaine **trusting** (pas l'inverse).
- **Bidirectional (two-way)** : les users des deux domaines accèdent aux ressources de l'autre.

> ⚠️ Risque M&A : un trust bidirectionnel avec une société acquise (posture inconnue/non testée) importe son risque. Un attaquant peut viser la société acquise (cible plus molle) pour rentrer indirectement. À **remonter dans le rapport** — souvent la grosse org ignore l'existence du trust.

## 3. Énumération — AD PowerShell module

```powershell
Import-Module activedirectory
Get-ADTrust -Filter *
```
Propriétés utiles dans la sortie :
- **`IntraForest : True`** → trust **intra-forêt** (= child domain). Ex. `LOGISTICS.INLANEFREIGHT.LOCAL`.
- **`ForestTransitive : True`** → **forest / external trust**. Ex. `FREIGHTLOGISTICS.LOCAL`.
- **`Direction : BiDirectional`** → auth dans les deux sens.

## 4. Énumération — PowerView

```powershell
# Lister les trusts existants
Get-DomainTrust

# Mapping complet (type + direction, dans les deux sens)
Get-DomainTrustMapping
```
Champs : `TrustType` (WINDOWS_ACTIVE_DIRECTORY), `TrustAttributes` (**WITHIN_FOREST** = child / **FOREST_TRANSITIVE** = forest trust), `TrustDirection`.

Une fois le trust confirmé, énumérer à travers :
```powershell
# Users du child domain
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```

## 5. Énumération — netdom (built-in)

```cmd
netdom query /domain:inlanefreight.local trust          :: trusts
netdom query /domain:inlanefreight.local dc             :: contrôleurs de domaine
netdom query /domain:inlanefreight.local workstation    :: workstations / serveurs
```

## 6. Énumération — BloodHound

Requête pré-construite **« Map Domain Trusts »** → visualise les trusts et leur direction (bidirectionnels visibles d'un coup d'œil).

---

## 7. À retenir

| Besoin | Commande |
|--------|----------|
| Trusts (built-in) | `Get-ADTrust -Filter *` |
| Trusts (PowerView) | `Get-DomainTrust` / `Get-DomainTrustMapping` |
| Users d'un domaine trusté | `Get-DomainUser -Domain <child.domain>` |
| Trusts (cmd natif) | `netdom query /domain:<dom> trust` |
| Visuel | BloodHound → *Map Domain Trusts* |

**Lire la sortie** : `IntraForest`/`WITHIN_FOREST` = child domain · `ForestTransitive`/`FOREST_TRANSITIVE` = forest/external trust · `Bidirectional` = exploitable dans les deux sens.
