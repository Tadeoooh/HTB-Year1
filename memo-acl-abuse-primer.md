# Mémo — ACL Abuse (primer)

> Section de théorie : comprendre les **ACL / ACE** AD avant d'enchaîner sur les attaques pratiques.
> 💡 Les ACL mal configurées **n'apparaissent pas** dans les scans de vulns et traînent souvent des années.
> Super vecteur de **lateral movement / escalade / persistance** quand les misconfigs « classiques » sont déjà corrigées.

---

## 1. ACL & ACE : définitions

- **ACL** (Access Control List) = liste qui définit **qui** a accès à une ressource et **quel niveau** d'accès.
- **ACE** (Access Control Entry) = une entrée de l'ACL. Chaque ACE → un **security principal** (user / groupe / process) + les droits accordés.
- **Tout objet** AD a une ACL, et peut avoir **plusieurs ACE** (plusieurs principals y accèdent).

### Deux types d'ACL
| Type | Rôle |
|------|------|
| **DACL** (Discretionary ACL) | Définit qui est **autorisé / refusé** sur l'objet. Composée d'ACE allow/deny. |
| **SACL** (System ACL) | **Audit** : logue les tentatives d'accès (onglet *Auditing* dans ADUC). |

> ⚠️ Pas de DACL = accès **total** à tous. DACL présente mais **vide** (0 ACE) = accès **refusé** à tous.

### Types d'ACE
| ACE | Rôle |
|-----|------|
| **Access denied** | Refuse explicitement (dans une DACL). |
| **Access allowed** | Autorise explicitement (dans une DACL). |
| **System audit** | Génère un log d'audit (dans une SACL). |

### Composition d'une ACE (4 éléments)
1. **SID** du user/groupe concerné.
2. Flag du **type** d'ACE (denied / allowed / audit).
3. Flags d'**héritage** (les objets enfants héritent-ils de l'ACE ?).
4. **Access mask** : valeur 32 bits = droits accordés.

> Les ACL sont évaluées **de haut en bas** et s'arrêtent dès qu'un **access denied** matche.

---

## 2. Droits (ACE) abusables + outil PowerView

| Droit | Abus avec |
|-------|-----------|
| **ForceChangePassword** | `Set-DomainUserPassword` |
| **Add Members** | `Add-DomainGroupMember` |
| **GenericAll** | `Set-DomainUserPassword` ou `Add-DomainGroupMember` |
| **GenericWrite** | `Set-DomainObject` |
| **WriteOwner** | `Set-DomainObjectOwner` |
| **WriteDACL** | `Add-DomainObjectACL` |
| **AllExtendedRights** | `Set-DomainUserPassword` ou `Add-DomainGroupMember` |
| **AddSelf** | `Add-DomainGroupMember` |

---

## 3. Les 4 ACE couverts dans ce module

| ACE | Ce que ça permet |
|-----|------------------|
| **ForceChangePassword** | Reset le mdp d'un user **sans connaître** l'ancien. ⚠️ Destructif → valider avec le client. |
| **GenericWrite** | Écrire sur un attribut non protégé. Sur un **user** → poser un **SPN** puis Kerberoasting. Sur un **groupe** → s'y ajouter. Sur un **computer** → RBCD (hors scope). |
| **AddSelf** | Groupes dans lesquels un user peut **s'auto-ajouter**. |
| **GenericAll** | **Contrôle total**. User/groupe → reset pwd, modif membership, **Kerberoasting ciblé** (réponse HTB pour le roast ciblé). Sur un **computer + LAPS** → lire le mdp LAPS = admin local. |

> 👀 Autres rights croisés en vrai : **ReadGMSAPassword** (→ `GMSAPasswordReader`), extended rights type `Unexpire-Password`, `Reanimate-Tombstones`...
> Se familiariser avec les **edges BloodHound** et les **Extended Rights** AD.

**Énum/visualisation** : **BloodHound** (voit & dessine les chemins) + **PowerView** (built-in AD tools aussi).

---

## 4. ACL abuse en situation réelle

Usages : **lateral movement**, **escalade de privilèges**, **persistance**.

| Scénario | Description |
|----------|-------------|
| **Abus des resets de mdp** | Help Desk / IT ont souvent le droit de reset des mdp. Prendre un tel compte → reset le mdp d'un compte **plus privilégié**. |
| **Abus de gestion de groupes** | Droit d'ajouter/retirer des membres → s'ajouter à un **groupe privilégié** (built-in ou à privilège intéressant). |
| **Droits excessifs** | Objets user/computer/group avec des droits non voulus (ex. install **Exchange** = beaucoup de changements d'ACL, legacy, confort...). |

---

## 5. OPSEC / reporting

> 📝 Certaines attaques ACL sont **destructives** (changer un mdp, modifier l'AD). En cas de doute : **accord écrit** du client avant.
> **Documenter** chaque action du début à la fin, **revert** les changements, et les **mettre en évidence** dans le rapport
> pour que le client puisse vérifier que tout a bien été remis en état.

---

## 6. À retenir

| Point | Détail |
|-------|--------|
| ACL = qui + niveau d'accès | composée d'**ACE** |
| DACL vs SACL | DACL = allow/deny ; SACL = audit |
| Pas de DACL | accès total ; DACL vide = accès refusé |
| Évaluation | haut → bas, stop au 1er **deny** |
| Pourquoi juteux | invisible aux scans de vulns, traîne des années |
| GenericWrite sur user | poser un SPN → **Kerberoasting** |
| GenericAll sur computer + LAPS | lire le mdp LAPS → **admin local** |
| Énum | **BloodHound** + **PowerView** |
| ⚠️ Destructif | accord client + revert + doc |
