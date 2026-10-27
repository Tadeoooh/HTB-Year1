# Mémo — Password Spraying interne depuis Windows (DomainPasswordSpray)

> Contexte : foothold sur un hôte **Windows joint au domaine** (box managée fournie par le client,
> VM sur site, ou pivot après un premier accès). Domaine : `INLANEFREIGHT.LOCAL`.
> **Objectif** : obtenir des credentials d'un compte ayant plus de droits dans le domaine.
> Pendant de [Password Spraying interne depuis Linux](memo-password-spraying-interne-linux.md).
> ⚠️ Toujours **respecter le lockout** et **logguer** l'activité.

---

## 1. DomainPasswordSpray en bref

- Outil **PowerShell** très efficace depuis un hôte joint au domaine.
- Si on est **authentifié au domaine**, l'outil fait tout seul :
  - génère la **liste d'users** depuis Active Directory,
  - lit la **password policy** du domaine,
  - **exclut** les comptes à 1 essai du lockout (anti-lockout automatique).
- Si on est sur un hôte Windows **non authentifié** au domaine → fournir sa propre liste via `-UserList`
  (comme le spray côté Linux).

---

## 2. Utilisation (hôte joint au domaine)

Hôte joint au domaine → on **saute `-UserList`** et on laisse l'outil générer la liste.

```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

| Flag                       | Rôle                                                        |
|----------------------------|-------------------------------------------------------------|
| `-Password Welcome1`       | **Un seul** mot de passe testé contre tous les users.       |
| `-OutFile spray_success`   | Écrit les succès dans un fichier (réutilisable ensuite).    |
| `-UserList <file>`         | (si **non** joint au domaine) fournir sa propre liste.      |
| `-ErrorAction SilentlyContinue` | Masque le bruit des erreurs.                           |

Sortie (extraits) :
```
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1
```
> L'outil lit la policy, retire les **comptes désactivés** et ceux **à 1 essai du lockout**,
> demande une **confirmation** avant de spray (`Are you sure... [Y]`), puis sort les hits dans `-OutFile`.

> **Alternative** : **Kerbrute** permet de faire la même énumération + spray depuis Windows
> (présent dans `C:\Tools` dans le lab). Cf. [mémo Linux](memo-password-spraying-interne-linux.md) pour la syntaxe.

---

## 3. Remédiation (défense en profondeur)

> Aucune solution unique ne bloque tout → **empiler** les mesures rend le spray très difficile.

| Technique                        | Description                                                               |
|----------------------------------|---------------------------------------------------------------------------|
| **MFA**                          | Réduit fortement le risque. ⚠️ Certaines implémentations révèlent quand même si le couple user/mdp est valide → réutilisable ailleurs. À mettre sur **tous les portails externes**. |
| **Restreindre l'accès**          | Moindre privilège : limiter l'accès aux applis aux users qui en ont besoin (souvent n'importe quel compte du domaine peut se log). |
| **Réduire l'impact**             | Comptes **séparés** pour l'admin, permissions par appli, **segmentation réseau** pour freiner le mouvement latéral. |
| **Hygiène des mots de passe**    | Sensibiliser aux **passphrases**, filtre de mots de passe (interdire mots du dico, mois/saisons, nom de la boîte). |

> ⚠️ **Attention au lockout lui-même** : une policy trop stricte (déverrouillage manuel par un admin)
> peut transformer un spray maladroit en **déni de service** (verrouillage massif de comptes).

---

## 4. Détection

- **Nombreux lockouts** sur une courte période.
- Logs serveur/appli : beaucoup de tentatives de login (users valides **ou inexistants**),
  ou beaucoup de requêtes vers une appli/URL précise.
- **DC — Event ID 4625** : *An account failed to log on* → corréler N échecs dans un intervalle = alerte.
- Attaquant plus fin → cible **LDAP** plutôt que SMB → surveiller **Event ID 4771**
  (*Kerberos pre-authentication failed*) ; nécessite d'**activer le logging Kerberos**.

---

## 5. Password Spraying externe (hors scope du module, mais utile)

Méthode courante pour obtenir un foothold **depuis Internet** (inbox email, intranet externe...).
Cibles fréquentes utilisant l'auth AD :

- Microsoft O365, **Outlook Web Access (OWA)** / Exchange Web Access
- Skype for Business, Lync Server
- Microsoft **RDS** (Remote Desktop Services) portals
- Portails **Citrix** avec auth AD
- **VDI** (VMware Horizon...) avec auth AD
- Portails **VPN** (Citrix, SonicWall, OpenVPN, Fortinet...) avec auth AD
- Applis web custom avec auth AD

---

## 6. Et après ? (Moving Deeper)

Avec plusieurs **credentials valides** en main → **énumération credentialed** du domaine
(outils complémentaires pour une image complète), puis **mouvement latéral et vertical**
vers l'objectif de l'assessment.

---

## 7. À retenir

| Point                              | Valeur                                                          |
|------------------------------------|-----------------------------------------------------------------|
| Outil (Windows, joint au domaine)  | **DomainPasswordSpray.ps1** (PowerShell)                        |
| Import                             | `Import-Module .\DomainPasswordSpray.ps1`                       |
| Spray                              | `Invoke-DomainPasswordSpray -Password <pw> -OutFile <file>`     |
| Génération liste + policy          | **automatique** si authentifié au domaine                       |
| Anti-lockout                       | exclut auto les comptes à **1 essai du lockout**                |
| Non joint au domaine               | fournir `-UserList <file>`                                      |
| Alternative                        | **Kerbrute** (dans `C:\Tools`)                                  |
| Détection (SMB)                    | Event ID **4625** sur le DC                                     |
| Détection (LDAP)                   | Event ID **4771** (logging Kerberos activé)                     |
| Remédiation clé                    | **MFA** + moindre privilège + hygiène mdp + segmentation        |
| Risque propre                      | spray maladroit → **lockout massif = DoS**                      |
