# Mémo — Énumération des contrôles de sécurité (AD, depuis un hôte compromis)

> Contexte : après un **foothold** sur un hôte du domaine, on recense les **protections en place**
> (Defender, AppLocker, CLM, LAPS...) avant de choisir nos outils d'énumération / exploitation.
> Domaine : `INLANEFREIGHT.LOCAL`.
> **Pourquoi** : les produits présents conditionnent les outils utilisables → éviter/adapter
> (ex. PowerView bloqué par Defender). Section **théorique** (pas de composant interactif) ;
> l'énumération *et* le bypass des contrôles sont couverts dans d'autres modules.

---

## 1. Windows Defender (Microsoft Defender)

Bloque par défaut des outils comme **PowerView**. Bypass couverts ailleurs.

```powershell
Get-MpComputerStatus
```
- Cmdlet PowerShell **native** (living off the land).
- Champ clé : **`RealTimeProtectionEnabled : True`** → Defender actif (protection temps réel).
- Autres champs utiles : `AntivirusEnabled`, `AMServiceEnabled`, `BehaviorMonitorEnabled`.

---

## 2. AppLocker (whitelisting applicatif)

Liste blanche d'exécutables/scripts autorisés (contrôle sur .exe, scripts, MSI, DLL, apps packagées).
Souvent : `cmd.exe` et `PowerShell.exe` bloqués + écriture restreinte sur certains dossiers — **bypassable**.

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

**Angle de bypass classique** : les admins bloquent souvent **uniquement** le PowerShell 64-bit
```
%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe
```
…mais oublient les **autres emplacements** → on appelle PowerShell depuis :
- `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` (version 32-bit)
- `PowerShell_ISE.exe`

> Dans l'exemple : règle `Deny` « Block PowerShell » ciblant `...system32\...\powershell.exe`
> pour le SID des **Domain Users** (`...-513`). Les règles par défaut autorisent `Program Files`,
> `Windows` (Everyone) et **tout** pour les **Administrators** locaux (`S-1-5-32-544`).

---

## 3. PowerShell Constrained Language Mode (CLM)

Verrouille les fonctionnalités PS puissantes : bloque objets COM, limite aux types .NET approuvés,
workflows XAML, classes PowerShell, etc.

```powershell
$ExecutionContext.SessionState.LanguageMode
```
- Retour `FullLanguage` = pas de restriction.
- Retour **`ConstrainedLanguage`** = mode restreint actif → beaucoup de scripts d'attaque cassent.

---

## 4. LAPS (Local Administrator Password Solution)

Randomise et fait **tourner** les mots de passe admin local → casse le mouvement latéral (réutilisation).
On énumère **qui** peut lire les mdp LAPS et **quelles machines** n'ont pas LAPS. Outil : **LAPSToolkit**.

> Le compte ayant **joint** une machine au domaine reçoit **All Extended Rights** dessus → peut lire le mdp.

| Fonction (LAPSToolkit)         | Rôle                                                                 |
|--------------------------------|----------------------------------------------------------------------|
| `Find-LAPSDelegatedGroups`     | Groupes **délégués** pour lire LAPS, par OU (souvent groupes protégés).|
| `Find-AdmPwdExtendedRights`    | Vérifie les droits de lecture / users en **All Extended Rights** (`Reason: Delegated`). Ces users sont parfois **moins protégés** → cible intéressante. |
| `Get-LAPSComputers`            | Machines avec LAPS, dates d'expiration, et **mdp en clair** si on y a accès. |

```powershell
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```
Exemple `Get-LAPSComputers` (mdp local en clair récupéré) :
```
ComputerName                Password       Expiration
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
SQL01.INLANEFREIGHT.LOCAL   9G#f;p41dcAe,s 09/26/2020 00:30:09
```

> **Cible** : trouver un **user AD qui peut lire LAPS** sur un hôte → lire le mdp admin local → accès.

---

## 5. À retenir

| Contrôle                | Commande d'énum                                              | Indice clé                          |
|-------------------------|-------------------------------------------------------------|-------------------------------------|
| Windows Defender        | `Get-MpComputerStatus`                                      | `RealTimeProtectionEnabled : True`  |
| AppLocker               | `Get-AppLockerPolicy -Effective \| select -Expand RuleCollections` | règles `Deny`/`Allow` + chemins |
| Bypass AppLocker (idée) | appeler PS depuis `SysWOW64\...\powershell.exe` ou `PowerShell_ISE.exe` | 64-bit bloqué, 32-bit oublié  |
| Constrained Language    | `$ExecutionContext.SessionState.LanguageMode`              | `ConstrainedLanguage`               |
| LAPS — qui peut lire     | `Find-LAPSDelegatedGroups` / `Find-AdmPwdExtendedRights`   | groupes délégués / All Ext. Rights  |
| LAPS — mdp en clair      | `Get-LAPSComputers`                                        | colonne `Password`                  |
| Outil LAPS              | **LAPSToolkit**                                             | —                                   |
