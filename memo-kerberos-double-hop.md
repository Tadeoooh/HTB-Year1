# Mémo — Kerberos "Double Hop" Problem

> Problème rencontré quand on s'authentifie en **Kerberos sur 2 sauts** (ou +), typiquement via **WinRM/PSRemoting**.
> Symptôme : on a un shell valide sur le host A, mais toute commande qui doit parler à un **3e host** (ex. interroger le DC avec PowerView) échoue → *"An operations error occurred"*.

---

## 1. Le cœur du problème

- Un **ticket Kerberos ≠ mot de passe** : c'est une donnée signée par le KDC qui dit « ce compte peut accéder à CETTE ressource ».
- En WinRM, l'authentification est de type **network** → le mdp n'est **jamais mis en cache** dans la session.
- Ce qui est envoyé au host A = le **TGS** (ticket pour CE service). Le **TGT** (qui prouve l'identité pour demander d'autres TGS) **n'est PAS transmis**.
- Résultat : depuis A, on ne peut pas prouver notre identité au host B/DC → accès refusé.

```
Attack Host  --->  DEV01 (1er hop)  --->  DC01 (2e hop)
            WinRM : TGS envoyé            ❌ pas de TGT → requête rejetée
```

> Comparaison : avec **PSExec / SMB / LDAP** (auth par mdp), le **NTLM hash** est stocké en mémoire → réutilisable pour le 2e saut. Pas de double hop problem.

### Preuve
- `mimikatz sekurlsa::logonpasswords` sur le host distant → **credentials vides** pour notre user (juste le compte machine `DEV01$`).
- `klist` dans la session evil-winrm → **1 seul ticket** (TGS du service courant, ex. `academy-...ms0$`), pas de TGT.
- Le process de la session WinRM = **`wsmprovhost.exe`** (`tasklist /V | findstr <user>`).

> 💡 **Exception : unconstrained delegation.** Si le serveur l'a activé, le TGT **est** envoyé avec le TGS → pas de double hop problem (et de toute façon, si tu es sur un host en unconstrained delegation, t'as déjà gagné).

---

## 2. Workaround #1 — PSCredential (marche en evil-winrm)

Passer explicitement les creds **à chaque commande** via `-Credential`.
```powershell
# dans la session WinRM (evil-winrm), après import PowerView :
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)

get-domainuser -spn -credential $Cred | select samaccountname   # ✅ marche
get-domainuser -spn | select samaccountname                      # ❌ échoue (pas de -credential)
```
> Simple et fiable, mais il faut re-passer `-Credential` sur **chaque** appel (et l'outil doit supporter ce flag).

---

## 3. Workaround #2 — Register-PSSessionConfiguration (GUI Windows requis)

Pour un **host Windows joint au domaine** ou un **attack host Windows** (RDP), via `Enter-PSSession`.
```powershell
# 1. (une fois) enregistrer une session config qui tourne "RunAs" notre user
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm

# 2. redémarrer WinRM (ça nous éjecte de la session)
Restart-Service WinRM

# 3. se reconnecter en utilisant la session nommée
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName backupadmsess
```
Résultat : `klist` montre un **TGT** → on peut interroger le DC directement, sans re-passer de creds.
```powershell
[DEV01]: PS> get-domainuser -spn | select samaccountname   # ✅ marche sans -credential
```
Pourquoi : la machine locale **impersonne** le host distant dans le contexte du user → les requêtes partent directement vers le DC.

### ⚠️ Limites du #2
- **Impossible en evil-winrm** : pas de popup de credentials.
- `-RunAsCredential $Cred` → erreur : **RunAs exige un terminal PowerShell élevé** (admin).
- Ne marche **pas** depuis PowerShell sur Parrot/Ubuntu (limites Kerberos de PS Linux).
- → Réservé à un **attack host Windows** / host compromis utilisé en **jump host** (RDP).

---

## 4. Autres méthodes (non détaillées ici)

**CredSSP**, **port forwarding**, ou injection dans un **processus sacrificiel** tournant dans le contexte du user cible.

---

## 5. À retenir

| Point | Détail |
|-------|--------|
| Cause | WinRM/Kerberos : TGS transmis, **pas le TGT** → 2e saut refusé |
| Auth par mdp (PSExec/SMB) | NTLM en mémoire → **pas** de double hop |
| Diagnostic | `klist` = 1 ticket / `sekurlsa::logonpasswords` = creds vides |
| Exception | **unconstrained delegation** (TGT envoyé) |
| Fix evil-winrm | **PSCredential** + `-Credential` sur chaque commande |
| Fix GUI Windows | **Register-PSSessionConfiguration** `-RunAsCredential` + `-ConfigurationName` |
| RunAs | nécessite terminal **élevé** ; pas en evil-winrm ni PS Linux |
