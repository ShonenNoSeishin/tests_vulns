# Fortinet — lot de correctifs de novembre 2026

> Fortinet a publié le **10/11/2026** environ **100 correctifs** (dont une vingtaine de critiques selon la presse spécialisée), annoncés sans
> détail depuis octobre. **Aucune exploitation connue** et aucune entrée au catalogue CISA KEV à ce jour, mais les équipements Fortinet
> sont des cibles habituelles dès la divulgation : ne pas attendre. **Mise à jour du 19/11/2026** : ajout de l'avis **FG-IR-26-219**
> (CVE-2026-126170, CVSS **9.8**, injection JSON dans l'API JRPC de FortiManager/FortiAnalyzer) — une faille différente de FG-IR-26-275,
> dans le même lot de novembre.

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Vous avez un **FortiManager / FortiAnalyzer** (ou FortiAnalyzer-BigData) ou un **FortiGate (FortiOS)** dans une version listée ci-dessous. |
| **Comment tester ?** | `./check_fortinet_version.sh fortios 7.4.12` (ou `fortimanager`/`fortianalyzer-bigdata`) — compare une version, **sans se connecter** au pare-feu. |
| **Comment corriger ?** | Mettre à niveau vers la version corrigée de votre branche (tableau ci-dessous). En attendant : ne pas exposer FGFM/admin à Internet, désactiver l'API JSON si elle est activée. |

## Les trois avis vérifiés à la source

| Avis | Produit | CVSS | Conditions | Vulnérables | Corrigées |
|---|---|---|---|---|---|
| **FG-IR-26-275** — CVE-2026-126261 | **FortiManager / FortiAnalyzer** : exécution de code ou de commandes **sans authentification** via le service **FGFM** | **9.0** | accès réseau au port FGFM (TCP 541) | 8.0.0 ; 7.6.0–7.6.7 ; 7.4.0–7.4.5 ; 7.2.0–7.2.8 | **8.0.1 ; 7.6.8 ; 7.4.6 ; 7.2.9** |
| **FG-IR-26-219** — CVE-2026-126170 | **FortiManager / FortiAnalyzer** (+ **FortiAnalyzer-BigData**) : injection JSON dans l'**API JRPC**, exécution non authentifiée si l'API JSON est activée | **9.8** | API JSON activée sur un profil admin (**désactivée par défaut**) | FortiManager/FortiAnalyzer 8.0.0–8.0.2 ; 7.6.0–7.6.7 ; BigData 7.6.0–7.6.2. **7.4 et 7.2 non concernés** | **8.0.3** (⚠️ annoncé mais pas encore publié au 19/11/2026, voir plus bas) ; **7.6.8** ; BigData **7.6.3** |
| **FG-IR-26-267** — CVE-2026-126253 | **FortiOS** : contournement d'authentification du démon **OSPF** | **9.3** | attaquant sur le réseau adjacent, OSPF actif | 8.0.0–8.0.1 ; 7.6.0–7.6.7 ; 7.4.0–7.4.12 ; 7.2.0–7.2.13 ; 7.0.1–7.0.19 | **8.0.2 ; 7.6.8 ; 7.4.13 ; 7.2.14** (7.0 : **pas de correctif**, migrer) |

> ⚠️ **FG-IR-26-219, branche 8.0** : le correctif 8.0.3 était encore annoncé "à venir" (pas publié) au moment de la rédaction. Avant de
> planifier une mise à niveau, vérifier sa disponibilité réelle sur le portail de téléchargement Fortinet — en attendant, appliquer le
> contournement (section 2).

Le lot contient d'autres correctifs (FortiOS : SSH, noyau, proxy WAD ; FortiMail : plusieurs critiques ; FortiSASE) : **installez la
dernière version de votre branche** plutôt que la version minimale, et consultez le [portail PSIRT](https://www.fortiguard.com/psirt)
pour les produits non couverts ici.

## 1. Tester

Relevez la version : interface web (tableau de bord) ou, en CLI, `get system status`.

```bash
chmod +x check_fortinet_version.sh
./check_fortinet_version.sh fortios 7.4.12
./check_fortinet_version.sh fortimanager 7.4.5
./check_fortinet_version.sh fortianalyzer-bigdata 7.6.2
# ou directement depuis le pare-feu :
ssh admin@<pare-feu> 'get system status' | ./check_fortinet_version.sh
```

```powershell
.\Check-FortinetVersion.ps1 -Product fortios -Version 7.4.12
.\Check-FortinetVersion.ps1 -Product fortianalyzer-bigdata -Version 7.6.2
```

Le script affiche **une ligne par avis applicable** à la branche donnée (`fortimanager` est vérifié contre FG-IR-26-275 **et** FG-IR-26-219
en même temps, puisque les deux concernent ce produit) :

| Ligne | Signification |
|---|---|
| `[VULNÉRABLE]` | version antérieure à la version corrigée de cet avis |
| `[CORRIGÉ]` | corrigée pour **cet** avis |
| `[À VÉRIFIER]` | branche non listée dans cet avis, ou version illisible |
| `[NON CONCERNÉ]` | cet avis précis ne concerne pas cette branche (ex. FG-IR-26-219 sur une branche 7.4/7.2) |

Le **bilan final** et le **code de sortie** reflètent le pire cas parmi tous les avis applicables (0 = corrigé partout, 1 = au moins un
« à vérifier », 2 = vulnérable à au moins un avis).

**Exposition** (indépendamment de la version) : depuis un poste hors de votre réseau d'administration, `nc -zv <FortiManager> 541` doit **échouer**.
Ne scannez que vos propres équipements.

## 2. Corriger

1. **Sauvegarder** la configuration (FortiManager : *Système > Paramètres > Sauvegarde* ; FortiGate : *Configuration > Sauvegarde*).
2. Choisir le chemin de mise à niveau avec l'[outil officiel](https://docs.fortinet.com/upgrade-tool).
3. Mettre à niveau : FortiManager d'abord (il pilote les FortiGate), puis les FortiGate **un nœud de cluster à la fois**.
4. Relancer le vérificateur : chaque ligne doit passer à `[CORRIGÉ]`.

**En attendant** :
- restreindre FGFM (TCP 541) et l'administration web/SSH aux réseaux de gestion ;
- désactiver OSPF s'il n'est pas utilisé ;
- **FG-IR-26-219** : si l'API JSON n'est pas utilisée (cas le plus courant, elle est désactivée par défaut), vérifier qu'elle l'est bien ;
  si elle est activée sur un profil admin, la désactiver en attendant le correctif :
  ```
  config system admin profile
    edit <nom_du_profil>
      set rpc-permit none
    end
  ```
- ne jamais exposer l'interface d'administration à Internet.

## Limites

- Cet outil ne couvre que les **trois avis vérifiés** ci-dessus ; le lot contient d'autres failles (voir le portail PSIRT).
- Il compare des numéros de version fournis par vous : il ne se connecte à aucun équipement.
- Les branches 7.0 et antérieures de FortiManager ne figurent pas dans les avis : `[À VÉRIFIER]`.
- FG-IR-26-219 ne peut être confirmée "activement exploitable" qu'en vérifiant aussi si l'API JSON est activée (le script ne le vérifie
  pas — c'est un réglage de configuration, pas un numéro de version) : une version vulnérable avec l'API désactivée reste à mettre à
  jour, mais n'est pas immédiatement exploitable tant que l'API reste désactivée.
- FortiManager/FortiAnalyzer **Cloud** ont des bornes de version légèrement différentes du on-prem pour FG-IR-26-219 (démarrent à
  .1 au lieu de .0) : non distingué par ce script, toujours vérifier le détail sur l'avis officiel pour une instance Cloud.

## Impact sur nos solutions

| Solution | Statut | Remarque |
|---|---|---|
| Proxmox VE | Non impacté |  |
| Docker | Non impacté |  |
| LXC | Non impacté |  |
| Veeam | Non impacté |  |
| Nakivo | Non impacté |  |
| 3CX | Non impacté |  |
| Elastix | Non impacté |  |
| Andrisoft WANGuard | Non impacté |  |
| Datalust Seq | Non impacté |  |
| LibreNMS | Non impacté |  |
| Observium | Non impacté |  |
| Debian | Non impacté |  |
| Ubuntu | Non impacté |  |
| Windows Server (2012/2016/2019/2022/2025) | Non impacté |  |
| SMB (Samba, Debian) | Non impacté |  |
| SFTP (Debian) | Non impacté |  |
| Cisco | Non impacté |  |
| Ubiquiti | Non impacté |  |
| HP/Aruba | Non impacté |  |
| FortiGate | Impacté | FG-IR-26-267 (OSPF) + lot plus large de novembre 2026 |
| FortiAnalyzer | Impacté | FG-IR-26-219 (API JRPC) |
| FortiManager | Impacté | FG-IR-26-275 (FGFM) et FG-IR-26-219 (API JRPC) |
| Sophos | Non impacté | Avis Fortinet uniquement -- sans rapport avec les produits Sophos |
| nginx | Non impacté |  |
| Certbot | Non impacté |  |
| Odoo (self-hosted) | Non impacté |  |
| Nextcloud | Non impacté |  |
| JumpCloud | Non impacté |  |
| Python | Non impacté |  |
| Django | Non impacté |  |
| React | Non impacté |  |
| PHP | Non impacté |  |
| MikroTik | Non impacté |  |
| Ceph | Non impacté |  |
| QEMU-KVM | Non impacté |  |

## Références

- [FG-IR-26-275 — FortiManager FGFM](https://www.fortiguard.com/psirt/FG-IR-26-275)
- [FG-IR-26-219 — Injection JSON API JRPC](https://www.fortiguard.com/psirt/FG-IR-26-219)
- [FG-IR-26-267 — FortiOS OSPF](https://www.fortiguard.com/psirt/FG-IR-26-267)
- [Portail PSIRT Fortinet](https://www.fortiguard.com/psirt)
