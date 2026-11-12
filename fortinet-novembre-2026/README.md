# Fortinet — lot de correctifs de novembre 2026

> Fortinet a publié le **10/11/2026** environ **100 correctifs** (dont une vingtaine de critiques selon la presse spécialisée), annoncés sans
> détail depuis octobre. **Aucune exploitation connue** et aucune entrée au catalogue CISA KEV au 11/11, mais les équipements Fortinet
> sont des cibles habituelles dès la divulgation : ne pas attendre.

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Vous avez un **FortiManager / FortiAnalyzer** ou un **FortiGate (FortiOS)** dans une version listée ci-dessous. |
| **Comment tester ?** | `./check_fortinet_version.sh fortios 7.4.12` (ou `fortimanager`) — compare une version, **sans se connecter** au pare-feu. |
| **Comment corriger ?** | Mettre à niveau vers la version corrigée de votre branche (tableau ci-dessous). En attendant : ne pas exposer FGFM/admin à Internet. |

## Les deux avis vérifiés à la source

| Avis | Produit | Gravité | Conditions | Vulnérables | Corrigées |
|---|---|---|---|---|---|
| **FG-IR-26-275** — CVE-2026-126261 | **FortiManager / FortiAnalyzer** : exécution de code ou de commandes **sans authentification** via le service **FGFM** | **9.0** | accès réseau au port FGFM (TCP 541) | 8.0.0 ; 7.6.0–7.6.7 ; 7.4.0–7.4.5 ; 7.2.0–7.2.8 | **8.0.1 ; 7.6.8 ; 7.4.6 ; 7.2.9** |
| **FG-IR-26-267** — CVE-2026-126253 | **FortiOS** : contournement d'authentification du démon **OSPF** | **9.3** | attaquant sur le réseau adjacent, OSPF actif | 8.0.0–8.0.1 ; 7.6.0–7.6.7 ; 7.4.0–7.4.12 ; 7.2.0–7.2.13 ; 7.0.1–7.0.19 | **8.0.2 ; 7.6.8 ; 7.4.13 ; 7.2.14** (7.0 : **pas de correctif**, migrer) |

Aucun contournement n'est proposé par Fortinet pour ces deux avis. Le lot contient d'autres correctifs (FortiOS : SSH, noyau, proxy WAD ;
FortiMail : plusieurs critiques ; FortiSASE) : **installez la dernière version de votre branche** plutôt que la version minimale, et
consultez le [portail PSIRT](https://www.fortiguard.com/psirt) pour les produits non couverts ici.

## 1. Tester

Relevez la version : interface web (tableau de bord) ou, en CLI, `get system status`.

```bash
chmod +x check_fortinet_version.sh
./check_fortinet_version.sh fortios 7.4.12
./check_fortinet_version.sh fortimanager 7.4.5
# ou directement depuis le pare-feu :
ssh admin@<pare-feu> 'get system status' | ./check_fortinet_version.sh
```

```powershell
.\Check-FortinetVersion.ps1 -Product fortios -Version 7.4.12
```

| Ligne | Signification |
|---|---|
| `[VULNÉRABLE]` | version antérieure à la version corrigée de sa branche (exit 2) |
| `[CORRIGÉ]` | corrigée pour **cet** avis (exit 0) |
| `[À VÉRIFIER]` | branche non listée ou version illisible (exit 1) |

**Exposition** (indépendamment de la version) : depuis un poste hors de votre réseau d'administration, `nc -zv <FortiManager> 541` doit **échouer**.
Ne scannez que vos propres équipements.

## 2. Corriger

1. **Sauvegarder** la configuration (FortiManager : *Système > Paramètres > Sauvegarde* ; FortiGate : *Configuration > Sauvegarde*).
2. Choisir le chemin de mise à niveau avec l'[outil officiel](https://docs.fortinet.com/upgrade-tool).
3. Mettre à niveau : FortiManager d'abord (il pilote les FortiGate), puis les FortiGate **un nœud de cluster à la fois**.
4. Relancer le vérificateur : la ligne doit passer à `[CORRIGÉ]`.

**En attendant** : restreindre FGFM (TCP 541) et l'administration web/SSH aux réseaux de gestion ; désactiver OSPF s'il n'est pas utilisé ;
ne jamais exposer l'interface d'administration à Internet.

## Limites

- Cet outil ne couvre que les **deux avis vérifiés** ci-dessus ; le lot contient d'autres failles (voir le portail PSIRT).
- Il compare des numéros de version fournis par vous : il ne se connecte à aucun équipement.
- Les branches 7.0 et antérieures de FortiManager ne figurent pas dans l'avis : `[À VÉRIFIER]`.

## Références

- [FG-IR-26-275 — FortiManager FGFM](https://www.fortiguard.com/psirt/FG-IR-26-275)
- [FG-IR-26-267 — FortiOS OSPF](https://www.fortiguard.com/psirt/FG-IR-26-267)
- [Portail PSIRT Fortinet](https://www.fortiguard.com/psirt)
