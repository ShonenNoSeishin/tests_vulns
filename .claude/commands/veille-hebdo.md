---
description: Veille hebdomadaire des failles/CVE importantes de la semaine (hébergeur cloud — 3CX, Ubuntu Server, Windows Server AD/TS/SQL, Proxmox/Ceph)
---

Tu fais la veille sécurité hebdomadaire d'un hébergeur cloud. Lis d'abord
`/home/thib/ir-context/company-profile.md` (contexte privé : parc machines, priorités) — ne cite
jamais son contenu brut dans le document final, utilise-le seulement pour prioriser et filtrer.

## 1. Collecte

Cherche les failles/CVE **divulguées ou mises à jour significativement dans les 7 derniers jours**
(date du jour : calcule-la, ne la suppose pas). Couvre au minimum :

- **CISA KEV** (Known Exploited Vulnerabilities) — toute entrée ajoutée cette semaine, priorité absolue.
- **NVD** / GitHub Security Advisories pour les composants du parc : 3CX, Ubuntu Server (USN —
  Ubuntu Security Notices), Windows Server (Patch Tuesday du mois si dans la fenêtre, avisories
  MSRC pour AD/RDS/SQL Server), Proxmox VE (forum/changelog officiel), Ceph (liste de sécurité
  Ceph/RADOS), QEMU/KVM (évasion VM).
- **Équipements périmètre** : avis de sécurité officiels Sophos (Sophos Firewall/XGS), Fortinet
  PSIRT (FortiGate/FortiOS, **FortiManager**), MikroTik (RouterOS changelog sécurité). Ces
  avis sont historiquement une cible fréquente d'exploitation active dès divulgation — vérifier
  systématiquement le KEV CISA et la présence d'un exploit public pour chaque CVE trouvée ici.
- Recoupe avec des flux généralistes (ex. The Hacker News, BleepingComputer, Rapid7, Tenable
  blog) seulement pour repérer ce qui serait massivement exploité et absent des sources
  officielles ci-dessus — jamais comme source principale de la version/patch.
- **Grosses failles généralistes de la semaine, même hors liste de composants explicite** :
  fais systématiquement une recherche large type "major/critical CVE this week" en plus des
  recherches ciblées par produit ci-dessus. Logiciels d'infrastructure très largement déployés
  (ex. nginx, Apache httpd, OpenSSL, HAProxy, Linux kernel générique, PHP, bibliothèques très
  répandues) comptent même s'ils ne sont pas nommément dans `company-profile.md` : un hébergeur
  cloud les fait presque certainement tourner quelque part (reverse-proxy, panneaux d'admin,
  sites clients) même sans que ce soit documenté précisément composant par composant. Ne pas se
  limiter à la liste de produits du parc pour décider si une faille "compte".
- Note si un exploit public (Metasploit, exploit-db, PoC GitHub) existe déjà : ça change la
  priorité d'action.

Écarte le bruit : failles mineures sans exploitabilité réseau/distante, ou sur des composants
hors du parc, sauf CVSS ≥ 9, présence dans le KEV CISA, **ou forte probabilité de présence dans
l'infra malgré l'absence du parc** (toujours les garder, même hors parc — mais dans le corps
principal du résumé exécutif si RCE non authentifiée + très large adoption, sinon en section
"veille large").

## 2. Priorisation

Classe par ordre de criticité selon `company-profile.md` :
1. Proxmox VE / QEMU-KVM / Ceph (hyperviseur et stockage partagés entre clients)
2. Équipements périmètre exposés (FortiGate/FortiManager, Sophos, MikroTik)
3. Windows Server — rôle AD
4. 3CX
5. Windows Server — SQL / TS, puis Ubuntu Server
6. Reste, seulement si KEV ou CVSS ≥ 7

Pour chaque faille retenue dans le résumé exécutif, recroiser aussi avec la section « Liste
exhaustive des solutions à vérifier » de `company-profile.md` (Veeam, Nakivo, Elastix, Andrisoft
WANGuard, Datalust Seq, LibreNMS, Observium, Docker, LXC, SMB/SFTP, Cisco, Ubiquiti, HP/Aruba,
nginx, Certbot, Odoo, Nextcloud, JumpCloud, Python/Django/React/PHP...) — cette liste est plus
large que les 6 catégories ci-dessus, qui restent l'ordre de *priorité* pour décider quoi traiter
en premier. La matrice d'impact **structurée** (une entrée par solution, pas juste une mention au
fil du texte) n'est obligatoire que dans les fiches `/deep-dive-vuln` (`vuln.yaml` → `impact:`,
voir `docs/FORMAT.md`) — la veille elle-même reste un document privé plus informel, mais doit
quand même signaler explicitement si une solution de cette liste est concernée.

## 1bis. Plages IP publiques Cloudflare/OVH/Gandi (whitelists)

À chaque veille, vérifie et mets à jour `/home/thib/ir-context/veille/ip-ranges-dns.md` :
- Cloudflare : récupère `https://www.cloudflare.com/ips-v4` et `https://www.cloudflare.com/ips-v6`,
  note la date de vérification et si les plages ont changé depuis la dernière veille.
- OVH : vérifie si une plage/AS (AS16276) ou un bulletin officiel a changé.
- Gandi : vérifie si une liste de plages IP sortantes officielles existe désormais (sinon
  réaffirmer "non disponible publiquement" avec la date de vérification).
Si rien n'a changé depuis la dernière veille, note juste "vérifié le <date>, inchangé" — ne
réécris pas tout le fichier inutilement.

## 3. Document de sortie

Écris **un seul fichier** `/home/thib/ir-context/veille/veille-<année ISO>-S<semaine ISO
2 chiffres>.md` (ex. `veille-2026-S45.md`). Structure :

```markdown
# Veille sécurité — semaine <SXX> <année> (<date début> → <date fin>)

## Résumé exécutif
Tableau trié par criticité : | Faille | Composant | CVSS | KEV ? | Exploit public ? | Action requise |

## <CVE ou nom de la faille> — <composant>
**Criticité : ...**

### Contexte
Résumé court et concret : qu'est-ce qui est cassé, comment c'est exploité, pourquoi ça compte
pour un hébergeur cloud.

### Dates importantes
- Divulgation : ...
- Publication du patch : ...
- Ajout au KEV CISA (si applicable) + date limite de remédiation : ...

### Matériel / fournisseur / versions impactées
Tableau : fournisseur, produit, versions vulnérables, versions corrigées. Préciser les cas de
**backporting** connus (ex. "Ubuntu LTS a backporté le correctif dans la version X du paquet,
vérifier via `apt changelog` / security tracker, pas juste le numéro upstream").

### Méthodes de détection
Comment vérifier si on est exposé (commande, requête, indicateur réseau/version) — sans fournir
de payload d'exploitation ici, uniquement de l'inventaire/détection.

### Méthode(s) de patch
Commande(s) ou procédure de mise à jour par méthode d'installation (paquet, Docker, Snap,
installeur Windows...).

### Versions non patchables / sans correctif disponible
Si applicable : workaround officiel, mitigation réseau (firewall, désactivation d'un module),
ou mention explicite "aucun contournement connu — isoler/segmenter en urgence".

### Liens importants
Avis officiel, CVE, KEV CISA si applicable, PoC public s'il existe (lien seulement, pas de payload).

## Veille large (hors parc mais KEV/CVSS≥9)
Liste courte, même structure allégée.
```

## 4. Après écriture

- N'écris rien dans `/home/thib/Incident_Response_Project` (repo public) pendant cette veille.
- **Rien de cette veille n'apparaît dans IRM tant qu'un `/deep-dive-vuln` n'a pas créé la fiche
  (dossier + `vuln.yaml` valide dans `Incident_Response_Project/`) et que ce n'est pas poussé sur
  les deux remotes.** La veille seule, même détaillée, ne nourrit que `ir-context/` (privé) — ne
  jamais laisser croire que la veille a elle-même mis à jour l'app.
- Termine ta réponse par : le chemin complet du fichier produit, et la liste des failles qui
  mériteraient un `/deep-dive-vuln` cette semaine, par ordre de priorité.
- Si une faille de la semaine touche un composant du parc et est **critique ou déjà exploitée**,
  liste-les explicitement et **propose de lancer les `/deep-dive-vuln` correspondants tout de
  suite, l'un après l'autre**, plutôt que d'attendre une demande ultérieure.
