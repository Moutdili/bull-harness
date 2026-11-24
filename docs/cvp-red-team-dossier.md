# CVP — passer de Defense à Red Team : analyse d'écart (2026-11-22)

Source primaire : https://support.claude.com/en/articles/14604842-cyber-verification-program (lue le 2026-11-22).

## Ce que dit la règle

| | Defense (actuel) | Red Team |
|---|---|---|
| Couvre | SecOps, IR, malware, détection, **triage et validation de vulnérabilités** | Pentest autorisé, red team, **développement d'outils offensifs et d'exploits** |
| Pour qui | … **bug bounty hunters, chercheurs individuels** | Sociétés de pentest, red teams internes |
| Qui peut postuler | Organisations **et individus** | **Organisations uniquement** |
| Plans | Pro, Max, Ultra, Team, Enterprise, API | **Enterprise et API seulement** |
| Usage « interne » | Inclut la recherche bug bounty indépendante, dans les règles du programme | idem |

→ **Avec un compte individuel Pro, Red Team est impossible.** Il faut une organisation (entreprise) sur Claude Console (API, paiement au token) ou Enterprise.

## Chemin « petite société de test » ou « société cyber »

Une seule ligne suffit, au nom de l'entreprise :

| Option | Exigence | Délai réaliste pour Mio |
|---|---|---|
| A. Société cyber | Un **crédit CVE récent au nom de la société**, ou une liste CNA, ou un membre FIRST, ou une accréditation CREST/CHECK | Le plus court : entreprise créée + un CVE publié via divulgation coordonnée et crédité à l'entreprise |
| B. Petite société de test | Registre du commerce **≥ 1 an** + page publique des services + **≥ 2 testeurs certifiés** (OSCP, GPEN, CREST) + SOW, rapport ou référence client caviardé de moins de 12 mois | ≥ 12 mois, et un 2ᵉ testeur certifié |

Contrôles à **attester** (toutes options Red Team) :

| Contrôle | Comment l'obtenir en solo | Statut |
|---|---|---|
| MFA résistant au phishing | Clé FIDO2 (YubiKey) sur tous les comptes | ❓ |
| Clés API désactivées (Red Team) | Workload Identity Federation sur Console | ❓ |
| Comptes sur domaine de l'entreprise | Domaine + mail pro | ❓ |
| Appareils contrôlés par l'organisation | Poste dédié, chiffré, géré | ❓ |
| Contrôles réseau sortants | Le **gate** de bull-harness (allowlist, journalisation) en est un exemple direct | en conception |
| Background checks | Pour chaque personne nommée ; en Suisse, extrait du casier judiciaire au minimum | ❓ |

Ce qui est accepté comme preuve : un lien public vérifiable (registre, annuaire de certifs, page de l'émetteur, profil bug bounty public). Un profil LinkedIn ou une capture d'écran ne suffit généralement pas. Les noms doivent correspondre exactement.

## Ce qu'on peut faire dès maintenant (sans tricher sur rien)

1. **Rester sur Defense pour le harnais.** C'est le tier prévu pour les chasseurs de bug bounty. La recon, le triage et la validation y sont couverts. Mesurer les refus réels (todo `refusal`) au lieu de supposer.
2. **Construire un historique public vérifiable** : profils YWH et Intigriti publics avec des rapports acceptés ; CVE obtenus par divulgation coordonnée sur des projets open source (GitHub Security Advisories est une CNA).
3. **Si une entreprise existe ou est créée** : faire créditer les CVE à son nom, puis postuler en Red Team depuis une org Console. Defense reste actif pendant l'examen (environ 2 semaines, plus long en ce moment).
4. **Certification OSCP** : utile pour l'option B et pour une candidature de stage.

## À ne pas faire
- Attester un contrôle qui n'est pas en place, ou gonfler l'équipe. L'accès peut être retiré à tout moment, et une candidature refusée ne peut être retentée qu'après 7 jours.
