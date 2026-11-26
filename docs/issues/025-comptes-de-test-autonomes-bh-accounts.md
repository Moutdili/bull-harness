---
id: 25
title: "Comptes de test autonomes (bh accounts)"
labels: [P0, area:autonomy, owner:claude, build]
status: closed
---

# Comptes de test autonomes (bh accounts)

Conteneur `browser` piloté par l'hôte (jamais par l'agent), recette d'inscription dans le YAML de scope, mails de confirmation lus par l'API Gmail en lecture seule (décision Mio 2026-11-25), TOTP RFC 6238 sur l'hôte, secrets dans secrets/identities/. Inscription seulement si le programme l'autorise (champ de scope, null = interdit). Plan : docs/research/10-sessions-anti-bot.md §3, §5.

**Acceptation :** lab : `bh accounts enroll lab-juiceshop user-a` finit avec la sonde authentifiée, sans action humaine ; `bh accounts ls` n'affiche aucun secret

## Mail de confirmation (Gmail, lecture seule) — 2026-11-25

- `src/bh/accounts/mail.py` : `GmailMailbox` (stdlib), choisie par `mail.mailbox()` quand `BH_GMAIL_TOKEN` (défaut `~/.hermes/google_token.json`) contient un `refresh_token`, sinon `NoMailbox`. Le fichier d'Hermes est lu, jamais écrit ; le jeton d'accès reste en mémoire (pas dans `var/state/`, monté dans le gate).
- Requête `to:<alias> from:<domaine> after:<epoch s>`, puis `messages/<id>?format=raw`. Garde-fous §3.5 : expéditeur du domaine ; `Authentication-Results` du haut avec dkim/spf/dmarc=pass pour le domaine, s'il existe ; `internalDate` > inscription ; destinataire = alias ; un seul lien https sur le domaine, sinon un code de 4-8 chiffres. Log : id du message et domaine.
- `bh accounts mail-check` : rafraîchit le jeton, compte les mails des 24 h à l'alias de `researcher.env`, n'affiche que le compte.
- Validation live 2026-11-25 : `ERR token refresh failed: HTTP 400 invalid_grant Bad Request`. Le refresh token est expiré ou révoqué. Une app OAuth « External » en statut « Testing » reçoit des refresh tokens valables 7 jours ([doc](https://developers.google.com/identity/protocols/oauth2#expiration)). À faire par Mio : passer l'app en « In production » (écran de consentement, Google Cloud), refaire le consentement `gmail.readonly` côté Hermes, puis relancer `bh accounts mail-check`.
- Reste : `enroll.py` n'appelle pas encore la boîte (pas d'étape `confirm` dans la recette). Le lien rendu devra être suivi via le gate.

Plan : [docs/plan-v3.md](../plan-v3.md)

Fermée le 2026-11-25 : inscription et reconnexion par recette, validées sur Juice Shop et Larkspur. Reste hors issue : lecture Gmail (code prêt, jeton Hermes `invalid_grant`, app OAuth à passer en production).

2026-11-25 (soir) : Gmail branché. L'app OAuth `datk-oauth` est publiée (plus d'expiration à 7 jours) ; le harnais a
son propre jeton lecture seule (`bh accounts gmail-login` → `secrets/gmail_token.json`, 0600), préféré à celui
d'Hermes. `bh accounts mail-check` : token ok. Les codes de connexion Microsoft vont à `code_to` (Gmail de Mio).
