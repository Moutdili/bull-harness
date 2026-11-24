---
id: 25
title: "Comptes de test autonomes (bh accounts)"
labels: [P0, area:autonomy, owner:claude, build]
status: open
---

# Comptes de test autonomes (bh accounts)

Conteneur `browser` piloté par l'hôte (jamais par l'agent), recette d'inscription dans le YAML de scope, mails de confirmation lus par l'API Gmail en lecture seule (décision Mio 2026-11-25), TOTP RFC 6238 sur l'hôte, secrets dans secrets/identities/. Inscription seulement si le programme l'autorise (champ de scope, null = interdit). Plan : docs/research/10-sessions-anti-bot.md §3, §5.

**Acceptation :** lab : `bh accounts enroll lab-juiceshop user-a` finit avec la sonde authentifiée, sans action humaine ; `bh accounts ls` n'affiche aucun secret

Plan : [docs/plan-v3.md](../plan-v3.md)
