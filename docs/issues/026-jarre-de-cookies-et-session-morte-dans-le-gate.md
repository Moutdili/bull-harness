---
id: 26
title: "Jarre de cookies et session morte dans le gate"
labels: [P0, area:gate, owner:claude, build]
status: closed
---

# Jarre de cookies et session morte dans le gate

Plan : docs/research/10-sessions-anti-bot.md §3.4, §5.4 tâches 2-3. Restriction ou injection seulement, jamais d'élargissement.

**Acceptation :** un Set-Cookie sous identité met à jour la session ; hors scope ou sans identité : rien ; session-dead émis sur 401 ou 302 vers login_url ; le runner relance le login au plus 1 fois par heure

Plan : [docs/plan-v3.md](../plan-v3.md)
