---
id: 35
title: "Preuves avec écriture : valeurs fraîches au rejeu"
labels: [P1, area:verify, owner:claude, build]
status: open
---

# Preuves avec écriture : valeurs fraîches au rejeu

Banc Larkspur du 2026-11-25 : F18 (quantité négative, vraie faille V6) reste `inconclusive`. La preuve réserve un
créneau fixe ; il est pris depuis la chasse, donc le rejeu répond 409 dès le premier passage, alors que le juge a
confirmé avec un objet neuf. Rejouer les écritures une seule fois (`c7e70a5`) ne suffit pas : l'état persiste entre
la chasse et la vérification.

Piste : gabarits remplacés au rejeu dans l'URL, les en-têtes et le corps (`{{uniq}}` = hex aléatoire par passage,
`{{int:a-b}}` = entier aléatoire borné, utile pour un créneau ou une quantité), règle de doctrine « une écriture qui
crée un objet utilise une valeur fraîche », et `validate` qui signale une écriture créatrice sans gabarit.

**Acceptation :** F18 rejouée avec des gabarits → `reproduced: true` deux vérifications de suite ; test unitaire du
remplacement ; aucune valeur générée dans un champ d'identité.

Plan : [docs/plan-v3.md](../plan-v3.md)
