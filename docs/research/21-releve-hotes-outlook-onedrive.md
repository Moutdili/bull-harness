# 21 — Relevé des hôtes OneDrive et Outlook.com (ML23, 2026-11-26)

Relevé par l'orchestrateur pendant la chasse manuelle du 26 (journal `hunt/live.log`), avec nos deux comptes
personnels (user-a `mio_msobb_0@hotmail.com`, user-b `mio_msobb_1@hotmail.com`). Seul ce qui a été **vu en vrai**
figure ici. Le lot W2-H n'écrit aucun hôte qui n'y est pas.

## OneDrive personnel (relevé)

Vu au travers de Copilot (upload d'un fichier, lien d'un fichier référencé dans un chat partagé) et de
`onedrive.live.com` ouvert dans bh-browser.

| Hôte, préfixe | Rôle | Méthodes vues | Type de route |
|---|---|---|---|
| `https://graph.microsoft.com/v1.0/me/drive/special/copilotuploads` | dossier « Copilot uploads » du compte | GET | lecture |
| `https://graph.microsoft.com/v1.0/me/drive/special/copilotuploads:` | session d'upload (`:/<fichier>:/createUploadSession`) | POST | écriture (`link` : aucun destinataire) |
| `https://my.microsoftpersonalcontent.com/personal/<CID>/_api/v2.0/drive/items/<id>/uploadSession` | envoi des octets | PUT | écriture |
| `https://onedrive.live.com/` | interface web (`/?cid=…&id=…`, vue `shared`) | GET | lecture |
| `api.onedrive.com` (`/v2.1/drive`, `/v2.1/drives/<CID>`, `/v2.1/sites/root/consumerSiteAppConfigs/…`, `/inappmessaging/v1/messages`, `/v2.1/unifiedStorageQuota/…`) | API de l'interface | GET | lecture |
| `https://d.docs.live.net/<CID>/<chemin>` | accès WebDAV à un fichier (redirige vers une connexion `ssl.live.com` propre) | GET (302) | lecture |
| `https://home.microsoftpersonalcontent.com/contentstorage/<conteneur><CID>` et `/_api/v2.1/drives/b!…` | conteneur SharePoint Embedded des notebooks Copilot (Loop) | GET, POST | lecture, écriture |
| `pus4-collabhubrtc.officeapps.live.com` | collaboration temps réel Loop (Fluid) | websocket | — |
| `https://graph.microsoft.com/v1.0/me/people` | sélecteur de personnes (invitation à un notebook) | GET | lecture |

Faits utiles :
- l'accès au drive d'un autre compte répond **404** (`api.onedrive.com/v2.1/drives/<CID de B>` sous user-a) ;
- un fichier téléversé dans Copilot atterrit dans `Microsoft Copilot Chat Files/` du OneDrive du compte ;
- un compte neuf n'a pas de OneDrive tant qu'il n'a pas ouvert `onedrive.live.com` (GET du dossier spécial → 404).

Non relevé : partage d'un fichier OneDrive (invitation, lien), corbeille, versions. Aucune route `send` (invitation
nommant un destinataire) n'a été vue sur OneDrive : à relever avant de l'ouvrir.

## Outlook.com (non relevé)

Aucun trafic d'Outlook.com n'est passé par le gate le 26 : Mio a envoyé le mail de user-a vers user-b depuis son
propre navigateur. **Rien n'est à ajouter pour Outlook.com** tant que le relevé n'est pas fait (ML23 reste ouvert
pour Outlook) : le lot W2-H prépare le programme et ses gardes sans cible Outlook.
