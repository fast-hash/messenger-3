# API Reference

## REST Endpoints

Полная спецификация доступна в файле [docs/api/openapi.yaml](api/openapi.yaml).

### POST /api/auth/register

- Тело: `{ username, email, password, publicKey }`
- Ответ: `201 { userId }` + HTTP-only cookie `accessToken`
- Ошибки: `400 invalid_payload`, `400 user_exists`
  【F:server/server/src/server/src/routes/server/src/routes/auth.js†L87-L138】

### POST /api/auth/login

- Тело: `{ email, password }`
- Ответ: `200 { userId }` + обновлённая cookie `accessToken`
- Ошибки: `400 missing_credentials`, `400 invalid_credentials`, `429 too_many_attempts`
  【F:server/server/src/server/src/routes/server/src/routes/auth.js†L140-L179】

### POST /api/auth/logout

- Сбрасывает cookie `accessToken`
- Ответ: `204 No Content`
  【F:server/server/src/server/src/routes/server/src/routes/auth.js†L181-L184】

### GET /api/auth/session

- Требует действующую cookie `accessToken`
- Ответ: `200 { userId }`
- Ошибки: `401 unauthorized`
  【F:server/server/src/server/src/routes/server/src/routes/auth.js†L186-L188】

### POST /api/keybundle

- Требует cookie `accessToken` или заголовок `Authorization: Bearer <JWT>`
- Тело: `{ identityKey, signedPreKey, oneTimePreKeys: [{ keyId, publicKey }] }`
- Ответ: `204 No Content`
- Ошибки: `400 invalid_payload`, `500 server_error`
  【F:server/server/src/server/src/routes/server/src/routes/keybundle.js†L93-L149】

### GET /api/keybundle/:userId

- Требует cookie `accessToken` или заголовок `Authorization`
- Ответ: `{ identityKey, signedPreKey, oneTimePreKey: { keyId, publicKey } }`
- Ошибки: `404 not_found`, `410 no_prekeys`
  【F:server/server/src/server/src/routes/server/src/routes/keybundle.js†L151-L244】

### POST /api/messages

- Требует cookie `accessToken` или заголовок `Authorization`
- Тело: `{ chatId: ObjectIdString, encryptedPayload: Base64String }`
- Успех: `200 { ok: true, id }`
- Ошибки: `401 unauthenticated`, `403 forbidden`, `409 duplicate`, `413 ciphertext too large`, `422 invalid chatId/encryptedPayload`
  【F:server/server/src/server/src/routes/server/src/routes/messages.js†L17-L109】

### GET /api/messages/:chatId

- Требует cookie `accessToken` или заголовок `Authorization`
- Ответ: `[{ id, chatId, senderId, encryptedPayload, createdAt }]`
- Ошибки: `401 unauthenticated`, `403 forbidden`, `422 invalid chatId`
  【F:server/server/src/server/src/routes/server/src/routes/messages.js†L111-L188】

## Socket.IO

- Хендшейк: cookie `accessToken` (устанавливается при логине) или явный `Authorization: Bearer <JWT>`/`auth.token`.
- События:
  - `join { chatId }` → ack `{ ok: true }` при участии в чате, иначе `{ ok: false, error }`.
  - `message { id, chatId, senderId, encryptedPayload, createdAt }` — рассылается после записи в БД.
    【F:server/server/src/server/src/app.js†L147-L240】【F:server/server/src/server/src/routes/server/src/routes/messages.js†L69-L188】

## Примеры

```json
POST /api/messages
{
  "chatId": "64f1c8e1b4c03f4a2d8f8c11",
  "encryptedPayload": "QUJDRA=="
}
```

```json
GET /api/messages/:chatId
[
  {
    "id": "64f1c8e1b4c03f4a2d8f8c12",
    "chatId": "64f1c8e1b4c03f4a2d8f8c11",
    "senderId": "64f1c8e1b4c03f4a2d8f8c13",
    "encryptedPayload": "QUJDRA==",
    "createdAt": "2024-10-15T12:00:00.000Z"
  }
]
```
