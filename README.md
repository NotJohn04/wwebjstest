# wwebjs webhook inspector

Sends every WhatsApp event from [whatsapp-web.js](https://github.com/pedroslopez/whatsapp-web.js) to a webhook (for example [webhook.site](https://webhook.site)), so you can see exactly what each message type looks like, especially images and other media.

## Setup

```bash
npm install
cp .env.example .env   # then set WEBHOOK_URL
npm start
```

Scan the QR code (it is shown in the terminal and opened as `qr.png`) from WhatsApp → Linked devices → Link a device. The session is saved in `.wwebjs_auth`, so you only scan once.

## What each request contains

- `event`: `message.chat`, `message.image`, `message.video`, `message.ptt`, `message.document`, `message_ack`, `message_reaction`, `message_edit`, `message_revoke_everyone`, `call`, `group_join`, `group_leave`, `ready`, `disconnected`
- `summary`: readable fields (sender, chat, `fromMe`, type, text or caption, quoted message)
- `media`: mimetype, file size, the full file as `base64` (controlled by `MEDIA_BASE64`), and where the file was saved in `./media`
- `raw`: the full `msg._data` from WhatsApp Web

## How media works

For images, `raw.body` is **not** the image. It is a small (about 72×72) base64 JPEG thumbnail. The full file is stored encrypted on WhatsApp's servers at `raw.deprecatedMms3Url` / `raw.directPath`. To decrypt it:

1. Run HKDF-SHA256 on `mediaKey` with the info string `"WhatsApp Image Keys"` (or Video/Audio/Document) to get 112 bytes: the IV is bytes 0–16, the AES key is bytes 16–48 and the MAC key is bytes 48–80.
2. Download the encrypted file. Its last 10 bytes are a MAC; check it with HMAC-SHA256(macKey, iv + file).
3. Decrypt the rest with AES-256-CBC.

If `msg.downloadMedia()` fails (in whatsapp-web.js 1.34.7 it currently throws `"r"`), the bot does these steps itself. `media.method` shows which way was used.

## Notes

- whatsapp-web.js is unofficial. Use a spare number.
- Anyone with your webhook.site link can see the messages and images sent there.
- Never commit `.wwebjs_auth`. Anyone who has it can use your WhatsApp.
