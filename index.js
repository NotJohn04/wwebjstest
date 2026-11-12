import 'dotenv/config';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import qrcode from 'qrcode-terminal';
import QRCode from 'qrcode';
import { exec } from 'node:child_process';
import pkg from 'whatsapp-web.js';

const { Client, LocalAuth } = pkg;

const WEBHOOK_URL = process.env.WEBHOOK_URL;
const MEDIA_BASE64 = (process.env.MEDIA_BASE64 || 'full').toLowerCase();
const SAVE_MEDIA = process.env.SAVE_MEDIA !== 'false';
const MEDIA_DIR = path.resolve('media');

if (!WEBHOOK_URL) {
  console.error('Set WEBHOOK_URL in .env');
  process.exit(1);
}
if (SAVE_MEDIA) fs.mkdirSync(MEDIA_DIR, { recursive: true });

// ---------- webhook sender ----------
async function post(event, payload) {
  const body = { event, sentAt: new Date().toISOString(), ...payload };
  try {
    let res = await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-WA-Event': event },
      body: JSON.stringify(body, null, 2),
    });
    // Too big? retry without the full base64 so you still see the metadata
    if (!res.ok && body.media?.base64 && res.status === 413) {
      body.media.base64 = body.media.base64.slice(0, 300) + '...(truncated, payload too large)';
      res = await fetch(WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-WA-Event': event },
        body: JSON.stringify(body, null, 2),
      });
    }
    console.log(`→ [${event}] webhook ${res.status}`);
  } catch (err) {
    console.error(`✗ [${event}] webhook failed:`, err.message);
  }
}

// ---------- media handling ----------
const EXT = {
  'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif',
  'video/mp4': 'mp4', 'audio/ogg; codecs=opus': 'ogg', 'audio/mpeg': 'mp3',
  'audio/mp4': 'm4a', 'application/pdf': 'pdf',
};

// Manual download + decrypt, straight from the fields in msg._data.
// WhatsApp stores media encrypted on its CDN (mmg.whatsapp.net). mediaKey → HKDF → iv + AES key + MAC key.
const HKDF_INFO = {
  image: 'WhatsApp Image Keys', sticker: 'WhatsApp Image Keys',
  video: 'WhatsApp Video Keys', gif: 'WhatsApp Video Keys',
  audio: 'WhatsApp Audio Keys', ptt: 'WhatsApp Audio Keys',
  document: 'WhatsApp Document Keys',
};
async function manualDownload(msg) {
  const d = msg._data;
  const url = d.deprecatedMms3Url || (d.directPath && `https://mmg.whatsapp.net${d.directPath}`);
  if (!url || !d.mediaKey) throw new Error('no url/mediaKey in message');
  const res = await fetch(url);
  if (!res.ok) throw new Error(`CDN responded ${res.status}`);
  const enc = Buffer.from(await res.arrayBuffer());
  const keys = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(d.mediaKey, 'base64'),
    Buffer.alloc(32), HKDF_INFO[msg.type] || 'WhatsApp Document Keys', 112));
  const iv = keys.subarray(0, 16), cipherKey = keys.subarray(16, 48), macKey = keys.subarray(48, 80);
  const file = enc.subarray(0, -10), mac = enc.subarray(-10);
  const calc = crypto.createHmac('sha256', macKey).update(Buffer.concat([iv, file])).digest().subarray(0, 10);
  if (!calc.equals(mac)) throw new Error('MAC mismatch');
  const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey, iv);
  const plain = Buffer.concat([decipher.update(file), decipher.final()]);
  return { mimetype: d.mimetype, filename: d.filename ?? null, filesize: plain.length, data: plain.toString('base64') };
}

async function extractMedia(msg) {
  if (!msg.hasMedia) return null;
  try {
    let media, method = 'downloadMedia', libError = null;
    try {
      media = await msg.downloadMedia();
    } catch (err) {
      libError = err.message;
    }
    if (!media) {
      media = await manualDownload(msg);
      method = 'manual-decrypt';
    }

    const ext = EXT[media.mimetype] || media.mimetype.split('/')[1]?.split(';')[0] || 'bin';
    const fileName = media.filename || `${msg.timestamp}_${msg.id.id}.${ext}`;
    let savedTo = null;
    if (SAVE_MEDIA) {
      savedTo = path.join(MEDIA_DIR, fileName.replace(/[\/\\]/g, '_'));
      fs.writeFileSync(savedTo, Buffer.from(media.data, 'base64'));
    }

    const out = {
      method,
      libError,
      mimetype: media.mimetype,
      filename: media.filename ?? null,
      filesize: media.filesize ?? null,
      base64Length: media.data.length,
      approxBytes: Math.round((media.data.length * 3) / 4),
      savedTo,
      // paste this into a browser address bar to view the image:
      dataUrlPrefix: `data:${media.mimetype};base64,`,
    };
    if (MEDIA_BASE64 === 'full') out.base64 = media.data;
    else if (MEDIA_BASE64 === 'preview') out.base64 = media.data.slice(0, 300) + '...';
    return out;
  } catch (err) {
    return { error: err.message };
  }
}

// ---------- message → readable summary ----------
async function describe(msg) {
  let chatName = null, contactName = null, isGroup = null;
  try {
    const chat = await msg.getChat();
    chatName = chat.name;
    isGroup = chat.isGroup;
  } catch {}
  try {
    const contact = await msg.getContact();
    contactName = contact.pushname || contact.name || contact.number;
  } catch {}

  let quoted = null;
  if (msg.hasQuotedMsg) {
    try {
      const q = await msg.getQuotedMessage();
      quoted = { id: q.id._serialized, type: q.type, body: q.body?.slice(0, 200) };
    } catch {}
  }

  return {
    id: msg.id._serialized,
    type: msg.type, // chat, image, video, ptt, audio, document, sticker, location, vcard, revoked...
    fromMe: msg.fromMe,
    from: msg.from,
    to: msg.to,
    author: msg.author ?? null, // sender inside a group
    chatName,
    contactName,
    isGroup,
    timestamp: msg.timestamp,
    timeReadable: new Date(msg.timestamp * 1000).toISOString(),
    body: msg.type === 'chat' ? msg.body : undefined, // for images, body = thumbnail base64, see raw
    caption: msg.type !== 'chat' ? (msg._data?.caption ?? null) : undefined,
    hasMedia: msg.hasMedia,
    isForwarded: msg.isForwarded,
    hasQuotedMsg: msg.hasQuotedMsg,
    quoted,
    mentionedIds: msg.mentionedIds,
    location: msg.location ?? undefined,
    vCards: msg.vCards?.length ? msg.vCards : undefined,
    deviceType: msg.deviceType,
  };
}

// ---------- WhatsApp client ----------
const client = new Client({
  authStrategy: new LocalAuth(), // session saved in .wwebjs_auth so you scan only once
  puppeteer: { headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] },
});

client.on('qr', (qr) => {
  console.log('\nScan this QR with WhatsApp → Linked devices → Link a device:\n');
  qrcode.generate(qr, { small: true });
  // also save as an image and open it (macOS)
  QRCode.toFile('qr.png', qr, { width: 400 }).then(() => {
    console.log('QR saved to qr.png');
    exec('open qr.png');
  });
});
let isReady = false;
let readyWatchdog = null;
client.on('authenticated', () => {
  console.log('Authenticated');
  fs.rmSync('qr.png', { force: true });
  // whatsapp-web.js sometimes logs in but never fires 'ready' after a session restore.
  // If that happens, reload WhatsApp Web once a minute until it does.
  if (!readyWatchdog) {
    readyWatchdog = setInterval(async () => {
      if (isReady) return clearInterval(readyWatchdog);
      const state = await client.getState().catch(() => 'unknown');
      console.log(`Not ready yet (state: ${state}), reloading WhatsApp Web...`);
      await client.pupPage?.reload().catch((e) => console.error('Reload failed:', e.message));
    }, 60_000);
  }
});
client.on('auth_failure', (m) => console.error('Auth failure:', m));
client.on('ready', async () => {
  isReady = true;
  clearInterval(readyWatchdog);
  console.log(`Ready as ${client.info.wid._serialized}. Send yourself a message / image to test.`);
  await post('ready', { me: client.info });
});
client.on('disconnected', (reason) => {
  console.log('Disconnected:', reason);
  post('disconnected', { reason });
});

// message_create fires for BOTH incoming and outgoing (fromMe) messages
client.on('message_create', async (msg) => {
  console.log(`[${msg.type}] ${msg.fromMe ? 'me →' : '← '} ${msg.from}: ${msg.type === 'chat' ? msg.body : '(media/other)'}`);
  const summary = await describe(msg);
  const media = await extractMedia(msg);
  await post(`message.${msg.type}`, {
    summary,
    media,
    raw: msg._data, // everything WhatsApp Web knows about the message
  });
});

client.on('message_ack', (msg, ack) => {
  // -1 error, 0 pending, 1 sent (server), 2 delivered, 3 read, 4 played
  const label = { '-1': 'error', 0: 'pending', 1: 'sent', 2: 'delivered', 3: 'read', 4: 'played' }[ack];
  post('message_ack', { id: msg.id._serialized, to: msg.to, ack, ackLabel: label });
});

client.on('message_revoke_everyone', (after, before) =>
  post('message_revoke_everyone', { after: after?._data, before: before?._data }));

client.on('message_edit', (msg, newBody, prevBody) =>
  post('message_edit', { id: msg.id._serialized, newBody, prevBody }));

client.on('message_reaction', (reaction) => post('message_reaction', { reaction }));

client.on('group_join', (n) => post('group_join', { notification: n }));
client.on('group_leave', (n) => post('group_leave', { notification: n }));
client.on('call', (call) => post('call', { call }));

client.initialize();
