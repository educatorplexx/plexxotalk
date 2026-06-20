# PlexxoTalk

A real-time messenger with username/password accounts (no phone or email),
direct messages, groups, and channels, and end-to-end encrypted text, voice
notes, images, videos, and PDFs.

Backend: `server.js` — Express + Socket.io + SQLite (better-sqlite3), all in
one file.
Frontend: `public/index.html` — a single-page app (HTML + CSS + JS), no
build step, no framework.

## How the encryption actually works

This matters more than the rest of the README, so read it before you tell
anyone this app is "encrypted."

- When someone creates an account, their **browser** generates an RSA-OAEP
  keypair. The public key goes to the server. The private key is encrypted
  (AES-GCM, key derived from their password via PBKDF2) and only the
  *encrypted* blob goes to the server — the server cannot decrypt it because
  it never has the password.
- Every chat (DM, group, or channel) has one AES-256 symmetric key, generated
  in the creator's browser. That key is wrapped (RSA-OAEP) individually for
  every member, using each member's public key, before it's uploaded. The
  server stores these wrapped copies but can't open any of them.
- All text messages, voice notes, images, videos, and PDFs are encrypted
  with that room's AES key **in the browser**, before upload. The server
  only ever stores and relays ciphertext.
- New members of a public group/channel join with no key. The next member
  who's online and already holds the key automatically re-wraps it for the
  new person and hands it over. Until that happens, the new member's app
  shows "waiting for key" and can't read anything.

**What this is not:** this is not Signal-protocol-grade encryption. There's
no forward secrecy and no key rotation — if a room's AES key is ever
compromised, every past and future message in that room is exposed, and
removing a member from a group doesn't issue a new key (they'd still be able
to decrypt anything sent after they "left," if they intercepted it).
Building a proper double-ratchet protocol is a much larger project. What you
have here is genuine end-to-end encryption (the server is structurally
unable to read content) without the advanced guarantees of Signal/WhatsApp.

## Running it locally

```bash
npm install
cp .env.example .env     # then edit JWT_SECRET to something random and long
npm start
```

Open http://localhost:3000 — create an account (name, username, password —
nothing else), then create a second account in another browser/incognito
window to test messaging between two people.

## Deploying so real people can use it

You need somewhere that keeps a Node process running continuously (this
can't be a static host like GitHub Pages, since it has a real server and
database).

**Render or Railway (easiest):**
1. Push this folder to a GitHub repo.
2. Create a new Web Service from that repo on Render.com or Railway.app.
3. Build command: `npm install`. Start command: `npm start`.
4. Set the environment variable `JWT_SECRET` to a long random string.
5. Deploy. You'll get a `https://your-app.onrender.com` URL — that's your
   live PlexxoTalk.

A couple of things to know about this setup:
- The SQLite database and uploaded files are stored on disk
  (`data/plexxotalk.db`, `uploads/`). On Render's free tier the disk is
  *not* persistent across redeploys — add a persistent disk (Render has a
  paid disk add-on) or switch to a managed Postgres + S3-style storage if
  you need data to survive redeploys.
- File uploads are capped at 100MB (ciphertext size) and avatars at 8MB —
  change the `limits` in `server.js` if you need different caps.
- For a real public launch, also put this behind HTTPS (Render/Railway do
  this for you automatically) — encryption keys are only as good as the
  channel they're exchanged over.

## Project layout

```
server.js              backend: auth, rooms, messages, file relay, sockets
public/index.html       frontend: auth/unlock screens, chat UI, all crypto
package.json
.env.example
data/                    SQLite database (created on first run)
uploads/avatars/         profile photos (not encrypted — they're public)
uploads/files/           encrypted message attachments (ciphertext only)
```

## Features included

- Sign up with name + username + password only. Only accounts created here
  can log in.
- Direct messages, groups, and channels (channels: only admins can post,
  everyone else reads — toggle a room "public" so others can discover and
  join it from the Discover tab).
- Edit your display name and profile photo any time.
- Send text, voice notes (record in-browser), images, videos, and PDFs in
  any chat, group, or channel — all encrypted before they leave the device.
- Real-time delivery via Socket.io; messages persist in SQLite so history
  loads on login.

## Reasonable next steps if you keep building this

- Add a "forgot password" flow that's honest about the trade-off: if you
  let people reset their password without their old one, you lose the
  ability to recover their old encrypted private key (i.e., old messages
  become unreadable) — that's actually correct behavior for real E2E
  encryption, just worth deciding on deliberately.
- Push notifications for offline users (currently messages just wait in the
  database until they next open the app).
- Read receipts / typing indicators (a `typing` socket event already exists
  server-side; the frontend doesn't render it yet).
- Move to a proper double-ratchet library (e.g., the same approach Signal
  uses) if you need forward secrecy.
