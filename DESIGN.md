# git-remote-enc — design

`git-remote-enc` is a git remote helper that stores an end-to-end encrypted
repository inside an ordinary git repository on an untrusted host. The host
(GitLab, GitHub, a bare repo over ssh, anything `git push` reaches) sees one
branch of opaque blobs. Only the participants named in a signed manifest can
read the refs, the history or even the participant list.

This document is the authoritative description of the on-remote format and the
protocol. The format is a compatibility contract: any change to it bumps the
manifest version (section 4.1).

## 1. Goals and non-goals

Goals

- **Confidentiality and integrity** of the repository against the host and
  anyone with read access to the hosting repository: refs, objects, ref names,
  commit metadata and the participant list are never visible in clear. What
  does show is listed in section 6.4, the backend branch name first.
- **Access control decided by the owner:** a participant list of public keys,
  carried in the manifest and signed. Adding a reader is a manifest rewrite;
  no out-of-band shared config.
- **Plain git semantics:** `git clone`, `fetch`, `push`, `pull` behave as with
  any remote. A non-fast-forward push is rejected; concurrent pushers never
  overwrite each other.
- **Incremental transfer:** a push or fetch costs proportional to the new
  objects, not to the history. No periodic full re-upload.
- **Works with a hosting service** over the transports it already offers (ssh,
  https). No rsync, no special server side, no shell access to the host.
- **Modern, boring crypto** with reference implementations: age (X25519 +
  ChaCha20-Poly1305) and SSH signatures. Participants reuse the SSH key they
  already use with the host.

Non-goals

- Hiding traffic analysis: the host sees push/fetch times, the number and size
  of encrypted packs, and the pushing account.
- Revoking read access to *past* history from a removed participant. They had
  the bytes; rotation only protects future pushes (section 6.3).
- Fine-grained per-branch permissions inside one remote. Any participant with a
  signing key may update any ref. Use separate remotes for separate audiences.
- Compatibility with the git-remote-gcrypt format.

## 2. Why not git-remote-gcrypt

git-remote-gcrypt's design is sound (encrypted packs named by hash, an
encrypted+signed manifest listing refs and pack keys) but two properties of its
implementation make it impractical on a git host. Both were measured on
gcrypt 1.5 against a local bare repository (4 pushes of 300 KB each):

| | gcrypt | after chaining backend commits |
|---|---|---|
| bytes received by the host on push 4 | 1.20 MB | 0.30 MB |
| bytes fetched after one new push | 1.72 MB | 0.30 MB |

- **Whole-history re-upload on every push and fetch.** Each gcrypt push writes
  a *parentless* root commit to the backend branch and deletes its local
  tracking ref afterwards. Git's transfer negotiation only marks the trees of
  *parent* commits as already-present, so every encrypted pack blob is sent
  again each time, in both directions. Chaining the commits (`-p` on the
  previous tip) and keeping the tracking ref makes both directions incremental.
- **Every push is a force push.** gcrypt never checks fast-forward itself, and
  git only checks it for a helper when the old tip object happens to be local
  (a missing object is passed through instead of being rejected as
  `fetch first`). The manifest is then rewritten blindly, and the backend
  branch is pushed with `-f`, so two concurrent pushers silently lose one
  another's packs. A git backend can do a real compare-and-swap with
  `--force-with-lease`; rsync/sftp cannot, which is why gcrypt's "good" backend
  cannot fix this.
- Secondary: full repack of the whole history every 25 pushes (unnecessary on a
  git backend, where N small blobs cost one round trip), packs are not thin
  (a modified file is re-uploaded whole), GnuPG as the only crypto engine.

## 3. Architecture

```
  git  ──stdin/stdout──▶  git-remote-enc  ──git plumbing──▶  local repo ($GIT_DIR)
        (helper protocol)        │                              │
                                 │ age / ssh-key                │ git fetch / push
                                 ▼                              ▼
                        manifest, pack keys,           backend branch on the host
                        signatures (in memory)          (tree of opaque blobs)
```

Two crates:

- `enccore` — the library: `git` (plumbing wrappers), `manifest`, `crypto`,
  `backend` (git-hosted store), `state` (local per-remote state), `remote`
  (connect / list / fetch / push), `config`, `guard` (pre-push hook,
  section 6.7).
- `git-remote-enc` — the protocol loop and a `manifest` inspection subcommand.

All object-level work (pack generation, thin-pack completion, indexing,
transfer negotiation) is delegated to `git pack-objects`, `git index-pack`,
`git fetch` and `git push`. The helper never parses a pack beyond its 12-byte
header. This keeps the code small and guarantees that "what is transferred"
follows git's own reachability semantics.

## 4. On-remote format

### 4.1 Backend tree

The remote is one branch of a git repository (default `refs/heads/enc`,
overridable with a URL fragment: `enc::git@gitlab.com:g/r.git#mybranch`). Each
push appends exactly one commit, whose parent is the previous tip, with a fixed
anonymous author/committer/date. Its tree is flat:

```
manifest              age file: the encrypted, signed manifest
<sha256-hex>.age      age file: one encrypted git pack, per push
...
```

Blob names are the SHA-256 of the age ciphertext, so the manifest can bind a
pack line to exactly one blob. The tree only ever grows (a deleted ref keeps
its objects in earlier packs); section 7 discusses compaction.

Because the commits are chained, a fetch of the branch is a normal incremental
fetch, and a push is a normal incremental push. No object is ever transferred
twice in either direction.

### 4.2 Manifest

The manifest plaintext is UTF-8 text, one item per line, `\n`-terminated. Its
first line is the format tag. Version 2:

```
enc-manifest 2
generation 42
time 1790000000
repo 3f9c6e4d0b1a2c7e8d9f0a1b2c3d4e5f
head refs/heads/main
participant ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop
participant ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... bob@ci
participant age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
admin ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@laptop
ref 7f3a...c1 refs/heads/main
ref 91b2...4e refs/tags/v1.0
pack 5b0e...d7 AGE-SECRET-KEY-1QG5...
pack a3c1...20 AGE-SECRET-KEY-1K7W...
```

| item | meaning |
|---|---|
| `enc-manifest <n>` | format version; a reader refuses an unknown `n`. Readers accept 1 and 2 and write 2 |
| `generation <n>` | strictly increasing per push; anti-rollback (section 6.2) |
| `time <unix seconds>` | when the pusher wrote it, by the pusher's clock; for the audit trail only, never for trust decisions. New in version 2 |
| `repo <hex>` | random id chosen at creation; detects a recreated remote |
| `head <ref>` | what `HEAD` points to on clone (first pushed branch by default) |
| `participant <key>` | an `ssh-ed25519` public key (may read, may push) or an `age1…` recipient (read-only, cannot sign) |
| `admin <key>` | a participant (`ssh-ed25519`) who may change the `participant` and `admin` lists (section 6.1). New in version 2; a version 1 manifest has none |
| `ref <oid> <name>` | a git ref and its object id, as in `git ls-remote` |
| `pack <sha256> <age-secret-key>` | a pack blob and the X25519 identity that decrypts it, in append order |
| `extn <name> …` | reserved: unknown items are preserved verbatim by writers that do not understand them |

Pack lines are ordered: a pack may be *thin* relative to every pack before it,
so a reader indexes them in manifest order (section 5.2).

Version 1 had no `admin` item. The first push by a version 2 writer rewrites a
version 1 manifest as version 2 with an empty admin list, which older binaries
then refuse to read: every participant must upgrade.

### 4.3 Manifest envelope

```
plaintext  = manifest text
sig        = SSH signature over plaintext, namespace "git-remote-enc",
             hash sha512, PEM ("-----BEGIN SSH SIGNATURE-----")
envelope   = plaintext ‖ sig
blob       = age.Encrypt(recipients = all participants, envelope)
```

Sign-then-encrypt: the signer's identity is inside the ciphertext, so the host
cannot tell which participant pushed. The recipient stanzas in the age header
do reveal the *number* of participants and, for `ssh-*` recipients, a short
tag derived from the public key (this is inherent to age's ssh recipient
types). Public keys are routinely published, so that tag can name the
participants; section 6.4 has the consequence and the mitigation. An
`age1…` recipient stanza carries no key tag.

### 4.4 Pack blobs

Each push produces at most one pack:

```
pack       = git pack-objects --thin --stdout  (section 5.1)
key        = fresh X25519 identity
blob       = age.Encrypt(recipients = [key.public], pack)
name       = hex(sha256(blob)) ‖ ".age"
```

The per-pack identity goes in the manifest's `pack` line. Encrypting to a
throwaway X25519 key rather than using a raw symmetric key keeps every
ciphertext a standard age file (`age -d -i <key>` reads it), with age's own
chunked AEAD (64 KiB ChaCha20-Poly1305 STREAM), for the cost of one X25519
operation per pack.

## 5. Protocol

### 5.1 Push

Invoked by git as a batch of `push [+]<src>:<dst>` lines after `list
for-push`.

1. **Connect** (once per helper process): `git fetch -f <url>
   +<branch>:refs/enc/<state-key>`; a missing branch means a new remote. Read
   `manifest` from the tip's tree, decrypt with the local identities, split the
   envelope, verify the signature (section 6), parse.
2. **Ref checks**, for each refspec, in the helper (git does not do it reliably
   for helpers, section 2):
   - deletion (`:<dst>`): allowed;
   - `<dst>` unknown on the remote: create;
   - `<dst>` known, `+` or `--force`: update;
   - otherwise the old tip must exist locally (`error <dst> fetch first`) and
     be an ancestor of the new one (`error <dst> non-fast-forward`).
   Refs that fail are reported and skipped; the others proceed, as git does.
3. **Pack.** `git pack-objects --revs --thin --stdout` with stdin
   `<new oid>…` then `^<oid>` for every manifest ref whose object exists
   locally. Everything reachable from a manifest ref is on the remote, so the
   pack contains only new objects and may use deltas against remote objects
   (thin). An empty pack (object count 0 in the header) is not stored.
4. **Encrypt + hash** the pack stream into a temporary file under
   `<common>/enc/`, then `git hash-object -w` it.
5. **New manifest:** refs updated, pack line appended, `generation + 1`,
   participants unchanged (from config only when creating the remote, or for
   `git-remote-enc participants --apply`, section 6.3), `head` set if absent.
   Sign with the local signing key, encrypt to the participants.
6. **Commit:** tree = previous tree + pack blob + new `manifest`; `commit-tree
   -p <old tip>`.
7. **Compare-and-swap:** `git push <url> <commit>:<branch>
   --force-with-lease=<branch>:<old tip>` (empty old tip for a new remote:
   "must not exist"). On a stale lease someone pushed in between: go back to
   step 1 and redo everything (at most 3 attempts). Their pack is still valid;
   ours is rebuilt against the new manifest. The lease is checked by the
   client (`stale info`) and enforced again by the server (old value
   mismatch); any rejection after which the branch tip has moved is treated as
   a lost race, anything else as a hard error.
8. Move the tracking ref to the new commit, record the new pack as indexed
   locally (its objects are ours), report `ok <dst>` per ref.

The lease is what makes concurrent pushes safe: the manifest we replace is
provably the one we read, so no pack line can be lost.

**Git LFS.** LFS replaces tracked files by pointers and uploads their
content from its pre-push hook to a separate LFS server, usually the forge
named by the product's `.lfsconfig`. The helper sees only the pointers; the
files would leave in clear, with the push succeeding. git calls the helper's
`list for-push` before it runs the pre-push hook, so the helper refuses there
when `hooks/pre-push` (under `core.hooksPath` too) or a `hook.*.command`
invokes Git LFS, unless `enc-allowLfs` is set. Setting it is for a clone where
LFS was neutralized (`lfs.url` pointed at nothing in the local config, which
overrides `.lfsconfig`). Encrypting LFS objects into the backend, as a custom
LFS transfer agent, is not implemented.

### 5.2 Fetch

After `list`, git sends the `fetch <oid> <name>` lines it wants. The helper
ignores the individual wants and downloads every pack it has not indexed yet:

1. For each `pack` line in manifest order not present in the local `have`
   list: `git cat-file blob <blob oid>` (already in the local object store
   from the branch fetch) → age decrypt with the pack key → `git index-pack
   --stdin --fix-thin --fsck-objects` → append to `have`.
2. The SHA-256 of the ciphertext is checked against the pack name while
   streaming; a mismatch fails the fetch.

Order matters because `--fix-thin` completes a thin pack with base objects
that must already be present.

The packs reach the object store through `index-pack` run by the helper, not
through `git fetch`, which would otherwise be the one to check them. The
helper therefore checks every object as `fetch.fsckObjects` would (a tree
entry named `.git`, malformed objects), and does so by default, unlike git:
content from a remote everyone trusts is where a hostile object does the most
harm. `fetch.fsck.<msg-id>` severities and `fetch.fsck.skipList` apply;
`fetch.fsckObjects = false` (or `transfer.fsckObjects = false`) turns it off.

### 5.3 List

`list` and `list for-push` print `<oid> <ref>` for each manifest ref and
`@<head> HEAD`.

### 5.4 Local state

Per remote, keyed by `sha256(url ‖ branch)[..16]`, under the repository's
common directory (`git rev-parse --git-common-dir`: the main `.git`, shared by
every linked worktree, so trust accepted in one worktree holds in all):

- `refs/enc/<key>` — tracking ref for the backend branch. Its existence is
  what makes the next fetch/push incremental; it must not be deleted after a
  run.
- `<common>/enc/<key>/have` — pack names already indexed.
- `<common>/enc/<key>/trust` — the last accepted manifest's `generation`,
  `repo` id, participant list and the SHA-256 of its text (section 6), ending
  in `mac <key id> <tag>`: HMAC-SHA256 of the lines above, keyed by
  HMAC-SHA256(identity secret, "git-remote-enc local trust state v1") for the
  first configured identity (`key id` is its public fingerprint or age
  recipient). A file whose tag does not verify, or that has no tag line, is
  refused; so is state written by 0.1.0, which had none. The tag stops a
  rewrite by anything that lacks the private key; it does not stop someone who
  can write `.git` and simply runs code through a hook instead.
- `<common>/enc/<key>/tmp/` — temporary files for the pack pipeline.

The encrypted blobs live in the local object store (reachable from the
tracking ref) next to the decrypted objects, so a repository costs roughly
twice its size locally. This is the price of using git's transfer negotiation
and is accepted (section 7 lists a mitigation).

## 6. Trust model

### 6.1 Who may write

A manifest is accepted iff it is signed by a participant of the **previously
accepted** manifest. On first contact there is no previous manifest:

- if another remote of the same local repository has already accepted a
  manifest with this `repo` id (the same remote reached through a different
  URL spelling), that state applies, signer check and rollback check included;
- else if the local config names participants (`enc-participants`), the signer
  must be one of them;
- else the manifest is refused, and the error names the signer's fingerprint
  to confirm out of band. `enc.trustOnFirstUse = true` accepts it unverified
  (trust on first use) instead.

Without a pinned list, whoever controls the host on first contact chooses what
the new clone trusts: they cannot read an existing remote, but they can serve
a fabricated one, and anything pushed to it lands in a history they control.

A pinned list is not enough on its own: the host can still serve any manifest
a pinned key ever signed, an old generation of this remote (from before a
participant was removed, so the new clone re-encrypts to them) or another
remote with the same signer. `enc-repo` pins the `repo` id and
`enc-minGeneration` a floor for `generation`, both learned out of band with
the key; a manifest that does not match is refused, on first contact and
after. The first-contact message prints both values, and says when they were
not pinned.

After acceptance the participant list is stored locally, so:

- a participant may add or remove participants (including themselves);
- an attacker with write access to the hosting repository cannot inject a
  manifest: they can encrypt to us, but they cannot produce a signature by a
  trusted key;
- consequently a compromised host can at most **withhold** or **roll back**
  (6.2), never forge.

Any participant that can sign may push refs; only an **admin** may change who
participates. A manifest is accepted over the previous one only if either it
leaves the `participant` and `admin` lists unchanged (compared by key), or its
signer is an admin of the previous manifest; and once a remote has admins, a
manifest with none is refused. Every admin must be an `ssh-ed25519`
participant. A new remote's admins are `enc-admins` if configured, else its
creator. Writers enforce the same rules before pushing, so a refused change
never reaches the host.

A remote created before version 2 has no admins, and then any signing
participant may change the lists, as in version 1, with a warning;
`git-remote-enc participants --apply` with `enc-admins` set appoints them.
Read-only participants (`age1…` keys) cannot sign and therefore cannot push.

### 6.2 Rollback

`generation` is strictly increasing. A reader refuses a manifest whose
generation is lower than the last one it accepted, and warns when it is equal
but the content differs (compared by the SHA-256 of the manifest text kept in
the local state): two validly signed manifests with one generation mean the
history forked, because the host served different views or rewound the branch
under a pusher. A pusher always writes `previous + 1`; the lease
guarantees "previous" is the real tip.

### 6.3 Adding and removing participants

The participant and admin lists change only on request, by an admin
(section 6.1): `git-remote-enc participants <remote>` shows the remote's lists
and how the configured ones (`enc-participants`, `enc-admins`) differ, and
`--apply` pushes a manifest carrying the configured lists and no ref change.
An ordinary push keeps the remote's lists, so a clone with a stale or partial
configuration cannot drop someone as a side effect of an unrelated push.

Adding a reader is cheap: re-encrypt the manifest to the new set (the pack keys
are inside it, so all history becomes readable). Removing a participant
re-encrypts the manifest without them; every *future* pack key is then unknown
to them. Past pack keys were in manifests they could read, so past history
stays readable to them — this is inherent, and identical to gcrypt. Full
revocation means a fresh remote and a re-push (`git push --mirror`).

### 6.4 What the host learns

- **The backend branch name**, in clear: it is a ref on the host, and anyone
  who can read the hosting repository (`git ls-remote`) sees it, with the
  times its commits appeared. The name comes from the URL fragment (`#<name>`,
  default `enc`); a descriptive one (`embargo-CVE-2026-31337`) tells every
  reader of the host what is being worked on and since when. Use a neutral
  name, or one opaque remote per audience with the default name.
- Number and size of packs, timing, pushing account (transport layer).
- Number of participants (age recipient stanzas), and for `ssh-*` recipients a
  4-byte tag derived from the public key. That tag identifies the key to
  anyone who holds the public key, and public keys are not secret: forges
  publish every user's SSH keys without authentication
  (`https://<forge>/<user>.keys`). Whoever collects the published keys of an
  organisation can therefore tell which of those keys each manifest is
  encrypted to, i.e. who participates. Where membership itself is sensitive,
  use participant keys that are not published anywhere (a dedicated
  `ssh-ed25519` key per remote, not the key registered with the forge) or
  `age1…` recipients, whose stanzas carry no key tag.
- Nothing about refs, object ids, commit metadata, file names, or who signed.

### 6.5 Key material on the client

Identities are OpenSSH private keys (`ssh-ed25519`; passphrase
protected keys are decrypted with a prompt on `/dev/tty`) or age identity
files. ssh-agent cannot be used for decryption: X25519 key agreement is not an
agent operation. The same SSH key signs; signing therefore also uses the key
file, not the agent. Hardware-backed keys are not supported in v1.

In memory, the decrypted manifest, every pack key, the key passphrase and the
key derived for the local trust state are wiped when dropped (`zeroize`); the
private keys themselves are wiped by age and ssh-key. Pages are not locked
(`mlock`), so a secret can still reach swap or a core dump while it is live:
run with encrypted swap and core dumps disabled where that matters.

### 6.6 Audit trail

The backend commits are anonymous and undated by design (section 4.1), so the
audit trail lives inside the encrypted history instead: every manifest names
its signer through its signature and carries its `time`, and the backend
branch keeps every past manifest. `git-remote-enc log <remote>` walks the
branch and prints, per generation, the signer, the time, and the ref,
participant and admin changes. Manifests from before one's own key was added
are not readable and are listed as such. `time` is self-asserted by the pusher.

The host controls that branch and can rewrite it, e.g. squash past commits
into one, without touching the current manifest. Two checks surface it:
connect warns when the new tip does not descend from the tip fetched before
(the forced fetch leaves the old one in the object store), and `log` reports
every place where the generations stop following the commits one for one
(each push adds one commit and one generation), printing which generation a
manifest's changes are relative to when that is not the one just before. Both
detect a rewrite; neither restores what it removed. Protecting the branch on
the host against force pushes, and keeping the host's push log, does.

### 6.7 Publishing by mistake

Encryption ends at `$GIT_DIR`: a clone that knows both an encrypted remote
and a plain one holds the decrypted commits of the first and can push them to
the second with one command. `git-remote-enc install-hook` writes a pre-push
hook running `git-remote-enc pre-push <remote> <url>`, which refuses a push
that carries content of an encrypted remote the destination does not already
have. "The encrypted remote" is every other remote with an `enc::` URL: its
remote-tracking refs, and the local branches whose upstream it is (they hold
fix commits not pushed yet). "Already has" is the destination's
remote-tracking refs and the old values of the pushed refs.

The test is on content, not history, since backporting a fix by cherry-pick
or squash creates commits the encrypted remote never had. A push is refused
when the objects it would send (commits, trees, blobs; the empty blob and
tree aside) share one with the objects only the encrypted remote has, which
catches a fixed file carried over unchanged; or when one of its commits has
the patch id (`git patch-id --stable`) of an encrypted-only commit, which
catches the same change applied to a diverged file. Any git failure while
checking refuses the push. A change rewritten by hand, or squashed together
with other edits to the same files onto a diverged base, matches neither.

git chooses the transport from the push URL, so `remote.<name>.pushurl`, or
a `url.<base>.pushInsteadOf` (or `insteadOf`) rule, can send pushes to an
`enc::` remote in clear, to a plain URL, without running the helper. The
guard refuses a push whose remote is configured with an `enc::` URL when the
URL git actually pushes to is not one. The helper cannot see such a push,
but it refuses every other use of that remote (fetch, the subcommands) while
its push URL resolves to a plain one.

Pushing to another encrypted remote is checked the same way, since its
audience differs. The disclosure itself is a deliberate `git push
--no-verify`; once the fix is public and fetched, the guard no longer
matches it. The hook only covers clones where it is installed, and content
that reaches no encrypted ref (a fix written but never pushed to or branched
from the encrypted remote) is invisible to it.

### 6.8 Threat model

**Assets.** The repository's contents and history; its ref names and commit
metadata; the participant and admin lists; the pack keys (which decrypt the
whole history); the participants' private keys; and the integrity of the refs
participants fetch and build on.

**Actors.** Participants: admins, signing participants and `age1…` readers. A
participant removed from the list. The host operator, and anyone with write
access to the hosting repository. Anyone with read access to it. A network
attacker between client and host. A local attacker on a participant's
machine.

**Trust boundaries and data flows.**

```
  participant's machine (trusted)                  │  host (trusted for availability only)
                                                   │
  private keys ───┐                                │
  .git/config ────┼──▶ git-remote-enc ── push ─────┼──▶ backend branch: the signed,
  (participants,  │      │       ▲                 │    encrypted manifest and the
   admins)        │      ▼       └──── fetch ◀─────┼─── encrypted packs (its name and
                  │   $GIT_DIR: decrypted objects, │    the blob sizes are visible)
                  │   trust state (authenticated)  │
                                                   │
  out of band: the other participants' public keys and fingerprints (first contact)
```

The host is trusted for availability only: not to read, not to change what
it stores, not to serve the same view to everyone. The participant's machine
is trusted with everything: private keys, plaintext objects and the local
trust state. The first contact relies on a channel outside both, through
which a participant learns another's public key (and, to bound a rollback or
substitution, the repository id and generation). Git LFS, when a repository
uses it, is a second flow from the machine to the host that does not go
through the helper at all (5.1).

| Threat | Mitigation | Residual risk |
|---|---|---|
| The host or a host reader reads the repository | age encryption of manifest and packs (4.3, 4.4) | the metadata of section 6.4: branch name, sizes, timing, participant count, key tags |
| The host forges refs or a manifest | a manifest is accepted only when signed by a previously accepted participant (6.1) | none once a manifest has been accepted |
| The host rolls the branch back | strictly increasing `generation`, checked against local state (6.2), or against `enc-minGeneration` on first contact (6.1) | a host can withhold new pushes from a client that never saw them (freeze); a first contact without `enc-minGeneration` accepts any generation its pinned signer signed |
| The host serves different views to different clients | a changed manifest for an accepted generation is reported (6.2) | detected only by a client that sees both views |
| The host substitutes its own remote on first contact | first contact needs a pinned participant list; `enc-repo` pins the repository; repo id lookup across URL spellings (6.1) | `enc.trustOnFirstUse = true` reopens it, by choice, and set in the global config it does so for every remote; without `enc-repo`, another remote signed by a pinned key passes |
| The host deletes or recreates the branch | refused; `forget` needs a human decision (section 9) | availability: protect the branch on the host and keep a mirror; deletion stops work until restored |
| A participant changes who participates | only admins change the lists; a push never does it implicitly (6.1, 6.3) | a remote from before format 2 has no admins until appointed; admins are fully trusted |
| A participant rewrites or deletes refs | every change is signed and kept in the backend history (`log`, 6.6) | no per-ref permission: one remote per audience (section 1) |
| The host rewrites the backend history, erasing the audit trail | a tip that does not descend from the last one seen is reported; `log` flags missing generations (6.6) | the removed manifests are gone unless the branch is protected on the host or mirrored; a first contact after the rewrite gets no warning, only `log`'s |
| A removed participant reads the past | future pack keys are unknown to them (6.3) | they keep the past history; full revocation is a new remote |
| A participant's private key is compromised | passphrase on the key; admins remove the key | the whole readable history is exposed, permanently; no hardware or agent-held keys (6.5) |
| A local attacker rewrites the trust state | HMAC keyed from the user's identity; a file with a wrong or missing tag, or missing while the tracking ref exists, is refused (5.4, section 9) | stops tampering without code execution (a restored backup, a synced or shared directory); whoever can write `.git` can run code through hooks instead |
| A participant pushes a hostile git object (a `.git` tree entry) | received objects are fsck-checked by default (5.2) | none with the default; `fetch.fsckObjects = false` disables it |
| A crafted `enc::` URL runs a command | the URL goes to git after `--`, and a leading `-` is refused | none known |
| Secrets leak through tooling | pack keys redacted by default; no passphrase from the environment; secrets wiped from memory (6.5) | swap and core dumps while a secret is live |
| git config reroutes pushes to an encrypted remote to a plain URL (`pushurl`, `pushInsteadOf`) | the pre-push guard refuses it; the helper refuses to fetch from such a remote (6.7) | a clone without the guard pushes in clear; an `insteadOf` that rewrites the fetch URL too never runs the helper at all |
| Git LFS uploads tracked files in clear alongside a push | a push is refused while a pre-push hook runs Git LFS (5.1) | `enc-allowLfs` with LFS still pointed at the forge; an LFS invocation the check does not recognise (a hook manager that calls it indirectly) |
| Plaintext leaks through the developer's workflow | `install-hook`: a pre-push hook refuses to push content of an encrypted remote (shared objects, or a cherry-picked change by patch id) to any other remote (6.7) | clones without the hook, `--no-verify`, content not yet tied to an encrypted ref, a fix rewritten by hand or squashed with other edits onto a diverged base; the decrypted objects live in the local `$GIT_DIR` (5.4): use a dedicated clone, disk encryption, and delete the clone when done |
| A malicious or compromised build | reproducible builds from pinned inputs, SHA-pinned actions, Sigstore-signed provenance and an SBOM per release, `cargo audit` and `cargo deny` in CI | the build image runs Nix with `sandbox = false`; dependencies include a pre-release crate (`kem`) and an unfixed but unreachable one (`rsa`, RUSTSEC-2023-0071) |
| A parser bug on untrusted input | Rust with panics denied by lint; the signature is checked before parsing when a signer list is known; mutation tests of every parser (section 10) | no coverage-guided fuzzing; trust on first use parses unauthenticated text |
| Traffic analysis | none (non-goal, section 1) | the host sees who pushes and fetches, when, and how much |

## 7. Performance and growth

- Push cost: `pack-objects` over new objects + one age encryption + one
  incremental `git push`. Fetch cost symmetric. Independent of history length.
- The backend tree grows by one blob per push; git handles trees with tens of
  thousands of entries fine, but a very active repository may want
  **compaction**: download all packs, `git pack-objects` the union into one,
  encrypt, write a new manifest listing only that pack, and drop the old blobs
  from the tree. Old blobs remain in the host's history (branch history is
  never rewritten) — a `git push --force` of an orphaned commit plus host-side
  GC would reclaim them. Compaction is an explicit subcommand, never
  automatic, so a push never surprises the user with a full re-upload.
- Local 2× storage: `git fetch --filter=blob:none` of the backend branch and
  fetching pack blobs on demand would remove it on hosts that support partial
  clone (GitLab does). Deferred until the simple design has been used in
  anger.
- Thin packs give cross-push deltas for modified files. Unlike gcrypt, a
  100-byte change to a 1 MB file costs roughly the delta, not 1 MB.

## 8. Configuration

| key | meaning |
|---|---|
| `remote.<name>.enc-identity`, `enc.identity` (multi) | identity files. Default: `user.signingkey` when `gpg.format = ssh` and it is a path, else `~/.ssh/id_ed25519` |
| `remote.<name>.enc-signingkey`, `enc.signingkey` | SSH private key used to sign. Default: the first SSH identity |
| `remote.<name>.enc-participants`, `enc.participants` (multi) | public keys, one per value, or `@<file>` (authorized_keys-style). Required to create a remote; on first contact with an existing remote, the signer must be one of them; on an existing remote a push never applies it (it warns when it differs); `git-remote-enc participants --apply` does (section 6.3) |
| `remote.<name>.enc-admins`, `enc.admins` (multi) | like `enc-participants`, for the admin list: the admins of a new remote (default: its creator), or the list `participants --apply` sets (section 6.1) |
| `remote.<name>.enc-trustOnFirstUse`, `enc.trustOnFirstUse` | boolean, default false. Accept the signer of an unknown remote without a pinned participant list (section 6.1) |
| `remote.<name>.enc-repo`, `enc.repo` | the `repo` id the remote must serve (section 6.1) |
| `remote.<name>.enc-minGeneration`, `enc.minGeneration` | the lowest `generation` accepted (section 6.1) |
| `remote.<name>.enc-allowLfs`, `enc.allowLfs` | boolean, default false. Push although a pre-push hook runs Git LFS (section 5.1) |
| `fetch.fsckObjects`, `transfer.fsckObjects`, `fetch.fsck.*` | git's own keys; received objects are checked unless one of the first two is false (section 5.2) |

URL: `enc::<any git url>[#<branch>]`. Everything after `enc::` is handed to
git verbatim, so ssh aliases, `https://token@…`, insteadOf rewrites and
credential helpers all work.

## 9. Failure modes and recovery

- **Push interrupted after step 7:** the host has the new commit, the local
  tracking ref is stale. The next connect fetches and reconciles; the pack is
  re-indexed from the blob (its objects are already local, `index-pack` is
  idempotent).
- **Push interrupted before step 7:** nothing on the host changed; the temp
  file is removed by a later run once it is a day old (a younger one may
  belong to a helper still running on the same remote).
- **Repo id changed, or the backend branch vanished:** the remote was
  recreated or deleted, or the host is replacing it. The helper refuses: silently
  accepting would defeat the anti-rollback and trust chain. Recovery is a
  decision for the participants, taken out of band: once they confirm the
  change, `git-remote-enc forget <remote>` removes the local state and the
  tracking ref, and the next contact is a first contact, which needs a pinned
  participant list (section 6.1).
- **Local trust state missing or altered:** the trust file is gone while the
  tracking ref shows a manifest was accepted, or its tag is missing or does
  not verify. The helper refuses rather than falling back to a first contact;
  recovery is the same `forget`.
- **Not a participant:** age reports no matching key; the helper says so and
  names the identities it tried.
- **Stale lease three times:** give up with a clear message; the user retries.

## 10. Testing

Black-box tests (`crates/git-remote-enc/tests/e2e.rs`) run the real binary
through git against a local bare repository as the "host", with generated
ed25519 keys:

- init, push, clone, fetch round trip; contents identical;
- incremental transfer: bytes received by the host per push are bounded by the
  new objects (asserted via `transfer.unpackLimit=1` and pack sizes);
- non-fast-forward rejected without `--force`, accepted with it;
- concurrent push: a stale lease is retried and no pack is lost;
- a key that is not a participant cannot read; a `age1…` reader can read but
  cannot push; a manifest signed by a non-participant is rejected;
- rollback of the backend branch to an older tip is refused, and so is an
  older or substituted manifest on a first contact pinned with `enc-repo` and
  `enc-minGeneration`;
- a backend history rewritten by the host is reported by fetch and `log`;
- a tampered trust file, with or without its tag line, is refused;
- a hostile object (a `.git` tree entry) is refused on fetch;
- a push is refused, before the hook runs, while a pre-push hook runs Git
  LFS;
- the pre-push guard refuses to publish commits of an encrypted remote.

Unit tests cover manifest parsing/serialization, refspec parsing and the trust
rules. Every parser of untrusted input (manifest, envelope, refspec,
participant keys, SSH signatures, the local trust file) also gets thousands
of deterministic mutations of a valid input (`enccore/src/mutate.rs`: bit
flips, insertions, deletions, truncation, duplicated and dropped lines) and
must return an error or a consistent value, never panic. This stands in for
coverage-guided fuzzing, which needs a nightly toolchain the pinned one does
not provide.

## 11. Credits

- Cyrille Mucchietto — security design review
