# UNRELEASED

## `http-semantics` — RFC 9110 §11's six authentication fields, and two bounds that refuse rather than truncate

An `auth` module joins the crate: §11.2's `auth-param` and `token68`, and the
one production §11.3 spells `challenge` and §11.4 spells `credentials`, over
the six fields §11.6 and §11.7 define between them. Before this, a caller
handed a 401 or a CONNECT 407 could hold `WWW-Authenticate`'s bytes and do
nothing with them: the walk existed nowhere in this workspace, and
`http1-proto`'s README listed §11.3's challenge walk among the work nobody here
had done. That caller can now select a challenge by its scheme and read that
challenge's parameters to the last one, without allocating and without this
crate implementing any scheme. Phase 1 of the #70 ledger.

`xtask/snapshots/http-semantics-documented.txt` gains 120 lines and loses none:
`grep -vc '^#'` counts 572 documented items on it at `6360957` and 692 here.
`cargo test -p http-semantics --all-features` reports 379 unit tests passing, 81
of them this module's, beside the no-panic harness's fifteen and one doctest.
The crate is still `no_std`, allocation-free, clock-free and panic-free, on the
same `std` / `alloc` / `no-atomic` tiers its siblings run, and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

### Added

- **`auth` — one production, reached by three entry points that differ only in
  how many of it a field holds.**

  ```rust
  pub fn challenges<'a, I>(lines: I) -> impl Iterator<Item = Result<Credential<'a>, AuthError>>
  where I: IntoIterator<Item = &'a [u8]>;

  pub fn credentials(value: &[u8]) -> Result<Credential<'_>, AuthError>;

  pub fn auth_info<'a, I>(lines: I) -> impl Iterator<Item = Result<AuthParam<'a>, AuthError>>
  where I: IntoIterator<Item = &'a [u8]>;

  impl<'a> Credential<'a> {
    pub const fn scheme(&self) -> &'a [u8];
    pub fn scheme_is(&self, name: &str) -> bool;
    pub const fn token68(&self) -> Option<&'a [u8]>;
    pub const fn params(&self) -> AuthParamIter<'a>;
  }

  impl<'a> AuthParam<'a> {
    pub const fn name(&self) -> &'a [u8];
    pub fn value(&self) -> Result<ParamValue<'a>, ValueSpansFieldLines>;
  }
  ```

  `challenges` reads §11.6.1's `WWW-Authenticate` and §11.7.1's
  `Proxy-Authenticate`, the two fields whose value is a list of challenges;
  `credentials` reads §11.6.2's `Authorization` and §11.7.2's
  `Proxy-Authorization`, which hold exactly one; `auth_info` reads §11.6.3's
  `Authentication-Info` and §11.7.3's `Proxy-Authentication-Info`, which are a
  parameter list with no scheme in front of it. One `Credential` type serves the
  first two because `challenge` and `credentials` are the same production
  written twice.

  **Two of the three take field LINES rather than a value, because a challenge
  is not always one field line.** RFC 9110 §5.2 makes a repeated field one
  value, its field line values "concatenated in order, with each field line
  value separated by a comma", so a sender may split one challenge's parameter
  list at any element boundary in it and the pieces arrive as separate lines. A
  reader that borrows rather than joining has to name every line one challenge
  landed on at once, which is what `Credential` does and what
  `MAX_CHALLENGE_LINES` bounds. The one thing a join can still take away is a
  single value's contiguity: a `quoted-string` that opens on one line and closes
  on the next is reported at `AuthParam::value` as `ValueSpansFieldLines`, and
  the parameter's own name is answered anyway. Closing is not ending, though —
  `auth-param = token BWS "=" BWS ( token / quoted-string )` takes one
  alternative whole, so only the `OWS` §5.6.1.2 hangs on the next comma may
  follow that close, and `Basic realm="x` followed by `"junk` is
  `AuthError::MalformedParameter` exactly as the same bytes written on one line
  already were. A run behind such a close derives nothing, so it holds no
  `quoted-string` for a DQUOTE in it to open: the element ends at the first RAW
  comma in that run, and a malformed challenge cannot swallow the comma in
  front of the next one. The walk that gets PAST an already-reported challenge
  reads the same way, for the same reason.

  **The whole of that rule, at both of its scopes: only bytes some production
  still admits may decide where anything ends.** Within one element, a DQUOTE
  opens a `quoted-string` only at the position §11.2 admits a value, and the
  string that opens there closes the last thing the element may hold. Within a
  `#challenge` value, the moment an element derives nothing, repeats a name,
  fills the last slot there is, or takes the challenge past
  `MAX_CHALLENGE_LINES`, **that challenge is refused and the rest of its extent
  is found by raw commas alone** — so `Basic a="q` followed by
  `r"junk, trap="open, Digest realm=z` reports one `MalformedParameter` and
  still yields `Digest`, where a walk that found the boundary first and derived
  the body afterwards let `trap="` swallow the comma in front of it. Deriving
  each element before the next element's bytes are read is what makes that
  true, and the `auth` module's own documentation states it as the invariant a
  change there has to keep.

  **One derivation of an element's boundary, and every walk in the module gets
  its elements from it.** The walk that cuts a challenge's body and the walk a
  caller reads that challenge's parameters through are the same function over
  the same bytes: a region is kept as the field line the collecting walk read,
  from the credential's first byte on it, and where the credential stops is
  that walk's own cursor recorded rather than a second reading of the same
  bytes. A disagreement between the two would have dropped a parameter from a
  challenge that parsed and reported nothing, and there is now nothing for them
  to disagree about.

  **A malformed value can yield more faults than a sender wrote, and that is
  the safe direction.** Getting past a refused challenge is done by raw commas,
  so a comma a quote-aware recovery would have swallowed as data ends the
  refused run here and what stands behind it is refused in its turn:
  `Basic<HTAB>Newauth realm="a, b"` is two `AuthError::MalformedScheme`s where
  such a recovery reports one. No challenge is ever lost by it and every `Ok` is
  the same `Ok`, but a caller counting the `Err`s of a malformed value is
  counting something this reader decides. `challenges` says so where a caller
  reads what it yields.

  **Which of RFC 9110 §11.2's two alternatives a body took is a recipient's
  decision, and this module writes its own down.** §11.2 says in prose that a
  scheme is followed by "either a comma-separated list of parameters or a single
  sequence of characters capable of holding base64-encoded information", and
  nothing in
  `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]` orders the two.
  `Credential::token68` reports the answer this module reached: the run is a
  `token68` when it matches that production AND ends the credential, so
  `Scheme foo=` is a `token68` rather than a parameter missing its value, while
  `Scheme foo=bar` is one parameter.

  **Validation is eager, which is what makes `AuthParamIter` infallible.** A
  challenge is walked to its end before it is yielded, so `Credential::params`
  cannot fail and one `challenges` walk can go on after a fault — RFC 9110
  §11.4 has a user agent choose by "selecting the challenge with what it
  considers to be the most secure auth-scheme that it understands", and a list a
  caller searches must not let one unreadable challenge hide the readable one
  behind it. A
  parameter list is not searched that way: `auth_info` reports its fault and
  ends, as `grammar::parameterised_list` already does.

  **RFC 9110 §11.2's one-name-once MUST is checked, per parameter list.**
  "Authentication parameters are name/value pairs, where the name token is
  matched case-insensitively and each parameter name MUST only occur once per
  challenge", so `realm` repeated as `Realm` is `AuthError::DuplicateParameter`.
  Applying it across a whole `#challenge` value instead would refuse the RFC's
  own §11.6.1 example, which carries `realm` in both of its challenges — that
  example is a test here, asserted challenge by challenge and parameter by
  parameter.

- **`MAX_CHALLENGE_LINES` and `MAX_PARAMS_PER_CREDENTIAL`, both sixteen, and both a
  refusal rather than a cap.** Each can refuse input the grammar allows, and
  each says so at its own definition rather than leaving a caller to find out.

  A challenge spread over a seventeenth field line is
  `AuthError::ChallengeSpansTooManyLines` and not the first sixteen lines of
  one: a challenge is chosen by its scheme and answered with its parameters, so
  part of one is not a smaller answer but a wrong one. A seventeenth distinct
  parameter name is `AuthError::TooManyParameters` and not a list read with the
  MUST left unchecked past the last name that fit, which is the alternative and
  is worse than a refusal rather than merely different: a walk that stopped
  CHECKING at its last slot would hand back a list it never established was
  duplicate-free. `validator::MAX_TAGS` already made that trade in this crate
  and is named in the same words at both constants.

  Neither counts what RFC 9110 §5.6.1.2 excuses — "Empty elements do not
  contribute to the count of elements present." — so a comma flood spends no
  slot, and a `token68` credential spends none either, holding no name that
  could repeat. The numbers are the storage: a slot is a `&[u8]`, so sixteen of
  them is 256 bytes on a 64-bit target, which with the two `usize`s beside the
  array is what puts `Credential` at 304. Both are parse-constants rather than
  knobs — the storage is in the binary, so a caller cannot raise them.

- **Five leaves join the crate's `no-panic` link proof**, one per entry point
  plus the `auth-param` parser and the `token68` scanner, each proven
  non-vacuous by injecting a reachable panic and reading which shims the link
  then names. Two omissions are written at the shim site rather than left to be
  inferred: no shim covers a `Display` impl, and the two generic walks are
  proven for the one monomorphization the test instantiates.

### What this cycle does NOT do

- **No authentication scheme, because RFC 9110 defines none.** §11.1: "Aside
  from the general framework, this document does not specify any authentication
  schemes." Basic and Digest are RFC 7617 and RFC 7616, and neither is here.
  Nothing in this module computes a credential, verifies one, or decides whether
  a challenge should be answered — `scheme_is` compares the scheme token
  case-insensitively and that is the whole of what it knows about schemes.

- **`realm` is a parameter like any other, and there is no `Realm` type.** §11.5
  assigns the protection-space comparison to the scheme, and this crate
  implements no scheme, so two challenges with the same scheme and different
  realms are two `Credential`s and nothing merges them. §11.5's own two
  sentences about `realm`'s syntax bind a sender or are permissive to a
  recipient; what licenses reading `realm=x` here is RFC 9110 §11.2's production
  plus its reason, that scheme definitions "need to accept both notations, both
  for senders and recipients, to allow recipients to use generic parsing
  components regardless of the authentication scheme", which is precisely what
  this is.

- **Nothing here honours §11.6.3's trailer sentence, and nothing here needs to.**
  `auth_info` takes field lines and takes nothing else — no section reaches it,
  so no branch in it can turn on one, and a trailer section's lines are read
  identically to a header section's by construction rather than by a check that
  could be got wrong. Whether the scheme allows the field there is the caller's.

- **No caller is wired to it yet.** `http1-proto` re-exports `grammar` and
  `media` from this crate and nothing else, so a driver reaches `auth` by naming
  `http-semantics` in its own manifest and handing it the field values a
  `HeadView` walked out. That crate's README said §11.3's challenge walk was
  work nobody had done, three lines after saying the neighbouring derivations
  were computed there; both sentences are rewritten to the true state, which is
  unwired rather than unreachable, and §11.3 is no longer listed as missing.

## A fifth gate whose green was narrower than its name, and a vocabulary that is not closed

### Tooling

- **`doc-check` lints intra-doc links on PRIVATE items now, across the whole
  workspace.** The workspace already denies `rustdoc::broken_intra_doc_links`:
  CI's doc job runs `cargo doc --workspace --all-features --no-deps` under
  `RUSTDOCFLAGS: --cfg docsrs -Dwarnings`. But `cargo doc` documents no private
  item, and rustdoc resolves links only in the items it documents, so that
  denial covered the public surface and nothing else — while
  `http-semantics/src/range/multipart.rs`, where the defect was found, is
  almost entirely private.

  Measured both ways, on the exact input that motivated this. Put a dangling
  `[is_mechanism]` back on the private `is_mime_token` and the CI doc step
  above exits 0; the new check exits 1 naming
  `http-semantics/src/range/multipart.rs:2281:7: unresolved intra-doc link to
  is_mechanism`. It was only ever seen at all because an ambient
  `RUSTDOCFLAGS` leaked into `doc-continuity`'s own `--document-private-items`
  pass.

  **Turning it on found sixteen dangling links, in five of the nine workspace
  crates** — `wren-reactor` 6, `http3-proto` 4, `websocket-proto` 3,
  `http1-proto` 2, `http-semantics` 1 — every one of them on an item `cargo
  doc` does not document. All sixteen are fixed in this commit; the gate is
  green over the workspace, so nothing is left on a backlog.

  **Not folded into `doc-continuity`'s pass, which already carries
  `--document-private-items`.** That was the cheaper place and the wrong one:
  it iterates `GATED_CRATES`, which holds three of the sixteen and none of the
  other thirteen; it needs nightly and SKIPS without it, so the stable docs
  workflow would carry none of it; and its failure arm says *the crate most
  likely does not build*, which is true of a build failure and false of a lint
  — one exit code standing for two facts, which is the shape this command
  exists to remove. The new check takes no crate list at all: `--workspace` is
  a set no edit to `xtask` can narrow.

  **One lint, named, rather than `-Dwarnings`.** Run the same pass with
  `RUSTDOCFLAGS` set to `-W rustdoc::all` and `redundant_explicit_link` warns twelve
  times, plus one `missing_crate_level_docs`; each is its own backlog with its
  own argument, and a green run here says exactly one thing. The VERDICT is
  cargo's exit status alone — rustdoc's wording is read only to NAME the sites,
  so a reworded diagnostic costs the per-site messages and can never turn a
  failure into a pass.

### `http-semantics`

- **BREAKING (unreleased): `PartEncoding` is `#[non_exhaustive]`.** It gained a
  variant twice already — `Undecoded`, when a mechanism this
  crate can name but does not perform stopped being a malformed body, and
  `Unrecognised`, when RFC 2045 §6.4's `application/octet-stream` fallback
  stopped being a refusal — and each would have broken a downstream exhaustive
  `match` on what is otherwise a bug-fix release. The enum is not RFC 2045
  §6.1's five mechanism names, which ARE a closed list; it is the set of
  distinct readings a receiver owes a part's `Content-Transfer-Encoding`, and
  §6.3 leaves the vocabulary those readings range over open at both ends —
  standardised names arrive by standards-track RFC, private ones by an
  `x-token` needing nobody's permission. The type's doc names what would close
  it: a snapshot of that vocabulary which this crate tracks and updates.

  Nothing inside the crate needed a wildcard arm — `#[non_exhaustive]` binds a
  downstream `match` only, and the two `match`es here stay exhaustive as
  written. Construction is untouched: the variants stay public.

## `http-semantics` — conditional requests, Range, and the equalities that compared spellings

RFC 9110 §8.8's validators, §13's conditional requests and §14's range requests
join the §5.6 field grammar, the §8.3.1/§12 media machinery and the §5.6.7
`HTTP-date` this crate already held, and `http1-proto`'s status vocabulary moves
in beside them. Four modules arrive — `conditional`, `validator`, `range` and
`status` — and the one that moved is re-exported under its old name, so no call
site changed.

`xtask/snapshots/http-semantics-documented.txt` gains 378 lines and loses none:
`grep -vc '^#'` counts 194 documented items on it at `fc30179` and 572 here.
`cargo test -p http-semantics --all-features` reports 298 unit tests passing,
beside the no-panic harness's ten and one doctest. The crate is still
`no_std`, allocation-free, clock-free and panic-free, on the same `std` /
`alloc` / `no-atomic` tiers its siblings run.

### Added

- **`conditional` — RFC 9110 §13's five conditional fields and §14.2's `Range`,
  accumulated one field at a time and settled only once the walk is over.**

  ```rust
  impl<'a> Preconditions<'a> {
    pub const fn new(now_unix_seconds: i64) -> Self;
    pub fn push(&mut self, name: &[u8], value: &'a [u8]);
    pub const fn refusal(&self) -> Option<PreconditionRefusal>;
    pub fn evaluate(&self, selected: &Selected<'_>, method: Method, recipient: Recipient) -> Verdict;
  }
  ```

  `push` reports nothing, and that is §13.2.2's order rather than a taste for
  accumulators. That algorithm reaches `If-Unmodified-Since` only "When
  recipient is the origin server, If-Match is not present, and
  If-Unmodified-Since is present", so whether one field's step runs at all turns
  on a field that may still be several lines away: nothing can be committed
  while the header section is still arriving, and a walk over one should not
  branch per line. `grammar::Expectations::push` has the same signature for the
  same reason. What a value could not settle is read back afterwards, through
  `refusal`, `range_ignored` or a `DateField`.

  **A date field has three states, because ignoring and failing are different
  answers.** RFC 9110 §13.1.3 and §13.1.4 each MUST-ignore their field for
  several reasons and do not agree on how many — four and three, the whole
  difference being that only `If-Modified-Since` carries a rule about the
  request method — and exactly one of those reasons is a fact about the VALUE.
  So a value is `Usable`, `PresentUnusable` or `Absent`: the sibling entity-tag
  field, the method, and whether the resource has a modification date at all are
  the evaluation's, and an `If-Unmodified-Since` against a representation with
  no `Last-Modified` SKIPS its step rather than failing it. A value carrying two
  dates needs no rule of its own, §13.1.4 having folded it into the same one —
  "A recipient MUST ignore the If-Unmodified-Since header field if the received
  field value is not a valid HTTP-date (including when the field value appears
  to be a list of dates)" — and none of §5.6.7's three formats can absorb the
  extra bytes anyway.

  **Two fields refuse an unreadable value and three do not, and only the first
  pair departs from the RFC.** The two entity-tag lists guard against lost
  updates, and a guard the recipient quietly dropped is the failure they exist
  to prevent, so a value neither list can read stops the request through
  `refusal`. That is a departure taken deliberately rather than a gap in the
  specification: RFC 9110 §13.1.1's and §13.1.2's evaluation lists each close
  with a total step, so the RFC does have an answer, and this crate declines it.
  `If-Range` does not refuse, because §13.1.5 makes it the opposite of a
  lost-update guard — a value neither of its forms reads makes the condition
  false, which costs a 200, the field's own designed degraded mode, where
  refusing would answer with the 412 the field exists to avoid. `Range` does not
  either, on §14.2's outright "A server MAY ignore the Range header field.", and
  `range_ignored` is what says the field was there at all.

  **`evaluate` runs §13.2.2's six steps behind the two of §13.2.1's three
  exclusion rules a recipient can decide from what it holds.** Every outcome the
  algorithm names has a `Verdict` variant — ten of them, which
  `grep '^http_semantics::conditional::Verdict::' xtask/snapshots/http-semantics-documented.txt | grep -v '\.'`
  lists — so a caller matches once rather than reading a cause and re-deriving a
  code from prose. The third exclusion rule is not this crate's and cannot be:
  "A server MUST ignore all received preconditions if its response to the same
  request without those conditions, prior to processing the request content,
  would have been a status code other than a 2xx (Successful) or 412
  (Precondition Failed)." A caller that has already settled on a redirect or a
  failure must not call this at all.

  Three rules each read as unconditional and one request satisfies all three — a
  malformed `If-Match` on an OPTIONS request at a proxy — so the order between
  them is written down rather than derived. `Recipient::Forwarding` answers
  first, because §13.2.1 states the forward MUST NOT unconditionally and only
  then attaches the method rule with *Likewise*, and because `Verdict::Proceed`
  promises no forwarding: answering it there would license a proxy to drop
  fields it MUST forward. `Method::NoRepresentation` is next and does answer
  `Proceed`, since to ignore every conditional field is to act as if none
  arrived. A refusal ranks below both, being this crate's own departure rather
  than one of the RFC's, and a departure cannot displace a MUST.

  **A refusal is then answered INSIDE the step that consults its field, not
  ahead of the algorithm.** Dispatching it up front saw only the recipient
  gates, and §13.2.2's steps are also a control flow: step 1 answering 412 for a
  false `If-Match` ENDS the run, and step 3 sits downstream of that answer, so a
  malformed `If-None-Match` beside a false `If-Match` is a field the evaluation
  never consulted. Six candidate wirings were built and run against this
  module's own cells; the one those cells were blind to is a refusal placed
  between the gates and step 1 with each field gated as its own step is, because
  such a refusal crosses no recipient gate and so reds nothing about recipients.
  `a_refusal_at_step_3_does_not_displace_the_step_that_terminated_first` is the
  cell that was missing, and it is that wiring's sole witness.

  **Step 5 answers 416 where the step's own *otherwise* reads 200, and the site
  records that as a choice rather than a derivation.** Nothing above it
  satisfied step 5's first bullet, so a literal reading lands in "otherwise,
  ignore the Range header field and respond 200 (OK)" — while RFC 9110 §14.2,
  whose subject is this exact request, makes it a SHOULD-416 and every conjunct
  of that SHOULD is met. §13.1.5 is the third text and it is what tips the
  reading: "Otherwise, the recipient SHOULD process the Range header field as
  requested", and processing an unsatisfiable ranges-specifier as requested is
  what §14.2 spells out one section later. The other reading is defensible and
  the function says so at length; no erratum on RFC 9110 touches either section,
  so 416 stands as a choice and not as a correction.

  **RFC 9111 §4.3.2 binds a `Recipient::Cache`, and this crate can apply one
  third of it.** Its MUST NOT has three disjuncts — "A cache MUST NOT evaluate
  conditional header fields that only apply to an origin server, occur in a
  request with semantics that cannot be satisfied with a cached response, or
  occur in a request with a target resource for which it has no stored
  responses; such preconditions are likely intended for some other (inbound)
  server." — and only the first is a fact about the fields, applied here as
  §13.2.2's own origin gate on steps 1 and 2. The other two are facts about the
  cache's store, which this call is never told, so they are a delegation on
  `evaluate` in the shape §13.2.1's third exclusion rule already has one RFC
  over. §4.3.2's `Date` SHOULD is a delegation too: `Selected` takes one
  modification date and does not ask where it came from.

  What the accumulator costs a caller is pinned rather than bounded, per pointer
  width, at module scope so that every `cargo check` on every tier enforces it —
  `assert!(core::mem::size_of::<Preconditions<'_>>() == 1152)` on a 64-bit
  target and 728 under `cargo check -p http-semantics --no-default-features
  --target thumbv6m-none-eabi`, which is the tier the number is written down
  for. Almost all of it is the two `TagList`s and the `RangesSpecifier`, and a
  bound set well above a value asserts nothing about it.

- **`validator` — RFC 9110 §8.8's entity tag, its list form, and the selected
  representation a precondition is evaluated against.**

  `EntityTag` reads `entity-tag = [ weak ] opaque-tag`, and the marker is
  case-sensitive because RFC 9110 §8.8.3 says so in prose as well as in ABNF:
  an origin server "MUST mark the entity tag as weak by prefixing its opaque
  value with "W/" (case-sensitive)", so a lowercase `w/` is not a weakness
  marker but a value that is no `entity-tag` at all. `strong_eq` and `weak_eq`
  are §8.8.3.2's two comparison functions, and which one a field takes is a MUST
  rather than a preference — §13.1.1 requires the strong one of an origin server
  for `If-Match`, §13.1.2 the weak one of a recipient for `If-None-Match`, and
  §13.1.5 the strong one again for `If-Range`'s tag form. Each function's doc
  names the sections that put it there, because wiring a field to the wrong one
  is a defect this module cannot see.

  **`TagList` walks its own commas, because each of the crate's two existing
  walkers gets a live guard wrong.** `grammar::list_elements` splits on raw
  commas and `etagc = %x21 / %x23-7E / obs-text` admits one between the DQUOTEs,
  so it reads the single tag `"a,b"` as two elements that are each malformed.
  `grammar::parameterised_list` is quote-aware in the wrong sense: it implements
  RFC 9110 §5.6.4's `quoted-string`, which has `quoted-pair`, and §8.8.3's
  `opaque-tag` has none — so `"a\"` is one valid tag whose content is `a\`, and
  a `quoted-string` reader takes that DQUOTE for escaped data, runs off the end
  of the value, and refuses a live lost-update guard as malformed. §8.8.3's own
  note names backslash unescaping as what recipients carried over from RFC 2616,
  so reproducing it here would be building the legacy bug on purpose. What does
  not come along with a walk of its own is §5.6.1.2's empty-element rule, which
  `list_elements` holds for every recipient list it can delimit; `TagList::parse`
  carries that rule across explicitly and is tested for it here.

  `MAX_TAGS` is sixteen and it bounds REAL tags. §5.6.1.2 opens "Empty elements
  do not contribute to the count of elements present.", so an empty element
  spends no slot here either and the empties are unbounded, which
  `a_comma_flood_is_not_too_many_tags` pins. Overflow is `TagError::TooMany`
  rather than a truncation, and that is the whole reason there is a bound rather
  than a cap: judging a precondition from the tags that fit could find no match,
  answer as though the client sent none of the others, and silently void the
  guard. The clause that asks a recipient to accept empties "but not so much
  that they could be used as a denial-of-service mechanism" governs EMPTY
  elements, and it was standing in for a bound on real ones at three sites:
  `git grep -n 'not so much that they' fc30179` names them, and they are
  `MAX_SUBPROTOCOL_OFFERS`, the test that pins it, and the cycle-6 entry below,
  which this cycle amends to rest on §5.4 — the clause that is about the size of
  what a server agrees to process.

  `Selected` is a type-state rather than a struct with a rule written on it:
  every validator lives on `Present`, so `Selected::absent()` has no method that
  could attach one. Strength is asserted and never deduced —
  `with_last_modified` records a weak validator and `with_strong_last_modified`
  a strong one — because §8.8.2.2 makes a `Last-Modified` used as a request
  validator "implicitly weak unless it is possible to deduce that it is strong"
  and gives three ways to deduce it: one is knowledge only the origin server
  has, and the other two are half `Date` arithmetic this crate could do and half
  a judgement about clocks that it could not. There is no `Date`-taking
  constructor on purpose, because computing the arithmetic half would read as
  having checked the rule.

  `etagc` is read from RFC 9110 §8.8.3's body text, which admits `obs-text`,
  and not from Appendix A's collected grammar, which spells the same rule
  `etagc = "!" / %x23-7E` and drops it. No erratum settles the disagreement, so
  the body text governs: a recipient refusing a byte the sender was allowed to
  send would refuse the guard the tag exists to carry.

- **`range` — RFC 9110 §14.1's `ranges-specifier`, §14.4's `Content-Range` in
  both directions, and §14.6's `multipart/byteranges` written and read.**

  **`Pos::Beyond` is how §14.1.2's closing MUST is met.** That section requires
  that "recipients MUST anticipate potentially large decimal numerals and
  prevent parsing errors due to integer conversion overflows", and this design
  meets it by never performing the conversion: a numeral no `u64` holds becomes
  `Beyond`, and every §14.1.2 rule stays total over one — a `Beyond` `first-pos`
  is at or above every possible length, a `Beyond` `last-pos` is already that
  section's own normalisation condition, and a `Beyond` `suffix-length` exceeds
  every representation. `Range: bytes=0-18446744073709551616` therefore parses,
  resolves, and is not an ignore. Validity is settled while the digits are still
  in hand: §14.1.1's "An int-range is invalid if the last-pos value is present
  and less than the first-pos" is decided by comparing the two numerals as digit
  strings, since `Beyond` deliberately keeps none of them.

  `ContentRange` takes the opposite decision on the same question, and on
  DEFINEDNESS rather than on cost. §14.1.2's rules each have a total answer for
  a `Beyond` position, as above; §14.4's validity clauses compare the numerals
  against EACH OTHER, and `Beyond` against `Beyond` decides neither of them. So
  a `Content-Range` numeral past `u64::MAX` is refused whole — affordable in a
  way a refused `Range` would not have been, since the only thing §14.4 grants a
  recipient over a value it cannot read is to decline to recombine.

  The production parsed is the corrected one. RFC 9110 §14.1.1 prints
  `ranges-specifier = range-unit "=" range-set`; erratum 7306, reported by
  Julian Reschke and verified in 2023, puts an `OWS` back between the `=` and
  the range-set, lost when the grammar was converted away from implied linear
  whitespace. Under the printed production §14.1.2's own printed example
  `bytes= 0-999, 4500-5499, -1000` is malformed, and under the corrected one it
  is grammar.

  `MAX_RANGE_SPECS` is eight where `MAX_TAGS` is sixteen, and the difference is
  what overflow COSTS. Refusing a range-set is an ignore, sanctioned outright by
  §14.2, so the client gets the 200 it would have got had it never sent the
  field; refusing a tag list voids a guard, and no status the RFC names fits.
  The shape eight deliberately does not hold is the one §14.2 itself names as an
  attack, "a set of many small ranges that are not listed in ascending order".

  **A span this crate does not interpret is still constrained, and by the
  grammar at its DESTINATION.** RFC 9110 §14.1.1 hands the range unit what a
  specifier MEANS — "The range unit name determines what kinds of range-spec are
  applicable to its own specifiers" — and hands over none of the grammar that is
  generic, so every element of a range-set under every unit is held to
  `other-range = 1*( %x21-2B / %x2D-7E )`, and a `Content-Range`'s opaque tail
  to §5.5's `1*field-vchar`. The second is load-bearing rather than tidy: that
  tail is written back out verbatim, and into a header line of a body this crate
  frames, where a CRLF would be a field line this crate wrote and nobody sent.
  §14.4's two validity clauses reach every unit for the same reason — they are
  stated over `range-resp`, whose numerals are `1*DIGIT`, with no unit condition
  on either half — while a span that does not match that numeric shape stays
  opaque, which is what keeps §14.6's own `exampleunit 1.2-4.3/25` readable.

  The rule runs the other way too, and that direction is the one easily missed.
  RFC 9110 §14.6 frames a body part by RFC 2046, whose §5.1.1 says "in no event
  are headers (either message headers or body part headers) allowed to contain
  anything other than US-ASCII characters." — narrower than what an HTTP field
  value admits. So `ContentRange::parse` stays exactly as permissive as §5.5
  lets it be, and the narrower rule sits at the encoder that crosses into MIME.
  But RFC 2045 §5.1's grammar for a body part's `Content-Type` is WIDER than
  §8.3.1's in places, so the reader is held to RFC 2045's own lexis rather than
  being repaired by narrowing the value until an HTTP parser can read it —
  `media`'s summary tabulates nine values where the two grammars part company,
  and reading the field in the grammar of the place the field is answers all of
  them at once. `RangeError::NonAsciiPartHeader` is answered by the reader and
  the writer alike, because one crate giving two answers about the same bytes is
  what either asymmetry produces.

  **The reader ends the cycle accepting and refusing things a first reading does
  not.** Each is now a rule stated at its site:

  - A line beginning with the `dash-boundary` whose tail makes it neither of RFC
    2046 §5.1.1's two delimiters means different things in different places.
    Inside a body part it is a fault, on §5.1's "The boundary delimiter MUST NOT
    appear inside any of the encapsulated parts, on a line by itself or as the
    prefix of any line."; in the preamble it is text to walk past, on §5.1.1's
    "implementations must ignore anything that appears before the first boundary
    delimiter line or after the last one." A reader applying either sentence
    everywhere is wrong somewhere — applying §5.1's everywhere fails a
    conforming body over the one region the specification names as the place to
    ignore whatever is there.
  - A delimiter line is read to the end its own grammar gives it: RFC 2046
    §5.1.1's `transport-padding := *LWSP-char` and then CRLF for an ordinary
    one, and two more hyphens, padding and an optional epilogue for the close.
    Skipping to the line's CRLF from wherever the boundary ended let `--SEP--`
    and `--SEP--JUNK` close a body alike, with the junk dropped in silence.
  - A recognised part field is held unparsed until the line beneath it settles
    whether it was folded. Reading it on its own physical line failed a folded
    `Content-Type: text/` against its own grammar half-read and answered a
    verdict about the MESSAGE over the conforming input
    `RangeError::PartValueNotContiguous` exists to describe — which names a
    limit of a no-alloc reader and not a fault in the body.
  - A `Content-Transfer-Encoding` this crate does not recognise is not a
    malformed body. RFC 2045 §6.4 states the receiver behaviour for exactly that
    value and it is not rejection: "Any entity with an unrecognized
    Content-Transfer-Encoding must be treated as if it has a Content-Type of
    "application/octet-stream", regardless of what the Content-Type header field
    actually says." So there are four readings and not two — the set that may
    skip §15.3.7.2's width test on the strength of a NAME stays closed to §6.1's
    five, and everything else that is still a `mechanism` is handed over with
    its token intact and the skip made visible.
  - `message/partial` and `message/external-body` are held to `7bit`, and RFC
    2045 §6.4's composite prohibition does not already cover it. §6.4 says that
    "it is EXPRESSLY FORBIDDEN to use any encodings other than "7bit", "8bit",
    or "binary" with any composite media type"; RFC 2046 §5.2.2 and §5.2.3 then
    withdraw two of the three §6.4 permits, each calling `8bit` and `binary`
    explicitly prohibited for its own subtype. A guard keyed on a top-level type
    cannot express that, and answering the composite refusal there would be a
    true refusal with a false reason.

- **`status` — the vocabulary moved out of `http1-proto`, and the move renamed
  it.** `SuggestedStatus` was named for what a failed parse suggests, and RFC
  9110 §13.2.2's algorithm produces 200 and 206, which that name cannot hold
  without reading as a category error. The type is
  `http_semantics::status::Status` now, with five codes that vocabulary did not
  have — 200, 206, 304, 412 and 416 — and `http1-proto` re-exports it under the
  old name, so no call site changed. Membership is about the vocabulary's HOME
  rather than about which crate produces each code, and the crate's README
  gained the exception class that keeps `FieldsTooLarge` in it: RFC 6585 §5's
  rule, which RFC 9110 §19.2 lists as an informative reference rather than a
  specification it builds on.

### Breaking (unreleased)

- **BREAKING (unreleased): `MediaType`, `MediaRange`, `ParamValue` and
  `ListMember` derive no `PartialEq` or `Eq`, and every type added this cycle
  was born without one.** Each derive compared the bytes as the sender wrote
  them, and each type's own section makes some of those bytes insignificant:
  RFC 9110 §8.3.1's "The type and subtype tokens are case-insensitive." over
  `text/plain` against `TEXT/PLAIN`; §5.6.6's `OWS` around a parameter's `;`
  over `text/plain;charset=utf-8` against `text/plain; charset=utf-8`; and
  §5.6.6's "A parameter value that matches the token production can be
  transmitted either as a token or within a quoted-string.  The quoted and
  unquoted values are equivalent." over the two spellings of one parameter
  value. `ListMember` compares a private field besides, so two members with
  identical `name` and `params` bytes compare unequal when one was parsed across
  an RFC 9110 §5.2 field-line join and the other was not — a property of how the
  input arrived, not of what the sender said, and one the type never claimed to
  report.

  **A doc note beside the derive is what was there already, and it is not a
  substitute.** All four shipped at `fc30179` with a paragraph directing a
  caller to compare the accessors case-insensitively instead; a documented trap
  is still a trap, because the disclosure tells a reader that `==` answers a
  question it should not have been asked and leaves the wrong answer one
  keystroke away. **And a semantic `PartialEq` is not the repair either.** RFC
  9110 §5.6.6 settles only half of it — "Parameter names are case-insensitive.
  Parameter values might or might not be case-sensitive, depending on the
  semantics of the parameter name." — which is conditional on a name these types
  do not know, while parameter ORDER is nobody's rule at all; folding case would
  invent one answer and not folding it the other. What each type offers instead
  is the unconditional half: `ParamValue::unescaped` walks a value with the
  quoted-string's spelling gone, so `a.unescaped().eq(b.unescaped())` compares
  across both variants, and the media types direct a caller at `ty`, `subtype`
  and `params`.

- **BREAKING (unreleased): `HttpDate` gained `Ord` and `PartialOrd`, and both
  are DERIVED on purpose.** The fields are declared coarsest-first — year,
  month, day, hour, minute, second — so the derived lexicographic comparison IS
  civil order, and `23:59:60` sorts strictly before the midnight that follows
  it, which is the true UTC order. Writing the comparison over `unix_seconds`
  instead is the obvious shape and is unlawful: a leap second shares that value
  with the following midnight, so an instant-ordering answers `Equal` for two
  values the structural `Eq` calls unequal. Reordering the fields silently
  breaks it, which the declaration says in as many words. Two tests defend the
  ordering and both compare through `<` and `>`, which resolve to `PartialOrd` —
  a hand-written `Ord` over `unix_seconds` with `PartialOrd` left derived passes
  both, and only clippy's deny-by-default `derive_ord_xor_partial_ord` catches
  it, so an `#[allow]` on that lint is the tests' blind spot.

### A defect the same sweep found and did not fix

- **`http1_proto::Target` keeps a derived equality that compares spellings, and
  now says so.** Nothing about it changed but its documentation.
  `Eq`/`PartialEq` there compare the request-target as the sender wrote it, byte
  for byte, and RFC 9110 §4.2.3 is the section it disagrees with: scheme-based
  normalization omits a port equal to the scheme's default, makes an empty path
  equivalent to `/` outside an OPTIONS target, and equates an unreserved
  character with its percent-encoded octet, while on case it is explicit — "The
  scheme and host are case-insensitive and normally provided in lowercase; all
  other components are compared in a case-sensitive manner." The section then
  prints three URIs it calls equivalent,
  `http://example.com:80/~smith/home.html`,
  `http://EXAMPLE.com/%7Esmith/home.html` and
  `http://EXAMPLE.com:/%7esmith/home.html`, and the derive answers false for
  every pair of them.

  The derive is kept and the narrow question it does answer is now written at
  the type — whether two requests carried the same bytes in the same form —
  because §4.2.3 leaves the comparison open, "HTTP does not require the use of a
  specific method for determining equivalence.", and a normalising `PartialEq`
  would have to pick one, over a `&str` this crate parses and does not decode. A
  caller deciding that two requests address the same resource normalizes first
  and does not ask `==`. It is recorded here rather than left in a commit
  message because it is a live defect on a sibling crate's public surface, and
  the branch that found it owes the disclosure whether or not it took the fix.
  This branch touches `http1-proto` for the status move and for doc links, and
  it does not touch `Target`'s derive.

### Tooling

- **Three specs joined `quote-check`'s `FETCHED` list, one of them obsolete.**
  RFC 822, RFC 2045 and RFC 2046 bring the cache to fourteen
  (`ls .rfc-cache/*.txt | wc -l`). RFC 822 is there despite being superseded,
  and it is not the exception the list's own rule forbids: RFC 2045 §1 makes it
  live law for a MIME body part's header fields — "All of the header fields
  defined in this document are subject to the general syntactic rules for header
  fields specified in RFC 822." — so a body part's `Content-Type` is read in RFC
  822's lexical classes and those productions are gradeable against nothing
  else. The list also gained the rule that a spec belongs on it as soon as the
  workspace has the text on disk, not when a quotation of it first lands:
  `--fetch` builds the cache CI grades against, so a spec present in a
  developer's cache and absent from the list is a local-green/CI-red trap, and
  that trap had already sprung once.

- **`quote-check` read a production as `name =`, and RFC 2046 writes
  `name :=`.** Every production of that RFC was therefore ungraded. The
  separator is widened and nothing on the right-hand side moved. It is the shape
  the private-item link gate above has: a green that covered less than its name
  said, and a check that never looked reading exactly like one that looked and
  found nothing.

- **`quote-check` could not fail a FABRICATED quotation, and one shipped.** An
  invented sentence matches no spec, so it anchors in nothing, so it can never
  be graded; naming an RFC in its block moves it from invisible to counted and
  no further. The backlog of unanchored spans is now held PER FILE against a
  committed table, pinned exactly in both directions. Per file rather than one
  workspace total, because deleting a genuine span in one file and adding an
  invented one in another leaves a total unmoved and moves two per-file numbers.
  Exact rather than a ceiling, because a growth-only budget lets the backlog
  shrink unrecorded — a span deleted, reworded past the extractor, or moved into
  a fence read differently — and because reading a span and repairing it then
  reds the gate with the smaller number to write down, which is the ratchet.
  **What neither half closes is named at the table rather than left to be
  found:** substituting an invented span for a genuine one INSIDE one file moves
  no number, exactly as it would not under a growth-only budget.

- **`doc-check` collected no documented re-export at all.** rustdoc gives a
  `use` item `name: null` and puts the imported name in `inner.use.name`, so
  `http1_proto::grammar`, `http1_proto::media` and this cycle's own
  `pub use http_semantics::status::Status as SuggestedStatus` were invisible to
  the snapshot — prose that could be deleted with nothing failing. All three sit
  on it now, under the names a caller writes; `http1-proto`'s snapshot moves
  from 792 documented items to 786 across this branch, the fall being
  `SuggestedStatus`'s six variants and two methods becoming one re-export line.
  The fixture test carries a control — an item with empty docs that must NOT be
  collected — so it cannot pass by collecting everything.

- **Six new leaves join the link-time no-panic proof, and the crate got its
  first size assertions.** `grep -c 'fn shim_' http-semantics/tests/no_panic.rs`
  counts twelve where `fc30179` had six: the entity tag and its list, the
  ranges-specifier and the resolution behind it, and `Content-Range` in both
  directions, beside the `shim_lie` control. `resolve` is a shim of its own
  rather than a tail on the parse's, because it holds the cycle's only new
  checked arithmetic and a shim should fail for the code it names. Measured
  rather than assumed: a bare index put in place of `ContentRange::encode`'s
  buffer test reds the link naming `shim_content_range_encode` and nothing else,
  and one put in place of `TagList::get`'s slot lookup names `shim_tag_list`.
  And `git grep -c 'const _: () = assert!' fc30179 -- 'http-semantics/src/*'`
  finds nothing where the crate now carries twelve, in three files —
  `Option<EntityTag>` and `TagList`, `Option<Pos>`, `Option<RangeSpec>` and
  `RangesSpecifier`, and `Preconditions` — each pinned per pointer width, so a
  slot count raised without thinking reds the build rather than the device.

## A fourth bypass of one gate, and the redesign that ends the series

### Tooling

- **`shim-check` no longer decides REACHABILITY by reading Rust source. It asks
  the linker.** The check now has two halves, each asking its question where
  that question's answer lives.

  The fourth bypass is what made the split necessary rather than tidy. Its
  comment-and-literal blanker knew ordinary `"…"` and not raw strings, so in
  `r#""assert!(shim_x(black_box(…)));""#` the quotes INSIDE the literal ended
  and restarted the blanking and handed the call scanner string data as code.
  Measured on `http3-proto`: `shim_varint_decode`'s whole `#[test]` body
  replaced by that one line left `shim-check` exiting 0 over 139 "rooted" call
  sites, `cargo test -p http3-proto --release --features test-no-panic` ok on 5
  tests, the lie-check still red on `shim_lie` — and `nm` over that binary
  finding no `shim_varint_decode` at all. Round two of the same review had
  closed three others: a call inside `debug_assert!`, a call under a `#[cfg]`
  release turns off, and a call in a helper nothing reaches. Patching the fourth
  corner buys the fifth; a lexical scanner over Rust source has an unbounded
  supply of them, and `xtask` takes no dependencies, so no real lexer is
  available to it.

  **What moved.** "Was this shim instantiated" is now read out of the ARTIFACT:
  per crate, `cargo test --release --features test-no-panic --test no_panic
  --no-run --message-format=json` — the build the `no-panic` job already does,
  so the link steps below become cache hits — then the test binary's own symbol
  table, and, for every declared shim, a DEFINED FUNCTION symbol whose mangled
  path is the test crate followed by that shim. It does not read Rust, so it has
  no corners. All five mutations above red on it, and three of the
  five are invisible to the source half entirely, including one no lexical
  checker could ever see: a lexically perfect call inside `if NEVER { … }`.

  **What stayed lexical.** `black_box` at every argument and a live answer are
  properties of how a shim is WRITTEN, and a symbol table cannot see an
  argument. They are still read from the source, and the module says in as many
  words which half answers which question. The blanker was fixed anyway — every
  raw, raw-byte and C-string form, any hash count — and it now REFUSES a literal
  or block comment it cannot finish reading instead of guessing where it ended.

  **Two declaration changes make a symbol mean what the check reads it as.**
  `#[inline(never)]` on `no_panic_shim!`, because a private `fn` with one call
  site is inlined into its `#[test]` and leaves no symbol at all — measured:
  before it, `nm` over these binaries found no `shim_*` whatever. And
  `black_box` around each shim's own answer, because a body the optimizer can
  prove pure and trivial is forwarded to its callers and deleted even though it
  IS called: `http1-proto`'s `shim_widen` wraps `u64::try_from(usize)`, the
  identity on a 64-bit target, and this check's first run over the live files
  found it missing. Deleted-because-trivial and deleted-because-uncalled are one
  silence in a symbol table, and the alternative to telling them apart is a list
  of excused shims, which is a bypass with a name. Neither change weakens the
  proof — the leaves still inline INTO the body, which is what the fat-LTO steps
  are for — and both were measured: all four real steps still link clean, all
  four lie-checks still refuse to link naming `shim_lie`.

  **It fails closed on every way it can fail to know.** A binary that did not
  build, a `cargo` JSON reporting other than exactly one `no_panic` executable,
  an object format the reader does not read, a stripped table with no symbols in
  it, a shim under a `#[cfg]` the build does not enable — each is a named
  failure rather than a shim counted as fine. The one exemption is the
  lie-control, and it is tied to both the name `shim_lie` and the gate
  `feature = "test-no-panic-lie"`, at most one per file, so it cannot be spread
  over a real shim. The symbol reader is written rather than shelled to `nm`:
  a check whose answer depends on whether a tool is installed has a second way
  to go quiet. It reads ELF64 and 64-bit Mach-O, with its own tests over
  hand-built files of each.

  The line a run prints now carries both denominators — `written — 24 shim(s) in
  4 file(s), 149 call site(s), 239 argument(s) through black_box; 0 span(s) this
  check could not analyse` and `instantiated — 20 of 24 declared shim(s) are
  DEFINED, as a function whose mangled path is no_panic::<shim>, in the release
  test binary their no-panic step links; over 6840 symbol(s) read, 4668 of them
  defined functions; 4 lie-control shim(s) excluded`.

- **The symbol reader now requires the shim's whole PATH and the symbol's kind,
  and honours every extent the object file declares.** Two findings of the same
  shape from the round that reviewed the reader above: the gate could pass while
  the property it names was false.

  **A name is not an identity.** The verdict accepted any symbol containing the
  shim's name as a mangled path component, and never checked the `no_panic`
  test-crate path its own constant documented. An executable carries every
  dependency's symbols and every symbol it merely REFERENCES, so a dead local
  `shim_decode` was satisfied by `elsewhere::shim_decode`, by
  `no_panic::inner::shim_decode`, by a `static` of that name, or by an undefined
  entry — no forgery required, an ordinary dependency collision does it — and
  combined with a textually valid but compiled-away call, both halves passed
  over an empty proof. The rule is now a DEFINED FUNCTION whose mangled path is
  `no_panic::<shim>`, read anchored in both mangling schemes, and the failure
  names the symbol that spelled it so a collision reads as one. The doc that
  described the requirement the code did not perform is now the doc of the
  requirement it does.

  **A truncated string table could still yield a passing name.** The ELF reader
  followed a symbol table's `sh_link` without checking that section's type or
  size, and its `cstr` scanned to end-of-file and treated a missing NUL as a
  terminator; the Mach-O path ignored `strsize`. A table shortened by one byte,
  with a shim's spelling in the bytes that follow it, was therefore read as
  CONTAINING that shim. Every lookup is now bounded by the extent the file
  declares — `sh_link`'s type, each section's size, `sizeofcmds`, each
  `cmdsize`, `nsyms`, `strsize` — and a name with no terminator inside its table,
  or an offset outside it, is REFUSED by name rather than improvised over. The
  reader was checked against real ELF64 and Mach-O artifacts of both mangling
  schemes, not only its hand-built fixtures.

  Three name matches of the same shape were tightened with them: the test
  binary's own target name (`no_panic_extra-…` passed a `starts_with`), the
  `no_panic_shim!` invocation, and the `macro_rules! no_panic_shim` definition
  whose exemption a `no_panic_shim_other` could take.

## Three adversarial-review findings: a rule that could not be stated, a permissive sender, and a gate with a bypass

### `http-semantics`

- **BREAKING (unreleased): `parse_http_date_from` takes a reference INSTANT,
  not a reference year.**

  ```rust
  pub fn parse_http_date_from(v: &[u8], now_unix_seconds: i64) -> Result<HttpDate, DateError>;
  ```

  RFC 9110 §5.6.7 has a recipient "interpret a timestamp that appears to be
  more than 50 years in the future as representing the most recent year in the
  past that had the same last two digits". Both sides of that comparison are
  timestamps — the value's, and fifty years past the recipient's own instant —
  and a `u16` of years can represent neither. A recipient whose clock reads
  2026-01-01 must read `Friday, 31-Dec-76 00:00:00 GMT` as 1976, because its
  fifty-year anniversary is 2076-01-01 and that value is most of a year past
  it; the same recipient on 2026-12-31 must read it as 2076. Handed only the
  year 2026, the window could not tell the two apart, and answered 2076 for
  both. The rule is now applied where it is stated: the candidate timestamp
  against the exact fifty-year anniversary of `now_unix_seconds`, to the
  second.

  **Seconds since the POSIX epoch rather than an `HttpDate`**, because seconds
  since the epoch is what a clock answers. `SystemTime`'s duration since
  `UNIX_EPOCH`, a POSIX `time_t` and an embedded RTC's counter are this number
  already; an `HttpDate` would put the civil-calendar conversion this module
  owns on every caller, or make the crate publish a second constructor whose
  only purpose is to feed the first. It is also what `HttpDate::unix_seconds`
  answers, so a `Date` field this parser has read is a legal reference for the
  next call. Every `i64` is an instant, so the argument has no malformed value
  and adds no refusal of its own.

  `parse_http_date`'s anchor moves with it: `REFERENCE_INSTANT` is
  2026-01-01T00:00:00Z, whose anniversary is 2076-01-01T00:00:00Z. `94` still
  reads as 1994; `76` now reads as 1976 for every timestamp of that year except
  the one that IS the anniversary, which is what a recipient with a real 2026
  clock answers and what the year-wide window could not.

  Two private helpers arrive with it: `civil_from_days`, Hinnant's exact
  inverse of the `days_from_civil` already here — the anniversary needs the
  month and day the caller's instant falls on, and seconds since the epoch does
  not carry them — and `seconds_since_midnight`, one definition of "how far
  into the day" shared by `HttpDate::unix_seconds` and the window, so the two
  cannot disagree about the instant the rule turns on. `DateError` is unchanged
  in this direction: `FiftyYearWindow` still names a year no `u16` holds, and
  where each band begins is now a function of the candidate's own month, day
  and time of day as well as of the clock, which is the point.

- **BREAKING (unreleased): `format_imf_fixdate` refuses a year below 1900, as
  the new `DateError::YearBefore1900`. The parser still accepts one.** RFC 9110
  §5.6.7 gives `year` the semantics of the Internet Message Format construct of
  that name, and RFC 5322 §3.3 says "The year is any numeric year 1900 or
  later". This crate reasoned earlier that the bound does not bind at all,
  because §3.3's conformance sentence enumerates four constituents and `year`
  is not among them, and because §5.6.7 re-spells the production as
  `year = 4DIGIT` where RFC 5322 has `4*DIGIT`. That reasoning holds for the
  READER and not for the writer. §5.6.7 tells a recipient to "be robust in
  parsing timestamps", and a year below 1900 is an unambiguous instant every
  recipient reads alike — but robustness is not an argument available to a
  sender, who commits the fault instead of carrying it. Every other clause of
  §3.3 is already discharged here at the sender, `day-name` included; this one
  now is too.

  Its own variant rather than `DateError::Year`, under this crate's
  one-variant-per-rule convention. The two refuse at the two ends of one field
  for two different reasons: above 9999 there is no column in `date1`'s
  `year = 4DIGIT` to write the digits in, while 1899 has four digits and a
  column for each and is refused for what the year means. Folding them together
  would leave a test unable to say which end refused, and would let a writer
  that had lost the `4DIGIT` ceiling pass the test written for the 1900 floor.

  It is a real asymmetry and not a hypothetical one: `Sat, 01 Jan 0000
  00:00:00 GMT` parses and will not be written back, and so does an
  `rfc850-date` whose fifty-year window lands before 1900 — `99` measured from
  an 1860 clock is 1899. The round trip was never total; it now costs one more
  input, and `grammar`'s own `list_elements` / `sender_list_shape` pair states
  the same doctrine one module over: recipient tolerance is not a licence to
  emit.

- **The fifty-year rule's tests are graded by §5.6.7's sentence, not by the
  implementation's model.** The exhaustive test that shipped last round
  computed its expected value as `horizon = reference_year + 50`,
  `want = horizon - horizon % 100 + two_digits` — the implementation's own
  model, spelled a second time. It walked all 6_553_600 argument pairs and
  every one agreed, because a wrong model checked against itself agrees
  everywhere; the year-versus-timestamp defect above sat inside the model both
  halves shared, so no amount of coverage could reach it.

  The oracle is now built from the section's sentence and shares nothing with
  the code it grades. Its calendar is a day-of-year table plus a leap-year
  count where the module runs Hinnant's March-based 400-year eras, and the two
  are pinned against each other — in both directions, `civil_from_days`
  included — over every month boundary of every year a `u16` holds. It applies
  the rule by SEARCH, enumerating the years ending in the given two digits and
  keeping the most recent whose timestamp is not past the anniversary, where
  the module computes one candidate from a century and conditionally steps it
  back.

  The reference-year sweep stays exhaustive, so nothing the old test covered is
  lost, and a second sweep covers the dimension it could not express at all:
  every month, every day column the grammar admits and five times of day around
  the anniversary, for all hundred two-digit years. Beside them are the named
  boundaries — the anniversary to the second in each of month, day, hour,
  minute and second; the leap-day anniversary, which never lands on a leap day
  and falls on 1 March; and the century the rule picks deciding whether
  `29-Feb-00` is a date at all.

### Tooling

- **`shim-check` no longer accepts a call site the release build removes.**
  `debug_assert`, `debug_assert_eq` and `debug_assert_ne` were on its
  accepted-consumer list, and those macros delete their expression when
  `debug_assertions` is off — which is the `--release` every `no-panic` step
  builds in. Replacing a real shim's calls with
  `debug_assert_eq!(shim_x(black_box(…)), …)` therefore passed: the arguments
  were opaque, the lexical call was there, the answer was consumed, and the
  linker saw no call at all. The real step linked clean over an empty proof
  while the crate's `shim_lie` still failed on its own, so both CI controls
  stayed green — the same defect this check exists to report, arriving through
  the check itself.

  A call site now counts only when it is REACHED: a `#[test]` in the same file
  must reach it, directly or through other functions of that file, under `cfg`
  predicates the shim itself carries. That closes all three routes — a
  `debug_assert`, a `#[cfg]` on the test that the shim does not have, and a
  helper nothing calls — and admits the lie-check's own shape, where shim and
  `#[test]` sit under one `feature = "test-no-panic-lie"`. Each route has a
  negative test, and each of those reds when the rule behind it is disarmed.

  **What a lexical checker cannot reach is now stated and counted rather than
  assumed harmless.** `cfg` predicates are compared as written and never
  evaluated; only top-level items are read; the call graph stops at the file;
  and a call through a function pointer is not found at all. A `cfg` inside a
  function body and a call in no top-level `fn` are each reported as a span the
  check could not analyse — failed, not skipped — and the count is on the line
  every run prints, which now reads `24 shim(s) in 4 file(s), 149 call site(s)
  — 149 rooted in a release-enabled #[test], 0 not; 239 argument(s) through
  black_box; 0 span(s) this check could not analyse and did not assume
  harmless`. The exact answer is the linker's, and the module names it as the
  open follow-up: read the release test binary's symbol table and require a
  symbol per declared shim, which costs no extra build and needs a stable
  name-to-symbol mapping this check does not have.

  Its test module now drives `check_file` itself instead of a second copy of
  the per-file body. The copy shared the helpers but not the composition, so a
  rule added to the command and not to the copy was a rule no test exercised —
  and a rule deleted from the command left every test green on the copy. The
  rooting rules above were added under exactly that hazard.

## Two adversarial-review findings: a control with no subject, and a clamp with no caller

### Tooling

- **`cargo run -p xtask -- shim-check`: the structural half of the `no-panic`
  link proofs.** The four `test-no-panic-lie` controls prove that `no-panic`,
  the selected profile and `black_box` still work — for `shim_lie`, which is
  their own subject and nobody else's. Put one real shim's call site back to
  bare literals and nothing in CI moves: measured on `websocket-proto` with
  `FrameHeader::encode`'s high-bit-length call, the real step still linked clean
  and reported `ok` on 6 tests while the lie step still exited 101 on the marker
  naming `shim_lie`. Both green, that crate's proof empty.

  The new check reads the source instead of building it. Every `#[no_panic]`
  shim declared through `no_panic_shim!` must have at least one call site; every
  argument at every call site must be a whole `core::hint::black_box(…)` call;
  and every call's answer must feed an assertion or be wrapped in `black_box` —
  or, for a shim answering `()`, be held by an opaque `&mut` it writes through.
  It also floors its own discovery: a file whose macro stopped applying the
  attribute, a shim declared by writing `#[no_panic::no_panic]` outside that
  macro, a `no_panic_shim!` block it cannot read, a claimed crate with no proof
  file, and a `tests/no_panic.rs` no entry of `SHIMMED_CRATES` claims are each a
  failure. It prints its denominator — 24 shims in 4 files, 149 call sites, 239
  arguments today — so a green run is distinguishable from a run that never
  looked. (A call site's REACHABILITY became part of the same check in the
  round above.) It runs first in the `no-panic` job, in milliseconds, where the
  alternative was one must-fail release build per shim.

- **`doc-check` reports the size of the snapshot it compared against, and fails
  on an empty one.** `lost_docs` is one-directional, so a `-documented.txt`
  truncated to nothing loses nothing and every later run printed a healthy
  `N documented items, 0 lost` for a comparison against no subject at all. The
  line now reads `N documented items against M snapshotted, K lost`, and `M = 0`
  for a gated crate is a failure — the same floor `verdicts` puts under
  `tables == 0`, one file over.

### `http-semantics`

- **BREAKING (unreleased): an `rfc850-date` whose fifty-year year this parser
  cannot represent is now refused, as the new `DateError::FiftyYearWindow`,
  instead of parsed with a clamped year.** §5.6.7's rule is measured from a
  reference year the caller supplies, so it can name a year outside `u16` at
  either end. Those two ends saturated — at `u16::MAX` above and at year 0
  below — and a clamp there is not a narrower answer but a wrong one that
  arrives as `Ok`: `(36, 65486)` denotes 65536 and parsed as year 65535, a value
  that does not even end in the `36` the sender wrote, with `unix_seconds()`
  describing the wrong instant. The earlier reasoning for keeping the clamp was
  that a clamped bound "reads as a clamp"; it does not — a caller holding an
  `HttpDate` cannot tell a clamped year from a written one. Only a refusal is
  visible, so both ends refuse and they refuse alike: it is one rule, §5.6.7's
  fifty-year rule, naming a year this module cannot hold.

  Its own variant rather than `DateError::Year`, under this crate's one-variant-
  per-rule convention: `Year` is about the LITERAL not being the digits its
  format spells, and here the two digits are digits — what failed is the rule
  computed from them, and its cause is the caller's `reference_year` rather than
  the input bytes. A test can now assert which of the two refused.

  Nothing a real clock can reach changes: the refusing bands are 1225 argument
  pairs (reference years 0 through 48) and 1275 (65486 through 65535) out of
  6_553_600. `format_imf_fixdate`'s `DateError::Year` for a year past four
  digits is untouched and still reachable.

  (The `reference_year` this entry names became a reference INSTANT in the round
  above, which moves where each band begins; the refusal and its variant are
  unchanged.)

- **The exhaustive window test is now two-directional.** It used to assert that
  the clamped bands came back clamped — a successful parse of 65535 for a rule
  that named 65536 was what it REQUIRED, which is what let the defect through.
  It now requires every `Ok` to equal the unclamped `i32` oracle AND to end in
  the two digits supplied, and every `Err` to be a pair whose oracle no `u16`
  holds, so it fails both on a wrong answer and on a refusal that was not owed.
  Reverted to the shipped arithmetic it reds three tests, the exhaustive one
  reporting `(51, 0) -> 0, but the rule names -49, which no u16 holds`.

  (Two-directional and still blind: the `i32` oracle named here restated the
  implementation's own year-only model, which is the finding the round above
  fixes.)

## `websocket-proto` and `http3-proto` — the two link proofs get something that can falsify them

### Tooling

- **Every shim argument now goes through `core::hint::black_box`, and each crate
  carries a must-fail `test-no-panic-lie` control.** Both crates publish
  `panic-free` in their `Cargo.toml` description and in their README, and both
  already carried a `tests/no_panic.rs` with a CI step behind it — but neither
  file used `black_box` anywhere, and neither had a lie control. Nothing in
  either crate could report the proof going empty.

  It had gone empty in places, and that is measured rather than inferred. A
  reachable panic put on `FrameHeader::encode`'s 63-bit-length refusal arm — the
  arm a caller reaches by asking to encode a length with the high bit set —
  linked CLEAN and the test reported `ok`, because the two lengths the file
  passed were `5` and `70_000`, so LLVM proved the arm dead and the shim proved
  nothing about it. The same in `http3-proto`: replacing
  `frame::decode_header`'s `input.get(n0..).unwrap_or(&[])` with a bare index
  linked clean, because every input was a literal whose length the optimizer
  could count against the `n0` it folded out of the first varint. With every
  argument through `black_box`, both injections red the link, naming
  `shim_encode` and `shim_frame_decode`. What the proofs already bit on is
  unchanged — injections into `frame::mask`, the base64 encoder and
  `varint::decode` reddened before this change and still do; the sweep pins a
  property that until now held by how those particular call sites happened to
  lower.

  Slices are wrapped as slices (`black_box(bytes.as_slice())`,
  `black_box(&mut buf[..])`) rather than as arrays, because
  `black_box(&[1, 2, 3])` hides the pointer and leaves the LENGTH a compile-time
  constant — the half of a bounds check that matters. Every call now feeds an
  assertion or is itself wrapped, so no shim can be deleted whole for having an
  unused answer, and the smokes are wrapped too: a smoke folded away stops
  running the code it exists to run.

  Neither crate's CI step uses fat LTO, unlike `http1-proto`'s and
  `http-semantics`' — their shimmed leaves are `#[inline]`, so they inline into
  the shim under the default profile. That is why the lie-check greps for
  `no-panic`'s own link-error marker: with no LTO there is no second,
  profile-shaped reason the lie build could fail for, so the marker is the whole
  control rather than a check on top of one.

- **The four lie-checks are one CI step, not four.** `ci.yml`'s `no-panic` job
  would have carried four hand-copied must-fail blocks — four places for one to
  be weakened without the others disagreeing. They are now one `lie_check` shell
  function called once per crate. Nothing is pooled but the assertion: each call
  builds its own crate under its own profile (fat LTO for `http1-proto` and
  `http-semantics`, the default for the two above), captures its own log,
  asserts a non-zero exit AND the marker naming `shim_lie`, and names its own
  crate in the `::error::` it raises.

## `http-semantics` — a new crate for the half of HTTP no version owns

New in this unreleased cycle. `http-semantics` holds the version-independent
half of HTTP — RFC 9110's §5.6 field grammar, its §8.3.1/§12 media and `Accept`
machinery, and its §5.6.7 `HTTP-date` — which `http1-proto` re-exports at their
existing paths. It depends on no protocol crate, which is the whole reason it
exists: `http1-proto`, `http3-proto` and anything later reach the same rules
without reaching through each other. `no_std` and no-alloc capable, panic-free,
on the same `std` / `alloc` / `no-atomic` tiers its siblings run.

### Added

- **`grammar` and `media` live here now, and every path a caller writes is
  unchanged.** `http1-proto` re-exports both modules whole
  (`pub use http_semantics::grammar;`, `pub use http_semantics::media;`), so
  `http1_proto::grammar::…` and `http1_proto::media::…` resolve exactly as
  before. The move is a relocation and not a rewrite: no runtime behaviour
  changed.

  Both modules were version-independent by RFC 9110's own construction, and
  `media` had been in the wrong crate from the day it was written: nothing
  inside `http1-proto` ever called it, so it was a module that crate carried in
  order to re-export. `grammar` is the opposite case and the load-bearing one —
  `http1-proto` imports it into ten of its own files, and `websocket-proto`
  imports eight of its predicates, so a second consumer already existed before
  there was a crate for the two to share it through.

  One type's home crate moved with them, in an API that is not yet published:
  `ParamValue::unescape_into` now returns `grammar::BufferTooSmall` rather than
  `http1_proto::Error::BufferTooSmall`. Same fields, same `Display`.

- **`date` — RFC 9110 §5.6.7 `HTTP-date`, read in three formats and written in
  one.** `parse_http_date` accepts `IMF-fixdate`, `rfc850-date` and
  `asctime-date`, because §5.6.7 requires a recipient to accept all three;
  `format_imf_fixdate` writes `IMF-fixdate` and nothing else, because the same
  section requires a sender to generate that one. No argument selects an output
  format, so a caller of this crate cannot use it to break the second rule.

  ```rust
  pub fn parse_http_date(v: &[u8]) -> Result<HttpDate, DateError>;
  pub fn parse_http_date_from(v: &[u8], now_unix_seconds: i64) -> Result<HttpDate, DateError>;
  pub fn format_imf_fixdate(date: &HttpDate, out: &mut [u8]) -> Result<usize, DateError>;
  pub const IMF_FIXDATE_LEN: usize = 29;
  impl HttpDate {
    pub const fn year(&self) -> u16;
    pub const fn unix_seconds(&self) -> i64;
  }
  ```

  **The recipient's clock is an argument, not state this crate holds.**
  §5.6.7's fifty-year rule for a two-digit `rfc850-date` year is measured
  against the recipient's clock, and a clock is an I/O capability the caller
  owns — so `parse_http_date_from` takes the instant to measure from, and
  `parse_http_date` is that call with this crate's own anchor and nothing else.
  The reference instant reaches exactly one of the three formats: `rfc850-date`
  is the only one whose year is two digits, and the other two readers are never
  handed it, which is checkable from the three-arm match rather than from a
  comment.

  **A refusal names the rule that refused it.** Seven of `DateError`'s nine
  variants are the reading side — `Length`, `DayName`, `Month`, `Year`,
  `TimeOfDay`, `Separator`, `NotGmt`, and `FiftyYearWindow` — one per rule that
  can refuse, so a test asserts the REASON rather than the refusal. The writing
  side has two of its own, `BufferTooSmall` and `YearBefore1900`, and neither
  is folded into a reading-side variant: an output buffer too short for
  twenty-nine bytes broke no rule the input broke, and a year RFC 5322 §3.3
  forbids a sender is not a year the input spelled wrongly.

  **The `day-name` a sender writes is derived, never echoed.** §5.6.7 gives the
  semantics of five constituents to RFC 5322 §3.3, which requires the
  day-of-week to be the day the date implies — so `format_imf_fixdate` computes
  it. `HttpDate` carries no day-name field at all, which is what makes echoing
  one structurally inexpressible rather than merely avoided.

  Everything above is `no_std`, allocation-free, clock-free, and covered by the
  link proof below.

### Tooling

- **The crate has its own `no-panic` link proof, and its own must-fail lie
  control.** `tests/no_panic.rs` link-checks five leaves behind the internal
  `test-no-panic` feature — the §5.6.6 parameterised-list walk, the §12.4.2
  `qvalue` reader, the §12.5.1 weight selection, and §5.6.7's two halves, the
  date reader and the `IMF-fixdate` writer — while `test-no-panic-lie` adds one
  shim whose reachable panic must FAIL the link. CI runs both under
  `CARGO_PROFILE_RELEASE_LTO=fat` and asserts the second's failure by
  `no-panic`'s own link-error marker rather than by its exit code alone, which
  is what keeps the first from passing with an empty proof.

  Three of the five came from `http1-proto/tests/no_panic.rs`, where they had
  been working: with fat LTO, a panic injected into `media::parse_qvalue`
  reddened that crate's link naming two shims, and one injected into
  `grammar::is_token` named two more. They moved for three other reasons — the
  proof belongs beside the code it covers; it lets `media::parse_qvalue` go back
  to `pub(crate)` instead of being `pub` to serve another crate's test (it is no
  longer reachable as `http1_proto::media::parse_qvalue` either); and coverage
  held in another crate's test file lasts only as long as that file chooses to
  carry it, with no gate of this crate's own to report the loss. The other two
  arrived with `date`, in the same crate as the code they cover.

## `http1-proto` — cycle 6 (opportunistic upgrade on an ordinary exchange)

Issue #44. A client could state RFC 9110 §7.8's `Upgrade` offer only by building
a `Connection<Client, Tunnel>` first, which spends the connection on a handshake
whether or not the server takes it — so the shape §7.8 is actually written for,
where a client offers on an ordinary request and carries on in HTTP when the
server declines, could not be expressed at all. It can now, on a General client
whose operator asks for it. The mode type-state is unchanged: BUILDING a
handshake is still `Tunnel`'s, and what General gained is the ability to CARRY
one that arrived on an exchange it opened for its own reasons.

### Breaking

- **`Event::CloseSignaled` is removed, and `Connection::transport()` replaces
  it.** A pre-1.0 break, and the one this cycle exists to justify: the end of
  keep-alive was stored as a queued, once-delivered INSTRUCTION, and eight of the
  eleven defects found on this branch were lifecycle failures of that stored
  copy — delivered stale, stranded onto a later exchange, destroyed by a path
  that owned other state, duplicated beside a terminal error, leaked through
  `Debug`, and diverged between the two modes. Those are the complete failure
  catalogue of caching a derived fact.

  The fact is now a LEVEL, derived on the ask and never stored:

  ```rust
  pub enum Transport { Live, Ending, Failed, HandedOver }
  impl<Ro, Mo> Connection<Ro, Mo> { pub const fn transport(&self) -> Transport }
  ```

  One `match`, exhaustive over the tunnel phase and the lifecycle, over fields
  that already existed — `HandedOver` and `Failed` absorbing, `HandedOver`
  checked first, which is where "a switch wins over a local close" now lives.
  `Role`- and `Mode`-free by construction, so a fix applied to one mode and not
  the other is not a shape it can take. A level has no instances, so it has none
  of the failures a stored instruction had: nothing to mint stale, nothing to
  destroy, nothing to deliver twice, no second copy to disagree.

  **Migrating — and this IS a break for every external driver, even though no
  crate in this workspace needed a line changed.** Nothing here consumed the
  variant, so a green workspace build proves only that this repo did not use it;
  it exercises none of the migration below. What an external driver must do:
  delete the `Event::CloseSignaled` match arm — the variant no longer exists, so
  the arm will not compile — and read `conn.transport()` after draining items and
  events instead:
  `Ending` means finish what is parsed, send what is owed, then close; `Failed`
  means send the owed error response if `is_awaiting_send()`, then close;
  `HandedOver` means hand the transport to the negotiated protocol and never
  close it; `Live` means carry on, refined by `wants_read`/`is_awaiting_send`.
  A driver that wants to act once on a change edge-detects against its own last
  value — the crate no longer keeps one, which is the point. A driver that
  matched `Event` exhaustively without a `_` arm will also stop compiling on the
  variant's removal; `Event` is `#[non_exhaustive]`, so that arm was always
  required.

  `poll_event` remains, narrowed to message-scoped facts: `ExchangeAborted` only.
  The line between the two representations is that **an event is right when its
  subject dies before the driver could ask** — an exchange, destroyed at
  settlement — **and a level is right when its subject is the very thing the
  driver holds.** The crate already applied the level idiom to this same subject
  in `wants_read` and `is_awaiting_send`, the two transport channels that never
  produced a defect.

  Removed with it: the queue slot on `Connection`, both producers' mutual dedup,
  the hold-and-suppress machinery and its four cancel sites, and
  `SendState::ErrorOwed`'s cached copy of the same bit. Net-negative code and
  net-negative state; `size_of::<Connection<_, _>>()` falls to 184 bytes against
  a 256-byte budget.


### Added

- **`Limits::allow_opportunistic_upgrade`**: permits a connection to make a §7.8
  offer on an ordinary `open_request`, and to accept the 101 that answers one.
  **Off by default**, and conforming rather than merely
  cautious: §7.8 obliges a client to nothing — the offer is an invitation a
  server "MAY ignore", and
  "Upgrade cannot be used to insist on a protocol change" — so refusing is fully
  conforming, while a proxy-shaped driver forwarding a downstream client's
  `Upgrade` field never chose to send one and must not be switched for carrying
  it through. Named `allow_` rather than `with_` like its siblings because they
  set a VALUE and this grants a PERMISSION:
  `allow_opportunistic_upgrade(false)` reads as withholding one, which is what
  it does. It is the operator's CEILING — a request may decline to offer on a
  permitting connection and may not offer on a refusing one — and it is read
  once, at construction, so a live connection has no path back to it.

  What the permission governs is §7.8's INDICATION, which is the `Upgrade` field
  alone: "A server MUST NOT switch to a protocol that was not indicated by the
  client in the corresponding request's Upgrade header field." The `upgrade`
  connection option is §7.8's separate sender MUST and is REQUIRED of a
  permitted offer rather than asked as part of the question — a request
  carrying the field without it is refused
  (`an upgrade offer states Connection: upgrade and an Upgrade protocol list`,
  the constant Tunnel's `open_upgrade` already refuses the same omission under).
  Keying the permission on both halves would have let the un-optioned field —
  which a server may legally switch on, and which intermediaries forward — walk
  past the ceiling and past every rule below it.

  A permitted offer must be bodiless, and this one is a **deviation**, recorded
  as such. §7.8 permits the message it refuses: a 101 may answer a request whose
  body is still going out, since "A client cannot begin using an upgraded
  protocol on the connection until it has completely sent the request message"
  — the body is finished in the OLD protocol and the new one begins after it,
  with "the server still has an outstanding request to satisfy after the
  protocol has been changed". This core does not implement that: it parks at the
  101 and hands the transport to the caller, so there is no send side left to
  finish a body through. `open_request` therefore refuses a bodied offer with
  `Error::InvalidState` — a restriction on this end's own sends, which §7.8
  obliges no client to observe, and the same one Tunnel's `open_upgrade` keeps
  on the way out and its `classify` on the way in.
- **`Connection<Client, Tunnel>::open_connect` refuses an `Upgrade` field.** A
  CONNECT already states RFC 9110 §9.3.6's takeover, and §7.8's field on it
  invites a second one this handshake has no answer for: `ClientTunnelOutcome`
  makes a CONNECT's success the 2xx tunnel, and `handle_response` condemns a
  `101` to a CONNECT as `SWITCH_WAS_NEVER_OFFERED`. But an `Upgrade` field IS
  §7.8's indication, so a server that switched on one this core had written
  would have broken nothing — and the condemnation would be a false accusation.
  Refused before encoding, over the indication alone (the connection option
  beside it changes nothing about whether a server may act), for the reason
  `UPGRADE_NEEDS_TUNNEL` gives on the General side: the request "would have
  opened an exchange its own continuation forbids".

  §7.8's sender MUST — "A sender of Upgrade MUST also send an `Upgrade`
  connection option in the Connection header field" — is otherwise SPLIT along
  the line `connection::outbound`'s delegation table draws, and the table now
  states it as a RULE rather than a list, so a send path added later is
  classified without anyone editing the row: ENFORCED where writing the field
  ARMS a switch, REFUSED where a switch could not be answered at all, and
  DELEGATED to the caller at every other head-encoding send path, where the
  field arms nothing and §7.8 gives a server its own reasons to state it — a 426
  "MUST send an Upgrade header field to indicate the acceptable protocols", and
  any other response "MAY send an Upgrade header field … to advertise" support.
  Membership today: arming is `open_request`'s offer branch, `open_upgrade`, and
  `accept`'s 101 branch; refusing is `open_connect`; delegated is the remaining
  six — General's `send_interim`, `send_response` and `send_error_response`, and
  Tunnel's own `send_interim`, `accept`'s CONNECT-2xx branch, and `reject`.
- **`Item::Switched { head, leftover }`**: the 101 that answered the offer, and
  the bytes behind it — verbatim, because they are the new protocol's. The
  connection is spent from there: it holds no leftover, it will read no further
  byte, and every later call refuses. The exchange is NOT ended and no item says
  it was, because §7.8 leaves "the server still has an outstanding request to
  satisfy after the protocol has been changed" — reporting an abort or a
  completion would be false. WHICH protocol was switched to stays the caller's
  to check against what it offered: §7.8 makes naming it the server's MUST and
  this core refuses a 101 that names none, so the field is there in `head` to be
  read, and only the caller knows what it asked for.

  Every other 101 a General connection can receive is still a protocol error —
  every 101 at a server, at an unpermitted client, and at a permitted client
  that offered nothing — because RFC 9110 §7.8 makes switching to a protocol "not
  indicated by the client in the corresponding request's Upgrade header field" a
  server MUST NOT. Permission is not indication, and the gate reads the OFFER.
  The 101 it does accept is validated exactly as Tunnel validates the one it
  accepts: the same head checks, the same both-halves predicate, and RFC 9112
  §9.6's `close` fact — so a head one mode switches on is a head the other
  switches on, and this crate does not become two recipients that read one
  response differently (RFC 9112 §11.1).

  §9.6's fact is asked of the head IN HAND, not only of the heads before it, and
  in BOTH modes. A 101 may state its own `Connection: close`, and no accumulator
  can see that — a 101 never reaches the head-commit path that accumulates the
  option — so both modes asked `validate::ends_persistence` of the 101 itself. A peer that ends the connection's persistence in the very response
  that would switch has committed to closing and has nothing to continue into,
  which is the rule both readers were already documented to keep; the same
  predicate also answers §9.3's HTTP/1.0 half, where a message without
  `keep-alive` is non-persistent however it spells its `Connection`. One
  constant, `101 after the peer stated close`, for both statements of the one
  fact and both modes.

  That rule is one corner of a wider invariant this cycle closed: **no path of
  this crate arms, makes, or accepts a §7.8 switch on a connection either end has
  said it is closing.** §9.6 binds both ends with MUSTs, and a switch is the
  opposite promise. Newly refused: a 101 this end WRITES while stating `close`
  (`accept`), an offer this end writes while stating it (`open_request`'s offer
  branch and `open_upgrade`) — both `an upgrade offer or switch states no
  Connection: close` — and a received offer that states it, which is no longer
  classified as a handshake (`an upgrade offer that also states Connection:
  close`). That last one is where Tunnel had stopped agreeing with General about
  one wire request: General accumulates the close and refuses the transition
  `NOT_OPEN`, and Tunnel's direct classification now mirrors that answer rather
  than inventing one. The invariant, its classifying rule and a verdict for every
  site are stated once on `TunnelPhase::Switched`.

  The rule covers BOTH takeovers, with no exclusion. An earlier version exempted
  RFC 9110 §9.3.6's tunnel, reading `close` on a CONNECT 2xx as "no HTTP reuse
  once the tunnel ends". RFC 9112 §9.6's text does not support that: it defines
  the option unconditionally as an obligation to close after reading the
  response carrying it, and §9.3.6 has that same response switching to tunnel
  mode "immediately after the response header section". One instant, opposite
  demands — so a close-bearing CONNECT or CONNECT 2xx is refused at all four
  corners, exactly as a close-bearing 101 is.
- **`TransitionRefused::SWITCHED`**: `into_tunnel` on a connection that has
  already switched. Never today's reported reason on either edge — a General
  server cannot reach the phase at all, and a client is refused first by
  `EXCHANGE_IN_FLIGHT`, which §7.8 makes TRUE rather than coincidental — and
  gated all the same, because a coincidence between today's writers is not a
  rule, and what this one guards is a transport another protocol is already
  reading.

### Changed

- **`Items::next` has THREE `Err` answers, not two**, and the third is new only
  for a driver that opted in: after `Item::Switched` it answers
  `Error::InvalidState` on the first call and on every call after it, having
  latched nothing. The reason string is `pub(crate)`, so the connection cannot
  tell it apart from post-failure misuse on your behalf — **your own record is
  the discriminator**. A driver that took `Item::Switched` hands the transport
  over and must NOT tear it down; one that did not is looking at the
  post-failure misuse it has always been, and tearing down is exactly right.
  The rest of the General surface goes quiet with it: `wants_read` and
  `is_awaiting_send` are both `false`, `handle_eof`, `open_request`, `send_body`
  and `finish_body` refuse, and `body_progress` reports no body. `wants_read`
  answers FROM THE PHASE rather than from the message state, and has to — §7.8
  retains the exchange and the idle-client rule reads exactly that, so an
  exchange-first answer would send a driver to read the next protocol's bytes.
  `poll_event` still drains, and that is the deliberate exception: a queued
  `Event::CloseSignaled` is a fact about the CONNECTION recorded before the
  transport changed hands, and this crate documents it as arriving exactly once.
  `close` and `handle_eof` say what they always said, and the notice they queue
  is HELD rather than delivered while a handover is still possible. There is
  exactly one place a notice reaches a driver — `poll_event`, which is `Role`-
  and `Mode`-generic — and that is where the hold lives, so no producer has to
  remember: an instruction about the transport is not handed over while
  `handover_possible` says whose transport it is has not been decided, and it is
  released by the next poll once that is settled — the answering head, a refusal,
  or the fault that ends the connection. Only an actual handover cancels one, at
  all four writers of `TunnelPhase::Switched`, through a single routine.

  Nothing is stored and nothing is resolved, which is the point: an earlier
  design had each producer WITHHOLD the notice and each terminal path resolve
  it, which put the fact in storage another path could destroy — and one did.
  Holding at delivery removes the storage and the resolvers together.

  `Event`'s variants carry the classification that decides all of this, once, at
  the enum: `CloseSignaled` INSTRUCTS a driver about the transport ("then close
  the transport"), `ExchangeAborted` INFORMS about a message. Informational
  notices are never held and never suppressed, which is what leaving `poll_event`
  live after a switch was always for. Both that match and `handover_possible`'s
  over `TunnelPhase` are exhaustive, so a new notice or a new phase is a compile
  error rather than a forgotten site.

  After the switch `close` is accepted and INERT, and that is enforced rather
  than merely true:
  it would otherwise move the lifecycle and queue the very
  `Event::CloseSignaled` that tells a driver to close a transport now belonging
  to the negotiated protocol, which is this feature's contract inverted. It
  returns through the same phase guard the accessors read, leaving a notice
  queued before the switch untouched.

  Every entry point above is classified by a RULE rather than by a list, so a
  method added later lands in one of its cases by construction: an entry point
  that can return `Result` REFUSES with a reason naming the switch; one that
  cannot is INERT, taking the only other answer its signature permits; and
  `poll_event` alone stays LIVE, because a notice recorded before the transport
  changed hands is still the driver's to collect. Anything that fits none of the
  three is a hole. The sixteen of them are `poll_event`, `handle`, `handle_eof`,
  `wants_read`, `is_awaiting_send`, `body_progress`, `close`, `open_request`,
  `send_body`, `finish_body`, `into_tunnel`, the two `const` limit accessors,
  and `Items::{next, consumed, limit_body}`.

## `http1-proto` — cycle 6 (media types and the `Accept` ranking)

Issue #42. `Content-Type` and `Accept` were the two fields this core scanned but
would not read: a consumer holding their values had to re-implement RFC 9110
§5.6.6's parameter grammar to get at a charset, and §12.5.1's precedence to pick
a representation — the second of which is a ranking the RFC settles and a
hand-rolled one gets wrong. Both are now parsed here, to the last parameter. The
PICK stays the caller's: §12.1 says a user agent "cannot rely on proactive
negotiation preferences being consistently honored", so this crate answers what
weight applies and nothing about what to serve.

### Added

- **`media_type`, `MediaType`**: reads ONE `Content-Type` value into §8.3.1's
  `type "/" subtype parameters`, borrowing the value rather than copying it.
  `ty()` and `subtype()` hand back the tokens as written, since §8.3.1 makes them
  case-insensitive and the comparison is the caller's; `params()` yields every
  parameter in wire order. It takes a single VALUE rather than a field's lines
  because §8.3 makes `Content-Type` a singleton, and a comma outside a
  quoted-string is refused rather than recovered from: §8.3 records that
  recipients which take "the last syntactically valid member of the list" cause
  "potential interoperability and security issues", and refusal is the one
  behaviour that cannot diverge between two recipients.
- **`accept`, `MediaRange`**: walks an `Accept` field's §12.5.1 media ranges.
  Takes the field's LINES, not one value, for the reason `parameterised_list`
  does — §5.2 makes a repeated field one comma-joined value and a quoted-string
  may span the join. `ty()`/`subtype()` report `None` for exactly the two
  wildcard SHAPES §12.5.1 names, so a literal asterisk reached through the
  `type "/" subtype` alternative (`*/json`) stays an ordinary token and matches
  nothing real. `params()` never yields `q`, wherever it appeared: §12.5.1 says
  recipients "SHOULD process any parameter named "q" as weight, regardless of
  parameter ordering", so none of them is a range parameter. The walk STOPS at
  the first faulting member and every `next` after that `Err` is `None` —
  whether the fault is the list walk's own (a member whose boundaries it cannot
  resolve) or one found here while reading an already-delimited member as a
  range (a `q` that is not a `qvalue`, a parameter with no value, a quoted value
  spanning the §5.2 join). A caller handed the suffix of a malformed `Accept`
  would be the second of two recipients disagreeing about a hostile field.
- **`weight_for`**: the §12.5.1 selection — the weight an `Accept` field gives
  one candidate. Precedence is a lexicographic key over the ranges that matched
  (shape, then matched parameter instances, then field order) which GENERATES
  §12.5.1's printed four-item list rather than transcribing it, which is what
  ranks a parameterised wildcard above its bare form — a pair that list does not
  contain. Three parts of it are readings rather than answers §12.5.1 gives and
  ship as implementation-defined determinism; they are named in the function's
  own doc. `Weight::ZERO` both for a matching range that says `q=0` and for a
  candidate nothing matched (§12.4.3). A range's parameter matches a
  candidate's when the NAMES agree ASCII-case-insensitively (§5.6.6) and the
  values agree byte-exact after unescaping — except `charset`, which folds ASCII
  case because §8.3.2 says "In both cases, charset names are matched
  case-insensitively". That exception is load-bearing rather than cosmetic:
  without it `text/plain;charset=UTF-8;q=0` would not match a candidate spelling
  its charset `utf-8`, and the field's own refusal would be answered with the
  weight of whatever coarser range sat behind it. A parameter whose own
  registration gives its value other semantics is NOT settled here and compares
  byte-exact, with the same failure shape — including against a `q=0` range, so
  a refusal can be missed; `weight_for_with` below is how a caller supplies what
  it knows. An ABSENT field is a third
  input rather than an empty one: no lines at all is how a caller spells a
  request that carried no `Accept`, and §12.4.1 — titled Absence — says such a
  request "implies that the sender has no preference on that dimension of
  negotiation", so every candidate keeps `Weight::ONE`. ONE line that happens
  to be empty is a field that WAS sent naming an empty `#`-list, which stays
  `Weight::ZERO` with every other unmentioned value (§12.4.3). The lines
  iterator already carries the distinction — zero items against one empty item
  — so no signature encodes what the input already says. Field order settles
  every residual tie, and does so through the STRICT key comparison alone: a
  later range whose key ties the incumbent's leaves it standing. There is no
  positional counter in the key, deliberately — one would decide nothing the
  strict comparison has not already decided, while carrying an `enumerate`
  index over a caller-supplied iterator that a 16-bit `usize` can overflow,
  which panics with checks on and wraps without them.
- **`weight_for_with`**: `weight_for` with the caller's own rule for which
  parameter VALUES compare ASCII-case-insensitively. §8.3.1 makes that a
  property of the parameter's REGISTRATION — "Parameter values might or might
  not be case-sensitive, depending on the semantics of the parameter name" —
  and registrations do use non-byte semantics: RFC 9782 §6.3 registers
  `eat_profile` for `application/eat+cwt` with a case-insensitive value. This
  crate does not carry the registry, and without a hook a caller needing one
  such parameter compared correctly would have to re-implement §12.5.1's whole
  selection, which is the second-reader failure the scope rule's first clause
  exists to prevent. So the ranking stays here and the one fact the caller has
  arrives as an argument. `fold(ty, subtype, name)` is keyed on all three,
  because a parameter is registered per media type; the type handed over is the
  CANDIDATE's, since it is always concrete while the range may be `*/*`. It is
  generic rather than a `fn` pointer, so each policy monomorphises and no two
  callers share one instantiation. It ADDS to RFC 9110's own rule and cannot
  subtract: `charset` folds under any policy, because §8.3.2 settles it and it
  is not a default anyone may disagree with — so `weight_for` is exactly
  `weight_for_with` with a policy that answers `false`.
- **`Weight`**: a §12.4.2 `qvalue` in thousandths, `0..=1000`. Fixed point rather
  than a float, because the grammar is already fixed point and this core compares
  weights exactly, on tiers with no FPU and under a link-time no-panic proof.
  `Ord` is PREFERENCE ("0.001 is the least preferred and 1 is the most
  preferred"), not §12.5.1's separate question of which range applies.
- **`MediaError`**: why a media-type or `Accept` walk stopped.
  `ValueSpansFieldLines` and `TooManyParameters` are their own variants rather
  than `Parameters` details, because one condition gets one representation: the
  first is well-formed input that is simply not one contiguous slice, and the
  second names a limit of a no-alloc match rather than a fault the sender
  committed.
- **`MAX_TRACKED_PARAMS`**: the most parameter instances a candidate may carry
  while a range's parameters are matched against it. §12.5.1's match is per
  INSTANCE — a range naming `a` twice matches only a candidate offering two, so
  repeating a parameter cannot buy precedence — which means remembering which of
  the candidate's instances are already spent, and a no-alloc core cannot grow
  that memory. Exceeding it is `Err`, never a weight read off the parameters the
  walk could see. A parse-constant like `MAX_HEADERS`, not a `Limits` knob: the
  storage is in the binary, so a caller cannot raise it. A range carrying no
  parameters spends no slot and keeps matching a candidate with any number.
- **`validate::parse_content_length`**: the §8.6 `1*DIGIT` reader, made `pub`.
  It was already the crate's one spelling of that parse and a consumer had no
  way to reach it. One element only; a caller holding a comma-bearing value
  composes it with the existing `grammar::list_elements` and `grammar::trim_ows`.
  An overflow is a framing error rather than a wrapped length.
- **`ParamValue::unescaped`, `unescape_into` and `eq_unescaped_ignore_ascii_case`**:
  new methods, not new consumers of an old one — none of the three existed
  before this branch. `unescaped` is the no-alloc iterator the other two are
  built on and the one a no-alloc caller reaches for first: `same_value` (the
  range-vs-candidate parameter match behind `weight_for`) compares two values
  with it directly. `unescape_into` writes it into a caller-supplied slice;
  `range_from` uses it to unescape a `q` parameter's digits before
  `parse_qvalue` reads them. `eq_unescaped_ignore_ascii_case` has no internal
  caller yet — it answers the common question ("is this charset utf-8?")
  without a buffer, for whoever asks it next. Neither `unescaped` nor
  `unescape_into` folds case, and the folding one says so in its name: §8.3.1
  says parameter values "might or might not be case-sensitive, depending on the
  semantics of the parameter name", so which of them fold belongs to the field
  asking rather than to these three. `same_value` is where the media surface
  answers it, and RFC 9110 answers it for exactly one parameter — see
  `weight_for` above. Parameter NAMES compare ASCII-case-insensitively
  regardless (§5.6.6).
- **`ListMember` now derives `Eq` and `PartialEq`**, comparing a member's bytes
  as written; `MediaType` and `MediaRange` reuse it through their own derives.

### Internals

- **The §12.4.2 `qvalue` reader and the §12.5.1 weight selection join the
  link-time `no-panic` proof.** The `qvalue` reader carries the feature's only
  checked accumulation; the weight shim is driven over a field's LINES rather
  than one value, so §5.2's join branches stay live rather than being pruned as
  visibly dead before the guard can act on them. Both shims, and the §5.6.6
  list-walk shim beside them, moved to `http-semantics` later in this same
  unreleased cycle, with the code they cover — see that crate's section above.
  Thirteen leaves are link-checked across the two crates either way; eight of
  them are `http1-proto`'s.

## `http1-proto` — cycle 6 (the General ↔ Tunnel mode edges)

PR1 of the cycle. A server could not answer WebSocket upgrades and ordinary HTTP
on one port, because `Connection`'s mode is a compile-time type-state and had to
be chosen before the request that decides it had been read. The type-state is
unchanged; what is new is an EDGE between the two modes, taken AFTER the read
rather than instead of it.

### Added

- **`Connection::<Server, General>::into_tunnel`**: answers an upgrade request
  the General pump has ALREADY read. RFC 9110 §7.8 makes the switch an answer and
  permits it only once the client "has completely sent the request message", so
  the edge runs after the read — which is also why an upgrade request carrying
  CONTENT is switchable here and is not on the native path: General has drained
  the body by then. It lands the connection where `handle_request` leaves one, so
  `accept` writes the 101.
- **`Connection::<Client, General>::into_tunnel`**: spends an IDLE pooled
  connection on a handshake — a decision this end takes rather than an answer it
  owes, so what it gates on is that nothing is outstanding. Both edges are
  consuming, since the General state has no meaning past the switch.
- **`TransitionRefused`**: a refused transition hands the connection back beside
  it (`Err((Self, TransitionRefused))`), because a switch that cannot be taken is
  a reason to answer differently, not a reason to lose the ability to answer at
  all. It names ONE gate rather than reporting a set: the gates are checked in a
  FIXED order, several of them fail together on the same connection — a peer that
  stated `close` moved the lifecycle and queued a notice in the same step — and a
  caller told a different reason on different runs could act on none of them.
  Branch by comparing against the named constants; `reason()` and `Display` write
  the same string for a log line.
- **`HeadBinding` and `Connection::<Server, Tunnel>::head_binding`**: whether a
  head the caller is holding is the head that armed this connection's handshake.
  A layer that answers RFC 9110 §7.8 upgrades on a connection it did not read the
  request on holds two values per exchange, and nothing in either one's type says
  they belong together: `into_tunnel` CONSUMES the connection a lifetime brand
  would be tied to while the head outlives it, and `ExchangeId` cannot say it
  either, since the transition resets the counter. Three answers rather than a
  `bool`, because neither `bool` can be written correctly — `Matches`; `Mismatch`
  for a live handshake this head did not arm, RFC 9110 §9.3.6's CONNECT included,
  which made no §7.8 offer for any head to be; and `NoHandshake` for a connection
  holding no handshake at all, which is the answer a throwaway
  `Connection::new()` gives and the reason it stays usable for validating a head
  BEFORE spending the one-way transition. `Matches` is FNV-1a digest equality
  over the whole head block, computed only for a request that offered a switch,
  so an ordinary request pays nothing for it. Against an accidental mispairing
  the miss probability is 2⁻⁶⁴ per event; it is NOT a security boundary, since
  head content is peer-controlled and a colliding pair is constructible offline.
- **`HeadView::request_line`**: the RFC 9112 §3 request-line read back out of the
  block the view already borrows, so a consumer that needs the method, the
  request-target or the version reads what the ONE §3 codec in this crate
  produced instead of re-implementing it. `None` on a response head, whose start
  line is the §4 status-line.

### Internals

- **An `Exchange` carries four facts durably** — `expect_unanswered`, `version`,
  `upgrade_offered` and `head_digest`, which are exactly the four `into_tunnel`
  reads off it — because a transition is where a transient copy is lost.
  `expect_unanswered` is RFC 9110 §7.8's outstanding `100 (Continue)`: the
  transient copy lives in `RecvState::Body` and is gone by the time an answer is
  written, so both sends that discharge the ask clear the durable copy alongside
  it and `into_tunnel` reads the obligation off that. `version` is the version
  the REQUEST stated, which RFC 9112 §6.1 and RFC 9110 §15.2 both turn on and
  which no response can be read for. `upgrade_offered` is §7.8's two-halved offer
  as the receive side decided it, which cannot be re-derived once the head is
  gone. `head_digest` is WHICH request made that offer, and it is the fact
  `head_binding` answers from on the far side of the edge. Without the four, a
  Tunnel handed back across it would owe an interim it cannot know about, would
  answer under a version it can no longer see, could not tell that a switch was
  offered at all, and could not tell the request it is holding from any other.

## `http1-proto` — cycle 6 (the inbound body gets a ceiling)

PR2 of the cycle. The message body was the only unbounded quantity this core
handled: it streamed borrowed chunks and never accumulated, but a consumer that
needed a whole body accumulated them itself and nothing bounded that, so the
crate handed its consumers a denial-of-service surface. A body now has a
per-message ceiling, and exceeding it is a POLICY REFUSAL that leaves the
connection answerable rather than failed — which is the whole point, since a 413
carrying an explanation has to stay representable.

### Breaking (0.2.0 at the next publish; the crate is unpublished today)

- `Connection::new()` applies its role's default ceiling. A driver that
  previously accepted any body now refuses one past 1 MiB at a server, 64 MiB at
  a client, with `Error::Refused` rather than an item stream that never ends.
  `Connection::with_limits` is how a driver states its own.
- `Error` gains a `Refused` variant and `SuggestedStatus` a `ContentTooLarge`
  one; both enums are already `#[non_exhaustive]`, so a `_` arm keeps compiling
  and a driver that wants the 413 matches for it.

### Added

- **`Limits`**, and the constructors that read it —
  `Connection::<Ro, Mo>::default_limits()`, `with_max_body_bytes`,
  `with_max_chunk_framing_bytes`, `max_body_bytes`, `max_chunk_framing_bytes`,
  and `Connection::with_limits`. The seed hangs off the CONNECTION type rather
  than off `Limits`, so the wrong role's seed has no shorter spelling than the
  right one. Read once, at construction: a live connection has no path back to
  it, so the ceiling has one writer and the only direction a route can move it
  is down.
- **Role-dependent defaults** on the sealed `Role` trait — a server's 1 MiB is
  nginx's `client_max_body_size 1m` and exactly `MAX_HEAD_BYTES × MAX_HEADERS`;
  a client's 64 MiB is where RFC 9112 §6.3 item 8's undeclared, close-delimited
  framing lives and matches `websocket-proto`'s own `max_message_size`.
- **A chunk-framing budget resolved from the payload ceiling in force** — a
  sixteenth of it, with the role default as a floor. Derived from the ceiling
  rather than fixed because a fixed one reproduces, one knob up, the failure it
  exists to prevent: 100 MiB at the commonest 4 KiB chunk granularity spends
  153,600 octets of RFC 9112 §7.1 size lines, so a budget frozen at 64 KiB would
  refuse ordinary traffic about 42.7 MiB into a body the payload ceiling allows.
  `u64::MAX >> 4` is 2⁶⁰, so "unbounded" stays one knob.
- **`Error::Refused(Refusal::BodyTooLarge { exchange, limit })`** — deliberately
  not an `H1Error`. RFC 9110 §15.5.14 names this as a double MAY ("The server
  MAY terminate the request, if the protocol version in use allows it;
  otherwise, the server MAY close the connection") and HTTP/1.1 has no way to
  end one request without the connection, so this core takes the second branch:
  keep-alive ends, `Event::CloseSignaled` is queued once, and a server's one
  response is still owed and still sendable.
- **`SuggestedStatus::ContentTooLarge`** (413) and **`SuggestedStatus::reason()`**,
  which retires a defect class rather than adding a convenience: both wren
  drivers mapped a suggested status through `match code { Some(414) => …, _ =>
  (400, …) }`, so every variant added later degraded silently at two
  byte-identical sites. Both now map `(s.code(), s.reason())`.

### Changed

- **A refused body constrains what may still be written.** The final response
  must state the `close` connection option — RFC 9112 §9.3 makes reading the
  whole body or closing a MUST, this core has taken the close branch on the
  driver's behalf, and RFC 9110 §10.1.1 makes stating it a SHOULD — and
  `send_interim` is refused outright, because a refused exchange owes exactly
  one final answer. Both gates are keyed on a refused body, so nothing that
  works today changes.
- **An oversized `Content-Length` never yields `Item::ExpectContinue`.** The
  expectation asks "shall I send the content?" and this end has already answered
  no, so the ask is not surfaced and no `100 (Continue)` can be written for it.
- **Closing after a 413 is a STAGED close, and a driver must do it that way.**
  The peer is mid-transmission of the refused body by construction, so RFC 9112
  §9.6's reset case is guaranteed rather than incidental and an immediate full
  close can erase the very response this path exists to deliver. Half-close the
  write side, keep draining the socket at the transport level until the peer
  closes or a deadline expires, then close. `wants_read() == false` means the
  CORE needs no more octets, not that the socket should stop being drained;
  nothing discarded that way is parsed, so §9.6's "MUST NOT process any further
  requests" is untouched.
- **What the ceiling does NOT bound: time.** A peer declaring exactly the
  ceiling and then dribbling one octet per read is not refused, and pins a
  connection for as long as the driver lets it. The core is Sans-I/O and has no
  clock; the socket read deadline is the driver's, and it is the real control.

## `http1-proto` — cycle 6 (the ceiling narrows per exchange, and reports)

PR3 of the cycle. The ceiling PR2 gave the inbound body is the connection's, and
a connection serves many routes: the one that accepts uploads and the one that
takes a 4 KiB JSON document had to share a number chosen for the larger. A route
can now tighten that ceiling once its own head has been read, a driver can ask
where the body it is receiving stands, and a counted body can be taken as one
borrowed chunk with no copy path anywhere in this core.

### Added

- **`Items::limit_body(max)`** — narrows the ceiling on the body in flight to
  `max` payload octets. NARROWING ONLY: the effective ceiling is
  `min(current, max)`, and `min` is idempotent and commutative, so it may be
  called any number of times, in any order, right after `Item::Head` or
  mid-body, and the answer is the same. There is no "exactly once, before X"
  rule to get wrong, which is why the call is safe to FORGET — forgetting it
  leaves the operator's ceiling in force. A routing bug cannot LIFT that ceiling
  because the operation has no increasing direction to be pointed in, not
  because a check refuses one.

  On `Items` rather than on `Connection`, and only there: `Item<'a>` borrows the
  INPUT rather than the iterator, so a driver narrows while still holding the
  head it just pulled — before the pump has decoded one octet of that body, even
  when head and body arrived in the same offer. A `Connection`-level twin could
  not promise that, and two surfaces with one signature and different timing
  guarantees is a trap dressed as symmetry.

  **The connection ceiling must be the maximum over all route limits.** A route
  asking for more than the connection allows is capped silently, since narrowing
  is `min`: `limit_body(8 << 20)` under a 1 MiB ceiling answers `Ok` and grants
  1 MiB. A ceiling taken from any one route's limit caps every route above it
  and reports nothing.

  It refuses — `Err(Error::Refused(Refusal::BodyTooLarge { .. }))`, with the
  connection moved to the same refused disposition a wire-side breach produces —
  when `max` cannot be satisfied: more octets have already been delivered than it
  allows, or the framing has already DECLARED more than fits (a `Content-Length`
  remainder, RFC 9112 §6.3 item 6, or the remainder of the chunk in flight,
  §7.1). The `limit` such a refusal carries is the ROUTE's `max` and not the
  ceiling it replaced, because the narrowing is committed before satisfiability
  is checked; a driver logging one otherwise reads back a number that never
  refused anything.

  It answers `Ok(())` on a message with no body. RFC 9112 §6.3 items 1 and 7
  frame a bodiless message as a body of no octets, so nothing has been
  delivered, no ceiling can be exceeded at any value, and a uniform
  narrow-after-every-head driver — the natural shape — is never told that a
  conformant GET, HEAD response or 304 was an error. A body already THROUGH is a
  different case and is measured like any other: its octets are out, so the
  window between `Item::BodyChunk` and `Item::ExchangeComplete` — in which the
  iterator is still usable and a route may still narrow — answers about what the
  body delivered rather than about how far the item stream has been pumped. `Error::InvalidState` is reserved for a connection that cannot act on
  the call at all: no message being received, or a failed or drained connection.
  That reservation is deliberate, because `InvalidState` carries a `&'static str`
  a caller cannot branch on — folding "this message has no body" into it would
  make it indistinguishable from "this connection is dead".

- **`BodyProgress` and `Connection::body_progress()`** — where the body being
  received stands: its exchange, the payload octets already delivered, the
  ceiling now in force, and what the framing has COMMITTED to and not yet handed
  over. That last one separates the three RFC 9112 §6.3 framings cleanly when
  read right after the head: `Some(total)` is a counted body, `None` is chunked
  or close-delimited. Inside a chunk it is the remainder of THAT CHUNK — §7.1
  never declares a body total, and it must not be read as one.

  On the CONNECTION rather than on `Items`, which is the opposite side from
  `limit_body` and for the same reason: the iterator borrows the connection for
  as long as it lives, so this is read once it has been dropped — which is
  exactly where the recipe below wants it.

- **The zero-copy contiguous handover**, which needs no new API beyond the
  above and adds no copy path. Wait until the driver's own buffer holds
  `announced` more octets and the next `handle` yields the whole body as ONE
  borrowed `Item::BodyChunk`, because the counted framing claims
  `min(remaining, input.len())` in one go. Two steps of that are not
  discoverable from the signatures and both are required:

  1. **Stop pulling at `Item::Head` and DROP the iterator.** One more `next()`
     may hand back a partial chunk of whatever happened to be buffered, and
     `body_progress` is unreachable while `Items` borrows the connection.
  2. **Answer any pending expectation BEFORE waiting.** `Item::ExpectContinue`
     is yielded by the BODY pump, so a driver that stopped at the head has never
     seen it and must re-derive the ask from the head's own `Expect` field. RFC
     9110 §10.1.1 provides for a client that waits for its `100 (Continue)`
     before sending content, so against one that does both ends wait — the server
     for octets, the client for permission to send them.

  **The wait is bounded in MAGNITUDE and unbounded in TIME, and that is not a
  footnote.** A declaration above the ceiling was already refused, so the wait
  can never ask for more than `limit` octets of driver buffer — but it can ask
  for them for as long as the peer likes, and a peer that declares exactly the
  ceiling and then dribbles pins that buffer for the whole dribble. That is the
  consumer-side accumulation the ceiling exists to close, reintroduced at
  `limit`. Per process: a streaming driver costs about 200 core bytes per
  connection, a contiguous-handover driver up to `limit` — roughly 10 GB at ten
  thousand connections on the server default, and **640 GB on the client's 64
  MiB default**. **Liveness is the DRIVER's**, and this core cannot take it: it
  owns no clock. `body_progress().received` is the quantity to sample against
  the driver's own clock, and the socket read deadline is the real control.

## `http1-proto` — cycle 6 (the chunk framing gets a budget of its own)

PR4 of the cycle, and the last of it. A payload ceiling bounds content, and RFC
9112 §7.1's chunk-size lines are not content: `chunk-size = 1*HEXDIG` admits
unlimited leading zeros, so 271 of them and a `1` is a 272-octet line that
parses cleanly, announces ONE payload octet and costs 277 octets of wire. A body
comfortably inside its ceiling could therefore make this end parse about 277
wire octets per payload octet, for as long as it liked, because nothing counted
them. The framing a chunked body may spend is now bounded per message, at the
one place it is parsed.

### Added

- **A cumulative chunk-framing budget**, charged over the whole chunk-size LINE
  — digits, `chunk-ext` and the CRLF that ends it — and reset per body. The
  budget is `Limits::max_chunk_framing_bytes()`, which PR2 already resolved from
  the payload ceiling in force (a sixteenth of it, floored at the role default);
  this is the PR that makes it bind. The last chunk's `0\r\n` is charged like
  every other line, since it comes through the same parse and exempting it would
  be a second rule.

  **The LINE and not the extension**, which is the whole of why it catches
  anything: RFC 9112 §7.1.1 asks a server to "limit the total length of chunk
  extensions received in a request to an amount reasonable for the services
  provided", and the zero-padding attack above spends 274 framing octets with no
  extension in it at all. An extension-only budget never sees it.

- **`Refusal::ChunkFramingTooLarge { exchange, limit }`**, whose `limit` is the
  budget in framing octets. Its advised status is `SuggestedStatus::BadRequest`
  and not the 413 its sibling advises: RFC 9112 §7.1.1 asks for "an appropriate
  4xx (Client Error) response if that amount is exceeded", and 413's name — RFC
  9110 §15.5.14, "Content Too Large" — is about content this message may be well
  inside. `Refusal` is `#[non_exhaustive]`, so a `_` arm keeps compiling and a
  driver mapping `(s.code(), s.reason())` answers `400 Bad Request` without
  changing. Everything else is the refusal disposition PR2 built: not a protocol
  failure, `Event::CloseSignaled` once, and a server still owing exactly one
  answer that has to state `close`.

- **The granularity the budget implies, and it does not move with the role.** At
  a full payload ceiling the smallest chunk size a whole body can be sent in is
  **65 octets** at either role, because the budget scales with the ceiling: 1 MiB
  in exactly-64-octet chunks writes 16,384 `40\r\n` lines, spends 65,536 to the
  byte, and is refused at the terminating `0\r\n` with every payload octet
  already delivered. 128-octet chunks have 2× margin, and 1 MiB in 4 KiB chunks
  — the commonest reverse-proxy granularity — writes 256 six-octet size lines
  and spends 1,539 octets of the 65,536.

### Changed

- **A chunked body over the payload ceiling is now refused at the size LINE**
  that announces the octets, one chunk ahead of the data, rather than by the
  cumulative charge as the octets arrive. RFC 9112 §7.1 declares one chunk at a
  time, so the announcement is measured against what is left of the allowance:
  the same `Refusal::BodyTooLarge` with the same `limit`, reached sooner, with
  every octet the ceiling allowed still delivered first.
- **Syntax still runs before policy**, on both budgets. A line that is not
  `1*HEXDIG`, or whose extensions break the §7.1.1 grammar, is diagnosed as
  malformed however far past a budget it also was — only a message that PARSED
  can be refused by policy — and a line breaching both budgets is refused as
  framing, deterministically.

### The exposure numbers this changes

- **Per message**: `payload + (5/3) × framing_budget`, plus a trailer section
  (already capped at 16,384 octets by `MAX_HEAD_BYTES`, with `MAX_HEADERS` over
  its line count) and one unterminated line. Each chunk spends at least three
  charged octets, so the budget admits at most `F/3` chunks and the `2F/3`
  octets of chunk-data CRLF that go with them. At the server defaults that is
  1 MiB of content plus **109,227 octets** — 106.7 KiB — of framing and
  chunk-data CRLF.
- **Per narrowed route**: `Items::limit_body` narrows the PAYLOAD ceiling only —
  the framing budget belongs to the connection — so a route narrowed to 4 KiB on
  a connection with a 64 KiB framing budget still admits `4096 + (5/3) × 65,536`
  ≈ **113,300 octets** (110.7 KiB) of wire. Construct the connection's budget
  accordingly; there is deliberately no per-route knob for it.
- **The instantaneous 277:1 ratio is unchanged.** What this bounds is the
  absolute amount, not the ratio: an attacker still gets 277 wire octets per
  payload octet, and now runs out.

## `websocket-proto` — cycle 6 (handshakes on a connection the caller holds)

PR1 of the cycle. Both h1 handshakes can now be driven on a connection the caller
transitioned out of `http1-proto`'s General mode, so one port can serve WebSocket
upgrades and ordinary HTTP, and a client handshake can ride a connection kept
warm by ordinary keep-alive exchanges. The handshake that opens its own
connection is unchanged; what is added is a second way in.

### Breaking

- **`classify` DERIVES the request-line rather than taking one beside the head.**
  The signature is `classify(&head, leftover)`; what was a `RequestLine` argument
  is now `HeadView::request_line` read out of the block this call was handed. A
  caller-supplied line is exactly the class of mistake this call exists to
  refuse: RFC 9112 §3.2.2 makes an absolute-form target override `Host`, so a
  foreign line grants the right request's key against a different request's
  resource name and authority, and the head digest says nothing about it. A head
  that begins with no §3 request-line answers `NotARequestHead`, which is a
  refusal the old signature had no way to express.

### Added

- **`ServerHandshake::adopt`**: takes the `Connection<Server, Tunnel>` the caller
  transitioned, where `new` creates one. It pairs with `classify`, and the pair
  is also how a caller pre-validates WITHOUT spending a connection: because
  `Connection::into_tunnel` is one-way, a request that is a valid RFC 9110 §7.8
  upgrade but an invalid RFC 6455 §4.2.1 handshake leaves a caller that
  transitioned FIRST holding a tunnel it must reject and no keep-alive HTTP
  connection left to serve. `adopt(Connection::new())` plus `classify` runs every
  §4.2.1 check against the head the General pump produced, touching neither that
  pump's connection nor the throwaway one — `classify` advances nothing — so a
  rejection costs a discarded handshake and an acceptance is the go-ahead to
  transition for real. Discarding it is REQUIRED rather than tidy: a refused head
  spends the one request that handshake is offered.
- **`ServerHandshake::classify`**: validates the request head the CALLER read,
  where `handle` reads one itself. Nothing binds a borrowed head to a connection
  at compile time, so the binding is stated at RUNTIME:
  `Connection::head_binding` is asked ahead of every §4.2.1 check, and a
  `Mismatch` — a head that armed some OTHER connection, or a connection armed by
  RFC 9110 §9.3.6's CONNECT — is refused with `HeadMismatch`. `NoHandshake`
  PROCEEDS rather than refusing, which is what keeps the pre-validation recipe
  above working, and `accept` refuses a 101 on such a connection anyway. Three
  content checks stand behind the binding, and on the throwaway path, where no
  identity check runs, the first two are the WHOLE of the protection. Two restore
  §4.2.1 items the native path proves as it reads the head — item 1's HTTP/1.1
  floor, which RFC 9110 §7.8 makes a MUST by making an HTTP/1.0 `Upgrade` field a
  MUST-ignore, and item 4's `Connection` naming `upgrade`. The third is §7.8's
  outstanding `100 (Continue)`, and it is ONE-DIRECTIONAL: a connection owing one
  against a head that states no such expectation is a mismatched pair, while the
  converse is a conforming sequence — an interim sent on the General connection
  before the transition discharges the obligation and leaves the answer owed.
- **`ClientHandshake::with_connection`**: opens the handshake on a connection the
  caller transitioned. It and `new` are two callers of one private validation
  path, so neither entry point can grow a gate the other lacks. It checks the
  connection itself not at all: `TunnelPhase` is crate-private to `http1-proto`,
  so this crate cannot read whether a handshake is already outstanding on the
  connection it was handed — and none is needed, since `open_upgrade` refuses
  such a connection when `encode_request` reaches it, which is where the bytes
  would have been written and where the caller can act on it.
- **`pub use http1_proto`**: the h1 handshake surface NAMES that crate's types —
  `adopt` takes a `Connection<Server, Tunnel>`, `classify` a `HeadView`,
  `with_connection` a `Connection<Client, Tunnel>` — and a type a caller cannot
  name is one it cannot build an argument out of. Reaching them through here is
  also what makes them the SAME types: a downstream that depends
  on `http1-proto` directly agrees with this crate only while the two version
  requirements resolve to one crate, and the day they do not, the two
  `Connection`s are distinct types printed with the same name. A doctest builds
  `adopt`'s argument entirely through this path, so a version split stops
  compiling instead.
- **Five `ServerHandshakeError` variants**: `UnsupportedHttpVersion`, the head
  is not HTTP/1.1 — distinct from `UnsupportedVersion`, which is §4.2.1 item 6's
  `Sec-WebSocket-Version` and is answered with a 426, since there is no HTTP
  version to advertise back; `ExpectationMismatch`, the connection owes a
  `100 (Continue)` while the head states no such expectation, so the two describe
  different requests; `HeadMismatch`, the head is not the one the adopted
  connection read — either a head that armed some other connection, or a
  connection armed by RFC 9110 §9.3.6's CONNECT, which made no §7.8 offer for any
  head to be; `NotARequestHead`, the head begins with no RFC 9112 §3
  request-line, of which a view of a RESPONSE head is the reachable case, kept
  distinct from `HeadMismatch` because a status-line head handed to a connection
  holding nothing raises no binding question at all; and `AlreadyClassified`,
  below.

### Changed

- **A handshake is offered its one request exactly once** — whichever entry point
  offers it, and WHATEVER the outcome. `handle` and `classify` read one latch,
  and both spend it on the ATTEMPT rather than on success: the connection was
  armed with its one request before the handshake existed, so a head that fails a
  check is definitively not that request, and the next head has no better claim
  to being it. A second request offered to either now answers
  `AlreadyClassified`, which is a NEW answer on paths that previously gave a
  lower-layer error or none at all — a second `handle`, which fell through to
  `http1-proto`'s own narrower guard against a connection that is no longer idle;
  `handle` after `classify` and `classify` after `handle`, which cross entry
  points and were caught by neither; and a request this layer REFUSED, a generic
  upgrade or RFC 9110 §9.3.6's CONNECT, which left the offer open on a connection
  `http1-proto` had already armed. Answering a second head would pair a
  `Sec-WebSocket-Accept` with a request the client did not make, which §7.8
  forbids, and would set it beside whatever RFC 6455 §4.2.2 grants an earlier
  head had settled. A `NeedMore` and a `Closed` consumed no request, so neither
  spends the offer. On error the handshake survives and stays reject-only, so
  §4.2.1's "return an HTTP response with an appropriate error code" is still
  writable — but a corrected pairing needs a fresh handshake.

## `http1-proto` — cycle 5 (Sans-I/O HTTP/1.1 core)

A hand-rolled Sans-I/O HTTP/1.1 message and connection core — no_std +
no-alloc capable, with no buffer, clock, or allocator of its own. PR1 of the
cycle: the standalone crate. PR2 re-bases `websocket-proto`'s h1 handshake onto
it.

### What it is

- **Scope**: RFC 9110 / RFC 9112 as a complete message and connection layer —
  grammar, both start lines, a resumable bounded head scanner, the §6.3 body
  framing decision list, counted / chunked / read-to-close bodies, validated
  encoders, and a connection state machine for both roles. Not a router, a URI
  resolver, a cache, or a content codec: it reports what the message says and
  refuses what the RFCs make unframable.

### Codec leaves (panic-free)

- **Grammar** (RFC 9110 §5.6): `token` / `field-value` over raw bytes
  (`field-vchar = VCHAR / obs-text`, interior SP/HTAB, OWS-trimmed, CTLs
  rejected), the RFC 3986 target validators, the §5.6.1 list splitter, and
  `parameterised_list` — the §5.6.6 `#`-list walk that crosses a §5.2 field-line
  join without materialising it. That walk has **no consumer in this workspace**:
  it was added for `websocket-proto`'s `Sec-WebSocket-Extensions`, which turned
  out to need RFC 6455 §9.1's own grammar instead (see that crate's *Fixed*
  below). It stays because it is the right reading of the fields §5.6.6 actually
  governs — `Accept`, `Content-Type`, `Forwarded`, a `Transfer-Encoding` with
  parameters — which is what an HTTP core is for, and because it is the one place
  the join-crossing rule is implemented.
- **Start lines** (RFC 9112 §3, §4): all four §3.2 request-target forms with
  method pairing; single-SP separators only; case-sensitive `HTTP-version`,
  higher 1.x minor processed as 1.1 (RFC 9110 §6.2), other majors → 505.
- **Head scanner** (RFC 9112 §2.1, §5): **resumable** — it carries a watermark
  rather than restarting, so a head arriving one byte at a time is O(N) not
  O(N²). `MAX_HEAD_BYTES = 16384`, `MAX_HEADERS = 64`, and at most 4 leading
  empty lines server-side; an over-long request-line is 414, an over-large
  field section 431.
- **Lazy head view**: fields walked out of the borrowed block on demand — no
  table, no copies — with case-insensitive lookup and repeated-line iteration.
- **Chunked** (RFC 9112 §7.1): overflow-guarded `1*HEXDIG` size, no whitespace
  after it, `1*("0")` last-chunk, grammar-checked `chunk-ext` under a 256-byte
  per-line cap, trailer section surfaced separately and never merged.
- **Encoders**: heads and chunk framing written into a caller slice with exact
  sizing, no partial writes, and refusal of anything a parser would reject.

### Connection state machine

- `Connection<Client | Server, General | Tunnel>`: the mode is a **compile-time
  type-state**, not a runtime flag — a General connection cannot be asked to
  switch protocols, and a Tunnel connection cannot be asked to stream
  exchanges.
- **General**: `handle(input) -> Items` lends borrowed
  `Item::{Head, BodyChunk, Trailer, ExchangeComplete, ExpectContinue}` naming
  their `ExchangeId`; the core holds no buffer, so `Items::consumed()` is the
  driver's cursor into its own append-only accumulation. Keep-alive re-arm,
  pipelining tolerance (RFC 9112 §9.3.2), 1xx interim, `Expect: 100-continue`,
  HTTP/1.0 fallback, close-delimited responses, §9.6 draining.
- **Readiness split**: `wants_read()` / `is_awaiting_send()` — the two disjoint
  answers to why the items ran out, which `Ok(None)` alone cannot give.
- **Send side**: `open_request`, `send_response`, `send_interim`, `send_body`,
  `finish_body`, and the single RFC-mandated `send_error_response` owed after a
  violation (injects `close`, refuses a contradicting caller field). RFC 9112
  §3.2's `Host` is enforced outbound as well as inbound: every request path
  (CONNECT included) refuses a section that states none, and writes nothing.
- **Tunnel**: one switch — RFC 9110 §7.8 `Upgrade` or §9.3.6 `CONNECT`, at
  either end — reporting the **leftover** that belongs to the new protocol, and
  enforcing a 100 before a 101 when both were asked for.
- **Errors**: a byte offset on every violation and a `SuggestedStatus`
  (400 / 414 / 431 / 501 / 505) wherever a server would answer.

### Tiers

| Cargo features | Heap | Target |
|---|---|---|
| `default` (`std`) | yes | any std platform |
| `alloc` | yes | WASM, embedded with allocator |
| `no-atomic` | yes (no atomic CAS) | `thumbv6m-none-eabi` |
| _(none)_ | **no** | `thumbv6m-none-eabi`, `thumbv7em-none-eabihf` |

### Tooling

- **no-panic link test** (`tests/no_panic.rs`): shims over `find_head_end`,
  `parse_status_line` and `parse_chunk_size`, plus four release smokes.
  Requires `--release` **and fat LTO** — the shims call across the crate
  boundary, so the default thin-local LTO false-positives on all of them; CI
  sets `CARGO_PROFILE_RELEASE_LTO=fat` on that step.
- **httparse differential oracle** (`tests/differential.rs`): never more
  permissive than `httparse`; every divergence adjudicated in-file and the
  allowlists checked for stale entries.
- **Request-smuggling corpus** (`tests/smuggling.rs`): each named vector, accept
  and reject side.
- **Split-robustness property** (`tests/split_robustness.rs`): where the
  transport cut the stream cannot change what the connection says about it, over
  one shot / byte-at-a-time / every single cut / proptest multi-cut vectors.
- Green on every tier and under `cargo hack test --each-feature`; the suite is
  enumerated in `http1-proto/CHANGELOG.md`. No total is quoted here: the figure
  this line used to carry (254) was 133 short of the measured suite, because a
  count is invalidated by every commit that adds a test and nothing checks it.

## `websocket-proto` 0.2.0 — cycle 5 (h1 handshake re-based onto `http1-proto`)

PR2 of the cycle. websocket-proto's private HTTP/1.1 layer is deleted and both
h1 handshakes are rebuilt on `http1-proto`'s Tunnel API, so the split between
the two crates is the split between the two specifications: `http1-proto` owns
HTTP — head grammar and caps, RFC 9112 §3.2's `Host` and request-target rules,
RFC 9110 §7.8's upgrade offer and the 101 that answers it, and the leftover
handoff — and this crate keeps only what RFC 6455 adds on top: the
`Sec-WebSocket-Key`/`-Accept` SHA-1, the version check, subprotocol and
extension negotiation, and the §4.2.1.1 resource-name policy. `RequestView`'s
inline 64-entry header table (~2 KB) is replaced by the borrowed `HeadView`.

### Breaking

- **The handshakes are stateful, one instance per handshake.** Every method that
  drives the connection — `handle`, `encode_request`, `encode_response`,
  `encode_rejection` — takes `&mut self` and ADVANCES it, so `handle` is no
  longer replayable and a driver that used to re-parse the head must carry the
  handshake instead. `ServerHandshake` is no longer `Copy`/`Clone`/`Default` and
  `ClientHandshake` is no longer `Clone` (`http1_proto::Connection` is not
  `Clone`).
- **Answering a request splits in two, and the answer never leaves the
  handshake.** The head's borrow ends before the driver decides, so RFC 6455
  §4.2.2's request-bound checks — the chosen subprotocol was offered, the
  deflate grant is one this request legalizes — run in the new
  `PendingUpgrade::validate_accept(&accept)` while the view is alive. It returns
  `Result<(), ServerHandshakeError>` and stores what it settled INSIDE the
  handshake; `ServerHandshake::encode_response(&extras, out)` takes no answer
  argument and returns `(usize, Negotiated)`, writing the subprotocol and the
  extension grant out of that stored answer. A handshake that validated nothing
  answers with the new `ServerHandshakeError::AnswerNotValidated`, so there is no
  unvalidated path to a 101.
- **`AcceptDecision` is gone, and so is the request argument.** Both halves of
  the pairing used to be values a caller held: an owned decision between the two
  calls, and the classified `RequestView` handed to `validate_accept`. Both were
  policed by COMPARING the request's `Sec-WebSocket-Key`, which is data the PEER
  chooses — a client may send one key on two concurrent requests (§4.1 asks for a
  randomly selected value, which binds a conforming client and not a hostile
  one), and the comparison then passes: A's subprotocol and A's extension grant
  written into the 101 answering B, whose client offered neither, with every call
  returning `Ok`. Deleting the pairable objects deletes the pairing rather than
  policing it. The answer lives in the handshake that validated it, and
  `ServerHandshake::handle` now yields a `PendingUpgrade` that holds its
  handshake by mutable borrow next to the view — `validate_accept` is a method on
  it and takes no request. No function in the crate accepts a `RequestView`, so
  answering one exchange out of another's offers does not compile
  (`PendingUpgrade`'s `compile_fail` proofs), and one handshake cannot hold two
  pending upgrades at once. `ServerHandshakeError::MismatchedRequest` is gone
  with the comparison it named.
- **Extra response headers move off `Accept` and onto `encode_response`.**
  `Accept::with_extra_headers` is gone; `Accept` now carries only the
  request-bound half of an answer (the subprotocol and the grant). Nothing
  about an extra header depends on the request — the checks are token names,
  field-value bytes, and no collision with a managed field — so they are
  supplied and validated where the answer is written. Pass
  `&ExtraHeaders::new()` when there are none. This is what keeps the decision
  free of borrows; the rejection path is unchanged
  (`Rejection::with_extra_headers` stays).
- `handshake::h1` now re-exports `InvalidOptionsDetail`. It was a `pub` type
  reachable only through an error variant, so no downstream crate could name it
  and rustdoc had nothing to link.
- `ServerProgress::Request(view)` is now `Upgrade(PendingUpgrade)`, whose
  `request()` hands out a `Copy` of the view and whose `leftover()` is whatever
  the client pipelined behind the head. `ServerProgress` carries the handshake's
  borrow as a second lifetime, `ServerProgress<'h, 'a>`. The new
  `ServerProgress::Closed` is "the peer closed WITHOUT sending a request";
  closing part-way through one stays an error.
- `RequestView::{origin, header}` return `&[u8]` rather than `&str` — RFC 9110
  §5.5 admits `obs-text` in a field value, so bytes are what the head layer can
  honestly hand over — and `extensions` yields the raw `Sec-WebSocket-Extensions`
  field lines rather than parsed `&str` entries, and is no longer `deflate`-gated.
  `consumed()` is gone (the offset is `PendingUpgrade::leftover`);
  `method()`, `target()` and `head()` are new. `method`, `target`, `path`,
  `query`, `host` and `subprotocols` stay `&str`: each is validated ASCII by
  construction.
- `ClientHandshakeError::UnexpectedStatus(u16)` is gone, and a refusal is not an
  error at all: `ClientProgress` gains `Refused { status, consumed }`. A server
  that will not switch is the peer ANSWERING, and RFC 6455 §4.1 sends the caller
  to "HTTP procedures" for it — "the client might perform authentication if it
  receives a 401 status code; the server might redirect the client using a 3xx
  status code" — which read `WWW-Authenticate` and `Location`. A status code
  alone cannot even locate those fields, so the outcome carries the offset its
  head ended at and the caller hands `data[..consumed]` to whatever HTTP client
  it already has.
- `ClientProgress` also gains `Interim { status, consumed }` (see *Fixed*).
- The `Head(HeadError)` variant on both error enums is now
  `Http(http1_proto::Error)`, and `handshake::{HeadError, MalformedDetail}` are
  no longer re-exported — name `http1_proto`'s directly.
  `ServerHandshakeError::NotHttp11` is gone with them: an HTTP/1.0 upgrade
  request is still refused (RFC 9110 §7.8's `Upgrade` is not honoured below
  1.1), but the verdict is `http1-proto`'s and arrives as `Http(_)`.
- `derive_more::TryUnwrap` is gone from `ServerProgress` and `ClientProgress`;
  match instead. The derive cannot generate one for a struct variant, and on
  `ClientProgress` it was actively dangerous: `try_unwrap_complete()` routes
  `Interim` into the "not yet" arm, so a driver using it re-reads the same head
  forever. `IsVariant` stays on both, and both error enums keep `TryUnwrap`.
- `negotiation::{accept_deflate_offer, parse_deflate_response}` take `&[u8]`
  values rather than `&str`: RFC 6455 §9.1 lets an extension parameter value be
  a quoted-string and RFC 9110 §5.5 admits `obs-text`, so `&str` at this seam
  was either lossy or fallible at the wrong layer. Subprotocols are tokens
  (§4.2.1.8) and stay `&str`.
- `negotiation::select_subprotocol` returns the matching element of `supported`
  rather than of the client's offers, so the selection outlives the request
  head. Its lifetime follows the ENTRIES rather than the slice holding them, so
  a caller that collects its supported names into a temporary keeps a selection
  that outlives the collection. Selection ORDER is unchanged — the offers are
  walked in client preference order.
- The head cap is `http1-proto`'s 16 KiB rather than this crate's 8 KiB.

### Added

- `ServerHandshake::handle_eof` and `ClientHandshake::handle_eof`: the
  transport's read side ended. Idempotent, and they decide nothing on their own
  — the next `handle` resolves the offer that ran out.
- `h1::MAX_SUBPROTOCOL_OFFER_BYTES` (512): how much the client's offers may
  measure once comma-joined into the one `Sec-WebSocket-Protocol` field value.
  Seven offers at `negotiation::MAX_SUBPROTOCOL_LEN`, twenty-five at the lengths
  RFC 6455 §11.5's registered names run to, a hundred and seventy-one at the
  one-byte floor. See *Fixed*.
- `negotiation::MAX_SUBPROTOCOL_OFFERS` (64) and
  `negotiation::MAX_SUBPROTOCOL_LIST_BYTES` (16384): how many offers, and how
  many bytes of them, either server will READ — and, mirrored at both emitters,
  how many either client will write. The first cannot be lower than the sixty
  `sixty_subprotocol_offers_round_trip_through_our_own_server` pins and is
  `http1_proto::MAX_HEADERS`; the second is `http1_proto::MAX_HEAD_BYTES`, so on
  h1 it refuses nothing the head cap did not already. See *Fixed*.
- `connect::ConnectRequestView::origin` and
  `connect::ConnectRequestError::DuplicateOrigin`. See *Fixed*.
- `negotiation::MAX_EXTENSION_VALUE_BYTES` (160): how large a buffer holds any
  `Sec-WebSocket-Extensions` value this crate RENDERS, which is what
  `DeflateOffer::write` and `DeflateResponse::write` want to be called with —
  128 bytes at the widest, pinned by
  `the_widest_rendered_extension_value_fits`. It was four separate numbers (both
  h1 scratches, both extended-CONNECT views' inline buffers, and the re-render
  behind the server-side grant check), three named apart and the fourth an
  anonymous literal; naming it once is why there is no fifth to drift. It does
  NOT bound a value a PEER sends — that one is bounded by the transport's own
  head cap and read in place.

### Documented

- **The head limits an extra header is read under are the RECEIVING peer's**,
  and they are now stated where a caller sets one:
  `h1::ClientOptions::with_extra_headers`,
  `h1::ServerHandshake::encode_response` and `h1::Rejection::with_extra_headers`
  each name `http1_proto::MAX_HEADERS` (64 field lines) and
  `http1_proto::MAX_HEAD_BYTES` (16 KiB), and how many lines the managed
  handshake fields already spend. Neither emitter bounds its own head, and that
  is deliberate — a large head violates nothing, and refusing to write one a
  lenient peer would accept is a rule no RFC has — but sixty extra request
  headers is sixty-five field lines against a sixty-four-line cap, and a caller
  met that as an error from the far end with nothing in the documentation to
  explain it.

### Fixed

- **Interim 1xx responses are parsed instead of failing the handshake.** The old
  client mapped a `100 Continue` prefix to `UnexpectedStatus(100)`, which RFC
  9110 §15.2 forbids: "A client MUST be able to parse one or more 1xx
  responses received prior to a final response". `ClientProgress::Interim`
  reports which one arrived AND how far the buffer advanced past it — a driver
  told only that an interim arrived cannot advance, so it re-offers the same
  head and reads it forever.
- **An extension offer can no longer be fabricated out of a quoted string.**
  `Sec-WebSocket-Extensions` is walked with a quoted-string-aware parser that
  splits only on the commas and semicolons OUTSIDE a quoted-string. The previous
  `str::split` splitter cut inside quoted strings and read their CONTENT as list
  members, so a peer that never offered permessage-deflate could have it
  negotiated — and then be sent RSV1-compressed frames it never agreed to.
  Demonstrated against the old code with
  `x-note; v="a,permessage-deflate;client_max_window_bits=8,b"`, and pinned by
  `an_offer_cannot_be_fabricated_from_inside_a_quoted_string`.
- **A malformed `Sec-WebSocket-Extensions` field fails the handshake.** RFC 6455
  §9.1: "If a value is received by either the client or the server during
  negotiation that does not conform to the ABNF below, the recipient of such
  malformed data MUST immediately _Fail the WebSocket Connection_." Both h1
  handshakes and both extended-CONNECT gates used to read the field only to
  negotiate with, so an unreadable offer yielded no grant and a 101 all the
  same — the freedom §9.1 gives a recipient to DECLINE an extension is about one
  it does not want, not about data it cannot read. The new
  `negotiation::extension_list_conforms` is the gate, and it runs on every
  handshake carrying the field, on both sides, whatever extensions the build
  supports: `ServerHandshakeError::MalformedExtensions`,
  `ClientHandshakeError::MalformedExtensions`,
  `ConnectRequestError::MalformedExtensions`,
  `ConnectResponseError::MalformedExtensions`. The server's refusal is
  reject-only, so §4.2.1's "HTTP response with an appropriate error code" still
  goes out. Two consequences of the ABNF: a quoted value whose unescaped form is
  not a `token` is malformed, and so is a value that spans an RFC 9110 §5.2
  field-line join — the join's comma lands inside it and a comma is not a
  `tchar`. And a semicolon with nothing behind it — `permessage-deflate;`,
  `permessage-deflate;;client_max_window_bits` — is malformed too: what `[ … ]`
  makes optional in `extension-param = token [ "=" (token | quoted-string) ]` is
  the value, not the parameter, RFC 2616 §2.1's implied *LWS rule puts whitespace
  between productions rather than removing one, and the null elements §2.1's
  `#rule` does permit are list elements rather than parameters. Pinned from both
  ends by `a_malformed_extension_list_fails_the_handshake`.
- **`Sec-WebSocket-Extensions` has ONE parser, and it is RFC 6455 §9.1's.** The
  gate above and the negotiation behind it briefly read two grammars — the gate
  §9.1's, the readers `http1_proto::grammar::parameterised_list`'s RFC 9110
  §5.6.6 — on the argument that a divergence could only decline an extension,
  never grant one. That is true of the OFFER path and false of the RESPONSE
  path: RFC 7692 §8.1 makes an extension response the client will not accept
  FAIL the connection, so "declined" there means "handshake refused". §9.1 states
  its ABNF "including the 'implied *LWS rule'", so a conforming server may write
  `permessage-deflate ; server_max_window_bits = 11` — the gate passed it and
  `parse_deflate_response` then rejected it, on the h1 client and on the
  extended-CONNECT client alike. The gate's §9.1 walk now YIELDS the members and
  parameters it was already traversing, and `extension_list_conforms`,
  `accept_deflate_offer`, `parse_deflate_response` and the server-side grant bind
  all consume it; websocket-proto no longer uses `parameterised_list` at all (see
  the http1-proto note above for why the walker stays). The walk is line-local,
  which for this grammar is the same question as the joined value: a member spans
  §5.2's join only inside a quoted-string, and such a string is malformed either
  way. Pinned by
  `a_response_written_with_implied_lws_completes_the_handshake` (h1) and by
  `connect_gates_enforce_the_extension_grammar` (extended CONNECT).
- **RFC 9110 §7.8's ordering MUST is honoured.** When the upgrade request
  carried `Expect: 100-continue`, `encode_response` writes the `100 (Continue)`
  ahead of the 101 into the same buffer; a short buffer leaves the obligation
  outstanding rather than discharging it against bytes the caller must not send
  (`a_hundred_continue_precedes_the_switch`,
  `a_short_buffer_does_not_lose_the_hundred_continue`).
- **An extended CONNECT refuses an ambiguous `Origin`, and the client cannot
  write one.** RFC 8441 §5 carries `Origin` onto the h2/h3 transports in as many
  words — "The Origin [RFC6454], Sec-WebSocket-Version, Sec-WebSocket-Protocol,
  and Sec-WebSocket-Extensions header fields are used in the CONNECT request and
  response-header fields as defined in [RFC6455]" — and RFC 6454 §7 gives it one
  SP-separated `origin-list-or-null`, so RFC 9110 §5.3 forbids repeating it. The
  gate now refuses a repeat as `DuplicateOrigin` (reject-only, so the caller
  still answers), `ConnectRequestView::origin` resolves it, and `origin` is out
  of the first-occurrence escape hatch on BOTH transports: `header("origin")`
  routes back through the accessor, so the two cannot answer differently even
  below a gate. The outbound half is the same defect from the other side — the h1
  client could put two `Origin` extras in a request its own server then refused —
  and `ExtraHeaders::validate` now refuses a repeated extra header for the names
  this crate itself resolves as singletons: `Origin`, plus `Host`,
  `Sec-WebSocket-Key` and `Sec-WebSocket-Accept`, which the managed-collision
  check already refuses outright. Every other name may still repeat, because RFC
  9110 §5.3's exception covers every field "definition \[that\] allows multiple
  field line values to be recombined as a comma-separated list" — an open set
  that includes `Cache-Control` and `Via`, so refusing by default would break
  conforming layouts. `Sec-WebSocket-Version` is deliberately absent for the same
  reason: the only extras that may carry it are a rejection's, and RFC 6455
  §11.3.5 makes it one that "MAY appear multiple times in an HTTP response"
  (`a_repeated_origin_is_refused_on_extended_connect`,
  `the_two_transports_agree_on_the_origin_rule`,
  `the_escape_hatch_does_not_answer_a_resolved_field`,
  `an_extra_header_may_not_repeat_a_singleton_field_name`,
  `a_rejection_may_advertise_several_versions_but_not_two_origins`,
  `what_the_client_emits_our_own_server_accepts`).
- **The offer-uniqueness scan is no longer quadratic in a peer's input.** The
  offers "MUST all be unique" (RFC 6455 §4.1 item 10) and this crate allocates
  nothing, so uniqueness is proved by re-walking the value once per offer —
  Θ(offers × bytes) over input an unauthenticated peer chooses. A 16 KiB head of
  one-byte offers cost **22.8 ms and was ACCEPTED**; extended CONNECT passed the
  same function a header slice with no length of its own at all. Both halves are
  now bounded inside the one function both gates call, and mirrored at both
  emitters so nothing this crate writes is something it refuses to read. The
  worst input either server now accepts costs **371 µs**, and the 16 KiB dense
  head is refused in 13.8 µs. RFC 9110 §5.4 is what licenses the bound — a
  server refuses a "request header field line, field value, or set of fields
  larger than it wishes to process" with a 4xx, which is what a reject-only
  handshake writes. (§5.6.1.2's denial-of-service clause governs EMPTY list
  elements, which this bound does not count and does not limit; citing it here
  was the misattribution `MAX_TAGS` later shed.) (`the_offer_list_is_bounded`,
  `the_offer_count_is_bounded_by_what_our_own_server_reads`,
  `the_offer_count_bound_is_the_same_in_both_directions`,
  `the_offer_count_bound_is_symmetric_on_both_transports`).
- **The client's subprotocol offers are one field line again.** The re-base
  emitted one `Sec-WebSocket-Protocol` field LINE per offer, so sixty one-byte
  offers made a sixty-five-line head — and `http1-proto`'s own server, the one
  behind `ServerHandshake` and behind both drivers, refuses a head past
  `MAX_HEADERS = 64`. Configurations that round-tripped before the re-base failed
  after it, on every path. RFC 6455 §4.1 item 10 spells the offer as "one or more
  comma-separated subprotocol", and that is what goes out: `ClientHandshake::new`
  joins the offers ONCE, in the pass that already validated them, into an inline
  buffer the `Headers` walk only reads — which is what keeps the section
  walk-stable without a line per offer. The accidental field-count cliff at the
  peer becomes the documented byte limit `h1::MAX_SUBPROTOCOL_OFFER_BYTES` (512),
  and a longer list is refused by `ClientHandshake::new` with the limit named
  (`subprotocol_offers_travel_as_one_bounded_field_line`,
  `sixty_subprotocol_offers_round_trip_through_our_own_server`, and one test per
  driver).

### Changed

- An HTTP/1.0 status line is accepted rather than refused outright, and a higher
  1.x minor is processed as 1.1 (RFC 9110 §6.2).
- Up to four leading empty lines before a request are tolerated (RFC 9112 §2.2).
- A `Sec-WebSocket-Extensions` member the walk cannot resolve ENDS the walk —
  past a value §9.1's grammar does not admit, nothing behind it is what the peer
  wrote — where the old splitter skipped that element and kept looking. An offer
  behind a malformed member is therefore not granted
  (`an_offer_behind_an_unresolvable_member_is_not_granted`). This fails closed:
  declining an extension is always available to a server (RFC 7692 §7.1.1), so
  the handshake still completes, just without compression.

### Tooling

- **Handshake differential harness** (`handshake-corpus`, driven by
  `cargo run -p xtask -- handshake-diff <base> [head]`): 1967 cases over the five
  handshake surfaces — the h1 server and client, the extended-CONNECT gate on
  both sides, and the two EMITTERS read back by this crate's own gate — each
  reporting the verdict a build reaches for it. `xtask` builds the corpus (one
  file, always the working tree's, public API only) against two revisions of
  `websocket-proto` and diffs the records, so a verdict that moved is the
  revision range's doing and nothing else's. It reports them grouped by
  `(role, field, reason)`.
- 165 of the cases' groups are **equivalence groups**: one logical field value
  written several ways (RFC 9110 §5.2/§5.3, RFC 6455 §9.1's "MAY be split or
  combined across multiple lines", RFC 2616 §2.1's null elements), which must all
  reach one verdict. A group that disagrees is a reader making a distinction the
  grammar does not — the defect found three times in this cycle, always between a
  gate and a reader that resolved one field separately — and one on the head side
  fails the command. The claim is withheld exactly where the ROLES make the
  distinction: the response `Sec-WebSocket-Protocol` is §4.2.2's single
  selection, and `Origin` is RFC 6454 §7's SP-separated `origin-list-or-null`,
  so neither has a split spelling.
- Measured over this branch: `3b13c5d..HEAD` moves 204 verdicts and takes the
  equivalence violations from 8 to 0; `90d1d1e..HEAD` — the last two commits —
  moves 117 and holds them at 0. Earlier revisions are out of reach: the corpus
  is written against the public API, and `ServerProgress::Upgrade` was a struct
  variant before `3b13c5d`.

## `wren-compio` + `wren-reactor` — cycle 5 (re-based handshake drivers)

Both drivers follow `websocket-proto` 0.2.0's two-phase accept: the pending
accept carries an advanced `ServerHandshake`, which holds the validated answer
itself, so the application's accept-or-reject choice happens between
classification and the answer, and either answer is written through the
connection that read the request — with nothing beside it that could be paired
with a different one.

### Fixed

- **A handshake the server stops processing is answered, not dropped.** RFC 6455
  §4.2.1: "the server MUST stop processing the client's handshake and return an
  HTTP response with an appropriate error code (such as 400 Bad Request)".
  `accept`/`accept_pending` used to propagate the fault and drop the transport
  with nothing on the wire, leaving the client unable to tell a rejected
  handshake from a dead server. A version the server does not speak now gets RFC
  6455 §4.2.2's 426 carrying `Sec-WebSocket-Version: 13`; anything else gets 400,
  or the code `http1_proto::Error::suggested_status` names for an HTTP-level
  fault. Best-effort by construction: the error returned is always the one that
  failed the handshake, never one from writing the refusal — the caller needs to
  know why the handshake failed, not that the apology could not be delivered. A
  `validate_accept` failure is deliberately NOT answered this way: the answer was
  built from this request's own offers, so a fault there is the server refusing
  its own answer rather than the client's handshake being invalid.
- **Interim responses no longer grow the client's buffer without bound.** The
  client loop advanced a cursor past each consumed 1xx head and never dropped
  what it had passed, while later reads kept appending — and RFC 9110 §15.2 puts
  no limit on how many interim responses may precede the final one, so a hostile
  server could stream 1xx heads until the client exhausted memory. The consumed
  prefix is now dropped after each interim (the suffix glued behind it, when one
  read carried both, is preserved), which bounds the buffer at one head plus one
  read chunk.
- **…and the reading stops.** Compacting bounds the memory that stream costs,
  not the work: a server can still send interim responses forever, and a client
  that obeys §15.2 literally never returns — a connect hung with nothing to
  report, and neither driver applies a handshake deadline. Both now abandon the
  attempt after 32 interim responses with the new
  `ConnectError::TooManyInterimResponses { limit }`. 32 is set against what a
  conforming server sends (RFC 9110 §10.1.1 allows one `100 (Continue)` per
  request; RFC 8297's `103 (Early Hints)` arrives once or a small handful of
  times), so it bounds a hostile peer's work at 32 heads without touching any
  real pattern. It is a driver policy, not a protocol rule: `websocket-proto`
  classifies one head per call and has no loop to bound.

## `http3-proto` — cycle 4 (Sans-I/O HTTP/3 tunnel core)

A novel hand-rolled Sans-I/O HTTP/3 Extended-CONNECT tunnel core for Rust —
no_std + no-alloc capable, zero external runtime dependencies on the bare tier.

### What it is

- **Scope**: the RFC 9114 / 9204 / 9220 subset needed to carry a tunneled byte
  stream (WebSocket or arbitrary protocol) over QUIC — not a general HTTP/3
  implementation. The core stays HTTP-status-agnostic and WebSocket-agnostic: it
  reports the peer's HEADERS as `Frame::Request` / `Frame::Response` and leaves
  validation of `:status` / `:protocol` to the driver.

### Codec leaves (panic-free, fuzzed)

- **QUIC varint** (RFC 9000 §16): 1/2/4/8-byte encode/decode with zero
  arithmetic side-effects.
- **HTTP/3 frame header** (RFC 9114 §7.1): type + length varint pairs;
  `decode_header` / `encode_header`.
- **Static-table-only QPACK** (RFC 9204): field-section encode/decode with the
  dynamic table permanently disabled (matching the WS-tunnel scope). `decode_field_section_into` (no-alloc, caller scratch) and `decode_field_section`
  (std/alloc, owned scratch). A lending iterator yields `Pair { name, value }`
  per call with raw/static borrows or Huffman decoding into the scratch.
- **SETTINGS codec** (RFC 9114 §7.2.4, RFC 9204 §5, RFC 9220 §3): encode/decode
  the small SETTINGS payload carried on the control stream preamble.

### Connection state machine

- `Connection<Client>` / `Connection<Server>`: Sans-I/O state machine generic
  over the role marker. No I/O, no clocks, no async.
- **Setup**: `open_with` (client) / `start` (server) enqueue the control stream
  (type byte + SETTINGS frame), two idle QPACK uni-streams (encoder + decoder),
  and (client only) the bidirectional request stream with the CONNECT HEADERS
  frame. The driver pumps `poll_transmit` and opens the streams, reporting each
  assigned id via `provide_stream`.
- **Receive**: `handle_stream(id, bytes, scratch)` routes inbound bytes by
  stream id — control stream (accumulate + parse SETTINGS), QPACK streams (idle
  after type byte), unknown uni-streams (classify by leading type varint,
  buffered across calls), or request stream (HEADERS decode + DATA relay). The
  request stream yields a lending `Frames` iterator; all other streams yield
  nothing.
- **Events**: `poll_event` drains `Event::{Established, PeerClosed, Reset,
  ConnError}` from a fixed-capacity bounded queue (no heap).
- **Transmit ring**: a fixed-capacity, no-alloc ring buffer carries outbound
  transmit slots. `poll_transmit` lends `Transmit { kind, bytes, fin }` one
  at a time; `StreamKind::{OpenUni, OpenRequest, Existing}` tells the driver
  which quinn call to make.
- **Tunnel data + close**: `send_data(payload)` encodes a DATA frame; `close`
  enqueues a FIN on the request stream.

### Tiers

| Cargo features | Heap | Target |
|---|---|---|
| `default` (`std`) | yes | any std platform |
| `alloc` | yes | WASM, embedded with allocator |
| _(none)_ | **no** | `thumbv6m-none-eabi`, `thumbv7em-none-eabihf` |

### Tooling

- **no-panic link test** (`tests/no_panic.rs`): wraps `varint::decode` and
  `frame::decode_header` in `#[no_panic]` shims and verifies panic-freedom at
  link time in release (they are `#[inline]`, so they inline fully into the
  shim where `no-panic` can see them). `qpack::decode_field_section_into`
  panic-freedom is enforced by the crate-wide clippy lint wall
  (`unwrap_used` / `indexing_slicing` / `arithmetic_side_effects` / …) +
  fuzzing — its call-tree depth prevents full inlining into a single shim.
  Enabled via `--features test-no-panic`.
- **Fuzz harnesses** (`fuzz/fuzz_targets/`): four targets —
  `varint_decode`, `frame_decode`, `qpack_decode`, `connection_handle` —
  covering all codec leaf paths and the full connection receive machine with
  arbitrary byte streams.
- **Bare-tier smoke test** (`tests/tiers.rs`): four tests run under
  `--no-default-features` proving the bare tier needs no allocator:
  `open_with` + drain, varint round-trip, frame decode, QPACK decode-into.
- **100 unit + integration tests** across all features (from prior cycles).

## `wren-reactor` — cycle 3 (runtime-agnostic full-duplex driver)

- **`wren-reactor`**: readiness-based WebSocket driver over `websocket-proto`,
  runtime-agnostic across **tokio and smol** (feature-selected) via
  `agnostic-net` / `agnostic-lite`. Client (`connect` over `ws://` / `wss://`,
  or `client` over any `futures::io` stream) and server (`accept`, plus the
  two-step `accept_pending` → inspect → `accept` / `reject` for pre-upgrade
  authorization). **Caller-driven, no background tasks** (tungstenite / soketto
  parity): `WebSocket<R, Ro, S>` owns the proto state machine and the transport
  and implements `futures::Stream` / `Sink` plus convenience methods
  (`send_text`, `send_binary`, `ping`, `close`, the `*_compressed` sends);
  polling `next()` / the `Sink` *is* the pump — it drives pong echoes and the
  close handshake. `split()` yields independently-owned read and write halves
  sharing the connection through a mutex held only across brief, non-blocking
  poll steps and never across a pending I/O, so a stalled write releases the lock
  and reads never head-of-line-block behind it (the limitation `wren-compio`'s
  single pump documented). A single ordered write buffer carries data, pongs, and
  the Close in FIFO order, so a close never overtakes queued data. Sends are
  cancellation-safe (a dropped send never leaves a partial frame and still
  backpressures the next). The write buffer applies *inter-message* backpressure
  (a send waits for it to fall below a soft cap before encoding the next frame, and
  the read pump stops reading while a stalled flush has it over the cap, so neither a
  flooding nor a slow peer grows it without bound); a single message still allocates
  its whole frame, so bound an individual outbound payload caller-side if needed.
  **Liveness, write deadlines, and the close handshake
  are the caller's** — the library is a state machine, not a supervisor, with no
  autonomous timers: bound them with `timeout(next())`, `timeout(send())`,
  `timeout(close())`, a ping loop, or OS TCP keepalive. A send not yet flushed
  when `close` is issued is not guaranteed delivered; await it (or flush) before
  closing. A recorded transport write error poisons the connection and surfaces
  as the real `Io` error on every send path; a peer protocol violation fails the
  connection fast and surfaces as `Error::Protocol(CloseCode)` carrying the code,
  distinct from a transport reset. Features: `tokio` (default), `smol`,
  `tls` (futures-rustls + rustls/ring, webpki roots by default, full
  `TlsConnector` override), `deflate`, `tracing`.

## `wren-compio` + `wren-trace` — cycle 2 (first async driver)

- **`wren-compio`**: compio-native (io_uring / IOCP / kqueue, thread-per-core)
  WebSocket driver over `websocket-proto`. Client (`connect` over `ws://` /
  `wss://`, or `client` over any `IntoDuplex` transport) and server
  (`accept`, plus the two-step `accept_pending` → inspect → `accept` /
  `reject` for pre-upgrade authorization by Origin, Host, path, or auth).
  One direct connection object — no background task: `next()` pumps reads,
  keepalive/close timers, pong echoes, and queued writes. `split()` yields
  read/write halves for ANY stream type (no `Clone` bound) via a
  doorbell-flushed outbound queue; a split writer's sends progress while
  the read half is polled. `next()` and the senders are cancellation-safe:
  the driver runs on a poll-based duplex (completion streams adapt through
  `compio_io::compat::AsyncStream`), so dropping a pump or send future
  mid-await — a caller `timeout` or lost `select!` arm — neither loses
  inbound bytes nor strands the transport, and partial write progress
  resumes on the next call. The close handshake is fully bounded by the
  close timeout (flush, echo wait counted from the flush, and transport
  shutdown each get the budget), protocol replies flush before buffered
  messages are delivered, a peer close only reads as clean once our echo
  is on the wire, and the first write failure poisons the connection
  instead of splicing frames after a partial one. Features: `tls`
  (compio-tls + rustls/ring, webpki roots by default, full `TlsConnector`
  override), `deflate` (transparent inflate on receive,
  `send_*_compressed` senders), `tracing`.
- **`wren-trace`**: the family's zero-cost tracing shim — `tracing`-or-noop
  diagnostic and span macros whose disabled form type-checks but never
  evaluates its arguments.

## `websocket-proto` — cycle 1 (Sans-I/O core)

The first functional cycle of the Sans-I/O WebSocket protocol core. Highlights:

### Framing & connection (RFC 6455)

- Lossless §5.2 frame codec: incremental header decode/encode with canonical
  length enforcement, and in-place payload masking (§5.3).
- Transport-blind `Connection` state machine for both roles (`Client`/`Server`),
  generic over a monotonic `Instant` clock. Receive is a **lending iterator**
  (`handle` → `Events::next`): uncompressed payload chunks borrow the input with
  no copy; protocol-generated frames (pong/close echoes, keepalive pings) are
  queued internally and drained via `poll_transmit`.
- Incremental UTF-8 validation across `handle` calls (§8.1), fragmentation
  sequencing, the close handshake with code/reason validation and a close-timeout
  state, and keepalive pings. Protocol violations fail the connection with the
  prescribed close code rather than returning errors.

### permessage-deflate (RFC 7692)

- Inflate inbound compressed messages inside `Connection`; compressed messages
  surface as ordinary decoded text/binary chunks (text re-validated as UTF-8
  post-inflation). Context takeover, negotiated window bits, and an inflated-size
  cap (1009) are honoured; malformed DEFLATE fails 1007.
- Opt-in `encode_text_compressed` / `encode_binary_compressed` with RSV1, the
  §7.2.1 sync-flush tail stripped, per-message reset under `no_context_takeover`,
  and a graceful `CompressionUnavailable` fallback when deflate is not negotiated
  or the outbound window is below 15 bits.

### Handshakes & negotiation

- HTTP/1.1 opening handshake for both roles (RFC 6455 §4): stateless re-parsing
  request/response validators, subprotocol selection, and permessage-deflate
  offer/accept. Caller-supplied extra headers are passed as an `ExtraHeaders`
  newtype (`ClientOptions` / `Accept` / `Rejection`), with shared token + CR/LF
  validation; the client additionally rejects names that collide with the
  headers it manages.
- RFC 8441 / RFC 9220 negotiation surfaces (the header-data form of the same
  negotiation for WebSocket over HTTP/2 and HTTP/3).

### Tiers, assembly & tooling

- `alloc`-tier `MessageAssembler` folding events into owned `Message::{Text,
  Binary}`, carrying cheap-clone (`O(1)`) payloads — `smol_str::SmolStr` text and
  `bytes::Bytes` binary, exposed as the public `TextBuf` / `BinaryBuf` aliases;
  bare `no_std` (no-alloc) tier supported — the inline subprotocol storage retains negotiation results without any allocator.
- Allocator-free `SliceAssembler` on **every** tier (including bare `no_std`):
  folds events into a caller-provided buffer and yields a borrowed `MessageRef`
  (`Text` / `Binary`); the buffer length is the message-size cap.
- `no-atomic` heap tier for cores without native atomic CAS (Cortex-M0+ /
  thumbv6m / RP2040): the same `Message` / `Negotiated` storage as `alloc`, but
  the refcounted text / binary buffers and negotiated subprotocol use
  `portable_atomic_util::Arc` (clone via a `critical-section` impl the final
  binary provides) instead of `smol_str` + `bytes`. Pick one heap tier; `deflate`
  is not available on this tier (it requires `alloc`). Checked on
  `thumbv6m-none-eabi` in CI.
- Autobahn TestSuite harnesses (`examples/autobahn-server`,
  `examples/autobahn-client`) and an opt-in `autobahn` CI workflow; sections 1–9
  and the §12/§13 permessage-deflate cases pass.
- `no-panic` link-time verification of the core codec leaf paths (frame
  decode/encode, masking, UTF-8, base64), alongside the crate-wide clippy
  panic-freedom lint wall.

### Fixes landed this cycle

- permessage-deflate compressed sends of large/incompressible payloads were
  silently truncated (and corrupted the context-takeover stream for every
  following message) because the compressor's buffered output and sync-flush were
  drained into a fixed, too-small window. The compressor now drains to
  completion; verified against an independent reference decoder and Autobahn
  §12/§13.
- Multiple pings arriving in one `handle` batch now each receive a pong where a
  heap is available (Autobahn 2.10); the bare tier still coalesces to the most
  recent ping (RFC 6455 §5.5.3).
