# UNRELEASED

## `http-semantics` — two shims with one body are one symbol, and one of the two proved nothing

`shim_accept_charset` and `shim_accept_encoding` had identical bodies. The two
entry points are one walk at one element rule — which is a fact about the
grammar and is pinned by a test — and `cloned()` and `copied()` over a `&&[u8]`
lower to the same code, so after optimization the two shims WERE the same
function and the linker folded them. One symbol survived for two shims, and
`shim_accept_encoding`'s `no-panic` guard was never evaluated: its proof was
empty while its own step reported `ok`.

### Fixed

- `shim_accept_charset` folds `is_wildcard` into its answer, which makes it a
  different function from `shim_accept_encoding` and also drives an accessor no
  other shim reaches. `shim-check`'s artifact half now reports
  `http-semantics 21/21`; before it reported `20/21` and named the missing one.

### How it was missed, which is the part worth writing down

`shim-check` prints two lines. The first is the SOURCE half — how many shims are
declared, how many call sites, how many arguments through `black_box` — and it
was green throughout. The second is the ARTIFACT half, which asks the linker
which shims are actually defined in the release test binary, and it was red from
the commit that added the second shim. Three commit messages reported "all
instantiated" on the strength of the first line alone, because the runs were
piped through `head -1` and the exit code went with the pipe rather than with
the command.

That check exists precisely because identical code folding and a deleted call
are the same silence in a symbol table. It caught this. What did not catch it
was reading its output.

## `http-semantics` — the roles this crate serves, as a scope rule and not a note

al8n/wren#70 records two items resting on the ABSENCE of a scope rule: neither
README says whether an intermediary is served, so §7.6.2's `Max-Forwards` and
§7.6.3's `Via` sat in neither the implemented bucket nor the out-of-scope one.
One sentence settles them, and it belongs where a reader looks for scope rather
than at the one value that happens to have raised it.

### Changed

- **`http-semantics`'s README gains a role rule**: this crate serves an origin
  server and a user agent, and an intermediary is out of scope. The rules RFC
  9110 writes for an intermediary alone are STATED where a caller meets the
  value they govern, so a caller acting as one can obey them, and are not
  enforced here. RFC 9110 §12.5.5's "A proxy MUST NOT generate "*" in a Vary
  field value." is named as one such rule; §7.6.2 and §7.6.3 are out of scope by
  the same sentence rather than missing, which resolves #70's two pending items.

  The rule says why enforcing one of them would be worse than stating it:
  shipping a single prohibition while writing no `Vary`, no `Via`, no
  `Max-Forwards` and stripping no hop-by-hop field a §7.6.1 `Connection` names
  gives an intermediary author a floor that is not there. What the crate owes
  such a caller instead is the FACT each rule turns on —
  `negotiation::VaryMember::Wildcard` is that fact for §12.5.5 — so obeying it
  needs no second parse and no reading of the section at the call site.

  It is a rule about ROLES and is explicitly not the membership rule above it:
  an item still belongs here when only an intermediary would read it. What this
  settles is whether a MUST that binds an intermediary is enforced.

- `VaryMember::Wildcard` now reads as the restatement it is, and points at the
  README as where the ruling is settled once.
- `encoding_acceptability` says why it walks the field once per coding asked
  about: answering several candidates in one pass means remembering a weight per
  candidate, which is storage a no-alloc reader cannot grow and would have to
  bound the way `MAX_TRACKED_PARAMS` bounds `weight_for`'s per-instance match.
  These fields hold a handful of members, and a caller that wants one pass has
  `accept_encoding`.

## `xtask` — two gates disagreed about what a citation is, and four correct quotations sat in the backlog for it

`doc-check` requires a comment quoting an RFC sentence with an inline reference
in it to escape the brackets — rustdoc reads a bare `[RFC6455]` as an intra-doc
link and fails the build under `-D rustdoc::broken_intra_doc_links`. The spec
being quoted writes the bare form. `quote-check` then had to agree that those
are the same mark, and it did not.

### Fixed

- **`strip_bracket_insertions` now takes the escape's backslash with the
  bracket.** That function removes a `[bracketed]` span and the space in front
  of it; the escape puts a `\` between the space and the `[`, so the
  space-eating loop stopped at the backslash and left a space the spec's side
  had already dropped. `squeeze` then deleted the backslash and collapsed
  whitespace, which HID the difference whenever a space followed the closing
  bracket and EXPOSED it whenever anything else did.

  **Measured with a probe carrying both positions, on two sentences of RFC 9110
  §12.5.4, before the fix.** A citation mid-sentence — `Section 3 of` the
  escaped reference `defines several matching schemes.` — was reported
  verbatim. The same citation at the end of a sentence — `found in Section 2.3
  of` the escaped reference, then a full stop — failed, printing a comment side
  ending `Section 2.3 of .` against a spec side ending `Section 2.3 of.` One
  space, in one position. A rule that holds for a citation in the middle of a
  sentence and breaks for the same citation at the end of one is worse than
  either answer, because the author who meets it reads the failure as being
  about their words.

  `an_escaped_bracket_is_the_same_mark_as_a_bare_one` drives both positions and
  pins the literal normalised form, so the test cannot pass by comparing two
  identically-wrong sides. The ABNF path is untouched: `[ … ]` is RFC 5234
  syntax there and stays.

### What the fix found

Four quotations of RFC 8441 §5 in `websocket-proto` — its sentence about the
`Origin`, `Sec-WebSocket-Version`, `Sec-WebSocket-Protocol` and
`Sec-WebSocket-Extensions` fields, which carries two bracketed references and
ends one of them with a full stop — were sitting in the untriaged backlog
because of exactly this. One of them is introduced with the word *verbatim*: the
author believed it was, and the gate could not confirm it. All four now grade
verbatim against `.rfc-cache/rfc8441.txt:245`.

`UNTRIAGED` is lowered accordingly, which is what that table asks for when
triage happens: `websocket-proto/src/handshake/connect.rs` from 4 to 1 and
`websocket-proto/src/handshake/fields.rs` from 5 to 4. The workspace backlog
goes from 91 spans to 87, and the one span left in `connect.rs` is the author's
own paraphrase in quotation marks, which is correctly still untriaged.

### Changed

- `http-semantics`'s `accept_charset` carries RFC 9110 §8.3.2's Note in full
  again. It had been shortened past the bracket to get around this defect, which
  is the local move that leaves the next author to rediscover it.

## `http-semantics` — `Vary` is a different shape, and its proxy MUST NOT is stated rather than enforced

RFC 9110 §12.5.5 shares §12.5's subject and none of its machinery.
`Vary = #( "*" / field-name )` brackets no `[ weight ]`, so there is nothing for
§12.4.2 to rank, and its `"*"` is an alternative of the ELEMENT rather than a
name the `token` alternative happens to also derive. It gets its own item type,
its own error type and its own walk, and shares only §5.6.1's list split with
the three ranked readers beside it.

### Added

- `negotiation::vary` — RFC 9110 §12.5.5's `Vary = #( "*" / field-name )` over
  §5.1's `field-name     = token`. It takes a field's lines, yields one
  `VaryMember` per element in wire order, and latches on the first fault.
- `negotiation::VaryMember`, whose two variants are `Wildcard` and
  `FieldName(&str)`; and `negotiation::VaryError`, whose one variant is
  `NotAFieldName`. Both carry `#[non_exhaustive]` where a variant could be
  added.

### The §12.5.5 rule that is stated and not enforced, and the ruling behind it

RFC 9110 §12.5.5: "A proxy MUST NOT generate "*" in a Vary field value." It is
stated at `VaryMember::Wildcard` and nothing checks it. **That is a decision,
not an omission**, and `VaryMember::Wildcard` is where it is written down.

**An intermediary is out of scope for this crate**, which resolves the open
question al8n/wren#70 records. Enforcing this rule needs a `Vary` writer, which
does not exist here, and the knowledge that the caller is an intermediary, which
is no fact about any bytes this crate reads. Adding both to satisfy one
prohibition would be worse than leaving it stated: a proxy needs far more than a
single MUST NOT — §7.6.3's `Via`, §7.6.2's `Max-Forwards`, §7.6.1's `Connection`
and the hop-by-hop fields it names — and shipping this one without the rest
gives an intermediary author a FALSE FLOOR, a crate that looks like it has taken
a position on forwarding when it has taken one and left the others unwritten.
The same answer covers `Via` and `Max-Forwards`, which is why they are unfiled
rather than pending.

What this crate owes an intermediary is the fact it needs in order to obey the
rule itself, and that fact is the variant: a proxy re-emitting the members it
read knows from the variant alone which one it may not write.

### The wildcard is a member, not a state of the whole value

§12.5.5 puts `"*"` inside the list construct and speaks of a list containing it,
so `*, accept-encoding` is one list of two members and the wildcard is the
first. A `Vary` reader that made the wildcard a property of the value would
answer a different question, and would have nowhere to put the field names
beside it.

## `http-semantics` — §12.5.3's acceptability rules, measured total rather than argued away

The three readers hand a caller RFC 9110 §12.4.2's weight per member and leave
§12.5.3's `identity` default — a representation with no content coding is
acceptable unless the field explicitly refuses it — for every caller to
reimplement out of the same paragraph. It was left out on the argument that a
partial answer would be worse than none. That argument was not measured, and
measuring it refutes it: **every rule §12.5.3 states about acceptability is
expressible from two inputs a caller already holds** — the representation's
content coding or its absence, and the field's lines or none of them.

### Added

- `negotiation::encoding_acceptability(coding, lines)`, answering RFC 9110
  §12.5.3's own question: "A server tests whether a content coding for a given
  representation is acceptable using these rules". `coding` is `None` where the
  representation HAS no coding, which is rule 2's subject; no lines is an absent
  field, which is rule 1's.
- `negotiation::Acceptability`, with `is_acceptable` and `weight`. Three states,
  because §12.5.3 reaches its verdict through three different sentences:
  `AcceptableByDefault` (acceptable, no weight named), `Weighed(Weight)`
  (acceptable iff not zero) and `Unmentioned` (§12.4.3's unacceptable, with no
  weight). `weight` is `None` for the two that name none, rather than
  `Weight::ONE` — §12.4.2's default of 1 is what an absent `q` on a PRESENT
  member means, and there is no member in either case.

### The enumeration, rule by rule

| # | rule | expressible from (coding-or-absence, lines-or-none)? |
|---|---|---|
| 1 | Rule 1 — no field, any coding acceptable | **yes**: a field is present exactly when a line names it, so no lines is the absent field and one empty line is not |
| 2 | Rule 2 — no coding, acceptable unless `identity;q=0`, or `*;q=0` with no more specific `identity` entry | **yes** |
| 3 | Rule 3 — a listed coding is acceptable unless accompanied by a qvalue of 0 | **yes**, case-insensitively per §8.4.1 |
| 4 | §12.5.3's asterisk sentence — `*` matches any coding not explicitly listed | **yes** |
| 5 | §12.4.3 — no wildcard, unmentioned values unacceptable | **yes**; this is the sentence that closes the question, since rules 1 to 3 leave that case with no verdict |
| 6 | §12.5.3's empty-field sentence | **yes**, and as a CONSEQUENCE of 2, 3 and 5 rather than a case: no branch spells it, and a test asserts it falls out |
| 7 | §12.5.3's response direction — evaluated the same way as in a request | **yes**: one function, no direction argument |

**Verdict: total.** Nothing was left needing an input the caller cannot hand
over, so the "total except one load-bearing site" objection does not apply and
it ships.

Two further rules of §12.5.3 are **not** acceptability rules and are not
answered: preferring the highest non-zero qvalue among codings "that have the
same purpose", and the SHOULD about what to send when nothing is acceptable.
Each needs the set of representations the responder holds, which is not this
field and not this coding. The first ranks by `Acceptability::weight`, asked
once per candidate.

### Two clauses that a plain reading of rule 2 gets backwards

Both are tests rather than prose.

- **A `*;q=0` does not exclude a representation with no coding when the field
  also carries an `identity` entry.** That entry is rule 2's "more specific
  entry", and it governs whatever it says.
- **A non-zero `*` lends no weight to a representation with no coding at all.**
  Rule 2 names only `*;q=0` as reaching that case, so `Accept-Encoding: *;q=0.5`
  answers `AcceptableByDefault` with no weight, not `Weighed(500)`.

### A coding the field names twice: one half is derived, the other is chosen

**RFC 9110 does not settle what a field naming one coding twice with two
different weights means.** That sentence is worth more than either half below,
and `fold_repeated_entry` carries where the rule that would settle it was looked
for and is not: §12.4.2, which defines the weight and never mentions repetition;
§12.5.1's only ordering sentence, which is about a parameter's position INSIDE
one member; §5.6.1 and §5.6.1.2, which bound cardinality and empty elements and
say nothing about a repeated one; §5.3, which says order is significant without
saying which end — "The order in which field lines with the same name are
received is therefore significant to the interpretation of the field value" —
and §8.6, the one place RFC 9110 rules on a repeat, which rules for one field on
the case where the repeats are IDENTICAL and so never reaches two different
weights.

The two halves do not have the same standing, and reading them as one rule is
the mistake the split is there to prevent:

- **Derived.** A zero anywhere among the entries naming a coding excludes it.
  Rule 3's own wording read plainly, and independent of order, so two recipients
  reading the same field from opposite ends agree whatever rule each took.
- **Chosen, and derived from nothing.** Where no entry is zero, the last in wire
  order gives the weight. Nothing chooses between that, the first, and the
  largest.

**The undecidedness is now visible rather than implied.**
`a_repeated_entry_is_undecided_and_this_is_the_reading_taken` asserts the
zero-absorbing half in BOTH orders — which is what makes it derived rather than
chosen, since no reading can move it — and asserts the non-zero pair both ways
round, so the reading is pinned on the ORDER and not on a value that happens to
be larger. A future reading that takes the first entry, or the largest, reds
there instead of quietly disagreeing.

Both of those are measured rather than predicted: replacing
`fold_repeated_entry`'s body with `seen.unwrap_or(found)` reds the test, and
replacing it with a zero-absorbing largest-wins reds it on the mirror assertion,
naming that assertion's own message. The function was restored from a copy after
each.

`absorbing_zero` is renamed `fold_repeated_entry`, because a name that describes
only the derived half asserted the chosen half was settled.

### Why there is no `Accept-Language` counterpart

RFC 9110 §12.5.4 states no acceptability rules and hands the question away in
one sentence: "For matching, Section 3 of [RFC4647] defines several matching
schemes. Implementations can offer the most appropriate matching scheme for
their requirements." A function here would be picking one of those schemes on
the caller's behalf. The same enumeration for §12.5.2 finds only §12.4.3's
wildcard rule and no default of its own, so it has nothing §12.5.3's rule 2
gives it either.

## `http-semantics` — the rest of RFC 9110 §12.5, over an element that carries no parameters

`Accept` and its ranking shipped in this crate; §12.5's other four fields had no
reader at all. The three that rank share one shape and one walk — a §5.6.1 list
of a bare name with §12.4.2's weight optionally hung off it — and differ only in
which names the element production admits.

### Added

- `negotiation`, a module for the RFC 9110 §12.5 fields whose element is a bare
  name, and `negotiation::accept_encoding` — §12.5.3's
  `Accept-Encoding  = #( codings [ weight ] )` over
  `codings          = content-coding / "identity" / "*"`. It takes a field's
  lines like `media::accept` does, yields one `Preference` per element in wire
  order, and latches on the first fault.
- `negotiation::accept_language` — RFC 9110 §12.5.4's
  `Accept-Language = #( language-range [ weight ] )`, over the element §12.5.4
  does NOT spell.
- `negotiation::accept_charset` — RFC 9110 §12.5.2's
  `Accept-Charset = #( ( token / "*" ) [ weight ] )`.
- `negotiation::Preference`, with `name` (`None` for the wildcard `*`),
  `is_wildcard` and `weight`; and `negotiation::NegotiationError`, whose three
  variants are `NotAnElement`, `NotAWeight` and `BadWeight`. It is
  `#[non_exhaustive]`.
- `4647` in `quote_check`'s `FETCHED`, and RFC 4647's text in the cache CI
  grades against.

### RFC 9110 §12.5.4 hands its element out, and the workspace did not have the spec

`language-range  = <language-range, see [RFC4647], Section 2.1>` is a
`prose-val`: RFC 9110 holds no grammar for `Accept-Language`'s element, so a
transcription of that rule was gradeable against nothing this workspace had
loaded, and a comment carrying it would have been invisible to `quote-check`
rather than checked by it. RFC 4647 joins `FETCHED` the way RFC 2046 did for the
multipart writer, and the rule is transcribed from RFC 4647 §2.1's own text:
`language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*"` over
`alphanum         = ALPHA / DIGIT`.

Two things that rule says which reading it off §12.5.4's examples would miss.
The two subtag positions are different productions — `1*8ALPHA` in front and
`1*8alphanum` behind — so `en-us-1` is a range and `1-en` is not; and the
eight-character bound applies at EVERY position, not only the first. RFC 4647
§2.1 also names the digit as a correction to the rule it replaced, of which it
says: "is incorrect, since it disallows the use of digits anywhere in the
'language-range'".

It is §2.1's BASIC range and not §2.2's `extended-language-range`, which admits
a `*` in any subtag position: §12.5.4's `prose-val` names §2.1, so `en-*` is no
element of this field.

RFC 4647's range is NARROWER than RFC 9110 §5.6.2's `token` and inside it —
ALPHA, DIGIT and `-` are all `tchar`s — so no `language-range` can move an
element boundary, and the narrowing is checked rather than widened away. A test
holds both halves of that over its own samples: every range in the list is a
token, and five of the thirteen are tokens and no range.

### §12.5.1's `q` rule is not inherited, and that is a refusal rather than an omission

RFC 9110 §12.5.1 tells a recipient to process any parameter named `q` as weight
regardless of ordering. An `Accept` reader needs that because a `media-range`
CARRIES `parameters` and the weight is whichever of them is named `q`. An
element here carries none — §8.4.1's `content-coding   = token`, and then the
ABNF is out of alternatives — so the only production a `;` can open is
`[ weight ]`, there is at most one, and there is nothing for it to be ordered
against.

Importing `Accept`'s parameter handling would have ADDED three things the
grammar does not have, and each moves an answer:

- **A quoted value.** §5.6.6 makes a parameter's quoted and unquoted values
  equivalent, so `Accept: text/plain;q="0.5"` weighs 0.5. `weight` spells its
  value `qvalue` with no `quoted-string` alternative, so
  `Accept-Encoding: gzip;q="0.5"` is malformed. Both halves of that pair are one
  test.
- **A repetition.** RFC 9110 §5.6.6's
  `parameters      = *( OWS ";" OWS [ parameter ] )` repeats where `[ weight ]`
  brackets one, so `gzip;q=0.5;p=1` is a media range's shape and no element of
  this field.
- **A comma inside a value.** The one that moves a BOUNDARY rather than a
  verdict: nothing reachable from an element here admits a DQUOTE, so every
  comma is §5.6.1's separator and the elements are exactly what
  `grammar::list_elements` splits. That is also why walking a field's lines and
  walking §5.2's joined value cannot part.

### `Accept-Charset` is deprecated to SEND, and this is the receiving side

RFC 9110 §12.5.2's Note deprecates the field, and every clause of it is about a
sender: sending a detailed list wastes bandwidth, increases latency and makes
passive fingerprinting easy, and most general-purpose user agents do not send
one. A recipient still meets the field, because a deprecation does not unsend
what is deployed, and a recipient that cannot read it can neither honour it nor
ignore it deliberately. So the Note is the reason `accept_charset` exists AND
the reason nothing in this crate writes an `Accept-Charset`; there is no encoder
here and none is owed.

**The element is `token`, and the ledger's `charset` is not a production RFC
9110 has.** §12.5.2's ABNF is `Accept-Charset = #( ( token / "*" ) [ weight ] )`
— measured against the cached text at line 5506 and against Appendix A's
collected grammar — and §8.3.2 defines charset names in prose rather than in
ABNF. Its Note says where the difference falls: RFC 2978's `mime-charset` admits
`{` and `}`, which §5.6.2's `token` does not. This reads the rule the field
spells, so `a{b}` is refused.

**It shares its element rule with `Accept-Encoding` as a fact about the
grammar.** RFC 9110 §12.5.2's `( token / "*" )` and §12.5.3's
`codings          = content-coding / "identity" / "*"` derive the SAME strings —
§8.4.1's `content-coding   = token`, `identity` is a `token`, `*` is a `tchar` —
so nothing an element may say tells the two fields apart. A test holds the two
entry points to identical answers over ten values, so the sharing is pinned
rather than left as a property of one implementation.

### `coding-corpus` grades none of these productions, and the module says so

A new reader owes an answer to whether it is a second reader of a production
that harness already grades, because several readers of one production is how
al8n/wren#76 happened. This one is not, twice over. RFC 9110 §8.4.1's
`content-coding   = token` is not §10.1.4's
`transfer-coding    = token *( OWS ";" OWS transfer-parameter )` under another
name — `chunked;p=1`, which that corpus is built to exercise, is a
`transfer-coding` and is no `codings`. And the three productions this module
does share with existing readers are reached by CALLING the one implementation
of each — `grammar::list_elements`, `grammar::is_token` and
`media::parse_qvalue` — so there is no second reading to diverge from.

## `http-semantics` — the export that was going to unblock three readers was not one

al8n/wren#70's Phase 2 says one line unblocks three of the four fields it adds:
`media::parse_qvalue` is `pub(crate)`, and publishing it turns three "cannot"
into three "inconvenient". Measured before writing any of them, both halves of
that sentence are wrong.

**It is not one line, and it is not a line at all.** `pub(crate)` is crate-wide.
The three readers land in this crate, so they call the function with no edit to
its visibility — there was never anything to unblock. What a `pub` would change
is what a caller OUTSIDE the crate can reach, which is a different question
that no reader in Phase 2 asks.

**And it is the wrong shape for the question it was answering.** `Weight` is
already `pub`; what a caller wants is the weight a member CARRIES, which
`MediaRange::weight` hands over off a member this crate has already walked. A
public `qvalue` reader beside it is a standing invitation to read the same bytes
a second time — the thing that accessor exists to remove — and this crate has
already published this function once, for `http1-proto`'s panic shim and no
other caller, and taken it back.

### Changed

- `media::parse_qvalue` keeps `pub(crate)`, and its doc now carries the ruling:
  the four RFC 9110 elements that end in `[ weight ]`, why a reader in this
  crate needs no export, and why the `TE` reader §10.1.4's `t-codings` implies
  is in the same position and gets the same answer.

## `xtask` — a code span that wrapped, a citation that wrapped, and a block whose marks do not pair

Three ways a quotation left `quote-check` without being graded, counted or
reported, and each one's failure was watched before it was written down. Closes
al8n/wren#84.

### Fixed

- **The masking unit is a paragraph** (`mask_paragraph`), and it was a line. A
  code span that wraps across two comment lines met no closing backtick on the
  first of them, so the masker emitted the rest of that line as prose and every
  quote character inside the span leaked into the block. `quoted_spans` pairs
  marks left to right, so an ODD number of leaked ones displaces every real
  quotation after it: the author's opening mark is consumed as a closer and the
  closing mark becomes an opener with nothing to close on. Where the prose
  between the leak and the quotation falls under the five-word and
  twenty-four-character floors, `grade` returns before it counts anything —
  nothing prints, nothing fails, and the quotation is **never graded, never
  counted and never reported**. That is the escape #75 closed in `abnf_spans`,
  arriving through the quotation path.

  The paragraph is the unit a Markdown code span may wrap across and the unit
  `abnf_spans` already read. Both paths now go through one reading of a code
  span (`code_spans`), pairing backtick RUNS the way rustdoc does, so what the
  mask erases and what the ABNF path admits can no longer disagree.

  Demonstrated before it was fixed, on a constructed block whose code span wraps
  and holds one DQUOTE, followed by a quotation of RFC 9110 §5.6.1.2 with its
  last word altered. `main` at `e42b30d` is **exit 0**, `1139 quotations
  checked`, and no line naming the file. This branch is **exit 1**, `1140
  quotations checked`, and `quote_span_demo.rs:5: quoted words are not
  rfc9110's`. `a_code_span_wrapped_across_lines_does_not_leak_its_quotes` and
  `a_leaked_quote_can_take_a_quotation_out_of_the_gate_without_a_trace` hold
  both halves — the displaced span and the silence — in the suite.

  **Not the whole block**, which is the other way to close the leak and the way
  the issue's own measurement was taken. A code span may not cross a blank line,
  so pairing over a block pairs two paragraphs' unrelated stray backticks and
  masks the quotation between them; run over this workspace that baseline
  invented a span in `quote_check.rs`'s own module doc. Under the paragraph unit
  it does not, and `a_stray_backtick_pairs_no_further_than_its_own_paragraph` is
  the boundary — constructed, because this workspace holds no block the two
  units read differently today, and a corpus that cannot spell the case cannot
  witness the rule.

  What moved, workspace-wide, measured by running the real extraction under both
  units over every file the command reads: **43 extracted spans lost and none
  gained**, in 14 files, every one of them a sub-prose code fragment the leak
  had manufactured (`=`, `x`, `trailers`, `*/*`, `c, Digest realm=z`). **No span
  large enough to be graded changed at all** — no comment starts being graded
  that was not, and no verdict moves. Every printed total is what it was.

- **A citation wrapped where Markdown indents past is still a citation.**
  `markdown_quotations` joined a paragraph's lines RAW into the comment block
  and TRIMMED into the paragraph the code-span reader gets — two readings of one
  line. The raw one put the next line's layout indentation between `RFC` and its
  number, and `cited_rfcs` takes the digits immediately after that space, so a
  citation wrapped at exactly that point was invisible. `CHANGELOG.md` wraps
  there several times. One buffer now feeds both, and it holds the trimmed line.

  Its own commit because it is its own behaviour change, measured on its own:
  with the raw line restored and the paragraph mask otherwise untouched the run
  prints `1024 … 115`, which is `main`'s narrow-fallback split exactly; with the
  trimmed line it prints `1025 … 114`. One quotation moves from being graded
  against any loaded spec to being graded against the spec its own block names.
  It was verbatim before and is verbatim now — the target set only narrowed.

- **A block whose quotation marks do not pair is reported, and held.** The
  pairing above is block-wide, so one leftover mark cuts every quotation behind
  it in the wrong place and drops the last of them entirely — the same
  disappearance, arriving from the author's own prose rather than from a code
  span. This workspace was holding that off by CONVENTION: a `gate-exempt:`
  marker naming a value whose quoted-string never closes is kept out of the doc
  comment below it, in a block of its own, because its lone mark would otherwise
  shift every pairing in that block by one.

  A convention people have to remember is a guard at one entrance, and the run
  finds the entrance that was already open: `http-semantics/src/auth/mod.rs`
  puts four such markers directly under its module doc with no blank line
  between them, so a `//` line continues the `//!` block and the module doc's
  own block holds seventeen marks. It is harmless only by position — the lone
  mark is the last of the seventeen, so the sixteen in front of it still pair
  with each other. Move a marker or add one and the module doc's quotations
  start being cut somewhere else.

  The run prints the count every time and holds the split per file against
  `UNPAIRED`, the way `UNTRIAGED` holds the attribution backlog; the two tables
  run on one rule (`drift`) and differ only in the repair they name. Also
  demonstrated: a constructed block with a stray mark in front of a real
  quotation leaves `7f798b9` at **exit 0** and `1139 quotations checked` — the
  same number as with no such file at all, so the quotation in it was never
  graded — and leaves this branch at **exit 1** with
  `unpaired_demo.rs:4: the block beginning at line 1 holds 3 quotation mark(s)`.

  **What it does not see, said in the code rather than left to be
  rediscovered:** parity sees a BLOCK, not a quotation, so an EVEN number of
  stray or leaked marks is still mis-paired and still unreported — the shape
  #84's own opening case had, since the comment that surfaced the leak held two
  wrapped code spans. This narrows the class along one axis and leaves the other
  open. `UNPAIRED`'s own limit is `UNTRIAGED`'s: a per-file count cannot see one
  entry replacing another at the same count, which is one shared consequence of
  identifying a site by a count rather than by a line every edit moves.

  **Eight blocks stood when the check was first run**, and the table says what
  each is. One was a real comment in this crate and is repaired —
  `doc_check.rs`'s `the opening '"'` now says DQUOTE, which is the repair this
  table asks of anyone who lands in it. Seven remain: one comment worth changing
  (`http-semantics/src/auth/mod.rs`, left alone because that crate is not this
  change's to edit — repaired in this branch after all, see below), two
  deliberate markers, and four blocks that are not
  comments at all — continuation lines of multi-line Rust string literals whose
  contents hold a `//` or a `///`, where the lone mark is the one CLOSING the
  Rust string. `trailing_comment_at` cannot see past that: a string left open at
  end of line ends its walk, so the line after it is read as fresh code.

### Added

- **The measurement is a test.** The claim that no quotation in this workspace
  is affected by the masking unit was reproducible only by re-applying an
  instrumentation patch, so it decayed the moment anybody edited a comment.
  `the_two_masking_units_agree_on_every_graded_span_in_this_workspace` runs the
  REAL extraction over both units — `take_paragraph` takes the masker as a
  parameter, so the counterfactual shares the whole loop rather than
  reimplementing it beside one — and compares every graded-size span in every
  file the command reads. A detector that reports zero because it cannot fail
  reports zero too, so `the_differential_reports_a_leak_it_is_given` hands the
  same helper a block that does leak.

## `xtask` — one marker syntax, two attachment rules, and neither was written down

`quote-check` and `doc-check` read the identical `// gate-exempt: <text> —
<reason>` comment under DIFFERENT attachment rules, and nothing said so. A blank
line added to `http-semantics/src/auth/mod.rs` for the first gate red the second
five times on CI (al8n/wren#87).

### Fixed

- **A module doc is checked against its MODULE, not against the first code run
  beneath it.** `doc-check`'s items are runs of consecutive comment lines plus
  the code under them, so a `//!` block became an item whose body was whatever
  code happened to follow and whose exemptions were whatever markers happened to
  be glued to it. Both are facts about layout. `callee_scope` gives a `//!` item
  the split it should have had all along — its leading comments are the file's
  PROLOGUE (the comment run before any code) and its body is everything after
  that prologue — so the answer no longer depends on where the blank lines are.

  Not the whole file for the body, which was written first and is wrong:
  `names_identifier` is deliberately loose about what counts as a use, so the
  module doc's own sentence would satisfy the check about itself and every
  module-doc mention would pass forever. Not the whole file for the markers
  either: that silenced one more mention than `main` had — `outbound.rs`'s
  module-doc mention of `validate::host_value_is_valid`, over a marker three
  hundred lines below it. With the prologue on both halves the run prints `26
  mentions checked, 15 exempt, 0 unresolved`, which is `main`'s line exactly.

  **The rule is the fix, so no comment moves.** Three files sit in the position
  that broke: `auth/mod.rs`, `validator/mod.rs` and `range/mod.rs` all glue
  markers to a module doc. Inserting the blank line into each, under the old
  item rule, fails 5, 2 and 4 mentions; under the module rule all three answer 0
  with the line and 0 without it. `validator` and `range` are untouched and
  stay green either way.

- **Both attachment rules are now written where the marker syntax is
  documented**, in `exemption_reason` and in `exempted_spans`, in the same
  words: `quote-check` attaches a marker to the FILE (every line is read, and a
  marker anywhere suppresses a matching span anywhere), `doc-check` attaches it
  to the ITEM (a marker exempts only the mentions in its own comment run), with
  the module widening as the single exception. Nothing said this before, which
  is why one gate could be satisfied and the other broken by the same line.

## `http-semantics` — a blank line is what keeps four markers out of the module doc

### Fixed

- **`auth/mod.rs`'s four `gate-exempt:` markers sat inside the module doc's
  comment block**, because a `//` line CONTINUES a `//!` block rather than
  starting one. The module doc's block therefore held seventeen quotation marks,
  the seventeenth being the lone one the third of them carries in a value whose
  quoted-string never closes, and
  `quote-check` pairs marks left to right across a whole block. It was correct
  **only by position** — the lone mark is last, so the sixteen in front of it
  still paired with each other. Adding a marker, moving one, or writing another
  sentence of module doc past it would have changed that silently.

  A blank line ends the block. The markers are their own now, the way
  `websocket-proto/src/negotiation.rs` already keeps its own, and the note under
  them is there because the gate cannot defend the line: `UNPAIRED` counts one
  odd block in this file either way, so deleting the blank line is a change the
  run would not fail. Found by the check added to `quote-check` in the same
  branch.

  Nothing else moves under `quote-check`, measured rather than assumed: before
  and after, the file yields the same four markers, the same six production
  candidates exempted by them, no exempted quotations either way, 80 admitted
  and 4 uncited candidates, and 51 extracted spans with an identical digest.
  Only which block is the odd one changes — the module doc at line 1 holding 17
  marks becomes the marker block at line 225 holding 5.

  `doc-check` was a different matter and is the subject of the entry above: the
  same line took the `use` statement out of the module doc's item and its
  markers out of the module doc's comment run, and red that gate five times. The
  measurement recorded here was made against `quote-check` alone, which is
  exactly the failure this branch exists to stop — a gate reporting green
  because the wrong question was asked of it.

## `http-semantics` — the auth recovery invented a challenge out of a parameter's own data

`challenges()` could hand a caller a challenge no origin server sent, built out
of bytes the sender wrote as a parameter's **value** — and it did so on
CONFORMING input, because the refusal that opened the door was this reader's own
bound rather than a fault of the sender's. al8n/wren#77, measured at `9dd8708`:

```text
WWW-Authenticate: Basic p1=1, …, p17=17, x="c, Digest realm=evil, junk"
```

No repeated name, nothing malformed, no byte RFC 9110 §5.5 forbids, one field
line. §11.2 bounds `#auth-param` nowhere, so this value conforms; what refuses
it is `MAX_PARAMS_PER_CREDENTIAL`. The walk answered
`[Err(TooManyParameters), Ok(scheme="Digest", params=[realm="evil"]), Err(MalformedScheme)]`,
and §11.4 has a user agent answer a 401 by "selecting the challenge with what it
considers to be the most secure auth-scheme that it understands" — so the scheme
and the realm that choice turns on were whoever wrote `x`'s value. The same
bytes with no fault in front of them are ONE `Basic` challenge whose `realm`
holds that comma. The recovery is what invented the `Digest`.

All six triggers reach that recovery — a trailing suffix behind a closed value,
a malformed parameter, a duplicate name, the parameter bound, the line bound,
and a byte §5.6.4 forbids — and the reasoning that hid it generalised a
measurement taken for ONE of them to all six: it conflated the byte that
TRIGGERS a refusal with the bytes the recovery then walks, which are ordinary
data.

### Fixed

- **A comma is a boundary only where EVERY reading of the bytes in front of it
  ends the element there.** Behind a fault nothing forces §11.2's
  `( token / quoted-string )` on the bytes at a value position, so the DQUOTE
  there is one a reading may open and a reading may leave shut. `seek` now
  crosses only the commas the two agree on — `refused_element_end`, over
  `some_reading_holds` — and where they part it reports
  `AuthError::ChallengeBoundaryUnknown` and stops. Cutting there instead is the
  defect; crossing to the string's close instead would hide every challenge an
  unclosed value swallows, and inventing a challenge and hiding one are the same
  harm.

  There is exactly one place a reading may open a string in such a run, and that
  is what makes one scan an answer about every reading rather than a sample of
  two: a second opener needs a second element, a second element needs a comma,
  and the run ends at the first comma by construction. The `grammar` walk asks
  the same question of §5.6.6's `parameters`, where a member's own `;` puts many
  openers in one run and a subset construction over their states is what answers;
  an `auth-param` is one whole element with nothing repeating inside it, so the
  construction collapses to a single `scan_quoted` bounded at the candidate
  comma.

  **Which place it is, §11.6.1 answers twice**, and `opener_at` reads both. An
  element of the outer list is one more `auth-param` of the challenge already
  open — its own value position — or the `auth-scheme` of the next one, whose
  first parameter's value position stands behind `auth-scheme 1*SP`. The two
  shapes exclude each other (§5.6.2's `tchar` holds no `=`, so a token followed
  by `BWS "="` is not a token followed by `1*SP` and another token), so the run
  still holds one opener or none and one scan still answers.

- **A refused element's extent is one reading's, so the recovery goes back to
  where the readings part.** An element whose extent `element_end` cut by
  OPENING its own string, and which then derives nothing, has a reading that
  leaves the DQUOTE shut and ends it at the first comma instead. Recovery now
  runs from the element's own first byte, or — where §5.2's join carried it onto
  a later line — from the head of the line the value closed on, with the close
  as the offset in front of which no comma on that line is a boundary.
  `Basic a="x` and `trap="open, Digest realm=z` are two field lines whose second
  reading holds `Digest` inside `trap`'s value, and the walk yielded it.

- **A join admits a whole CHALLENGE on the continuation line, and its
  parameter's DQUOTE is not at the recovery cursor.** The reading that shut a
  refused element's value at §5.2's join ends that element there, and what opens
  at the continuation line's first byte is an element of the outer `#challenge`
  list — which §11.6.1 lets be a scheme, its `1*SP` and its parameters. That
  challenge's first parameter has its value position behind the scheme, at an
  offset a check asked only at the cursor never looks at. `Basic a="x` and
  `Digest realm="evil, Newauth realm=z, junk", Safe realm=s` are the two field
  lines: one reading takes the DQUOTE behind `realm=` as the CLOSE of `a`'s
  value, the other as the OPEN of a `realm` whose data runs
  `evil, Newauth realm=z, junk` — and crossing the comma behind `evil` handed a
  caller a `Newauth` challenge out of the middle of that realm. `Recovery`
  carries whether a comma stands in front of the cursor, and `seek` takes it on
  its first run only, since every later cursor is one `opens_a_challenge` has
  already answered `false` for.

- **The element behind a join comma does not begin at the join comma.** §5.6.1.2
  expands its list as `#element => [ element ] *( OWS "," OWS [ element ] )`,
  hanging whitespace on BOTH sides of the comma — so a sender that wrote one
  space in front of a continuation line's element moved that element, and BOTH
  of the openers above, off the offset §5.2's join left the cursor on. §5.6.2's
  `tchar` excludes SP and HTAB, so a check asked at the offset instead of at the
  element found no `token` at all and read the run as one holding no opener.

  ```text
  WWW-Authenticate: Basic a="x
  WWW-Authenticate:  realm="evil, Digest realm=z
  ```

  One space, and the walk answered `Err(MalformedParameter), Ok(Digest realm=z)`
  — a `Digest` read out of the middle of a `realm` the sender wrote whole. The
  whole-challenge spelling (` Newauth realm=…`) and the two-join spelling failed
  alike. `opener_at` now skips §5.6.3's `OWS` to the element's real start before
  checking either shape, and the mutual-exclusion argument that keeps this ONE
  scan is stated where it holds: the two readings share one `token`, so they are
  read from one offset, and that offset is the element's. `Recovery::at` keeps
  the unskipped offset, because `Recovery::floor` counts the commas this line
  holds from the line's head.

- **The `token68` verdict a body holds for its first element comes due where a
  quoted-string decided that element's extent.** §11.2's `token68` alphabet
  holds no DQUOTE, so an element carrying one is not one — and holding the
  verdict to `BodyCheck::finish` reported it with the cursor already past a
  boundary that element's own string had chosen.

- **A challenge refused at its `auth-scheme` opened no parameter list**, so no
  `auth-param` begins in what is left of it and no DQUOTE in it opens a string
  in any reading — unless a list is open earlier in the value, where §11.6.1
  lets the refused element be a malformed parameter of a challenge still open.
  `Basic, type=1, x="a, Digest realm=z` reaches `Digest`; `Basic a=1, =x,
  x="c, Digest realm=z"` does not.

- **That list has a LIFETIME, and it used to have only a beginning.** The bit
  recording it only ever turned on, so a refusal inherited the state of any
  earlier body in the value — including one a completed challenge had since
  closed. `1*SP` is the body's only entrance in
  `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, so a challenge
  with nothing but §5.6.1.2's `OWS` and its comma behind its scheme took no body
  under ANY reading and opened no list; and its own element DERIVES, so
  §11.6.1's other reading of it — one more `auth-param` of the list in front of
  it — is a non-derivation beside a derivation rather than one of the two
  readings §11.6.1 leaves a recipient to choose between. Every reading therefore
  has the earlier list closed at the comma in front of such a scheme, and
  `Challenges::list_open` now says so. `Basic a=1, Bearer,
  Broken<HTAB>junk, x="open, Digest realm=z` reaches `Digest`; it did not.

  **A `token68` body closes one for the same reason.** §11.3 writes
  `token68 / #auth-param` as an ABNF `/`,
  and RFC 5234 §3.2's unordered choice says a recipient may TRY either
  alternative; it does not make an alternative that derives NONE of these bytes
  into a reading of them. Where the run reaches the end of its own element,
  `auth-param = token BWS "=" BWS ( token / quoted-string )` derives nothing
  there: `token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`
  puts nothing but more `=` and §5.6.3's `OWS` behind its first `=`, and the
  production needs a `tchar` or a DQUOTE. So the challenge derives, no list is
  open behind it, and `Bearer abc, Broken<HTAB>junk, x="open, Digest realm=z`
  reaches `Digest` — as does `Bearer abc, x="open, Digest realm=z`, which the
  walk used to REFUSE the `Bearer` of, because the parameter-shaped element
  behind the run made the body loop settle a verdict on a body §11.2 had already
  decided. `Challenges::challenge` now finalises the challenge at that element's
  delimiter before reading a byte of it, and
  `the_two_branches_are_never_both_derivable` is the disjointness the rule rests
  on, executed over 37 448 elements.

  **What takes that argument away is a fault in front of the challenge.** It
  rests on every reading of the value having this element as a challenge, and
  behind a fault nothing derives — so the readings include one in which every
  element since the fault is garbage the open list still holds. The expiry is
  conditioned on `Challenges::faulted` for that reason, and
  `Basic a=1, Broken<HTAB>junk, Bearer, x="open, Digest realm=z` is the value
  that needed it: a bare scheme that closed a list it could not close, and a
  `Digest` read out of the middle of `x`'s value. Corpus L is that shape.

  **And the expiry is one write for every completion path.** It was three
  completion paths with the `false` on one of them, which is how a fourth would
  have inherited a stale `true`; `Challenges::challenge` now derives it from
  `Complete::opens_a_list` at the single point every completion passes through.

- **A scheme fault is recovered from the ELEMENT's own first byte**, not from
  behind the scheme token. §11.6.1 gives that element two readings and they open
  a §5.6.4 quoted-string in different places: read as one more `auth-param` of a
  list still open, its value position is behind its own `token BWS "="`, and a
  scan starting past the token never looks there. `Basic a=1, Broken<HTAB>junk,
  Bearer, x="open, Digest realm=z` is the value — `x=`'s DQUOTE stands at a
  value position of a list `Basic` opened, and the walk crossed the comma inside
  it. Whether that reading is admitted at all is still `Challenges::list_open`'s
  to say, so `Basic="q, Digest realm=z` — where no list is open anywhere —
  reaches `Digest` exactly as before.

- **A `token68` is the whole BODY, and an empty element in front of it is part
  of that body.** §5.6.1.2's "Empty elements do not contribute to the count of
  elements present." is why `BodyLines` spends no region on one that is all
  `OWS` and commas — so a body whose empty elements stood on the line §5.2's
  join left behind arrived at `BodyCheck::finish` as the bytes BEHIND them, and
  a run reading as the whole of what arrived was taken as the body. `Basic<SP>,`
  and `a=` on two field lines are `Basic ,,a=` under §5.2, whose body no
  `token68` derives; the same value on ONE line always answered
  `MalformedParameter`, and the two now agree. The question is asked at the
  element instead, where the empty elements are still visible.

- **The line bound met with a value still OPEN across §5.2's join leaves no
  boundary at all.** Every comma behind that DQUOTE is the value's data in the
  only reading there is, and the line that would close the string is one
  `MAX_CHALLENGE_LINES` forbids this reader to hold. The two spellings of such a
  value — one field line apart, the join comma folded in or not — used to answer
  with different numbers of challenges; they now answer alike, and
  `the_line_bound_met_inside_a_value_leaves_the_two_spellings_the_same_answer`
  is that agreement pinned where the disagreement used to be recorded.

- **The ambiguity a refusal leaves behind it is scoped to a recovery epoch, and
  a bound this reader sets opens none.** This class showed up in three places,
  one after another: a list-open bit monotone over the whole value, then the
  same bit cleared on one completion path out of three, then a global
  `faulted` latch that held it past a completion RFC 9110 had already settled.
  Each fix made the expiry a little more total and left one entrance open;
  each of those entrances is what the next fix had to close. The flags are
  gone. What one
  refusal leaves behind it is an `Epoch`: whether an `#auth-param` list was open
  where the refusal was met, and whether a derivation of the value still reaches
  the cursor. `Challenges::list_open` is now the completed challenge's own shape
  and nothing carried across one — no completion path writes it, because there
  is only one place it is written at all — and the `1*SP` no longer writes it
  either: a fault met at the body position is `Refusal::Bounded`, which says a
  list is open by construction.

  **Which refusals open an epoch is decided once**, by
  `AuthError::is_a_receiver_bound`, and the match is exhaustive so a variant
  added later cannot skip the question. §11.6.1's ambiguity is about where
  one element ends and the next begins; behind an element the grammar derives no
  part of, no boundary is fixed. `MAX_CHALLENGE_LINES`, `MAX_PARAMS_PER_CREDENTIAL`
  and §11.2's one-name-once MUST move no comma: the grammar derives every byte
  of the value they refuse, with every element where §5.6.1.2 puts it, so the
  first element no `auth-param` derives ends the list exactly as it would have
  with no refusal at all.
  `Basic p1=1, …, p17=17, Bearer abc, x="open, Digest realm=z` is the value:
  `Bearer abc` is §11.2's `token68`, no `auth-param`
  derives it, and the `Digest` behind `x` was declined for a list that had ended
  three elements earlier.

- **A fault reaches past its own challenge only through the list it stood in.**
  The rule that an epoch opened behind an unclosable epoch is itself unclosable
  was written without a condition, and it should not have been. A fault changes what the bytes
  behind it may be read as in exactly one way — the DQUOTE at a RFC 9110 §11.2
  value position becomes a reading's to open and a reading's to leave shut — and
  §11.2 admits a value position only inside a `#auth-param` list. So an epoch
  with no list has no such position, no DQUOTE any reading may choose, and
  nothing it can make the bytes behind it mean that the grammar does not already
  make them mean. `Epoch::reaches_past_itself` is that channel, and it is what
  `refuse` asks before inheriting an older epoch's non-derivability.

  `Broken;junk, Safe, Basic a=1, a=2, Bearer abc, x="open, Digest realm=z` is
  the value: `Broken;junk` opens no list, yet its epoch poisoned the
  `DuplicateParameter` epoch three elements later, stopped `Bearer abc` closing
  it, and declined the `Digest`. With the prefix removed the same value yields
  it. `a_list_free_fault_in_front_of_a_value_hides_none_of_its_challenges` pins
  that pairing over eight tails, and corpus M pins it over 210 (refusal,
  separator, trap) triples.

- **The two faults reported over an extent already complete are refusals like
  every other.** A body neither of §11.3's alternatives derives, and the line
  bound met on the region the challenge ENDS in, reached the caller through `?`
  and recorded nothing at all — so `Basic ;, Bearer, x="open, Digest realm=z`
  handed back a `Digest` read out of the middle of `x`'s own value: the body of
  `;` derives nothing, nothing behind it does either, and a walk that recorded
  no fault let the `Bearer` close a list no reading of these bytes closes. Both
  now pass through `Challenges::refuse` as `Refusal::Ended`, whose only
  difference from the others is that there is nothing left to seek.

- **An epoch ends at a challenge that COMPLETES, and at nothing else.** The
  element `seek` resumes on is not a second such position and the difference is
  what the mutation table caught: `opens_a_challenge` says no `auth-param`
  BEGINS at that element, which is not the same as a challenge deriving there.
  Where the walk goes on to refuse it, nothing derives at that element under any
  reading, so the reading in which the list is still running and the element is
  garbage inside it survives —
  `Basic p1=1, ..., p17=17, y=1, Broken;junk, x="open, Digest realm=z` is the
  value, and closing an epoch at the resume crosses the comma inside `x`'s own
  value.

- **A challenge that is yielded may not simultaneously be treated as possibly
  inside an earlier list**, and that is now checked rather than argued.
  `a_yielded_challenge_is_no_parameter` is asserted at both places a challenge
  completes, on every credential a debug build produces, and it cannot fire:
  suppose an element is both, and `auth-param`'s `token BWS "="` puts the body
  of the challenge reading AT the `=`, where neither `#auth-param` nor `token68`
  derives anything —
  `an_element_that_completes_a_challenge_is_no_parameter_of_the_list_in_front_of_it`
  runs that over 37 448 elements. It is compiled away where `debug_assertions`
  are off, as `walks_to_its_end` is.

### Added

- `AuthError::ChallengeBoundaryUnknown` — `challenges()`'s LAST item, and the
  one fault it raises about itself rather than about a challenge. A caller that
  receives it knows exactly what it holds: the challenges yielded in front of
  it, and no claim at all about the rest of the value. `AuthError` is
  `#[non_exhaustive]`.

### `auth-corpus` — the harness was part of the defect

The differential was GREEN over 36 records that each said the reader had handed
a caller a challenge built out of a parameter's own data, because `over-yield`
— the corpus's own name for exactly that — was pinned as a constant (16 for
corpus D, 20 for E) rather than driven to zero. And `TooManyParameters`, the
strongest trigger of the recovery, occurred **0 times in the whole corpus**:
corpus E writes one parameter per field line, so the line bound always fired
first and the parameter bound was unreachable by the harness built to find it.

- **`over-yield` and `hider-unexcused` are zero-targets**, asserted by
  `the_two_classes_this_module_is_driven_to_zero_on_are_zero` rather than
  pinned. Both are 0 over all 937 150 records, and `hider-declined` — the
  hiding direction's own target, added later in this entry — is the third.

- **Corpus H reaches the challenge a join opens**: 72 records over four heads
  that leave a quoted-string open where their field line ends, nine
  continuation lines, and one join or two. Every corpus in front of it puts its
  tail at the recovery cursor itself, so a check asked only there was green over
  all of them; corpus H answered `over-yield` **24** against the commit that
  first drove that class to zero. A zero-target is only as strong as the shapes
  the generators can write, which is corpus G's lesson repeated.

- **Corpus I reaches the opener a list's own `OWS` moves**: corpus H's 4 heads
  and 9 continuations again, times the 4 spellings of §5.6.3's `OWS` and one
  join or two — 288 records. Corpus H starts every continuation at the element's
  own first byte, so the openers a reader looks for at §5.2's join offset were
  always AT that offset; corpus I answered `over-yield` **128** against the
  commit that added H, and 0 here. Two families, and both defects
  lived where the generator could not write.

- **Corpus J reaches what an EARLIER challenge left open**: 8 prefixes of
  challenges that COMPLETE, times 3 elements refused at their `auth-scheme`,
  times 5 tails carrying the probe — 120 records. Every generator in front of it
  refuses the value's FIRST challenge, so the list state a recovery reads was
  written by the very challenge that failed and nothing measured what an
  intervening one left behind. It answered `hider-unresolved` **6** against that
  same commit, **18** against the one that closed the OWS defect, and 0 here —
  the 18 being the `token68` prefixes, whose probe the walk hid for an argument
  that does not hold. It also pins the direction that must NOT move, and
  `ows_after_the_join_comma_and_a_challenge_completed_in_front_are_shapes_these_generators_write`
  asserts both halves per prefix, so a family that stopped writing its own shape
  reds rather than going quiet.

- **Corpus K reaches the `OWS` in FRONT of the join comma**: corpus H's 4 heads
  and 9 continuations, times §5.6.3's 4 spellings of `OWS` written at the END of
  every line §5.2 puts a comma behind, times one join or two — 288 records.
  Corpus I unfixed the side behind that comma and this is the side in front of
  it, which is not the same question: behind the comma the whitespace moves an
  element and both of §11.6.1's openers with it, and in front of it the
  whitespace is INSIDE the element the join carries, so whether it is the list's
  at all depends on whether the head's quoted-string is still open there. K and
  I answer alike record for record over inputs that differ in every record, and
  that agreement is asserted rather than left to two tallies that happen to
  match. The other half of the same axis — whitespace at the value's own head —
  is closed by argument and a control instead:
  `Challenges::open_element` takes §5.6.3's `OWS` at every cursor including the
  value's first, so the answer for such a value IS the answer for the value
  without it, and
  `whitespace_at_the_head_of_the_value_is_the_one_edge_that_cannot_matter`
  measures that over 288 comparisons rather than asserting it.

- **Corpus L reaches what a challenge BEHIND the fault leaves open**: 2 list
  states in front of the fault, times 3 elements refused at their `auth-scheme`,
  times 4 challenges completing behind that refusal, times 5 tails carrying the
  probe — 120 records. Corpus J varies what completes in FRONT of the refusal,
  where the argument for closing a list is whole; nothing measured a challenge
  completing behind one, and a bare scheme closing a list there is how
  `Basic a=1, Broken<HTAB>junk, Bearer, x="open, Digest realm=z` handed a caller
  a `Digest` out of the middle of `x`'s value. It answered `over-yield` **6**
  against the commit that closed the stale-list defect and 0 here. Three
  families, and each defect lived where the generators could not
  write.

- **Corpus M reaches the SECOND recovery epoch**: 3 states in front of the first
  refusal — no list, a list, and a fault that opens a THIRD epoch nothing can
  close — times 7 refusals, four faults of the grammar and this reader's three
  bounds, times 6 things standing between the two epochs, times 5 tails carrying
  the probe: 630 records. Every family in front of it varies bytes
  WITHIN one epoch, and the epoch count had been fixed at one since the first
  generator, so no corpus could write a value in which one refusal's ambiguity
  has to END before a later refusal's question can be answered. It answered
  `over-yield` **12** and `hider-unresolved` **36** against `338e37a` and 0 and
  0 here, and the 48 records it moved are the whole of what it moved: the
  other twelve families are byte-identical, answer for answer, over 936 100
  records. Its own two extra dimensions moved nothing and pin two directions
  instead — a bound met behind a fault of the grammar is a bound whose epoch
  cannot be closed either, and an epoch is closed by no element recovery merely
  RESUMES on. Four families, and each defect lived where the
  generators could not write.
  `a_second_recovery_epoch_is_a_shape_this_generator_writes` asserts
  the family's shape, the fault each row is about, and both directions of the
  axis it adds.

- **The hiding direction has a zero-target of its own: `hider-declined`.** Two
  of the three classes this module drove to zero watched a challenge being
  INVENTED, and the third watched one hidden in silence. Nothing watched a
  challenge hidden behind a notice, because `hider-unresolved` was pinned at a
  non-zero constant, and a defect graded into it. Under the split, that defect
  reds: corpus M answers `hider-declined` **36** against `338e37a` and **0**
  here, and the 36 are the whole of that class, its own witness included.

  The split is two questions, because `hider-unresolved` was one class doing
  three jobs. `oracle::every_comma_in_front_is_settled` asks whether any RFC
  9110 §5.6.1.2 comma in front of the probe is one the readings DISAGREE about
  — a walk may decline such a comma and may not decline any other — and
  `Verdict::reached` asks whether the whole value derives, since a walk that
  refused conforming input refused it for a bound of its own.
  `hider-conforming` is that third job with a name: 6 records in corpus D and 5
  in corpus E, all of them `MAX_CHALLENGE_LINES` met with a quoted-string that
  CLOSES on a line this reader may not hold. `hider-unresolved` keeps the
  remaining 32.

- **The oracle can now tell a string the grammar FORCES from one a reading
  chooses.** `covers` gained a `Regime`: `Every` is the walk it always made, and
  `Forced` drops both ways a covering reading can be a choice — the free regime
  behind a fault, and a `quoted-string` whose own element derives nothing, since
  `( token / quoted-string )` is one alternative taken WHOLE. So a comma inside
  `a="x,y"` is settled as that parameter's DATA and one inside `a=","a` is a
  disagreement, which is the difference the new class turns on. `Regime::Every`
  is byte-for-byte the old walk: the axis column moves on 11 records and every
  one of them is `hider-unresolved` → `hider-conforming`.

- **`oracle::covers` carried a comment that was provably false, and the code it
  described was right.** It said RFC 9110 §11.2's one-name-once MUST "makes no
  difference" to where a quoted-string may open. It makes one:
  `Basic a=1, a=2, Bearer abc, x="open, Digest realm=z` is `excused: false` as
  the code reads it and `excused: true` if the repeat is made an element nothing
  derives. The code is right and the sentence was not, and the sentence is now
  the argument — §5.6.1.2 delimits the list before §11.2 says anything about
  names, so honouring the MUST moves no comma and un-derives no element, and
  this function asks a question about element boundaries. What the MUST does
  decide is whether the value CONFORMS, which is `Verdict::reached`'s question;
  `step` applies it for exactly that reason and the two functions differ because
  they are asked different things. Nothing in the graded counts moves, because
  no code path changed: the rule reaches 362 records, 328 of them graded on the
  axis.

- **The oracle carried the module's own defect, so the new zero-target could not
  see it.** `covers` set `faulted` unconditionally in `resume`, so a fault at an
  element with no list open still switched every later element into the free
  regime — where the walk re-entered a list opened three elements behind it and
  found a reading in which the probe was that list's data. `excused` was `true`,
  and `axis` excuses a hiding before it asks whether the notice was warranted.
  **`hider-declined` graded this shape `hider-excused` at the commit that
  introduced the target.** `resume` now
  propagates `list` rather than `true`, on the same channel argument as the
  reader's, and with it the target reds: corpus M answers `hider-declined` 12
  against `684fe2f` and 0 here. An oracle that shares a defect with the module
  cannot grade the module for it.

- **Corpus M crosses the earlier epoch's own state**, which was the missing
  shape. `M_OPENERS` is five: nothing, a list, a
  list-free grammar fault, the same fault inside a list, and a bound of this
  recipient's — the whole cross of the two facts an earlier epoch has, less the
  one combination `refuse` cannot build, since a receiver bound is only ever met
  inside a body. 1050 records, and the family asserts the pairing directly: the
  list-free prefix moves no probe over any of its 210 triples, the same fault
  inside a list moves exactly the 18 a bound would otherwise have closed, and it
  never moves one in the direction of showing more.

- **A per-corpus digest is keyed to the corpus it is about.** Corpus I and
  corpus K answer alike record for record — §5.6.1.2 spells one list two ways,
  and the identity is asserted where it belongs — so their two rows in `ANSWERS`
  held the same sixty-four characters and a maintainer pasting one family's
  actual digest into the OTHER family's row was green. The corpus name goes into
  the hash first, the table is asserted to hold no repeat, and `WHOLE` stays
  unkeyed because it is the number `auth-diff` prints.

- **Corpus G reaches the parameter bound**: 180 records writing 2 to 21 distinct
  parameters on ONE field line, behind nine tails — the eight corpora D and E
  share plus one no other corpus can spell, a well-formed quoted value that
  carries the probe, a comma and more of its own data and then CLOSES. Every
  quoted tail in `TAILS` leaves its string open, so a reader could be right
  about all of them for the wrong reason. `TooManyParameters` now occurs 46
  times.

- **The oracle asked the wrong question.** `Verdict::excused` asked whether the
  WHOLE value derives and REACHES the position, so one malformed element made it
  decide that no reading licensed a quoted-string §11.2 admits perfectly well —
  and the axis therefore graded al8n/wren#77's own siblings `yields-underivable`
  with `excused: false`, blind to the reader cutting those values in half. It is
  now a recursive enumeration over readings: the grammar decides in front of the
  first fault, where a `parameter-value` beginning with a DQUOTE derives only the
  `quoted-string` alternative, and every admitted DQUOTE is a free choice behind
  it. A `challenge` is read only at an element of the outer list, and an
  `auth-param` only where a list is open.

  **And it located the first fault in a branch that failed rather than in the
  value.** `covers` entered the `#auth-param` alternative at every body position,
  so a body §11.2's `token68` derives whole was read as a list whose first
  element derives nothing — a fault at a position no reading of the value is at.
  Every DQUOTE behind it then became a free choice, and 222 records were excused
  on the strength of a reading nobody has. The alternative is now taken only
  where `token68` does not derive the body, and the two never derive one element
  between them. Measured over the same reader: `Verdict::derives` moves on 0 of
  the 523 648 probe-carrying records, `Verdict::reached` on 0, and
  `Verdict::excused` on 222 — every one of them `true → false`, and every one of
  them a value with a `token68` challenge standing in front of its fault.

- **A third class, `hider-unresolved`**, for the 43 records where the reader
  declined to place a boundary and SAID SO. A challenge nobody was shown and
  nobody was told about is the harm this axis exists against; a challenge the
  caller is told it has not been shown is a cost, and
  `every_challenge_this_walk_declines_to_place_says_so_to_the_caller` asserts
  that every record graded here carries the notice.

- **The reproduction this table used to carry is gone, and says so.** `AXIS`
  reproduced five per-corpus figures published before any harness was committed;
  it cannot now, because the classifier those figures were computed with is the
  one #77 found the defect in. What is kept is the part that can still be
  checked — `RECOVERED` identifies the record set one earlier commit moved and
  asserts its size — and the move itself is tabulated at `AXIS`.

`cargo test -p http-semantics --all-features` reports 442 unit tests passing, 103
of them this module's, beside the no-panic harness's fifteen and one doctest;
`cargo test -p auth-corpus` reports 20 over 937 150 records.
`xtask/snapshots/http-semantics-documented.txt` gains 86 lines and loses four —
`Challenges.opened_a_list`, renamed `list_open` because it no longer only ever
turns on, and `Challenges.faulted`, `Challenges.parameters` and
`Challenges.after_comma`, which `Epoch` took over: `git diff --numstat 9dd8708 --` is those two figures, and
`grep -vc '^#'` counts 697 documented items on it at `9dd8708` and 779 here.

## `xtask` — a production that is not a rule, a rule no line could hold, and a `miri` budget that stops rather than reports

Three ways something walked past a gate, and each one's failure was watched
before it was written down. Closes #75 and #73.

<!-- gate-exempt: transfer-coding = token *( OWS ";" OWS transfer-parameter — the measured truncation, quoted to name it, not a production of any RFC -->

### Added

- **`quote-check` asks whether a candidate IS a rule before asking whether it is
  the spec's** (#75). The comparison is a substring test, so a production with
  its tail cut off matched:
  `transfer-coding = token *( OWS ";" OWS transfer-parameter` is a substring of
  RFC 9110 §10.1.4's own text, and the run that graded it printed `verbatim` and
  meant it. A candidate is now asked for a name, a definition operator and a
  right-hand side that BALANCES before anything compares it — `(` and `[` closed
  in nesting order, `"` and `<` opening a `char-val` and a `prose-val` nothing is
  read inside of, `;` outside both ending the rule. It is deliberately not part
  of the admission test: keying admission on the right-hand side would make a
  broken production stop looking like a production, so the gate's own defect
  would delete the item it should report. Admitted by the name and the operator,
  failed on the right-hand side.

  Demonstrated, not asserted. Dropping the trailing ` )` from
  `coding-corpus/src/tests.rs:672` leaves `main` at **exit 0** with
  `569 ABNF productions verbatim`, and this branch at **exit 1** with
  `coding-corpus/src/tests.rs:672: ABNF production is not a whole rule` /
  ``a `(` this never closes``.

- **The extractor reads a PARAGRAPH, so a rule wrapped across two comment lines
  is graded at all.** Backticks were paired within one line, so a rule too long
  for a line — closing backtick on the next — had no span extracted from it: not
  graded and passed, but never graded. That is the same escape as the truncation
  above, one step earlier. Spans are now read over the paragraph a Markdown code
  span may wrap across, pairing backtick RUNS the way rustdoc does, so a
  doubled-backtick span holding a literal backtick is one span rather than two.

  What the corpus gains, measured by swapping only `xtask/src/quote_check.rs` on
  one tree and dumping every admitted candidate: **30 backticked spans that were
  never extracted before**, and none lost. Twenty-nine of them clear the
  three-word floor and were graded for the first time: **22 were already
  verbatim and 7 were not.** Of those 7 — two real transcription defects (both
  fixed below), one correct production of a spec that was not being loaded (RFC
  6454, now fetched), three field values and Rust expressions that are
  production-SHAPED and not productions, and one correct RFC 2616 rule whose
  spec is deliberately absent from the cache; the last four carry
  `gate-exempt:` markers naming why. Seven more spans were gained in blocks
  citing no RFC, where there is nothing to grade them against. The run's own
  last line moved from `574 ABNF productions verbatim` to `599`, and its
  gate-exempt count from 17 to 21.

- **`xtask miri-test`, a per-test budget under `miri` that STOPS the run**
  (#73). Nothing failed when a test that is cheap natively and expensive
  interpreted was added without a `#[cfg_attr(miri, ignore = "…")]`: one such
  test — 1.1 s natively, over two hours interpreted — took
  `cargo miri test -p http-semantics` from minutes to 3 h 10 m, 80 % of a
  four-crate job limited to six hours, and the two crates queued behind it were
  reported as neither passing nor failing. Interpreted cost does not track
  native cost, so a reviewer has nothing to read.

  It is a WATCHDOG rather than a report, because the harm is the job's budget
  being spent and a run that named the offender at the end would have spent it
  already. libtest on one thread flushes `test <name> ... ` before it runs the
  test, so the unterminated tail of the stream names the test running NOW; when
  the budget expires on it the whole process GROUP is killed — `cargo miri test`
  is cargo over `cargo-miri runner` over `miri`, and killing the cargo at the top
  leaves the interpreter under it running. The after-the-fact check over
  finished tests is kept beside it as the floor.

- **A second budget on the crate's TOTAL, because the first cannot see the harm
  the job dies of.** A job has a wall-clock limit and dies of the SUM: five
  hundred tests of forty seconds each is 20000 s with no single test within an
  hour of its own ceiling, and the job dead anyway. The two rules catch disjoint
  shapes — one test that ran away, and a crate that grew — and neither implies
  the other. It is a watchdog too: the crate's clock runs against everything
  finished plus the running test's elapsed, and whichever budget expires first
  stops the run.

  **4000 s per crate**, derived the way the per-test budget was derived from its
  floor. The job's hard limit is 21600 s and it runs four crate steps, so four
  crates sitting exactly on the ceiling spend 16000 s of test time — 74 % of the
  limit, leaving 5600 s for `cargo miri setup`, four `cargo miri` builds
  (roughly 150 s each) and the margin a red needs in order to be reported rather
  than killed mid-print. Measured today, one crate at a time on one machine:
  `http-semantics` 1597.6 s, `websocket-proto` 1551.8 s, `http1-proto` 784.3 s,
  `http3-proto` 83.3 s — **4017 s in total, 18.6 % of the job's limit and 25.1 %
  of what these four ceilings allow.** The slowest crate has 2.50 times its own
  total to grow into, less headroom than the per-test budget's 3.50 and
  necessarily so: a total is already the sum of everything a crate does. Two of
  those figures are upper bounds and both are `websocket-proto`'s — its run was
  the only one sharing the machine, and timing that crate on an aarch64 host at
  all needed `sha1`'s soft backend — and both inflate rather than deflate.

  The multiplication is asserted rather than left to a reader, and its other
  factor is READ: `crates_the_job_names` counts the workflow's `miri-test` steps
  and the command refuses to start when that count and the constant disagree, in
  either direction. A fifth crate added to the job, or one quietly dropped from
  it, reds until the arithmetic is re-derived.

  Every run now prints its crate's total as a percentage of that ceiling, pass
  or fail — the only thing that makes a crate on its way there visible before it
  arrives.

### Changed

- The `miri` job's four `cargo miri test` steps are `cargo run -p xtask --
  miri-test <crate>`. One command rather than a run and a log check, because the
  second of two steps is the one that gets dropped. `PROPTEST_CASES` and
  `MIRIFLAGS` moved off the workflow and into the wrapper, defaulted only when
  the caller has not already chosen, so a developer measuring locally measures
  what CI measures.

- **RFC 6454 joins `FETCHED`.** `websocket-proto` reads `Origin` as one
  SP-separated list because RFC 6454 §7.1 says
  `origin-list = serialized-origin *( SP serialized-origin )`, and that rule sat
  in a comment that wrapped it across two lines — so until the extractor read a
  paragraph there was no span to grade and no reason to notice the spec was
  missing. `load_specs` reads the whole cache directory, so a spec on disk and
  absent from `FETCHED` grades locally and is missing in CI; that is the trap
  this list already sprang once. Adding it moved nothing else: the untriaged
  backlog, both citation counts and the graded total were identical either side.

- **A production in none of the loaded specs no longer names one of them.**
  `grade_production` searches every loaded spec and returns the first
  arbitrarily; printing that name read as an attribution, and
  `is not rfc2045's` over an RFC 9110 rule sends the reader to compare against a
  spec that never carried it. The line now reports what the check established —
  that none of the loaded specs holds those characters.

- **A production carrying an elision mark is not asked whether it is whole.**
  `…` and `...` are this file's existing convention for a deliberate cut, read
  when a span is split into the segments that get graded; a rule that says it is
  not whole is not one for a wholeness test to fail.

- **A fenced rule's continuation must be INDENTED past the rule it continues.**
  Reading every non-production line up to the next blank one as a continuation
  left #75's own class alive inside the fix for #75: a rule truncated inside a
  group, followed with no blank line by prose carrying the closer it dropped,
  BALANCED and passed. The indent is the RFCs' own typesetting rather than a
  heuristic about content — all seven wrapped rules in this workspace are set
  that way — and it is counted by `comment_body` before the trim that throws it
  away. Demonstrated: truncating RFC 9110 §12.5.1's `media-range` after its
  first line in `coding-corpus/src/oracle.rs` and writing the missing `)` as
  prose at the rule's own indent leaves the blind join at exit 0 with
  `599 ABNF productions verbatim`, and this rule at exit 1 with
  `ABNF production is not a whole rule`. Every count over the workspace is
  unchanged either side, so it refuses nothing that was being read. What remains
  is narrower and stated: prose that is itself indented under the rule still
  joins.

### Fixed

- **`http1-proto/src/head/encode.rs` cited RFC 9112 §3 for RFC 7230's
  `request-line`.** §3 is
  `request-line = method SP request-target SP HTTP-version`; the comment ended it
  with a `CRLF`, which is RFC 7230 §3.1.1's spelling and which RFC 9112 moved
  into §2.1's `start-line CRLF`. The sibling comment four lines down transcribes
  §4's `status-line` correctly, which is how invisible this was: same file, same
  shape, same author, one wrong.

- **`http1-proto/src/validate/tests.rs` cited RFC 9110 §10.1.1 for RFC 7231's
  `expectation`.** §10.1.1 is
  `expectation = token [ "=" ( token / quoted-string ) parameters ]`; the comment
  spelled the container out as RFC 7231 §5.1.1 does, bracketing the slot
  differently — which is the same class of difference, in the same place, as the
  one that opened #75.

Both were found by the paragraph extractor on its first run, and neither was
reachable before it: each is written across two comment lines.

## `coding-corpus` — the third §5.6.6 reader's extent, graded through what a fold can still state

The two commits below put the walk and `media::accept` into an extent
comparison and left `Expectations` out of it, because that reader hands out no
member. A branch that closes "a fourth uncompared walk" while leaving a third
reader uncompared has not closed the class — it is the shape #76 was filed
over. Measured before anything was changed: RFC 9110 §10.1.1's reader mutated
so that a member's extent stops at its name left **all 35 tests green, exit 0**.

### The obstacle, stated rather than worked around

`Expectations` is a fold over eight bits with **no lifetime parameter**. It
borrows no field line and retains no slice, so issue #79's argument — that the
borrowed subslice `place` needs is already handed out — does not transfer, and
the offset grading the other two readers get cannot be asked of it at any
surface short of turning it into a borrowing walk. No accessor was added, and
none was `differential`-gated.

What it does state about an extent is `expects_continue()`, which is
`parsed() && bare`, and `bare` is set only where a member parsed WHOLE as the
bare `100-continue`. RFC 9110 §10.1.1 puts everything behind the `token` inside
one optional group, so a member that is its head and nothing else is exactly the
distinction that flag carries — and exactly what a reader whose member ended
early gets wrong.

### Added

- **`projected_expectation`**, deriving §10.1.1's two verdicts from the one
  derivation the oracle admits, and holding the reader to them. The same shape
  `projected_verdict` already is, for the reason its own doc gives: a reader
  with a verdict and no member list, and an oracle with members and no verdict,
  can otherwise only be compared on whether the value parsed.

- **`Reading::member_heads`**, the oracle's record of where each element's head
  ends and whether the boundary-reaching derivation ends there. When the value
  derives, those keys are exactly the members of its one derivation — each start
  has at most one end the list admits, so the chain from the first start is
  unique.

- **Corpus G, 120 records.** The §5.6.6 comparison already handed
  `Expectations` a value on every record, but writes the head `x=1` in front of
  every element, so no member is ever named `100-continue` and both verdicts are
  constants no extent decision moves. Corpus G writes the names — bare, shouted,
  with an argument, with a quoted argument, with an argument and parameters, and
  with parameters and no argument — as one- and two-member lists and across the
  RFC 9110 §5.2 join.

- **The number that says what this is worth: 70.** 86 477 records have the bit
  compared (`EXPECT_EXTENT_GRADED`); on **70** of them a `100-continue` member's
  extent is what decides it (`EXPECT_EXTENT_DECISIVE`), and those are the only
  records the comparison can fail on. Both are asserted, and
  `the_extent_grading_was_asked_this_much` requires the second to be non-zero.
  Reading the first as coverage would be reading a tautology: everywhere else
  both sides answer the same way whatever the reader thinks a member's extent
  is.

  **This half is one bit per value where the other two are an offset per
  parameter.** That is the hole, stated in the same asserted form as the 37 772
  / 225 779 split beside it. Closing it means `Expectations` handing out a
  member, which is a public API decision this corpus does not make on a reader's
  behalf.

- **The control.**
  `the_expectation_extent_projection_reds_on_a_reader_that_truncates` runs the
  projection against a reader whose member ends at its name and requires the
  live one to stay green, in both directions (`100-continue=1` and
  `100-continue`) and case-insensitively.
  `the_expectation_reader_borrows_nothing_to_place` pins the obstacle as
  something the compiler checks, so if the type ever gains a lifetime the test
  stops compiling and whoever changed it can replace the projection with
  offsets.

- **Reachability**, as the other families have it:
  `every_expectation_shape_arises_from_the_expect_generator` asserts the set of
  shapes reached — `decisive` among them — arises from the generator, so a
  vocabulary edit that stopped writing a `100-continue` with something behind it
  reds instead of turning the comparison into an equality between two constants.
  `expect-continue` 34, `expect-other` 107, `expect-extent-decisive` 70.

### Changed

- The corpus is 245 217 → 245 337 records. Corpora `A`..`F` digest identically;
  corpus G's and the whole run's are new.
- `expect-parsed` 6 323 → 6 420, `expect-refused` 80 034 → 80 057,
  `expect-empty-element` 2 751 → 2 771 — corpus G's contribution to rows that
  already existed.
- `member_extent`'s failure message names the head as well as the parameter
  offsets, so a red says which of the three readers it is about.

## `coding-corpus` — `TE` is read, and the reading RFC 9110 leaves open is recorded rather than picked

RFC 9110 §10.1.4's productions are `TE`'s as well as RFC 9112 §7's, and every
§10.1.4 value this corpus wrote was a `Transfer-Encoding`. So the literal
`"trailers"` and §12.4.2's weight — the two things `TE`'s container has that
`#transfer-coding` has not — were bytes nothing here asserted anything about,
and a `TE` reader landing later would have been a fourth uncompared walk over
one production, which is issue #76's shape exactly. Closes #80.

### Added

- **Corpus F, and `Production::TCodings`.** 168 records: every one- and
  two-member `TE` list over a twelve-member vocabulary, and each member once cut
  across RFC 9110 §5.2's join. `every_te_shape_arises_from_the_te_generator`
  asserts the shapes arise from the GENERATOR and not from a hand-written value,
  for the reason `every_verdict_arises_from_the_list_generator` does.

- **The `t-codings` oracle derives exactly what `transfer-coding` does, and both
  halves of that are facts about §5.6.2's `token`.** `"trailers"` is spelled by
  `token`, and every `weight` is spelled by `OWS ";" OWS transfer-parameter`
  because `"q="` is a `token` and an `=` and every §12.4.2 `qvalue` is DIGIT and
  `.`, both `tchar`. What differs is only what a member's parameters ARE — which
  is why this needed the extent question the commit below adds, and could not
  have been graded before it.

- **The ambiguity, recorded and not settled.** `gzip;q=0.5` is a
  `transfer-coding` carrying a `transfer-parameter` named `q` AND a
  `transfer-coding` followed by a `weight`, over one string ending at one
  offset. The oracle admits both, the grading accepts either, and `tests` pins
  which one each reader takes: the walk reads it as a `transfer-parameter` on
  all **125** such members (`extents_q_as_parameter`), and the weight reading is
  asserted at **zero** rather than left as an absent row, so a reader that
  starts taking it says so. `media::accept` takes the other reading on its own
  field and drops the `q` on **14** members (`media-q-dropped`).

- **Reachability rows, so a vocabulary edit reds rather than going quiet.**
  `te-trailers` 24, `te-weight-ambiguous` 100, `te-q-read-as-parameter` 100, and
  `te-q-no-weight` 84 — a `q` no `weight` reaches, which the vocabulary spells
  four ways: a value that is no `qvalue`, a §5.6.4 `quoted-string` where `weight`
  has no alternative, §5.6.3's `BWS` where `weight` writes one literal, and a
  repetition standing behind the `q` where the bracket cannot reach. Without the
  last row the ambiguity row could not be told from a corpus that writes one `q`
  and never varies it.

### Why the `q` is not settled here, and what was checked

The obvious ruling — that a `q` terminates the parameter section and begins the
weight, RFC 9110 §12.5.1 stating as much for `Accept` and §10.1.4 inheriting it
— does not survive reading §12.5.1. That section says the opposite of a
positional rule: "Recipients SHOULD process any parameter named "q" as weight,
regardless of parameter ordering", which tells a recipient to recognise a `q`
that has parameters BEHIND it. And the grammar the ruling leans on is not in
this RFC at all — §12.5.1 records: "The accept extension grammar (accept-params,
accept-ext) has been removed"; it was RFC 7231 §5.3.2's. What §12.5.1 does carry
is scoped to `Accept`, and its own note grounds it in the media type registry
disallowing a parameter named `q` — a registry that governs media types and not
transfer codings. §12.4.2 calls the weight a common parameter named `q` and says
only what it means. §10.1.4 says nothing. No verified erratum touches any of
them.

So no clause settles it for `TE`, and this corpus grades both readings rather
than choosing one on a reader's behalf.

### Changed

- The corpus is 245 049 → 245 217 records. Corpora `A`..`E` digest identically;
  corpus F's and the whole run's are new.
- `recovered-member` 11 719 → 11 721. Both are corpus F's split spelling putting
  RFC 9110 §5.2's comma inside a parameter, which the walk recovers past.
- Two fault rows, `te-codings:MissingParameterValue` 2 and
  `te-codings:NotAToken` 7 — the same arm `te` uses, so they are new witnesses
  and not new variants.

### What this still does not say

There is no `TE` PAIR, because there is no second reader of `TE` in this
workspace: corpus F is one walk against an oracle. That is issue #80's own
sequencing — the oracle first, so a reader arrives into a graded production and
is held to it.

## `coding-corpus` — a member's extent, graded exactly, and the column that was its own baseline

Every axis this harness carried was a question about where a member BEGINS, so a
reader that ended its LAST member one well-formed parameter early — and yielded
nothing behind it — satisfied all of them. Issue #79 measured it: a walk patched
to do exactly that moved 6 050 records' `answer` and left every `grade` byte
identical over all 245 049. The only thing watching that column was a SHA-256
taken OVER it, so a reader that shipped truncating would have had the baseline
computed from the truncation. Closes #79.

### Added

- **The extent axis, `member-extent`, a zero-target.** For every member a reader
  began where RFC 9110 licenses an element to begin, the offsets of the
  parameter names it handed over must be the offsets of the parameter names of
  the derivation of that element which reaches a list boundary. Graded on 37 466
  members over 25 623 records.

  **Exact, and not a bound.** A bound — no parameter the grammar does not
  admit — is passed by a member that stopped a parameter early, because a
  truncation reads a strict PREFIX of what the grammar admits. That prefix is
  the whole of the defect class, so the comparison is equality.

- **A fourth question in the oracle: `Reading::member_params`.** The first three
  are about the bytes in FRONT of an offset, which is issue #77's finding; an
  extent is about the bytes BEHIND one, and it can be answered exactly because
  at most one end of an element is a list boundary. Every step the element walk
  takes past an end needs a particular byte to stand at it — `;` for a
  repetition, `=` for RFC 9110 §10.1.1's argument — and a boundary needs `,` or
  the value's end, so an end the element continues past is one the list does not
  admit.

- **No new public item, and none was needed.** Issue #79 costed an accessor on
  `ListMember` and `MediaRange` — a semver surface pinning where a member ends,
  a widening of two `Copy` types on the no-panic path, a borrow promise across
  RFC 9110 §5.2's join, and a `doc-check` snapshot move. None of it is required:
  a parameter's NAME is already a borrowed subslice, which is what `ParamIter`
  yields, and `place` already maps any such subslice to its offset in the
  §5.2-joined value. The offsets come through the public API as it stands.

- **The control that says the axis bites.**
  `the_extent_axis_reds_on_a_reader_that_truncates` runs the grader against the
  truncation issue #79 measured and against three shapes a truncation is not,
  and requires the honest reading to stay green in the same test. Re-run over
  the whole corpus, the mutation now reds `nothing_this_corpus_grades_is_a_defect`
  at **2 564 records**; before this change it redded the digest and one control
  and nothing else.

- **What the grading is NOT asked, counted rather than argued.** 225 768 member
  extents over 200 764 records are unasked: the reader refused the value, its
  production does not derive it, the member began where the grammar begins no
  element, or the member's own parameter walk faulted. Behind a fault a reader
  is recovering and its members are a derivation of nothing, so the question has
  no answer rather than an excused one.
  `the_extent_question_is_declined_only_where_nothing_could_answer_it` shows
  each reason to be the case it claims.

- **`media-q-dropped` (14).** `MediaRange::params` hands over every parameter
  except one named `q`, at any position, which is that reader's answer to RFC
  9110 §12.5.1. The extent grading has to know it to grade `accept` at all, so
  it is a licensed difference with a count rather than a silent subtraction.

### Changed

- `unplaced` now covers a parameter's name as well as a member's, and stays a
  zero-target: a `token` cannot cross RFC 9110 §5.2's join, because the join
  writes a comma and §5.6.2's `tchar` excludes it.
- No record's `answer` moved, so every digest and every per-corpus count is
  unchanged. The extent grading reads offsets the records never carried.

### What this still does not say

A member's extent is graded only where a derivation of the whole value exists to
settle it, which is a fifth of the members this corpus sees; the rest are
deliberately malformed. Where a reader recovers past a fault, the RFC 9112 §6.3
item 4 verdict projection remains the only thing narrowing where its members
stop, and the RFC 9110 §5.6.6 pairs have no verdict at all.

## `coding-corpus` — a pair is two walks or one walk twice, and the tally says which

A differential that counts a same-engine pair beside a cross-implementation one
overstates its own coverage, and a reader of a green run cannot tell which kind
produced it. That is the disease this harness exists to catch, in the harness.
It was concern 1 of the three the third reader was landed with; 5 and 6 are here
too.

### Added

- **A pair kind, in the key every pair is counted under.** `media::accept` is
  `parameterised_list_with(lines, is_media_name, …)` — the same walk the RFC
  9110 §5.6.6 comparison's first reader is, at a different member-name rule — so
  the (walk, `accept`) pair proves the CONFIGURATION is wired the way each field
  needs and proves nothing about whether that reading of §5.6.6 is right: a
  defect in the walk is in both halves. It is now `one-walk-twice`, and the four
  pairs whose halves decide a member's boundaries with separate loops are
  `cross-walk`. Four of the five pairs are the second kind. **The two totals are
  asserted apart** — 319 359 comparisons by two walks against 80 434 by one walk
  twice — so a pair filed under the wrong kind moves its own row AND both
  totals, and reds naming them.

  The kind says WALK and not implementation on purpose: every reader here
  reaches the same `http_semantics::grammar` primitives for §5.6.2's `tchar`,
  §5.6.3's `OWS` and §5.6.4's quoted-string scan — `http1-proto`'s accumulator
  imports `token_end`, `skip_ows`, `scan_quoted` and `scan_quoted_after_join`
  rather than spelling its own — so no pair here would part on a wrong `tchar`
  table. The oracle is what grades that layer.

- **`asked` beside `parted`, per pair.** A pair driven to zero partings by a
  comparability filter that stopped comparing anything looks exactly like a pair
  that agrees. The coverage is now a number: `te-walk-accumulator` 147 921,
  the three §5.6.6 pairs 80 434 each, `empty-accumulator-expect` 10 570.

- **How much weaker `accept`'s half of the boundary comparison is, measured.**
  It latches at its first faulting member, so on a faulting value it reports the
  starts in front of the fault and no others. Over the §5.6.6 comparison it put
  **24 200 member starts up for grading where the walk put 42 223** — 57 % — and
  the 18 023 it did not report fall on 15 904 records. The opposite direction is
  zero, asserted, which is what makes this half the weaker one rather than
  merely the different one. Nothing here can grade a start wrongly: an
  unreported start is one nothing was said about.

- **RFC 9110 §12.5.1's wildcard name shapes, and the trap they were.**
  `MediaRange::ty` is `None` for `"*/*"`, so a range of that shape would have
  been counted `unplaced` — a zero-target for a member whose name lay in none of
  the lines — and the first person to write a wildcard case would have got a red
  naming the wrong fact. Verified rather than argued: with the wildcard folded
  back into `unplaced`, the new cases red `nothing_this_corpus_grades_is_a_defect`
  at 4. Corpus D now writes all three shapes (`*/*`, `x/*`, `*/y`) behind five
  payloads, the wildcard is counted apart as `media-wildcard` (4), and its cost
  is stated: that member's start is graded by nothing. `x/*` and `*/y` both
  place their type, because the distinction is §12.5.1's ALTERNATIVE and not the
  asterisk.

### Changed

- `params-pair-parts`, `params-media-parts` and `params-expect-media-parts` are
  gone as states. They were pair partings counted in the same table as
  reachability states, with nothing saying which pair was which kind; they are
  now rows of the pair table, keyed by kind.
- Corpus D 329 → 344 records, and the corpus 245 034 → 245 049. Digest and
  per-corpus counts move with it; nothing else does.
- CI's comment on the `coding-corpus` job carried 239 420 records over three
  readers from the first commit of the branch. It is 245 049 over four, and it
  now names the pair-kind split as what a green run is worth.

### What this still does not say

`boundary-walk-short` has no row in the state table, and its absence is asserted
at zero rather than left to be noticed. The wildcard's ungraded start is a third
narrowing of the boundary comparison beside the two the crate doc already named.
And the (walk, `accept`) pair remains worth what a one-walk-twice pair is worth —
splitting the tally does not make it independent, it makes the run say so.

## `coding-corpus` — a third reader for §5.6.6, and the blind spot written where it cannot be missed

A harness built to remove blind spots must not ship with a known one it could
have closed, and must say plainly which one it could not. Two of the seven
concerns the differential was landed with are answered here.

### Added

- **A third RFC 9110 §5.6.6 reader: `media::accept`.** The §5.6.6 comparison
  could not be asked about a list of more than one element, because an element
  the payload's own comma opens carries no head, and a head is exactly where
  the readers' grammars differ. §12.5.1 is the rule that makes it askable:

  ```text
  media-range    = ( "*/*"
                     / ( type "/" "*" )
                     / ( type "/" subtype )
                   ) parameters
  ```

  Its `parameters` sit behind a name and behind NO bracket, which is the shape
  the walk's element has and §10.1.1's — `expectation = token [ "="
  ( token / quoted-string ) parameters ]` — does not. So the corpus writes one
  head per reader in front of EVERY element it intends (`x`, `x=1`, `x/y`), and
  holds all three to equal well-formedness pairwise over the one payload behind
  them. No product code changed: `media::accept` is already public.

- **Two-element spellings, and the count that says they are compared.** Each
  §5.6.6 payload is now also written as the first and as the second element of
  a two-element list, with a `parameters` payload of its own behind the head on
  the other side of the comma. `params-comparable-multi` counts the comparable
  records that are lists, and `params-comparable-multi-parameterised` (4 903)
  counts the ones where an element other than the first carries parameters —
  the question the comparison had never been asked. A change that reverted the
  two-element spellings leaves the first count looking healthy and reds the
  second.

- **Corpus E, so no verdict rests on a name.** Three of the eight RFC 9112 §6.3
  item 4 verdicts were reached once, twice and twice, entirely from hand-written
  values: an alphabet of nine bytes spells no second `chunked`. Corpus E
  enumerates one- to three-element coding lists over a small vocabulary and
  reaches all eight on its own, and `every_verdict_arises_from_the_list_generator`
  asserts that property rather than the numbers — which are asserted anyway. The
  three now stand at 17, 34 and 73.

- **Two licensed differences the third reader brings, both counted.**
  `axis-media-weight` (28) is §12.4.2's `qvalue` under the parameter name `q`,
  a rule §5.6.6 does not carry; `axis-media-borrow` (4) is a quoted value that
  crosses §5.2's field-line join, which is a fact about the LINES that the
  oracle — grading the one value §5.2 joins them into — cannot see. Both must be
  non-zero, or the licenses would be exempting nothing.

### What the differential does and does not compare, stated at the top

The crate doc now opens on it, in the words a maintainer needs: a green run says
whether a value parsed, where each member BEGINS, and the §6.3 item 4 verdict of
the one pair that has one. It does not say where a member ENDS — no reader hands
out a member's extent, so a walk that ended its LAST member early satisfies every
assertion. Measured rather than asserted: with the §5.6.6 walk patched to end its
last member one well-formed parameter short, the `grade` column is byte-identical
on all 245 034 records and every state, fault and verdict count is unchanged;
6 050 records render a different `answer`, so only the digest moves — and a
digest is a baseline a reader shipping with the defect would have been pinned to.
That needs a reader to EXPOSE extents, which is a public API decision rather than
a test fix; **#79** carries it with what it would cost. **#80** carries the other
one the doc now names: every §10.1.4 value here is a `Transfer-Encoding`, so
`TE`'s `weight` and its `"trailers"` alternative are ungraded.

### Changed

- The comparability filter is decided from the offsets the GENERATOR wrote a
  head at, rather than from the value's length and a `tailed` flag. Same rule,
  spelled as what it always meant, and it extends to lists of any length.
  75 503 comparable records became 80 419; 5 741 excluded became 5 923, which is
  6.9 % of the §5.6.6 records rather than 7.1 %. The remainder is exactly the
  payloads that open a head-less element, and it cannot go to zero: RFC 9110
  §5.6.2's `tchar` admits no solidus, so a name §12.5.1 derives is one the two
  token-headed readers refuse, and the other way round. There is no third
  choice, and `the_five_six_six_comparison_reaches_a_second_element_and_stops_at_a_headless_one`
  pins both halves.

## `coding-corpus` — three readers of two productions, and the first gate that asks whether they agree

Three walks in this workspace parse RFC 9110 §10.1.4's `transfer-coding` and
§5.6.6's `parameters`, and nothing asserted that any pair of them answers alike:

```text
transfer-coding    = token *( OWS ";" OWS transfer-parameter )
transfer-parameter = token BWS "=" BWS ( token / quoted-string )
parameters         = *( OWS ";" OWS [ parameter ] )
parameter          = parameter-name "=" parameter-value
parameter-name     = token
parameter-value    = ( token / quoted-string )
expectation        = token [ "=" ( token / quoted-string ) parameters ]
#element => [ element ] *( OWS "," OWS [ element ] )
```

`grammar::parameterised_list` under `ParamSyntax::TransferParameter` is the
public API for the first pair of rules; `http1-proto`'s `Transfer-Encoding`
accumulator is what actually reads the field off the wire; `grammar::Expectations`
reads the third. Each has its own tests, each passes, and each test was written
from the same reading that produced the implementation beside it — so a
divergence between two of them was invisible to every gate, and `gzip;` was
accepted by one and refused by another until an external reviewer read the ABNF.
Nine commits on the branch that fixed it said a differential would have found it.

### Added

- **`coding-corpus`, a differential over 239 420 records.** One corpus, every
  reader, and an assertion per pair. §10.1.4's two readers are held to EQUALITY,
  on well-formedness and on the RFC 9112 §6.3 item 4 verdict both — the second
  projected from the walk's member names, so a divergence in where a member ENDS
  is visible and not only one in whether the value parsed. §5.6.6's two readers
  are held to equality over one shared `parameters` payload written behind each
  reader's own head, because §10.1.1 puts `parameters` inside
  `[ "=" ( token / quoted-string ) parameters ]` and §5.6.6's has no head at
  all. §5.6.1.1's two readers are held to equality over values whose elements
  both element grammars derive. The two `ParamSyntax` arms are held to NO
  relation: each is graded against its own production, so the four differences
  PR #78 enumerated fall out as counted states rather than as exceptions.

- **An oracle written from the productions, not from any of the three.** It
  answers three questions and names what each is asked ABOUT, because #77
  records an oracle that asked whether the WHOLE value derives and answered "no
  reading licenses this" about a locally-admitted quoted string: whether the
  whole value derives, which offsets some derivation of a PREFIX begins an
  element at, and which offsets some prefix derivation reads as a
  quoted-string's data.

- **Zero-targets that are zero, and states that carry their count.** #77 records
  that `auth-corpus` pins `over-yield` at a non-zero constant instead of driving
  it to zero, and reaches `TooManyParameters` zero times because one generator
  always fires a different bound first. Neither happens here: five axes are
  zero-targets, every state carries the exact number of records that reach it,
  and the one residue — the bare parameter name §5.6.6 does not derive and
  `ParamSyntax::Parameter` hands over as `ParamValue::None` — is held to an
  exact characterisation in both directions rather than to a number.

- **A negative control for the strongest axis.** `manufactured-member` is zero
  over the whole corpus, and a zero nothing asks is worth nothing, so the grader
  is run against a reader written to commit the defect: one that splits the RFC
  9110 §5.2-joined value on every raw comma and takes each element's leading
  token, which reads a `chunked` out of a parameter value's own data. The axis
  has to fire on it, and must not fire on either arm that is live today.

- **The demonstration against the divergence #76 was filed over.** The pre-#78
  reading of a `Transfer-Encoding` is not stubbed, it is selected: before #78
  the walk had one parameter production — §5.6.6's — and read a
  `Transfer-Encoding` with it, so today's `ParamSyntax::Parameter` arm applied
  to one IS that reading on both axes the two productions differ on.
  `the_transfer_coding_pair_reds_on_the_pre_78_reading` asserts the pair parts
  on thirteen of the named values, `gzip;` among them, and that the arm live
  today parts on none.

- **`http1-proto`'s `differential` feature.** One doc-hidden, semver-exempt
  wrapper over the crate-private `Transfer-Encoding` accumulator, so the corpus
  can hand it the same field lines the §10.1.4 walk is handed. It adds no rule:
  every method forwards one call, and its verdict enum is an exhaustive
  re-spelling, so a variant added to the crate's own classification stops it
  compiling rather than being folded onto an existing row of the record.

### What the differential still cannot see

A member's EXTENT, except through the offset the next member begins at and
through the `Transfer-Encoding` verdict: no reader hands out where a member
ends, so a walk that ended its LAST member early and yielded nothing behind it
would satisfy every assertion. `recovered-member` — a member shown past a fault
at an offset no derivation reaches and no reading holds inside a string — is a
counted state and not a zero-target, because that is the walk not letting a
malformed member hide the members behind it; only the subset a reading DOES hold
inside a string is a defect. And a tally of grades cannot see an answer that
moves within its grade, which is what the SHA-256 over the `answer` column is
for; there is no two-revision driver for this corpus as `xtask auth-diff` is one
for `auth-corpus`, so finding WHICH record moved means running the binary at both
revisions and diffing.

## `http-semantics` — a boundary no reading ended in front of

The previous commit proved that no reading of the bytes behind a fault holds the
candidate comma inside an RFC 9110 §5.6.4 quoted-string. That is a proof about
where the member ENDS only where no reading had already ended it at an EARLIER
comma: a reading that stopped behind the candidate reads the bytes between the
two as a member of its own, and certifying the candidate hides it.
`scan_parameters` was asking about a comma some reading had already stopped in
front of.

```text
transfer-coding    = token *( OWS ";" OWS transfer-parameter )
transfer-parameter = token BWS "=" BWS ( token / quoted-string )
parameters         = *( OWS ";" OWS [ parameter ] )
parameter          = parameter-name "=" parameter-value
parameter-value    = ( token / quoted-string )
quoted-string      = DQUOTE *( qdtext / quoted-pair ) DQUOTE
```

`gzip;p="a, chunked;q="x", br` is the input. `grammar::parameter_end` cuts the
faulting repetition's extent by OPENING the string at the first parameter's
value position — it must, since that extent is what `grammar::ParamIter` hands
the caller — and that string closes at the DQUOTE at the second parameter's
value position, so the extent reaches the comma in front of `br`. Every reading
stands outside a string at THAT comma, so the analysis certified it and the walk
resumed at `br`. The reading that never opens the first string ended the member
at the comma behind `"a`, and reads `chunked;q="x"` as a `transfer-coding` of
its own. On `TE` and `Transfer-Encoding` that is a framing decision — RFC 9112
§6.1 makes `chunked` the coding that says where the message body ends — and
hiding one is the harm inventing one is.

So the candidate comes from the FAULT and from nowhere else. The earliest comma
from the fault is where the member ends under the reading that opens nothing,
and no reading ends it earlier, since an open string only ever hides a comma —
so every reading's own end lies at or behind that comma and none can have
terminated in front of it.

### Fixed

- **`grammar::refused_member_end` takes its candidate comma from the fault.**
  It no longer takes a cursor as well: the earliest comma from the fault is the
  only offset that can be certified, so the parameter that let a caller name a
  later one is gone. `scan_parameters` passes the `;` that opened the refused
  repetition and keeps that repetition's greedy extent for the refused member's
  SLICE alone — where the boundary is not derivable, the extent is handed back
  as an extent and `Refusal::Unbounded` says everything behind it is unread.
  `seek` and the arm of `member` behind RFC 9110 §5.2's join already stood on
  the fault and are unchanged in behaviour.

- **The three recovery entrances answer alike again.** They did not:
  `gzip;p="a, chunked;q="x", br` was a bounded refusal from `scan_parameters`
  and `ListError::MemberBoundaryUnknown` from both of the others, because only
  `scan_parameters` had a greedily cut extent to take a candidate from.
  `the_three_entrances_reach_one_verdict` carries that tail as a seventh row.

- **The brute force asks the rule as a rule.** `every_reading_ends_at` walks
  every opener choice and returns the offset only where EVERY reading ends the
  member there, which is the half a coverage question cannot state, and
  `every_reading_is_carried_over_a_generated_corpus` asserts
  `grammar::refused_member_end` against it over all 1,111,460 sections. The old
  corpus already held the shape — `;t=","t` is seven bytes over family A's own
  alphabet — and 2,039 of the sections stand in it; that count is asserted, so a
  corpus that stopped reaching the shape would red rather than pass quietly.
  The two entrance shapes the old test asked at were one question asked twice,
  which is why it never saw them: its refusal count halves exactly, 29,076 to
  14,538, and nothing else about the corpus moves.

- **And the corpus reaches that shape through the WALK, not only through the
  analysis asked directly.** Both of the spellings above stand where the walk
  dies: a section led by a `;` has an empty member name, which
  `grammar::parameterised_list` refuses before `scan_parameters` is entered. So
  every section is spelled a third way, with one `tchar` written in front of
  that `;`, and walked end to end — 585,730 of them, 1,831 standing in the
  shape and 775 deferring on it, each count asserted. The four counts the other
  two spellings assert do not move, and
  `the_shortest_named_section_in_the_shape_is_pinned` holds one such input on
  its own, measured offset by offset, so the shape outlives any change to the
  generator.

- **Why the walk carries the same underivable-boundary guard twice is
  asserted.** `a_joined_refusal_leaves_the_cursor_where_no_member_opens` sweeps
  every string family A's alphabet spells to seven bytes at every offset a
  quoted-string could close at: where `after_close` leaves a cursor no boundary
  is derivable from, that cursor is on a `;` and the element there is empty, so
  the walk reaches `seek` and asks the same question at the same offset. 858
  cursors reach it, and the count is asserted so the sweep cannot go quiet.

### Changed

- **Twenty-nine probed answers move and none of the previous commit's 410
  does.** Re-run byte for byte, the previous round's whole probe is identical;
  every mover is a shape this round adds, and every one is a refused repetition
  whose string swallows a comma.

- **Nineteen of them were hiding a `transfer-coding` the sender wrote.**
  Measured by walking the bytes behind the candidate comma on their own, which
  is what the reading that leaves the string shut reads there: ` chunked;q="x",
  br` is `chunked` and then `br` under both productions. That spelling appears
  at every entrance, mid-line, on a later line, behind §5.2's join, with the
  `BWS` §10.1.4 admits, with a settled repetition in front of the fault, and
  with a parameter fault of its own. The cost is that the `br` behind it — a
  member under every reading — is no longer reported either: the walk is
  ordered, and yielding `br` after `gzip` states a member sequence no reading
  has.

- **Eight were reporting a member only the greedy reading admits.**
  `gzip;p="a, b"c, chunked` yielded `chunked`, and the shut reading reads
  `b"c` there, which is no `token` and no member at all. So did
  `gzip;p="a, chunked"x, br` and `t;t=","t,t`, the shortest spelling over the
  generated corpus's own alphabet.

- **Two `media::media_type` answers change which refusal they report.**
  `text/plain;p="a, text/html;q="x", text/css` was `MediaError::NotASingleton`
  and is now `MediaError::Parameters(ListError::NotAToken)`. `has_bare_comma`
  reports no bare comma behind an unbounded refusal — the rule `698b8e9`
  established — so the value is refused for the parameter that does not parse
  rather than for a second media type whose comma the walk can no longer place.
  Both are refusals of the same value.

- **A member behind a refused repetition whose extent crosses no comma is still
  reported.** `gzip;p="a"x, chunked`, `gzip;p="a chunked"x, br` and
  `gzip;;x="a", chunked` are unchanged, and so are `gzip;q, chunked` and
  `m;;a="x;b="y,chunked,z",w`: where the extent reaches no comma the fault does
  not, the candidate is the same offset either way.

`cargo test -p http-semantics --all-features` reports 424 unit tests passing,
beside the no-panic harness's fifteen and one doctest; `--no-default-features`
reports 404. `http1-proto`'s 409 and `websocket-proto`'s 277 are unchanged, and
`xtask/snapshots/http-semantics-documented.txt` does not move — no documented
item is added or removed. The crate is still `no_std`, allocation-free and
panic-free on every tier, and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

## `http-semantics` — a comma some reading holds inside a string is no boundary

The previous commit decided a member's end behind a fault by COMPARING two
readings of the bytes in front of it: one that opens no RFC 9110 §5.6.4
quoted-string and one that opens every string the field's own production
admits. Two readings agreeing is not every reading agreeing, and the readings
between them are readings too.

```text
transfer-coding    = token *( OWS ";" OWS transfer-parameter )
transfer-parameter = token BWS "=" BWS ( token / quoted-string )
parameters         = *( OWS ";" OWS [ parameter ] )
parameter          = parameter-name "=" parameter-value
parameter-value    = ( token / quoted-string )
quoted-string      = DQUOTE *( qdtext / quoted-pair ) DQUOTE
```

`m;;a="x;b="y,chunked,z",w` is the input. The empty slot RFC 9110 §10.1.4
refuses is a fault, and behind it two positions admit a string. The greedy
reading opens the one at the `a` parameter's value — which swallows the DQUOTE
that would have opened the one at the `b` parameter's — so it and the raw
reading both end the member at the comma behind `y`, they agreed, and the walk
took it and yielded `chunked`. The reading that leaves the first shut opens the
second, and holds that comma and the `chunked` behind it inside a value the
sender wrote. On `TE` and `Transfer-Encoding` that is a framing decision made
up out of the sender's data, which is the one thing this walk exists not to do.

So the rule is no longer a comparison. It is a subset construction over every
choice of which admitted strings a reading opens, carried one byte at a time,
and the comma is taken only where NO reachable state holds it inside a string.

### Fixed

- **A member behind a fault is reported only where no reading of the bytes in
  front of it covers the comma.** `grammar::refused_member_end` takes the
  earliest comma `grammar::raw_comma_end` reaches — which is where the member
  ends under the reading that opens nothing, and no reading ends it earlier,
  since an open string only ever hides a comma — and hands it back only where
  the new `grammar::readings_at` reports every reading outside a string there.
  That walk carries `grammar::Readings`, three flags wide: some reading inside
  a string, some reading inside one with a `quoted-pair` backslash pending, and
  some reading holding one that reached a byte RFC 9110 §5.6.4 forbids and so
  can never close. The reading outside every string is the fourth state and
  needs no flag, because it is reachable at every offset. Each byte is stepped
  through `grammar::scan_quoted`, this crate's one implementation of what a
  quoted-string is, so no second spelling of `qdtext` and `quoted-pair` exists
  to drift from it.

- **The state walk starts at the FAULT, not at the offset the walk stands on.**
  `scan_parameters` finds its fault at a repetition whose own extent was already
  cut by opening that repetition's string, so it now passes the `;` that opened
  the refused repetition as well as its end. Without it
  `m;;a="x;b="y,chunked,z",w` read as RFC 9110 §5.6.6's `parameter` still
  yielded `chunked` — §5.6.6
  brackets the empty slot, so the fault there is the `a` repetition itself and
  the greedy cut of that repetition stood in front of the walk. `seek` and the
  arm behind §5.2's join stand on the fault already and pass it for both.

- **The property is brute-forced, since it is now provable rather than
  compared.** `every_reading_is_carried_over_a_generated_corpus` runs 1,111,460
  generated parameter sections — exhaustive over two alphabets, pseudorandom and
  longer over a third — and asserts, at both entrance shapes and under both
  productions, that the subset construction agrees with an independent
  enumeration of every opener choice, and that no member the walk yields over
  those bytes begins at an offset that enumeration says a reading covers. The
  corpus size, the 29,076 refusals it reaches and the 150,209 members it yields
  are asserted too, so a generator that produced nothing cannot pass it.

### Changed

- **Twenty-two of 410 probed answers move, every one of them the same way.** A
  boundary the previous commit took because two readings agreed is now refused
  because a third does not, and `ListError::MemberBoundaryUnknown` says so. None
  moves the other way and no answer moves between `Ok` and `Err` on the first
  member. **Eighteen stop yielding a `chunked` that stood inside a parameter
  value** — the reviewer's counterexample at every entrance, under both
  productions, with two admitted positions and with three.

- **The other four are members that were real, and boundaries that were not.**
  `m;;a="x;b="y, z", w` is one of the twenty-nine the previous commit restored,
  and its release note recorded that it recovered because both extremes cut at
  the same comma. The `w` behind that comma is a member under every reading; the
  COMMA is a separator under only some of them, and the same bytes with
  `chunked` in place of `z` turn that same boundary into an invented transfer
  coding. A boundary that is right by luck is not one this walk may take, so it
  is refused with the rest of its class, and `gzip;;a="x;b="y, chunked", br` and
  the RFC 9110 §5.6.6 spellings of both go with it. What a reading disputes here
  is where the member ENDS, which is exactly what
  `ListError::MemberBoundaryUnknown` reports.

- **A member whose boundary every reading agrees about is still reported.**
  `gzip;;x="a", chunked` and `gzip;q, chunked` are unchanged, and so is
  `gzip;;a="x;b="y", chunked` — the same shape as the counterexample with the
  exposed string CLOSING in front of the comma, where the readings differ about
  which strings open and agree about where the member ends anyway.

`cargo test -p http-semantics --all-features` reports 423 unit tests passing,
beside the no-panic harness's fifteen and one doctest; `--no-default-features`
reports 403. `grammar::quoted_comma_end` is replaced by `grammar::readings_at`
and `grammar::Readings`, so
`xtask/snapshots/http-semantics-documented.txt` goes from 734 documented items
to 741 — one deletion and eight additions. `http1-proto`'s 409 and
`websocket-proto`'s 277 are unchanged. The crate is still `no_std`,
allocation-free and panic-free on every tier — the state set is three `bool`s
and no collection — and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

## `http-semantics` — a string that closes before the comma moves no boundary

The previous commit stopped `grammar::parameterised_list` manufacturing a member
out of a parameter value, and stopped it too widely. Its trigger was a POSITION:
a repetition behind the refused one whose value BEGAN with a DQUOTE. RFC 9110
§10.1.4 and §5.6.4:

```text
transfer-coding    = token *( OWS ";" OWS transfer-parameter )
transfer-parameter = token BWS "=" BWS ( token / quoted-string )
quoted-string      = DQUOTE *( qdtext / quoted-pair ) DQUOTE
```

For `gzip;;x="a", chunked` the empty slot RFC 9110 §10.1.4 does not admit is a
fault, and `x`'s string does open at the position that production names — but it
CLOSES in front of the only comma, so both readings of the value end the member
there. `chunked` was knowable and was suppressed anyway, on one field line and
across §5.2's join alike. A DQUOTE where a string MAY open is not a string that
DOES cover the delimiter.

Two triggers have now been wrong in opposite directions: stopping at any fault
hid `chunked` in `gzip;q, chunked`, which holds no DQUOTE for any production to
open a string with, and stopping at a value position hid it above. So this one
is stated as a comparison of two computations rather than as a property of the
bytes, which is a thing that can be decided rather than judged.

### Fixed

- **A member behind a fault is reported whenever the two readings of the bytes
  in front of it agree.** `grammar::refused_member_end` now asks
  `grammar::raw_comma_end`, which opens no string at all, and the new
  `grammar::quoted_comma_end`, which opens every RFC 9110 §5.6.4 quoted-string
  the field's own `parameter` production admits, of the same bytes from the same
  offset. Where the two answer the same comma the member ends there: that comma
  is §5.6.1.2's separator whichever reading is the sender's, so the boundary is
  known WITHOUT deciding which one that is. Where they answer different commas,
  or the quoted one closes no string and so answers none,
  `ListError::MemberBoundaryUnknown` says the end is not derivable, exactly as
  before. `gzip;;x="a, chunked, b", br` still yields no `chunked`: there the two
  readings end the member 13 bytes apart.

- **One function, three entrances, and a test that reds if they part.**
  `scan_parameters`, the arm of the walk that handles a value which closed on a
  later field line and ran on past that close, and `seek` all ask
  `refused_member_end`, and none of them asks either scan directly — so the
  comparison cannot be half-applied. `the_three_entrances_reach_one_verdict`
  spells four tails at all three entrances under both `ParamSyntax` values and
  asserts one verdict for each of the twenty-four walks.

### Changed

- **Twenty-nine of 375 probed answers move, every one of them the same way.** A
  member the previous commit stopped yielding is yielded again, because both
  readings place its start at the same offset. None moves the other way, none is
  a member read out of a quoted-string, and no answer moves between `Ok` and
  `Err`. One of the twenty-nine, `gzip;;x="chunked", br`, is one of the thirty
  members that commit had lost; the other twenty-eight are shapes this round
  added to the probe, including the reviewer's `gzip;;x="a", chunked` at every
  entrance and under both productions.

- **Twenty-nine of those thirty stay lost, and each for a stated reason.**
  Twenty-five hold an admitted string that COVERS the earliest raw comma, so the
  two readings end the member at different offsets — `gzip;;q="a,b", chunked`
  ends it at offset 10 read raw and at 13 with the string open. Four hold one
  that never closes on the line in hand, so the quoted reading reaches no comma
  to be compared. Both are the underivable case and neither is a widening this
  commit could have taken without guessing.

- **A reading in which SOME admitted strings open is not asked.** The two scans
  are the extremes, and the previous commit's own counterexample —
  `m;;a="x;b="y, z", w`, where opening `a`'s string exposes a comma that the
  string the `b` parameter would open covers — now recovers, because both extremes cut at
  that same comma. The third reading is recorded in `refused_member_end`'s doc
  rather than left for the next reader to find.

`cargo test -p http-semantics --all-features` reports 422 unit tests passing,
two of them this change's, beside the no-panic harness's fifteen and one
doctest; `--no-default-features` reports 402. No older test moved with an
answer: every one of the twenty-nine had been measured by probe and pinned by
none. `http1-proto`'s 409 and `websocket-proto`'s 277 are unchanged.
`xtask/snapshots/http-semantics-documented.txt` goes from 733 documented items
to 734, one addition and no deletion. The crate is still `no_std`,
allocation-free and panic-free on every tier, and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

## `http-semantics` — what a fault leaves unknown is not the walk's to invent

`grammar::parameterised_list` cut a refused member at the first RAW comma behind
the repetition that earned the refusal, on the ground that a `parameters` which
has failed to derive opens no quoted-string behind itself. That reading cuts
inside bytes the sender wrote as a value. RFC 9110 §10.1.4:

```text
transfer-coding    = token *( OWS ";" OWS transfer-parameter )
transfer-parameter = token BWS "=" BWS ( token / quoted-string )
```

For `gzip;;x="a, chunked, b", br` the walk reported the malformed `gzip`, then a
`chunked` that had stood inside `x`'s quoted-string, then a `b"` that is no
`token` — which ends the walk and buries the `br` the sender really did write. On
the field that decides framing, manufacturing a coding and hiding one are the
same harm, and this input did both at once.

The other reading is no better. Admitting the string takes the comma in front of
`chunked` as data, and where that string never closes — `gzip;;q="oops, chunked`
— it swallows a coding the sender did send. Behind a fault neither reading is
derivable, and this stops offering either.

### Fixed

- **A member is never manufactured out of a parameter value.** The new
  `grammar::refused_member_end` crosses only the runs in which no
  `parameter-value` position stands: RFC 9110 §5.6.4's
  `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` opens at a DQUOTE,
  §5.6.6 and §10.1.4 admit one at the first byte of a `parameter-value` and
  nowhere else, §5.6.2's `tchar` excludes DQUOTE and §5.6.3's `OWS` is SP and
  HTAB. A comma with no such position in front of it is §5.6.1.2's separator
  under EVERY reading of the value, and the member behind it is reported.
  Reaching a repetition that does open one, there is no rule left to pick
  between the two readings: the walk yields the member the fault was found in,
  with that fault on it, and then the new `ListError::MemberBoundaryUnknown`.
  Everything behind an unresolved boundary is unread, and the walk says so
  rather than ending as though the value had.

- **The same question, asked at the two other places a refusal recovers.**
  `after_close` now stops a run-on value at its own repetition's end rather than
  running to the comma, so the cross-repetition question is asked once; and the
  walk's `seek` asks it of each element of a refused member it crosses, since
  `y"z;w="a, chunked, b"` standing behind one would otherwise resume the walk
  wherever that string's commas fall.

- **A comma the walk cannot vouch for is not evidence of a list.** RFC 9110 §8.3
  makes `Content-Type` a singleton, and `grammar::has_bare_comma` answers that
  through the same `member_end` the walk uses so the two cannot disagree. Where
  the boundary is underivable it now reports no comma, and `media_type` reports
  the parameter fault the value certainly does have:
  `text/plain;p x;q="a,b"` is `Parameters(NotAToken)` again, where the previous
  commit had made it `NotASingleton`. Three more values of that shape move with
  it, which retires that commit's second recorded concern.

### Changed

- **`ListError` gains `MemberBoundaryUnknown`.** The enum is `#[non_exhaustive]`,
  so no exhaustive match a caller wrote is broken. `media` needs no variant of
  its own: `MediaError::Parameters` carries it, as it carries every other walker
  detail. No public signature changes.

- **Fifty-six of 317 probed answers move**, measured over the public API against
  `ba20db0` and this tree. Fifty-one are the walk's, and every one of them is a
  refusal before and a refusal after. 19 stop yielding a member that had been
  read out of a quoted-string the field's own `parameter` admits — the finding,
  retired. 4 stop yielding one that stood behind a DQUOTE at such a position
  whose string never closes. 26 stop yielding one written outside every such
  string, whose position only a cross-reading argument establishes and which the
  walk therefore declines to place. 2 gain the trailing error alone, with
  nothing behind them to hide. The remaining five are `media_type`'s and each
  restores the answer it gave at `76617f6`. No value that parsed stopped
  parsing, and no answer moved from `Err` to `Ok`.

`cargo test -p http-semantics --all-features` reports 420 unit tests passing,
two of them this change's, beside the no-panic harness's fifteen and one
doctest; `--no-default-features` reports 400. Five older tests moved with the
answer they pinned, each of which had asserted that a member behind an
underivable boundary is yielded. `http1-proto`'s 409 and `websocket-proto`'s 277
are unchanged. `xtask/snapshots/http-semantics-documented.txt` goes from 725
documented items to 733, eight additions and no deletion. The crate is still
`no_std`, allocation-free and panic-free on every tier, and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

## `http-semantics` — a verdict taken after the boundary is a verdict that can move it

`grammar::parameterised_list` found a member's extent and then verdicted the
parameters inside it, in that order and in two passes. Three rounds of review
had each carried a little more information across RFC 9110 §5.2's field-line
join, and each time the boundary pass had already used bytes the verdict pass
would go on to refuse. This replaces the two passes with one: a repetition is
derived the moment its extent is settled and BEFORE the next repetition's bytes
are read, so no refusal can arrive after the boundary it is a refusal about.

### Fixed

- **A refused parameter could still hide the member written behind it.**
  RFC 9110 §10.1.4 brackets nothing —
  `transfer-coding = token *( OWS ";" OWS transfer-parameter )` — so `gzip;;q=…`
  states an empty `transfer-parameter` slot and is malformed. The walk said so.
  It then went on reading, admitted the quoted-string the `q=` behind that slot
  opened, and let it swallow the §5.6.1.2 comma in front of the next coding:
  `gzip;;q="oops, chunked` reported the fault on `gzip` and never said that
  `chunked` had been sent. A recipient that frames a body from
  `Transfer-Encoding` was told about one coding of the two.

  Once a repetition is refused, `parameters` has already failed to derive and
  nothing behind it derives either — so nothing behind it opens a quoted-string,
  and every comma behind it is the separator it looks like. `scan_parameters`
  now stops at the first refusal and recovers the member's extent with
  `grammar::raw_comma_end`, which is the rule `raw_run_end` and `after_close`
  already applied INSIDE a refused run, one level out. It is the same rule
  `auth::Challenges` settles a refused challenge with.

  Both spellings of the shape are fixed together, because one pass answers both:
  the joined `gzip;p="a` + `";;q="oops, chunked` the external reviewer wrote, and
  the single-line `gzip;;q="oops, chunked` that had the same hole and that no
  round had looked at.

- **What is left of a refused member is got past, not read.** A raw comma can
  fall inside bytes the sender wrote as a quoted-string, so cutting the member
  there leaves a tail — `b"` in `gzip;;q="a,b", chunked` — that is no member of
  anyone's. The walk crosses such elements by raw commas and resumes at the
  first one whose NAME its own grammar admits, so cutting early costs no member:
  `chunked` is still yielded. This also RETIRES a documented cost. At `76617f6`,
  `m;p ="a,b", second` read as `m` with a parameter fault and then
  `Err(NotAToken)` for a member `b"` the sender never wrote, and the `second`
  behind it was never reached; it now yields `m` and `second`.

- **A parameter behind the join is verdicted by the field, not only by the
  grammar.** `ListMember::params` can hand out only the repetitions on the line
  the member BEGAN on, so a rule a field applies to the pairs it is shown is a
  rule §5.2's join gets past. The rule is now DECLARED with the list instead.
  RFC 9110 §5.6.6 and §10.1.4:
  ```text
  parameter          = parameter-name "=" parameter-value
  parameter-name     = token
  parameter-value    = ( token / quoted-string )
  transfer-parameter = token BWS "=" BWS ( token / quoted-string )
  ```

  Neither brackets the `=`, so a bare name is always somebody's refusal. `TE` and
  `Transfer-Encoding` spell no grammar of their own over §10.1.4, so
  `parameterised_list` refuses one there — the new
  `ListError::MissingParameterValue`, at every entrance, `gzip;p="a` + `";q`
  included, where the value used to read `ValueSpansFieldLines`: well formed, and
  merely not contiguous, for a value §10.1.4 does not admit. §5.6.6's
  `parameters` is the production other fields EXTEND, and one whose own
  `parameter` brackets the value reads a bare name rather than refusing it, so
  the shape is still handed over as `ParamValue::None` there. `media` says which
  it is and gets `MediaError::ValuelessParameter` for `text/plain;p="a` + `";q`,
  the same answer `text/plain;charset` earns on one field line.

### Changed

- **`ListError` gains `MissingParameterValue`**, and `grammar::has_bare_comma`
  and `grammar::parameterised_list_with` — both crate-internal — take the field's
  answer for a valueless parameter beside its `ParamSyntax`. The public
  signature of `parameterised_list` is unchanged; what moves under it is
  §10.1.4's reading of a bare `transfer-parameter`, from a shape to a fault, at
  every entrance rather than at one.

- **Twenty-four of 240 probed answers move**, measured over the public API
  against `76617f6` and this tree. Every one is `Err` or a shape §10.1.4 does not
  admit before, and `Err` after; no member that was yielded stopped being
  yielded, and eleven answers gained a member that had been hidden. The §5.6.6
  callers move four: `accept(["text/plain;p=\"a", "\";q"])` is
  `ValuelessParameter` where it was `ValueSpansFieldLines`, and three
  `media_type` values whose parameter section is refused in FRONT of a quoted
  comma — `text/plain;p x;q="a,b"` among them — are `NotASingleton` where they
  were `Parameters(NotAToken)`. That last is the singleton check and the walk
  agreeing about which commas separate members, which is why both ask
  `member_end`; RFC 9110 §8.3 is what makes the singleton the first thing such a
  value violates.

`cargo test -p http-semantics --all-features` reports 418 unit tests passing,
two of them this change's, beside the no-panic harness's fifteen and one
doctest; `--no-default-features` reports 398. Four older tests moved with the
answer they pinned — two that expected a manufactured member behind a raw cut,
and two that expected a bare `transfer-parameter` to be a shape. `http1-proto`'s
409 and `websocket-proto`'s 277 are unchanged.
`xtask/snapshots/http-semantics-documented.txt` goes from 713 documented items
to 725, thirteen additions and one deletion — `ParamIter::resumed`, whose
deferred second pass this replaces. The crate is still `no_std`,
allocation-free and panic-free on every tier, and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

## `http-semantics` — one walk, two `parameter` productions, and the extent that may not come from the narrower

`grammar::parameterised_list` derived a member's extent from RFC 9110 §5.6.6's
`parameter`, whose `=` admits no whitespace on either side. That is the right
reading for the fields §5.6.6 governs. It is the wrong one for the two it does
not: RFC 9110 §10.1.4 spells `TE` out of a wider `parameter`, and RFC 9112 §7
gives `Transfer-Encoding` the same `transfer-coding`.

```text
TE                 = #t-codings
t-codings          = "trailers" / ( transfer-coding [ weight ] )
transfer-coding    = token *( OWS ";" OWS transfer-parameter )
transfer-parameter = token BWS "=" BWS ( token / quoted-string )
```

Reading that whitespace is not leniency. RFC 9110 §5.6.3 makes it a recipient's
obligation: "A recipient MUST parse for such bad whitespace and remove it before
interpreting the protocol element."

So `gzip;p = "a,b", chunked` — one conforming coding, one parameter whose quoted
value holds a comma, and a second coding behind it — was read with the narrower
production. `p ` is no `parameter-name` there, so no quoted-string opened, the
member ended at the comma INSIDE `"a,b"`, a member `b"` the sender never wrote
was invented, and because this walk stops at its first `Err` the `chunked` was
never yielded at all. Measured on `3a1a8ce`: `Ok(gzip)`, then `Err(NotAToken)`,
and nothing behind it. Measured on `9dd8708`, before either of the two commits
below: `Ok(gzip)`, then `Ok(chunked)`. **This branch introduced that**, and
hiding the final coding of a `Transfer-Encoding` from the reader that frames the
body is the same harm those two commits exist to close, one production over.

A boundary may never be derived from a production narrower than the value's own.
Getting an extent wrong hides bytes; getting a validity verdict wrong is a
lesser fault, and one the caller can tighten. The production is therefore
carried by the walk, and BOTH questions — where the member ends, and whether its
parameters parse — are answered from it, so the two can never come from
different grammars.

### Every difference between the two productions, and what each one costs

Introducing a second syntax mode means the two grammars diverge everywhere they
diverge, not once per review round. Derived from the ABNF rather than from the
code — RFC 9110 §5.6.6 at `rfc9110.txt:1818` and §10.1.4 at `:4647`:

```text
parameters      = *( OWS ";" OWS [ parameter ] )
parameter       = parameter-name "=" parameter-value
parameter-name  = token
parameter-value = ( token / quoted-string )
```

```text
transfer-coding    = token *( OWS ";" OWS transfer-parameter )
transfer-parameter = token BWS "=" BWS ( token / quoted-string )
```

They differ in three places and no others.

1. **`BWS` around the `=`.** §10.1.4 admits it on both sides; §5.6.6 admits
   none, and RFC 9110 §5.6.6 says so: "Parameters do not allow whitespace (not
   even `bad` whitespace) around the `=` character." Carried by `ParamSyntax`,
   which decides where a quoted-string may open and so where a member ends.
2. **Whether the slot may be EMPTY.** §5.6.6 brackets it; §10.1.4 does not.
   Carried by `ParamSyntax` too, but in `ParamIter` rather than in the boundary
   scan — an empty slot ends at the same byte under both, so only the verdict
   moves.
3. **Whether the head token is part of the rule.** §10.1.4 puts it inside
   `transfer-coding`, so a `TE` member name is §5.6.2's `token` and nothing
   else. §5.6.6's `parameters` has no head at all and takes one from whatever
   rule concatenates it — §8.3.1's `type "/" subtype`, for `media-type`. This
   one is carried by the member-name grammar each entry point supplies, and
   `parameterised_list`, the only door to `ParamSyntax::TransferParameter`,
   supplies `is_token`.

Everything else is the same rule written twice, and was compared rather than
assumed: the `*( OWS ";" OWS … )` repetition and its `OWS` on both sides of the
`;`; the `token` a parameter names; the `( token / quoted-string )` it values,
one alternative taken whole; §5.6.4's quoted-string inside that, so a comma in
one is data under both; and that neither production spells a bare name with no
`=`.

The `#`-list around them is RFC 9110 §5.6.1's under both, and §5.6.1.2's "A
recipient MUST parse and ignore a reasonable number of empty list elements"
governs both — a different level from difference 2, and conflating the two is
exactly what let `gzip;` pass. The optional `weight` that may follow a member is
§12.4.2's `weight = OWS ";" OWS "q=" qvalue` for `Accept` and for `TE` alike, so
`q` is spelled like a parameter under both and neither production resolves it;
this walk yields it as a parameter and the field separates it.

Two sentences §5.6.6 carries have no counterpart in §10.1.4 — RFC 9110 §5.6.6's
"Parameter names are case-insensitive." and its "A parameter value that matches
the token production can be transmitted either as a token or within a
quoted-string.  The quoted and unquoted values are equivalent." — and the walk
honours the difference by deciding neither: it hands over the bytes as written
under both, and `ListMember` and `ParamValue` derive no equality for that
reason. RFC 9112 §7's "All transfer-coding names are case-insensitive" is about
the coding NAME, not about a `transfer-parameter`.

### Breaking (unreleased)

- **`grammar::parameterised_list` takes a `ParamSyntax`.** There is no default,
  because there is no safe one: the two productions differ in where a
  quoted-string may open, that decides which commas are data, and a caller
  cannot repair the answer afterwards. A reader of `Content-Type` or `Accept`
  passes `ParamSyntax::Parameter`; a reader of `Transfer-Encoding` or `TE`
  passes `ParamSyntax::TransferParameter`. The new enum's own documentation
  carries the two ABNF productions and what picking the narrower costs.

### Fixed

- **A `transfer-parameter`'s `BWS` no longer splits a quoted value.**
  `gzip;p = "a,b", chunked` walked as `ParamSyntax::TransferParameter` is one
  coding whose parameter `p` is the quoted-string `a,b`, and `chunked` behind
  it; every spelling of the whitespace — either side of the `=`, SP or HTAB —
  answers alike, since RFC 9110 §5.6.3's `BWS = OWS` and `OWS = *( SP / HTAB )`.
  The `parameters` repetition RFC 9110 §5.2's join re-enters on a later field
  line uses the caller's production too, so a value that closed across the join
  and is followed by another parameter is delimited by the same rule that
  delimited the first.
- **A `transfer-parameter` is no longer optional.** RFC 9110 §5.6.6 writes its
  slot `[ parameter ]` and §10.1.4 writes `transfer-parameter` with no brackets,
  and the walk reused §5.6.6's unconditional skip for both — so `gzip;`,
  `gzip;;p=x` and `gzip;p=x;` produced no error under
  `ParamSyntax::TransferParameter`. `gzip;` was worse than accepted: the member
  dropped its `;` and stored an empty parameter slice, making it
  indistinguishable through `name()` and `params()` from a well-formed `gzip`,
  so a malformed `Transfer-Encoding` was reported as a conforming one to the
  reader that frames the body with it. A member now records whether it had a `;`
  at all, one with none walks no parameters under either production, and an
  empty slot — leading, interior or trailing — is `ListError::NotAToken` under
  `TransferParameter` and ends that member's parameter walk. §5.6.6 keeps its
  brackets: `text/plain;` and `text/plain;;charset=utf-8` are the media types
  they were.

- **RFC 9110 §5.2's join is not a way past a parameter's grammar.** §5.2 makes a
  field's lines one value, "concatenated in order, with each field line value
  separated by a comma", and a quoted-string open at a line's end carries its
  member across that comma — so the rest of that member's `parameters` are read
  on a LATER field line. `ListMember` holds only what the member occupies on the
  line it BEGAN on, which is all a borrowing walk can hand out, so `ParamIter`
  never reached those repetitions and nothing else verdicted them. `gzip;p="a` +
  `";;q=x, chunked` and `gzip;p="a` + `";q=x, chunked` therefore read alike
  through every public accessor — member `gzip`, one parameter reported as
  `ListError::ValueSpansFieldLines`, then member `chunked` — and the first of
  them states an empty `transfer-parameter` slot §10.1.4 does not admit.
  `ValueSpansFieldLines` names a value that is well formed and merely not one
  contiguous slice, so a recipient may recover from it and go on to frame a body
  with a `Transfer-Encoding` the RFC refuses.

  Those repetitions are now walked by `ParamIter` where they are cut, under the
  member's own production, and the first fault among them is carried on the
  member and reported in place of `ValueSpansFieldLines` — the one verdict this
  walk gives that would otherwise call the member well formed. Every other
  verdict already refuses the member and is left where the sender's order put
  it. The fault is CARRIED rather than returned from the member walk: an `Err`
  there ends the walk, and the member written BEHIND this one would be hidden by
  a fault in a parameter of this one, which is the harm the two entries above
  exist to close. The empty-slot rule itself is now stated once, in
  `grammar::empty_slot`, and read at both places a repetition is cut.

  The three answers `QuotedTail` gives the member's own value are the three a
  parameter behind the join now gets: one that closes across a later join and
  runs on past the close is `NotAToken`, since RFC 9110 §5.6.6's
  `parameter-value = ( token / quoted-string )` takes one alternative whole; one
  whose string is still open when the lines run out is
  `UnterminatedQuotedString`; and one that merely spans the join is no fault at
  all. A bare name is no fault behind the join either, for the reason it is none
  in front of it — neither production spells one, and this walk reports the
  shape and leaves the refusal to the field.

### Changed

- **What moves for a `ParamSyntax::Parameter` caller, and what does not.**
  `media::media_type`, `media::accept` and `grammar::has_bare_comma` name
  §5.6.6's production, which is what §8.3.1 and §12.5.1 give them. Every answer
  they give for a value on ONE field line is the one they gave at `3a1a8ce` —
  including the cost the entry below documents, that `m;p ="a,b", second` ends
  its member at the raw comma. That value is refused by §5.6.6 before the cut is
  reached; `gzip;p = "a,b", chunked` is not refused by §10.1.4 at all, and
  telling the two apart is the whole of the first change above.
  `media::media_type` and `has_bare_comma` read a single value and cannot reach
  the §5.2 join at all, so no `Content-Type` answer can move.
- **`media::accept` names the fault behind the join instead of the join.** It
  takes the field's LINES, so it is the one §5.6.6 caller the join is reachable
  from, and three of its answers move — each an `Err` before and an `Err` after,
  none turning a range that parsed into one that does not. `text/plain;p="a` +
  `";q = 0.5` and `text/plain;p="a` + `";q="0.5"j` are
  `MediaError::Parameters(NotAToken)` where they were
  `MediaError::ValueSpansFieldLines`, and `text/plain;p="a` + `";q="0` is
  `Parameters(UnterminatedQuotedString)`. What changes is that a value §5.6.6
  refuses is no longer reported as one it admits. `text/plain;p="a` +
  `";;q=0.5` does not move, because §5.6.6 brackets its slot and the empty one
  is a parameter it does not state rather than a fault.

`cargo test -p http-semantics --all-features` reports 416 unit tests passing,
twenty-two of them this change's — six for the `BWS`, six for the brackets and
the head token, and ten for the join — beside the no-panic harness's fifteen
and one doctest. Two older tests moved with the answer they pinned, both of them
about a fault standing BEHIND the join:
`a_later_parameters_trailing_bytes_are_not_the_head_parameters_fault` (from
`093ffa6`) is now `a_later_parameters_trailing_bytes_are_reported_and_not_as_its_own`
and expects `NotAToken`, and the §5.6.6 half of
`the_join_re_enters_the_callers_own_parameter_production` (from `7160a20`)
expects `NotAToken` where it expected `ValueSpansFieldLines`. Neither walk
changed and no boundary moved; what moved is whether a member holding a
malformed parameter reads as well formed. Every other test that stood at
`3a1a8ce` still passes, unrenamed and unedited, as do `http1-proto`'s 409 and
`websocket-proto`'s 277, both unchanged.
`xtask/snapshots/http-semantics-documented.txt` goes from 701 documented items
to 713, twelve additions and no deletions. The crate is still
`no_std`, allocation-free and panic-free on every tier — the `no_panic` shim
over this walk now drives the production as an OPAQUE argument, so both arms are
proved rather than one folded away — and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

## `http-semantics` — a `1#token` list has no quoted-string for a DQUOTE to open

`grammar::sender_list_shape` is the RFC 9110 §5.6.1.1 gate every outbound
`Connection` and `Upgrade` value passes, and it delimited its elements by
reading every DQUOTE as opening a §5.6.4 quoted-string. §7.6.1 spells
`Connection = #connection-option` with `connection-option = token`, and §7.8
spells `Upgrade = #protocol` out of `protocol-name` and `protocol-version`,
both `token`s — and §5.6.2's `tchar` excludes DQUOTE, so neither value admits a
quoted-string at any position. Every comma in one of them is the §5.6.1 separator
it looks like.

So a phantom string hid the very thing that gate exists to refuse. The value
`keep-alive",,", close` answered `Sendable` while carrying the `,,` RFC 9110
§5.6.1.1 forbids: "a sender MUST NOT generate empty list elements". 336 values
of length six or less did the same. And in the other direction, an unpaired
DQUOTE made a perfectly shaped list report as no list at all —
`keep-alive"x, close` is two elements, one of which is not a token, which is the
field's own grammar's business and not the shape check's.

`is_protocol_list` read the same walk. Its answers cannot move under either
reading — an element that differs between them always contains a DQUOTE, which
is no `tchar` — so the change there is to the reasoning alone, and its comment
now carries it.

The recipient half of the pair, `grammar::list_elements`, was already a raw comma
split and was already right; so were `token_list_contains`, `lists_a_protocol`,
`RangesSpecifier` and `http1-proto`'s `Content-Length` fold, none of which ever
entered this walker. `Expect` and `Transfer-Encoding` are the two lists whose
elements DO admit a quoted-string, via §5.6.6 `parameters`; both already delimit
their own and answer §5.6.1.1 from their own accumulators, and both stay there.

### Fixed

- **`grammar::sender_list_shape` counts the elements a `1#token` value really
  has.** Elements are delimited by the raw comma scan `grammar::raw_comma_end`
  already performed for a run §5.6.6 had refused; its documentation now names
  both kinds of run and each caller says which one it holds, the way
  `auth::raw_comma_end` does for §11.2's list. `grammar::is_protocol_list` is
  delimited the same way. `list_element_end` and `quoted_string_end` are gone:
  with the scan raw the first was a duplicate of `raw_comma_end`, and the second
  had no other caller.
- **`http1-proto` reports the empty element ahead of the grammar fault for a
  value that states both.** `Connection: a",,",b` and `Upgrade: a",` were
  refused with `an interpreted field states its own grammar`; they are now
  refused with `a list field states no empty element`, which is the fault the
  sender's bytes carry first. Both were refusals before and after; no message
  this core would have written becomes writable, and none that was writable is
  refused.

### Changed

- **BREAKING (unreleased): `grammar::ListShape` loses its `Unparseable` variant.**
  A downstream `match` on this public enum stops compiling; `http1-proto`'s, the
  only one in the tree, is exhaustive again with the two variants that remain.
  It meant "not a list at all — a quoted-string opens and never closes", and
  with no quoted-string admitted anywhere in the two lists this reader serves,
  nothing can produce it.
  The distinction it drew is real and still lives where it belongs: `Expect` and
  `Transfer-Encoding` keep a `parsed` answer separate from an empty-element one,
  because a value ending inside an open string genuinely has no boundary to call
  empty.

`cargo test -p http-semantics --all-features` reports 394 unit tests passing,
one of them this change's, beside the no-panic harness's fifteen and one
doctest; every one of the 393 that stood at `093ffa6` still passes, unrenamed and
unedited, as do `http1-proto`'s 409 (one new) and `websocket-proto`'s 277
(unchanged). `xtask/snapshots/http-semantics-documented.txt` goes from 704
documented items to 701. The crate is still `no_std`, allocation-free and
panic-free on every tier, and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

## `http-semantics` — a §5.6.6 member's extent is not for its refused bytes to decide

`grammar::parameterised_list` is the walk `media_type` and `accept` — so
`Content-Type` and `Accept` — enter through, and it decided where a member
stopped by reading EVERY DQUOTE as opening an RFC 9110 §5.6.4 quoted-string.
(`TE`, `Transfer-Encoding` and `Sec-WebSocket-Extensions` were named here when
this was written and do not enter through it: the first two are `http1-proto`'s
`CodingList` and the third is `websocket-proto`'s own §9.1 walk, which
`negotiation.rs` says in as many words why. The entry below this one is what
that mistake cost.) §5.6.6 admits one at a single position — the first byte of a
`parameter-value` — and three defects followed from that difference (#71).

**Bytes consumed without validation.** `parameterised_list(["m;p=\"a", "\"junk"])`
joins to `m;p="a,"junk`: the string closes across §5.2's join and `junk` stood
behind it, dropped without a word while the parameter reported
`ValueSpansFieldLines` — the variant that says a value is well formed and merely
not one contiguous slice. RFC 9110 §5.6.6 spells
`parameter-value = ( token / quoted-string )`, one alternative taken WHOLE, so
that value is not derivable and it now reports `NotAToken`: the same fault the
walk already reported when the close and the bytes behind it lay on one field
line.

**Bytes already proven invalid still steering the boundary.**
`parameterised_list(["m;p=\"a", "r\"ju\"nk, second"])` dropped `second`
entirely. Once `p`'s value has closed and non-`OWS` stands behind it the
remainder derives nothing — and a run that derives nothing holds no
quoted-string, so the DQUOTE inside `ju"nk` opens none and the comma in front of
`second` is the §5.6.1.2 separator it looks like. Recovery now runs to the first
RAW comma and the hidden member is yielded.

**A DQUOTE where the grammar admits no string at all.** The third entrance the
#71 comment predicted is present here, and was measured in four shapes:
`m;p=x"y, second`, the value having already taken the `token` alternative;
`m;p="a""b, second`, behind a value that already closed; `m;p"x, second`, at a
`parameter-name`; and `["m;p=x\"y", "second"]`, where the unadmitted DQUOTE held
the member open across §5.2's join and swallowed the whole next field line. Each
hid the member written behind it.

The rule is stated at BOTH of this grammar's delimiter levels, which is what
`auth`'s single-level version of it did not have to be. RFC 9110 §5.6.6's
`parameters = *( OWS ";" OWS [ parameter ] )` repeats, so a value that closes
across the join may be followed by another `parameter` — and that one admits a
quoted-string of its own, commas and all. `ext;p="a` + `"; q="b, c", other` is one member and two
parameters, and a boundary scan that answered the close with a raw-comma scan
would cut it inside `q`'s value. So the close re-enters the `parameters` loop
where §5.6.6 says it may, and only a remainder that has been REFUSED is read raw.

RFC 9110 §5.6.6's `parameter` has no `BWS`, and this reads it that way:
"Parameters do not allow whitespace (not even "bad" whitespace) around the "="
character." §11.2's `auth-param` does have it, so `crate::auth`'s helpers keep
their own reading and are NOT refactored into a shared primitive with this one;
the two `param_value_at`s and the two `after_close`s each name the other in
their doc comments so a reader finds both. **What that reasoning missed is that
§10.1.4's `transfer-parameter` has the `BWS` too**, and this one walk serves it
— which is the entry above this one, and the reason `parameterised_list` now
takes the production as an argument.

### Fixed

- **`grammar::parameterised_list` — a member ends where the productions the
  sender's bytes actually reach say it ends.** A DQUOTE opens a quoted-string
  only at a `parameter-value`'s first byte; a value that closed is not a value
  that ended, and only `OWS` may stand between the close and the `;` or `,`
  behind it; and a run some production has already refused is recovered to the
  first raw comma, granting no DQUOTE in it any standing. `QuotedTail` gains a
  third answer for the one verdict a member's own slice cannot carry — a value
  that closed across §5.2's join with bytes behind that close — and
  `parse_param` reports it as the `NotAToken` it is.

### Changed

- **`media::media_type` reports `NotASingleton` where it used to report a
  parameter fault, for a comma no quoted-string admits.**
  `text/plain;p=x"y,z"` names two members: `p`'s value took the `token`
  alternative, so the DQUOTE opens nothing and the comma is §5.6.1.2's. §8.3's
  singleton violation is what such a value breaks first, and `has_bare_comma`
  now answers through the same `member_end` the walk behind it uses rather than
  through a scan with a rule of its own.

`cargo test -p http-semantics --all-features` reports 393 unit tests passing,
eight of them this change's, beside the no-panic harness's fifteen and one
doctest; every one of the 385 that stood at `9dd8708` still passes, unrenamed
and unedited. `xtask/snapshots/http-semantics-documented.txt` goes from 697
documented items to 704: `scan_to_delim` is gone, and `param_value_at`,
`raw_run_end`, `raw_comma_end`, `after_close`, `parameter_end`,
`scan_parameters`, `member_end` and `QuotedTail::Trails` replace it. The crate is
still `no_std`, allocation-free and panic-free on every tier, and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

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

`xtask/snapshots/http-semantics-documented.txt` gains 125 lines and loses none:
`grep -vc '^#'` counts 572 documented items on it at `6360957` and 697 here.
`cargo test -p http-semantics --all-features` reports 385 unit tests passing, 87
of them this module's, beside the no-panic harness's fifteen and one doctest.
The crate is still `no_std`, allocation-free, clock-free and panic-free, on the
same `std` / `alloc` / `no-atomic` tiers its siblings run, and
`cargo check -p http-semantics --no-default-features --target thumbv6m-none-eabi`
is green.

The walk's answers are also graded from OUTSIDE the crate. `auth-corpus` reads
935 032 inputs through the three entry points and grades each against an oracle
written from RFC 9110 rather than from this module — does a malformed challenge
hide a well-formed one behind it? — and `cargo test -p auth-corpus`, a step in
CI's `test` job, pins the per-corpus tally that answer produces, the fault each
answer names, and a SHA-256 of the answers themselves. The tally is blind by
construction to an answer that moves inside its own axis class; the digest is
blind to nothing, and is the number `cargo run -p xtask -- auth-diff` publishes.
So a change here that moves what a caller is shown moves a number in that diff,
where a reviewer can ask which and why.

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
  fills the last slot there is, carries a byte §5.6.4 forbids inside a
  quoted-string, or takes the challenge past `MAX_CHALLENGE_LINES`, **that
  challenge is refused and the rest of its extent is found by raw commas
  alone** — so `Basic a="q` followed by
  `r"junk, trap="open, Digest realm=z` reports one `MalformedParameter` and
  still yields `Digest`, where a walk that found the boundary first and derived
  the body afterwards let `trap="` swallow the comma in front of it. Deriving
  each element before the next element's bytes are read is what makes that
  true, and the `auth` module's own documentation states it as the invariant a
  change there has to keep.

  **No fault ends the walk.** `AuthError::InvalidQuotedString` was the one
  exception, on the argument that a scan which failed inside a quoted-string can
  no longer tell which commas separate elements. That argument states the
  premise of the invariant above and then declines its conclusion: raw-comma
  recovery is what a walk which cannot trust a comma does. So
  `Basic a="x\0, Digest realm=z` now reports `InvalidQuotedString` and still
  yields `Digest`, where it used to hide it. Every byte that raises that fault
  is a CTL other than HTAB, which §5.5 admits nowhere in a field value — it puts
  a MUST on CR, LF and NUL and calls the rest "also invalid" — so there is no
  derivation of the value for the recovery to be wrong about, and `obs-text` is
  the pair that keeps the rule honest: `%x80-FF` IS `qdtext`, so
  `Basic realm="a\xffb, Digest realm=z"` stays ONE challenge with ONE
  parameter, comma and all.

  Where that recovery starts is where the scan stood, which differs between a
  forbidden byte met on the head field line and one met after §5.2's join — so
  a value written on one line and the same value split across a join can yield
  different numbers of challenges. Both yield at least what they yielded when
  this fault ended the walk, and the challenge that differs is never one any
  derivation of the value admits. `Challenges::skip_element` records it.

  **A refusal BINDS where it is met, and is never a fact left for a later
  reader.** The five faults an element carries are returned by the check or the
  scan that found them, one element at a time. The sixth — the line bound — is
  met at
  three crossings and binds at each, and the one that matters is the crossing an
  element still OPEN across §5.2's join makes: taking the region left behind and
  asking for the next line are ONE operation there, so a challenge that may not
  hold the line has no line to read, and `Basic a="x` followed by sixteen
  continuation lines and then `\0, Digest realm=z` answers
  `ChallengeSpansTooManyLines` and still yields `Digest` rather than reading a
  byte §5.6.4 forbids on a line it had already refused and ending the walk
  there. A section that has refused holds no body at all, so the two readers
  that answer for a crossing which could not return a verdict — the bound asked
  before the next element, and the region the challenge ends in — can be handed
  nothing instead.

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
  such a recovery reports one. No challenge a sender wrote is ever lost by it,
  and a caller counting the `Err`s of a malformed value is counting something
  this reader decides. What a caller can be shown that the sender did not write
  is two cases and two only, and they are not the same kind of thing.
  `MAX_CHALLENGE_LINES` is this recipient's refusal rather than a fault of the
  sender's, so it is the only one that can refuse a value some derivation still
  admits — a quoted-string that would have closed on a line past the bound — and
  a comma the sender put inside such a value is then read as the separator it is
  not. `AuthError::InvalidQuotedString` can do the same arithmetic, but only on
  a field value §5.5 admits nowhere, so what is recovered there was never a
  value to be the data of. Both constants carry their trade and why ending the
  walk instead is the worse half of it; `challenges` says both where a caller
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

  `AuthParamIter` is `core::iter::FusedIterator`, and the promise is not a
  formality: the walk records WHY it has no next element, and a fault it can
  only meet by reading past the credential it was built from is recorded rather
  than dropped. Being infallible, this iterator can answer a fault only by
  ending — so the two ways it can end are kept apart, and a debug build asserts
  of every `Credential` this crate builds that walking its own parameters
  reaches the end of the credential rather than a fault behind it.

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
