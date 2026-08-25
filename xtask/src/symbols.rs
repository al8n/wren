//! The symbol table of a linked executable, read here rather than shelled out.
//!
//! [`shim_check`](crate::shim_check) asks the LINKER which `#[no_panic]` shims a
//! build actually instantiated. That question has an exact answer and no
//! reading of the source has it, so the answer has to come out of the artifact
//! — and `xtask` takes no dependencies, so the reader is written rather than
//! imported.
//!
//! It is written rather than shelled to `nm` for one reason: `nm` is a tool
//! that may not be installed, and a check whose answer depends on whether a
//! tool is present has a second way to go quiet. This has none. It reads the
//! two object formats this workspace's proofs are ever linked into — ELF64 on
//! the Linux runner CI's `no-panic` job uses, Mach-O 64 on a developer's
//! machine — and REFUSES anything else by name.
//!
//! # Refusing is the point
//!
//! Every path out of here that is not a symbol table is an [`Err`] naming what
//! it saw. Returning an empty list instead would be the same shape of defect
//! `shim-check` exists to report: a check that examined nothing, reporting a
//! number that reads like a result. An empty table and a table this could not
//! read must not be one answer, so they are two — and the caller fails on
//! both, with different words.
//!
//! That rule governs the BYTES as well as the file. Every extent this walks is
//! the one the file declares — a section's `sh_size`, a load command's
//! `cmdsize`, `sizeofcmds`, `strsize` — and a name offset outside its string
//! table, or a name with no terminator inside it, is refused rather than
//! improvised over. A reader that scans to end-of-file for a NUL, or that
//! follows a string table's offset without its size, answers out of whatever
//! bytes happen to follow: a truncated table whose tail still spells a shim's
//! name would then be read as CONTAINING that shim. "Cannot read this table"
//! and "this table does not contain that shim" are the same two answers as
//! above, one level down, and they are kept apart the same way.
//!
//! # What counts as a symbol for the shim's name
//!
//! A name is not an identity. An executable contains every dependency's
//! symbols and every symbol it merely references, so a name alone can be
//! spelled by another crate, by another module, or by an UNDEFINED entry that
//! defines nothing at all. The caller's question is whether THIS build
//! generated the shim's code, so [`read`] classifies each entry — is it a
//! defined function, in a section of this file that holds instructions? — and
//! [`rooted`] parses the mangled path down to the crate root it hangs off and
//! the item under it. Either half alone can be satisfied by a collision;
//! together they cannot.
//!
//! Nor is a crate NAME an identity. Several crates in one link may be called
//! `no_panic` — one may simply be named that, and this workspace's `no-panic`
//! dependency is — and what tells them apart is the disambiguator v0 writes
//! beside the name. [`Rooted`] keeps it, [`Rooted::same_crate_as`] compares it,
//! and the caller establishes which crate the binary IS from the binary itself
//! before crediting any symbol to it.
use std::{fs, path::Path};

/// The `\x7fELF` magic.
const ELF: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// Mach-O's 64-bit magic `0xFEEDFACF`, as the four bytes a little-endian file
/// stores it in.
const MACHO_64_LE: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];
/// The same magic as a big-endian file stores it.
const MACHO_64_BE: [u8; 4] = [0xfe, 0xed, 0xfa, 0xcf];
/// Mach-O's 32-bit magic `0xFEEDFACE`, both ways round — recognised only so the
/// refusal can name it.
const MACHO_32_LE: [u8; 4] = [0xce, 0xfa, 0xed, 0xfe];
/// The 32-bit magic stored big-endian.
const MACHO_32_BE: [u8; 4] = [0xfe, 0xed, 0xfa, 0xce];
/// A universal ("fat") Mach-O archive, both ways round.
const MACHO_FAT_BE: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
/// The fat magic stored little-endian.
const MACHO_FAT_LE: [u8; 4] = [0xbe, 0xba, 0xfe, 0xca];

/// `SHT_SYMTAB`, the ELF section type holding the full symbol table.
const SHT_SYMTAB: u32 = 2;
/// `SHT_STRTAB`, the section type a symbol table's `sh_link` must name.
///
/// Checked rather than assumed: `sh_link` is an index, and an index into a
/// table of sections of every kind is not a string table until its type says
/// so. Following it blind is how a symbol name comes out of whatever section
/// the number happened to reach.
const SHT_STRTAB: u32 = 3;
/// `SHT_DYNSYM`, the dynamic-linking subset. Read as well as `SHT_SYMTAB`
/// because a `strip`ped executable keeps only this one, and a table that is
/// present but cannot hold a file-local `fn` is better reported by the shim it
/// fails to find than by a missing section.
const SHT_DYNSYM: u32 = 11;
/// `STT_FUNC`, the low nibble of `st_info` an ELF symbol addressing code
/// carries. A `static` is `STT_OBJECT` and a section marker is `STT_SECTION`;
/// neither is a function this build generated.
const STT_FUNC: u8 = 2;
/// `SHN_UNDEF`. A symbol in section zero is one this file REFERENCES and does
/// not define — the name is in the table, the code is not in the binary.
const SHN_UNDEF: u16 = 0;
/// `SHN_LORESERVE`. From here up an `st_shndx` is not an index into the section
/// header table at all: `SHN_ABS` (0xfff1) says the value is absolute and
/// `SHN_COMMON` (0xfff2) says it is an unallocated common block. Neither names
/// a section, so neither carries a body — and looking either up as an index
/// would read whichever section header happened to sit at 65521.
const SHN_LORESERVE: u16 = 0xff00;
/// `SHN_XINDEX`, the escape a file with more than 65279 sections uses: the real
/// index is in that symbol's `SHT_SYMTAB_SHNDX` entry, which this does not
/// read. REFUSED rather than answered — see [`defines_code`].
const SHN_XINDEX: u16 = 0xffff;
/// `SHF_EXECINSTR`, the section flag that says a section holds instructions.
///
/// Required of the section a defined `STT_FUNC` points into, because
/// `STT_FUNC` is a CLAIM about a symbol and the section is where the claim
/// would have to be paid: a type byte with no executable bytes behind it
/// defines no body, and the question this reader answers is whether the body
/// was generated.
const SHF_EXECINSTR: u64 = 0x4;
/// `LC_SYMTAB`, the Mach-O load command pointing at the symbol table.
const LC_SYMTAB: u32 = 0x2;
/// `LC_SEGMENT_64`, the load command whose sections this reads so a symbol's
/// `n_sect` can be told from a data section's.
const LC_SEGMENT_64: u32 = 0x19;
/// `N_STAB`. Any bit of this mask set makes the entry a debugger symbol, whose
/// `n_type` is not the `N_TYPE` field at all.
const N_STAB: u8 = 0xe0;
/// The `N_TYPE` field of a Mach-O `n_type`.
const N_TYPE: u8 = 0x0e;
/// `N_SECT`: defined, in the section `n_sect` names. `N_UNDF` (0) is the
/// undefined case this refuses to count.
const N_SECT: u8 = 0x0e;
/// `S_ATTR_PURE_INSTRUCTIONS`, the section attribute that says a section holds
/// code. Mach-O's symbol table has no function type, so a defined symbol is a
/// function here exactly when the section it lives in is instructions.
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;

/// One entry of a linked executable's symbol table.
#[derive(Debug)]
pub struct Symbol {
  /// The name exactly as the table spells it: MANGLED, and with Mach-O's
  /// leading `_` still on it.
  ///
  /// Demangling in full would need a decoder for two whole grammars and buy
  /// nothing: [`rooted`] parses the part of the path this asks about — the
  /// crate root and the item under it — which both schemes spell straight, and
  /// neither escapes the identifiers involved.
  pub name: String,
  /// Whether this entry DEFINES a function in this file.
  ///
  /// The caller's question is whether the shim's code was generated, and only
  /// a defined function answers it. An undefined entry names code that is
  /// somewhere else; a data symbol names no code at all.
  pub defined_function: bool,
}

/// Every symbol in the executable at `path`.
pub fn read(path: &Path) -> Result<Vec<Symbol>, String> {
  let bytes = fs::read(path).map_err(|err| format!("could not read {}: {err}", path.display()))?;
  let magic: [u8; 4] = bytes
    .get(..4)
    .and_then(|head| head.try_into().ok())
    .ok_or_else(|| format!("{} is shorter than a file header", path.display()))?;
  match magic {
    ELF => elf(&bytes),
    MACHO_64_LE => macho(&bytes, true),
    MACHO_64_BE => macho(&bytes, false),
    MACHO_32_LE | MACHO_32_BE => {
      Err("a 32-bit Mach-O executable; this reads 64-bit Mach-O and ELF64 only".to_string())
    }
    MACHO_FAT_LE | MACHO_FAT_BE => Err(
      "a universal (\"fat\") Mach-O archive rather than a single executable; \
       this reads one architecture's symbol table, not a chooser over several"
        .to_string(),
    ),
    other => Err(format!(
      "an object format this does not read: the file begins {other:02x?}. ELF \
       and 64-bit Mach-O are the two the `no-panic` proofs are linked into"
    )),
  }
  .map_err(|err| format!("{}: {err}", path.display()))
}

/// A byte slice read with a known endianness, every read bounds-checked.
struct At<'a> {
  bytes: &'a [u8],
  little: bool,
}

impl At<'_> {
  /// The `u8` at `at`.
  fn u8(&self, at: usize) -> Option<u8> {
    self.bytes.get(at).copied()
  }

  /// The `u16` at `at`.
  fn u16(&self, at: usize) -> Option<u16> {
    let raw: [u8; 2] = self.bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(if self.little {
      u16::from_le_bytes(raw)
    } else {
      u16::from_be_bytes(raw)
    })
  }

  /// The `u32` at `at`.
  fn u32(&self, at: usize) -> Option<u32> {
    let raw: [u8; 4] = self.bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(if self.little {
      u32::from_le_bytes(raw)
    } else {
      u32::from_be_bytes(raw)
    })
  }

  /// The `u64` at `at`.
  fn u64(&self, at: usize) -> Option<u64> {
    let raw: [u8; 8] = self.bytes.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(if self.little {
      u64::from_le_bytes(raw)
    } else {
      u64::from_be_bytes(raw)
    })
  }

  /// The NUL-terminated string in `at..end`, or nothing when there is no NUL
  /// inside that extent.
  ///
  /// `end` is the string table's DECLARED end, not the file's. A name whose
  /// terminator is not inside the table is a name this cannot read: scanning
  /// on would return whatever follows the table, which is exactly how a
  /// truncated table comes back holding a symbol it does not hold. Invalid
  /// UTF-8 inside the extent is replaced rather than refused — a symbol name
  /// is compared, never executed.
  fn cstr(&self, at: usize, end: usize) -> Option<String> {
    let field = self.bytes.get(at..end)?;
    let len = field.iter().position(|byte| *byte == 0)?;
    Some(String::from_utf8_lossy(field.get(..len)?).into_owned())
  }
}

/// `value` as a `usize`, or nothing on a 32-bit host where it does not fit.
fn index(value: u64) -> Option<usize> {
  usize::try_from(value).ok()
}

/// Whether `start..start + len` is inside a file of `total` bytes.
fn inside(start: usize, len: usize, total: usize) -> bool {
  start.checked_add(len).is_some_and(|end| end <= total)
}

/// Every symbol in an ELF file.
fn elf(bytes: &[u8]) -> Result<Vec<Symbol>, String> {
  match bytes.get(4) {
    Some(2) => {}
    Some(1) => return Err("a 32-bit ELF file; this reads ELF64".to_string()),
    other => return Err(format!("an ELF file with class byte {other:?}")),
  }
  let little = match bytes.get(5) {
    Some(1) => true,
    Some(2) => false,
    other => return Err(format!("an ELF file with data byte {other:?}")),
  };
  let at = At { bytes, little };
  let total = bytes.len();

  let bad = || "an ELF64 header this could not read".to_string();
  let sections = index(at.u64(0x28).ok_or_else(bad)?).ok_or_else(bad)?;
  let entry_size = usize::from(at.u16(0x3a).ok_or_else(bad)?);
  let mut count = usize::from(at.u16(0x3c).ok_or_else(bad)?);
  if entry_size < 0x40 {
    return Err(format!(
      "an ELF64 file whose section headers are {entry_size} bytes; the format's \
       are at least 64"
    ));
  }
  if sections == 0 {
    return Err(
      "an ELF64 file whose `e_shoff` is zero, so it carries no section header \
       table and no section a symbol table could be"
        .to_string(),
    );
  }
  // `e_shnum == 0` means the real count is in section zero's `sh_size` — the
  // escape ELF uses past 65535 sections. Handled rather than refused: it is
  // legal, and a linker that starts emitting it should not turn this check off.
  if count == 0 {
    if !inside(sections, entry_size, total) {
      return Err(format!(
        "an ELF64 file whose section header table starts at {sections}, which \
         is not {entry_size} bytes inside a file of {total}"
      ));
    }
    count = index(at.u64(sections + 0x20).ok_or_else(bad)?).ok_or_else(bad)?;
  }
  let span = count
    .checked_mul(entry_size)
    .ok_or_else(|| "an ELF64 section header table longer than this host can address".to_string())?;
  if !inside(sections, span, total) {
    return Err(format!(
      "an ELF64 file declaring {count} section header(s) of {entry_size} bytes \
       at {sections}, which does not fit in a file of {total} bytes"
    ));
  }

  // Every section header first, so a symbol table's `sh_link` can address the
  // string table it names — and so that string table's TYPE and extent can be
  // checked before a name is read out of it.
  let mut headers = Vec::with_capacity(count);
  for nth in 0..count {
    let start = sections + nth * entry_size;
    headers.push(Section {
      kind: at.u32(start + 0x04).ok_or_else(bad)?,
      flags: at.u64(start + 0x08).ok_or_else(bad)?,
      offset: index(at.u64(start + 0x18).ok_or_else(bad)?).ok_or_else(bad)?,
      size: index(at.u64(start + 0x20).ok_or_else(bad)?).ok_or_else(bad)?,
      link: at.u32(start + 0x28).ok_or_else(bad)? as usize,
      entsize: index(at.u64(start + 0x38).ok_or_else(bad)?).ok_or_else(bad)?,
    });
  }

  let mut symbols = Vec::new();
  let mut tables = 0usize;
  for table in headers.iter() {
    if table.kind != SHT_SYMTAB && table.kind != SHT_DYNSYM {
      continue;
    }
    if table.entsize < 24 {
      return Err(format!(
        "an ELF64 symbol table whose entries are {} bytes; `Elf64_Sym` is 24",
        table.entsize
      ));
    }
    if !inside(table.offset, table.size, total) {
      return Err(format!(
        "an ELF64 symbol table of {} bytes at {}, which does not fit in a file \
         of {total} bytes",
        table.size, table.offset
      ));
    }
    if !table.size.is_multiple_of(table.entsize) {
      return Err(format!(
        "an ELF64 symbol table of {} bytes, which is not a whole number of its \
         own {}-byte entries",
        table.size, table.entsize
      ));
    }
    let strings = headers.get(table.link).ok_or_else(|| {
      format!(
        "an ELF64 symbol table naming section {}, which is not there",
        table.link
      )
    })?;
    if strings.kind != SHT_STRTAB {
      return Err(format!(
        "an ELF64 symbol table whose names are said to be in section {}, whose \
         type is {} rather than `SHT_STRTAB` ({SHT_STRTAB}). A section that is \
         not a string table holds no names, and reading one out of it would be \
         reading whatever that section does hold",
        table.link, strings.kind
      ));
    }
    if !inside(strings.offset, strings.size, total) {
      return Err(format!(
        "an ELF64 string table of {} bytes at {}, which does not fit in a file \
         of {total} bytes",
        strings.size, strings.offset
      ));
    }
    tables += 1;
    for nth in 0..table.size / table.entsize {
      let entry = table.offset + nth * table.entsize;
      let name = at.u32(entry).ok_or_else(bad)? as usize;
      if name == 0 {
        continue;
      }
      if name >= strings.size {
        return Err(format!(
          "an ELF64 symbol name at offset {name} of a string table that \
           declares {} bytes. The name is outside the table this file says \
           holds it, and the bytes there belong to something else",
          strings.size
        ));
      }
      let start = strings.offset + name;
      let text = at
        .cstr(start, strings.offset + strings.size)
        .ok_or_else(|| {
          format!(
            "an ELF64 symbol name at offset {name} with no terminator before the \
           end of its {}-byte string table. Reading on would return bytes past \
           the table, which is how a truncated table comes back holding a \
           symbol it does not hold",
            strings.size
          )
        })?;
      let info = at.u8(entry + 4).ok_or_else(bad)?;
      let section = at.u16(entry + 6).ok_or_else(bad)?;
      symbols.push(Symbol {
        // `&&` short-circuits, so the section is resolved only for an entry
        // that CLAIMS to be a function — which is the only entry whose section
        // this is ever asked about, and the only one a `SHN_XINDEX` this
        // cannot follow would make unanswerable.
        name: text,
        defined_function: info & 0x0f == STT_FUNC && defines_code(section, &headers)?,
      });
    }
  }
  if tables == 0 {
    return Err(
      "an ELF64 executable with no symbol table section at all. A `strip`ped \
       binary is the usual reason, and a stripped binary cannot answer which \
       functions it contains"
        .to_string(),
    );
  }
  Ok(symbols)
}

/// Whether a defined symbol's `st_shndx` names a section of THIS file that
/// holds executable code.
///
/// `STT_FUNC` and "not `SHN_UNDEF`" was the whole test, and neither of them is
/// about code. `st_info`'s type is a claim the producer writes; `st_shndx` is
/// where that claim would have to be paid, and it can name something that is
/// not a section at all — `SHN_ABS` for an absolute value, `SHN_COMMON` for an
/// unallocated block — or a section that holds no instructions. A `STT_FUNC`
/// entry so placed carries the shim's exact name over no function body, which
/// is the one thing this reader exists to tell apart from a body that is there.
///
/// `SHN_XINDEX` is REFUSED rather than answered either way. It says the real
/// index is in a `SHT_SYMTAB_SHNDX` table this does not read, so "yes" would be
/// invented and "no" would silently drop every function in a file with more
/// than 65279 sections — an under-count that reads exactly like a shim nobody
/// instantiated. An index past the table is refused for the same reason
/// `sh_link` is: a file contradicting its own header is one this does not
/// understand, not one to read the plausible part of.
fn defines_code(section: u16, headers: &[Section]) -> Result<bool, String> {
  match section {
    SHN_UNDEF => Ok(false),
    SHN_XINDEX => Err(
      "an ELF64 symbol whose `st_shndx` is `SHN_XINDEX`, so its real section is \
       in a `SHT_SYMTAB_SHNDX` table this reader does not follow. Which section \
       a symbol is in decides whether it defines a function here, and that \
       question cannot be answered out of this file alone"
        .to_string(),
    ),
    reserved if reserved >= SHN_LORESERVE => Ok(false),
    nth => {
      let holder = headers.get(usize::from(nth)).ok_or_else(|| {
        format!(
          "an ELF64 symbol in section {nth}, of a file declaring {} section \
           header(s). The section it names is not there, so what it is defined \
           in cannot be read",
          headers.len()
        )
      })?;
      Ok(holder.flags & SHF_EXECINSTR != 0)
    }
  }
}

/// The six `Elf64_Shdr` fields this reads.
struct Section {
  kind: u32,
  /// `sh_flags`, for the one bit [`defines_code`] asks about.
  flags: u64,
  offset: usize,
  size: usize,
  link: usize,
  entsize: usize,
}

/// One `LC_SYMTAB` command's four fields.
struct SymtabCommand {
  symbols: usize,
  count: usize,
  strings: usize,
  strings_size: usize,
}

/// Every symbol in a 64-bit Mach-O file.
///
/// Two passes over the load commands, because a symbol's `n_sect` cannot be
/// told from a data section's until the sections are known and `LC_SYMTAB` is
/// not required to come after the segments that hold them.
fn macho(bytes: &[u8], little: bool) -> Result<Vec<Symbol>, String> {
  let at = At { bytes, little };
  let total = bytes.len();
  let bad = || "a Mach-O header this could not read".to_string();
  let commands = at.u32(16).ok_or_else(bad)? as usize;
  let region = at.u32(20).ok_or_else(bad)? as usize; // sizeofcmds

  // `mach_header_64` is 32 bytes; the load commands follow it and `sizeofcmds`
  // is how many bytes of them the file declares. Every command below is read
  // inside THAT, not inside the file: a command whose `cmdsize` walks past the
  // region is a command this file does not actually declare.
  const HEADER: usize = 32;
  if !inside(HEADER, region, total) {
    return Err(format!(
      "a Mach-O file declaring {region} bytes of load commands after its \
       32-byte header, which does not fit in a file of {total} bytes"
    ));
  }
  let end = HEADER + region;

  // `n_sect` is a 1-based ordinal over every section of every segment, in the
  // order they are declared; `code` records, for each, whether it is
  // instructions.
  let mut code: Vec<bool> = Vec::new();
  let mut symtabs: Vec<SymtabCommand> = Vec::new();
  let mut cursor = HEADER;
  for _ in 0..commands {
    if cursor >= end {
      return Err(format!(
        "a Mach-O file declaring {commands} load command(s) in {region} bytes, \
         which ran out after the ones before offset {cursor}"
      ));
    }
    let kind = at.u32(cursor).ok_or_else(bad)?;
    let size = at.u32(cursor + 4).ok_or_else(bad)? as usize;
    if size < 8 || !size.is_multiple_of(8) {
      return Err(format!(
        "a Mach-O load command of {size} bytes; a 64-bit file's are at least 8 \
         and a multiple of 8"
      ));
    }
    if !inside(cursor, size, end) {
      return Err(format!(
        "a Mach-O load command of {size} bytes at {cursor}, which runs past the \
         {region} bytes of load commands the header declares"
      ));
    }
    match kind {
      LC_SEGMENT_64 => {
        // `segment_command_64` is 72 bytes; `nsects` `section_64`s of 80
        // follow it, and the section's `flags` are 64 bytes into each.
        let sects = at.u32(cursor + 64).ok_or_else(bad)? as usize;
        let span = sects
          .checked_mul(80)
          .ok_or_else(|| "a Mach-O segment with more sections than fit".to_string())?;
        if !inside(72, span, size) {
          return Err(format!(
            "a Mach-O segment declaring {sects} section(s) in a load command of \
             {size} bytes, which cannot hold them"
          ));
        }
        for nth in 0..sects {
          let flags = at.u32(cursor + 72 + nth * 80 + 64).ok_or_else(bad)?;
          code.push(flags & S_ATTR_PURE_INSTRUCTIONS != 0);
        }
      }
      LC_SYMTAB => {
        if size != 24 {
          return Err(format!(
            "a Mach-O `LC_SYMTAB` of {size} bytes; `symtab_command` is 24"
          ));
        }
        symtabs.push(SymtabCommand {
          symbols: at.u32(cursor + 0x08).ok_or_else(bad)? as usize, // symoff
          count: at.u32(cursor + 0x0c).ok_or_else(bad)? as usize,   // nsyms
          strings: at.u32(cursor + 0x10).ok_or_else(bad)? as usize, // stroff
          strings_size: at.u32(cursor + 0x14).ok_or_else(bad)? as usize, // strsize
        });
      }
      _ => {}
    }
    cursor += size;
  }

  let mut symbols = Vec::new();
  for table in &symtabs {
    // `nlist_64` is 16 bytes, its `n_strx` first.
    let span = table
      .count
      .checked_mul(16)
      .ok_or_else(|| "a Mach-O symbol table longer than this host can address".to_string())?;
    if !inside(table.symbols, span, total) {
      return Err(format!(
        "a Mach-O symbol table of {} entries at {}, which does not fit in a \
         file of {total} bytes",
        table.count, table.symbols
      ));
    }
    if !inside(table.strings, table.strings_size, total) {
      return Err(format!(
        "a Mach-O string table of {} bytes at {}, which does not fit in a file \
         of {total} bytes",
        table.strings_size, table.strings
      ));
    }
    for nth in 0..table.count {
      let entry = table.symbols + nth * 16;
      let name = at.u32(entry).ok_or_else(bad)? as usize;
      if name == 0 {
        continue;
      }
      if name >= table.strings_size {
        return Err(format!(
          "a Mach-O symbol name at offset {name} of a string table that \
           declares {} bytes. The name is outside the table this file says \
           holds it, and the bytes there belong to something else",
          table.strings_size
        ));
      }
      let text = at
        .cstr(table.strings + name, table.strings + table.strings_size)
        .ok_or_else(|| {
          format!(
            "a Mach-O symbol name at offset {name} with no terminator before \
             the end of its {}-byte string table. Reading on would return bytes \
             past the table, which is how a truncated table comes back holding \
             a symbol it does not hold",
            table.strings_size
          )
        })?;
      let kind = at.u8(entry + 4).ok_or_else(bad)?;
      let section = usize::from(at.u8(entry + 5).ok_or_else(bad)?);
      // A debugger symbol's `n_type` is not an `N_TYPE` at all, an `N_UNDF`
      // entry defines nothing, and Mach-O has no function type — so a defined
      // symbol is a function exactly when its section holds instructions.
      let defined_function = kind & N_STAB == 0
        && kind & N_TYPE == N_SECT
        && section
          .checked_sub(1)
          .and_then(|nth| code.get(nth))
          .copied()
          .unwrap_or(false);
      symbols.push(Symbol {
        name: text,
        defined_function,
      });
    }
  }
  if symtabs.is_empty() {
    return Err(
      "a Mach-O executable with no LC_SYMTAB load command at all. A `strip`ped \
       binary is the usual reason, and a stripped binary cannot answer which \
       functions it contains"
        .to_string(),
    );
  }
  Ok(symbols)
}

/// Which of the two schemes a mangled symbol is written in.
///
/// Part of a crate's IDENTITY rather than a detail of reading it: the scheme is
/// fixed per compiled crate, so a symbol written the other way round than this
/// binary's own crate writes them came out of some other crate, whatever its
/// path spells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
  /// `_ZN8no_panic6shim_x17hcafe0123456789abE`.
  Legacy,
  /// `_RNvCsg8Ts9hS57d_8no_panic6shim_x`.
  V0,
}

/// A mangled symbol's path, read as far as the crate root it is rooted at and
/// the item written directly under that root.
///
/// Both fields of the crate are kept, not only its name, because a NAME is not
/// a crate. Several crates in one link may be called `no_panic` — a dependency
/// may simply be named that, and this workspace's `no-panic` dependency IS —
/// and what tells them apart is the disambiguator v0 writes beside the name.
/// [`same_crate_as`](Self::same_crate_as) is where that comparison lives, and
/// it is the whole of what binds a symbol to one crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rooted<'a> {
  /// The scheme the symbol is written in.
  pub scheme: Scheme,
  /// The crate root's name.
  pub krate: &'a str,
  /// The crate root's v0 disambiguator, EXACTLY as written (`s<base-62>_`), or
  /// `""` where the encoding leaves it out — which means zero, and is a value
  /// like any other. Always `""` under legacy, which writes none at all.
  pub disambiguator: &'a str,
  /// The item written directly under that crate root, in v0's VALUE namespace
  /// — a `fn` or a `static`, which are the only items that carry a symbol at
  /// all and the only ones this is ever asked about. A `t`ype node written at
  /// the same path is a different item, and is not read as this one.
  ///
  /// Legacy encodes no namespace, so under it this is whatever item the path
  /// names — one more thing that scheme cannot say, and one more reason the
  /// caller prints which scheme it bound to.
  pub item: &'a str,
}

impl Rooted<'_> {
  /// Whether these two symbols come from the SAME crate.
  ///
  /// Name, disambiguator and scheme, all three. Under v0 that is an identity:
  /// two crates sharing a name are precisely two crates whose disambiguators
  /// differ, which is why the field is compared rather than discarded.
  ///
  /// Under LEGACY it is only the name, because legacy carries no crate
  /// disambiguator to compare — its per-symbol `17h…` hash is computed over the
  /// path AND the crate's disambiguator, but it is a hash of the whole symbol,
  /// so no two symbols of one crate share it and it cannot be matched across
  /// them. What that costs is stated rather than papered over: under a legacy
  /// toolchain, a second linked crate named `no_panic` defining a root `fn` of
  /// a shim's name would be credited with that shim. The caller prints which
  /// scheme it bound to for exactly this reason, so a run under the weaker
  /// binding says so on its own line.
  pub fn same_crate_as(&self, other: &Rooted<'_>) -> bool {
    self.scheme == other.scheme
      && self.krate == other.krate
      && self.disambiguator == other.disambiguator
  }
}

/// The crate root and root-level item `symbol`'s mangled path names, or nothing
/// when it names none this can read.
///
/// PARSED, not searched. The scan this replaced looked for `NvC` anywhere in
/// the string and read the bytes after it as a path, which the encoding does not
/// license: `_RNvC3foo26xNvC8no_panic11shim_decode` is the valid symbol for
/// `foo::xNvC8no_panic11shim_decode`, an item of crate `foo` whose NAME happens
/// to contain those three bytes, and a scan reads it as `no_panic::shim_decode`.
/// A component only begins where the grammar says one begins, so this walks the
/// symbol from its first byte and refuses anything it does not recognise.
///
/// What it reads is the outermost path's chain of nested nodes down to its
/// crate root — v0's `N<ns>` nodes write their PARENT before their own name, so
/// a run of them ending in `C<identifier>` is followed by that chain's
/// identifiers from the root outward, and the first of those is the item under
/// the root. `no_panic::shim_x` is `NvC…8no_panic6shim_x`; the closure inside it
/// is `NCNvC…8no_panic6shim_x0`, which is rooted at the same item and exists
/// only because that item's body was generated.
///
/// A path rooted at anything else — an impl (`M`), a trait impl (`X`/`Y`), a
/// generic instance (`I`), a backref (`B`) — is not read. Those forms can
/// mention an item without being it, and the shim they would speak for always
/// has a symbol of its own: `#[inline(never)]` is what guarantees it, and the
/// caller requires that attribute for this reason. Refusing them costs a
/// diagnostic at worst and removes a whole family of bytes this would otherwise
/// have to interpret.
pub fn rooted(symbol: &str) -> Option<Rooted<'_>> {
  // Mach-O writes an extra leading `_` on every symbol and ELF does not. Both
  // spellings are tried rather than decided from the format: the caller has a
  // name, not a file, and that byte carries no other meaning.
  [symbol, symbol.strip_prefix('_').unwrap_or(symbol)]
    .into_iter()
    .find_map(|text| {
      text
        .strip_prefix("_ZN")
        .and_then(legacy)
        .or_else(|| text.strip_prefix("_R").and_then(v0))
    })
}

/// A legacy-mangled symbol: its path components from the first byte, closed by
/// `E`.
///
/// The terminating `17h<16 hex>` component is REQUIRED, and it is what tells a
/// Rust symbol from a C++ one. `_ZN` is C++'s prefix too, and a C++ mangler will
/// spell `no_panic::shim_x` as `_ZN8no_panic6shim_xE` — the same bytes, from a
/// language whose namespaces this check knows nothing about. rustc closes every
/// legacy symbol with that hash; C++ never writes one.
fn legacy(path: &str) -> Option<Rooted<'_>> {
  let mut components = Vec::new();
  let mut rest = path;
  while !rest.starts_with('E') {
    let (name, tail) = legacy_component(rest)?;
    components.push(name);
    rest = tail;
  }
  let hash = components.pop()?;
  if hash.len() != 17
    || !hash.starts_with('h')
    || !hash.get(1..)?.bytes().all(|byte| byte.is_ascii_hexdigit())
  {
    return None;
  }
  Some(Rooted {
    scheme: Scheme::Legacy,
    krate: components.first().copied()?,
    disambiguator: "",
    item: components.get(1).copied()?,
  })
}

/// One legacy `<length><bytes>` component, and the text after it.
fn legacy_component(text: &str) -> Option<(&str, &str)> {
  let end = text.bytes().position(|byte| !byte.is_ascii_digit())?;
  let digits = text.get(..end)?;
  if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
    return None;
  }
  let len: usize = digits.parse().ok()?;
  let stop = end.checked_add(len)?;
  Some((text.get(end..stop)?, text.get(stop..)?))
}

/// A v0-mangled symbol, walked from its first byte.
fn v0(path: &str) -> Option<Rooted<'_>> {
  // `_R` may be followed by the ENCODING VERSION, and version zero — the only
  // one this reads — writes none. A digit here is a grammar this does not know,
  // and reading it as version zero's would be reading someone else's bytes.
  if path.starts_with(|ch: char| ch.is_ascii_digit()) {
    return None;
  }
  // The chain of nested nodes down to the crate root. `N <ns> <path>
  // <identifier>` writes the parent path BEFORE the name, so the run of `N`s at
  // the front is the depth, and what follows the root are that many identifiers
  // from the root outward.
  let mut rest = path;
  let mut namespace = None;
  loop {
    match rest.as_bytes().first()? {
      b'N' => {
        let ns = *rest.as_bytes().get(1)?;
        if !ns.is_ascii_alphabetic() {
          return None;
        }
        rest = rest.get(2..)?;
        namespace = Some(ns);
      }
      b'C' => {
        rest = rest.get(1..)?;
        break;
      }
      _ => return None,
    }
  }
  // The LAST namespace read is the innermost node's — the one whose parent is
  // the crate root, which is the item this answers about. `v` is the value
  // namespace: a `fn` or a `static`. A crate root on its own (no node at all)
  // names no item under it, and a `t`ype node of the same name is a different
  // item that would otherwise have read as this one.
  if namespace != Some(b'v') {
    return None;
  }
  let (disambiguator, krate, rest) = v0_identifier(rest)?;
  let (_, item, _) = v0_identifier(rest)?;
  Some(Rooted {
    scheme: Scheme::V0,
    krate,
    disambiguator,
    item,
  })
}

/// One v0 `<identifier>` — its disambiguator as written, its name, and the text
/// after it.
///
/// A Punycode identifier (`u`) is refused rather than compared undecoded: every
/// name this is ever asked about is ASCII, and an encoded one is a different
/// string than the name it stands for.
fn v0_identifier(text: &str) -> Option<(&str, &str, &str)> {
  let (disambiguator, rest) = match text.strip_prefix('s') {
    None => ("", text),
    Some(after) => {
      let end = after.find('_')?;
      if !after
        .get(..end)?
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric())
      {
        return None;
      }
      (text.get(..end + 2)?, after.get(end + 1..)?)
    }
  };
  if rest
    .strip_prefix('u')
    .is_some_and(|after| after.starts_with(|ch: char| ch.is_ascii_digit()))
  {
    return None;
  }
  let end = rest
    .bytes()
    .position(|byte| !byte.is_ascii_digit())
    .unwrap_or(rest.len());
  let digits = rest.get(..end)?;
  if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
    return None;
  }
  let len: usize = digits.parse().ok()?;
  // v0 separates the length from an identifier that would otherwise start with
  // a digit or `_`; the encoder writes that `_` exactly when it is needed.
  let start = end + usize::from(rest.get(end..).is_some_and(|tail| tail.starts_with('_')));
  let stop = start.checked_add(len)?;
  Some((disambiguator, rest.get(start..stop)?, rest.get(stop..)?))
}

/// Whether `symbol` contains `ident` as a Rust-mangled path COMPONENT,
/// wherever in the path it sits.
///
/// DIAGNOSTIC ONLY — [`rooted`] is the gate, and this must never become it.
/// A component test says the name is spelled somewhere in this symbol's path;
/// it says nothing about whose path, which is the whole distinction the gate
/// exists to draw. What it is for is the failure message: when a shim is not
/// instantiated but something in the binary spells its name, saying so turns
/// "not instantiated" into "instantiated by someone else, which is not this".
///
/// Both mangling schemes length-prefix each component of a path — legacy's
/// `_ZN8no_panic18shim_varint_decode17h…E`, v0's
/// `_RNvCs…_8no_panic18shim_varint_decode` — so `18shim_varint_decode` is the
/// needle, and the digits before it must not be part of a longer number.
pub fn names_component(symbol: &str, ident: &str) -> bool {
  let needle = format!("{}{ident}", ident.len());
  let mut from = 0usize;
  while let Some(found) = symbol.get(from..).and_then(|rest| rest.find(&needle)) {
    let at = from + found;
    let run_on = at > 0
      && symbol
        .as_bytes()
        .get(at - 1)
        .is_some_and(u8::is_ascii_digit);
    if !run_on {
      return true;
    }
    from = at + 1;
  }
  false
}

#[cfg(test)]
mod tests {
  use super::*;
  use Entry::{Absolute, Code, Data, NotCode, Undefined};

  /// One symbol for a hand-built fixture: its name, and what the table should
  /// say it IS. These are the shapes a shim's name can wear in a linked
  /// executable, and only the first of them is the shim.
  #[derive(Clone, Copy)]
  enum Entry<'a> {
    /// A defined function, in the section that holds instructions.
    Code(&'a str),
    /// A defined non-function — a `static`, which names no code at all.
    Data(&'a str),
    /// A name this file REFERENCES and does not define.
    Undefined(&'a str),
    /// A defined symbol that CLAIMS to be a function, in a section that holds
    /// no instructions. ELF's `st_info` says `STT_FUNC` and its `st_shndx`
    /// says `.rodata`; Mach-O has no function type at all, so there this is
    /// the same entry as [`Data`] — which is why that reader was already
    /// asking the only question available to it.
    NotCode(&'a str),
    /// A defined `STT_FUNC` whose section index is `SHN_ABS` — not a section
    /// at all, so nothing in the file holds its body.
    Absolute(&'a str),
  }

  impl<'a> Entry<'a> {
    fn name(self) -> &'a str {
      match self {
        Code(name) | Data(name) | Undefined(name) | NotCode(name) | Absolute(name) => name,
      }
    }
  }

  /// `SHT_PROGBITS`, the type of a section whose bytes are in the file.
  const SHT_PROGBITS: u32 = 1;
  /// `SHF_ALLOC`, which both of the fixture's loadable sections carry.
  const SHF_ALLOC: u64 = 0x2;
  /// `SHN_ABS`. A symbol's value is absolute — it is in no section.
  const SHN_ABS: u16 = 0xfff1;
  /// The sections [`elf64`] gives its file, in the order an object writes
  /// them: the null section, the code, the constants, and the two tables.
  ///
  /// A real object's shape rather than the shortest one that parses. The
  /// fixture this replaced had three sections and pointed every `Code` entry
  /// at section 1 — which was its own `SHT_SYMTAB` — and asserted that those
  /// entries classified as defined functions. It therefore MODELLED a symbol
  /// table claiming its functions live inside the symbol table, and the
  /// classification it graded had no way to notice: the reader asked only
  /// whether the index was non-zero. A fixture that cannot tell a right
  /// answer from a wrong one grades neither.
  const TEXT: usize = 1;
  const RODATA: usize = 2;
  const SYMTAB: usize = 3;
  const STRTAB: usize = 4;
  const SECTIONS: usize = 5;
  /// How many bytes those two loadable sections hold. Nothing reads them; what
  /// matters is that each is an extent of its own, so a symbol pointing into
  /// one is not pointing into a table.
  const TEXT_SIZE: usize = 16;
  const RODATA_SIZE: usize = 8;

  /// Where [`elf64`] puts each piece of a file holding `entries` symbols.
  ///
  /// Spelled once, because every refusal below is tested by breaking ONE field
  /// of a file that otherwise works, and a test that recomputed the layout by
  /// hand would break its own fixture instead of the field it names.
  struct ElfAt {
    headers: usize,
    text: usize,
    rodata: usize,
    symtab: usize,
    strtab: usize,
  }

  impl ElfAt {
    /// Where section header `nth` starts.
    fn header(&self, nth: usize) -> usize {
      self.headers + nth * 64
    }
  }

  fn elf_at(entries: usize) -> ElfAt {
    let headers = 64usize;
    let text = headers + SECTIONS * 64;
    let rodata = text + TEXT_SIZE;
    let symtab = rodata + RODATA_SIZE;
    ElfAt {
      headers,
      text,
      rodata,
      symtab,
      strtab: symtab + (entries + 1) * 24,
    }
  }

  /// The same for [`macho64`].
  struct MachoAt {
    segment: usize,
    symtab_command: usize,
    symtab: usize,
    strings: usize,
  }

  fn macho_at(entries: usize) -> MachoAt {
    let segment = 32usize;
    let symtab_command = segment + SEGMENT_SIZE;
    let symtab = symtab_command + 24;
    MachoAt {
      segment,
      symtab_command,
      symtab,
      strings: symtab + (entries + 1) * 16,
    }
  }

  /// `segment_command_64` plus the two `section_64`s [`macho64`] gives it.
  const SEGMENT_SIZE: usize = 72 + 2 * 80;
  /// `N_ABS`: the symbol's value is absolute, and `n_sect` is `NO_SECT`.
  const N_ABS: u8 = 0x2;

  /// A minimal ELF64 file whose symbol table holds `entries`.
  ///
  /// Hand-built rather than fixtured: a committed `.o` is a binary this
  /// workspace would carry and nobody would read, and building one here is what
  /// lets the refusals below be tested by breaking ONE field of a file that
  /// otherwise works.
  fn elf64(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut strings = vec![0u8];
    let mut offsets = Vec::new();
    for entry in entries {
      offsets.push(strings.len());
      strings.extend_from_slice(entry.name().as_bytes());
      strings.push(0);
    }
    // Five section headers of 64 bytes at 64, then `.text`, `.rodata`, the
    // symbol table and the string table.
    let layout = elf_at(entries.len());
    let symbols = (entries.len() + 1) * 24;

    let mut out = vec![0u8; layout.strtab + strings.len()];
    out[..4].copy_from_slice(&ELF);
    out[4] = 2; // ELFCLASS64
    out[5] = 1; // ELFDATA2LSB
    out[6] = 1; // EV_CURRENT
    out[0x28..0x30].copy_from_slice(&(layout.headers as u64).to_le_bytes()); // e_shoff
    out[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    out[0x3c..0x3e].copy_from_slice(&(SECTIONS as u16).to_le_bytes()); // e_shnum
    // Bytes in the section that holds bytes, so `.text` is an extent of its own
    // rather than a header over nothing.
    out[layout.text..layout.text + TEXT_SIZE].fill(0xc3); // `ret`

    let mut header =
      |nth: usize, kind: u32, flags: u64, offset: usize, size: usize, link: u32, ent: usize| {
        let at = layout.headers + nth * 64;
        out[at + 0x04..at + 0x08].copy_from_slice(&kind.to_le_bytes());
        out[at + 0x08..at + 0x10].copy_from_slice(&flags.to_le_bytes());
        out[at + 0x18..at + 0x20].copy_from_slice(&(offset as u64).to_le_bytes());
        out[at + 0x20..at + 0x28].copy_from_slice(&(size as u64).to_le_bytes());
        out[at + 0x28..at + 0x2c].copy_from_slice(&link.to_le_bytes());
        out[at + 0x38..at + 0x40].copy_from_slice(&(ent as u64).to_le_bytes());
      };
    header(
      TEXT,
      SHT_PROGBITS,
      SHF_ALLOC | SHF_EXECINSTR,
      layout.text,
      TEXT_SIZE,
      0,
      0,
    );
    header(
      RODATA,
      SHT_PROGBITS,
      SHF_ALLOC,
      layout.rodata,
      RODATA_SIZE,
      0,
      0,
    );
    header(
      SYMTAB,
      SHT_SYMTAB,
      0,
      layout.symtab,
      symbols,
      STRTAB as u32,
      24,
    );
    header(STRTAB, SHT_STRTAB, 0, layout.strtab, strings.len(), 0, 0);

    for (nth, (entry, offset)) in entries.iter().zip(&offsets).enumerate() {
      let at = layout.symtab + (nth + 1) * 24;
      out[at..at + 4].copy_from_slice(&(*offset as u32).to_le_bytes());
      // `st_info`'s low nibble is the type; `st_shndx` says where the body it
      // claims to have would be.
      let (info, section) = match entry {
        Code(_) => (STT_FUNC, TEXT as u16),
        Data(_) => (1u8, RODATA as u16), // STT_OBJECT
        Undefined(_) => (STT_FUNC, SHN_UNDEF),
        NotCode(_) => (STT_FUNC, RODATA as u16),
        Absolute(_) => (STT_FUNC, SHN_ABS),
      };
      out[at + 4] = info;
      out[at + 6..at + 8].copy_from_slice(&section.to_le_bytes());
    }
    out[layout.strtab..layout.strtab + strings.len()].copy_from_slice(&strings);
    out
  }

  /// The same for a 64-bit Mach-O file.
  ///
  /// It carries one `LC_SEGMENT_64` of two sections — `__text`, which holds
  /// instructions, and `__const`, which does not — because Mach-O's symbol
  /// table has no function type and a defined symbol is told from a data one
  /// by the section it points into.
  fn macho64(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut strings = vec![0u8];
    let mut offsets = Vec::new();
    for entry in entries {
      offsets.push(strings.len());
      strings.extend_from_slice(entry.name().as_bytes());
      strings.push(0);
    }
    let layout = macho_at(entries.len());

    let mut out = vec![0u8; layout.strings + strings.len()];
    out[..4].copy_from_slice(&MACHO_64_LE);
    out[16..20].copy_from_slice(&2u32.to_le_bytes()); // ncmds
    out[20..24].copy_from_slice(&((SEGMENT_SIZE + 24) as u32).to_le_bytes()); // sizeofcmds

    let segment = layout.segment;
    out[segment..segment + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out[segment + 4..segment + 8].copy_from_slice(&(SEGMENT_SIZE as u32).to_le_bytes());
    out[segment + 8..segment + 14].copy_from_slice(b"__TEXT");
    out[segment + 64..segment + 68].copy_from_slice(&2u32.to_le_bytes()); // nsects
    let text = segment + 72;
    out[text..text + 6].copy_from_slice(b"__text");
    out[text + 64..text + 68].copy_from_slice(&S_ATTR_PURE_INSTRUCTIONS.to_le_bytes());
    let constants = text + 80;
    out[constants..constants + 7].copy_from_slice(b"__const");
    // The second section's flags stay zero: it is not instructions.

    let command = layout.symtab_command;
    out[command..command + 4].copy_from_slice(&LC_SYMTAB.to_le_bytes());
    out[command + 4..command + 8].copy_from_slice(&24u32.to_le_bytes()); // cmdsize
    out[command + 8..command + 12].copy_from_slice(&(layout.symtab as u32).to_le_bytes()); // symoff
    out[command + 12..command + 16].copy_from_slice(&(entries.len() as u32 + 1).to_le_bytes()); // nsyms
    out[command + 16..command + 20].copy_from_slice(&(layout.strings as u32).to_le_bytes()); // stroff
    out[command + 20..command + 24].copy_from_slice(&(strings.len() as u32).to_le_bytes()); // strsize

    for (nth, (entry, offset)) in entries.iter().zip(&offsets).enumerate() {
      let at = layout.symtab + (nth + 1) * 16;
      out[at..at + 4].copy_from_slice(&(*offset as u32).to_le_bytes());
      let (kind, section) = match entry {
        Code(_) => (N_SECT, 1u8),
        // Mach-O has no function type, so a symbol that CLAIMS to be a
        // function in a section holding no instructions is written exactly
        // like a data symbol — the two are one entry here.
        Data(_) | NotCode(_) => (N_SECT, 2u8),
        Undefined(_) => (0x01u8, 0u8), // N_UNDF | N_EXT
        Absolute(_) => (N_ABS, 0u8),
      };
      out[at + 4] = kind;
      out[at + 5] = section;
    }
    out[layout.strings..layout.strings + strings.len()].copy_from_slice(&strings);
    out
  }

  /// Writes `bytes` under the test's own temporary directory and reads it back
  /// through [`read`], so the dispatch on magic is exercised and not bypassed.
  fn through_read(bytes: &[u8], name: &str) -> Result<Vec<Symbol>, String> {
    let path = std::env::temp_dir().join(format!("xtask-symbols-{name}-{}", std::process::id()));
    std::fs::write(&path, bytes).expect("the temporary directory is writable");
    let out = read(&path);
    let _ = std::fs::remove_file(&path);
    out
  }

  /// Each symbol's name and whether the reader called it a defined function.
  fn classified(found: &[Symbol]) -> Vec<(&str, bool)> {
    found
      .iter()
      .map(|symbol| (symbol.name.as_str(), symbol.defined_function))
      .collect()
  }

  // The fixture's own subject: `Code` has to point at a section that holds
  // instructions, and that section must not be one of the tables. The fixture
  // this replaced pointed every `Code` entry at section 1 — its own
  // `SHT_SYMTAB` — and expected `true`, so the classification it graded could
  // not have failed however wrong it was.
  #[test]
  fn the_fixture_puts_its_functions_in_a_section_that_holds_code() {
    let layout = elf_at(1);
    let elf = elf64(&[Code("main")]);
    let entry = layout.symtab + 24;
    let section = u16::from_le_bytes(elf[entry + 6..entry + 8].try_into().expect("two bytes"));
    assert_eq!(usize::from(section), TEXT);
    let at = layout.header(usize::from(section));
    let kind = u32::from_le_bytes(elf[at + 0x04..at + 0x08].try_into().expect("four bytes"));
    let flags = u64::from_le_bytes(elf[at + 0x08..at + 0x10].try_into().expect("eight bytes"));
    assert_eq!(kind, SHT_PROGBITS, "a `Code` entry is not in a table");
    assert!(flags & SHF_EXECINSTR != 0, "and its section holds code");
    assert_ne!(section, SYMTAB as u16);
  }

  #[test]
  fn an_elf64_symbol_table_is_read() {
    let found = through_read(
      &elf64(&[
        Code("_ZN8no_panic18shim_varint_decode17hcafe0123456789abE"),
        Data("_ZN8no_panic5TABLE17hcafe0123456789abE"),
        Undefined("_ZN8elsewhere18shim_varint_decode17hcafe0123456789abE"),
        NotCode("_ZN8no_panic11shim_decode17hcafe0123456789abE"),
        Absolute("_ZN8no_panic10shim_widen17hcafe0123456789abE"),
        Code("main"),
      ]),
      "elf",
    )
    .expect("a well-formed ELF64 file");
    assert_eq!(
      classified(&found),
      [
        ("_ZN8no_panic18shim_varint_decode17hcafe0123456789abE", true),
        ("_ZN8no_panic5TABLE17hcafe0123456789abE", false),
        (
          "_ZN8elsewhere18shim_varint_decode17hcafe0123456789abE",
          false
        ),
        ("_ZN8no_panic11shim_decode17hcafe0123456789abE", false),
        ("_ZN8no_panic10shim_widen17hcafe0123456789abE", false),
        ("main", true),
      ]
    );
  }

  #[test]
  fn a_macho64_symbol_table_is_read() {
    let found = through_read(
      &macho64(&[
        Code("__RNvCsg8Ts9hS57d_8no_panic18shim_varint_decode"),
        Data("__RNvCsg8Ts9hS57d_8no_panic5TABLE"),
        Undefined("__RNvCsg8Ts9hS57d_9elsewhere18shim_varint_decode"),
        NotCode("__RNvCsg8Ts9hS57d_8no_panic11shim_decode"),
        Absolute("__RNvCsg8Ts9hS57d_8no_panic10shim_widen"),
        Code("_main"),
      ]),
      "macho",
    )
    .expect("a well-formed Mach-O 64 file");
    assert_eq!(
      classified(&found),
      [
        ("__RNvCsg8Ts9hS57d_8no_panic18shim_varint_decode", true),
        ("__RNvCsg8Ts9hS57d_8no_panic5TABLE", false),
        ("__RNvCsg8Ts9hS57d_9elsewhere18shim_varint_decode", false),
        ("__RNvCsg8Ts9hS57d_8no_panic11shim_decode", false),
        ("__RNvCsg8Ts9hS57d_8no_panic10shim_widen", false),
        ("_main", true),
      ]
    );
  }

  // `STT_FUNC` is a CLAIM about a symbol, and `st_shndx` is where that claim
  // would have to be paid. Each of these wears a shim's exact name, defines
  // something, and has no function body in the executable behind it — which
  // is the one distinction this classification exists to draw. The fixture
  // that graded this before pointed its `Code` entries at the symbol table
  // itself and expected `true`, so it could not have told these apart.
  #[test]
  fn a_defined_symbol_with_no_executable_section_is_not_a_function() {
    const SHIM: &str = "_RNvCs7_8no_panic6shim_x";
    for entry in [NotCode(SHIM), Absolute(SHIM), Undefined(SHIM), Data(SHIM)] {
      let found = through_read(&elf64(&[entry]), "elf-no-code").expect("a well-formed ELF64 file");
      assert_eq!(classified(&found), [(SHIM, false)]);
    }
    const MACHO_SHIM: &str = "__RNvCs7_8no_panic6shim_x";
    for entry in [
      NotCode(MACHO_SHIM),
      Absolute(MACHO_SHIM),
      Undefined(MACHO_SHIM),
      Data(MACHO_SHIM),
    ] {
      let found =
        through_read(&macho64(&[entry]), "macho-no-code").expect("a well-formed Mach-O 64 file");
      assert_eq!(classified(&found), [(MACHO_SHIM, false)]);
    }
  }

  // The two section indexes that are not answers. `SHN_XINDEX` says the real
  // one is in a table this does not read, and an index past the table is a
  // file contradicting its own header — reading either as "not a function"
  // would drop a real body silently, which reads exactly like a shim nobody
  // instantiated.
  #[test]
  fn a_section_index_this_cannot_resolve_is_refused() {
    let layout = elf_at(1);
    for (section, expected) in [
      (0xffffu16, "`SHN_XINDEX`"),
      (9u16, "an ELF64 symbol in section 9"),
    ] {
      let mut elf = elf64(&[Code("_RNvCs7_8no_panic6shim_x")]);
      let entry = layout.symtab + 24;
      elf[entry + 6..entry + 8].copy_from_slice(&section.to_le_bytes());
      let err = through_read(&elf, "elf-shndx").expect_err("that section is not readable");
      assert!(err.contains(expected), "{expected}: {err}");
    }
  }

  // Every one of these would otherwise answer "no symbols", which the caller
  // reads as "no shim was instantiated" — a red build, but for the wrong
  // reason, and one nobody could act on. Each has to name what it saw.
  #[test]
  fn what_it_cannot_read_is_refused_by_name() {
    for (bytes, expected) in [
      (vec![], "shorter than a file header"),
      (b"\x7fELF\x01\x01\x01\0".to_vec(), "32-bit ELF"),
      (MACHO_FAT_BE.to_vec(), "universal"),
      (MACHO_32_LE.to_vec(), "32-bit Mach-O"),
      (b"MZ\x90\0".to_vec(), "an object format this does not read"),
    ] {
      let err = through_read(&bytes, "refused").expect_err("this is not readable");
      assert!(err.contains(expected), "{expected}: {err}");
    }
  }

  // A stripped binary has no table to read, and "no table" must not arrive as
  // "no shims" — that is the whole distinction this module is written for.
  #[test]
  fn a_file_with_no_symbol_table_is_refused_rather_than_read_as_empty() {
    let layout = elf_at(1);
    let mut elf = elf64(&[Code("main")]);
    for nth in [SYMTAB, STRTAB] {
      let at = layout.header(nth);
      elf[at + 0x04..at + 0x08].copy_from_slice(&0u32.to_le_bytes());
    }
    let err = through_read(&elf, "stripped-elf").expect_err("there is no symbol table");
    assert!(err.contains("no symbol table section"), "{err}");

    let mut macho = macho64(&[Code("_main")]);
    let command = macho_at(1).symtab_command;
    macho[command..command + 4].copy_from_slice(&0x25u32.to_le_bytes()); // LC_SEGMENT-ish
    let err = through_read(&macho, "stripped-macho").expect_err("there is no symbol table");
    assert!(err.contains("no LC_SYMTAB"), "{err}");
  }

  // A table this read PAST would answer with bytes that are not in it, and the
  // bytes after a short table belong to something else — they can spell
  // anything, a shim's own name included. Both formats, both routes there.
  #[test]
  fn a_table_outside_the_file_is_refused() {
    let layout = elf_at(1);
    let mut elf = elf64(&[Code("main")]);
    let header = layout.header(STRTAB);
    elf[header + 0x18..header + 0x20].copy_from_slice(&u64::from(u32::MAX).to_le_bytes());
    let err = through_read(&elf, "elf-strtab-out").expect_err("the string table is not there");
    assert!(err.contains("string table of"), "{err}");
    assert!(err.contains("does not fit in a file"), "{err}");

    let mut elf = elf64(&[Code("main")]);
    let header = layout.header(SYMTAB);
    elf[header + 0x20..header + 0x28].copy_from_slice(&u64::from(u32::MAX).to_le_bytes());
    let err = through_read(&elf, "elf-symtab-out").expect_err("the symbol table is not there");
    assert!(err.contains("symbol table of"), "{err}");
    assert!(err.contains("does not fit in a file"), "{err}");

    let command = macho_at(1).symtab_command;
    let mut macho = macho64(&[Code("_main")]);
    macho[command + 16..command + 20].copy_from_slice(&u32::MAX.to_le_bytes()); // stroff
    let err = through_read(&macho, "macho-strtab-out").expect_err("the string table is not there");
    assert!(err.contains("Mach-O string table of"), "{err}");

    let mut macho = macho64(&[Code("_main")]);
    macho[command + 12..command + 16].copy_from_slice(&u32::MAX.to_le_bytes()); // nsyms
    let err = through_read(&macho, "macho-symtab-out").expect_err("the symbol table is not there");
    assert!(err.contains("Mach-O symbol table of"), "{err}");
  }

  // The truncated table itself: the terminator is still IN THE FILE and
  // outside the size the file declares for the table. A reader that scans to
  // end-of-file finds it and answers with a name this binary does not hold —
  // here, a shim's.
  #[test]
  fn a_name_with_no_terminator_inside_the_declared_table_is_refused() {
    const SHIM: &str = "_RNvCs7_8no_panic6shim_x";

    let layout = elf_at(1);
    let mut elf = elf64(&[Code(SHIM)]);
    let declared = elf.len() - layout.strtab;
    let header = layout.header(STRTAB);
    elf[header + 0x20..header + 0x28].copy_from_slice(&((declared - 1) as u64).to_le_bytes());
    let err =
      through_read(&elf, "elf-unterminated").expect_err("the name does not end in the table");
    assert!(err.contains("no terminator before the end of its"), "{err}");

    let layout = macho_at(1);
    let mut macho = macho64(&[Code(SHIM)]);
    let declared = macho.len() - layout.strings;
    let command = layout.symtab_command;
    macho[command + 20..command + 24].copy_from_slice(&((declared - 1) as u32).to_le_bytes());
    let err =
      through_read(&macho, "macho-unterminated").expect_err("the name does not end in the table");
    assert!(err.contains("no terminator before the end of its"), "{err}");
  }

  // The other route to the same bytes: a name offset one past the table, with
  // a shim's name written there. An unbounded read answers with it; this must
  // not.
  #[test]
  fn a_name_offset_outside_the_declared_table_is_refused() {
    const PAST: &[u8] = b"_RNvCs7_8no_panic6shim_x\0";

    let layout = elf_at(1);
    let mut elf = elf64(&[Code("main")]);
    let declared = elf.len() - layout.strtab;
    elf.extend_from_slice(PAST);
    let entry = layout.symtab + 24;
    elf[entry..entry + 4].copy_from_slice(&(declared as u32).to_le_bytes());
    let err = through_read(&elf, "elf-name-out").expect_err("that name is not in the table");
    assert!(
      err.contains("outside the table this file says holds it"),
      "{err}"
    );

    let layout = macho_at(1);
    let mut macho = macho64(&[Code("_main")]);
    let declared = macho.len() - layout.strings;
    macho.extend_from_slice(PAST);
    let entry = layout.symtab + 16;
    macho[entry..entry + 4].copy_from_slice(&(declared as u32).to_le_bytes());
    let err = through_read(&macho, "macho-name-out").expect_err("that name is not in the table");
    assert!(
      err.contains("outside the table this file says holds it"),
      "{err}"
    );
  }

  // `sh_link` is an index, and an index is not a string table until its type
  // says so.
  #[test]
  fn a_symbol_table_whose_names_are_not_in_a_string_table_is_refused() {
    let layout = elf_at(1);
    let header = layout.header(SYMTAB);

    let mut elf = elf64(&[Code("main")]);
    elf[header + 0x28..header + 0x2c].copy_from_slice(&0u32.to_le_bytes()); // the null section
    let err = through_read(&elf, "elf-link-kind").expect_err("section zero holds no names");
    assert!(err.contains("rather than `SHT_STRTAB`"), "{err}");

    let mut elf = elf64(&[Code("main")]);
    elf[header + 0x28..header + 0x2c].copy_from_slice(&9u32.to_le_bytes());
    let err = through_read(&elf, "elf-link-missing").expect_err("there is no section nine");
    assert!(err.contains("which is not there"), "{err}");
  }

  // Every other extent a file declares about itself, in both formats. A file
  // that contradicts its own arithmetic is one this does not understand, not
  // one it reads the readable part of.
  #[test]
  fn a_declared_extent_this_cannot_honour_is_refused() {
    let layout = elf_at(1);

    let mut elf = elf64(&[Code("main")]);
    let header = layout.header(SYMTAB);
    elf[header + 0x20..header + 0x28].copy_from_slice(&35u64.to_le_bytes());
    let err = through_read(&elf, "elf-part-entry").expect_err("35 is not a multiple of 24");
    assert!(err.contains("not a whole number of its own"), "{err}");

    let mut elf = elf64(&[Code("main")]);
    elf[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
    let err = through_read(&elf, "elf-no-sections").expect_err("there are no section headers");
    assert!(err.contains("`e_shoff` is zero"), "{err}");

    let mut elf = elf64(&[Code("main")]);
    elf[0x3c..0x3e].copy_from_slice(&64u16.to_le_bytes()); // e_shnum
    let err = through_read(&elf, "elf-many-sections").expect_err("there are not 64 sections");
    // Both halves: five messages end "does not fit in a file", and only the
    // first says WHICH extent this one was.
    assert!(err.contains("declaring 64 section header(s)"), "{err}");
    assert!(err.contains("does not fit in a file"), "{err}");

    let layout = macho_at(1);

    let mut macho = macho64(&[Code("_main")]);
    macho[layout.segment + 4..layout.segment + 8].copy_from_slice(&264u32.to_le_bytes());
    let err = through_read(&macho, "macho-long-cmd").expect_err("that command does not fit");
    assert!(err.contains("runs past the"), "{err}");

    let mut macho = macho64(&[Code("_main")]);
    macho[layout.segment + 4..layout.segment + 8].copy_from_slice(&7u32.to_le_bytes());
    let err = through_read(&macho, "macho-odd-cmd").expect_err("7 is not a load command");
    assert!(err.contains("a multiple of 8"), "{err}");

    let mut macho = macho64(&[Code("_main")]);
    macho[layout.segment + 64..layout.segment + 68].copy_from_slice(&100u32.to_le_bytes());
    let err = through_read(&macho, "macho-many-sects").expect_err("100 sections do not fit");
    assert!(err.contains("which cannot hold them"), "{err}");

    let mut macho = macho64(&[Code("_main")]);
    let command = layout.symtab_command;
    macho[command + 4..command + 8].copy_from_slice(&16u32.to_le_bytes());
    let err = through_read(&macho, "macho-short-symtab").expect_err("`symtab_command` is 24");
    assert!(err.contains("`LC_SYMTAB` of 16 bytes"), "{err}");

    let mut macho = macho64(&[Code("_main")]);
    macho[20..24].copy_from_slice(&u32::MAX.to_le_bytes()); // sizeofcmds
    let err = through_read(&macho, "macho-big-region").expect_err("the file is not that long");
    assert!(err.contains("bytes of load commands after its"), "{err}");

    let mut macho = macho64(&[Code("_main")]);
    macho[16..20].copy_from_slice(&5u32.to_le_bytes()); // ncmds
    let err = through_read(&macho, "macho-many-cmds").expect_err("there are two commands");
    assert!(
      err.contains("ran out after the ones before offset"),
      "{err}"
    );
  }

  // ── whose symbol it is ────────────────────────────────────────────────────

  /// The whole of what [`rooted`] read, so a test names all of it rather than
  /// asking a yes/no question whose answer it cannot see the parts of.
  fn parsed(symbol: &str) -> Option<(Scheme, &str, &str, &str)> {
    rooted(symbol).map(|path| (path.scheme, path.krate, path.disambiguator, path.item))
  }

  // The shim's own symbol and the items nested inside it, in both mangling
  // schemes and in both the ELF and the Mach-O spelling of each.
  #[test]
  fn the_crate_root_and_item_a_symbol_names_are_read_from_its_own_bytes() {
    let legacy = (Scheme::Legacy, "no_panic", "", "shim_x");
    let v0 = (Scheme::V0, "no_panic", "sg8Ts9hS57d_", "shim_x");
    for (symbol, expected) in [
      ("_ZN8no_panic6shim_x17hcafe0123456789abE", legacy),
      ("__ZN8no_panic6shim_x17hcafe0123456789abE", legacy),
      (
        "_ZN8no_panic6shim_x28_$u7b$$u7b$closure$u7d$$u7d$17hcafe0123456789abE",
        legacy,
      ),
      ("_RNvCsg8Ts9hS57d_8no_panic6shim_x", v0),
      ("__RNvCsg8Ts9hS57d_8no_panic6shim_x", v0),
      // A crate root may carry no disambiguator at all, which encodes zero —
      // and zero is a value like any other, so it is KEPT rather than dropped.
      (
        "_RNvC8no_panic6shim_x",
        (Scheme::V0, "no_panic", "", "shim_x"),
      ),
      // A closure inside the shim, which exists only because the shim's body
      // was generated: a nested node whose parent is the shim itself.
      ("_RNCNvCsg8Ts9hS57d_8no_panic6shim_x0", v0),
    ] {
      assert_eq!(parsed(symbol), Some(expected), "{symbol}");
    }
  }

  // The finding this replaced a name test for: an executable holds every
  // dependency's symbols, so the shim's SPELLING is available to anything in
  // the link. None of these is `no_panic::shim_x`, and no forgery is needed for
  // any of them — the first two are an ordinary dependency collision.
  #[test]
  fn a_symbol_of_that_name_from_anywhere_else_is_not_that_item() {
    for symbol in [
      // Another crate's item of exactly this name.
      "_RNvCsg8Ts9hS57d_9elsewhere6shim_x",
      "_ZN9elsewhere6shim_x17hcafe0123456789abE",
      // The test crate itself, one module down.
      "_RNvNtCsg8Ts9hS57d_8no_panic5inner6shim_x",
      "_ZN8no_panic5inner6shim_x17hcafe0123456789abE",
      // A TYPE at the test crate's root rather than the `fn`. v0 writes the
      // namespace of the node whose parent is the crate root, and `t` is not
      // an item that carries a body.
      "_RNtCsg8Ts9hS57d_8no_panic6shim_x",
      // A longer name, written with its own length.
      "_RNvCsg8Ts9hS57d_8no_panic12shim_x_extra",
      "_ZN8no_panic12shim_x_extra17hcafe0123456789abE",
      // Digits running into the length: `16shim_xyz…` is a 16-byte component
      // that happens to start `6shim_x`.
      "_RNvCsg8Ts9hS57d_8no_panic16shim_xyzabcdefghij",
      // Legacy's components are parsed to the `E` that closes them, so what
      // follows the shim has to BE components. The matcher this replaced
      // stripped two and ignored the rest, which accepted any suffix at all.
      "_ZN8no_panic6shim_x_and_whatever_follows",
      // Not a Rust mangling at all — a C symbol, and the same with Mach-O's
      // leading underscore.
      "shim_x",
      "_shim_x",
      "no_panic_shim_x",
    ] {
      let found = parsed(symbol);
      assert!(
        !found.is_some_and(|(_, krate, _, item)| krate == "no_panic" && item == "shim_x"),
        "{symbol}: {found:?}"
      );
    }
  }

  // The scan this parser replaced looked for `NvC` ANYWHERE in the string and
  // read the bytes after it as a path. This is a perfectly valid symbol for an
  // item of crate `foo` whose NAME contains those bytes: nothing is forged, the
  // encoding simply does not license reading a component where no component
  // begins.
  #[test]
  fn a_node_embedded_in_a_name_is_not_a_path() {
    assert_eq!(
      parsed("_RNvC3foo26xNvC8no_panic11shim_decode"),
      Some((Scheme::V0, "foo", "", "xNvC8no_panic11shim_decode"))
    );
    // And the symbol it is trying to look like, for contrast.
    assert_eq!(
      parsed("_RNvC8no_panic11shim_decode"),
      Some((Scheme::V0, "no_panic", "", "shim_decode"))
    );
  }

  // A path this does not parse is not credited to anyone. `<{closure in
  // no_panic::shim_x} as FnOnce<()>>::call_once` MENTIONS the shim inside a
  // type, and the shim it would speak for always has a symbol of its own —
  // `#[inline(never)]` is what guarantees that, and the caller requires it.
  #[test]
  fn a_path_rooted_at_something_other_than_a_crate_is_not_read() {
    for symbol in [
      "_RNvYNCNvCsg8Ts9hS57d_8no_panic6shim_x0INtNtNtCs_4core3ops8function6FnOnceuE9call_once",
      "__RNvYNCNvCsg8Ts9hS57d_8no_panic6shim_x0INtNtNtCs_4core3ops8function6FnOnceuE9call_once",
      // A generic instance, whose outermost node is `I` rather than a path.
      "_RINvCsg8Ts9hS57d_8no_panic6shim_xlE",
      // A crate root on its own names no item under it.
      "_RC8no_panic",
      // An encoding version this does not read — the digit after `_R`.
      "_R9NvC8no_panic6shim_x",
    ] {
      assert_eq!(parsed(symbol), None, "{symbol}");
    }
  }

  // A crate NAME is not a crate. Several crates in one link may be called
  // `no_panic` — one may simply be named that, and this workspace's `no-panic`
  // dependency IS — and what tells two of them apart is the disambiguator v0
  // writes beside the name, which the matcher this replaced discarded.
  #[test]
  fn two_crates_of_one_name_are_two_crates() {
    let ours = rooted("_RNvCsg8Ts9hS57d_8no_panic4main").expect("the anchor is a v0 symbol");
    for (symbol, same) in [
      ("_RNvCsg8Ts9hS57d_8no_panic6shim_x", true),
      // The same crate name, a different disambiguator: another crate.
      ("_RNvCskTPi6a8sh2G_8no_panic6shim_x", false),
      // No disambiguator at all is not "any disambiguator" — it is zero.
      ("_RNvC8no_panic6shim_x", false),
      // And the scheme is part of it: one crate is compiled under one
      // mangling, so a symbol written the other way came out of another.
      ("_ZN8no_panic6shim_x17hcafe0123456789abE", false),
    ] {
      let other = rooted(symbol).expect("a symbol this reads");
      assert_eq!(ours.same_crate_as(&other), same, "{symbol}");
    }
  }

  // `_ZN` is C++'s prefix too, and a C++ mangler spells `no_panic::shim_x` with
  // the same bytes — minus the `17h…` hash rustc closes every legacy symbol
  // with, which is the one part of the encoding it does not write.
  #[test]
  fn a_legacy_symbol_without_rustcs_hash_is_not_read_as_one() {
    assert_eq!(parsed("_ZN8no_panic6shim_xE"), None);
    assert_eq!(parsed("_ZN8no_panic6shim_x17hcafe0123456789aE"), None);
    assert_eq!(parsed("_ZN8no_panic6shim_x17gcafe0123456789abE"), None);
    assert_eq!(
      parsed("_ZN8no_panic6shim_x17hcafe0123456789abE"),
      Some((Scheme::Legacy, "no_panic", "", "shim_x"))
    );
  }

  // The diagnostic, which is deliberately looser than the gate and is only
  // ever used to say WHO ELSE spells the name. Both schemes, and the two ways
  // a substring test could be wrong.
  #[test]
  fn the_diagnostic_names_a_component_in_either_scheme() {
    for symbol in [
      "_ZN8no_panic18shim_varint_decode17hcafe0123456789abE",
      "_RNvCsg8Ts9hS57d_8no_panic18shim_varint_decode",
      "__RNvYNCNvCsg8Ts9hS57d_8no_panic18shim_varint_decode0INtNtNtCs_4core3ops8function6FnOnceuE9call_once",
    ] {
      assert!(names_component(symbol, "shim_varint_decode"), "{symbol}");
      assert!(names_component(symbol, "no_panic"), "{symbol}");
    }

    // `shim_varint_decode_extra` is written with its own length, so the needle
    // for `shim_varint_decode` is not in it.
    let symbol = "_RNvCsg8Ts9hS57d_8no_panic24shim_varint_decode_extra";
    assert!(!names_component(symbol, "shim_varint_decode"), "{symbol}");
    assert!(
      names_component(symbol, "shim_varint_decode_extra"),
      "{symbol}"
    );

    // `118shim_x` is a 118-byte component that happens to start `8shim_x`; the
    // needle for `shim_x` is `6shim_x`, and the `1` before a would-be match is
    // what says the number was longer than the needle read.
    assert!(!names_component("_RNvCs_9no_panic16shim_xyz", "shim_x"));
    assert!(names_component("_RNvCs_8no_panic6shim_x", "shim_x"));

    // And it is looser than the gate ON PURPOSE: this is exactly the case
    // `rooted` reads as another crate's item and this one reports.
    assert!(names_component(
      "_RNvCsg8Ts9hS57d_9elsewhere6shim_x",
      "shim_x"
    ));
    assert_eq!(
      parsed("_RNvCsg8Ts9hS57d_9elsewhere6shim_x"),
      Some((Scheme::V0, "elsewhere", "sg8Ts9hS57d_", "shim_x"))
    );
  }
}
