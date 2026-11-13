//! morpheus-certificate-install 0.4.0 — bounds-checked ASN.1 TLV reader.
//!
//! The PKCS#7, PKCS#12 and JKS readers walk structures with this instead of typed decoders so that
//! (a) the order of a SET OF is kept as written (der 0.7 re-sorts it), and (b) BER from Windows and
//! older Java (indefinite lengths, constructed OCTET STRINGs) reads the same as DER.
//!
//! Every length is checked against the bytes that are actually there, with checked arithmetic, and
//! nesting is capped at [`MAX_DEPTH`]. Nothing here allocates in proportion to a declared length.

use std::fmt;

/// Deepest nesting we follow (PKCS#12 needs about 12; anything far deeper is hostile).
pub const MAX_DEPTH: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlvError {
    /// The value needs `need` bytes from here but only `have` are left.
    Truncated { need: usize, have: usize },
    /// Not well-formed (bad length encoding, high tag numbers, nesting too deep…).
    Bad(&'static str),
}

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlvError::Truncated { need, have } => write!(f, "cut short: needs {need} more bytes, {have} left"),
            TlvError::Bad(why) => f.write_str(why),
        }
    }
}

pub type Result<T> = std::result::Result<T, TlvError>;

/// One tag-length-value. `whole` is the complete encoding (header + content [+ end-of-contents]).
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub whole: &'a [u8],
    pub content: &'a [u8],
    pub indefinite: bool,
}

impl<'a> Tlv<'a> {
    pub fn constructed(&self) -> bool { self.tag & 0x20 != 0 }
    /// The children of a constructed value.
    pub fn children(&self) -> Result<Vec<Tlv<'a>>> { children(self.content) }
    pub fn expect(self, tag: u8, what: &'static str) -> Result<Self> {
        if self.tag == tag { Ok(self) } else { Err(TlvError::Bad(what)) }
    }
}

/// Read the first TLV of `buf` (trailing bytes are allowed; see [`read_exact`]).
pub fn read(buf: &[u8]) -> Result<Tlv<'_>> { read_depth(buf, 0) }

/// Read one TLV that must fill `buf` exactly.
pub fn read_exact(buf: &[u8]) -> Result<Tlv<'_>> {
    let t = read(buf)?;
    if t.whole.len() != buf.len() { return Err(TlvError::Bad("trailing data after the value")); }
    Ok(t)
}

/// The length the outer header claims, if it is definite and well-formed (for "file is cut short").
pub fn declared_len(buf: &[u8]) -> Option<usize> {
    let (len, hl) = header(buf).ok()?;
    hl.checked_add(len?)
}

/// (content length or None for indefinite, header length)
fn header(buf: &[u8]) -> Result<(Option<usize>, usize)> {
    if buf.len() < 2 { return Err(TlvError::Truncated { need: 2, have: buf.len() }); }
    if buf[0] & 0x1f == 0x1f { return Err(TlvError::Bad("high tag numbers are not used here")); }
    match buf[1] {
        n if n < 0x80 => Ok((Some(n as usize), 2)),
        0x80 => Ok((None, 2)),
        0xff => Err(TlvError::Bad("reserved length octet")),
        n => {
            let k = (n & 0x7f) as usize;
            if k > 4 { return Err(TlvError::Bad("length field longer than 4 bytes")); }
            if buf.len() < 2 + k { return Err(TlvError::Truncated { need: 2 + k, have: buf.len() }); }
            let len = buf[2..2 + k].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
            Ok((Some(len), 2 + k))
        }
    }
}

fn read_depth(buf: &[u8], depth: usize) -> Result<Tlv<'_>> {
    if depth > MAX_DEPTH { return Err(TlvError::Bad("nested too deeply")); }
    let tag = buf.first().copied().ok_or(TlvError::Truncated { need: 2, have: 0 })?;
    let (len, hl) = header(buf)?;
    match len {
        Some(len) => {
            let end = hl.checked_add(len).ok_or(TlvError::Bad("length overflows"))?;
            if buf.len() < end { return Err(TlvError::Truncated { need: end, have: buf.len() }); }
            Ok(Tlv { tag, whole: &buf[..end], content: &buf[hl..end], indefinite: false })
        }
        None => {
            if tag & 0x20 == 0 { return Err(TlvError::Bad("indefinite length on a primitive value")); }
            // Children until the end-of-contents octets 00 00.
            let mut pos = hl;
            loop {
                let rest = &buf[pos..];
                if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                    return Ok(Tlv { tag, whole: &buf[..pos + 2], content: &buf[hl..pos], indefinite: true });
                }
                if rest.is_empty() { return Err(TlvError::Truncated { need: 2, have: 0 }); }
                let child = read_depth(rest, depth + 1)?;
                pos += child.whole.len();
            }
        }
    }
}

/// Every TLV in `content`, in order.
pub fn children(mut content: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let t = read(content)?;
        content = &content[t.whole.len()..];
        out.push(t);
    }
    Ok(out)
}

/// OCTET STRING value: primitive (0x04 / an IMPLICIT primitive tag) as-is; constructed (BER) chunks
/// concatenated.
pub fn octets(t: &Tlv<'_>) -> Result<Vec<u8>> {
    fn walk(t: &Tlv<'_>, out: &mut Vec<u8>, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH { return Err(TlvError::Bad("nested too deeply")); }
        if !t.constructed() {
            out.extend_from_slice(t.content);
            return Ok(());
        }
        for c in t.children()? {
            if c.tag & !0x20 != 0x04 { return Err(TlvError::Bad("constructed OCTET STRING holds something else")); }
            walk(&c, out, depth + 1)?;
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(t, &mut out, 0)?;
    Ok(out)
}

/// Non-negative INTEGER that fits in a u64.
pub fn uint(t: &Tlv<'_>) -> Result<u64> {
    if t.tag != 0x02 { return Err(TlvError::Bad("expected an INTEGER")); }
    let c = t.content;
    if c.is_empty() { return Err(TlvError::Bad("empty INTEGER")); }
    if c[0] & 0x80 != 0 { return Err(TlvError::Bad("negative INTEGER")); }
    let c = if c[0] == 0 && c.len() > 1 { &c[1..] } else { c };
    if c.len() > 8 { return Err(TlvError::Bad("INTEGER too large")); }
    Ok(c.iter().fold(0u64, |a, b| (a << 8) | *b as u64))
}

pub fn oid(t: &Tlv<'_>) -> Result<const_oid::ObjectIdentifier> {
    if t.tag != 0x06 { return Err(TlvError::Bad("expected an OBJECT IDENTIFIER")); }
    const_oid::ObjectIdentifier::from_bytes(t.content).map_err(|_| TlvError::Bad("malformed OBJECT IDENTIFIER"))
}

/// Re-encode a tag and content as definite-length DER (for test fixtures crafted in memory and
/// for wrapping values this module unwrapped).
pub fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        v.push(0x80 | bytes.len() as u8);
        v.extend_from_slice(&bytes);
    }
    v.extend_from_slice(content);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definite_and_children() {
        let d = [0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0xAA];
        let t = read_exact(&d).unwrap();
        let c = t.children().unwrap();
        assert_eq!(uint(&c[0]).unwrap(), 5);
        assert_eq!(octets(&c[1]).unwrap(), vec![0xAA]);
    }

    #[test]
    fn indefinite_and_constructed_octets() {
        // SEQUENCE (indef) { OCTET STRING (constructed, indef) { 04 01 01, 04 02 02 03 } }
        let d = [0x30, 0x80, 0x24, 0x80, 0x04, 0x01, 0x01, 0x04, 0x02, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00];
        let t = read_exact(&d).unwrap();
        assert!(t.indefinite);
        let c = t.children().unwrap();
        assert_eq!(octets(&c[0]).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn hostile_lengths_are_errors_not_panics() {
        for d in [
            &[][..], &[0x30][..], &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff][..], &[0x30, 0x85, 1, 1, 1, 1, 1][..],
            &[0x30, 0x82, 0x01][..], &[0x30, 0x80][..], &[0x30, 0x80, 0x30, 0x80][..], &[0x04, 0x80, 0, 0][..],
            &[0x1f, 0x01, 0x00][..], &[0x30, 0xff][..],
        ] {
            assert!(read(d).is_err(), "{d:02x?}");
        }
        // Deep nesting of indefinite SEQUENCEs is capped, not a stack overflow.
        let mut deep = Vec::new();
        for _ in 0..10_000 { deep.extend_from_slice(&[0x30, 0x80]); }
        assert!(read(&deep).is_err());
        assert_eq!(declared_len(&[0x30, 0x82, 0x01, 0x00]), Some(260));
    }

    #[test]
    fn encode_lengths() {
        assert_eq!(encode(0x04, &[1, 2]), vec![0x04, 2, 1, 2]);
        let big = encode(0x04, &[0u8; 300]);
        assert_eq!(&big[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(read_exact(&big).unwrap().content.len(), 300);
    }
}
