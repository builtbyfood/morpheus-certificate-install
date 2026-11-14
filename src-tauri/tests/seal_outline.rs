//! morpheus-certificate-install 0.4.2 — the seal's 12-point outline is centred in its 68×68 viewBox,
//! in both places it's drawn: the app icon's source (src-tauri/icons/icon.svg) and the page's
//! `sealSvg()` (ui/index.html). The first scaffold's hand-drawn outline was off-centre, at about
//! (31, 28.5); 0.4.0 replaced it with a symmetric one.

use std::path::PathBuf;

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The `d` of the first `<path d="…">` inside the first `<svg viewBox="0 0 68 68"` after `after`:
/// the outline is the svg's first path in both files (sealSvg()'s glyph strings come before its svg).
fn outline_d(text: &str, after: &str) -> String {
    let start = text.find(after).unwrap_or_else(|| panic!("{after:?} not found"));
    let svg = text[start..].find("<svg viewBox=\"0 0 68 68\"").or_else(|| text[start..].find("viewBox=\"0 0 68 68\"")).expect("no 68×68 svg");
    let rest = &text[start + svg..];
    let i = rest.find("<path d=\"").expect("no <path d=") + "<path d=\"".len();
    let j = rest[i..].find('"').expect("unterminated d");
    rest[i..i + j].to_string()
}

/// The points of a polyline path: M/m, L/l, H/h, V/v and Z/z, absolute or relative, with
/// implicit repeats (`l5 4 6-1`). Anything else (curves, arcs) fails the test, since an outline
/// with curves would need a real bounding-box computation.
fn points(d: &str) -> Vec<(f64, f64)> {
    let mut tokens: Vec<String> = vec![];
    let mut num = String::new();
    let flush = |num: &mut String, tokens: &mut Vec<String>| {
        if !num.is_empty() { tokens.push(std::mem::take(num)); }
    };
    for ch in d.chars() {
        match ch {
            c if c.is_ascii_alphabetic() && c != 'e' && c != 'E' => { flush(&mut num, &mut tokens); tokens.push(c.to_string()); }
            '-' if !num.is_empty() && !num.ends_with(['e', 'E']) => { flush(&mut num, &mut tokens); num.push('-'); }
            c if c.is_whitespace() || c == ',' => flush(&mut num, &mut tokens),
            c => num.push(c),
        }
    }
    flush(&mut num, &mut tokens);
    let (mut pts, mut cur, mut cmd) = (vec![], (0.0f64, 0.0f64), 'M');
    let mut it = tokens.iter().peekable();
    let mut next = |it: &mut std::iter::Peekable<std::slice::Iter<String>>| -> f64 {
        it.next().expect("missing number").parse::<f64>().expect("bad number")
    };
    while let Some(t) = it.peek().cloned() {
        if let Some(c) = t.chars().next().filter(|c| c.is_ascii_alphabetic()) {
            it.next();
            cmd = c;
            if c == 'Z' || c == 'z' { continue; }
        }
        match cmd {
            'M' | 'L' => { cur = (next(&mut it), next(&mut it)); }
            'm' | 'l' => { let (dx, dy) = (next(&mut it), next(&mut it)); cur = (cur.0 + dx, cur.1 + dy); }
            'H' => cur.0 = next(&mut it),
            'h' => cur.0 += next(&mut it),
            'V' => cur.1 = next(&mut it),
            'v' => cur.1 += next(&mut it),
            'Z' | 'z' => panic!("number after Z in {d:?}"),
            other => panic!("path command {other:?} isn't a polyline command: {d:?}"),
        }
        pts.push(cur);
        // An M is followed by implicit L (m by l).
        if cmd == 'M' { cmd = 'L'; } else if cmd == 'm' { cmd = 'l'; }
    }
    pts
}

fn bbox_centre(pts: &[(f64, f64)]) -> (f64, f64) {
    let (mut x0, mut y0, mut x1, mut y1) = (f64::MAX, f64::MAX, f64::MIN, f64::MIN);
    for &(x, y) in pts { x0 = x0.min(x); y0 = y0.min(y); x1 = x1.max(x); y1 = y1.max(y); }
    ((x0 + x1) / 2.0, (y0 + y1) / 2.0)
}

fn assert_centred(what: &str, d: &str) {
    let pts = points(d);
    assert_eq!(pts.len(), 24, "{what}: a 12-point seal has 24 vertices, got {}", pts.len());
    let (cx, cy) = bbox_centre(&pts);
    assert!((cx - 34.0).abs() <= 0.1 && (cy - 34.0).abs() <= 0.1, "{what}: bounding-box centre ({cx:.2}, {cy:.2}), expected (34, 34) ± 0.1");
}

#[test]
fn the_app_icon_seal_is_centred() {
    assert_centred("src-tauri/icons/icon.svg", &outline_d(&read("icons/icon.svg"), "<svg"));
}

#[test]
fn the_page_seal_is_centred() {
    assert_centred("ui/index.html sealSvg()", &outline_d(&read("../ui/index.html"), "function sealSvg("));
}

#[test]
fn both_places_draw_the_same_outline() {
    assert_eq!(outline_d(&read("icons/icon.svg"), "<svg"), outline_d(&read("../ui/index.html"), "function sealSvg("));
}

/// The parser itself: the first scaffold's relative outline comes out off-centre, as described.
#[test]
fn the_old_outline_was_off_centre() {
    let old = "M34 3l5 4 6-1 3 5 6 2 0 6 4 5-3 5 2 6-5 4-1 6-6 1-3 5-6-1-5 4-5-4-6 1-3-5-6-1-1-6-5-4 2-6-3-5 4-5 0-6 6-2 3-5 6 1z";
    let (cx, cy) = bbox_centre(&points(old));
    assert!((cx - 31.0).abs() < 0.6 && (cy - 28.5).abs() < 0.6, "old outline centre ({cx}, {cy})");
}
