//! Strict encoding detection followed by the pinned, DTD-disabled XML parser.
use std::collections::BTreeMap;

#[derive(Debug)]
pub(super) struct Element {
    pub name: String,
    pub attributes: BTreeMap<String, String>,
    pub text: String,
    pub children: Vec<Element>,
}
impl Element {
    pub fn named(&self, name: &str) -> Vec<&Self> {
        self.children
            .iter()
            .filter(|node| node.name == name)
            .collect()
    }
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<String, String> {
    let (bytes, endian) = if let Some(rest) = bytes.strip_prefix(&[0xff, 0xfe]) {
        (rest, Some(true))
    } else if let Some(rest) = bytes.strip_prefix(&[0xfe, 0xff]) {
        (rest, Some(false))
    } else if bytes.starts_with(&[0x3c, 0, 0x3f, 0]) {
        (bytes, Some(true))
    } else if bytes.starts_with(&[0, 0x3c, 0, 0x3f]) {
        (bytes, Some(false))
    } else {
        (
            bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes),
            None,
        )
    };
    let text = if let Some(little) = endian {
        if bytes.len() % 2 != 0 {
            return Err("Odd UTF-16 XML byte count".into());
        }
        let units: Vec<_> = bytes
            .chunks_exact(2)
            .map(|pair| {
                let pair = [pair[0], pair[1]];
                if little {
                    u16::from_le_bytes(pair)
                } else {
                    u16::from_be_bytes(pair)
                }
            })
            .collect();
        String::from_utf16(&units).map_err(|e| format!("Invalid UTF-16 XML: {e}"))?
    } else {
        std::str::from_utf8(bytes)
            .map_err(|e| format!("Invalid UTF-8 XML: {e}"))?
            .into()
    };
    // Read only XML declaration pseudo-attributes. Document conformance remains
    // the parser's responsibility; this prevents its UTF-8 API ignoring evidence.
    if let Some(declaration) = text.trim_start_matches(xml_space).strip_prefix("<?xml") {
        let declaration = declaration.split("?>").next().unwrap_or(declaration);
        if let Some(rest) = declaration.split_once("encoding") {
            let rest = rest
                .1
                .trim_start()
                .strip_prefix('=')
                .ok_or("Malformed encoding declaration")?
                .trim_start();
            let quote = rest.chars().next().ok_or("Missing encoding value")?;
            if !['\'', '"'].contains(&quote) {
                return Err("Unquoted encoding declaration".into());
            }
            let encoding = rest[1..]
                .split(quote)
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let matches = match encoding.as_str() {
                "utf-8" => endian.is_none(),
                "utf-16" => endian.is_some(),
                "utf-16le" => endian == Some(true),
                "utf-16be" => endian == Some(false),
                _ => false,
            };
            if !matches {
                return Err(format!(
                    "Unsupported or conflicting XML encoding: {encoding}"
                ));
            }
        }
    }
    Ok(text)
}
fn expanded(namespace: Option<&str>, name: &str) -> String {
    match namespace {
        Some(uri) => format!("{{{uri}}}{name}"),
        None => name.into(),
    }
}
fn xml_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}
fn element(node: roxmltree::Node<'_, '_>) -> Element {
    Element {
        name: expanded(node.tag_name().namespace(), node.tag_name().name()),
        attributes: node
            .attributes()
            .map(|a| (expanded(a.namespace(), a.name()), a.value().into()))
            .collect(),
        text: node
            .children()
            .filter(|n| n.is_text())
            .filter_map(|n| n.text())
            .collect(),
        children: node
            .children()
            .filter(|n| n.is_element())
            .map(element)
            .collect(),
    }
}
pub(super) fn parse(bytes: &[u8]) -> Result<Element, String> {
    let text = decode(bytes)?;
    let document = roxmltree::Document::parse_with_options(
        text.trim_matches(xml_space),
        roxmltree::ParsingOptions {
            allow_dtd: false,
            ..Default::default()
        },
    )
    .map_err(|e| format!("Malformed XML (roxmltree): {e}"))?;
    Ok(element(document.root_element()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodings_entities_cdata_and_expanded_names() {
        for (label, little) in [("UTF-16LE", true), ("UTF-16BE", false)] {
            let text = format!("<?xml version='1.0' encoding='{label}'?><root a='&amp;&#x41;&#65;'><![CDATA[x<y]]> \u{e9}</root>");
            let mut bytes = if little {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            };
            for unit in text.encode_utf16() {
                bytes.extend(if little {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
            let root = parse(&bytes).unwrap();
            assert_eq!(root.attr("a"), Some("&AA"));
            assert_eq!(root.text, "x<y \u{e9}");
            assert!(parse(&bytes[..bytes.len() - 1]).is_err());
        }
        let root = parse(b"<r xmlns='urn:r' xmlns:a='urn:a' a:x='1'/>").unwrap();
        assert_eq!(root.name, "{urn:r}r");
        assert_eq!(root.attr("{urn:a}x"), Some("1"));
        assert_eq!(root.attr("x"), None);
    }
    #[test]
    fn rejects_invalid_documents_and_encoding_evidence() {
        for bytes in [
            b"<!DOCTYPE r><r/>".as_slice(),
            b"<r a='1' a='2'/>",
            b"<r/><r/>",
            b"<r>&external;</r>",
            b"<?xml version='1.0' encoding='UTF-16'?><r/>",
            b"<?xml version='1.0' encoding='latin1'?><r/>",
            b"<r>\xff</r>",
            b"\xc2\xa0<r/>",
            &[0xff, 0xfe, 0, 0xd8],
        ] {
            assert!(parse(bytes).is_err(), "{bytes:?}");
        }
    }
}
