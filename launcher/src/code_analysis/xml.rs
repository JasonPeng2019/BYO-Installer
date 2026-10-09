//! XML parsing uses Windows XmlLite through Microsoft's generated bindings.
//! DTDs and external resolution are prohibited; the reader owns its memory stream.
use std::collections::BTreeMap;
use windows::core::{Interface, PCWSTR};
use windows::Win32::Data::Xml::XmlLite::*;
use windows::Win32::System::Com::IMalloc;
use windows::Win32::UI::Shell::SHCreateMemStream;

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

unsafe fn reader_string(reader: &IXmlReader, value: bool) -> windows::core::Result<String> {
    let mut pointer = PCWSTR::null();
    let mut length = 0;
    if value {
        reader.GetValue(&mut pointer, Some(&mut length))?;
    } else {
        reader.GetQualifiedName(&mut pointer, Some(&mut length))?;
    }
    if length == 0 {
        return Ok(String::new());
    }
    // XmlLite owns this UTF-16 view until the reader moves. Copy before moving.
    Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
        pointer.0,
        length as usize,
    )))
}

pub(super) fn parse(bytes: &[u8]) -> Result<Element, String> {
    if bytes.len() > u32::MAX as usize {
        return Err("XML exceeds the native stream length limit".into());
    }
    let parsed = (|| -> windows::core::Result<Element> {
        unsafe {
            let stream =
                SHCreateMemStream(Some(bytes)).ok_or_else(windows::core::Error::from_thread)?;
            let mut raw = std::ptr::null_mut();
            CreateXmlReader(&IXmlReader::IID, &mut raw, None::<&IMalloc>)?;
            let reader = IXmlReader::from_raw(raw);
            reader.SetProperty(
                XmlReaderProperty_DtdProcessing.0 as u32,
                Some(DtdProcessing_Prohibit.0 as isize),
            )?;
            reader.SetProperty(
                XmlReaderProperty_ConformanceLevel.0 as u32,
                Some(XmlConformanceLevel_Document.0 as isize),
            )?;
            reader.SetInput(&stream)?;
            let mut stack: Vec<Element> = Vec::new();
            let mut root = None;
            loop {
                let mut node_type = XmlNodeType_None;
                let status = reader.Read(Some(&mut node_type));
                if status.0 == 1 {
                    break;
                } // S_FALSE is end-of-document, not an error.
                status.ok()?;
                if node_type == XmlNodeType_Element {
                    let mut uri = PCWSTR::null();
                    let mut uri_length = 0;
                    reader.GetNamespaceUri(&mut uri, Some(&mut uri_length))?;
                    // Match expanded names used by the accepted XML contract;
                    // a default namespace must not masquerade as XML-v2 results.
                    let name = if uri_length == 0 {
                        reader_string(&reader, false)?
                    } else {
                        format!(
                            "{{{}}}{}",
                            String::from_utf16_lossy(std::slice::from_raw_parts(
                                uri.0,
                                uri_length as usize
                            )),
                            reader_string(&reader, false)?
                        )
                    };
                    let mut element = Element {
                        name,
                        attributes: BTreeMap::new(),
                        text: String::new(),
                        children: Vec::new(),
                    };
                    let empty = reader.IsEmptyElement().as_bool();
                    let mut moved = reader.MoveToFirstAttribute();
                    while moved.0 == 0 {
                        element.attributes.insert(
                            reader_string(&reader, false)?,
                            reader_string(&reader, true)?,
                        );
                        moved = reader.MoveToNextAttribute();
                    }
                    moved.ok()?;
                    reader.MoveToElement()?;
                    if empty {
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(element);
                        } else {
                            root = Some(element);
                        }
                    } else {
                        stack.push(element);
                    }
                } else if node_type == XmlNodeType_EndElement {
                    let element = stack.pop().ok_or_else(windows::core::Error::from_thread)?;
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(element);
                    } else {
                        root = Some(element);
                    }
                } else if node_type == XmlNodeType_Text
                    || node_type == XmlNodeType_CDATA
                    || node_type == XmlNodeType_Whitespace
                {
                    if let Some(parent) = stack.last_mut() {
                        parent.text.push_str(&reader_string(&reader, true)?);
                    }
                }
            }
            if !stack.is_empty() {
                return Err(windows::core::Error::from_thread());
            }
            root.ok_or_else(windows::core::Error::from_thread)
        }
    })();
    parsed.map_err(|error| format!("Malformed XML (XmlLite): {error}"))
}
