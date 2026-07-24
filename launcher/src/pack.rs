use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use anyhow::{bail, Context, Result};
use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8] = b"BYOWPK1\n";
const MAX_PACK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RESOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESOURCES: usize = 2_000;

#[derive(Debug, Deserialize)]
struct Header {
    schema: u32,
    product: String,
    workspace_version: String,
    workflow_protocol: u32,
    compression: String,
    resources: Vec<Resource>,
}

#[derive(Debug, Deserialize)]
struct Resource {
    id: String,
    class: String,
    sha256: String,
    offset: usize,
    compressed_size: usize,
    original_size: usize,
}

#[derive(Debug)]
pub struct WorkspacePack {
    header: Header,
    body: Vec<u8>,
    positions: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCatalog {
    pub schema: u32,
    pub workflow_protocol: u32,
    pub modes: Vec<CompiledMode>,
    pub skills: BTreeMap<String, String>,
    pub agents: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledMode {
    pub name: String,
    pub family: String,
    pub extends: Vec<String>,
    pub full_access: bool,
    pub skills: Vec<String>,
    pub instruction_resources: Vec<String>,
    pub verify: CompiledVerify,
    pub codex: CompiledCodex,
    pub workflow: CompiledWorkflow,
    pub structure: CompiledStructure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledVerify {
    pub backend: String,
    pub required_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledCodex {
    pub permission_profile: String,
    pub sandbox_mode: Option<String>,
    pub approval_policy: String,
    pub web_search: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledWorkflow {
    pub one_way_doors: Vec<String>,
    pub adversarial_triggers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledStructure {
    pub version: u32,
    pub default_visibility: String,
    pub required_dirs: Vec<String>,
    pub required_files: Vec<String>,
    pub forbidden_paths: Vec<String>,
}

impl WorkspacePack {
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("failed to inspect workspace pack {}", path.display()))?;
        if !metadata.is_file() || metadata.len() > MAX_PACK_BYTES {
            bail!("workspace pack is not a bounded regular file");
        }
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read workspace pack {}", path.display()))?;
        if bytes.len() < MAGIC.len() + 8 || &bytes[..MAGIC.len()] != MAGIC {
            bail!("workspace pack magic is invalid");
        }
        let size_bytes: [u8; 8] = bytes[MAGIC.len()..MAGIC.len() + 8].try_into()?;
        let header_size = u64::from_be_bytes(size_bytes) as usize;
        let header_start = MAGIC.len() + 8;
        let body_start = header_start
            .checked_add(header_size)
            .context("workspace pack header size overflow")?;
        if body_start > bytes.len() {
            bail!("workspace pack header is truncated");
        }
        let header: Header = serde_json::from_slice(&bytes[header_start..body_start])
            .context("invalid pack header")?;
        if header.schema != 1
            || header.product != "byo"
            || header.workflow_protocol != 1
            || header.compression != "zlib"
            || header.resources.len() > MAX_RESOURCES
        {
            bail!("workspace pack declares an unsupported schema or protocol");
        }
        let body = bytes[body_start..].to_vec();
        let mut positions = BTreeMap::new();
        for (index, resource) in header.resources.iter().enumerate() {
            if resource.id.is_empty()
                || resource.class.is_empty()
                || resource
                    .offset
                    .checked_add(resource.compressed_size)
                    .is_none()
                || resource.offset + resource.compressed_size > body.len()
                || resource.original_size > MAX_RESOURCE_BYTES
                || positions.insert(resource.id.clone(), index).is_some()
            {
                bail!("workspace pack resource index is invalid");
            }
        }
        Ok(Self {
            header,
            body,
            positions,
        })
    }

    pub fn version(&self) -> &str {
        &self.header.workspace_version
    }

    pub fn resource(&self, id: &str) -> Result<Vec<u8>> {
        let index = self
            .positions
            .get(id)
            .with_context(|| format!("workspace resource is missing: {id}"))?;
        let resource = &self.header.resources[*index];
        let compressed = &self.body[resource.offset..resource.offset + resource.compressed_size];
        let mut decoder = ZlibDecoder::new(compressed);
        let mut output = Vec::with_capacity(resource.original_size);
        decoder.read_to_end(&mut output)?;
        if output.len() != resource.original_size
            || crate::manifest::sha256_bytes(&output) != resource.sha256
        {
            bail!("workspace resource failed integrity verification: {id}");
        }
        Ok(output)
    }

    pub fn workflow_catalog(&self) -> Result<WorkflowCatalog> {
        let catalog: WorkflowCatalog =
            serde_json::from_slice(&self.resource("compiled/workflow.json")?)
                .context("compiled workflow catalog is invalid")?;
        if catalog.schema != 1 || catalog.workflow_protocol != self.header.workflow_protocol {
            bail!("compiled workflow catalog schema or protocol is incompatible");
        }
        for mode in &catalog.modes {
            if mode.name.is_empty()
                || mode.family.is_empty()
                || mode.structure.version != 1
                || mode.structure.default_visibility.is_empty()
                || mode
                    .skills
                    .iter()
                    .any(|skill| !catalog.skills.contains_key(skill))
                || mode
                    .instruction_resources
                    .iter()
                    .any(|resource| !self.positions.contains_key(resource))
            {
                bail!("compiled workflow catalog contains an invalid mode");
            }
        }
        if catalog
            .skills
            .values()
            .chain(catalog.agents.values())
            .any(|resource| !self.positions.contains_key(resource))
        {
            bail!("compiled workflow catalog references a missing resource");
        }
        Ok(catalog)
    }

    pub fn mode(&self, name: &str) -> Result<CompiledMode> {
        self.workflow_catalog()?
            .modes
            .into_iter()
            .find(|mode| mode.name == name)
            .with_context(|| format!("compiled mode is missing: {name}"))
    }

    pub fn skill_resource(&self, mode: &CompiledMode, skill: &str) -> Result<Vec<u8>> {
        if !mode.skills.iter().any(|allowed| allowed == skill) {
            bail!("skill {skill:?} is not enabled for mode {}", mode.name);
        }
        let catalog = self.workflow_catalog()?;
        let resource = catalog
            .skills
            .get(skill)
            .with_context(|| format!("compiled skill is missing: {skill}"))?;
        self.resource(resource)
    }

    pub fn agent_resource(&self, agent: &str) -> Result<Vec<u8>> {
        let catalog = self.workflow_catalog()?;
        let resource = catalog
            .agents
            .get(agent)
            .with_context(|| format!("compiled agent is missing: {agent}"))?;
        self.resource(resource)
    }
}
