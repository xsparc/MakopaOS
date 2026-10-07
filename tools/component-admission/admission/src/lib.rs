//! Offline admission primitives for the MakopaOS profile-zero component bundle.
//!
//! The crate is deliberately host-only. It parses fixed records through explicit
//! little-endian offsets, verifies exact byte bindings, and never instantiates a
//! component.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use wasmparser::{
    ComponentExternalKind, ComponentTypeRef, Encoding, Parser, Payload, Validator, WasmFeatures,
};
use wit_parser::{Resolve, SourceMap};

pub const ADMISSION_BYTES: usize = 288;
pub const EXECUTION_PROFILE_BYTES: usize = 224;
pub const BUILD_EVIDENCE_BYTES: usize = 256;
pub const SIGNATURE_BYTES: usize = 64;
pub const PUBLIC_KEY_BYTES: usize = 32;
pub const KEY_ID_BYTES: usize = 16;
pub const SIGNATURE_MESSAGE_BYTES: usize = 318;
pub const SIGNATURE_DOMAIN: &[u8; 30] = b"MAKOPA-COMPONENT-ADMISSION-V1\0";
pub const KEY_ID_DOMAIN: &[u8; 25] = b"MAKOPA-ED25519-KEY-ID-V1\0";

pub const MAX_COMPONENT_BYTES: usize = 1_048_576;
pub const MAX_WIT_BYTES: usize = 65_536;
pub const MAX_SOURCE_MANIFEST_BYTES: usize = 65_536;
pub const MAX_SOURCE_FILE_BYTES: usize = 262_144;
pub const MAX_SOURCE_BYTES: usize = 1_048_576;
pub const MAX_SOURCE_FILES: usize = 256;
pub const MAX_COMPONENT_DEPTH: usize = 8;
pub const MAX_COMPONENT_SECTIONS: usize = 256;
pub const MAX_COMPONENT_TYPES: usize = 4_096;
pub const MAX_COMPONENT_IMPORTS: usize = 256;
pub const MAX_COMPONENT_EXPORTS: usize = 256;
pub const MAX_CUSTOM_SECTIONS: usize = 32;
pub const MAX_CUSTOM_SECTION_BYTES: usize = 65_536;
pub const MAX_COMPONENT_NAME_BYTES: usize = 256;

pub const EXPECTED_IMPORT: &str = "makopa:component/console@1.0.0";
pub const EXPECTED_EXPORT: &str = "makopa:component/task@1.0.0";
pub const EXPECTED_WIT: &[u8] = include_bytes!("../wit/console-workload.wit");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    Io,
    InputType,
    Size,
    Schema,
    Reserved,
    Field,
    Length,
    Digest,
    KeyId,
    WeakKey,
    Signature,
    Utf8,
    Document,
    Manifest,
    SourceInventory,
    Component,
    ComponentSurface,
    Wit,
}

impl AdmissionError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::InputType => "input-type",
            Self::Size => "size",
            Self::Schema => "schema",
            Self::Reserved => "reserved",
            Self::Field => "field",
            Self::Length => "length",
            Self::Digest => "digest",
            Self::KeyId => "key-id",
            Self::WeakKey => "weak-key",
            Self::Signature => "signature",
            Self::Utf8 => "utf8",
            Self::Document => "document",
            Self::Manifest => "source-manifest",
            Self::SourceInventory => "source-inventory",
            Self::Component => "component",
            Self::ComponentSurface => "component-surface",
            Self::Wit => "wit",
        }
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AdmissionError {}

impl From<io::Error> for AdmissionError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

pub type AdmissionResult<T> = Result<T, AdmissionError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentAdmissionV1 {
    pub component_id: u64,
    pub contract_major: u32,
    pub contract_minor: u32,
    pub contract_patch: u32,
    pub component_profile: u32,
    pub portable_artifact_length: u64,
    pub target_executable_length: u64,
    pub portable_artifact_sha256: [u8; 32],
    pub target_executable_sha256: [u8; 32],
    pub wit_package_sha256: [u8; 32],
    pub execution_profile_sha256: [u8; 32],
    pub build_evidence_sha256: [u8; 32],
    pub maximum_linear_memory_bytes: u64,
    pub maximum_execution_stack_bytes: u64,
    pub maximum_deterministic_fuel: u64,
    pub maximum_component_instances: u32,
    pub maximum_linear_memories: u32,
    pub maximum_tables: u32,
    pub maximum_component_resources: u32,
    pub maximum_accepted_console_calls: u32,
    pub maximum_console_bytes_per_call: u32,
    pub signing_key_id: [u8; 16],
}

impl ComponentAdmissionV1 {
    pub fn parse(bytes: &[u8]) -> AdmissionResult<Self> {
        require_size(bytes, ADMISSION_BYTES)?;
        if u32_at(bytes, 0)? != 1 || u32_at(bytes, 4)? != ADMISSION_BYTES as u32 {
            return Err(AdmissionError::Schema);
        }
        if !is_zero(&bytes[280..288]) {
            return Err(AdmissionError::Reserved);
        }
        let value = Self {
            component_id: u64_at(bytes, 8)?,
            contract_major: u32_at(bytes, 16)?,
            contract_minor: u32_at(bytes, 20)?,
            contract_patch: u32_at(bytes, 24)?,
            component_profile: u32_at(bytes, 28)?,
            portable_artifact_length: u64_at(bytes, 32)?,
            target_executable_length: u64_at(bytes, 40)?,
            portable_artifact_sha256: array_at(bytes, 48)?,
            target_executable_sha256: array_at(bytes, 80)?,
            wit_package_sha256: array_at(bytes, 112)?,
            execution_profile_sha256: array_at(bytes, 144)?,
            build_evidence_sha256: array_at(bytes, 176)?,
            maximum_linear_memory_bytes: u64_at(bytes, 208)?,
            maximum_execution_stack_bytes: u64_at(bytes, 216)?,
            maximum_deterministic_fuel: u64_at(bytes, 224)?,
            maximum_component_instances: u32_at(bytes, 232)?,
            maximum_linear_memories: u32_at(bytes, 236)?,
            maximum_tables: u32_at(bytes, 240)?,
            maximum_component_resources: u32_at(bytes, 244)?,
            maximum_accepted_console_calls: u32_at(bytes, 248)?,
            maximum_console_bytes_per_call: u32_at(bytes, 252)?,
            signing_key_id: array_at(bytes, 264)?,
        };
        if u32_at(bytes, 256)? != 1 || u32_at(bytes, 260)? != SIGNATURE_BYTES as u32 {
            return Err(AdmissionError::Field);
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> AdmissionResult<()> {
        let executable_pair_valid = if self.target_executable_length == 0 {
            is_zero(&self.target_executable_sha256)
        } else {
            !is_zero(&self.target_executable_sha256)
        };
        if self.component_id == 0
            || self.contract_major != 1
            || self.contract_minor != 0
            || self.contract_patch != 0
            || self.component_profile != 0
            || self.portable_artifact_length == 0
            || self.portable_artifact_length > MAX_COMPONENT_BYTES as u64
            || !executable_pair_valid
            || is_zero(&self.portable_artifact_sha256)
            || is_zero(&self.wit_package_sha256)
            || is_zero(&self.execution_profile_sha256)
            || is_zero(&self.build_evidence_sha256)
            || self.maximum_linear_memory_bytes == 0
            || self.maximum_execution_stack_bytes == 0
            || self.maximum_deterministic_fuel == 0
            || self.maximum_component_instances == 0
            || self.maximum_linear_memories == 0
            || self.maximum_accepted_console_calls != 1
            || self.maximum_console_bytes_per_call != 64
            || is_zero(&self.signing_key_id)
        {
            return Err(AdmissionError::Field);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProfileV1 {
    pub target_architecture: u32,
    pub target_environment: u32,
    pub runtime_family: u32,
    pub runtime_version: (u32, u32, u32),
    pub compiler_family: u32,
    pub compiler_version: (u32, u32, u32),
    pub component_profile: u32,
    pub code_publication_mode: u32,
    pub trap_mode: u32,
    pub memory_mode: u32,
    pub core_wasm_features: u64,
    pub component_model_features: u64,
    pub cpu_features: u64,
    pub target_triple_length: u32,
    pub runtime_configuration_length: u32,
    pub compiler_configuration_length: u32,
    pub target_triple_sha256: [u8; 32],
    pub runtime_configuration_sha256: [u8; 32],
    pub compiler_configuration_sha256: [u8; 32],
}

impl ExecutionProfileV1 {
    pub fn parse(bytes: &[u8]) -> AdmissionResult<Self> {
        require_size(bytes, EXECUTION_PROFILE_BYTES)?;
        if u32_at(bytes, 0)? != 1 || u32_at(bytes, 4)? != EXECUTION_PROFILE_BYTES as u32 {
            return Err(AdmissionError::Schema);
        }
        if u32_at(bytes, 100)? != 0 || !is_zero(&bytes[200..224]) {
            return Err(AdmissionError::Reserved);
        }
        let value = Self {
            target_architecture: u32_at(bytes, 8)?,
            target_environment: u32_at(bytes, 12)?,
            runtime_family: u32_at(bytes, 16)?,
            runtime_version: (u32_at(bytes, 20)?, u32_at(bytes, 24)?, u32_at(bytes, 28)?),
            compiler_family: u32_at(bytes, 32)?,
            compiler_version: (u32_at(bytes, 36)?, u32_at(bytes, 40)?, u32_at(bytes, 44)?),
            component_profile: u32_at(bytes, 48)?,
            code_publication_mode: u32_at(bytes, 52)?,
            trap_mode: u32_at(bytes, 56)?,
            memory_mode: u32_at(bytes, 60)?,
            core_wasm_features: u64_at(bytes, 64)?,
            component_model_features: u64_at(bytes, 72)?,
            cpu_features: u64_at(bytes, 80)?,
            target_triple_length: u32_at(bytes, 88)?,
            runtime_configuration_length: u32_at(bytes, 92)?,
            compiler_configuration_length: u32_at(bytes, 96)?,
            target_triple_sha256: array_at(bytes, 104)?,
            runtime_configuration_sha256: array_at(bytes, 136)?,
            compiler_configuration_sha256: array_at(bytes, 168)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> AdmissionResult<()> {
        if self.target_architecture != 1
            || self.target_environment != 2
            || self.runtime_family != 1
            || self.runtime_version != (48, 0, 1)
            || self.compiler_family != 1
            || self.compiler_version != (48, 0, 1)
            || self.component_profile != 0
            || self.code_publication_mode != 0
            || self.trap_mode != 0
            || self.memory_mode != 0
            || self.core_wasm_features != 1
            || self.component_model_features != 1
            || self.cpu_features != 0
            || !(1..=96).contains(&self.target_triple_length)
            || !(1..=4096).contains(&self.runtime_configuration_length)
            || !(1..=4096).contains(&self.compiler_configuration_length)
            || is_zero(&self.target_triple_sha256)
            || is_zero(&self.runtime_configuration_sha256)
            || is_zero(&self.compiler_configuration_sha256)
        {
            return Err(AdmissionError::Field);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildEvidenceV1 {
    pub build_type: u32,
    pub source_revision_kind: u32,
    pub source_revision_length: u32,
    pub builder_identity_length: u32,
    pub command_transcript_length: u32,
    pub dependency_lock_length: u32,
    pub tool_version_length: u32,
    pub command_count: u32,
    pub tool_count: u32,
    pub source_revision_sha256: [u8; 32],
    pub builder_identity_sha256: [u8; 32],
    pub command_transcript_sha256: [u8; 32],
    pub dependency_lock_sha256: [u8; 32],
    pub tool_version_sha256: [u8; 32],
}

impl BuildEvidenceV1 {
    pub fn parse(bytes: &[u8]) -> AdmissionResult<Self> {
        require_size(bytes, BUILD_EVIDENCE_BYTES)?;
        if u32_at(bytes, 0)? != 1 || u32_at(bytes, 4)? != BUILD_EVIDENCE_BYTES as u32 {
            return Err(AdmissionError::Schema);
        }
        if u32_at(bytes, 44)? != 0 || !is_zero(&bytes[208..256]) {
            return Err(AdmissionError::Reserved);
        }
        let value = Self {
            build_type: u32_at(bytes, 8)?,
            source_revision_kind: u32_at(bytes, 12)?,
            source_revision_length: u32_at(bytes, 16)?,
            builder_identity_length: u32_at(bytes, 20)?,
            command_transcript_length: u32_at(bytes, 24)?,
            dependency_lock_length: u32_at(bytes, 28)?,
            tool_version_length: u32_at(bytes, 32)?,
            command_count: u32_at(bytes, 36)?,
            tool_count: u32_at(bytes, 40)?,
            source_revision_sha256: array_at(bytes, 48)?,
            builder_identity_sha256: array_at(bytes, 80)?,
            command_transcript_sha256: array_at(bytes, 112)?,
            dependency_lock_sha256: array_at(bytes, 144)?,
            tool_version_sha256: array_at(bytes, 176)?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> AdmissionResult<()> {
        if self.build_type != 1
            || self.source_revision_kind != 1
            || !(1..=MAX_SOURCE_MANIFEST_BYTES as u32).contains(&self.source_revision_length)
            || !(1..=128).contains(&self.builder_identity_length)
            || !(1..=4096).contains(&self.command_transcript_length)
            || !(1..=524_288).contains(&self.dependency_lock_length)
            || !(1..=4096).contains(&self.tool_version_length)
            || self.command_count == 0
            || self.tool_count == 0
            || is_zero(&self.source_revision_sha256)
            || is_zero(&self.builder_identity_sha256)
            || is_zero(&self.command_transcript_sha256)
            || is_zero(&self.dependency_lock_sha256)
            || is_zero(&self.tool_version_sha256)
        {
            return Err(AdmissionError::Field);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntryV1 {
    pub mode: u32,
    pub length: u64,
    pub sha256: [u8; 32],
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceManifestV1 {
    pub tree_path: String,
    pub git_tree_sha1: [u8; 20],
    pub entries: Vec<SourceEntryV1>,
}

impl SourceManifestV1 {
    pub fn parse(bytes: &[u8]) -> AdmissionResult<Self> {
        if bytes.is_empty()
            || bytes.len() > MAX_SOURCE_MANIFEST_BYTES
            || !bytes.is_ascii()
            || bytes.last() != Some(&b'\n')
            || bytes.contains(&b'\r')
            || bytes.contains(&0)
            || bytes.ends_with(b"\n\n")
        {
            return Err(AdmissionError::Manifest);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| AdmissionError::Utf8)?;
        let mut lines = text[..text.len() - 1].split('\n');
        exact_line(lines.next(), "schema=makopa-source-manifest-v1")?;
        exact_line(
            lines.next(),
            "repository=git+https://github.com/xsparc/MakopaOS",
        )?;
        let tree_path = value_line(lines.next(), "tree-path=")?.to_owned();
        validate_path(&tree_path)?;
        let tree_hex = value_line(lines.next(), "git-tree-sha1=")?;
        let git_tree_sha1 = decode_hex_array::<20>(tree_hex)?;
        let file_count = parse_canonical_decimal(value_line(lines.next(), "file-count=")?)?;
        if file_count == 0 || file_count > MAX_SOURCE_FILES as u64 {
            return Err(AdmissionError::Manifest);
        }

        let mut entries = Vec::with_capacity(file_count as usize);
        let mut prior_path: Option<String> = None;
        let mut aggregate = 0_u64;
        for line in lines {
            let mut fields = line.splitn(4, ' ');
            let mode_text = fields.next().ok_or(AdmissionError::Manifest)?;
            let length_text = fields.next().ok_or(AdmissionError::Manifest)?;
            let digest_text = fields.next().ok_or(AdmissionError::Manifest)?;
            let path = fields.next().ok_or(AdmissionError::Manifest)?.to_owned();
            if fields.next().is_some() {
                return Err(AdmissionError::Manifest);
            }
            let mode = match mode_text {
                "100644" => 0o100644,
                "100755" => 0o100755,
                _ => return Err(AdmissionError::Manifest),
            };
            let length = parse_canonical_decimal(length_text)?;
            if length > MAX_SOURCE_FILE_BYTES as u64 {
                return Err(AdmissionError::Manifest);
            }
            aggregate = aggregate
                .checked_add(length)
                .ok_or(AdmissionError::Manifest)?;
            if aggregate > MAX_SOURCE_BYTES as u64 {
                return Err(AdmissionError::Manifest);
            }
            validate_path(&path)?;
            if let Some(prior) = prior_path.as_deref()
                && (prior.as_bytes() >= path.as_bytes()
                    || path
                        .strip_prefix(prior)
                        .is_some_and(|suffix| suffix.starts_with('/')))
            {
                return Err(AdmissionError::Manifest);
            }
            let sha256 = decode_hex_array::<32>(digest_text)?;
            prior_path = Some(path.clone());
            entries.push(SourceEntryV1 {
                mode,
                length,
                sha256,
                path,
            });
        }
        if entries.len() != file_count as usize {
            return Err(AdmissionError::Manifest);
        }
        Ok(Self {
            tree_path,
            git_tree_sha1,
            entries,
        })
    }

    pub fn verify_staged_root(&self, root: &Path) -> AdmissionResult<()> {
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AdmissionError::SourceInventory);
        }
        let mut actual = BTreeMap::new();
        collect_source_files(root, root, &mut actual)?;
        if actual.len() != self.entries.len() {
            return Err(AdmissionError::SourceInventory);
        }
        for entry in &self.entries {
            let value = actual
                .get(entry.path.as_str())
                .ok_or(AdmissionError::SourceInventory)?;
            if value.mode != entry.mode
                || value.length != entry.length
                || value.sha256 != entry.sha256
            {
                return Err(AdmissionError::SourceInventory);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentSurface {
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub section_count: usize,
    pub type_count: usize,
    pub custom_section_count: usize,
    pub custom_section_bytes: usize,
    pub maximum_depth: usize,
}

pub fn inspect_component(bytes: &[u8]) -> AdmissionResult<ComponentSurface> {
    if bytes.is_empty() || bytes.len() > MAX_COMPONENT_BYTES {
        return Err(AdmissionError::Size);
    }
    let features = WasmFeatures::WASM1 | WasmFeatures::COMPONENT_MODEL;
    Validator::new_with_features(features)
        .validate_all(bytes)
        .map_err(|_| AdmissionError::Component)?;

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut section_count = 0_usize;
    let mut type_count = 0_usize;
    let mut custom_section_count = 0_usize;
    let mut custom_section_bytes = 0_usize;
    let mut depth = 0_usize;
    let mut maximum_depth = 0_usize;
    let mut saw_top_version = false;
    let mut saw_top_end = false;

    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|_| AdmissionError::Component)? {
            Payload::Version { encoding, .. } => {
                if !saw_top_version {
                    if encoding != Encoding::Component {
                        return Err(AdmissionError::Component);
                    }
                    saw_top_version = true;
                } else {
                    depth = depth.checked_add(1).ok_or(AdmissionError::Component)?;
                    maximum_depth = maximum_depth.max(depth);
                    if maximum_depth > MAX_COMPONENT_DEPTH {
                        return Err(AdmissionError::Component);
                    }
                }
            }
            Payload::End(_) => {
                if depth == 0 {
                    saw_top_end = true;
                } else {
                    depth -= 1;
                }
            }
            Payload::ComponentImportSection(reader) => {
                section_count += 1;
                if depth == 0 {
                    for item in reader {
                        let item = item.map_err(|_| AdmissionError::Component)?;
                        if !matches!(item.ty, ComponentTypeRef::Instance(_)) {
                            return Err(AdmissionError::ComponentSurface);
                        }
                        if item.name.implements.is_some()
                            || item.name.version_suffix.is_some()
                            || item.name.external_id.is_some()
                        {
                            return Err(AdmissionError::ComponentSurface);
                        }
                        push_name(&mut imports, item.name.name, MAX_COMPONENT_IMPORTS)?;
                    }
                }
            }
            Payload::ComponentExportSection(reader) => {
                section_count += 1;
                if depth == 0 {
                    for item in reader {
                        let item = item.map_err(|_| AdmissionError::Component)?;
                        if item.kind != ComponentExternalKind::Instance {
                            return Err(AdmissionError::ComponentSurface);
                        }
                        if item.name.implements.is_some()
                            || item.name.version_suffix.is_some()
                            || item.name.external_id.is_some()
                        {
                            return Err(AdmissionError::ComponentSurface);
                        }
                        push_name(&mut exports, item.name.name, MAX_COMPONENT_EXPORTS)?;
                    }
                }
            }
            Payload::TypeSection(reader) => {
                section_count += 1;
                type_count =
                    checked_count(type_count, reader.count() as usize, MAX_COMPONENT_TYPES)?;
            }
            Payload::ComponentTypeSection(reader) => {
                section_count += 1;
                type_count =
                    checked_count(type_count, reader.count() as usize, MAX_COMPONENT_TYPES)?;
            }
            Payload::CustomSection(reader) => {
                section_count += 1;
                custom_section_count = checked_count(custom_section_count, 1, MAX_CUSTOM_SECTIONS)?;
                custom_section_bytes = checked_count(
                    custom_section_bytes,
                    reader.data().len(),
                    MAX_CUSTOM_SECTION_BYTES,
                )?;
            }
            Payload::CodeSectionEntry(_) => {}
            _ => {
                section_count = checked_count(section_count, 1, MAX_COMPONENT_SECTIONS)?;
            }
        }
        if section_count > MAX_COMPONENT_SECTIONS {
            return Err(AdmissionError::Component);
        }
    }
    if !saw_top_version
        || !saw_top_end
        || imports.as_slice() != [EXPECTED_IMPORT]
        || exports.as_slice() != [EXPECTED_EXPORT]
        || imports.len() > MAX_COMPONENT_IMPORTS
        || exports.len() > MAX_COMPONENT_EXPORTS
    {
        return Err(AdmissionError::ComponentSurface);
    }
    Ok(ComponentSurface {
        imports,
        exports,
        section_count,
        type_count,
        custom_section_count,
        custom_section_bytes,
        maximum_depth,
    })
}

pub fn validate_wit_contract(bytes: &[u8]) -> AdmissionResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_WIT_BYTES || bytes != EXPECTED_WIT {
        return Err(AdmissionError::Wit);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| AdmissionError::Utf8)?;
    let mut source_map = SourceMap::new();
    source_map.push_str("console-workload.wit", source);
    let group = source_map.parse().map_err(|_| AdmissionError::Wit)?;
    let mut resolve = Resolve::default();
    resolve.push_group(group).map_err(|_| AdmissionError::Wit)?;
    Ok(())
}

pub fn signing_key_id(public_key: &[u8; PUBLIC_KEY_BYTES]) -> [u8; KEY_ID_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_DOMAIN);
    hasher.update(public_key);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut result = [0_u8; KEY_ID_BYTES];
    result.copy_from_slice(&digest[..KEY_ID_BYTES]);
    result
}

pub fn signature_message(
    admission_record: &[u8],
) -> AdmissionResult<[u8; SIGNATURE_MESSAGE_BYTES]> {
    require_size(admission_record, ADMISSION_BYTES)?;
    let mut message = [0_u8; SIGNATURE_MESSAGE_BYTES];
    message[..SIGNATURE_DOMAIN.len()].copy_from_slice(SIGNATURE_DOMAIN);
    message[SIGNATURE_DOMAIN.len()..].copy_from_slice(admission_record);
    Ok(message)
}

pub fn verify_signature(
    admission_record: &[u8],
    detached_signature: &[u8],
    public_key: &[u8],
    expected_key_id: &[u8; KEY_ID_BYTES],
) -> AdmissionResult<()> {
    require_size(detached_signature, SIGNATURE_BYTES)?;
    require_size(public_key, PUBLIC_KEY_BYTES)?;
    let public_key_array: [u8; PUBLIC_KEY_BYTES] =
        public_key.try_into().map_err(|_| AdmissionError::Size)?;
    if signing_key_id(&public_key_array) != *expected_key_id {
        return Err(AdmissionError::KeyId);
    }
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_array).map_err(|_| AdmissionError::Signature)?;
    if verifying_key.is_weak() {
        return Err(AdmissionError::WeakKey);
    }
    let signature =
        Signature::from_slice(detached_signature).map_err(|_| AdmissionError::Signature)?;
    let message = signature_message(admission_record)?;
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| AdmissionError::Signature)
}

pub struct BundleInputs<'a> {
    pub admission_record: &'a [u8],
    pub detached_signature: &'a [u8],
    pub public_key: &'a [u8],
    pub portable_component: &'a [u8],
    pub target_executable: Option<&'a [u8]>,
    pub wit: &'a [u8],
    pub execution_profile_record: &'a [u8],
    pub target_triple: &'a [u8],
    pub runtime_configuration: &'a [u8],
    pub compiler_configuration: &'a [u8],
    pub build_evidence_record: &'a [u8],
    pub source_manifest: &'a [u8],
    pub builder_identity: &'a [u8],
    pub command_transcript: &'a [u8],
    pub dependency_lock: &'a [u8],
    pub tool_versions: &'a [u8],
    pub staged_source_root: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionReportV1 {
    pub component_id: u64,
    pub portable_sha256: [u8; 32],
    pub source_file_count: usize,
    pub source_byte_count: u64,
    pub section_count: usize,
    pub maximum_depth: usize,
}

impl AdmissionReportV1 {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"schema_version\":1,\"scope\":\"os041a-admission-core-v1\",\"status\":\"pass\",\"admission_authority\":false,\"component_id\":{},\"portable_sha256\":\"{}\",\"source_file_count\":{},\"source_byte_count\":{},\"section_count\":{},\"maximum_depth\":{}}}",
            self.component_id,
            encode_hex(&self.portable_sha256),
            self.source_file_count,
            self.source_byte_count,
            self.section_count,
            self.maximum_depth,
        )
    }
}

pub fn verify_bundle(inputs: &BundleInputs<'_>) -> AdmissionResult<AdmissionReportV1> {
    let admission = ComponentAdmissionV1::parse(inputs.admission_record)?;
    verify_signature(
        inputs.admission_record,
        inputs.detached_signature,
        inputs.public_key,
        &admission.signing_key_id,
    )?;

    verify_bound_bytes(
        inputs.portable_component,
        admission.portable_artifact_length,
        &admission.portable_artifact_sha256,
    )?;
    match (admission.target_executable_length, inputs.target_executable) {
        (0, None) => {}
        (length, Some(bytes)) if length != 0 => {
            verify_bound_bytes(bytes, length, &admission.target_executable_sha256)?
        }
        _ => return Err(AdmissionError::Length),
    }
    verify_digest(inputs.wit, &admission.wit_package_sha256)?;
    verify_digest(
        inputs.execution_profile_record,
        &admission.execution_profile_sha256,
    )?;
    verify_digest(
        inputs.build_evidence_record,
        &admission.build_evidence_sha256,
    )?;

    let execution = ExecutionProfileV1::parse(inputs.execution_profile_record)?;
    if execution.component_profile != admission.component_profile {
        return Err(AdmissionError::Field);
    }
    verify_length_digest(
        inputs.target_triple,
        execution.target_triple_length,
        &execution.target_triple_sha256,
    )?;
    verify_length_digest(
        inputs.runtime_configuration,
        execution.runtime_configuration_length,
        &execution.runtime_configuration_sha256,
    )?;
    verify_length_digest(
        inputs.compiler_configuration,
        execution.compiler_configuration_length,
        &execution.compiler_configuration_sha256,
    )?;
    validate_target_triple(inputs.target_triple)?;
    validate_name_value_document(inputs.runtime_configuration)?;
    validate_name_value_document(inputs.compiler_configuration)?;

    let build = BuildEvidenceV1::parse(inputs.build_evidence_record)?;
    verify_length_digest(
        inputs.source_manifest,
        build.source_revision_length,
        &build.source_revision_sha256,
    )?;
    verify_length_digest(
        inputs.builder_identity,
        build.builder_identity_length,
        &build.builder_identity_sha256,
    )?;
    verify_length_digest(
        inputs.command_transcript,
        build.command_transcript_length,
        &build.command_transcript_sha256,
    )?;
    verify_length_digest(
        inputs.dependency_lock,
        build.dependency_lock_length,
        &build.dependency_lock_sha256,
    )?;
    verify_length_digest(
        inputs.tool_versions,
        build.tool_version_length,
        &build.tool_version_sha256,
    )?;
    validate_builder_identity(inputs.builder_identity)?;
    validate_line_document(inputs.command_transcript, build.command_count)?;
    validate_name_value_document_counted(inputs.tool_versions, build.tool_count)?;

    let manifest = SourceManifestV1::parse(inputs.source_manifest)?;
    manifest.verify_staged_root(inputs.staged_source_root)?;
    validate_wit_contract(inputs.wit)?;
    let surface = inspect_component(inputs.portable_component)?;
    let source_byte_count = manifest.entries.iter().try_fold(0_u64, |sum, entry| {
        sum.checked_add(entry.length).ok_or(AdmissionError::Length)
    })?;

    Ok(AdmissionReportV1 {
        component_id: admission.component_id,
        portable_sha256: admission.portable_artifact_sha256,
        source_file_count: manifest.entries.len(),
        source_byte_count,
        section_count: surface.section_count,
        maximum_depth: surface.maximum_depth,
    })
}

pub fn read_bounded(path: &Path, maximum: usize) -> AdmissionResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AdmissionError::InputType);
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(AdmissionError::Size);
    }
    Ok(bytes)
}

fn verify_bound_bytes(bytes: &[u8], length: u64, digest: &[u8; 32]) -> AdmissionResult<()> {
    if length > usize::MAX as u64 || bytes.len() != length as usize {
        return Err(AdmissionError::Length);
    }
    verify_digest(bytes, digest)
}

fn verify_length_digest(bytes: &[u8], length: u32, digest: &[u8; 32]) -> AdmissionResult<()> {
    if bytes.len() != length as usize {
        return Err(AdmissionError::Length);
    }
    verify_digest(bytes, digest)
}

fn verify_digest(bytes: &[u8], expected: &[u8; 32]) -> AdmissionResult<()> {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if actual != *expected {
        return Err(AdmissionError::Digest);
    }
    Ok(())
}

fn validate_target_triple(bytes: &[u8]) -> AdmissionResult<()> {
    if bytes.is_empty()
        || bytes.len() > 96
        || !bytes.is_ascii()
        || bytes
            .iter()
            .any(|byte| byte.is_ascii_whitespace() || !byte.is_ascii_graphic())
    {
        return Err(AdmissionError::Document);
    }
    Ok(())
}

fn validate_builder_identity(bytes: &[u8]) -> AdmissionResult<()> {
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes.is_ascii()
        || bytes.iter().any(|byte| !byte.is_ascii_graphic())
        || contains_sensitive_evidence(bytes)
    {
        return Err(AdmissionError::Document);
    }
    Ok(())
}

fn validate_name_value_document(bytes: &[u8]) -> AdmissionResult<()> {
    let count = line_count(bytes)?;
    validate_name_value_document_counted(bytes, count as u32)
}

fn validate_name_value_document_counted(bytes: &[u8], expected_count: u32) -> AdmissionResult<()> {
    let text = line_text(bytes)?;
    let mut prior: Option<&str> = None;
    let mut count = 0_u32;
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once('=').ok_or(AdmissionError::Document)?;
        if name.is_empty()
            || value.is_empty()
            || name.contains('=')
            || value.contains('=')
            || line
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || !byte.is_ascii_graphic())
            || value.contains(":\\")
            || value.starts_with('/')
            || value.starts_with("\\\\")
            || contains_sensitive_evidence(line.as_bytes())
        {
            return Err(AdmissionError::Document);
        }
        if prior.is_some_and(|previous| previous.as_bytes() >= line.as_bytes()) {
            return Err(AdmissionError::Document);
        }
        prior = Some(line);
        count = count.checked_add(1).ok_or(AdmissionError::Document)?;
    }
    if count != expected_count {
        return Err(AdmissionError::Document);
    }
    Ok(())
}

fn validate_line_document(bytes: &[u8], expected_count: u32) -> AdmissionResult<()> {
    let text = line_text(bytes)?;
    let mut count = 0_usize;
    for line in text.split('\n').filter(|line| !line.is_empty()) {
        if contains_machine_local_path(line) || contains_sensitive_evidence(line.as_bytes()) {
            return Err(AdmissionError::Document);
        }
        count = count.checked_add(1).ok_or(AdmissionError::Document)?;
    }
    if count != expected_count as usize {
        return Err(AdmissionError::Document);
    }
    Ok(())
}

fn contains_machine_local_path(line: &str) -> bool {
    if line.contains("\\\\") || line.contains("file://") {
        return true;
    }
    let bytes = line.as_bytes();
    for index in 0..bytes.len().saturating_sub(2) {
        if bytes[index].is_ascii_alphabetic()
            && bytes[index + 1] == b':'
            && matches!(bytes[index + 2], b'/' | b'\\')
        {
            return true;
        }
    }
    line.split_ascii_whitespace().any(|token| {
        let candidate = token.trim_matches(['\'', '"', '(', ')', '[', ']', '{', '}', ',']);
        candidate.starts_with('/')
            || candidate
                .split_once('=')
                .is_some_and(|(_, value)| value.starts_with('/'))
    })
}

fn contains_sensitive_evidence(bytes: &[u8]) -> bool {
    let lower = bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    [
        b"credential".as_slice(),
        b"password".as_slice(),
        b"passwd".as_slice(),
        b"private-key".as_slice(),
        b"private_key".as_slice(),
        b"secret=".as_slice(),
        b"signature=".as_slice(),
        b"token=".as_slice(),
    ]
    .iter()
    .any(|needle| lower.windows(needle.len()).any(|window| window == *needle))
}

fn line_count(bytes: &[u8]) -> AdmissionResult<usize> {
    Ok(line_text(bytes)?
        .split('\n')
        .filter(|line| !line.is_empty())
        .count())
}

fn line_text(bytes: &[u8]) -> AdmissionResult<&str> {
    if bytes.is_empty()
        || bytes.last() != Some(&b'\n')
        || bytes.ends_with(b"\n\n")
        || bytes.contains(&0)
        || bytes.contains(&b'\r')
    {
        return Err(AdmissionError::Document);
    }
    std::str::from_utf8(bytes).map_err(|_| AdmissionError::Utf8)
}

fn collect_source_files(
    root: &Path,
    directory: &Path,
    result: &mut BTreeMap<String, SourceEntryV1>,
) -> AdmissionResult<()> {
    let mut children = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(AdmissionError::SourceInventory);
        }
        if metadata.is_dir() {
            collect_source_files(root, &path, result)?;
            continue;
        }
        if !metadata.is_file() || metadata.len() > MAX_SOURCE_FILE_BYTES as u64 {
            return Err(AdmissionError::SourceInventory);
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| AdmissionError::SourceInventory)?;
        let relative = relative
            .components()
            .map(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .ok_or(AdmissionError::SourceInventory)
            })
            .collect::<AdmissionResult<Vec<_>>>()?
            .join("/");
        validate_path(&relative)?;
        let bytes = read_bounded(&path, MAX_SOURCE_FILE_BYTES)?;
        let mode = file_mode(&metadata);
        let entry = SourceEntryV1 {
            mode,
            length: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
            path: relative.clone(),
        };
        if result.insert(relative, entry).is_some() || result.len() > MAX_SOURCE_FILES {
            return Err(AdmissionError::SourceInventory);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        0o100644
    } else {
        0o100755
    }
}

#[cfg(not(unix))]
fn file_mode(_: &fs::Metadata) -> u32 {
    0o100644
}

fn validate_path(path: &str) -> AdmissionResult<()> {
    if path.is_empty()
        || path.len() > 128
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path.contains('\\')
        || path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        || path.bytes().any(|byte| {
            !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'/')
        })
    {
        return Err(AdmissionError::Manifest);
    }
    Ok(())
}

fn parse_canonical_decimal(text: &str) -> AdmissionResult<u64> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(AdmissionError::Manifest);
    }
    text.parse().map_err(|_| AdmissionError::Manifest)
}

fn decode_hex_array<const N: usize>(text: &str) -> AdmissionResult<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AdmissionError::Manifest);
    }
    let mut result = [0_u8; N];
    for (index, value) in result.iter_mut().enumerate() {
        let high = hex_nibble(text.as_bytes()[index * 2])?;
        let low = hex_nibble(text.as_bytes()[index * 2 + 1])?;
        *value = (high << 4) | low;
    }
    Ok(result)
}

fn hex_nibble(byte: u8) -> AdmissionResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AdmissionError::Manifest),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0xf) as usize] as char);
    }
    result
}

fn exact_line(actual: Option<&str>, expected: &str) -> AdmissionResult<()> {
    if actual != Some(expected) {
        return Err(AdmissionError::Manifest);
    }
    Ok(())
}

fn value_line<'a>(actual: Option<&'a str>, prefix: &str) -> AdmissionResult<&'a str> {
    actual
        .and_then(|line| line.strip_prefix(prefix))
        .filter(|value| !value.is_empty())
        .ok_or(AdmissionError::Manifest)
}

fn push_name(target: &mut Vec<String>, name: &str, maximum: usize) -> AdmissionResult<()> {
    if name.is_empty() || name.len() > MAX_COMPONENT_NAME_BYTES || target.len() >= maximum {
        return Err(AdmissionError::ComponentSurface);
    }
    target.push(name.to_owned());
    Ok(())
}

fn checked_count(current: usize, additional: usize, maximum: usize) -> AdmissionResult<usize> {
    let value = current
        .checked_add(additional)
        .ok_or(AdmissionError::Component)?;
    if value > maximum {
        return Err(AdmissionError::Component);
    }
    Ok(value)
}

fn require_size(bytes: &[u8], expected: usize) -> AdmissionResult<()> {
    if bytes.len() != expected {
        return Err(AdmissionError::Size);
    }
    Ok(())
}

fn u32_at(bytes: &[u8], offset: usize) -> AdmissionResult<u32> {
    Ok(u32::from_le_bytes(array_at(bytes, offset)?))
}

fn u64_at(bytes: &[u8], offset: usize) -> AdmissionResult<u64> {
    Ok(u64::from_le_bytes(array_at(bytes, offset)?))
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> AdmissionResult<[u8; N]> {
    let end = offset.checked_add(N).ok_or(AdmissionError::Size)?;
    bytes
        .get(offset..end)
        .ok_or(AdmissionError::Size)?
        .try_into()
        .map_err(|_| AdmissionError::Size)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wasm_encoder::{
        ComponentBuilder, ComponentExportKind, ComponentExternName, ComponentTypeRef, InstanceType,
        MemorySection, MemoryType, Module,
    };

    const RFC8032_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    fn put_u32(record: &mut [u8], offset: usize, value: u32) {
        record[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(record: &mut [u8], offset: usize, value: u64) {
        record[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn admission_record() -> [u8; ADMISSION_BYTES] {
        let mut record = [0_u8; ADMISSION_BYTES];
        put_u32(&mut record, 0, 1);
        put_u32(&mut record, 4, ADMISSION_BYTES as u32);
        put_u64(&mut record, 8, 7);
        put_u32(&mut record, 16, 1);
        put_u64(&mut record, 32, 8);
        record[48..80].fill(1);
        record[112..144].fill(2);
        record[144..176].fill(3);
        record[176..208].fill(4);
        put_u64(&mut record, 208, 65_536);
        put_u64(&mut record, 216, 16_384);
        put_u64(&mut record, 224, 1_000);
        put_u32(&mut record, 232, 1);
        put_u32(&mut record, 236, 1);
        put_u32(&mut record, 248, 1);
        put_u32(&mut record, 252, 64);
        put_u32(&mut record, 256, 1);
        put_u32(&mut record, 260, SIGNATURE_BYTES as u32);
        record[264..280].copy_from_slice(&signing_key_id(&RFC8032_PUBLIC_KEY));
        record
    }

    fn execution_profile_record() -> [u8; EXECUTION_PROFILE_BYTES] {
        let mut record = [0_u8; EXECUTION_PROFILE_BYTES];
        put_u32(&mut record, 0, 1);
        put_u32(&mut record, 4, EXECUTION_PROFILE_BYTES as u32);
        put_u32(&mut record, 8, 1);
        put_u32(&mut record, 12, 2);
        put_u32(&mut record, 16, 1);
        put_u32(&mut record, 20, 48);
        put_u32(&mut record, 28, 1);
        put_u32(&mut record, 32, 1);
        put_u32(&mut record, 36, 48);
        put_u32(&mut record, 44, 1);
        put_u64(&mut record, 64, 1);
        put_u64(&mut record, 72, 1);
        put_u32(&mut record, 88, 24);
        put_u32(&mut record, 92, 12);
        put_u32(&mut record, 96, 13);
        record[104..136].fill(1);
        record[136..168].fill(2);
        record[168..200].fill(3);
        record
    }

    fn build_evidence_record() -> [u8; BUILD_EVIDENCE_BYTES] {
        let mut record = [0_u8; BUILD_EVIDENCE_BYTES];
        put_u32(&mut record, 0, 1);
        put_u32(&mut record, 4, BUILD_EVIDENCE_BYTES as u32);
        put_u32(&mut record, 8, 1);
        put_u32(&mut record, 12, 1);
        put_u32(&mut record, 16, 256);
        put_u32(&mut record, 20, 12);
        put_u32(&mut record, 24, 11);
        put_u32(&mut record, 28, 100);
        put_u32(&mut record, 32, 15);
        put_u32(&mut record, 36, 1);
        put_u32(&mut record, 40, 1);
        for offset in [48, 80, 112, 144, 176] {
            record[offset..offset + 32].fill((offset / 32) as u8);
        }
        record
    }

    fn raw_surface_component(import: ComponentExternName<'_>, export: &str) -> Vec<u8> {
        let mut builder = ComponentBuilder::default();
        let instance_type = builder.type_instance(None, &InstanceType::new());
        let imported = builder.import(import, ComponentTypeRef::Instance(instance_type));
        builder.export(export, ComponentExportKind::Instance, imported, None);
        builder.finish()
    }

    fn manifest(file_bytes: &[u8]) -> Vec<u8> {
        format!(
            "schema=makopa-source-manifest-v1\nrepository=git+https://github.com/xsparc/MakopaOS\ntree-path=fixtures/console-component\ngit-tree-sha1={}\nfile-count=1\n100644 {} {} source.rs\n",
            "0".repeat(40),
            file_bytes.len(),
            encode_hex(&Sha256::digest(file_bytes)),
        )
        .into_bytes()
    }

    #[test]
    fn derives_domain_separated_key_id() {
        assert_eq!(
            encode_hex(&signing_key_id(&RFC8032_PUBLIC_KEY)),
            "d50f4bd9ff307ac1053b74493e5cf3b7"
        );
    }

    #[test]
    fn creates_exact_signature_message() {
        let record = [0x5a_u8; ADMISSION_BYTES];
        let message = signature_message(&record).unwrap();
        assert_eq!(&message[..30], SIGNATURE_DOMAIN);
        assert_eq!(&message[30..], &record);
    }

    #[test]
    fn parses_all_fixed_records() {
        let admission = ComponentAdmissionV1::parse(&admission_record()).unwrap();
        assert_eq!(admission.component_id, 7);
        assert_eq!(admission.maximum_console_bytes_per_call, 64);

        let execution = ExecutionProfileV1::parse(&execution_profile_record()).unwrap();
        assert_eq!(execution.runtime_version, (48, 0, 1));
        assert_eq!(execution.core_wasm_features, 1);

        let build = BuildEvidenceV1::parse(&build_evidence_record()).unwrap();
        assert_eq!(build.command_count, 1);
        assert_eq!(build.tool_count, 1);
    }

    #[test]
    fn verifies_strict_signature_and_rejects_mutation() {
        let record = admission_record();
        let signature = decode_hex_array::<64>(
            "ee0908f864b5458ee0957f1c969717c1018a470b6f38cb9aea5609318c1345b50846c7f221db8ca0a37593af3116c593432150972ec87eb5b0902b008400e004",
        )
        .unwrap();
        let key_id = signing_key_id(&RFC8032_PUBLIC_KEY);
        verify_signature(&record, &signature, &RFC8032_PUBLIC_KEY, &key_id).unwrap();

        let mut changed = record;
        changed[8] ^= 1;
        assert_eq!(
            verify_signature(&changed, &signature, &RFC8032_PUBLIC_KEY, &key_id),
            Err(AdmissionError::Signature)
        );
    }

    #[test]
    fn binds_exact_lengths_and_digests() {
        let bytes = b"portable";
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        verify_bound_bytes(bytes, bytes.len() as u64, &digest).unwrap();
        assert_eq!(
            verify_bound_bytes(bytes, (bytes.len() - 1) as u64, &digest),
            Err(AdmissionError::Length)
        );
        let mut changed = *bytes;
        changed[0] ^= 1;
        assert_eq!(
            verify_bound_bytes(&changed, changed.len() as u64, &digest),
            Err(AdmissionError::Digest)
        );
    }

    #[test]
    fn validates_canonical_supporting_documents() {
        validate_target_triple(b"x86_64-unknown-linux-gnu").unwrap();
        validate_builder_identity(b"github-actions").unwrap();
        validate_name_value_document(b"a=1\nb=2\n").unwrap();
        validate_line_document(b"cargo test --locked\n", 1).unwrap();

        assert_eq!(
            validate_name_value_document(b"b=2\na=1\n"),
            Err(AdmissionError::Document)
        );
        assert_eq!(
            validate_name_value_document(b"secret=value\n"),
            Err(AdmissionError::Document)
        );
        assert_eq!(
            validate_line_document(b"cargo test C:\\private\n", 1),
            Err(AdmissionError::Document)
        );
    }

    #[test]
    fn validates_exact_component_surface_and_feature_mask() {
        let valid = raw_surface_component(EXPECTED_IMPORT.into(), EXPECTED_EXPORT);
        let surface = inspect_component(&valid).unwrap();
        assert_eq!(surface.imports, [EXPECTED_IMPORT]);
        assert_eq!(surface.exports, [EXPECTED_EXPORT]);

        let wrong_export =
            raw_surface_component(EXPECTED_IMPORT.into(), "other:component/task@1.0.0");
        assert_eq!(
            inspect_component(&wrong_export),
            Err(AdmissionError::ComponentSurface)
        );

        let annotated_import = ComponentExternName {
            name: EXPECTED_IMPORT.into(),
            implements: Some("makopa:component/console@1.0.0".into()),
            version_suffix: None,
            external_id: None,
        };
        let annotated = raw_surface_component(annotated_import, EXPECTED_EXPORT);
        assert!(matches!(
            inspect_component(&annotated),
            Err(AdmissionError::Component | AdmissionError::ComponentSurface)
        ));

        let mut memory64_module = Module::new();
        let mut memories = MemorySection::new();
        memories.memory(MemoryType {
            minimum: 1,
            maximum: Some(1),
            memory64: true,
            shared: false,
            page_size_log2: None,
        });
        memory64_module.section(&memories);
        let mut builder = ComponentBuilder::default();
        builder.core_module(None, &memory64_module);
        let instance_type = builder.type_instance(None, &InstanceType::new());
        let imported = builder.import(EXPECTED_IMPORT, ComponentTypeRef::Instance(instance_type));
        builder.export(
            EXPECTED_EXPORT,
            ComponentExportKind::Instance,
            imported,
            None,
        );
        assert_eq!(
            inspect_component(&builder.finish()),
            Err(AdmissionError::Component)
        );
    }

    #[test]
    fn parses_and_rejects_noncanonical_manifest_paths() {
        let good = manifest(b"fixture");
        let parsed = SourceManifestV1::parse(&good).unwrap();
        assert_eq!(parsed.entries[0].path, "source.rs");

        let bad = String::from_utf8(good)
            .unwrap()
            .replace("source.rs", "../source.rs");
        assert_eq!(
            SourceManifestV1::parse(bad.as_bytes()),
            Err(AdmissionError::Manifest)
        );
    }

    #[test]
    fn verifies_exact_staged_inventory() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("makopa-admission-{unique}"));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("source.rs"), b"fixture").unwrap();
        let parsed = SourceManifestV1::parse(&manifest(b"fixture")).unwrap();
        parsed.verify_staged_root(&root).unwrap();

        fs::write(root.join("source.rs"), b"altered").unwrap();
        assert_eq!(
            parsed.verify_staged_root(&root),
            Err(AdmissionError::SourceInventory)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn requires_exact_supplied_wit() {
        validate_wit_contract(EXPECTED_WIT).unwrap();
        let mut changed = EXPECTED_WIT.to_vec();
        changed.push(b'\n');
        assert_eq!(validate_wit_contract(&changed), Err(AdmissionError::Wit));
    }

    #[test]
    fn rejects_record_size_and_reserved_bytes() {
        assert_eq!(
            ComponentAdmissionV1::parse(&[0_u8; ADMISSION_BYTES - 1]),
            Err(AdmissionError::Size)
        );
        let mut record = [0_u8; ADMISSION_BYTES];
        record[0..4].copy_from_slice(&1_u32.to_le_bytes());
        record[4..8].copy_from_slice(&(ADMISSION_BYTES as u32).to_le_bytes());
        record[280] = 1;
        assert_eq!(
            ComponentAdmissionV1::parse(&record),
            Err(AdmissionError::Reserved)
        );
    }

    #[test]
    fn report_json_is_stable() {
        let report = AdmissionReportV1 {
            component_id: 7,
            portable_sha256: [0xab; 32],
            source_file_count: 2,
            source_byte_count: 9,
            section_count: 3,
            maximum_depth: 1,
        };
        assert_eq!(
            report.to_json(),
            format!(
                "{{\"schema_version\":1,\"scope\":\"os041a-admission-core-v1\",\"status\":\"pass\",\"admission_authority\":false,\"component_id\":7,\"portable_sha256\":\"{}\",\"source_file_count\":2,\"source_byte_count\":9,\"section_count\":3,\"maximum_depth\":1}}",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn bounded_reader_rejects_non_files() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("makopa-input-{unique}"));
        fs::create_dir(&root).unwrap();
        assert_eq!(read_bounded(&root, 16), Err(AdmissionError::InputType));
        fs::remove_dir(root).unwrap();
    }
}
