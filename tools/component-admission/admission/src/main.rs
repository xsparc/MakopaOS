use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use makopa_component_admission::{
    ADMISSION_BYTES, BUILD_EVIDENCE_BYTES, BundleInputs, EXECUTION_PROFILE_BYTES,
    MAX_COMPONENT_BYTES, MAX_SOURCE_MANIFEST_BYTES, MAX_WIT_BYTES, PUBLIC_KEY_BYTES,
    SIGNATURE_BYTES, read_bounded, verify_bundle,
};

const USAGE: &str = "usage: makopa-component-admission check \
--admission FILE --signature FILE --public-key FILE --component FILE \
--wit FILE --execution-profile FILE --target-triple FILE \
--runtime-config FILE --compiler-config FILE --build-evidence FILE \
--source-manifest FILE --builder-identity FILE --command-transcript FILE \
--dependency-lock FILE --tool-versions FILE --source-root DIRECTORY \
[--executable FILE]";

fn main() -> ExitCode {
    match run() {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(code) => {
            eprintln!(
                "{{\"schema_version\":1,\"scope\":\"os041a-admission-core-v1\",\"status\":\"fail\",\"admission_authority\":false,\"error\":\"{}\"}}",
                json_escape(code)
            );
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<String, &'static str> {
    let mut arguments = env::args_os().skip(1);
    if arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .as_deref()
        != Some("check")
    {
        return Err(USAGE);
    }
    let mut values = BTreeMap::<String, PathBuf>::new();
    while let Some(name) = arguments.next() {
        let name = name.into_string().map_err(|_| "argument-encoding")?;
        if !name.starts_with("--") || name == "--" {
            return Err("argument-name");
        }
        let value = arguments.next().ok_or("argument-value")?;
        if values.insert(name, PathBuf::from(value)).is_some() {
            return Err("argument-duplicate");
        }
    }

    const REQUIRED: &[&str] = &[
        "--admission",
        "--signature",
        "--public-key",
        "--component",
        "--wit",
        "--execution-profile",
        "--target-triple",
        "--runtime-config",
        "--compiler-config",
        "--build-evidence",
        "--source-manifest",
        "--builder-identity",
        "--command-transcript",
        "--dependency-lock",
        "--tool-versions",
        "--source-root",
    ];
    if values
        .keys()
        .any(|key| !REQUIRED.contains(&key.as_str()) && key != "--executable")
    {
        return Err("argument-unknown");
    }
    if REQUIRED.iter().any(|name| !values.contains_key(*name)) {
        return Err("argument-missing");
    }

    let admission = read(&values, "--admission", ADMISSION_BYTES)?;
    let signature = read(&values, "--signature", SIGNATURE_BYTES)?;
    let public_key = read(&values, "--public-key", PUBLIC_KEY_BYTES)?;
    let component = read(&values, "--component", MAX_COMPONENT_BYTES)?;
    let executable = values
        .get("--executable")
        .map(|path| read_bounded(path, MAX_COMPONENT_BYTES).map_err(|error| error.code()))
        .transpose()?;
    let wit = read(&values, "--wit", MAX_WIT_BYTES)?;
    let execution_profile = read(&values, "--execution-profile", EXECUTION_PROFILE_BYTES)?;
    let target_triple = read(&values, "--target-triple", 96)?;
    let runtime_configuration = read(&values, "--runtime-config", 4096)?;
    let compiler_configuration = read(&values, "--compiler-config", 4096)?;
    let build_evidence = read(&values, "--build-evidence", BUILD_EVIDENCE_BYTES)?;
    let source_manifest = read(&values, "--source-manifest", MAX_SOURCE_MANIFEST_BYTES)?;
    let builder_identity = read(&values, "--builder-identity", 128)?;
    let command_transcript = read(&values, "--command-transcript", 4096)?;
    let dependency_lock = read(&values, "--dependency-lock", 524_288)?;
    let tool_versions = read(&values, "--tool-versions", 4096)?;
    let source_root = path(&values, "--source-root")?;

    verify_bundle(&BundleInputs {
        admission_record: &admission,
        detached_signature: &signature,
        public_key: &public_key,
        portable_component: &component,
        target_executable: executable.as_deref(),
        wit: &wit,
        execution_profile_record: &execution_profile,
        target_triple: &target_triple,
        runtime_configuration: &runtime_configuration,
        compiler_configuration: &compiler_configuration,
        build_evidence_record: &build_evidence,
        source_manifest: &source_manifest,
        builder_identity: &builder_identity,
        command_transcript: &command_transcript,
        dependency_lock: &dependency_lock,
        tool_versions: &tool_versions,
        staged_source_root: source_root,
    })
    .map(|report| report.to_json())
    .map_err(|error| error.code())
}

fn read(
    values: &BTreeMap<String, PathBuf>,
    name: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, &'static str> {
    read_bounded(path(values, name)?, maximum).map_err(|error| error.code())
}

fn path<'a>(
    values: &'a BTreeMap<String, PathBuf>,
    name: &'static str,
) -> Result<&'a Path, &'static str> {
    values
        .get(name)
        .map(PathBuf::as_path)
        .ok_or("argument-missing")
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '"' => "\\\"".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            character if character.is_control() => "?".chars().collect(),
            character => vec![character],
        })
        .collect()
}
