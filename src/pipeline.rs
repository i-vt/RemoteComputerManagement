// src/pipeline.rs
//
// Pipeline stage parsing and validation for the builder's `--format bin`
// (and the matching BuildRequest.pipeline API field).
//
// A pipeline is a comma-separated list of stages. The FIRST stage is the
// source selector and decides which artifact feeds the pipeline:
//
//   pe | exe  -> build the agent EXE (client)
//   dll      -> build the agent DLL (client_dll)
//   pic      -> compile PIC C (--pic-src or templates/pic_template.c);
//               no Rust agent build at all
//
// Every later stage transforms the artifact:
//
//   donut           -> PE -> donut shellcode (needs the donut generator)
//   srdi            -> DLL -> sRDI reflective shellcode (rcm::shellcode)
//   pe_to_shellcode -> PE -> OEP reflective shellcode (rcm::shellcode)
//   sign            -> Authenticode-sign the PE in place (osslsigncode)
//   b64             -> base64-encode the current bytes
//
// The default pipeline for `--format bin` is "pe,donut" (Windows only in
// v1 - the builder rejects other platforms with a clear error).

/// Source stages: select the initial artifact. Valid only at position 0.
pub const SOURCE_STAGES: [&str; 4] = ["pe", "exe", "dll", "pic"];

/// Transform stages: applied left-to-right after the source stage.
pub const TRANSFORM_STAGES: [&str; 5] = ["donut", "srdi", "pe_to_shellcode", "sign", "b64"];

/// Default pipeline for --format bin when --pipeline is omitted.
pub fn default_pipeline() -> &'static str {
    "pe,donut"
}

/// Parse a pipeline spec into normalized stage names.
/// Errors on empty pipelines and unknown stage names.
pub fn parse_pipeline(spec: &str) -> Result<Vec<String>, String> {
    let stages: Vec<String> = spec
        .split(',')
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    if stages.is_empty() {
        return Err("pipeline must contain at least one stage".into());
    }
    for st in &stages {
        if !SOURCE_STAGES.contains(&st.as_str()) && !TRANSFORM_STAGES.contains(&st.as_str()) {
            return Err(format!(
                "unknown pipeline stage '{}' (known: {}, {})",
                st,
                SOURCE_STAGES.join(","),
                TRANSFORM_STAGES.join(",")
            ));
        }
    }
    Ok(stages)
}

/// Validate stage ordering / applicability:
///   - the first stage must be a source stage (pe|exe|dll|pic),
///   - source stages may not appear later,
///   - donut/srdi/pe_to_shellcode/sign need a PE artifact, i.e. they must
///     come after a pe/exe/dll source (not pic) and before any
///     bin-producing stage.
pub fn validate_pipeline_order(stages: &[String]) -> Result<(), String> {
    if stages.is_empty() {
        return Err("pipeline must contain at least one stage".into());
    }
    if !SOURCE_STAGES.contains(&stages[0].as_str()) {
        return Err(format!(
            "first pipeline stage must be a source stage ({}), got '{}'",
            SOURCE_STAGES.join(","),
            stages[0]
        ));
    }
    let mut is_pe = stages[0] != "pic";
    for (i, st) in stages.iter().enumerate() {
        match st.as_str() {
            s if SOURCE_STAGES.contains(&s) => {
                if i != 0 {
                    return Err(format!(
                        "stage '{s}' is a source stage and must be first"
                    ));
                }
            }
            "donut" | "srdi" | "pe_to_shellcode" => {
                if !is_pe {
                    return Err(format!(
                        "stage '{st}' requires a PE artifact - place it after a \
                         pe/exe/dll source and before any bin-producing stage"
                    ));
                }
                is_pe = false;
            }
            "sign" => {
                if !is_pe {
                    return Err("stage 'sign' requires a PE artifact".into());
                }
            }
            "b64" => {}
            other => return Err(format!("unknown pipeline stage '{other}'")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_pe_donut() {
        let stages = parse_pipeline(default_pipeline()).unwrap();
        assert_eq!(stages, ["pe", "donut"]);
        assert!(validate_pipeline_order(&stages).is_ok());
    }

    #[test]
    fn parses_commas_case_and_whitespace() {
        let stages = parse_pipeline(" DLL, SRDI ,b64 ").unwrap();
        assert_eq!(stages, ["dll", "srdi", "b64"]);
        assert!(validate_pipeline_order(&stages).is_ok());
    }

    #[test]
    fn rejects_empty_and_unknown() {
        assert!(parse_pipeline("").is_err());
        assert!(parse_pipeline(",,,").is_err());
        assert!(parse_pipeline("pe,magic").unwrap_err().contains("magic"));
    }

    #[test]
    fn first_stage_must_be_source() {
        let stages = parse_pipeline("donut").unwrap();
        assert!(validate_pipeline_order(&stages).unwrap_err().contains("source stage"));
        let stages = parse_pipeline("b64,donut").unwrap();
        assert!(validate_pipeline_order(&stages).is_err());
    }

    #[test]
    fn source_stages_only_first() {
        let stages = parse_pipeline("pe,dll,donut").unwrap();
        assert!(validate_pipeline_order(&stages).unwrap_err().contains("must be first"));
    }

    #[test]
    fn transforms_need_pe() {
        // pic yields shellcode, not a PE: donut after pic is invalid
        let stages = parse_pipeline("pic,donut").unwrap();
        assert!(validate_pipeline_order(&stages).unwrap_err().contains("PE"));
        // two bin-producing stages in a row: second one has no PE
        let stages = parse_pipeline("pe,donut,srdi").unwrap();
        assert!(validate_pipeline_order(&stages).is_err());
        let stages = parse_pipeline("dll,srdi,pe_to_shellcode").unwrap();
        assert!(validate_pipeline_order(&stages).is_err());
    }

    #[test]
    fn sign_needs_pe_but_keeps_it() {
        let stages = parse_pipeline("pe,sign,donut").unwrap();
        assert!(validate_pipeline_order(&stages).is_ok());
        let stages = parse_pipeline("pe,donut,sign").unwrap();
        assert!(validate_pipeline_order(&stages).unwrap_err().contains("PE"));
    }

    #[test]
    fn b64_allowed_anywhere_after_source() {
        let stages = parse_pipeline("pe,donut,b64").unwrap();
        assert!(validate_pipeline_order(&stages).is_ok());
        let stages = parse_pipeline("pic,b64").unwrap();
        assert!(validate_pipeline_order(&stages).is_ok());
    }
}
