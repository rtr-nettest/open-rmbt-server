use std::io::{self, Write};

use crate::stream::Transport;

/// True if the request target addresses the version endpoint (`/version`,
/// optionally with a query string).
pub fn matches(target: &str) -> bool {
    target == "/version" || target.starts_with("/version?")
}

/// The JSON body of `GET /version`, modelled on
/// `GET /RMBTControlServer/version` of the control server but with the
/// version only, e.g. `{"version":"v1.9.0-1-g0601658(dev)"}`.
pub fn body() -> String {
    format!(r#"{{"version":"{}"}}"#, version())
}

/// `v<version>(<branch>)`; without a known branch just `v<version>`.
fn version() -> String {
    let branch = env!("RMBTD_BRANCH");
    if branch.is_empty() {
        format!("v{}", env!("RMBTD_VERSION"))
    } else {
        format!("v{}({branch})", env!("RMBTD_VERSION"))
    }
}

/// Answer one request to `/version`.  `head` is the already-read request
/// header block; `hsts` the HSTS header line to add (empty when disabled).
/// Returns a short summary for logging.
pub fn handle(client: &mut Transport, head: &str, hsts: &str) -> io::Result<String> {
    let mut lines = head.split("\r\n");
    let method = lines.next().unwrap_or("").split(' ').next().unwrap_or("");
    // Browsers may call it cross-origin; a plain GET needs no preflight.
    let origin = lines.any(|l| l.split_once(':').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("origin")));
    let cors = if origin { "Access-Control-Allow-Origin: *\r\n" } else { "" };

    let (status, extra, body) = match method {
        "GET" => ("200 OK", "Content-Type: application/json\r\n", body()),
        _ => ("405 Method Not Allowed", "Allow: GET\r\n", String::new()),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\n\
         Connection: close\r\n\
         {hsts}{cors}{extra}\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len(),
    );
    client.write_all(resp.as_bytes())?;
    client.flush()?;
    Ok(format!("{method} /version -> {}", &status[..3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_path() {
        assert!(matches("/version"));
        assert!(matches("/version?x=1"));
        assert!(!matches("/version/"));
        assert!(!matches("/versions"));
        assert!(!matches("/RMBTControlServer/version"));
    }

    #[test]
    fn body_is_json_with_the_build_version() {
        let v: serde_json::Value = serde_json::from_str(&body()).unwrap();
        let s = v["version"].as_str().unwrap();
        assert!(s.starts_with(&format!("v{}", env!("RMBTD_VERSION"))), "{s}");
        assert_eq!(s.ends_with(')'), !env!("RMBTD_BRANCH").is_empty(), "{s}");
        assert_eq!(v.as_object().unwrap().len(), 1);
    }
}
