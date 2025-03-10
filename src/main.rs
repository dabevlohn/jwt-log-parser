use duckdb::{Connection, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Client request derived from log file.
#[derive(Deserialize, Serialize, Debug)]
pub struct JwtHeadRequest {
    pub timestamp: String,
    pub path: String,
    pub jwt: String,
}

/// JWT claims.
#[derive(Deserialize, Serialize, Debug)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    custom_claim: String,
    exp: u64,
}

/// Secret key for JWT token.
const SECRET: &str = "ecpkdocs";
const AUDIENCE: &str = "docportal";

/// Get logfile by HTTP-request.
async fn get_log() -> Result<String, reqwest::Error> {
    let url = "http://localhost:8000/log-sample.log";
    println!("Get log file from {}", url);
    return reqwest::get(url).await?.text().await;
}

/// Parse log file strings into JWT head requests.
fn parse_log_strings(log_text: &str) -> Result<Vec<JwtHeadRequest>, regex::Error> {
    let re = Regex::new(r"\[(.*)\]\s.HEAD\s(.*)\?jwt=(.*)\sHTTP/\d\.\d.\s\d{3}\s-")?;
    let mut requests: Vec<JwtHeadRequest> = Vec::new();

    for line in log_text.lines().filter(|line| re.is_match(line)) {
        if let Some(cap) = re.captures(&line) {
            requests.push(JwtHeadRequest {
                timestamp: cap[1].to_string(),
                path: cap[2].to_string(),
                jwt: cap[3].to_string(),
            });
        }
    }

    Ok(requests)
}

/// Validate JWT token.
fn validate_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&vec![AUDIENCE]);
    //validation.required_spec_claims = HashSet::new();
    //validation.validate_aud = false;

    let secret = jsonwebtoken::DecodingKey::from_secret(SECRET.as_bytes());
    let res = jsonwebtoken::decode::<Claims>(&token, &secret, &validation)?;
    Ok(res.claims)
}

/// Main.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;
    let now = Instant::now();

    let log = get_log().await?;

    let mut elapsed = now.elapsed();
    println!("1Gb log is downloaded. Elapsed: {:.2?}", elapsed);

    let requests = parse_log_strings(&log)?;

    elapsed = now.elapsed();
    println!("Requests are parsed. Elapsed: {:.2?}", elapsed);

    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
        r"CREATE TABLE logrecords (
              timestamp VARCHAR,
              path VARCHAR,
              userid VARCHAR
        );",
    )?;

    let mut app = conn.appender("logrecords")?;

    for req in requests {
        let claim = validate_token(&req.jwt)?;
        //let record = format!(
        //    "{} {} {} {}\n",
        //    req.timestamp, req.path, claim.sub, claim.custom_claim
        //);
        if req.path == claim.sub {
            app.append_row([req.timestamp, req.path, claim.custom_claim])?;
        }
    }

    app.flush();
    conn.execute_batch(
        r"COPY (SELECT * FROM logrecords)
                TO 'logrecords.parquet'
                (FORMAT PARQUET, COMPRESSION ZSTD);
                ",
    )?;

    elapsed = now.elapsed();
    println!(
        "Validated claims are written to the parquet file. Elapsed: {:.2?}",
        elapsed
    );

    Ok(())
}
