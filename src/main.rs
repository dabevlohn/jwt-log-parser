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
    return reqwest::get("http://localhost:8000/log-sample.log")
        .await?
        .text()
        .await;
}

/// Parse log file strings into JWT head requests.
fn parse_log_strings(log_text: &str) -> Vec<JwtHeadRequest> {
    let re = Regex::new(r"\[(.*)\]\s.HEAD\s(.*)\?jwt=(.*)\sHTTP/\d\.\d.\s\d{3}\s-").unwrap();
    let mut requests = Vec::new();

    for line in log_text.lines().filter(|line| re.is_match(line)) {
        let cap = re.captures(&line).unwrap();
        requests.push(JwtHeadRequest {
            timestamp: cap[1].to_string(),
            path: cap[2].to_string(),
            jwt: cap[3].to_string(),
        });
    }

    return requests;
}

/// Validate JWT token.
fn validate_token(token: &str) -> String {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&vec![AUDIENCE]);
    //validation.required_spec_claims = HashSet::new();
    //validation.validate_aud = false;

    let secret = jsonwebtoken::DecodingKey::from_secret(SECRET.as_bytes());
    let res = jsonwebtoken::decode::<Claims>(&token, &secret, &validation);
    format!("{:?}", res.unwrap().claims)
}

/// Main.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let log = get_log().await?;
    let requests = parse_log_strings(&log);
    for req in &requests {
        println!("{:?}", req);

        //validate_token(&req.jwt)
        //    .parse::<Claims>()
        //    .map(|claims| println!("{:?}", claims))
        //    .unwrap();
    }
    Ok(())
}
