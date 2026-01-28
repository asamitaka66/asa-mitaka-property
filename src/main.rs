use std::collections::HashSet;
use std::sync::Mutex;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use poem::{
    endpoint::StaticFiles,
    listener::TcpListener,
    web::Data,
    EndpointExt, Request, Result, Route,
};
use poem_openapi::{
    payload::{Json, PlainText},
    Object, OpenApi, OpenApiService, SecurityScheme, Tags,
};
use poem_openapi::auth::ApiKey;

use rand::RngCore;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use surrealdb::engine::local::{Db, RocksDb};
use surrealdb::{RecordId, Surreal};

type ServerKey = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
struct AdminClaims {
    exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionClaims {
    lic_id: String,
    exp: i64,
}

#[derive(Debug, Deserialize)]
struct RecordMeta {
    #[allow(dead_code)]
    id: RecordId,
}

/// ====== LICENSE MODEL ======
#[derive(Debug, Serialize, Deserialize)]
struct LicenseRecord {
    hash: String,          // Argon2 hash of the license
    created_at: i64,       // unix ts
    expires_at: i64,       // unix ts
    revoked: bool,
    last_used_at: Option<i64>,
}

#[derive(Object)]
struct CreateLicenseRequest {
    /// Duration in seconds: 1..=315360000 (10 years)
    duration_seconds: i64,
    /// Optional note for your own tracking (not required)
    note: Option<String>,
}

#[derive(Object)]
struct CreateLicenseResponse {
    /// Plaintext license (ONLY returned once)
    license: String,
    id: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Object)]
struct LicenseListItem {
    id: String,
    created_at: i64,
    expires_at: i64,
    revoked: bool,
    last_used_at: Option<i64>,
}

#[derive(Object)]
struct LicenseListResponse {
    items: Vec<LicenseListItem>,
    total: i64,
    offset: i64,
    limit: i64,
}

#[derive(Object)]
struct VerifyLicenseRequest {
    license: String,
}

#[derive(Object)]
struct VerifyLicenseResponse {
    valid: bool,
    expires_at: Option<i64>,
    /// Optional short-lived session token (JWT) your C++ can use for other APIs
    token: Option<String>,
    reason: Option<String>,
}

#[derive(Object)]
struct RevokeResponse {
    ok: bool,
}

#[derive(Tags)]
enum Tag {
    Admin,
    License,
    Ui,
}

/// ====== ADMIN AUTH (X-Admin-Key) ======
fn check_admin(req: &Request) -> poem::Result<()> {
    let expected = std::env::var("ADMIN_KEY").unwrap_or_default();
    let got = req
        .headers()
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if expected.is_empty() || got != expected {
        Err(poem::Error::from_status(StatusCode::UNAUTHORIZED))
    } else {
        Ok(())
    }
}

/// ====== OPTIONAL BLACKLIST (if you later add sessions) ======
struct TokenBlacklist {
    tokens: HashSet<String>,
}
impl TokenBlacklist {
    fn validate(&self, value: &str) -> poem::Result<()> {
        if self.tokens.contains(value) {
            Err(poem::Error::from_status(StatusCode::CONFLICT))
        } else {
            Ok(())
        }
    }
}
lazy_static::lazy_static! {
    static ref BLACKLIST: Mutex<TokenBlacklist> = Mutex::new(TokenBlacklist {
        tokens: HashSet::new(),
    });
}

/// ====== API KEY AUTH (X-API-Key) for session JWTs (optional) ======
#[derive(SecurityScheme)]
#[oai(
    ty = "api_key",
    key_name = "X-API-Key",
    key_in = "header",
    checker = "session_checker"
)]
struct Authorizor(SessionClaims);

async fn session_checker(req: &Request, api_key: ApiKey) -> Option<SessionClaims> {
    let server_key = req.data::<ServerKey>()?;
    let claims = VerifyWithKey::<SessionClaims>::verify_with_key(api_key.key.as_str(), server_key).ok()?;

    if claims.exp < Utc::now().timestamp() {
        return None;
    }

    if (BLACKLIST.lock().ok()?.validate(api_key.key.as_str())).is_err() {
        return None;
    }

    Some(claims)
}

/// ====== LICENSE STRING GENERATOR ======
fn gen_license(len: usize) -> String {
    const ALPH: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = String::with_capacity(len);
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    for b in buf {
        out.push(ALPH[(b as usize) % ALPH.len()] as char);
    }
    out
}

fn clamp_duration_seconds(s: i64) -> i64 {
    let min = 1_i64;
    let max = 315_360_000_i64; // 10 years (365d * 10)
    s.clamp(min, max)
}

struct Api;

#[OpenApi]
impl Api {
    /// Admin: create a new license (returns plaintext once)
    #[oai(path = "/license/create", method = "post", tag = "Tag::Admin")]
    async fn create_license(
        &self,
        db: Data<&Surreal<Db>>,
        req: &Request,
        body: Json<CreateLicenseRequest>,
    ) -> Result<Json<CreateLicenseResponse>> {
        check_admin(req)?;

        let duration = clamp_duration_seconds(body.0.duration_seconds);
        let now = Utc::now().timestamp();
        let expires_at = (Utc::now() + Duration::seconds(duration)).timestamp();

        let license = gen_license(10);

        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        let hash = Argon2::default()
            .hash_password(license.as_bytes(), &salt)
            .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?
            .to_string();

        let record = LicenseRecord {
            hash,
            created_at: now,
            expires_at,
            revoked: false,
            last_used_at: None,
        };

        let created: Option<RecordMeta> = db
            .create("license")
            .content(record)
            .await
            .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;

        let id = created
            .map(|m| m.id.to_string())
            .unwrap_or_else(|| "license:unknown".to_string());

        Ok(Json(CreateLicenseResponse {
            license,
            id,
            created_at: now,
            expires_at,
        }))
    }

    /// Admin: list licenses (simple pagination)
    #[oai(path = "/license/list", method = "get", tag = "Tag::Admin")]
    async fn list_licenses(
        &self,
        db: Data<&Surreal<Db>>,
        req: &Request,
        limit: poem_openapi::param::Query<Option<i64>>,
        offset: poem_openapi::param::Query<Option<i64>>,
    ) -> Result<Json<LicenseListResponse>> {
        check_admin(req)?;

        let limit = limit.0.unwrap_or(20).clamp(1, 200);
        let offset = offset.0.unwrap_or(0).max(0);

        // Count total
        let total: Option<i64> = db
            .query("SELECT count() AS total FROM license GROUP ALL;")
            .await
            .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?
            .take(0)
            .ok();

        let total = total.unwrap_or(0);

        // Fetch page
        let q = format!(
            "SELECT id, created_at, expires_at, revoked, last_used_at
             FROM license
             ORDER BY created_at DESC
             LIMIT {} START {};",
            limit, offset
        );

        #[derive(Deserialize)]
        struct Row {
            id: RecordId,
            created_at: i64,
            expires_at: i64,
            revoked: bool,
            last_used_at: Option<i64>,
        }

        let rows: Vec<Row> = db
            .query(q)
            .await
            .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?
            .take(0)
            .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;

        let items = rows
            .into_iter()
            .map(|r| LicenseListItem {
                id: r.id.to_string(),
                created_at: r.created_at,
                expires_at: r.expires_at,
                revoked: r.revoked,
                last_used_at: r.last_used_at,
            })
            .collect();

        Ok(Json(LicenseListResponse {
            items,
            total,
            offset,
            limit,
        }))
    }

    /// Admin: revoke license by record id (example: "license:abcd123")
    #[oai(path = "/license/revoke", method = "post", tag = "Tag::Admin")]
    async fn revoke_license(
        &self,
        db: Data<&Surreal<Db>>,
        req: &Request,
        id: Json<String>,
    ) -> Result<Json<RevokeResponse>> {
        check_admin(req)?;

        let rid: RecordId = id
            .0
            .parse()
            .map_err(|_| poem::Error::from_status(StatusCode::BAD_REQUEST))?;

        // Mark revoked
        let _ = db
            .query("UPDATE $id SET revoked = true;")
            .bind(("id", rid))
            .await
            .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;

        Ok(Json(RevokeResponse { ok: true }))
    }

    /// Public: verify license (your C++ calls this)
    #[oai(path = "/license/verify", method = "post", tag = "Tag::License")]
    async fn verify_license(
        &self,
        server_key: Data<&ServerKey>,
        db: Data<&Surreal<Db>>,
        body: Json<VerifyLicenseRequest>,
    ) -> Result<Json<VerifyLicenseResponse>> {
        let lic = body.0.license.trim();
        if lic.len() < 6 || lic.len() > 64 {
            return Ok(Json(VerifyLicenseResponse {
                valid: false,
                expires_at: None,
                token: None,
                reason: Some("bad_license_format".to_string()),
            }));
        }

        // Pull a page of licenses and compare using Argon2 verify.
        // For huge scale you'd index with a pepper+hash prefix, but for most projects this is fine.
        #[derive(Deserialize)]
        struct Row {
            id: RecordId,
            hash: String,
            expires_at: i64,
            revoked: bool,
        }

        let rows: Vec<Row> = db
            .query("SELECT id, hash, expires_at, revoked FROM license WHERE revoked = false;")
            .await
            .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?
            .take(0)
            .map_err(|_| poem::Error::from_status(StatusCode::INTERNAL_SERVER_ERROR))?;

        let now = Utc::now().timestamp();

        for r in rows {
            if r.expires_at < now {
                continue;
            }

            let parsed = match PasswordHash::new(&r.hash) {
                Ok(p) => p,
                Err(_) => continue,
            };

            if Argon2::default().verify_password(lic.as_bytes(), &parsed).is_ok() {
                // update last_used_at
                let _ = db
                    .query("UPDATE $id SET last_used_at = $ts;")
                    .bind(("id", r.id.clone()))
                    .bind(("ts", now))
                    .await;

                // issue short-lived session token (5 hours)
                let exp = (Utc::now() + Duration::hours(5)).timestamp();
                let token = SessionClaims {
                    lic_id: r.id.to_string(),
                    exp,
                }
                .sign_with_key(server_key.0)
                .ok();

                return Ok(Json(VerifyLicenseResponse {
                    valid: true,
                    expires_at: Some(r.expires_at),
                    token,
                    reason: None,
                }));
            }
        }

        Ok(Json(VerifyLicenseResponse {
            valid: false,
            expires_at: None,
            token: None,
            reason: Some("invalid_or_expired".to_string()),
        }))
    }

    /// Example protected endpoint (uses X-API-Key session token)
    #[oai(path = "/test/hello", method = "get", tag = "Tag::License")]
    async fn hello(&self, auth: Authorizor) -> PlainText<String> {
        PlainText(format!("Hello license {}", auth.0.lic_id))
    }
}

fn load_server_key() -> ServerKey {
    // Stable secret across restarts
    // Set JWT_SECRET to a strong random string (32+ bytes).
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        // fallback (not recommended for production)
        "dev_secret_change_me_dev_secret_change_me_32b".to_string()
    });

    Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("bad JWT_SECRET")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(debug_assertions)]
    std::env::set_var("RUST_LOG", "info");

    tracing_subscriber::fmt::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // DB
    let db = Surreal::new::<RocksDb>("db").await?;
    db.use_ns("test").use_db("test").await?;

    // API + Swagger
    let api_service =
        OpenApiService::new(Api, "Jammy Backend", "1.0").server("http://localhost:3000/api");
    let ui = api_service.swagger_ui();

    // static dashboard
    let static_files = StaticFiles::new("./static").index_file("index.html");

    let server_key = load_server_key();

    let app = Route::new()
        .nest("/api", api_service)
        .nest("/docs", ui)
        .nest("/", static_files)
        .data(server_key)
        .data(db);

    // IMPORTANT: Set ADMIN_KEY and JWT_SECRET in env
    // Windows PowerShell:
    //   $env:ADMIN_KEY="your_admin_key"
    //   $env:JWT_SECRET="your_jwt_secret_32+_bytes"
    //   cargo run --release
    
 let port: u16 = std::env::var("PORT")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(3000);

poem::Server::new(TcpListener::bind(format!("0.0.0.0:{port}")))
    .run(app)
    .await?;


    Ok(())
}
