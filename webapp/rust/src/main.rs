use async_session::{CookieStore, SessionStore};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, request, response, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum_extra::extract::cookie::SignedCookieJar;
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use hyper::{Client, Method, Request, Uri};
use sha2::{Digest, Sha256};
use sqlx::mysql::{MySqlConnection, MySqlPool};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use tokio::sync::{Mutex, OnceCell};
use uuid::Uuid;

pub mod utils;

const DEFAULT_SESSION_ID_KEY: &str = "SESSIONID";
const DEFUALT_SESSION_EXPIRES_KEY: &str = "EXPIRES";
const DEFAULT_USER_ID_KEY: &str = "USERID";
const DEFAULT_USERNAME_KEY: &str = "USERNAME";
const FALLBACK_IMAGE: &str = "../img/NoImage.jpg";
const SLOT_SIZE: i64 = 3600;

static ONCE: OnceCell<String> = OnceCell::const_new();
static LIVESTREAM_TAGS_MODEL_CACHE: LazyLock<Mutex<HashMap<i64, Vec<LivestreamTagModel>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static USER_MODEL_CACHE: LazyLock<Mutex<HashMap<i64, UserModel>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static USER_NAME_ID_CACHE: LazyLock<Mutex<HashMap<String, i64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static THEME_MODEL_CACHE: LazyLock<Mutex<HashMap<i64, ThemeModel>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LIVESTREAM_MODEL_CACHE: LazyLock<Mutex<HashMap<i64, LivestreamModel>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static TAG_MODEL_CACHE: LazyLock<Mutex<HashMap<i64, TagModel>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLx error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("async-session error: {0}")]
    AsyncSession(#[from] async_session::Error),
    #[error("hyper error: {0}")]
    HyperClientError(#[from] hyper::Error),
    #[error("{0}")]
    BadRequest(Cow<'static, str>),
    #[error("session error")]
    SessionError,
    #[error("unauthorized: {0}")]
    Unauthorized(Cow<'static, str>),
    #[error("forbidden: {0}")]
    Forbidden(Cow<'static, str>),
    #[error("not found: {0}")]
    NotFound(Cow<'static, str>),
    #[error("{0}")]
    InternalServerError(String),
}
impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        #[derive(Debug, serde::Serialize)]
        struct ErrorResponse {
            error: String,
        }

        let status = match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) | Self::SessionError => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Io(_)
            | Self::Sqlx(_)
            | Self::Bcrypt(_)
            | Self::AsyncSession(_)
            | Self::HyperClientError(_)
            | Self::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        tracing::error!("{}", self);
        (
            status,
            axum::Json(ErrorResponse {
                error: format!("{}", self),
            }),
        )
            .into_response()
    }
}

#[derive(Clone)]
struct AppState {
    pool: MySqlPool,
    key: axum_extra::extract::cookie::Key,
    powerdns_subdomain_address: Arc<String>,
    powerdns_address: Arc<String>,
    username_usermodel_cache: Arc<Mutex<HashMap<String, UserModel>>>,
    iconhash_cache: Arc<Mutex<HashMap<i64, String>>>,
}
impl axum::extract::FromRef<AppState> for axum_extra::extract::cookie::Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.clone()
    }
}

// snippet for pprof
// cargo add flate2
// cargo add pprof -F protobuf-codec
//
use axum::response::Response;
use flate2::write::GzEncoder;
use flate2::Compression;
use pprof::protos::Message;
use pprof::ProfilerGuardBuilder;
use tokio::time::sleep;
use tokio::time::Duration;

#[derive(serde::Deserialize)]
pub struct ProfileParams {
    pub seconds: Option<u64>,
}

pub async fn generate_profile(duration: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let guard = ProfilerGuardBuilder::default()
        .frequency(200)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()?;

    sleep(Duration::from_secs(duration)).await;

    let profile = guard.report().build()?.pprof()?;

    let mut body = Vec::new();
    let mut encoder = GzEncoder::new(&mut body, Compression::default());

    profile.write_to_writer(&mut encoder)?;
    encoder.finish()?;

    Ok(body)
}
async fn pprof_profile_axum(Query(params): Query<ProfileParams>) -> Result<Response, StatusCode> {
    let duration = params.seconds.unwrap_or(30);
    match generate_profile(duration).await {
        Ok(body) => Ok((
            StatusCode::OK,
            [("Content-Type", "application/octet-stream")],
            [(
                "Content-Disposition",
                "attachment; filename=\"profile.pb.gz\"",
            )],
            body,
        )
            .into_response()),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[derive(Debug, serde::Serialize)]
struct InitializeResponse {
    language: &'static str,
}

fn build_mysql_options() -> sqlx::mysql::MySqlConnectOptions {
    let mut options = sqlx::mysql::MySqlConnectOptions::new()
        .host("127.0.0.1")
        .port(3306)
        .username("isucon")
        .password("isucon")
        .database("isupipe");
    if let Ok(host) = std::env::var("ISUCON13_MYSQL_DIALCONFIG_ADDRESS") {
        options = options.host(&host);
    }
    if let Some(port) = std::env::var("ISUCON13_MYSQL_DIALCONFIG_PORT")
        .ok()
        .and_then(|port_str| port_str.parse().ok())
    {
        options = options.port(port);
    }
    if let Ok(user) = std::env::var("ISUCON13_MYSQL_DIALCONFIG_USER") {
        options = options.username(&user);
    }
    if let Ok(password) = std::env::var("ISUCON13_MYSQL_DIALCONFIG_PASSWORD") {
        options = options.password(&password);
    }
    if let Ok(database) = std::env::var("ISUCON13_MYSQL_DIALCONFIG_DATABASE") {
        options = options.database(&database);
    }
    options
}

async fn initialize_handler(
    State(AppState {
        pool,
        powerdns_address,
        username_usermodel_cache,
        iconhash_cache,
        ..
    }): State<AppState>,
) -> Result<axum::Json<InitializeResponse>, Error> {
    let client = Client::new();
    let url = format!(
        "http://{}:8080/api/internal/arecord/reset",
        powerdns_address
    );
    let a_req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .body(Body::from(""))
        .unwrap();
    let res = client.request(a_req).await?;
    if res.status() != StatusCode::CREATED {
        return Err(Error::InternalServerError(format!(
            "fail to reset dns records",
        )));
    }

    let output = tokio::process::Command::new("../sql/init.sh")
        .output()
        .await?;
    if !output.status.success() {
        return Err(Error::InternalServerError(format!(
            "init.sh failed with stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    //DBのインデックス
    let index_sqls = vec![
        "CREATE INDEX livestream_id_idx ON livestream_tags (livestream_id);",
        "CREATE INDEX user_id_idx ON icons (user_id);",
        "CREATE INDEX user_id_idx ON themes (user_id);",
        "CREATE INDEX user_id_idx ON livestreams (user_id);",
        "CREATE INDEX livestream_id_idx ON livecomments (livestream_id)",
        "CREATE INDEX user_id_livestream_id_idx ON ng_words (user_id, livestream_id)",
        "CREATE INDEX livestream_id_idx ON reactions (livestream_id)",
        "CREATE INDEX start_idx ON reservation_slots (start_at)",
        "CREATE INDEX time_idx ON reservation_slots (start_at, end_at)",
    ];
    //cacheのクリア
    {
        let mut username_usermodel_cache = username_usermodel_cache.lock().await;
        username_usermodel_cache.clear();
        let mut iconhash_cache = iconhash_cache.lock().await;
        iconhash_cache.clear();
        let mut tag_cache = LIVESTREAM_TAGS_MODEL_CACHE.lock().await;
        tag_cache.clear();
        let mut user_model_cache = USER_MODEL_CACHE.lock().await;
        user_model_cache.clear();
        let mut theme_model_cache = THEME_MODEL_CACHE.lock().await;
        theme_model_cache.clear();
        let mut tag_model_cache = TAG_MODEL_CACHE.lock().await;
        tag_model_cache.clear();
        let mut livestream_model_cache = LIVESTREAM_MODEL_CACHE.lock().await;
        livestream_model_cache.clear();
    }
    {
        let mut cache = USER_NAME_ID_CACHE.lock().await;
        cache.clear();
    }

    for sql in &index_sqls {
        if let Err(err) = utils::db::create_index_if_not_exists(&pool, sql).await {
            return Err(Error::Sqlx(err));
        }
    }
    //測定開始
    let client = Client::new();
    let _res = client
        .get(Uri::from_static(
            "http://isucon-o11y:9000/api/group/collect",
        ))
        .await;

    Ok(axum::Json(InitializeResponse { language: "rust" }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info,tower_http=debug,axum::rejection=trace");
    }
    tracing_subscriber::fmt::init();

    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .connect_with(build_mysql_options())
        .await
        .expect("failed to connect db");

    const DEFAULT_SECRET: &[u8] = b"isucon13_session_cookiestore_defaultsecret";
    let secret = if let Ok(secret) = std::env::var("ISUCON13_SESSION_SECRETKEY") {
        secret.into_bytes()
    } else {
        DEFAULT_SECRET.to_owned()
    };

    const POWERDNS_SUBDOMAIN_ADDRESS_ENV_KEY: &str = "ISUCON13_POWERDNS_SUBDOMAIN_ADDRESS";
    let Ok(powerdns_subdomain_address) = std::env::var(POWERDNS_SUBDOMAIN_ADDRESS_ENV_KEY) else {
        panic!(
            "environ {} must be provided",
            POWERDNS_SUBDOMAIN_ADDRESS_ENV_KEY
        );
    };
    const POWERDNS_ADDRESS: &str = "ISUCON13_POWERDNS_ADDRESS";
    let Ok(powerdns_address) = std::env::var("ISUCON13_POWERDNS_ADDRESS") else {
        panic!("environ {} must be provided", POWERDNS_ADDRESS);
    };

    let app = axum::Router::new()
        // 初期化
        .route("/api/initialize", axum::routing::post(initialize_handler))
        //プロファイラ
        .route(
            "/debug/pprof/profile",
            axum::routing::get(pprof_profile_axum),
        )
        // top
        .route("/api/tag", axum::routing::get(get_tag_handler))
        .route(
            "/api/user/:username/theme",
            axum::routing::get(get_streamer_theme_handler),
        )
        // livestream
        // reserve livestream
        .route(
            "/api/livestream/reservation",
            axum::routing::post(reserve_livestream_handler),
        )
        // list livestream
        .route(
            "/api/livestream/search",
            axum::routing::get(search_livestreams_handler),
        )
        .route(
            "/api/livestream",
            axum::routing::get(get_my_livestreams_handler),
        )
        .route(
            "/api/user/:username/livestream",
            axum::routing::get(get_user_livestreams_handler),
        )
        // get livestream
        .route(
            "/api/livestream/:livestream_id",
            axum::routing::get(get_livestream_handler),
        )
        // get polling livecomment timeline
        // ライブコメント投稿
        .route(
            "/api/livestream/:livestream_id/livecomment",
            axum::routing::get(get_livecomments_handler).post(post_livecomment_handler),
        )
        .route(
            "/api/livestream/:livestream_id/reaction",
            axum::routing::get(get_reactions_handler).post(post_reaction_handler),
        )
        // (配信者向け)ライブコメントの報告一覧取得API
        .route(
            "/api/livestream/:livestream_id/report",
            axum::routing::get(get_livecomment_reports_handler),
        )
        .route(
            "/api/livestream/:livestream_id/ngwords",
            axum::routing::get(get_ngwords),
        )
        // ライブコメント報告
        .route(
            "/api/livestream/:livestream_id/livecomment/:livecomment_id/report",
            axum::routing::post(report_livecomment_handler),
        )
        // 配信者によるモデレーション (NGワード登録)
        .route(
            "/api/livestream/:livestream_id/moderate",
            axum::routing::post(moderate_handler),
        )
        // livestream_viewersにINSERTするため必要
        // ユーザ視聴開始 (viewer)
        .route(
            "/api/livestream/:livestream_id/enter",
            axum::routing::post(enter_livestream_handler),
        )
        // ユーザ視聴終了 (viewer)
        .route(
            "/api/livestream/:livestream_id/exit",
            axum::routing::delete(exit_livestream_handler),
        )
        // user
        .route("/api/register", axum::routing::post(register_handler))
        .route(
            "/api/internal/arecord/:username",
            axum::routing::post(arecord_handler),
        )
        .route(
            "/api/internal/arecord/reset",
            axum::routing::post(reset_dns_handler),
        )
        .route("/api/login", axum::routing::post(login_handler))
        .route("/api/user/me", axum::routing::get(get_me_handler))
        // フロントエンドで、配信予約のコラボレーターを指定する際に必要
        .route("/api/user/:username", axum::routing::get(get_user_handler))
        .route(
            "/api/user/:username/statistics",
            axum::routing::get(get_user_statistics_handler),
        )
        .route(
            "/api/user/:username/icon",
            axum::routing::get(get_icon_handler),
        )
        .route("/api/icon", axum::routing::post(post_icon_handler))
        // stats
        // ライブ配信統計情報
        .route(
            "/api/livestream/:livestream_id/statistics",
            axum::routing::get(get_livestream_statistics_handler),
        )
        // 課金情報
        .route("/api/payment", axum::routing::get(get_payment_result))
        .with_state(AppState {
            pool,
            key: axum_extra::extract::cookie::Key::derive_from(&secret),
            powerdns_subdomain_address: Arc::new(powerdns_subdomain_address),
            powerdns_address: Arc::new(powerdns_address),
            username_usermodel_cache: Arc::new(Mutex::new(HashMap::new())),
            iconhash_cache: Arc::new(Mutex::new(HashMap::new())),
        })
        .layer(tower_http::trace::TraceLayer::new_for_http());

    // HTTPサーバ起動
    if let Some(tcp_listener) = listenfd::ListenFd::from_env().take_tcp_listener(0)? {
        axum::Server::from_tcp(tcp_listener)?
    } else {
        const LISTEN_PORT: u16 = 8080;
        axum::Server::bind(&std::net::SocketAddr::from(([0, 0, 0, 0], LISTEN_PORT)))
    }
    .serve(app.into_make_service())
    .await?;

    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct Tag {
    id: i64,
    name: String,
}

#[derive(Debug, sqlx::FromRow, Clone)]
struct TagModel {
    id: i64,
    name: String,
}

#[derive(Debug, serde::Serialize)]
struct TagsResponse {
    tags: Vec<Tag>,
}

async fn get_tag_handler(
    State(AppState { pool, .. }): State<AppState>,
) -> Result<axum::Json<TagsResponse>, Error> {
    let mut tx = pool.begin().await?;

    let tag_models: Vec<TagModel> = sqlx::query_as("SELECT * FROM tags")
        .fetch_all(&mut *tx)
        .await?;

    tx.commit().await?;

    let tags = tag_models
        .into_iter()
        .map(|tag| Tag {
            id: tag.id,
            name: tag.name,
        })
        .collect();
    Ok(axum::Json(TagsResponse { tags }))
}

async fn get_theme_model(tx: &mut MySqlConnection, user_id: i64) -> sqlx::Result<ThemeModel> {
    {
        let cache = THEME_MODEL_CACHE.lock().await;
        if let Some(theme) = cache.get(&user_id) {
            return Ok(theme.clone());
        }
    }
    let theme: ThemeModel = sqlx::query_as("SELECT * FROM themes WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

    {
        let mut cache = THEME_MODEL_CACHE.lock().await;
        cache.insert(user_id, theme.clone());
    }
    Ok(theme)
}

// 配信者のテーマ取得API
// GET /api/user/:username/theme
async fn get_streamer_theme_handler(
    State(AppState { pool, .. }): State<AppState>,
    jar: SignedCookieJar,
    Path((username,)): Path<(String,)>,
) -> Result<axum::Json<Theme>, Error> {
    verify_user_session(&jar).await?;

    let mut tx = pool.begin().await?;

    let user_id: i64 = get_user_id(&mut *tx, username).await?;

    let theme_model = get_theme_model(&mut *tx, user_id).await?;

    tx.commit().await?;

    Ok(axum::Json(Theme {
        id: theme_model.id,
        dark_mode: theme_model.dark_mode,
    }))
}

#[derive(Debug, serde::Deserialize)]
struct ReserveLivestreamRequest {
    tags: Vec<i64>,
    title: String,
    description: String,
    playlist_url: String,
    thumbnail_url: String,
    start_at: i64,
    end_at: i64,
}

#[derive(Debug, sqlx::FromRow, Clone)]
struct LivestreamModel {
    id: i64,
    user_id: i64,
    title: String,
    description: String,
    playlist_url: String,
    thumbnail_url: String,
    start_at: i64,
    end_at: i64,
}

#[derive(Debug, serde::Serialize)]
struct Livestream {
    id: i64,
    owner: User,
    title: String,
    description: String,
    playlist_url: String,
    thumbnail_url: String,
    tags: Vec<Tag>,
    start_at: i64,
    end_at: i64,
}

#[derive(Debug, sqlx::FromRow, Clone)]
struct LivestreamTagModel {
    #[allow(unused)]
    id: i64,
    livestream_id: i64,
    tag_id: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct ReservationSlotModel {
    #[allow(unused)]
    id: i64,
    slot: i64,
    start_at: i64,
    end_at: i64,
}

async fn reserve_livestream_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    axum::Json(req): axum::Json<ReserveLivestreamRequest>,
) -> Result<(StatusCode, axum::Json<Livestream>), Error> {
    verify_user_session(&jar).await?;

    if req.tags.iter().any(|&tag_id| tag_id > 103) {
        tracing::error!("unexpected tags: {:?}", req);
    }

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    // 2023/11/25 10:00からの１年間の期間内であるかチェック
    let term_start_at = Utc.from_utc_datetime(
        &NaiveDate::from_ymd_opt(2023, 11, 25)
            .unwrap()
            .and_hms_opt(1, 0, 0)
            .unwrap(),
    );
    let term_end_at = Utc.from_utc_datetime(
        &NaiveDate::from_ymd_opt(2024, 11, 25)
            .unwrap()
            .and_hms_opt(1, 0, 0)
            .unwrap(),
    );
    let reserve_start_at = DateTime::from_timestamp(req.start_at, 0).unwrap();
    let reserve_end_at = DateTime::from_timestamp(req.end_at, 0).unwrap();
    if reserve_start_at >= term_end_at || reserve_end_at <= term_start_at {
        return Err(Error::BadRequest("bad reservation time range".into()));
    }

    // 予約枠をみて、予約が可能か調べる
    // NOTE: 並列な予約のoverbooking防止にFOR UPDATEが必要
    let slots: Vec<ReservationSlotModel> = sqlx::query_as(
        "SELECT * FROM reservation_slots WHERE start_at >= ? AND start_at <= ? FOR UPDATE",
    )
    .bind(req.start_at)
    .bind(req.end_at - SLOT_SIZE)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        tracing::warn!("予約枠一覧取得でエラー発生: {e:?}");
        e
    })?;
    for slot in slots {
        let count: i64 = sqlx::query_scalar(
            "SELECT slot FROM reservation_slots WHERE start_at = ? AND end_at = ?",
        )
        .bind(slot.start_at)
        .bind(slot.end_at)
        .fetch_one(&mut *tx)
        .await?;
        tracing::info!(
            "{} ~ {}予約枠の残数 = {}",
            slot.start_at,
            slot.end_at,
            slot.slot
        );
        if count < 1 {
            return Err(Error::BadRequest(
                format!(
                    "予約期間 {} ~ {}に対して、予約区間 {} ~ {}が予約できません",
                    term_start_at.timestamp(),
                    term_end_at.timestamp(),
                    req.start_at,
                    req.end_at
                )
                .into(),
            ));
        }
    }

    sqlx::query(
        "UPDATE reservation_slots SET slot = slot - 1 WHERE start_at >= ? AND start_at <= ?",
    )
    .bind(req.start_at)
    .bind(req.end_at - SLOT_SIZE)
    .execute(&mut *tx)
    .await?;

    let rs = sqlx::query("INSERT INTO livestreams (user_id, title, description, playlist_url, thumbnail_url, start_at, end_at) VALUES(?, ?, ?, ?, ?, ?, ?)")
        .bind(user_id)
        .bind(&req.title)
        .bind(&req.description)
        .bind(&req.playlist_url)
        .bind(&req.thumbnail_url)
        .bind(req.start_at)
        .bind(req.end_at)
        .execute(&mut *tx)
        .await?;
    let livestream_id = rs.last_insert_id() as i64;

    // タグ追加
    for tag_id in req.tags {
        sqlx::query("INSERT INTO livestream_tags (livestream_id, tag_id) VALUES (?, ?)")
            .bind(livestream_id)
            .bind(tag_id)
            .execute(&mut *tx)
            .await?;
    }

    let livestream = fill_livestream_response(
        &mut tx,
        &iconhash_cache,
        LivestreamModel {
            id: livestream_id,
            user_id,
            title: req.title,
            description: req.description,
            playlist_url: req.playlist_url,
            thumbnail_url: req.thumbnail_url,
            start_at: req.start_at,
            end_at: req.end_at,
        },
    )
    .await?;

    tx.commit().await?;

    Ok((StatusCode::CREATED, axum::Json(livestream)))
}

#[derive(Debug, serde::Deserialize)]
struct SearchLivestreamsQuery {
    #[serde(default)]
    tag: String,
    #[serde(default)]
    limit: String,
}

async fn search_livestreams_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    Query(SearchLivestreamsQuery {
        tag: key_tag_name,
        limit,
    }): Query<SearchLivestreamsQuery>,
) -> Result<axum::Json<Vec<Livestream>>, Error> {
    let mut tx = pool.begin().await?;

    let livestream_models: Vec<LivestreamModel> = if key_tag_name.is_empty() {
        // 検索条件なし
        let mut query = "SELECT * FROM livestreams ORDER BY id DESC".to_owned();
        if !limit.is_empty() {
            let limit: i64 = limit
                .parse()
                .map_err(|_| Error::BadRequest("failed to parse limit".into()))?;
            query = format!("{} LIMIT {}", query, limit);
        }
        sqlx::query_as(&query).fetch_all(&mut *tx).await?
    } else {
        // タグによる取得
        let tag_id_list: Vec<i64> = sqlx::query_scalar("SELECT id FROM tags WHERE name = ?")
            .bind(key_tag_name)
            .fetch_all(&mut *tx)
            .await?;

        let mut query_builder = sqlx::query_builder::QueryBuilder::new(
            "SELECT * FROM livestream_tags WHERE tag_id IN (",
        );
        let mut separated = query_builder.separated(", ");
        for tag_id in tag_id_list {
            separated.push_bind(tag_id);
        }
        separated.push_unseparated(") ORDER BY livestream_id DESC");
        let key_tagged_livestreams: Vec<LivestreamTagModel> =
            query_builder.build_query_as().fetch_all(&mut *tx).await?;

        let mut livestream_models = Vec::new();
        for key_tagged_livestream in key_tagged_livestreams {
            let ls = get_livestream_model(&mut *tx, key_tagged_livestream.livestream_id).await?;

            livestream_models.push(ls);
        }
        livestream_models
    };

    let mut livestreams = Vec::with_capacity(livestream_models.len());
    for livestream_model in livestream_models {
        let livestream =
            fill_livestream_response(&mut tx, &iconhash_cache, livestream_model).await?;
        livestreams.push(livestream);
    }

    tx.commit().await?;

    Ok(axum::Json(livestreams))
}

async fn get_my_livestreams_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
) -> Result<axum::Json<Vec<Livestream>>, Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    let livestream_models: Vec<LivestreamModel> =
        sqlx::query_as("SELECT * FROM livestreams WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&mut *tx)
            .await?;
    let mut livestreams = Vec::with_capacity(livestream_models.len());
    for livestream_model in livestream_models {
        let livestream =
            fill_livestream_response(&mut tx, &iconhash_cache, livestream_model).await?;
        livestreams.push(livestream);
    }

    tx.commit().await?;

    Ok(axum::Json(livestreams))
}

async fn get_user_livestreams_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    Path((username,)): Path<(String,)>,
) -> Result<axum::Json<Vec<Livestream>>, Error> {
    verify_user_session(&jar).await?;

    let mut tx = pool.begin().await?;

    let user = get_user_model_from_name(&mut *&mut tx, username).await?;

    let livestream_models: Vec<LivestreamModel> =
        sqlx::query_as("SELECT * FROM livestreams WHERE user_id = ?")
            .bind(user.id)
            .fetch_all(&mut *tx)
            .await?;
    let mut livestreams = Vec::with_capacity(livestream_models.len());
    for livestream_model in livestream_models {
        let livestream =
            fill_livestream_response(&mut tx, &iconhash_cache, livestream_model).await?;
        livestreams.push(livestream);
    }

    tx.commit().await?;

    Ok(axum::Json(livestreams))
}

// viewerテーブルの廃止
async fn enter_livestream_handler(
    State(AppState { pool, .. }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
) -> Result<(), Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    let created_at = Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO livestream_viewers_history (user_id, livestream_id, created_at) VALUES(?, ?, ?)",
    )
    .bind(user_id)
    .bind(livestream_id)
    .bind(created_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(())
}

async fn exit_livestream_handler(
    State(AppState { pool, .. }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
) -> Result<(), Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM livestream_viewers_history WHERE user_id = ? AND livestream_id = ?")
        .bind(user_id)
        .bind(livestream_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(())
}

async fn get_livestream_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
) -> Result<axum::Json<Livestream>, Error> {
    verify_user_session(&jar).await?;

    let mut tx = pool.begin().await?;

    let livestream_model = get_livestream_model(&mut *tx, livestream_id).await?;

    let livestream = fill_livestream_response(&mut tx, &iconhash_cache, livestream_model).await?;

    tx.commit().await?;

    Ok(axum::Json(livestream))
}

async fn get_livecomment_reports_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
) -> Result<axum::Json<Vec<LivecommentReport>>, Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    let livestream_model = get_livestream_model(&mut *tx, livestream_id).await?;

    if livestream_model.user_id != user_id {
        return Err(Error::Forbidden(
            "can't get other streamer's livecomment reports".into(),
        ));
    }

    let report_models: Vec<LivecommentReportModel> =
        sqlx::query_as("SELECT * FROM livecomment_reports WHERE livestream_id = ?")
            .bind(livestream_id)
            .fetch_all(&mut *tx)
            .await?;

    let mut reports = Vec::with_capacity(report_models.len());
    for report_model in report_models {
        let report =
            fill_livecomment_report_response(&mut tx, &iconhash_cache, report_model).await?;
        reports.push(report);
    }

    tx.commit().await?;

    Ok(axum::Json(reports))
}

async fn get_livestream_tags(
    tx: &mut MySqlConnection,
    livestream_id: i64,
) -> sqlx::Result<Vec<LivestreamTagModel>> {
    {
        let cache = LIVESTREAM_TAGS_MODEL_CACHE.lock().await;
        if let Some(tag) = cache.get(&livestream_id) {
            return Ok(tag.clone());
        }
    }
    let livestream_tag_models: Vec<LivestreamTagModel> =
        sqlx::query_as("SELECT * FROM livestream_tags WHERE livestream_id = ?")
            .bind(livestream_id)
            .fetch_all(&mut *tx)
            .await?;

    {
        let mut cache = LIVESTREAM_TAGS_MODEL_CACHE.lock().await;
        cache.insert(livestream_id, livestream_tag_models.to_vec());
    }
    Ok(livestream_tag_models)
}

async fn get_user_model(tx: &mut MySqlConnection, user_id: i64) -> sqlx::Result<UserModel> {
    {
        let cache = USER_MODEL_CACHE.lock().await;
        if let Some(user) = cache.get(&user_id) {
            return Ok(user.clone());
        }
    }
    let user: UserModel = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

    {
        let mut cache = USER_MODEL_CACHE.lock().await;
        cache.insert(user_id, user.clone());
    }
    Ok(user)
}
async fn get_user_id(tx: &mut MySqlConnection, username: String) -> sqlx::Result<i64> {
    {
        let cache = USER_NAME_ID_CACHE.lock().await;
        if let Some(id) = cache.get(&username) {
            return Ok(*id);
        }
    }
    let user: UserModel = sqlx::query_as("SELECT * FROM users WHERE name = ?")
        .bind(&username)
        .fetch_one(&mut *tx)
        .await?;

    {
        let mut cache = USER_NAME_ID_CACHE.lock().await;
        cache.insert(username, user.id);
    }
    Ok(user.id)
}

async fn get_tag_model(tx: &mut MySqlConnection, tag_id: i64) -> sqlx::Result<TagModel> {
    {
        let cache = TAG_MODEL_CACHE.lock().await;
        if let Some(tag) = cache.get(&tag_id) {
            return Ok(tag.clone());
        }
    }
    let tag: TagModel = sqlx::query_as("SELECT * FROM tags WHERE id = ?")
        .bind(tag_id)
        .fetch_one(&mut *tx)
        .await?;

    {
        let mut cache = TAG_MODEL_CACHE.lock().await;
        cache.insert(tag_id, tag.clone());
    }
    Ok(tag)
}

async fn fill_livestream_response(
    tx: &mut MySqlConnection,
    iconhash_cache: &Arc<Mutex<HashMap<i64, String>>>,
    livestream_model: LivestreamModel,
) -> sqlx::Result<Livestream> {
    let owner_model = get_user_model(&mut *tx, livestream_model.user_id).await?;
    let owner = fill_user_response(tx, iconhash_cache, owner_model).await?;

    let livestream_tag_models = get_livestream_tags(&mut *tx, livestream_model.id).await?;

    let mut tags = Vec::with_capacity(livestream_tag_models.len());
    for livestream_tag_model in livestream_tag_models {
        let tag_model = get_tag_model(&mut *tx, livestream_tag_model.tag_id).await?;
        tags.push(Tag {
            id: tag_model.id,
            name: tag_model.name,
        });
    }

    Ok(Livestream {
        id: livestream_model.id,
        owner,
        title: livestream_model.title,
        tags,
        description: livestream_model.description,
        playlist_url: livestream_model.playlist_url,
        thumbnail_url: livestream_model.thumbnail_url,
        start_at: livestream_model.start_at,
        end_at: livestream_model.end_at,
    })
}

#[derive(Debug, serde::Deserialize)]
struct PostLivecommentRequest {
    comment: String,
    tip: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct LivecommentModel {
    id: i64,
    user_id: i64,
    livestream_id: i64,
    comment: String,
    tip: i64,
    created_at: i64,
}

#[derive(Debug, serde::Serialize)]
struct Livecomment {
    id: i64,
    user: User,
    livestream: Livestream,
    comment: String,
    tip: i64,
    created_at: i64,
}

#[derive(Debug, serde::Serialize)]
struct LivecommentReport {
    id: i64,
    reporter: User,
    livecomment: Livecomment,
    created_at: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct LivecommentReportModel {
    id: i64,
    user_id: i64,
    #[allow(unused)]
    livestream_id: i64,
    livecomment_id: i64,
    created_at: i64,
}

#[derive(Debug, serde::Deserialize)]
struct ModerateRequest {
    ng_word: String,
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
struct NgWord {
    id: i64,
    user_id: i64,
    livestream_id: i64,
    word: String,
    #[sqlx(default)]
    created_at: i64,
}

#[derive(Debug, serde::Deserialize)]
struct GetLivecommentsQuery {
    #[serde(default)]
    limit: String,
}

async fn get_livecomments_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
    Query(GetLivecommentsQuery { limit }): Query<GetLivecommentsQuery>,
) -> Result<axum::Json<Vec<Livecomment>>, Error> {
    verify_user_session(&jar).await?;

    let mut tx = pool.begin().await?;

    let mut query =
        "SELECT * FROM livecomments WHERE livestream_id = ? ORDER BY created_at DESC".to_owned();
    if !limit.is_empty() {
        let limit: i64 = limit.parse().map_err(|_| Error::BadRequest("".into()))?;
        query = format!("{} LIMIT {}", query, limit);
    }

    let livecomment_models: Vec<LivecommentModel> = sqlx::query_as(&query)
        .bind(livestream_id)
        .fetch_all(&mut *tx)
        .await?;

    let mut livecomments = Vec::with_capacity(livecomment_models.len());
    for livecomment_model in livecomment_models {
        let livecomment =
            fill_livecomment_response(&mut tx, &iconhash_cache, livecomment_model).await?;
        livecomments.push(livecomment);
    }

    tx.commit().await?;

    Ok(axum::Json(livecomments))
}

async fn get_ngwords(
    State(AppState { pool, .. }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
) -> Result<axum::Json<Vec<NgWord>>, Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    let ng_words: Vec<NgWord> = sqlx::query_as(
        "SELECT * FROM ng_words WHERE user_id = ? AND livestream_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .bind(livestream_id)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(axum::Json(ng_words))
}

async fn post_livecomment_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
    axum::Json(req): axum::Json<PostLivecommentRequest>,
) -> Result<(StatusCode, axum::Json<Livecomment>), Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    let livestream_model = get_livestream_model(&mut *tx, livestream_id).await?;

    // スパム判定
    let ngwords: Vec<NgWord> =
        sqlx::query_as("SELECT id, user_id, livestream_id, word FROM ng_words WHERE user_id = ? AND livestream_id = ?")
            .bind(livestream_model.user_id)
            .bind(livestream_model.id)
            .fetch_all(&mut *tx)
            .await?;

    for ngword in &ngwords {
        if req.comment.contains(&ngword.word) {
            return Err(Error::BadRequest(
                "このコメントがスパム判定されました".into(),
            ));
        }
    }

    let now = Utc::now().timestamp();

    let rs = sqlx::query(
        "INSERT INTO livecomments (user_id, livestream_id, comment, tip, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(livestream_id)
    .bind(&req.comment)
    .bind(req.tip)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let livecomment_id = rs.last_insert_id() as i64;

    let livecomment = fill_livecomment_response(
        &mut tx,
        &iconhash_cache,
        LivecommentModel {
            id: livecomment_id,
            user_id,
            livestream_id,
            comment: req.comment,
            tip: req.tip,
            created_at: now,
        },
    )
    .await?;

    tx.commit().await?;

    Ok((StatusCode::CREATED, axum::Json(livecomment)))
}

async fn report_livecomment_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id, livecomment_id)): Path<(i64, i64)>,
) -> Result<(StatusCode, axum::Json<LivecommentReport>), Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    let now = Utc::now().timestamp();
    let rs = sqlx::query(
        "INSERT INTO livecomment_reports(user_id, livestream_id, livecomment_id, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(livestream_id)
    .bind(livecomment_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let report_id = rs.last_insert_id() as i64;

    let report = fill_livecomment_report_response(
        &mut tx,
        &iconhash_cache,
        LivecommentReportModel {
            id: report_id,
            user_id,
            livestream_id,
            livecomment_id,
            created_at: now,
        },
    )
    .await?;

    tx.commit().await?;

    Ok((StatusCode::CREATED, axum::Json(report)))
}

#[derive(Debug, serde::Serialize)]
struct ModerateResponse {
    word_id: i64,
}

// NGワードを登録
async fn moderate_handler(
    State(AppState { pool, .. }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
    axum::Json(req): axum::Json<ModerateRequest>,
) -> Result<(StatusCode, axum::Json<ModerateResponse>), Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    // 配信者自身の配信に対するmoderateなのかを検証
    let owned_livestreams: Vec<LivestreamModel> =
        sqlx::query_as("SELECT * FROM livestreams WHERE id = ? AND user_id = ?")
            .bind(livestream_id)
            .bind(user_id)
            .fetch_all(&mut *tx)
            .await?;
    if owned_livestreams.is_empty() {
        return Err(Error::BadRequest(
            "A streamer can't moderate livestreams that other streamers own".into(),
        ));
    }

    let created_at = Utc::now().timestamp();
    let rs = sqlx::query(
        "INSERT INTO ng_words(user_id, livestream_id, word, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(livestream_id)
    .bind(req.ng_word.clone())
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
    let word_id = rs.last_insert_id() as i64;

    let query = r#"
    DELETE FROM livecomments
    WHERE livestream_id = ? AND
    comment LIKE CONCAT('%', ?, '%')
    "#;
    sqlx::query(query)
        .bind(livestream_id)
        .bind(req.ng_word)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        axum::Json(ModerateResponse { word_id }),
    ))
}

async fn get_livestream_model(
    tx: &mut MySqlConnection,
    livestream_id: i64,
) -> sqlx::Result<LivestreamModel> {
    {
        let cache = LIVESTREAM_MODEL_CACHE.lock().await;
        if let Some(livestream) = cache.get(&livestream_id) {
            return Ok(livestream.clone());
        }
    }
    let livestream: LivestreamModel = sqlx::query_as("SELECT * FROM livestreams WHERE id = ?")
        .bind(livestream_id)
        .fetch_one(&mut *tx)
        .await?;

    {
        let mut cache = LIVESTREAM_MODEL_CACHE.lock().await;
        cache.insert(livestream_id, livestream.clone());
    }
    Ok(livestream)
}

async fn fill_livecomment_response(
    tx: &mut MySqlConnection,
    iconhash_cache: &Arc<Mutex<HashMap<i64, String>>>,
    livecomment_model: LivecommentModel,
) -> sqlx::Result<Livecomment> {
    let comment_owner_model = get_user_model(&mut *tx, livecomment_model.user_id).await?;
    let comment_owner = fill_user_response(&mut *tx, iconhash_cache, comment_owner_model).await?;

    let livestream_model = get_livestream_model(&mut *tx, livecomment_model.livestream_id).await?;
    let livestream = fill_livestream_response(&mut *tx, iconhash_cache, livestream_model).await?;

    Ok(Livecomment {
        id: livecomment_model.id,
        user: comment_owner,
        livestream,
        comment: livecomment_model.comment,
        tip: livecomment_model.tip,
        created_at: livecomment_model.created_at,
    })
}

async fn fill_livecomment_report_response(
    tx: &mut MySqlConnection,
    iconhash_cache: &Arc<Mutex<HashMap<i64, String>>>,
    report_model: LivecommentReportModel,
) -> sqlx::Result<LivecommentReport> {
    let reporter_model = get_user_model(&mut *tx, report_model.user_id).await?;
    let reporter = fill_user_response(&mut *tx, iconhash_cache, reporter_model).await?;

    let livecomment_model: LivecommentModel =
        sqlx::query_as("SELECT * FROM livecomments WHERE id = ?")
            .bind(report_model.livecomment_id)
            .fetch_one(&mut *tx)
            .await?;
    let livecomment =
        fill_livecomment_response(&mut *tx, iconhash_cache, livecomment_model).await?;

    Ok(LivecommentReport {
        id: report_model.id,
        reporter,
        livecomment,
        created_at: report_model.created_at,
    })
}

#[derive(Debug, sqlx::FromRow, Clone)]
struct ReactionModel {
    id: i64,
    emoji_name: String,
    user_id: i64,
    livestream_id: i64,
    created_at: i64,
}

#[derive(Debug, serde::Serialize)]
struct Reaction {
    id: i64,
    emoji_name: String,
    user: User,
    livestream: Livestream,
    created_at: i64,
}

#[derive(Debug, serde::Deserialize)]
struct PostReactionRequest {
    emoji_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct GetReactionsQuery {
    #[serde(default)]
    limit: String,
}

async fn get_reactions_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
    Query(GetReactionsQuery { limit }): Query<GetReactionsQuery>,
) -> Result<axum::Json<Vec<Reaction>>, Error> {
    verify_user_session(&jar).await?;

    let mut tx = pool.begin().await?;

    let mut query =
        "SELECT * FROM reactions WHERE livestream_id = ? ORDER BY created_at DESC".to_owned();
    if !limit.is_empty() {
        let limit: i64 = limit.parse().map_err(|_| Error::BadRequest("".into()))?;
        query = format!("{} LIMIT {}", query, limit);
    }

    let reaction_models: Vec<ReactionModel> = sqlx::query_as(&query)
        .bind(livestream_id)
        .fetch_all(&mut *tx)
        .await?;

    let mut reactions = Vec::with_capacity(reaction_models.len());
    for reaction_model in reaction_models {
        let reaction = fill_reaction_response(&mut tx, &iconhash_cache, reaction_model).await?;
        reactions.push(reaction);
    }

    tx.commit().await?;

    Ok(axum::Json(reactions))
}

async fn post_reaction_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
    axum::Json(req): axum::Json<PostReactionRequest>,
) -> Result<(StatusCode, axum::Json<Reaction>), Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    let created_at = Utc::now().timestamp();
    let result =
        sqlx::query("INSERT INTO reactions (user_id, livestream_id, emoji_name, created_at) VALUES (?, ?, ?, ?)")
            .bind(user_id)
            .bind(livestream_id)
            .bind(&req.emoji_name)
            .bind(created_at)
            .execute(&mut *tx)
            .await?;
    let reaction_id = result.last_insert_id() as i64;

    let reaction = fill_reaction_response(
        &mut tx,
        &iconhash_cache,
        ReactionModel {
            id: reaction_id,
            user_id,
            livestream_id,
            emoji_name: req.emoji_name,
            created_at,
        },
    )
    .await?;

    tx.commit().await?;

    Ok((StatusCode::CREATED, axum::Json(reaction)))
}

async fn fill_reaction_response(
    tx: &mut MySqlConnection,
    iconhash_cache: &Arc<Mutex<HashMap<i64, String>>>,
    reaction_model: ReactionModel,
) -> sqlx::Result<Reaction> {
    let user_model = get_user_model(&mut *tx, reaction_model.user_id).await?;
    let user = fill_user_response(&mut *tx, iconhash_cache, user_model).await?;

    let livestream_model = get_livestream_model(&mut *tx, reaction_model.livestream_id).await?;

    let livestream = fill_livestream_response(&mut *tx, iconhash_cache, livestream_model).await?;

    Ok(Reaction {
        id: reaction_model.id,
        emoji_name: reaction_model.emoji_name,
        user,
        livestream,
        created_at: reaction_model.created_at,
    })
}

#[derive(Debug, sqlx::FromRow, Clone)]
struct UserModel {
    id: i64,
    name: String,
    display_name: Option<String>,
    description: Option<String>,
    #[sqlx(default, rename = "password")]
    hashed_password: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct User {
    id: i64,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    theme: Theme,
    icon_hash: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Theme {
    id: i64,
    dark_mode: bool,
}

#[derive(Debug, sqlx::FromRow, Clone)]
struct ThemeModel {
    id: i64,
    #[allow(unused)]
    user_id: i64,
    dark_mode: bool,
}

#[derive(Debug, serde::Deserialize)]
struct PostUserRequest {
    name: String,
    display_name: String,
    description: String,
    // password is non-hashed password.
    password: String,
    theme: PostUserRequestTheme,
}

#[derive(Debug, serde::Deserialize)]
struct PostUserRequestTheme {
    dark_mode: bool,
}

#[derive(Debug, serde::Deserialize)]
struct LoginRequest {
    username: String,
    // password is non-hashed password.
    password: String,
}

#[derive(Debug, serde::Deserialize)]
struct PostIconRequest {
    #[serde(deserialize_with = "from_base64")]
    image: Vec<u8>,
}
fn from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use base64::Engine as _;
    use serde::de::{Deserialize as _, Error as _};
    let value = String::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(D::Error::custom)
}

#[derive(Debug, serde::Serialize)]
struct PostIconResponse {
    id: i64,
}

fn calc_sha256(image: &Vec<u8>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(image);
    let result = hasher.finalize();
    let hash_string = hex::encode(result);
    return hash_string;
}

async fn get_fallback_icon_hash() -> String {
    let fallback_image_data = tokio::fs::read(FALLBACK_IMAGE).await.unwrap();
    calc_sha256(&fallback_image_data)
}

async fn get_hash(
    conn: &mut MySqlConnection,
    iconhash_cache: &Arc<Mutex<HashMap<i64, String>>>,
    user_id: i64,
) -> sqlx::Result<String> {
    {
        let iconhash_cache = iconhash_cache.lock().await;
        if let Some(hash) = iconhash_cache.get(&user_id) {
            return Ok(hash.clone());
        }
    }

    // データベースから画像を取得
    let image: Option<Vec<u8>> = sqlx::query_scalar("SELECT image FROM icons WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;

    // 画像が存在しない場合のエラーハンドリング
    let hash = match image {
        Some(image) => calc_sha256(&image),
        None => ONCE.get_or_init(get_fallback_icon_hash).await.clone(),
    };

    // キャッシュにハッシュを追加
    {
        let mut iconhash_cache = iconhash_cache.lock().await;
        iconhash_cache.insert(user_id, hash.clone());
    }

    Ok(hash)
}

async fn get_user_model_from_name(
    conn: &mut MySqlConnection,
    username: String,
) -> Result<UserModel, Error> {
    let user_id = get_user_id(&mut *conn, username).await?;

    let user = get_user_model(&mut *conn, user_id).await?;

    Ok(user)
}
async fn get_icon_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    Path((username,)): Path<(String,)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let mut tx = pool.begin().await?;

    let user = get_user_model_from_name(&mut *tx, username).await?;

    // 通常のアイコン画像のハッシュを取得
    let hash = get_hash(&mut *tx, &iconhash_cache, user.id).await?;

    // リクエストヘッダーからIf-None-Matchを取得
    if let Some(if_none_match) = headers.get(axum::http::header::IF_NONE_MATCH) {
        if let Ok(if_none_match_str) = if_none_match.to_str() {
            let if_none_match_str = if_none_match_str.trim_matches('"');
            // ハッシュを比較
            if if_none_match_str == hash {
                // 一致する場合は304 Not Modifiedを返す
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Body::empty())
                    .unwrap()
                    .into_response());
            }
        }
    }

    // 通常のアイコン画像を返す
    let image_data: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT image FROM icons WHERE user_id = ?")
            .bind(user.id)
            .fetch_optional(&mut *tx)
            .await?;

    match image_data {
        Some(image_data) => {
            let response_headers = [(axum::http::header::CONTENT_TYPE, "image/jpeg")];
            return Ok((response_headers, image_data).into_response());
        }
        _ => {}
    };

    // フォールバック画像を返す
    let response_headers = [(axum::http::header::CONTENT_TYPE, "image/jpeg")];
    let stream = tokio_util::io::ReaderStream::new(tokio::fs::File::open(FALLBACK_IMAGE).await?);
    let body = axum::body::StreamBody::new(stream);
    Ok((response_headers, body).into_response())
}

async fn post_icon_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    axum::Json(req): axum::Json<PostIconRequest>,
) -> Result<(StatusCode, axum::Json<PostIconResponse>), Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM icons WHERE user_id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    let rs = sqlx::query("INSERT INTO icons (user_id, image) VALUES (?, ?)")
        .bind(user_id)
        .bind(req.image)
        .execute(&mut *tx)
        .await?;
    let icon_id = rs.last_insert_id() as i64;

    tx.commit().await?;

    {
        let mut iconhash_cache = iconhash_cache.lock().await;
        iconhash_cache.remove(&user_id);
    }

    Ok((
        StatusCode::CREATED,
        axum::Json(PostIconResponse { id: icon_id }),
    ))
}

async fn get_me_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
) -> Result<axum::Json<User>, Error> {
    verify_user_session(&jar).await?;

    let cookie = jar.get(DEFAULT_SESSION_ID_KEY).ok_or(Error::SessionError)?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::SessionError)?;
    let user_id: i64 = sess.get(DEFAULT_USER_ID_KEY).ok_or(Error::SessionError)?;

    let mut tx = pool.begin().await?;

    let user_model = get_user_model(&mut *tx, user_id).await?;

    let user = fill_user_response(&mut tx, &iconhash_cache, user_model).await?;

    tx.commit().await?;

    Ok(axum::Json(user))
}

// dns登録API
async fn arecord_handler(
    State(AppState {
        powerdns_subdomain_address,
        ..
    }): State<AppState>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Result<StatusCode, Error> {
    let output = tokio::process::Command::new("pdnsutil")
        .arg("add-record")
        .arg("u.isucon.local")
        .arg(&username)
        .arg("A")
        .arg("0")
        .arg(&*powerdns_subdomain_address)
        .output()
        .await?;
    if !output.status.success() {
        return Err(Error::InternalServerError(format!(
            "pdnsutil failed with stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    return Ok(StatusCode::CREATED);
}
// dns初期化用API
async fn reset_dns_handler() -> Result<StatusCode, Error> {
    let output = tokio::process::Command::new("../sql/init.sh")
        .output()
        .await?;
    if !output.status.success() {
        return Err(Error::InternalServerError(format!(
            "init.sh failed with stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )));
    }
    return Ok(StatusCode::CREATED);
}

// ユーザ登録API
// POST /api/register
async fn register_handler(
    State(AppState {
        pool,
        powerdns_subdomain_address,
        powerdns_address,
        iconhash_cache,
        ..
    }): State<AppState>,
    axum::Json(req): axum::Json<PostUserRequest>,
) -> Result<(StatusCode, axum::Json<User>), Error> {
    if req.name == "pipe" {
        return Err(Error::BadRequest("the username 'pipe' is reserved".into()));
    }

    const BCRYPT_DEFAULT_COST: u32 = 4;
    let hashed_password = bcrypt::hash(&req.password, BCRYPT_DEFAULT_COST)?;

    let mut tx = pool.begin().await?;

    let result = sqlx::query(
        "INSERT INTO users (name, display_name, description, password) VALUES(?, ?, ?, ?)",
    )
    .bind(&req.name)
    .bind(&req.display_name)
    .bind(&req.description)
    .bind(&hashed_password)
    .execute(&mut *tx)
    .await?;
    let user_id = result.last_insert_id() as i64;

    sqlx::query("INSERT INTO themes (user_id, dark_mode) VALUES(?, ?)")
        .bind(user_id)
        .bind(req.theme.dark_mode)
        .execute(&mut *tx)
        .await?;

    let client = Client::new();
    let url = format!(
        "http://{}:8080/api/internal/arecord/{}",
        powerdns_address, &req.name
    );
    let a_req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .body(Body::from(""))
        .unwrap();
    let res = client.request(a_req).await?;
    if res.status() != StatusCode::CREATED {
        return Err(Error::InternalServerError(format!(
            "fail to create dns record {}",
            req.name
        )));
    }

    let user = fill_user_response(
        &mut tx,
        &iconhash_cache,
        UserModel {
            id: user_id,
            name: req.name,
            display_name: Some(req.display_name),
            description: Some(req.description),
            hashed_password: Some(hashed_password),
        },
    )
    .await?;

    tx.commit().await?;

    Ok((StatusCode::CREATED, axum::Json(user)))
}

#[derive(Debug, serde::Serialize)]
struct Session {
    id: String,
    user_id: i64,
    expires: i64,
}

// ユーザログインAPI
// POST /api/login
async fn login_handler(
    State(AppState { pool, .. }): State<AppState>,
    mut jar: SignedCookieJar,
    axum::Json(req): axum::Json<LoginRequest>,
) -> Result<(SignedCookieJar, ()), Error> {
    let mut tx = pool.begin().await?;

    // usernameはUNIQUEなので、whereで一意に特定できる
    let user_model: UserModel = sqlx::query_as("SELECT * FROM users WHERE name = ?")
        .bind(req.username)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::Unauthorized("invalid username or password".into()))?;

    tx.commit().await?;

    let hashed_password = user_model.hashed_password.unwrap();
    if !bcrypt::verify(&req.password, &hashed_password)? {
        return Err(Error::Unauthorized("invalid username or password".into()));
    }

    let session_end_at = Utc::now() + chrono::Duration::hours(1);
    let session_id = Uuid::new_v4().to_string();
    let mut sess = async_session::Session::new();
    sess.insert(DEFAULT_SESSION_ID_KEY, session_id).unwrap();
    sess.insert(DEFAULT_USER_ID_KEY, user_model.id).unwrap();
    sess.insert(DEFAULT_USERNAME_KEY, user_model.name).unwrap();
    sess.insert(DEFUALT_SESSION_EXPIRES_KEY, session_end_at.timestamp())
        .unwrap();
    let cookie_store = CookieStore::new();
    if let Some(cookie_value) = cookie_store.store_session(sess).await? {
        let cookie =
            axum_extra::extract::cookie::Cookie::build(DEFAULT_SESSION_ID_KEY, cookie_value)
                .domain("u.isucon.local")
                .max_age(time::Duration::minutes(1000))
                .path("/")
                .finish();
        jar = jar.add(cookie);
    }

    Ok((jar, ()))
}

// ユーザ詳細API
// GET /api/user/:username
async fn get_user_handler(
    State(AppState {
        pool,
        iconhash_cache,
        ..
    }): State<AppState>,
    jar: SignedCookieJar,
    Path((username,)): Path<(String,)>,
) -> Result<axum::Json<User>, Error> {
    verify_user_session(&jar).await?;

    let mut tx = pool.begin().await?;

    let user_model: UserModel = sqlx::query_as("SELECT * FROM users WHERE name = ?")
        .bind(username)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::NotFound(
            "not found user that has the given username".into(),
        ))?;

    let user = fill_user_response(&mut tx, &iconhash_cache, user_model).await?;

    tx.commit().await?;

    Ok(axum::Json(user))
}

async fn verify_user_session(jar: &SignedCookieJar) -> Result<(), Error> {
    let cookie = jar
        .get(DEFAULT_SESSION_ID_KEY)
        .ok_or(Error::Forbidden("".into()))?;
    let sess = CookieStore::new()
        .load_session(cookie.value().to_owned())
        .await?
        .ok_or(Error::Forbidden("".into()))?;
    let session_expires: i64 = sess
        .get(DEFUALT_SESSION_EXPIRES_KEY)
        .ok_or(Error::Forbidden("".into()))?;
    let now = Utc::now();
    if now.timestamp() > session_expires {
        return Err(Error::Unauthorized("session has expired".into()));
    }
    Ok(())
}

async fn fill_user_response(
    tx: &mut MySqlConnection,
    iconhash_cache: &Arc<Mutex<HashMap<i64, String>>>,
    user_model: UserModel,
) -> sqlx::Result<User> {
    let theme_model = get_theme_model(&mut *tx, user_model.id).await?;

    let icon_hash = get_hash(&mut *tx, iconhash_cache, user_model.id).await?;
    Ok(User {
        id: user_model.id,
        name: user_model.name,
        display_name: user_model.display_name,
        description: user_model.description,
        theme: Theme {
            id: theme_model.id,
            dark_mode: theme_model.dark_mode,
        },
        icon_hash,
    })
}

#[derive(Debug, serde::Serialize)]
struct LivestreamStatistics {
    rank: i64,
    viewers_count: i64,
    total_reactions: i64,
    total_reports: i64,
    max_tip: i64,
}

#[derive(Debug)]
struct LivestreamRankingEntry {
    livestream_id: i64,
    score: i64,
}

#[derive(Debug, serde::Serialize)]
struct UserStatistics {
    rank: i64,
    viewers_count: i64,
    total_reactions: i64,
    total_livecomments: i64,
    total_tip: i64,
    favorite_emoji: String,
}

#[derive(Debug)]
struct UserRankingEntry {
    username: String,
    score: i64,
}

/// MySQL で COUNT()、SUM() 等を使って DECIMAL 型の値になったものを i64 に変換するための構造体。
#[derive(Debug)]
struct MysqlDecimal(i64);
impl sqlx::Decode<'_, sqlx::MySql> for MysqlDecimal {
    fn decode(
        value: sqlx::mysql::MySqlValueRef,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use sqlx::{Type as _, ValueRef as _};

        let type_info = value.type_info();
        if i64::compatible(&type_info) {
            i64::decode(value).map(Self)
        } else if u64::compatible(&type_info) {
            let n = u64::decode(value)?.try_into()?;
            Ok(Self(n))
        } else if sqlx::types::Decimal::compatible(&type_info) {
            use num_traits::ToPrimitive as _;
            let n = sqlx::types::Decimal::decode(value)?
                .to_i64()
                .expect("failed to convert DECIMAL type to i64");
            Ok(Self(n))
        } else {
            todo!()
        }
    }
}
impl sqlx::Type<sqlx::MySql> for MysqlDecimal {
    fn type_info() -> sqlx::mysql::MySqlTypeInfo {
        i64::type_info()
    }

    fn compatible(ty: &sqlx::mysql::MySqlTypeInfo) -> bool {
        i64::compatible(ty) || u64::compatible(ty) || sqlx::types::Decimal::compatible(ty)
    }
}
impl From<MysqlDecimal> for i64 {
    fn from(value: MysqlDecimal) -> Self {
        value.0
    }
}

async fn get_user_statistics_handler(
    State(AppState { pool, .. }): State<AppState>,
    jar: SignedCookieJar,
    Path((username,)): Path<(String,)>,
) -> Result<axum::Json<UserStatistics>, Error> {
    verify_user_session(&jar).await?;

    // ユーザごとに、紐づく配信について、累計リアクション数、累計ライブコメント数、累計売上金額を算出
    // また、現在の合計視聴者数もだす

    let mut tx = pool.begin().await?;

    let user_id = get_user_id(&mut *&mut tx, username.clone()).await?;

    // ランク算出
    let query = r#"
    SELECT u.name, 
           COALESCE(SUM(r.reactions), 0) AS total_reactions,
           COALESCE(SUM(lc.count), 0) AS total_comments,
           COALESCE(SUM(lc.tip), 0) AS total_tips
    FROM users u
    LEFT JOIN livestreams l ON l.user_id = u.id
    LEFT JOIN (
        SELECT livestream_id, COUNT(*) AS reactions
        FROM reactions
        GROUP BY livestream_id
    ) r ON l.id = r.livestream_id
    LEFT JOIN (
        SELECT livestream_id, SUM(tip) AS tip, COUNT(*) AS count
        FROM livecomments
        GROUP BY livestream_id
    ) lc ON l.id = lc.livestream_id
    GROUP BY u.id
    "#;

    let user_stats: Vec<(String, MysqlDecimal, MysqlDecimal, MysqlDecimal)> =
        sqlx::query_as(query).fetch_all(&mut *tx).await?;

    let mut total_livecomments = 0;
    let mut total_tip = 0;
    let mut total_reactions = 0;
    let mut ranking = Vec::new();
    for (name, reaction, comment, tip) in user_stats {
        let reaction = i64::from(reaction);
        let comment = i64::from(comment);
        let tip = i64::from(tip);
        let score = reaction + tip;

        if (name == username) {
            total_livecomments = comment;
            total_tip = tip;
            total_reactions = reaction;
        }

        ranking.push(UserRankingEntry {
            username: name,
            score,
        });
    }
    ranking.sort_by(|a, b| {
        a.score
            .cmp(&b.score)
            .then_with(|| a.username.cmp(&b.username))
    });

    let rpos = ranking
        .iter()
        .rposition(|entry| entry.username == username)
        .unwrap();
    let rank = (ranking.len() - rpos) as i64;

    // 合計視聴者数
    let query = r"#
    SELECT COUNT(*) FROM users u
    INNER JOIN livestreams l ON l.user_id = u.id
    INNER JOIN livestream_viewers_history h ON h.livestream_id = l.id
    WHERE u.id = ?
    #";
    let MysqlDecimal(viewers_count) = sqlx::query_scalar(query)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

    // お気に入り絵文字
    let query = r#"
    SELECT r.emoji_name
    FROM users u
    INNER JOIN livestreams l ON l.user_id = u.id
    INNER JOIN reactions r ON r.livestream_id = l.id
    WHERE u.name = ?
    GROUP BY emoji_name
    ORDER BY COUNT(*) DESC, emoji_name DESC
    LIMIT 1
    "#;
    let favorite_emoji: String = sqlx::query_scalar(query)
        .bind(&username)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or_default();

    Ok(axum::Json(UserStatistics {
        rank,
        viewers_count,
        total_reactions,
        total_livecomments,
        total_tip,
        favorite_emoji,
    }))
}

async fn get_livestream_statistics_handler(
    State(AppState { pool, .. }): State<AppState>,
    jar: SignedCookieJar,
    Path((livestream_id,)): Path<(i64,)>,
) -> Result<axum::Json<LivestreamStatistics>, Error> {
    verify_user_session(&jar).await?;

    let mut tx = pool.begin().await?;

    // ランク算出
    // ランキングを一度のクエリで取得
    let livestreams: Vec<(MysqlDecimal, MysqlDecimal, MysqlDecimal)> = sqlx::query_as(
        "
        SELECT l.id AS livestream_id,
               COALESCE(SUM(r.reactions), 0) AS total_reactions,
               COALESCE(SUM(lc.tip), 0) AS total_tips
        FROM livestreams l
        LEFT JOIN (
            SELECT livestream_id, COUNT(*) AS reactions
            FROM reactions
            GROUP BY livestream_id
        ) r ON l.id = r.livestream_id
        LEFT JOIN (
            SELECT livestream_id, SUM(tip) AS tip
            FROM livecomments
            GROUP BY livestream_id
        ) lc ON l.id = lc.livestream_id
        GROUP BY l.id
        ",
    )
    .fetch_all(&mut *tx)
    .await?;

    // スコアを計算し、ランキングを作成
    let mut ranking: Vec<LivestreamRankingEntry> = livestreams
        .into_iter()
        .map(|(livestream_id, reaction, tip)| {
            let score = i64::from(reaction) + i64::from(tip);
            LivestreamRankingEntry {
                livestream_id: i64::from(livestream_id),
                score,
            }
        })
        .collect();
    ranking.sort_by(|a, b| {
        a.score
            .cmp(&b.score)
            .then_with(|| a.livestream_id.cmp(&b.livestream_id))
    });

    let rpos = ranking
        .iter()
        .rposition(|entry| entry.livestream_id == livestream_id)
        .unwrap();
    let rank = (ranking.len() - rpos) as i64;

    // 視聴者数算出
    let MysqlDecimal(viewers_count) = sqlx::query_scalar("SELECT COUNT(*) FROM livestreams l INNER JOIN livestream_viewers_history h ON h.livestream_id = l.id WHERE l.id = ?")
        .bind(livestream_id)
        .fetch_one(&mut *tx)
        .await?;

    // 最大チップ額
    let MysqlDecimal(max_tip) = sqlx::query_scalar("SELECT IFNULL(MAX(tip), 0) FROM livestreams l INNER JOIN livecomments l2 ON l2.livestream_id = l.id WHERE l.id = ?")
        .bind(livestream_id)
        .fetch_one(&mut *tx)
        .await?;

    // リアクション数
    let MysqlDecimal(total_reactions) = sqlx::query_scalar("SELECT COUNT(*) FROM livestreams l INNER JOIN reactions r ON r.livestream_id = l.id WHERE l.id = ?")
        .bind(livestream_id)
        .fetch_one(&mut *tx)
        .await?;

    // スパム報告数
    let MysqlDecimal(total_reports) = sqlx::query_scalar("SELECT COUNT(*) FROM livestreams l INNER JOIN livecomment_reports r ON r.livestream_id = l.id WHERE l.id = ?")
        .bind(livestream_id)
        .fetch_one(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(axum::Json(LivestreamStatistics {
        rank,
        viewers_count,
        max_tip,
        total_reactions,
        total_reports,
    }))
}

#[derive(Debug, serde::Serialize)]
struct PaymentResult {
    total_tip: i64,
}

async fn get_payment_result(
    State(AppState { pool, .. }): State<AppState>,
) -> Result<axum::Json<PaymentResult>, Error> {
    let mut tx = pool.begin().await?;

    let MysqlDecimal(total_tip) =
        sqlx::query_scalar("SELECT IFNULL(SUM(tip), 0) FROM livecomments")
            .fetch_one(&mut *tx)
            .await?;

    tx.commit().await?;

    Ok(axum::Json(PaymentResult { total_tip }))
}
