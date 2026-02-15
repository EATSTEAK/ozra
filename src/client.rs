//! HTTP 클라이언트 모듈 — OZ 서버와의 세션 관리 및 통신 플로우
//!
//! [`OzClient`]는 reqwest 기반 HTTP 클라이언트로, OZ 프로토콜의 전체 통신 플로우를 관리합니다.
//!
//! ## 통신 플로우
//!
//! 1. [`init_session`](OzClient::init_session) — `GET /ozView.jsp` → JSESSIONID 쿠키 획득
//! 2. [`login`](OzClient::login) — UserLogin 요청 → OZ 세션 ID 획득
//! 3. [`send`](OzClient::send) — 제네릭 요청-응답 (타입 안전)
//! 4. [`fetch_repository`](OzClient::fetch_repository) — .ozr/.odi 파일 다운로드 (편의 메서드)
//! 5. [`fetch_data_module`](OzClient::fetch_data_module) — DataModule 데이터 조회 (편의 메서드)
//!
//! ## 제네릭 send 메서드
//!
//! [`OzRequestResponse`] trait을 구현한 모든 요청 타입에 대해 타입 안전한 요청-응답 처리가 가능합니다:
//!
//! ```ignore
//! use ozra::messages::{RepositoryRequest, DataModuleRequest};
//!
//! // Repository 파일 다운로드
//! let repo_req = RepositoryRequest::new("/CM/report.ozr");
//! let repo_resp = client.send(&repo_req).await?;
//! let bytes = repo_resp.into_data();
//! println!("Downloaded {} bytes", bytes.len());
//!
//! // DataModule 쿼리
//! let dm_req = DataModuleRequest {
//!     odi_name: "query.odi".to_string(),
//!     category: "/CM".to_string(),
//!     params: vec![("year".to_string(), "2026".to_string())],
//! };
//! let dm_resp = client.send(&dm_req).await?;
//! println!("Datasets: {}", dm_resp.datasets.len());
//! ```
//!
//! ## 에러 복구 및 재시도
//!
//! [`RetryPolicy`]를 설정하면 일시적 오류(네트워크 에러, 서버 과부하 등) 발생 시
//! 지수 백오프(exponential backoff)를 적용하여 자동으로 재시도합니다.
//!
//! ```no_run
//! use ozra::client::{OzClientBuilder, RetryPolicy};
//! use std::time::Duration;
//!
//! # async fn example() -> ozra::Result<()> {
//! let client = OzClientBuilder::new("https://example.com/oz70", "guest", "guest")
//!     .retry_policy(RetryPolicy::new(3, Duration::from_millis(100)))
//!     .build()?;
//! # Ok(())
//! # }
//! ```

use std::sync::RwLock;
use std::time::Duration;

use reqwest::Client;

use crate::constants::{INITIAL_SESSION_ID, USER_AGENT};
use crate::error::{OzError, Result};
use crate::messages::{
    CompactDataModuleRequest, DataModuleRequest, LoginRequest, LoginResponse, OzRequest,
    OzRequestResponse, OzResponse, RepositoryRequest, TransactionDataSet, TransactionRequest,
    TransactionResponse, check_error_result,
};
use crate::types::DataModuleResponse;

/// 에러 복구를 위한 재시도 정책
///
/// 최대 재시도 횟수, 대기 시간, 지수 백오프 전략을 설정합니다.
/// 기본값은 재시도 없음(`max_retries = 0`)입니다.
///
/// # 백오프 전략
///
/// 각 재시도 시 대기 시간은 다음과 같이 계산됩니다:
///
/// ```text
/// delay = min(base_delay × backoff_factor^attempt, max_delay)
/// ```
///
/// # 예시
///
/// ```rust
/// use ozra::client::RetryPolicy;
/// use std::time::Duration;
///
/// // 재시도 없음 (기본값)
/// let no_retry = RetryPolicy::default();
/// assert_eq!(no_retry.max_retries, 0);
///
/// // 3회 재시도, 100ms 기본 대기
/// let policy = RetryPolicy::new(3, Duration::from_millis(100));
/// assert_eq!(policy.max_retries, 3);
///
/// // 커스텀 설정
/// let custom = RetryPolicy {
///     max_retries: 5,
///     base_delay: Duration::from_millis(200),
///     max_delay: Duration::from_secs(30),
///     backoff_factor: 3.0,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// 최대 재시도 횟수 (0이면 재시도 없음)
    pub max_retries: u32,
    /// 첫 번째 재시도 전 기본 대기 시간
    pub base_delay: Duration,
    /// 최대 대기 시간 (백오프 상한)
    pub max_delay: Duration,
    /// 백오프 승수 (각 재시도마다 대기 시간에 곱해짐)
    pub backoff_factor: f64,
}

impl Default for RetryPolicy {
    /// 재시도 없음 정책을 반환합니다 (`max_retries = 0`).
    fn default() -> Self {
        Self {
            max_retries: 0,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_factor: 2.0,
        }
    }
}

impl RetryPolicy {
    /// 지정된 최대 재시도 횟수와 기본 대기 시간으로 정책을 생성합니다.
    ///
    /// 백오프 승수는 `2.0`, 최대 대기 시간은 `30초`가 기본값입니다.
    ///
    /// # 인자
    ///
    /// - `max_retries`: 최대 재시도 횟수
    /// - `base_delay`: 첫 번째 재시도 전 기본 대기 시간
    pub fn new(max_retries: u32, base_delay: Duration) -> Self {
        Self {
            max_retries,
            base_delay,
            ..Default::default()
        }
    }

    /// 해당 시도 번호(0-based)에 대한 대기 시간을 계산합니다.
    ///
    /// ```text
    /// delay = min(base_delay × backoff_factor^attempt, max_delay)
    /// ```
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let multiplier = self.backoff_factor.powi(attempt as i32);
        let delay = self.base_delay.mul_f64(multiplier);
        std::cmp::min(delay, self.max_delay)
    }
}

/// 세션 상태 (원자적 관리)
///
/// OZ 프로토콜 세션 ID를 캡슐화하여 `RwLock`으로 보호합니다.
/// 멀티스레드 환경에서 안전한 세션 상태 관리를 보장합니다.
struct SessionState {
    session_id: String,
}

impl SessionState {
    fn new() -> Self {
        Self {
            session_id: INITIAL_SESSION_ID.to_string(),
        }
    }

    fn is_authenticated(&self) -> bool {
        self.session_id != INITIAL_SESSION_ID
    }
}

/// OZ 서버 HTTP 클라이언트
///
/// cookie_store를 활성화한 reqwest::Client로 JSESSIONID를 자동 관리하며,
/// OZ 프로토콜의 세션 ID를 추적합니다.
///
/// # 예시
///
/// ```no_run
/// use ozra::client::OzClient;
///
/// # async fn example() -> ozra::Result<()> {
/// let client = OzClient::new(
///     "https://example.com/oz70",
///     "guest",
///     "guest",
/// )?;
/// client.init_session().await?;
/// let login_resp = client.login().await?;
/// println!("Session ID: {}", login_resp.session_id);
/// # Ok(())
/// # }
/// ```
pub struct OzClient {
    /// reqwest HTTP 클라이언트 (cookie_store 활성화)
    http: Client,
    /// 서버 기본 URL (예: `"https://example.com/oz70"`)
    base_url: String,
    /// OZ 프로토콜 세션 상태 (`RwLock`으로 보호)
    session: RwLock<SessionState>,
    /// 로그인 사용자명
    username: String,
    /// 로그인 비밀번호
    password: String,
    /// 에러 복구를 위한 재시도 정책
    retry_policy: RetryPolicy,
}

impl OzClient {
    /// 새 OzClient를 생성합니다.
    ///
    /// - `base_url`: OZ 서버 기본 URL (예: `"https://example.com/oz70"`)
    /// - `username`: 로그인 사용자명 (기본: `"guest"`)
    /// - `password`: 로그인 비밀번호 (기본: `"guest"`)
    ///
    /// reqwest::Client는 cookie_store를 활성화하고 rustls-tls를 사용합니다.
    /// 세션 ID는 [`INITIAL_SESSION_ID`](`"-1905"`)로 초기화됩니다.
    pub fn new(base_url: &str, username: &str, password: &str) -> Result<Self> {
        OzClientBuilder::new(base_url, username, password).build()
    }

    /// 현재 설정된 재시도 정책을 반환합니다.
    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.retry_policy
    }

    /// 현재 OZ 프로토콜 세션 ID를 반환합니다.
    ///
    /// `RwLock` guard의 수명 제약으로 `String`을 반환합니다.
    pub fn session_id(&self) -> String {
        self.session
            .read()
            .expect("session lock poisoned")
            .session_id
            .clone()
    }

    /// 인증 여부를 확인합니다 (세션 ID가 초기값이 아닌지).
    pub fn is_authenticated(&self) -> bool {
        self.session
            .read()
            .expect("session lock poisoned")
            .is_authenticated()
    }

    /// 세션을 초기화합니다 — `GET {base_url}/ozView.jsp`로 JSESSIONID 쿠키를 획득합니다.
    ///
    /// reqwest cookie_store가 활성화되어 있으므로 Set-Cookie가 자동 저장됩니다.
    ///
    /// > **참고**: 파라미터 없이 호출하면 일부 서버에서 500 에러가 발생할 수 있습니다.
    /// > 그런 경우 [`init_session_with_params`](Self::init_session_with_params)를 사용하세요.
    ///
    /// # 에러
    ///
    /// - [`OzError::Http`] — 네트워크 에러
    /// - [`OzError::HttpStatus`] — 비정상 HTTP 상태 코드
    pub async fn init_session(&self) -> Result<()> {
        let url = format!("{}/ozView.jsp", self.base_url);
        self.send_init_session_request(&url).await
    }

    /// 세션을 초기화합니다 — 쿼리 파라미터를 포함하여 `GET {base_url}/ozView.jsp`를 호출합니다.
    ///
    /// JS POC의 `initSession(ozrname, category, params)` 플로우와 동일합니다.
    /// 서버에 따라 ozView.jsp 호출 시 `ozrname`, `category`, 파라미터 정보를 포함해야
    /// 정상 응답(200)이 반환될 수 있습니다.
    ///
    /// # 인자
    ///
    /// - `ozrname`: 보고서 이름 (예: `"zcm_get_abeek_plan_2018_new"`)
    /// - `category`: 카테고리 (예: `"CM"`)
    /// - `params`: 쿼리 파라미터 (키-값 쌍)
    ///
    /// # 예시
    ///
    /// ```no_run
    /// use ozra::client::OzClient;
    ///
    /// # async fn example() -> ozra::Result<()> {
    /// let client = OzClient::new("https://example.com/oz70", "guest", "guest")?;
    /// let params = vec![
    ///     ("arg1".to_string(), "2026".to_string()),
    ///     ("arg2".to_string(), "090".to_string()),
    /// ];
    /// client.init_session_with_params("report_name", "CM", &params).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # 에러
    ///
    /// - [`OzError::Http`] — 네트워크 에러
    /// - [`OzError::HttpStatus`] — 비정상 HTTP 상태 코드
    pub async fn init_session_with_params(
        &self,
        ozrname: &str,
        category: &str,
        params: &[(String, String)],
    ) -> Result<()> {
        let param_names: Vec<&str> = params.iter().map(|(k, _)| k.as_str()).collect();
        let param_values: Vec<&str> = params.iter().map(|(_, v)| v.as_str()).collect();

        let url = format!(
            "{}/ozView.jsp?ozrname={}&category={}&cnt={}&pName={}&pValue={}",
            self.base_url,
            urlencoding::encode(ozrname),
            urlencoding::encode(category),
            params.len(),
            urlencoding::encode(&param_names.join(",")),
            urlencoding::encode(&param_values.join(",")),
        );

        self.send_init_session_request(&url).await
    }

    /// init_session 공통 로직: GET 요청 + 쿠키 자동 저장
    async fn send_init_session_request(&self, url: &str) -> Result<()> {
        let resp = self
            .http
            .get(url)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(OzError::HttpStatus {
                status: status.as_u16(),
            });
        }

        // NOTE: cookie_store automatically persists JSESSIONID
        // NOTE: Response body is consumed and discarded for connection reuse
        let _ = resp.bytes().await?;

        Ok(())
    }

    /// OZ 서버에 바이너리 POST 요청을 전송합니다.
    ///
    /// - POST `{base_url}/server`
    /// - Content-Type: `application/octet-stream`
    /// - 프로토콜 에러 자동 감지 ([`check_error_result`])
    /// - 재시도 정책이 설정된 경우 재시도 가능한 에러에 대해 지수 백오프로 자동 재시도
    ///
    /// 이 메서드는 [`send`](Self::send) 메서드의 저수준 구현입니다.
    /// 일반적으로 [`send`](Self::send)를 통해 타입 안전한 요청-응답을 사용하세요.
    ///
    /// # 재시도 동작
    ///
    /// [`RetryPolicy`]가 설정되어 있고 `max_retries > 0`인 경우,
    /// 재시도 가능한 에러([`OzError::is_retryable`])가 발생하면 지수 백오프를 적용하여
    /// 최대 `max_retries`회까지 자동으로 재시도합니다.
    ///
    /// # 에러
    ///
    /// - [`OzError::Http`] — 네트워크 에러
    /// - [`OzError::HttpStatus`] — 비정상 HTTP 상태 코드
    /// - [`OzError::ProtocolError`] — 서버가 반환한 OZ 프로토콜 에러
    pub async fn send_request(&self, body: Vec<u8>) -> Result<Vec<u8>> {
        let mut last_err: Option<OzError> = None;

        for attempt in 0..=self.retry_policy.max_retries {
            // 재시도 시 백오프 대기
            if attempt > 0 {
                let delay = self.retry_policy.delay_for_attempt(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            match self.send_request_once(&body).await {
                Ok(buf) => return Ok(buf),
                Err(e) => {
                    // 재시도 불가능한 에러이거나 마지막 시도이면 즉시 반환
                    if !e.is_retryable() || attempt == self.retry_policy.max_retries {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
        }

        // max_retries == 0이고 에러 발생 시 여기에 도달할 수 없지만 안전장치
        Err(last_err.unwrap_or_else(|| OzError::HttpStatus { status: 0 }))
    }

    /// 단일 HTTP POST 요청을 전송합니다 (재시도 없음).
    ///
    /// [`send_request`](Self::send_request)의 내부 구현입니다.
    async fn send_request_once(&self, body: &[u8]) -> Result<Vec<u8>> {
        let url = format!("{}/server", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("Accept", "*/*")
            .body(body.to_vec())
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            return Err(OzError::HttpStatus {
                status: status.as_u16(),
            });
        }

        let buf = resp.bytes().await?.to_vec();

        check_error_result(&buf)?;

        Ok(buf)
    }

    /// 타입 안전한 요청-응답 메서드
    ///
    /// [`OzRequestResponse`] trait을 구현한 모든 요청 타입에 대해
    /// 요청 빌드 → HTTP 전송 → 응답 파싱을 자동으로 수행합니다.
    ///
    /// 요청 타입에 연결된 응답 타입을 컴파일 타임에 추론하므로,
    /// 잘못된 요청-응답 조합이 불가능합니다.
    ///
    /// # 인증 요구
    ///
    /// 이 메서드는 인증된 상태에서만 사용할 수 있습니다.
    /// [`login()`](Self::login) 호출 후 사용하세요.
    ///
    /// # 예시
    ///
    /// ```ignore
    /// use ozra::messages::{RepositoryRequest, DataModuleRequest};
    ///
    /// // Repository 파일 다운로드
    /// let repo_req = RepositoryRequest::new("/CM/report.ozr");
    /// let repo_resp = client.send(&repo_req).await?;
    ///
    /// // DataModule 쿼리
    /// let dm_req = DataModuleRequest {
    ///     odi_name: "query.odi".to_string(),
    ///     category: "/CM".to_string(),
    ///     params: vec![("year".to_string(), "2026".to_string())],
    /// };
    /// let dm_resp = client.send(&dm_req).await?;
    /// ```
    ///
    /// # 에러
    ///
    /// - [`OzError::NotAuthenticated`] — 로그인되지 않은 상태
    /// - [`OzError::Http`] — 네트워크 에러
    /// - [`OzError::HttpStatus`] — 비정상 HTTP 상태 코드
    /// - [`OzError::ProtocolError`] — 서버가 반환한 OZ 프로토콜 에러
    /// - 응답 파싱 중 발생 가능한 모든 에러
    pub async fn send<R>(&self, request: &R) -> Result<R::Response>
    where
        R: OzRequestResponse,
    {
        if !self.is_authenticated() {
            return Err(OzError::NotAuthenticated);
        }

        let session_id = self
            .session
            .read()
            .expect("session lock poisoned")
            .session_id
            .clone();
        let req_buf = request.build(&session_id)?;
        let resp_buf = self.send_request(req_buf).await?;
        R::Response::parse(&resp_buf)
    }

    /// 로그인하여 OZ 세션 ID를 획득합니다.
    ///
    /// [`LoginRequest`]를 빌드하여 서버에 전송하고, [`LoginResponse`]를 파싱합니다.
    /// 응답 헤더의 `"s"` 필드에서 세션 ID를 추출하여 내부 상태를 업데이트합니다.
    ///
    /// > **참고**: 이 메서드는 인증 전에 호출되므로 [`send`](Self::send)를 사용하지 않고
    /// > 직접 [`send_request`](Self::send_request)를 통해 요청을 전송합니다.
    ///
    /// # 에러
    ///
    /// - [`OzError::LoginFailed`] — 세션 ID가 여전히 `"-1905"`인 경우
    /// - `send_request`에서 발생 가능한 모든 에러
    pub async fn login(&self) -> Result<LoginResponse> {
        let req = LoginRequest::new(&self.username, &self.password);
        let session_id = self
            .session
            .read()
            .expect("session lock poisoned")
            .session_id
            .clone();
        let req_buf = req.build(&session_id)?;
        let resp_buf = self.send_request(req_buf).await?;
        let response = LoginResponse::parse(&resp_buf)?;

        if let Some(sid) = response.header.session_id() {
            self.session
                .write()
                .expect("session lock poisoned")
                .session_id = sid.to_string();
        }

        // NOTE: If session ID is still the initial value, login has failed
        let current_session_id = self
            .session
            .read()
            .expect("session lock poisoned")
            .session_id
            .clone();
        if current_session_id == INITIAL_SESSION_ID {
            return Err(OzError::LoginFailed {
                session_id: current_session_id,
            });
        }

        Ok(response)
    }

    /// Repository 파일(.ozr, .odi)을 다운로드합니다.
    ///
    /// 내부적으로 [`send`](Self::send)를 사용하여 [`RepositoryRequest`]를 전송하고,
    /// 응답에서 raw 바이트를 추출하여 반환합니다.
    ///
    /// # 인자
    ///
    /// - `path`: 리포지토리 경로 (예: `"/CM/report_name.ozr"`)
    ///
    /// # 에러
    ///
    /// - [`OzError::NotAuthenticated`] — 로그인되지 않은 상태
    /// - `send`에서 발생 가능한 모든 에러
    pub async fn fetch_repository(&self, path: &str) -> Result<Vec<u8>> {
        let req = RepositoryRequest::new(path);
        let resp = self.send(&req).await?;
        Ok(resp.into_data())
    }

    /// DataModule 데이터를 조회합니다.
    ///
    /// 내부적으로 [`send`](Self::send)를 사용하여 [`DataModuleRequest`]를 전송하고,
    /// [`DataModuleResponse`]를 반환합니다.
    ///
    /// # 인자
    ///
    /// - `odi_name`: ODI 파일명 (예: `"report_name.odi"`)
    /// - `category`: 카테고리 (예: `"/CM"`)
    /// - `params`: 쿼리 파라미터 (키-값 쌍)
    ///
    /// # 에러
    ///
    /// - [`OzError::NotAuthenticated`] — 로그인되지 않은 상태
    /// - `send`에서 발생 가능한 모든 에러
    pub async fn fetch_data_module(
        &self,
        odi_name: &str,
        category: &str,
        params: &[(String, String)],
    ) -> Result<DataModuleResponse> {
        let req = DataModuleRequest {
            odi_name: odi_name.to_string(),
            category: category.to_string(),
            params: params.to_vec(),
        };
        self.send(&req).await
    }

    /// DataModule 데이터를 간결 요청(서브타입 382)으로 조회합니다.
    ///
    /// [`fetch_data_module`](Self::fetch_data_module)과 동일한 응답을 반환하지만,
    /// 파라미터 없이 간결한 요청을 전송합니다.
    /// 서버가 파라미터 없이 데이터를 반환할 수 있는 경우에 사용하세요.
    ///
    /// # 인자
    ///
    /// - `odi_name`: ODI 파일명 (예: `"report_name.odi"`)
    /// - `category`: 카테고리 (예: `"/CM"`)
    ///
    /// # 에러
    ///
    /// - [`OzError::NotAuthenticated`] — 로그인되지 않은 상태
    /// - `send`에서 발생 가능한 모든 에러
    pub async fn fetch_data_module_compact(
        &self,
        odi_name: &str,
        category: &str,
    ) -> Result<DataModuleResponse> {
        let req = CompactDataModuleRequest {
            odi_name: odi_name.to_string(),
            category: category.to_string(),
        };
        self.send(&req).await
    }

    /// 트랜잭션을 실행합니다 (파라미터만, 데이터셋 없음).
    ///
    /// 내부적으로 [`send`](Self::send)를 사용하여 [`TransactionRequest`]를 전송하고,
    /// [`TransactionResponse`]를 반환합니다.
    ///
    /// 호출자가 소유권을 이전할 수 있으면 복사 0회, 그렇지 않으면
    /// 호출자가 `.clone()`을 결정합니다.
    ///
    /// # 인자
    ///
    /// - `transaction_name`: 트랜잭션 이름 (예: `"SAVE_ORDER"`)
    /// - `module_name`: 모듈 이름 (예: `"ORDER_MODULE"`)
    /// - `params`: 트랜잭션 파라미터 (키-값 쌍, 소유권 이전)
    ///
    /// # 에러
    ///
    /// - [`OzError::NotAuthenticated`] — 로그인되지 않은 상태
    /// - `send`에서 발생 가능한 모든 에러
    pub async fn execute_transaction(
        &self,
        transaction_name: &str,
        module_name: &str,
        params: Vec<(String, String)>,
    ) -> Result<TransactionResponse> {
        let req = TransactionRequest {
            transaction_name: transaction_name.to_string(),
            module_name: module_name.to_string(),
            params,
            datasets: vec![],
        };
        self.send(&req).await
    }

    /// 데이터셋을 포함하는 트랜잭션을 실행합니다.
    ///
    /// [`execute_transaction`](Self::execute_transaction)과 동일하지만,
    /// [`TransactionDataSet`] 목록을 추가로 전송합니다.
    ///
    /// # 인자
    ///
    /// - `transaction_name`: 트랜잭션 이름 (예: `"SAVE_ORDER"`)
    /// - `module_name`: 모듈 이름 (예: `"ORDER_MODULE"`)
    /// - `params`: 트랜잭션 파라미터 (키-값 쌍, 소유권 이전)
    /// - `datasets`: 전송할 데이터셋 목록
    ///
    /// # 에러
    ///
    /// - [`OzError::NotAuthenticated`] — 로그인되지 않은 상태
    /// - `send`에서 발생 가능한 모든 에러
    pub async fn execute_transaction_with_datasets(
        &self,
        transaction_name: &str,
        module_name: &str,
        params: Vec<(String, String)>,
        datasets: Vec<TransactionDataSet>,
    ) -> Result<TransactionResponse> {
        let req = TransactionRequest {
            transaction_name: transaction_name.to_string(),
            module_name: module_name.to_string(),
            params,
            datasets,
        };
        self.send(&req).await
    }

    /// 테스트용 세션 ID 설정 메서드
    #[cfg(test)]
    fn set_session_id(&self, session_id: &str) {
        self.session
            .write()
            .expect("session lock poisoned")
            .session_id = session_id.to_string();
    }
}

/// OZ 클라이언트 빌더
///
/// [`OzClient`]를 유연하게 구성할 수 있는 빌더 패턴을 제공합니다.
/// 재시도 정책 등 선택적 설정을 체이닝 방식으로 구성할 수 있습니다.
///
/// # 예시
///
/// ```no_run
/// use ozra::client::{OzClientBuilder, RetryPolicy};
/// use std::time::Duration;
///
/// # fn example() -> ozra::Result<()> {
/// let client = OzClientBuilder::new("https://example.com/oz70", "guest", "guest")
///     .retry_policy(RetryPolicy::new(3, Duration::from_millis(100)))
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct OzClientBuilder {
    base_url: String,
    username: String,
    password: String,
    retry_policy: RetryPolicy,
}

impl OzClientBuilder {
    /// 새 빌더를 생성합니다.
    ///
    /// 기본 재시도 정책은 재시도 없음(`RetryPolicy::default()`)입니다.
    pub fn new(base_url: &str, username: &str, password: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            username: username.to_string(),
            password: password.to_string(),
            retry_policy: RetryPolicy::default(),
        }
    }

    /// 재시도 정책을 설정합니다.
    ///
    /// # 인자
    ///
    /// - `policy`: 적용할 [`RetryPolicy`]
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// [`OzClient`]를 빌드합니다.
    ///
    /// reqwest::Client를 생성하고 설정된 값들로 `OzClient`를 구성합니다.
    ///
    /// # 에러
    ///
    /// - [`OzError::Http`] — reqwest 클라이언트 빌드 실패
    pub fn build(self) -> Result<OzClient> {
        let http = Client::builder()
            .cookie_store(true)
            .user_agent(USER_AGENT)
            .build()?;

        Ok(OzClient {
            http,
            base_url: self.base_url,
            session: RwLock::new(SessionState::new()),
            username: self.username,
            password: self.password,
            retry_policy: self.retry_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{INITIAL_SESSION_ID, REQUEST_FRAME_SIZE};
    use crate::messages::{
        CompactDataModuleRequest, DataModuleRequest, LoginRequest, OzRequest, RepositoryRequest,
    };

    #[test]
    fn test_oz_client_new_default_session() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        assert_eq!(client.session_id(), INITIAL_SESSION_ID);
        assert!(!client.is_authenticated());
        assert_eq!(client.base_url, "https://example.com/oz70");
        assert_eq!(client.username, "guest");
        assert_eq!(client.password, "guest");
    }

    #[test]
    fn test_oz_client_new_trailing_slash_trimmed() {
        let client = OzClient::new("https://example.com/oz70/", "guest", "guest").unwrap();
        assert_eq!(client.base_url, "https://example.com/oz70");
    }

    #[test]
    fn test_oz_client_new_custom_credentials() {
        let client = OzClient::new("https://test.com/oz", "admin", "s3cret").unwrap();
        assert_eq!(client.username, "admin");
        assert_eq!(client.password, "s3cret");
        assert_eq!(client.session_id(), INITIAL_SESSION_ID);
    }

    #[test]
    fn test_is_authenticated_false_initially() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        assert!(!client.is_authenticated());
    }

    #[test]
    fn test_is_authenticated_true_after_session_update() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        client.set_session_id("abc123");
        assert!(client.is_authenticated());
    }

    #[test]
    fn test_login_request_builds_correctly() {
        // LoginRequest trait 기반 빌드 검증
        let req = LoginRequest::new("guest", "guest");
        let buf = req.build(INITIAL_SESSION_ID).unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_repository_request_builds_correctly() {
        // RepositoryRequest trait 기반 빌드 검증
        let req = RepositoryRequest::new("/CM/test.ozr");
        let buf = req.build("12345").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_data_module_request_builds_correctly() {
        // DataModuleRequest trait 기반 빌드 검증
        let params = vec![
            ("arg1".to_string(), "2026".to_string()),
            ("arg2".to_string(), "090".to_string()),
        ];
        let req = DataModuleRequest {
            odi_name: "test.odi".to_string(),
            category: "/CM".to_string(),
            params,
        };
        let buf = req.build("12345").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_session_id_initial_value() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        assert_eq!(client.session_id(), "-1905");
    }

    #[test]
    fn test_multiple_clients_independent() {
        let client1 = OzClient::new("https://server1.com/oz70", "guest", "guest").unwrap();
        let client2 = OzClient::new("https://server2.com/oz70", "guest", "guest").unwrap();

        client1.set_session_id("sess_1");
        assert!(client1.is_authenticated());
        assert!(!client2.is_authenticated());
        assert_eq!(client2.session_id(), INITIAL_SESSION_ID);
    }

    /// send는 인증 전에 NotAuthenticated를 반환해야 함
    #[tokio::test]
    async fn test_send_not_authenticated() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        let req = RepositoryRequest::new("/CM/test.ozr");
        let err = client.send(&req).await.unwrap_err();
        assert!(matches!(err, OzError::NotAuthenticated));
    }

    /// fetch_repository는 인증 전에 NotAuthenticated를 반환해야 함
    #[tokio::test]
    async fn test_fetch_repository_not_authenticated() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        let err = client.fetch_repository("/CM/test.ozr").await.unwrap_err();
        assert!(matches!(err, OzError::NotAuthenticated));
    }

    /// fetch_data_module는 인증 전에 NotAuthenticated를 반환해야 함
    #[tokio::test]
    async fn test_fetch_data_module_not_authenticated() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        let params = vec![("arg1".to_string(), "val".to_string())];
        let err = client
            .fetch_data_module("test.odi", "/CM", &params)
            .await
            .unwrap_err();
        assert!(matches!(err, OzError::NotAuthenticated));
    }

    /// send with DataModuleRequest는 인증 전에 NotAuthenticated를 반환해야 함
    #[tokio::test]
    async fn test_send_data_module_not_authenticated() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        let req = DataModuleRequest {
            odi_name: "test.odi".to_string(),
            category: "/CM".to_string(),
            params: vec![("arg1".to_string(), "val".to_string())],
        };
        let err = client.send(&req).await.unwrap_err();
        assert!(matches!(err, OzError::NotAuthenticated));
    }

    #[test]
    fn test_compact_data_module_request_builds_correctly() {
        let req = CompactDataModuleRequest {
            odi_name: "test.odi".to_string(),
            category: "/CM".to_string(),
        };
        let buf = req.build("12345").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    /// fetch_data_module_compact는 인증 전에 NotAuthenticated를 반환해야 함
    #[tokio::test]
    async fn test_fetch_data_module_compact_not_authenticated() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        let err = client
            .fetch_data_module_compact("test.odi", "/CM")
            .await
            .unwrap_err();
        assert!(matches!(err, OzError::NotAuthenticated));
    }

    /// send with CompactDataModuleRequest는 인증 전에 NotAuthenticated를 반환해야 함
    #[tokio::test]
    async fn test_send_compact_data_module_not_authenticated() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        let req = CompactDataModuleRequest {
            odi_name: "test.odi".to_string(),
            category: "/CM".to_string(),
        };
        let err = client.send(&req).await.unwrap_err();
        assert!(matches!(err, OzError::NotAuthenticated));
    }

    // ── §5 SessionState 스레드 안전성 및 상태 전이 테스트 ──

    /// 여러 스레드에서 동시에 session_id를 읽어도 안전한지 검증
    #[test]
    fn test_session_state_concurrent_reads() {
        use std::sync::Arc;
        use std::thread;

        let client = Arc::new(OzClient::new("https://example.com/oz70", "guest", "guest").unwrap());
        client.set_session_id("concurrent_session");

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let c = Arc::clone(&client);
                thread::spawn(move || {
                    assert_eq!(c.session_id(), "concurrent_session");
                    assert!(c.is_authenticated());
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }

    /// 한 스레드에서 쓰고 다른 스레드에서 읽는 동시성 검증
    #[test]
    fn test_session_state_concurrent_write_read() {
        use std::sync::Arc;
        use std::thread;

        let client = Arc::new(OzClient::new("https://example.com/oz70", "guest", "guest").unwrap());

        let writer = {
            let c = Arc::clone(&client);
            thread::spawn(move || {
                c.set_session_id("new_session_42");
            })
        };

        writer.join().unwrap();

        // writer가 완료된 후 session_id가 업데이트되었는지 확인
        assert_eq!(client.session_id(), "new_session_42");
        assert!(client.is_authenticated());
    }

    /// 세션 상태 전이: 초기 → 인증 → 재인증
    #[test]
    fn test_session_state_transitions() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();

        // 1. 초기 상태: 미인증
        assert_eq!(client.session_id(), INITIAL_SESSION_ID);
        assert!(!client.is_authenticated());

        // 2. 인증 후
        client.set_session_id("session_abc");
        assert_eq!(client.session_id(), "session_abc");
        assert!(client.is_authenticated());

        // 3. 다른 세션으로 재인증
        client.set_session_id("session_xyz");
        assert_eq!(client.session_id(), "session_xyz");
        assert!(client.is_authenticated());
    }

    /// INITIAL_SESSION_ID로 되돌리면 미인증 상태로 복귀
    #[test]
    fn test_session_state_revert_to_initial() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();

        client.set_session_id("authenticated_session");
        assert!(client.is_authenticated());

        // INITIAL_SESSION_ID로 되돌림
        client.set_session_id(INITIAL_SESSION_ID);
        assert!(!client.is_authenticated());
        assert_eq!(client.session_id(), INITIAL_SESSION_ID);
    }

    /// 빈 문자열 세션 ID → 인증 상태 (INITIAL_SESSION_ID와 다르므로)
    #[test]
    fn test_session_state_empty_string_is_authenticated() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        client.set_session_id("");
        // 빈 문자열은 INITIAL_SESSION_ID("-1905")와 다르므로 인증으로 간주
        assert!(client.is_authenticated());
        assert_eq!(client.session_id(), "");
    }

    /// 여러 스레드에서 순차적으로 session_id를 갱신하는 스트레스 테스트
    #[test]
    fn test_session_state_sequential_updates_from_threads() {
        use std::sync::Arc;
        use std::thread;

        let client = Arc::new(OzClient::new("https://example.com/oz70", "guest", "guest").unwrap());

        for i in 0..20 {
            let c = Arc::clone(&client);
            let handle = thread::spawn(move || {
                c.set_session_id(&format!("session_{i}"));
            });
            handle.join().unwrap();
        }

        // 마지막 업데이트가 반영되어야 함
        assert_eq!(client.session_id(), "session_19");
        assert!(client.is_authenticated());
    }

    /// OzClient가 Send + Sync인지 컴파일 타임 검증
    #[test]
    fn test_oz_client_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OzClient>();
    }

    // ── RetryPolicy 테스트 ──────────────────────────────────────────

    #[test]
    fn test_retry_policy_default_no_retries() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 0);
        assert_eq!(policy.base_delay, Duration::from_millis(100));
        assert_eq!(policy.max_delay, Duration::from_secs(30));
        assert_eq!(policy.backoff_factor, 2.0);
    }

    #[test]
    fn test_retry_policy_new() {
        let policy = RetryPolicy::new(3, Duration::from_millis(200));
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.base_delay, Duration::from_millis(200));
        // 기본값 유지
        assert_eq!(policy.max_delay, Duration::from_secs(30));
        assert_eq!(policy.backoff_factor, 2.0);
    }

    #[test]
    fn test_retry_policy_delay_for_attempt_exponential() {
        let policy = RetryPolicy::new(5, Duration::from_millis(100));

        // attempt 0: 100ms × 2^0 = 100ms
        assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(100));
        // attempt 1: 100ms × 2^1 = 200ms
        assert_eq!(policy.delay_for_attempt(1), Duration::from_millis(200));
        // attempt 2: 100ms × 2^2 = 400ms
        assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(400));
        // attempt 3: 100ms × 2^3 = 800ms
        assert_eq!(policy.delay_for_attempt(3), Duration::from_millis(800));
    }

    #[test]
    fn test_retry_policy_delay_capped_at_max() {
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            backoff_factor: 10.0,
        };

        // attempt 0: 1s × 10^0 = 1s (max_delay 이하)
        assert_eq!(policy.delay_for_attempt(0), Duration::from_secs(1));
        // attempt 1: 1s × 10^1 = 10s → capped at 5s
        assert_eq!(policy.delay_for_attempt(1), Duration::from_secs(5));
        // attempt 2: 1s × 10^2 = 100s → capped at 5s
        assert_eq!(policy.delay_for_attempt(2), Duration::from_secs(5));
    }

    #[test]
    fn test_retry_policy_clone() {
        let policy = RetryPolicy::new(3, Duration::from_millis(100));
        let cloned = policy.clone();
        assert_eq!(cloned.max_retries, 3);
        assert_eq!(cloned.base_delay, Duration::from_millis(100));
    }

    #[test]
    fn test_retry_policy_debug() {
        let policy = RetryPolicy::default();
        let debug_str = format!("{:?}", policy);
        assert!(debug_str.contains("RetryPolicy"));
        assert!(debug_str.contains("max_retries"));
    }

    // ── OzClientBuilder 테스트 ──────────────────────────────────────

    #[test]
    fn test_builder_default_retry_policy() {
        let client = OzClientBuilder::new("https://example.com/oz70", "guest", "guest")
            .build()
            .unwrap();
        assert_eq!(client.retry_policy().max_retries, 0);
    }

    #[test]
    fn test_builder_custom_retry_policy() {
        let policy = RetryPolicy::new(5, Duration::from_millis(500));
        let client = OzClientBuilder::new("https://example.com/oz70", "guest", "guest")
            .retry_policy(policy)
            .build()
            .unwrap();
        assert_eq!(client.retry_policy().max_retries, 5);
        assert_eq!(client.retry_policy().base_delay, Duration::from_millis(500));
    }

    #[test]
    fn test_builder_trailing_slash_trimmed() {
        let client = OzClientBuilder::new("https://example.com/oz70/", "guest", "guest")
            .build()
            .unwrap();
        assert_eq!(client.base_url, "https://example.com/oz70");
    }

    #[test]
    fn test_builder_credentials() {
        let client = OzClientBuilder::new("https://example.com/oz70", "admin", "s3cret")
            .build()
            .unwrap();
        assert_eq!(client.username, "admin");
        assert_eq!(client.password, "s3cret");
    }

    #[test]
    fn test_builder_initial_session_state() {
        let client = OzClientBuilder::new("https://example.com/oz70", "guest", "guest")
            .build()
            .unwrap();
        assert_eq!(client.session_id(), INITIAL_SESSION_ID);
        assert!(!client.is_authenticated());
    }

    #[test]
    fn test_oz_client_new_uses_default_retry_policy() {
        // OzClient::new는 OzClientBuilder를 통해 생성되므로 기본 RetryPolicy 사용
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        assert_eq!(client.retry_policy().max_retries, 0);
    }

    /// send_request는 재시도 불가능한 에러에 대해 즉시 반환해야 함 (NotAuthenticated)
    #[tokio::test]
    async fn test_send_not_retryable_error_no_retry() {
        let policy = RetryPolicy::new(3, Duration::from_millis(10));
        let client = OzClientBuilder::new("https://example.com/oz70", "guest", "guest")
            .retry_policy(policy)
            .build()
            .unwrap();
        // NotAuthenticated는 재시도 불가능
        let req = RepositoryRequest::new("/CM/test.ozr");
        let err = client.send(&req).await.unwrap_err();
        assert!(matches!(err, OzError::NotAuthenticated));
    }

    /// HttpStatus 5xx는 재시도 가능
    #[test]
    fn test_http_status_5xx_is_retryable() {
        let err = OzError::HttpStatus { status: 500 };
        assert!(err.is_retryable());

        let err = OzError::HttpStatus { status: 502 };
        assert!(err.is_retryable());

        let err = OzError::HttpStatus { status: 503 };
        assert!(err.is_retryable());
    }

    /// HttpStatus 4xx는 재시도 불가능 (408, 429 제외)
    #[test]
    fn test_http_status_4xx_not_retryable() {
        let err = OzError::HttpStatus { status: 400 };
        assert!(!err.is_retryable());

        let err = OzError::HttpStatus { status: 401 };
        assert!(!err.is_retryable());

        let err = OzError::HttpStatus { status: 404 };
        assert!(!err.is_retryable());
    }

    /// HttpStatus 408 (Request Timeout), 429 (Too Many Requests)는 재시도 가능
    #[test]
    fn test_http_status_408_429_retryable() {
        let err = OzError::HttpStatus { status: 408 };
        assert!(err.is_retryable());

        let err = OzError::HttpStatus { status: 429 };
        assert!(err.is_retryable());
    }
}
