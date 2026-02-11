//! HTTP 클라이언트 모듈 — OZ 서버와의 세션 관리 및 5단계 통신 플로우
//!
//! [`OzClient`]는 reqwest 기반 HTTP 클라이언트로, OZ 프로토콜의 전체 통신 플로우를 관리합니다.
//!
//! ## 통신 플로우
//!
//! 1. [`init_session`](OzClient::init_session) — `GET /ozView.jsp` → JSESSIONID 쿠키 획득
//! 2. [`login`](OzClient::login) — UserLogin 요청 → OZ 세션 ID 획득
//! 3. [`fetch_repository`](OzClient::fetch_repository) — .ozr/.odi 파일 다운로드
//! 4. [`fetch_data_module`](OzClient::fetch_data_module) — DataModule 데이터 조회
//! 5. [`fetch_syllabus`](OzClient::fetch_syllabus) — 전체 플로우 통합 편의 메서드

use reqwest::Client;

use crate::codec::{
    build_data_module_request, build_login_request, build_repository_request, check_error_result,
    parse_data_module, parse_header,
};
use crate::constants::{INITIAL_SESSION_ID, USER_AGENT};
use crate::error::{OzError, Result};
use crate::types::{DataModuleResponse, OzMessageHeader};
use crate::wire::BufReader;

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
/// let mut client = OzClient::new(
///     "https://example.com/oz70",
///     "guest",
///     "guest",
/// )?;
/// client.init_session().await?;
/// let header = client.login().await?;
/// println!("Session ID: {:?}", header.session_id());
/// # Ok(())
/// # }
/// ```
pub struct OzClient {
    /// reqwest HTTP 클라이언트 (cookie_store 활성화)
    http: Client,
    /// 서버 기본 URL (예: `"https://example.com/oz70"`)
    base_url: String,
    /// OZ 프로토콜 세션 ID (`"-1905"` → 서버 발급 ID)
    session_id: String,
    /// 로그인 사용자명
    username: String,
    /// 로그인 비밀번호
    password: String,
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
        let http = Client::builder()
            .cookie_store(true)
            .user_agent(USER_AGENT)
            .build()?;

        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            session_id: INITIAL_SESSION_ID.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// 현재 OZ 프로토콜 세션 ID를 반환합니다.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// 인증 여부를 확인합니다 (세션 ID가 초기값이 아닌지).
    pub fn is_authenticated(&self) -> bool {
        self.session_id != INITIAL_SESSION_ID
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
    ///
    /// # 에러
    ///
    /// - [`OzError::Http`] — 네트워크 에러
    /// - [`OzError::HttpStatus`] — 비정상 HTTP 상태 코드
    /// - [`OzError::ProtocolError`] — 서버가 반환한 OZ 프로토콜 에러
    pub async fn send_request(&self, body: Vec<u8>) -> Result<Vec<u8>> {
        let url = format!("{}/server", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("Accept", "*/*")
            .body(body)
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

    /// 로그인하여 OZ 세션 ID를 획득합니다.
    ///
    /// `build_login_request()` → [`send_request()`](Self::send_request) → `parse_header()`
    /// 응답 헤더의 `"s"` 필드에서 세션 ID를 추출하여 내부 상태를 업데이트합니다.
    ///
    /// # 에러
    ///
    /// - [`OzError::LoginFailed`] — 세션 ID가 여전히 `"-1905"`인 경우
    /// - `send_request`에서 발생 가능한 모든 에러
    pub async fn login(&mut self) -> Result<OzMessageHeader> {
        let req_buf = build_login_request(&self.username, &self.password)?;
        let resp_buf = self.send_request(req_buf).await?;

        let mut reader = BufReader::new(&resp_buf);
        let header = parse_header(&mut reader)?;

        if let Some(sid) = header.session_id() {
            self.session_id = sid.to_string();
        }

        // NOTE: If session ID is still the initial value, login has failed
        if self.session_id == INITIAL_SESSION_ID {
            return Err(OzError::LoginFailed {
                session_id: self.session_id.clone(),
            });
        }

        Ok(header)
    }

    /// Repository 파일(.ozr, .odi)을 다운로드합니다.
    ///
    /// `build_repository_request()` → [`send_request()`](Self::send_request)
    ///
    /// # 인자
    ///
    /// - `path`: 리포지토리 경로 (예: `"/CM/report_name.ozr"`)
    ///
    /// # 에러
    ///
    /// - [`OzError::NotAuthenticated`] — 로그인되지 않은 상태
    /// - `send_request`에서 발생 가능한 모든 에러
    pub async fn fetch_repository(&self, path: &str) -> Result<Vec<u8>> {
        if !self.is_authenticated() {
            return Err(OzError::NotAuthenticated);
        }

        let req_buf = build_repository_request(path, &self.session_id)?;
        self.send_request(req_buf).await
    }

    /// DataModule 데이터를 조회합니다.
    ///
    /// `build_data_module_request()` → [`send_request()`](Self::send_request) → `parse_data_module()`
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
    /// - `send_request` 및 `parse_data_module`에서 발생 가능한 모든 에러
    pub async fn fetch_data_module(
        &self,
        odi_name: &str,
        category: &str,
        params: &[(String, String)],
    ) -> Result<DataModuleResponse> {
        if !self.is_authenticated() {
            return Err(OzError::NotAuthenticated);
        }

        let req_buf = build_data_module_request(odi_name, category, params, &self.session_id)?;
        let resp_buf = self.send_request(req_buf).await?;
        parse_data_module(&resp_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{INITIAL_SESSION_ID, REQUEST_FRAME_SIZE};

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
        let mut client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        client.session_id = "abc123".to_string();
        assert!(client.is_authenticated());
    }

    #[test]
    fn test_login_request_builds_correctly() {
        // NOTE: Indirectly verifies that build_login_request is called correctly
        let buf = build_login_request("guest", "guest").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_repository_request_builds_correctly() {
        let buf = build_repository_request("/CM/test.ozr", "12345").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_data_module_request_builds_correctly() {
        let params = vec![
            ("arg1".to_string(), "2026".to_string()),
            ("arg2".to_string(), "090".to_string()),
        ];
        let buf = build_data_module_request("test.odi", "/CM", &params, "12345").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_session_id_initial_value() {
        let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
        assert_eq!(client.session_id(), "-1905");
    }

    #[test]
    fn test_multiple_clients_independent() {
        let mut client1 = OzClient::new("https://server1.com/oz70", "guest", "guest").unwrap();
        let client2 = OzClient::new("https://server2.com/oz70", "guest", "guest").unwrap();

        client1.session_id = "sess_1".to_string();
        assert!(client1.is_authenticated());
        assert!(!client2.is_authenticated());
        assert_eq!(client2.session_id(), INITIAL_SESSION_ID);
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
}
