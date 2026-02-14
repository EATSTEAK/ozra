//! OZ 프로토콜 메시지의 공통 헤더 빌더 및 파서
//!
//! 모든 요청/응답 메시지에서 공유되는 헤더 구조를 처리합니다.
//!
//! ## 헤더 구조
//!
//! ```text
//! +---------------+-------------------+-------------+------------------+
//! | Magic (4B)    | ClassName (UTF-16)| FieldCount  | Fields (KV pairs)|
//! | 0x00002711    | 4B len + N×2B     | (4B)        | UTF-16BE pairs   |
//! +---------------+-------------------+-------------+------------------+
//! ```

use crate::constants::{
    CLIENT_VERSION, FIELD_D_DEFAULT, FIELD_R_DEFAULT, FIELD_RV_DEFAULT, MAGIC, MAX_FIELD_COUNT,
};
use crate::error::{OzError, Result};
use crate::types::OzMessageHeader;
use crate::wire::{BufReader, BufWriter};

/// 공통 16개 필드를 생성합니다.
///
/// OZ 프로토콜의 모든 요청 메시지는 동일한 16개 헤더 필드를 사용합니다.
/// 이 함수는 기본값으로 채워진 필드 목록을 반환합니다.
///
/// # Arguments
///
/// * `username` - 사용자명 (기본: "guest")
/// * `password` - 비밀번호 (기본: "guest")
/// * `session_id` - 세션 ID (로그인 전에는 "-1905")
///
/// # 필드 목록
///
/// | 키 | 설명 | 기본값 |
/// |---|---|---|
/// | `un` | 사용자명 | (인자로 전달) |
/// | `p` | 비밀번호 | (인자로 전달) |
/// | `s` | 세션 ID | (인자로 전달) |
/// | `cv` | 클라이언트 버전 | "20140527" |
/// | `t`, `i`, `o`, `z`, `j` | 예약 필드 | "" |
/// | `d` | 디버그 플래그 | "-1" |
/// | `r` | 재시도 플래그 | "1" |
/// | `rv` | 버전 플래그 | "268435456" |
/// | `xi`, `xm`, `xh`, `pi` | 확장 필드 | "" |
fn common_fields<'a>(
    username: &'a str,
    password: &'a str,
    session_id: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("un", username),
        ("p", password),
        ("s", session_id),
        ("cv", CLIENT_VERSION),
        ("t", ""),
        ("i", ""),
        ("o", ""),
        ("z", ""),
        ("j", ""),
        ("d", FIELD_D_DEFAULT),
        ("r", FIELD_R_DEFAULT),
        ("rv", FIELD_RV_DEFAULT),
        ("xi", ""),
        ("xm", ""),
        ("xh", ""),
        ("pi", ""),
    ]
}

/// 인증 정보를 포함한 공통 헤더를 작성합니다.
///
/// [`write_common_header`]와 동일하나, 사용자명/비밀번호를 직접 지정할 수 있습니다.
/// 로그인 요청 등 커스텀 인증 정보가 필요한 경우 사용합니다.
///
/// # Arguments
///
/// * `writer` - 바이너리 데이터를 쓸 BufWriter
/// * `class_name` - 요청 클래스명
/// * `username` - 사용자명
/// * `password` - 비밀번호
/// * `session_id` - 세션 ID
pub fn write_common_header_with_auth(
    writer: &mut BufWriter,
    class_name: &str,
    username: &str,
    password: &str,
    session_id: &str,
) -> Result<()> {
    writer.write_u32(MAGIC)?;
    writer.write_utf16be(class_name)?;

    let fields = common_fields(username, password, session_id);
    writer.write_u32(fields.len() as u32)?;
    for (key, value) in fields {
        writer.write_utf16be(key)?;
        writer.write_utf16be(value)?;
    }

    Ok(())
}

/// 공통 헤더를 작성합니다.
///
/// 모든 OZ 요청 메시지의 공통 헤더를 BufWriter에 기록합니다.
/// 사용자명/비밀번호는 "guest"/"guest"로 기본 설정됩니다.
///
/// # 헤더 형식
///
/// ```text
/// write_u32(MAGIC)           // 0x00002711
/// write_utf16be(class_name)  // 클래스명
/// write_u32(field_count)     // 16
/// for each (key, value):
///   write_utf16be(key)
///   write_utf16be(value)
/// ```
///
/// # Arguments
///
/// * `writer` - 바이너리 데이터를 쓸 BufWriter
/// * `class_name` - 요청 클래스명 (예: "oz.framework.cp.message.repository.OZRepositoryRequestUserLogin")
/// * `session_id` - 세션 ID
///
/// # Errors
///
/// - [`OzError::BufferOverflow`]: 버퍼 크기 초과
///
/// # 예시
///
/// ```ignore
/// use ozra::wire::BufWriter;
/// use ozra::messages::common::write_common_header;
///
/// let mut writer = BufWriter::new();
/// write_common_header(&mut writer, "TestClass", "-1905")?;
/// ```
pub fn write_common_header(
    writer: &mut BufWriter,
    class_name: &str,
    session_id: &str,
) -> Result<()> {
    write_common_header_with_auth(writer, class_name, "guest", "guest", session_id)
}

/// 응답 헤더를 파싱합니다.
///
/// OZ 응답 메시지의 공통 헤더를 BufReader에서 읽어 [`OzMessageHeader`]로 반환합니다.
///
/// # 형식
///
/// ```text
/// 1. magic = read_u32()
/// 2. magic != MAGIC → OzError::InvalidMagic
/// 3. class_name = read_utf16be()
/// 4. field_count = read_u32()
/// 5. fields = Vec::new()
/// 6. for _ in 0..field_count:
///      key = read_utf16be()
///      value = read_utf16be()
///      fields.push((key, value))
/// 7. return OzMessageHeader { magic, class_name, fields }
/// ```
///
/// # Arguments
///
/// * `reader` - 응답 바이너리를 읽을 BufReader
///
/// # Errors
///
/// - [`OzError::InvalidMagic`]: 매직 넘버 불일치
/// - [`OzError::TooManyFields`]: 필드 수가 허용 한도 초과 (DoS 방어)
/// - [`OzError::UnexpectedEof`]: 버퍼 부족
///
/// # 예시
///
/// ```ignore
/// use ozra::wire::BufReader;
/// use ozra::messages::common::parse_header;
///
/// let mut reader = BufReader::new(&response_buf);
/// let header = parse_header(&mut reader)?;
/// println!("Class: {}", header.class_name);
/// ```
pub fn parse_header(reader: &mut BufReader) -> Result<OzMessageHeader> {
    let magic = reader.read_u32()?;
    if magic != MAGIC {
        return Err(OzError::InvalidMagic {
            expected: MAGIC,
            actual: magic,
        });
    }

    let class_name = reader.read_utf16be()?;
    let field_count = reader.read_u32()? as usize;

    // DoS 방어: 필드 수가 너무 많으면 거부
    if field_count > MAX_FIELD_COUNT {
        return Err(OzError::TooManyFields {
            count: field_count,
            max: MAX_FIELD_COUNT,
        });
    }

    let mut fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        let key = reader.read_utf16be()?;
        let value = reader.read_utf16be()?;
        fields.push((key, value));
    }

    Ok(OzMessageHeader {
        magic,
        class_name,
        fields,
    })
}

/// 예외 응답을 파싱하여 [`OzError`]로 변환합니다.
///
/// OZ 서버가 에러를 반환할 때 사용하는 예외 메시지 형식을 파싱합니다.
/// 헤더 파싱 이후, 클래스명에 "ExceptionMessage"가 포함된 경우 호출됩니다.
///
/// # 예외 메시지 형식
///
/// ```text
/// [헤더 이후]
/// error_code: i32        // 에러 코드
/// msg_len: u32           // 메시지 문자 수
/// message: UTF-16BE      // 에러 메시지 (msg_len × 2 바이트)
/// ```
///
/// # Arguments
///
/// * `reader` - 헤더 이후 위치의 BufReader
///
/// # Returns
///
/// 파싱된 에러 정보를 담은 [`OzError::ProtocolError`]
///
/// # 예시
///
/// ```ignore
/// use ozra::messages::common::{parse_header, parse_exception};
///
/// let header = parse_header(&mut reader)?;
/// if header.class_name.contains("ExceptionMessage") {
///     return Err(parse_exception(&mut reader)?);
/// }
/// ```
pub fn parse_exception(reader: &mut BufReader) -> Result<OzError> {
    let error_code = reader.read_i32()?;
    let msg_len = reader.read_u32()? as usize;
    let msg_bytes = reader.read_bytes(msg_len * 2)?;

    let mut u16_buf = Vec::with_capacity(msg_len);
    for i in 0..msg_len {
        u16_buf.push(u16::from_be_bytes([msg_bytes[i * 2], msg_bytes[i * 2 + 1]]));
    }

    let message =
        String::from_utf16(&u16_buf).unwrap_or_else(|_| "unparseable message".to_string());

    Ok(OzError::ProtocolError {
        code: error_code,
        message,
    })
}

/// 응답 바이너리에서 에러 필드를 파싱합니다 (내부 공통 로직).
///
/// 처음 200바이트를 UTF-16BE 프로브하여 `"ExceptionMessage"` 포함 여부를 확인하고,
/// 에러가 감지되면 에러 코드와 메시지를 한 번만 파싱하여 반환합니다.
///
/// # Returns
///
/// - `Some((error_code, message))`: 에러가 감지된 경우
/// - `None`: 정상 응답인 경우
fn parse_error_fields(buf: &[u8]) -> Option<(i32, String)> {
    // 처음 200바이트를 2바이트씩 UTF-16BE로 디코딩
    let probe_len = buf.len().min(200);
    // probe_len이 홀수이면 짝수로 맞춤
    let probe_bytes = probe_len & !1;
    if probe_bytes < 2 {
        return None;
    }

    let mut probe = String::with_capacity(probe_bytes / 2);
    for i in (0..probe_bytes).step_by(2) {
        let code_unit = u16::from_be_bytes([buf[i], buf[i + 1]]);
        if let Some(ch) = char::from_u32(code_unit as u32) {
            probe.push(ch);
        }
    }

    if !probe.contains("ExceptionMessage") {
        return None;
    }

    // Exception format: magic(4) + className(4+N*2) + errorCode(4) + msgLen(4) + message(N*2)
    let result: Result<(i32, String)> = (|| {
        let mut reader = BufReader::new(buf);
        let _magic = reader.read_u32()?; // skip magic
        let _class_name = reader.read_utf16be()?; // skip className
        let error_code = reader.read_i32()?;
        let msg_len = reader.read_u32()? as usize;
        let byte_len = msg_len * 2;
        let msg_bytes = reader.read_bytes(byte_len)?;
        let mut u16_buf = Vec::with_capacity(msg_len);
        for i in 0..msg_len {
            u16_buf.push(u16::from_be_bytes([msg_bytes[i * 2], msg_bytes[i * 2 + 1]]));
        }
        let msg =
            String::from_utf16(&u16_buf).unwrap_or_else(|_| "unparseable message".to_string());
        Ok((error_code, msg))
    })();

    match result {
        Ok(fields) => Some(fields),
        Err(_) => Some((-1, "OZ Error (unparseable)".to_string())),
    }
}

/// 응답 바이너리에서 에러를 감지합니다.
///
/// 처음 200바이트를 UTF-16BE로 디코딩하여 `"ExceptionMessage"` 포함 여부를 확인합니다.
///
/// 에러가 감지되면 `Some(에러 메시지 문자열)`, 정상이면 `None`을 반환합니다.
///
/// 구조화된 에러가 필요하면 [`check_error_result`]를 사용하세요.
pub fn check_error(buf: &[u8]) -> Option<String> {
    parse_error_fields(buf).map(|(code, msg)| format!("OZ Error {}: {}", code, msg))
}

/// 응답 바이너리에서 에러를 감지하고 [`OzError::ProtocolError`]로 반환합니다.
///
/// [`check_error`]의 `Result` 반환 버전입니다.
/// 에러가 없으면 `Ok(())`, 에러가 감지되면 `Err(OzError::ProtocolError)`를 반환합니다.
///
/// # 예시
///
/// ```no_run
/// use ozra::messages::check_error_result;
///
/// fn handle_response(buf: &[u8]) -> ozra::Result<()> {
///     check_error_result(buf)?;
///     // 정상 응답 처리...
///     Ok(())
/// }
/// ```
pub fn check_error_result(buf: &[u8]) -> Result<()> {
    if let Some((code, message)) = parse_error_fields(buf) {
        return Err(OzError::ProtocolError { code, message });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 공통 헤더만 있는 최소 바이너리를 생성하는 헬퍼
    fn build_minimal_header(class_name: &str, session_id: &str) -> Vec<u8> {
        let mut writer = BufWriter::new();
        write_common_header(&mut writer, class_name, session_id).unwrap();
        let pos = writer.offset();
        let bytes = writer.into_bytes();
        bytes[..pos].to_vec()
    }

    /// 인증 정보를 포함한 헤더 바이너리를 생성하는 헬퍼
    fn build_header_with_auth(
        class_name: &str,
        username: &str,
        password: &str,
        session_id: &str,
    ) -> Vec<u8> {
        let mut writer = BufWriter::new();
        write_common_header_with_auth(&mut writer, class_name, username, password, session_id)
            .unwrap();
        let pos = writer.offset();
        let bytes = writer.into_bytes();
        bytes[..pos].to_vec()
    }

    #[test]
    fn test_common_fields_count() {
        let fields = common_fields("guest", "guest", "-1905");
        assert_eq!(fields.len(), 16);
    }

    #[test]
    fn test_common_fields_session_id() {
        let fields = common_fields("guest", "guest", "test_session");
        let session_field = fields.iter().find(|(k, _)| *k == "s");
        assert_eq!(session_field, Some(&("s", "test_session")));
    }

    #[test]
    fn test_common_fields_username() {
        let fields = common_fields("guest", "guest", "-1905");
        let un_field = fields.iter().find(|(k, _)| *k == "un");
        assert_eq!(un_field, Some(&("un", "guest")));
    }

    #[test]
    fn test_common_fields_password() {
        let fields = common_fields("guest", "guest", "-1905");
        let p_field = fields.iter().find(|(k, _)| *k == "p");
        assert_eq!(p_field, Some(&("p", "guest")));
    }

    #[test]
    fn test_common_fields_client_version() {
        let fields = common_fields("guest", "guest", "-1905");
        let cv_field = fields.iter().find(|(k, _)| *k == "cv");
        assert_eq!(cv_field, Some(&("cv", CLIENT_VERSION)));
    }

    #[test]
    fn test_common_fields_custom_auth() {
        let fields = common_fields("admin", "s3cret", "-1905");
        let un_field = fields.iter().find(|(k, _)| *k == "un");
        assert_eq!(un_field, Some(&("un", "admin")));
        let p_field = fields.iter().find(|(k, _)| *k == "p");
        assert_eq!(p_field, Some(&("p", "s3cret")));
    }

    #[test]
    fn test_write_common_header_magic() {
        let mut writer = BufWriter::new();
        write_common_header(&mut writer, "TestClass", "-1905").unwrap();
        let bytes = writer.as_bytes();
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(magic, MAGIC);
    }

    #[test]
    fn test_write_common_header_class_name() {
        let buf = build_minimal_header("TestClassName", "-1905");
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, "TestClassName");
    }

    #[test]
    fn test_write_common_header_field_count() {
        let buf = build_minimal_header("Test", "-1905");
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let _class_name = reader.read_utf16be().unwrap();
        let field_count = reader.read_u32().unwrap();
        assert_eq!(field_count, 16);
    }

    #[test]
    fn test_write_common_header_with_auth() {
        let buf = build_header_with_auth("TestClass", "admin", "password123", "sess1");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.get_field("un"), Some("admin"));
        assert_eq!(header.get_field("p"), Some("password123"));
        assert_eq!(header.session_id(), Some("sess1"));
    }

    #[test]
    fn test_parse_header_basic() {
        let buf = build_minimal_header("TestClass", "session123");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();

        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.class_name, "TestClass");
        assert_eq!(header.fields.len(), 16);
        assert_eq!(header.session_id(), Some("session123"));
    }

    #[test]
    fn test_parse_header_invalid_magic() {
        let mut buf = vec![0x00, 0x00, 0x00, 0x01]; // wrong magic
        buf.extend_from_slice(&0u32.to_be_bytes()); // empty class name
        buf.extend_from_slice(&0u32.to_be_bytes()); // field count = 0
        let mut reader = BufReader::new(&buf);
        let err = parse_header(&mut reader).unwrap_err();
        assert!(matches!(
            err,
            OzError::InvalidMagic {
                expected: MAGIC,
                actual: 1,
            }
        ));
    }

    #[test]
    fn test_parse_header_roundtrip() {
        let buf = build_minimal_header("oz.framework.TestClass", "-1905");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();

        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.class_name, "oz.framework.TestClass");
        assert_eq!(header.get_field("un"), Some("guest"));
        assert_eq!(header.get_field("p"), Some("guest"));
        assert_eq!(header.get_field("s"), Some("-1905"));
        assert_eq!(header.get_field("cv"), Some(CLIENT_VERSION));
        assert_eq!(header.get_field("d"), Some(FIELD_D_DEFAULT));
        assert_eq!(header.get_field("r"), Some(FIELD_R_DEFAULT));
        assert_eq!(header.get_field("rv"), Some(FIELD_RV_DEFAULT));
    }

    #[test]
    fn test_parse_header_korean_class_name() {
        let buf = build_minimal_header("한글클래스", "세션ID");
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();

        assert_eq!(header.class_name, "한글클래스");
        assert_eq!(header.session_id(), Some("세션ID"));
    }

    #[test]
    fn test_parse_header_empty_fields() {
        // 필드 0개인 헤더 수동 생성
        let mut writer = BufWriter::new();
        writer.write_u32(MAGIC).unwrap();
        writer.write_utf16be("EmptyClass").unwrap();
        writer.write_u32(0).unwrap();
        let pos = writer.offset();
        let bytes = writer.into_bytes();
        let buf = bytes[..pos].to_vec();

        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();

        assert_eq!(header.class_name, "EmptyClass");
        assert_eq!(header.fields.len(), 0);
    }

    #[test]
    fn test_parse_header_korean_values() {
        // 수동으로 한글 필드가 있는 헤더 생성
        let mut writer = BufWriter::new();
        writer.write_u32(MAGIC).unwrap();
        writer.write_utf16be("한글클래스").unwrap();
        writer.write_u32(1).unwrap();
        writer.write_utf16be("이름").unwrap();
        writer.write_utf16be("홍길동").unwrap();
        let pos = writer.offset();
        let bytes = writer.into_bytes();
        let buf = bytes[..pos].to_vec();

        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();

        assert_eq!(header.class_name, "한글클래스");
        assert_eq!(header.get_field("이름"), Some("홍길동"));
    }

    #[test]
    fn test_parse_exception_basic() {
        let mut writer = BufWriter::new();
        // 에러 코드
        writer.write_i32(-1).unwrap();
        // 메시지 길이 (문자 수)
        let msg = "access denied";
        writer.write_u32(msg.len() as u32).unwrap();
        // 메시지 (UTF-16BE)
        for ch in msg.encode_utf16() {
            writer.write_u16(ch).unwrap();
        }

        let buf = writer.into_bytes();
        let mut reader = BufReader::new(&buf);
        let err = parse_exception(&mut reader).unwrap();

        assert!(matches!(err, OzError::ProtocolError { code: -1, .. }));
        assert!(err.to_string().contains("access denied"));
    }

    #[test]
    fn test_parse_exception_korean_message() {
        let mut writer = BufWriter::new();
        writer.write_i32(-999).unwrap();
        let msg = "접근이 거부되었습니다";
        let u16_units: Vec<u16> = msg.encode_utf16().collect();
        writer.write_u32(u16_units.len() as u32).unwrap();
        for ch in &u16_units {
            writer.write_u16(*ch).unwrap();
        }

        let buf = writer.into_bytes();
        let mut reader = BufReader::new(&buf);
        let err = parse_exception(&mut reader).unwrap();

        assert!(matches!(err, OzError::ProtocolError { code: -999, .. }));
        assert!(err.to_string().contains("접근이 거부되었습니다"));
    }

    #[test]
    fn test_parse_exception_empty_message() {
        let mut writer = BufWriter::new();
        writer.write_i32(42).unwrap();
        writer.write_u32(0).unwrap(); // 빈 메시지

        let buf = writer.into_bytes();
        let mut reader = BufReader::new(&buf);
        let err = parse_exception(&mut reader).unwrap();

        assert!(matches!(err, OzError::ProtocolError { code: 42, .. }));
    }

    #[test]
    fn test_check_error_normal_response() {
        let buf = build_minimal_header("NormalResponse", "-1905");
        let result = check_error(&buf);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_error_detects_exception() {
        let mut writer = BufWriter::new();
        writer.write_u32(MAGIC).unwrap();
        writer
            .write_utf16be("oz.framework.OZCPExceptionMessage")
            .unwrap();
        writer.write_i32(-1).unwrap();
        let msg = "access denied";
        writer.write_u32(msg.len() as u32).unwrap();
        for ch in msg.encode_utf16() {
            writer.write_u16(ch).unwrap();
        }
        let buf = writer.into_bytes();
        let result = check_error(&buf);
        assert!(result.is_some());
        let err_msg = result.unwrap();
        assert!(err_msg.contains("OZ Error"));
        assert!(err_msg.contains("-1"));
        assert!(err_msg.contains("access denied"));
    }

    #[test]
    fn test_check_error_empty_buffer() {
        let buf: &[u8] = &[];
        assert!(check_error(buf).is_none());
    }

    #[test]
    fn test_check_error_small_buffer() {
        let buf: &[u8] = &[0x00, 0x01];
        assert!(check_error(buf).is_none());
    }

    #[test]
    fn test_check_error_result_ok_on_normal() {
        let buf = build_minimal_header("NormalResponse", "-1905");
        assert!(check_error_result(&buf).is_ok());
    }

    #[test]
    fn test_check_error_result_err_on_exception() {
        let mut writer = BufWriter::new();
        writer.write_u32(MAGIC).unwrap();
        writer
            .write_utf16be("oz.framework.OZCPExceptionMessage")
            .unwrap();
        writer.write_i32(-99).unwrap();
        let msg = "test error";
        writer.write_u32(msg.len() as u32).unwrap();
        for ch in msg.encode_utf16() {
            writer.write_u16(ch).unwrap();
        }
        let buf = writer.into_bytes();
        let err = check_error_result(&buf).unwrap_err();
        assert!(matches!(err, OzError::ProtocolError { code: -99, .. }));
        assert!(err.to_string().contains("test error"));
    }
}
