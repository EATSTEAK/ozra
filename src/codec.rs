//! 프로토콜 코덱 모듈 — OZ 메시지 요청 빌더 + 응답 파서
//!
//! OZ 프로토콜의 요청 메시지를 빌드하고, 응답 메시지를 파싱합니다.
//!
//! ## 요청 빌더
//!
//! - [`build_login_request`] — UserLogin 요청 (9,545바이트)
//! - [`build_repository_request`] — Repository 요청 (9,545바이트)
//! - [`build_data_module_request`] — DataModule 요청 (9,545바이트)
//!
//! ## 응답 파서
//!
//! - [`parse_header`] — 응답 헤더 파싱
//! - [`check_error`] — 에러 응답 감지
//! - [`parse_data_module`] — DataModule 응답 전체 파싱

use crate::constants::{
    CLIENT_VERSION, DATA_MODULE_PREFIX, DATA_MODULE_TYPE_MARKER, FIELD_D_DEFAULT, FIELD_R_DEFAULT,
    FIELD_RV_DEFAULT, INITIAL_SESSION_ID, LOGIN_TRAILING_MARKER, MAGIC, MAX_FIELD_COUNT,
    REPO_HEADER_MARKER, SUB_MAGIC,
};
use crate::error::{OzError, Result};
use crate::field::read_row;
use crate::types::{
    BasicField, DataModuleMeta, DataModuleResponse, DataSet, DataSetGroup, DataSetInfo, FieldKind,
    OzMessageHeader, RecordInfo, SqlType,
};
use crate::wire::{BufReader, BufWriter};

/// 메시지 클래스명 상수
pub mod class_names {
    /// UserLogin 요청 클래스명
    pub const USER_LOGIN: &str = "oz.framework.cp.message.repository.OZRepositoryRequestUserLogin";
    /// Repository 요청 클래스명
    pub const REPOSITORY_ITEM: &str =
        "oz.framework.cp.message.repositoryex.OZRepositoryRequestItem";
    /// DataModule 요청 클래스명
    pub const DATA_MODULE: &str = "oz.framework.cp.message.FrameworkRequestDataModule";
}

/// 공통 16개 필드를 생성합니다.
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

/// 공통 헤더를 writer에 씁니다.
///
/// 형식:
/// ```text
/// write_u32(MAGIC)           // 0x00002711
/// write_utf16be(class_name)  // 클래스명
/// write_u32(field_count)     // 16
/// for each (key, value):
///   write_utf16be(key)
///   write_utf16be(value)
/// ```
fn write_common_header(
    writer: &mut BufWriter,
    class_name: &str,
    fields: &[(&str, &str)],
) -> Result<()> {
    writer.write_u32(MAGIC)?;
    writer.write_utf16be(class_name)?;
    writer.write_u32(fields.len() as u32)?;
    for (key, value) in fields {
        writer.write_utf16be(key)?;
        writer.write_utf16be(value)?;
    }
    Ok(())
}

/// UserLogin 요청 바이너리를 빌드합니다 (9,545바이트).
///
/// - ClassName: [`class_names::USER_LOGIN`]
/// - 공통 헤더 (session="-1905") + trailing marker [`LOGIN_TRAILING_MARKER`] (0xB0)
/// - 결과: [`REQUEST_FRAME_SIZE`] (9,545바이트) 고정 크기
///
/// # 예시
///
/// ```
/// use ozra::codec::build_login_request;
/// use ozra::constants::REQUEST_FRAME_SIZE;
///
/// let buf = build_login_request("guest", "guest").unwrap();
/// assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
/// ```
pub fn build_login_request(username: &str, password: &str) -> Result<Vec<u8>> {
    let mut writer = BufWriter::new();
    let fields = common_fields(username, password, INITIAL_SESSION_ID);
    write_common_header(&mut writer, class_names::USER_LOGIN, &fields)?;
    writer.write_u32(LOGIN_TRAILING_MARKER)?;
    Ok(writer.into_bytes())
}

/// Repository 요청 바이너리를 빌드합니다 (9,545바이트).
///
/// - ClassName: [`class_names::REPOSITORY_ITEM`]
/// - 공통 헤더 + payload:
///   ```text
///   write_u32(0x100)      // REPO_HEADER_MARKER
///   write_u32(0x00)
///   write_u16(0x00)
///   write_utf16be(path)   // e.g. "/forcs/test.ozr"
///   ```
///
/// # 예시
///
/// ```
/// use ozra::codec::build_repository_request;
/// use ozra::constants::REQUEST_FRAME_SIZE;
///
/// let buf = build_repository_request("/CM/test.ozr", "12345").unwrap();
/// assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
/// ```
pub fn build_repository_request(path: &str, session_id: &str) -> Result<Vec<u8>> {
    let mut writer = BufWriter::new();
    let fields = common_fields("guest", "guest", session_id);
    write_common_header(&mut writer, class_names::REPOSITORY_ITEM, &fields)?;

    // Repository payload
    writer.write_u32(REPO_HEADER_MARKER)?;
    writer.write_u32(0x00)?;
    writer.write_u16(0x00)?;
    writer.write_utf16be(path)?;

    Ok(writer.into_bytes())
}

/// DataModule 요청 바이너리를 빌드합니다 (9,545바이트).
///
/// - ClassName: [`class_names::DATA_MODULE`]
/// - 공통 헤더 + payload
///
/// # 예시
///
/// ```
/// use ozra::codec::build_data_module_request;
/// use ozra::constants::REQUEST_FRAME_SIZE;
///
/// let params = vec![("arg1".to_string(), "2026".to_string())];
/// let buf = build_data_module_request("test.odi", "/CM", &params, "12345").unwrap();
/// assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
/// ```
pub fn build_data_module_request(
    odi_name: &str,
    category: &str,
    params: &[(String, String)],
    session_id: &str,
) -> Result<Vec<u8>> {
    let mut writer = BufWriter::new();
    let fields = common_fields("guest", "guest", session_id);
    write_common_header(&mut writer, class_names::DATA_MODULE, &fields)?;

    // NOTE: DataModule payload — corresponds to JS writeDataModulePayload
    writer.write_u32(DATA_MODULE_TYPE_MARKER)?; // 0x17C = 380
    writer.write_utf16be(odi_name)?;
    writer.write_u32(SUB_MAGIC)?; // 0x2710
    writer.write_utf16be(category)?;
    writer.write_u8(0x00)?; // T1E = false
    writer.write_u8(0x00)?; // w0J = false
    writer.write_utf16be("")?; // DPk = empty string
    writer.write_u32(params.len() as u32)?;
    for (key, value) in params {
        writer.write_utf16be(key)?;
        writer.write_utf16be(value)?;
    }
    // trailing constants
    writer.write_u32(2)?;
    writer.write_u32(0x20)?;
    writer.write_u32(0x11)?;

    Ok(writer.into_bytes())
}

/// 응답에서 OZ 메시지 헤더를 파싱합니다.
///
/// 형식:
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
/// # 에러
///
/// - [`OzError::InvalidMagic`] — 매직 넘버 불일치
/// - [`OzError::UnexpectedEof`] — 버퍼 부족
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

/// 응답 바이너리에서 에러를 감지합니다.
///
/// 처음 200바이트를 UTF-16BE로 디코딩하여 `"ExceptionMessage"` 포함 여부를 확인합니다.
///
/// 에러가 감지되면 `Some(에러 메시지 문자열)`, 정상이면 `None`을 반환합니다.
///
/// 구조화된 에러가 필요하면 [`check_error_result`]를 사용하세요.
pub fn check_error(buf: &[u8]) -> Option<String> {
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
    let result: Result<String> = (|| {
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
        Ok(format!("OZ Error {}: {}", error_code, msg))
    })();

    Some(result.unwrap_or_else(|_| "OZ Error (unparseable)".to_string()))
}

/// 응답 바이너리에서 에러를 감지하고 [`OzError::ProtocolError`]로 반환합니다.
///
/// [`check_error`]의 `Result` 반환 버전입니다.
/// 에러가 없으면 `Ok(())`, 에러가 감지되면 `Err(OzError::ProtocolError)`를 반환합니다.
///
/// # 예시
///
/// ```no_run
/// use ozra::codec::check_error_result;
///
/// fn handle_response(buf: &[u8]) -> ozra::Result<()> {
///     check_error_result(buf)?;
///     // 정상 응답 처리...
///     Ok(())
/// }
/// ```
pub fn check_error_result(buf: &[u8]) -> Result<()> {
    if let Some(msg) = check_error(buf) {
        // 에러 코드 재파싱 시도
        let code = (|| -> Result<i32> {
            let mut reader = BufReader::new(buf);
            let _magic = reader.read_u32()?;
            let _class_name = reader.read_utf16be()?;
            let error_code = reader.read_i32()?;
            Ok(error_code)
        })()
        .unwrap_or(-1);

        return Err(OzError::ProtocolError { code, message: msg });
    }
    Ok(())
}

/// IBasicField를 파싱합니다.
///
/// 형식:
/// ```text
/// kind_raw = read_i32()       // 1=Normal, 2=Calculated
/// sql_type_raw = read_i32()   // SQL 타입 코드
/// name = read_utf()
/// nullable = read_bool()
/// if kind_raw == 2:
///   parsing_code = Some(read_utf())
/// ```
///
/// # 에러
///
/// - [`OzError::UnknownFieldKind`] — 알 수 없는 필드 종류
/// - [`OzError::UnknownSqlType`] — 알 수 없는 SQL 타입 코드
pub fn parse_basic_field(reader: &mut BufReader) -> Result<BasicField> {
    let kind_raw = reader.read_i32()?;
    let sql_type_raw = reader.read_i32()?;
    let name = reader.read_utf()?;
    let nullable = reader.read_bool()?;

    let parsing_code = if kind_raw == 2 {
        Some(reader.read_utf()?)
    } else {
        None
    };

    let kind = FieldKind::try_from(kind_raw)?;
    let sql_type = SqlType::try_from(sql_type_raw)?;

    Ok(BasicField {
        kind,
        sql_type,
        name,
        nullable,
        parsing_code,
    })
}

/// DataSetGroup 메타데이터를 파싱합니다.
///
/// 형식:
/// ```text
/// name = read_utf()
/// type_name = read_utf()
/// subtype = read_utf()
/// // IMetaSet - 주 필드 목록
/// field_count1 = read_i32()
/// fields = [parse_basic_field() for _ in 0..field_count1]
/// // ⚠️ IMetaSet - 보조 필드 목록 (반드시 읽어서 오프셋 전진!)
/// field_count2 = read_i32()
/// secondary_fields = [parse_basic_field() for _ in 0..field_count2]
/// // 데이터셋 정보
/// ds_count = read_i32()
/// datasets = [DataSetInfo for _ in 0..ds_count]
/// ```
pub fn parse_dataset_group(reader: &mut BufReader) -> Result<DataSetGroup> {
    let name = reader.read_utf()?;
    let type_name = reader.read_utf()?;
    let subtype = reader.read_utf()?;

    // NOTE: IMetaSet — primary field list
    let field_count1 = reader.read_i32()? as usize;
    let mut fields = Vec::with_capacity(field_count1);
    for _ in 0..field_count1 {
        fields.push(parse_basic_field(reader)?);
    }

    // NOTE: IMetaSet — secondary field list (must read to advance offset)
    let field_count2 = reader.read_i32()? as usize;
    let mut secondary_fields = Vec::with_capacity(field_count2);
    for _ in 0..field_count2 {
        secondary_fields.push(parse_basic_field(reader)?);
    }

    // 데이터셋 정보
    let ds_count = reader.read_i32()? as usize;
    let mut datasets = Vec::with_capacity(ds_count);
    for _ in 0..ds_count {
        let byte_size = reader.read_i32()?;
        let row_count = reader.read_i32()?;
        let key = reader.read_utf()?;
        datasets.push(DataSetInfo {
            byte_size,
            row_count,
            key,
        });
    }

    Ok(DataSetGroup {
        name,
        type_name,
        subtype,
        fields,
        secondary_fields,
        datasets,
    })
}

/// DataModule 응답 전체를 파싱합니다.
///
/// 전체 바이너리 버퍼를 받아 헤더 + 페이로드를 모두 파싱합니다.
///
/// # 파싱 단계
///
/// 1. 헤더 파싱 (`parse_header`)
/// 2. 페이로드 헤더 (payloadSize, unknown, versionByte)
/// 3. TTk 헤더 (version, prefix "OZBINDEDDATAMODULE" 검증)
/// 4. 그룹 메타데이터 N개
/// 5. RecordInfo 배열
/// 6. 데이터 blob에서 각 행 디코딩
///
/// # 에러
///
/// - [`OzError::InvalidMagic`] — 매직 넘버 불일치
/// - [`OzError::InvalidPrefix`] — prefix != "OZBINDEDDATAMODULE"
/// - [`OzError::UnexpectedEof`] — 버퍼 부족
pub fn parse_data_module(buf: &[u8]) -> Result<DataModuleResponse> {
    let mut reader = BufReader::new(buf);

    let header = parse_header(&mut reader)?;

    let payload_size = reader.read_i32()?;
    let _unknown1 = reader.read_i32()?;
    let _version_byte = reader.read_u8()?;

    let version = reader.read_i32()?;
    let prefix = reader.read_utf()?;
    if prefix != DATA_MODULE_PREFIX {
        return Err(OzError::InvalidPrefix {
            expected: DATA_MODULE_PREFIX.to_string(),
            actual: prefix,
        });
    }
    let data_version = reader.read_i32()?;
    let _unknown2 = reader.read_i32()?;
    let _unknown3 = reader.read_i32()?;

    let group_count = reader.read_i16()?;
    let mut groups = Vec::with_capacity(group_count as usize);
    for _ in 0..group_count {
        groups.push(parse_dataset_group(&mut reader)?);
    }

    let total_data_size = reader.read_i32()?;

    let mut record_infos: Vec<Vec<RecordInfo>> = Vec::new();
    for group in &groups {
        for ds in &group.datasets {
            let mut ds_records = Vec::with_capacity(ds.row_count as usize);
            for _ in 0..ds.row_count {
                let length = reader.read_i32()?;
                let offset = reader.read_i32()?;
                ds_records.push(RecordInfo { length, offset });
            }
            record_infos.push(ds_records);
        }
    }

    let data_start = reader.offset();
    let mut datasets: Vec<DataSet> = Vec::new();
    let mut ri_idx = 0;

    for group in &groups {
        let mut group_rows = Vec::new();
        for _ds in &group.datasets {
            for ri in &record_infos[ri_idx] {
                // NOTE: Negative offset defense — guards against corrupted data
                if ri.offset < 0 {
                    return Err(OzError::UnexpectedEof {
                        offset: data_start,
                        needed: 0,
                        available: reader.remaining(),
                    });
                }
                let abs_offset = data_start + ri.offset as usize;
                reader.set_offset(abs_offset);
                let row = read_row(&mut reader, &group.fields)?;
                group_rows.push(row);
            }
            ri_idx += 1;
        }
        datasets.push((group.name.clone(), group_rows));
    }

    let meta = DataModuleMeta {
        payload_size,
        version,
        data_version,
        group_count,
        total_data_size,
    };

    Ok(DataModuleResponse {
        header,
        meta,
        groups,
        datasets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::REQUEST_FRAME_SIZE;
    use crate::types::FieldValue;

    /// 공통 헤더만 있는 최소 바이너리를 생성하는 헬퍼
    fn build_minimal_header(class_name: &str, fields: &[(&str, &str)]) -> Vec<u8> {
        let mut writer = BufWriter::new();
        write_common_header(&mut writer, class_name, fields).unwrap();
        let pos = writer.offset();
        let bytes = writer.into_bytes();
        bytes[..pos].to_vec()
    }

    #[test]
    fn test_build_login_request_size() {
        let buf = build_login_request("guest", "guest").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_build_login_request_magic() {
        let buf = build_login_request("guest", "guest").unwrap();
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(magic, MAGIC);
    }

    #[test]
    fn test_build_login_request_class_name() {
        let buf = build_login_request("guest", "guest").unwrap();
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, class_names::USER_LOGIN);
    }

    #[test]
    fn test_build_login_request_fields() {
        let buf = build_login_request("guest", "guest").unwrap();
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let _class_name = reader.read_utf16be().unwrap();
        let field_count = reader.read_u32().unwrap();
        assert_eq!(field_count, 16);

        // 첫 번째 필드: un=guest
        let k = reader.read_utf16be().unwrap();
        let v = reader.read_utf16be().unwrap();
        assert_eq!(k, "un");
        assert_eq!(v, "guest");
    }

    #[test]
    fn test_build_login_request_trailing_marker() {
        let buf = build_login_request("guest", "guest").unwrap();
        let mut reader = BufReader::new(&buf);
        // 매직 + 클래스명 + 필드 16개 + trailing marker를 파싱
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.fields.len(), 16);
        // trailing marker
        let marker = reader.read_u32().unwrap();
        assert_eq!(marker, LOGIN_TRAILING_MARKER);
    }

    #[test]
    fn test_build_login_request_session_id() {
        let buf = build_login_request("guest", "guest").unwrap();
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.session_id(), Some(INITIAL_SESSION_ID));
    }

    #[test]
    fn test_build_repository_request_size() {
        let buf = build_repository_request("/CM/test.ozr", "12345").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_build_repository_request_class_name() {
        let buf = build_repository_request("/CM/test.ozr", "12345").unwrap();
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, class_names::REPOSITORY_ITEM);
    }

    #[test]
    fn test_build_repository_request_payload() {
        let buf = build_repository_request("/CM/test.ozr", "session123").unwrap();
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.get_field("s"), Some("session123"));

        // Repository payload
        let marker = reader.read_u32().unwrap();
        assert_eq!(marker, REPO_HEADER_MARKER);
        let zero = reader.read_u32().unwrap();
        assert_eq!(zero, 0);
        let zero16 = reader.read_u16().unwrap();
        assert_eq!(zero16, 0);
        let path = reader.read_utf16be().unwrap();
        assert_eq!(path, "/CM/test.ozr");
    }

    #[test]
    fn test_build_data_module_request_size() {
        let params = vec![("arg1".to_string(), "2026".to_string())];
        let buf = build_data_module_request("test.odi", "/CM", &params, "12345").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
    }

    #[test]
    fn test_build_data_module_request_class_name() {
        let params = vec![];
        let buf = build_data_module_request("test.odi", "/CM", &params, "12345").unwrap();
        let mut reader = BufReader::new(&buf);
        let _magic = reader.read_u32().unwrap();
        let class_name = reader.read_utf16be().unwrap();
        assert_eq!(class_name, class_names::DATA_MODULE);
    }

    #[test]
    fn test_build_data_module_request_payload() {
        let params = vec![
            ("arg1".to_string(), "2026".to_string()),
            ("arg2".to_string(), "090".to_string()),
        ];
        let buf = build_data_module_request("report.odi", "/CM", &params, "sess1").unwrap();
        let mut reader = BufReader::new(&buf);
        let _header = parse_header(&mut reader).unwrap();

        // DataModule payload
        let type_marker = reader.read_u32().unwrap();
        assert_eq!(type_marker, DATA_MODULE_TYPE_MARKER);
        let odi_name = reader.read_utf16be().unwrap();
        assert_eq!(odi_name, "report.odi");
        let sub_magic = reader.read_u32().unwrap();
        assert_eq!(sub_magic, SUB_MAGIC);
        let category = reader.read_utf16be().unwrap();
        assert_eq!(category, "/CM");
        let bool1 = reader.read_u8().unwrap();
        assert_eq!(bool1, 0);
        let bool2 = reader.read_u8().unwrap();
        assert_eq!(bool2, 0);
        let empty_str = reader.read_utf16be().unwrap();
        assert_eq!(empty_str, "");
        let param_count = reader.read_u32().unwrap();
        assert_eq!(param_count, 2);
        let k1 = reader.read_utf16be().unwrap();
        let v1 = reader.read_utf16be().unwrap();
        assert_eq!(k1, "arg1");
        assert_eq!(v1, "2026");
        let k2 = reader.read_utf16be().unwrap();
        let v2 = reader.read_utf16be().unwrap();
        assert_eq!(k2, "arg2");
        assert_eq!(v2, "090");
        // trailing
        let t1 = reader.read_u32().unwrap();
        let t2 = reader.read_u32().unwrap();
        let t3 = reader.read_u32().unwrap();
        assert_eq!(t1, 2);
        assert_eq!(t2, 0x20);
        assert_eq!(t3, 0x11);
    }

    #[test]
    fn test_all_requests_exactly_9545_bytes() {
        let login = build_login_request("guest", "guest").unwrap();
        assert_eq!(login.len(), 9545);

        let repo = build_repository_request("/CM/test.ozr", "12345").unwrap();
        assert_eq!(repo.len(), 9545);

        let params = vec![("a".to_string(), "b".to_string())];
        let dm = build_data_module_request("test.odi", "/CM", &params, "12345").unwrap();
        assert_eq!(dm.len(), 9545);
    }

    #[test]
    fn test_parse_header_basic() {
        let bin = build_minimal_header("TestClass", &[("k1", "v1"), ("k2", "v2")]);
        let mut reader = BufReader::new(&bin);
        let header = parse_header(&mut reader).unwrap();

        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.class_name, "TestClass");
        assert_eq!(header.fields.len(), 2);
        assert_eq!(header.get_field("k1"), Some("v1"));
        assert_eq!(header.get_field("k2"), Some("v2"));
    }

    #[test]
    fn test_parse_header_invalid_magic() {
        let mut buf = vec![0x00, 0x00, 0x00, 0x01]; // wrong magic
        // append enough data for a minimal header
        buf.extend_from_slice(&0u32.to_be_bytes()); // empty class name (charCount=0)
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
    fn test_parse_header_empty_fields() {
        let bin = build_minimal_header("EmptyClass", &[]);
        let mut reader = BufReader::new(&bin);
        let header = parse_header(&mut reader).unwrap();

        assert_eq!(header.class_name, "EmptyClass");
        assert_eq!(header.fields.len(), 0);
    }

    #[test]
    fn test_parse_header_korean_values() {
        let bin = build_minimal_header("한글클래스", &[("이름", "홍길동")]);
        let mut reader = BufReader::new(&bin);
        let header = parse_header(&mut reader).unwrap();

        assert_eq!(header.class_name, "한글클래스");
        assert_eq!(header.get_field("이름"), Some("홍길동"));
    }

    #[test]
    fn test_check_error_normal_response() {
        // 정상 응답 (ExceptionMessage 미포함)
        let buf = build_login_request("guest", "guest").unwrap();
        let result = check_error(&buf);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_error_detects_exception() {
        // ExceptionMessage를 포함하는 에러 응답 생성
        let mut writer = BufWriter::new();
        writer.write_u32(MAGIC).unwrap();
        // 클래스명에 "ExceptionMessage" 포함
        writer
            .write_utf16be("oz.framework.OZCPExceptionMessage")
            .unwrap();
        // error code
        writer.write_i32(-1).unwrap();
        // message (UTF-16BE: msgLen(4B) + msg(N*2B))
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
    fn test_parse_basic_field_normal() {
        let mut w = BufWriter::new();
        w.write_i32(1).unwrap(); // kind = Normal
        w.write_i32(12).unwrap(); // sql_type = VarChar
        w.write_utf("PSUBJ").unwrap(); // name
        w.write_bool(true).unwrap(); // nullable
        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let field = parse_basic_field(&mut reader).unwrap();
        assert_eq!(field.kind, FieldKind::Normal);
        assert_eq!(field.sql_type, SqlType::VarChar);
        assert_eq!(field.name, "PSUBJ");
        assert!(field.nullable);
        assert!(field.parsing_code.is_none());
    }

    #[test]
    fn test_parse_basic_field_calculated() {
        let mut w = BufWriter::new();
        w.write_i32(2).unwrap(); // kind = Calculated
        w.write_i32(4).unwrap(); // sql_type = Integer
        w.write_utf("CALC_FIELD").unwrap();
        w.write_bool(false).unwrap();
        w.write_utf("some_expr_code").unwrap(); // parsingCode
        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let field = parse_basic_field(&mut reader).unwrap();
        assert_eq!(field.kind, FieldKind::Calculated);
        assert_eq!(field.sql_type, SqlType::Integer);
        assert_eq!(field.name, "CALC_FIELD");
        assert!(!field.nullable);
        assert_eq!(field.parsing_code.as_deref(), Some("some_expr_code"));
    }

    #[test]
    fn test_parse_basic_field_unknown_kind() {
        let mut w = BufWriter::new();
        w.write_i32(3).unwrap(); // kind = invalid
        w.write_i32(12).unwrap();
        w.write_utf("BAD").unwrap();
        w.write_bool(false).unwrap();
        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let err = parse_basic_field(&mut reader).unwrap_err();
        assert!(matches!(err, OzError::UnknownFieldKind { kind: 3 }));
    }

    #[test]
    fn test_parse_basic_field_unknown_sql_type() {
        let mut w = BufWriter::new();
        w.write_i32(1).unwrap(); // Normal
        w.write_i32(9999).unwrap(); // unknown sql type
        w.write_utf("BAD").unwrap();
        w.write_bool(false).unwrap();
        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let err = parse_basic_field(&mut reader).unwrap_err();
        assert!(matches!(err, OzError::UnknownSqlType { code: 9999 }));
    }

    #[test]
    fn test_parse_dataset_group_with_dual_fields() {
        let mut w = BufWriter::new();
        // 그룹 메타
        w.write_utf("ET_DEPLAN").unwrap();
        w.write_utf("ByteArraySet").unwrap();
        w.write_utf("").unwrap(); // subtype

        // 주 필드 목록 (2개)
        w.write_i32(2).unwrap(); // field_count1
        // 필드 1: Normal VarChar "NAME"
        w.write_i32(1).unwrap();
        w.write_i32(12).unwrap();
        w.write_utf("NAME").unwrap();
        w.write_bool(true).unwrap();
        // 필드 2: Normal Integer "AGE"
        w.write_i32(1).unwrap();
        w.write_i32(4).unwrap();
        w.write_utf("AGE").unwrap();
        w.write_bool(true).unwrap();

        // 보조 필드 목록 (1개 — 반드시 읽어서 오프셋 전진)
        w.write_i32(1).unwrap(); // field_count2
        // 보조 필드: Normal VarChar "SECONDARY"
        w.write_i32(1).unwrap();
        w.write_i32(12).unwrap();
        w.write_utf("SECONDARY").unwrap();
        w.write_bool(false).unwrap();

        // 데이터셋 정보 (1개)
        w.write_i32(1).unwrap(); // ds_count
        w.write_i32(1024).unwrap(); // byte_size
        w.write_i32(5).unwrap(); // row_count
        w.write_utf("ds1").unwrap(); // key

        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let group = parse_dataset_group(&mut reader).unwrap();
        assert_eq!(group.name, "ET_DEPLAN");
        assert_eq!(group.type_name, "ByteArraySet");
        assert_eq!(group.subtype, "");
        assert_eq!(group.fields.len(), 2);
        assert_eq!(group.fields[0].name, "NAME");
        assert_eq!(group.fields[0].sql_type, SqlType::VarChar);
        assert_eq!(group.fields[1].name, "AGE");
        assert_eq!(group.fields[1].sql_type, SqlType::Integer);
        assert_eq!(group.secondary_fields.len(), 1);
        assert_eq!(group.secondary_fields[0].name, "SECONDARY");
        assert_eq!(group.datasets.len(), 1);
        assert_eq!(group.datasets[0].byte_size, 1024);
        assert_eq!(group.datasets[0].row_count, 5);
        assert_eq!(group.datasets[0].key, "ds1");

        // reader가 모든 데이터를 정확히 소비했는지 확인
        assert_eq!(reader.offset(), data.len());
    }

    #[test]
    fn test_parse_dataset_group_empty_fields() {
        let mut w = BufWriter::new();
        w.write_utf("EmptyGroup").unwrap();
        w.write_utf("Type").unwrap();
        w.write_utf("Sub").unwrap();
        w.write_i32(0).unwrap(); // field_count1 = 0
        w.write_i32(0).unwrap(); // field_count2 = 0
        w.write_i32(0).unwrap(); // ds_count = 0

        let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();
        let mut reader = BufReader::new(&data);

        let group = parse_dataset_group(&mut reader).unwrap();
        assert_eq!(group.name, "EmptyGroup");
        assert!(group.fields.is_empty());
        assert!(group.secondary_fields.is_empty());
        assert!(group.datasets.is_empty());
    }

    #[test]
    fn test_roundtrip_login_request() {
        let buf = build_login_request("guest", "guest").unwrap();
        assert_eq!(buf.len(), REQUEST_FRAME_SIZE);

        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.magic, MAGIC);
        assert_eq!(header.class_name, class_names::USER_LOGIN);
        assert_eq!(header.get_field("un"), Some("guest"));
        assert_eq!(header.get_field("p"), Some("guest"));
        assert_eq!(header.get_field("s"), Some(INITIAL_SESSION_ID));
        assert_eq!(header.get_field("cv"), Some(CLIENT_VERSION));
        assert_eq!(header.get_field("d"), Some("-1"));
        assert_eq!(header.get_field("r"), Some("1"));
        assert_eq!(header.get_field("rv"), Some("268435456"));
        assert_eq!(header.fields.len(), 16);
    }

    #[test]
    fn test_roundtrip_repository_request() {
        let buf = build_repository_request("/CM/report.ozr", "sess42").unwrap();
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.class_name, class_names::REPOSITORY_ITEM);
        assert_eq!(header.get_field("s"), Some("sess42"));
    }

    #[test]
    fn test_roundtrip_data_module_request() {
        let params = vec![
            ("arg1".to_string(), "2026".to_string()),
            ("arg2".to_string(), "050".to_string()),
        ];
        let buf = build_data_module_request("report.odi", "/CM", &params, "sess99").unwrap();
        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.class_name, class_names::DATA_MODULE);
        assert_eq!(header.get_field("s"), Some("sess99"));
    }

    /// DataModule 응답 바이너리를 수동으로 생성합니다.
    fn build_test_data_module_response() -> Vec<u8> {
        // 응답 전체를 수동으로 구성
        // 충분한 크기의 버퍼를 사용
        let mut buf = Vec::with_capacity(4096);

        // === 헤더 ===
        // magic
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        // class_name (UTF-16BE: 4B charCount + N*2B)
        let class_name = "TestDataModule";
        let u16_units: Vec<u16> = class_name.encode_utf16().collect();
        buf.extend_from_slice(&(u16_units.len() as u32).to_be_bytes());
        for u in &u16_units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        // field_count = 1
        buf.extend_from_slice(&1u32.to_be_bytes());
        // field: s = "12345"
        let key = "s";
        let val = "12345";
        for s in [key, val] {
            let units: Vec<u16> = s.encode_utf16().collect();
            buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
            for u in &units {
                buf.extend_from_slice(&u.to_be_bytes());
            }
        }

        // === 페이로드 헤더 ===
        buf.extend_from_slice(&380i32.to_be_bytes()); // payload_size
        buf.extend_from_slice(&0i32.to_be_bytes()); // unknown1
        buf.push(0x01); // version_byte

        // === TTk 헤더 ===
        buf.extend_from_slice(&17i32.to_be_bytes()); // version
        // prefix: "OZBINDEDDATAMODULE" (Java Modified UTF-8)
        let prefix = DATA_MODULE_PREFIX;
        buf.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(prefix.as_bytes());
        buf.extend_from_slice(&2040i32.to_be_bytes()); // data_version
        buf.extend_from_slice(&0i32.to_be_bytes()); // unknown2
        buf.extend_from_slice(&0i32.to_be_bytes()); // unknown3

        // === 그룹 메타데이터 ===
        buf.extend_from_slice(&1i16.to_be_bytes()); // group_count = 1

        // Group 1: "TestGroup"
        let group_name = "TestGroup";
        buf.extend_from_slice(&(group_name.len() as u16).to_be_bytes());
        buf.extend_from_slice(group_name.as_bytes());
        let type_name = "ByteArraySet";
        buf.extend_from_slice(&(type_name.len() as u16).to_be_bytes());
        buf.extend_from_slice(type_name.as_bytes());
        let subtype = "";
        buf.extend_from_slice(&(subtype.len() as u16).to_be_bytes());
        buf.extend_from_slice(subtype.as_bytes());

        // 주 필드 목록 (2개 필드)
        buf.extend_from_slice(&2i32.to_be_bytes()); // field_count1 = 2
        // 필드 1: Normal(1), VarChar(12), "NAME", nullable=true
        buf.extend_from_slice(&1i32.to_be_bytes()); // kind
        buf.extend_from_slice(&12i32.to_be_bytes()); // sql_type
        let fname1 = "NAME";
        buf.extend_from_slice(&(fname1.len() as u16).to_be_bytes());
        buf.extend_from_slice(fname1.as_bytes());
        buf.push(0x01); // nullable = true
        // 필드 2: Normal(1), Integer(4), "AGE", nullable=true
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&4i32.to_be_bytes());
        let fname2 = "AGE";
        buf.extend_from_slice(&(fname2.len() as u16).to_be_bytes());
        buf.extend_from_slice(fname2.as_bytes());
        buf.push(0x01); // nullable = true

        // 보조 필드 목록 (0개)
        buf.extend_from_slice(&0i32.to_be_bytes()); // field_count2 = 0

        // 데이터셋 정보 (1개 데이터셋)
        buf.extend_from_slice(&1i32.to_be_bytes()); // ds_count = 1
        buf.extend_from_slice(&100i32.to_be_bytes()); // byte_size
        buf.extend_from_slice(&2i32.to_be_bytes()); // row_count = 2
        let ds_key = "ds0";
        buf.extend_from_slice(&(ds_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(ds_key.as_bytes());

        // === total_data_size ===
        buf.extend_from_slice(&100i32.to_be_bytes());

        // === RecordInfo[] (2행) ===
        // 행 데이터를 준비하고 RecordInfo 작성

        // 행 1 데이터: NAME="Alice", AGE=30
        let mut row1_data = Vec::new();
        row1_data.push(0x00); // VARCHAR: isNull=false
        let alice = "Alice";
        row1_data.extend_from_slice(&(alice.len() as u16).to_be_bytes());
        row1_data.extend_from_slice(alice.as_bytes());
        row1_data.push(0x00); // INTEGER: isNull=false
        row1_data.extend_from_slice(&30i32.to_be_bytes());

        // 행 2 데이터: NAME="Bob", AGE=25
        let mut row2_data = Vec::new();
        row2_data.push(0x00); // VARCHAR: isNull=false
        let bob = "Bob";
        row2_data.extend_from_slice(&(bob.len() as u16).to_be_bytes());
        row2_data.extend_from_slice(bob.as_bytes());
        row2_data.push(0x00); // INTEGER: isNull=false
        row2_data.extend_from_slice(&25i32.to_be_bytes());

        let row1_offset = 0i32;
        let row2_offset = row1_data.len() as i32;

        // RecordInfo: row 1
        buf.extend_from_slice(&(row1_data.len() as i32).to_be_bytes()); // length
        buf.extend_from_slice(&row1_offset.to_be_bytes()); // offset

        // RecordInfo: row 2
        buf.extend_from_slice(&(row2_data.len() as i32).to_be_bytes()); // length
        buf.extend_from_slice(&row2_offset.to_be_bytes()); // offset

        // === 데이터 blob ===
        buf.extend_from_slice(&row1_data);
        buf.extend_from_slice(&row2_data);

        buf
    }

    #[test]
    fn test_parse_data_module_full() {
        let buf = build_test_data_module_response();
        let response = parse_data_module(&buf).unwrap();

        // 헤더 검증
        assert_eq!(response.header.magic, MAGIC);
        assert_eq!(response.header.class_name, "TestDataModule");
        assert_eq!(response.header.get_field("s"), Some("12345"));

        // 메타데이터 검증
        assert_eq!(response.meta.payload_size, 380);
        assert_eq!(response.meta.version, 17);
        assert_eq!(response.meta.data_version, 2040);
        assert_eq!(response.meta.group_count, 1);

        // 그룹 검증
        assert_eq!(response.groups.len(), 1);
        assert_eq!(response.groups[0].name, "TestGroup");
        assert_eq!(response.groups[0].type_name, "ByteArraySet");
        assert_eq!(response.groups[0].fields.len(), 2);
        assert_eq!(response.groups[0].fields[0].name, "NAME");
        assert_eq!(response.groups[0].fields[1].name, "AGE");

        // 데이터셋 검증
        assert_eq!(response.datasets.len(), 1);
        let (group_name, rows) = &response.datasets[0];
        assert_eq!(group_name, "TestGroup");
        assert_eq!(rows.len(), 2);

        // 행 1: NAME="Alice", AGE=30
        assert_eq!(
            rows[0][0],
            ("NAME".to_string(), FieldValue::String("Alice".to_string()))
        );
        assert_eq!(rows[0][1], ("AGE".to_string(), FieldValue::Int(30)));

        // 행 2: NAME="Bob", AGE=25
        assert_eq!(
            rows[1][0],
            ("NAME".to_string(), FieldValue::String("Bob".to_string()))
        );
        assert_eq!(rows[1][1], ("AGE".to_string(), FieldValue::Int(25)));
    }

    #[test]
    fn test_parse_data_module_invalid_prefix() {
        // 잘못된 prefix를 가진 DataModule 응답 생성
        let mut buf = Vec::with_capacity(256);

        // 헤더
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "Test";
        let units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
        for u in &units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes()); // 0 fields

        // 페이로드 헤더
        buf.extend_from_slice(&0i32.to_be_bytes()); // payload_size
        buf.extend_from_slice(&0i32.to_be_bytes()); // unknown1
        buf.push(0x01); // version_byte

        // TTk 헤더
        buf.extend_from_slice(&17i32.to_be_bytes());
        let bad_prefix = "WRONGPREFIX";
        buf.extend_from_slice(&(bad_prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(bad_prefix.as_bytes());

        let mut reader = BufReader::new(&buf);
        let header = parse_header(&mut reader).unwrap();
        assert_eq!(header.magic, MAGIC);

        // 페이로드 파싱 시작 — 여기서 prefix 에러가 발생해야 함
        let err = parse_data_module(&buf).unwrap_err();
        assert!(matches!(err, OzError::InvalidPrefix { .. }));
    }

    #[test]
    fn test_parse_data_module_with_nulls() {
        // NULL 값이 포함된 DataModule 응답 생성
        let mut buf = Vec::with_capacity(4096);

        // 헤더
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "NullTest";
        let units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
        for u in &units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes()); // 0 fields

        // 페이로드 헤더
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.push(0x01);

        // TTk 헤더
        buf.extend_from_slice(&17i32.to_be_bytes());
        let prefix = DATA_MODULE_PREFIX;
        buf.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(prefix.as_bytes());
        buf.extend_from_slice(&2040i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());

        // 1 그룹
        buf.extend_from_slice(&1i16.to_be_bytes());

        // 그룹 메타
        let gname = "NullGrp";
        buf.extend_from_slice(&(gname.len() as u16).to_be_bytes());
        buf.extend_from_slice(gname.as_bytes());
        let tname = "ByteArraySet";
        buf.extend_from_slice(&(tname.len() as u16).to_be_bytes());
        buf.extend_from_slice(tname.as_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // subtype empty

        // 1 필드: Integer nullable
        buf.extend_from_slice(&1i32.to_be_bytes()); // field_count1
        buf.extend_from_slice(&1i32.to_be_bytes()); // kind=Normal
        buf.extend_from_slice(&4i32.to_be_bytes()); // sql_type=Integer
        let fname = "VAL";
        buf.extend_from_slice(&(fname.len() as u16).to_be_bytes());
        buf.extend_from_slice(fname.as_bytes());
        buf.push(0x01); // nullable=true

        buf.extend_from_slice(&0i32.to_be_bytes()); // field_count2=0

        // 1 데이터셋, 1행
        buf.extend_from_slice(&1i32.to_be_bytes()); // ds_count
        buf.extend_from_slice(&10i32.to_be_bytes()); // byte_size
        buf.extend_from_slice(&1i32.to_be_bytes()); // row_count=1
        let dk = "d0";
        buf.extend_from_slice(&(dk.len() as u16).to_be_bytes());
        buf.extend_from_slice(dk.as_bytes());

        // total_data_size
        buf.extend_from_slice(&10i32.to_be_bytes());

        // RecordInfo
        buf.extend_from_slice(&1i32.to_be_bytes()); // length
        buf.extend_from_slice(&0i32.to_be_bytes()); // offset

        // 데이터: INTEGER null (bool=true → 1바이트)
        buf.push(0x01); // isNull=true

        let response = parse_data_module(&buf).unwrap();
        let (_, rows) = &response.datasets[0];
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0].1, FieldValue::Null);
    }

    #[test]
    fn test_parse_data_module_multiple_groups() {
        let mut buf = Vec::with_capacity(4096);

        // 헤더
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "MultiGroup";
        let units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
        for u in &units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes());

        // 페이로드 헤더
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.push(0x01);

        // TTk 헤더
        buf.extend_from_slice(&17i32.to_be_bytes());
        let prefix = DATA_MODULE_PREFIX;
        buf.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(prefix.as_bytes());
        buf.extend_from_slice(&2040i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());

        // 2 그룹
        buf.extend_from_slice(&2i16.to_be_bytes());

        // --- 그룹 1: "G1" with SmallInt field, 1 row ---
        let g1 = "G1";
        buf.extend_from_slice(&(g1.len() as u16).to_be_bytes());
        buf.extend_from_slice(g1.as_bytes());
        let t1 = "ByteArraySet";
        buf.extend_from_slice(&(t1.len() as u16).to_be_bytes());
        buf.extend_from_slice(t1.as_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf.extend_from_slice(&1i32.to_be_bytes()); // 1 field
        buf.extend_from_slice(&1i32.to_be_bytes()); // kind=Normal
        buf.extend_from_slice(&5i32.to_be_bytes()); // sql_type=SmallInt
        let f1 = "ID";
        buf.extend_from_slice(&(f1.len() as u16).to_be_bytes());
        buf.extend_from_slice(f1.as_bytes());
        buf.push(0x00);

        buf.extend_from_slice(&0i32.to_be_bytes()); // 0 secondary fields
        buf.extend_from_slice(&1i32.to_be_bytes()); // 1 dataset
        buf.extend_from_slice(&4i32.to_be_bytes()); // byte_size
        buf.extend_from_slice(&1i32.to_be_bytes()); // 1 row
        let dk1 = "d0";
        buf.extend_from_slice(&(dk1.len() as u16).to_be_bytes());
        buf.extend_from_slice(dk1.as_bytes());

        // --- 그룹 2: "G2" with Bit field, 1 row ---
        let g2 = "G2";
        buf.extend_from_slice(&(g2.len() as u16).to_be_bytes());
        buf.extend_from_slice(g2.as_bytes());
        let t2 = "ByteArraySet";
        buf.extend_from_slice(&(t2.len() as u16).to_be_bytes());
        buf.extend_from_slice(t2.as_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf.extend_from_slice(&1i32.to_be_bytes()); // 1 field
        buf.extend_from_slice(&1i32.to_be_bytes()); // kind=Normal
        buf.extend_from_slice(&(-7i32).to_be_bytes()); // sql_type=Bit
        let f2 = "FLAG";
        buf.extend_from_slice(&(f2.len() as u16).to_be_bytes());
        buf.extend_from_slice(f2.as_bytes());
        buf.push(0x00);

        buf.extend_from_slice(&0i32.to_be_bytes()); // 0 secondary fields
        buf.extend_from_slice(&1i32.to_be_bytes()); // 1 dataset
        buf.extend_from_slice(&1i32.to_be_bytes()); // byte_size
        buf.extend_from_slice(&1i32.to_be_bytes()); // 1 row
        let dk2 = "d1";
        buf.extend_from_slice(&(dk2.len() as u16).to_be_bytes());
        buf.extend_from_slice(dk2.as_bytes());

        // total_data_size
        buf.extend_from_slice(&10i32.to_be_bytes());

        // RecordInfo: G1 ds0 row0
        let row1_data: Vec<u8> = 42i32.to_be_bytes().to_vec(); // SmallInt = 42
        let row2_data: Vec<u8> = vec![0x01]; // Bit = true

        buf.extend_from_slice(&(row1_data.len() as i32).to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes()); // offset=0

        // RecordInfo: G2 ds0 row0
        let row2_offset = row1_data.len() as i32;
        buf.extend_from_slice(&(row2_data.len() as i32).to_be_bytes());
        buf.extend_from_slice(&row2_offset.to_be_bytes());

        // 데이터 blob
        buf.extend_from_slice(&row1_data);
        buf.extend_from_slice(&row2_data);

        let response = parse_data_module(&buf).unwrap();
        assert_eq!(response.datasets.len(), 2);
        assert_eq!(response.datasets[0].0, "G1");
        assert_eq!(response.datasets[1].0, "G2");
        assert_eq!(
            response.datasets[0].1[0][0],
            ("ID".to_string(), FieldValue::Int(42))
        );
        assert_eq!(
            response.datasets[1].1[0][0],
            ("FLAG".to_string(), FieldValue::Bool(true))
        );
    }

    #[test]
    fn test_check_error_result_ok_on_normal() {
        let buf = build_login_request("guest", "guest").unwrap();
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

    #[test]
    fn test_parse_data_module_negative_record_offset() {
        // 음수 오프셋을 가진 RecordInfo가 포함된 DataModule 응답 생성
        let mut buf = Vec::with_capacity(4096);

        // 헤더
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        let cn = "NegOff";
        let units: Vec<u16> = cn.encode_utf16().collect();
        buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
        for u in &units {
            buf.extend_from_slice(&u.to_be_bytes());
        }
        buf.extend_from_slice(&0u32.to_be_bytes()); // 0 fields

        // 페이로드 헤더
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.push(0x01);

        // TTk 헤더
        buf.extend_from_slice(&17i32.to_be_bytes());
        let prefix = DATA_MODULE_PREFIX;
        buf.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
        buf.extend_from_slice(prefix.as_bytes());
        buf.extend_from_slice(&2040i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());

        // 1 그룹, 1 필드, 1 데이터셋, 1 행
        buf.extend_from_slice(&1i16.to_be_bytes());
        let gname = "G";
        buf.extend_from_slice(&(gname.len() as u16).to_be_bytes());
        buf.extend_from_slice(gname.as_bytes());
        let tname = "ByteArraySet";
        buf.extend_from_slice(&(tname.len() as u16).to_be_bytes());
        buf.extend_from_slice(tname.as_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf.extend_from_slice(&1i32.to_be_bytes()); // 1 field
        buf.extend_from_slice(&1i32.to_be_bytes()); // Normal
        buf.extend_from_slice(&4i32.to_be_bytes()); // Integer
        let fname = "V";
        buf.extend_from_slice(&(fname.len() as u16).to_be_bytes());
        buf.extend_from_slice(fname.as_bytes());
        buf.push(0x00);

        buf.extend_from_slice(&0i32.to_be_bytes()); // 0 secondary fields
        buf.extend_from_slice(&1i32.to_be_bytes()); // 1 dataset
        buf.extend_from_slice(&10i32.to_be_bytes()); // byte_size
        buf.extend_from_slice(&1i32.to_be_bytes()); // 1 row
        let dk = "d";
        buf.extend_from_slice(&(dk.len() as u16).to_be_bytes());
        buf.extend_from_slice(dk.as_bytes());

        buf.extend_from_slice(&10i32.to_be_bytes()); // total_data_size

        // RecordInfo with 음수 오프셋!
        buf.extend_from_slice(&5i32.to_be_bytes()); // length
        buf.extend_from_slice(&(-1i32).to_be_bytes()); // offset = -1 (음수!)

        // 데이터 blob (사용되지 않아야 함)
        buf.push(0x00);
        buf.extend_from_slice(&42i32.to_be_bytes());

        let err = parse_data_module(&buf).unwrap_err();
        assert!(matches!(err, OzError::UnexpectedEof { .. }));
    }
}
