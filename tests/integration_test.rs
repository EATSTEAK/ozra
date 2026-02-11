//! 통합 테스트 — 모듈 간 연동을 검증합니다.
//!
//! - 라운드트립 테스트 (요청 빌드 → 헤더 파싱)
//! - DataModule 전체 파이프라인 테스트
//! - 에러 전파 테스트
//! - Feature flag 테스트

use ozra::codec::{
    build_data_module_request, build_login_request, build_repository_request, check_error,
    check_error_result, class_names, parse_data_module, parse_header,
};
use ozra::constants::{
    CLIENT_VERSION, DATA_MODULE_PREFIX, INITIAL_SESSION_ID, MAGIC, REQUEST_FRAME_SIZE,
};
use ozra::error::OzError;
use ozra::field::{read_field_value, read_row};
use ozra::types::{BasicField, FieldKind, FieldValue, SqlType};
use ozra::wire::{BufReader, BufWriter};

#[test]
fn roundtrip_login_request_header() {
    let buf = build_login_request("guest", "guest").unwrap();
    assert_eq!(buf.len(), REQUEST_FRAME_SIZE);

    let mut reader = BufReader::new(&buf);
    let header = parse_header(&mut reader).unwrap();

    // 매직 넘버 검증
    assert_eq!(header.magic, MAGIC);
    // 클래스명 검증
    assert_eq!(header.class_name, class_names::USER_LOGIN);
    // 16개 필드 검증
    assert_eq!(header.fields.len(), 16);
    // 주요 필드 값 검증
    assert_eq!(header.get_field("un"), Some("guest"));
    assert_eq!(header.get_field("p"), Some("guest"));
    assert_eq!(header.session_id(), Some(INITIAL_SESSION_ID));
    assert_eq!(header.get_field("cv"), Some(CLIENT_VERSION));
    assert_eq!(header.get_field("d"), Some("-1"));
    assert_eq!(header.get_field("r"), Some("1"));
    assert_eq!(header.get_field("rv"), Some("268435456"));
    // 빈 필드 검증
    assert_eq!(header.get_field("t"), Some(""));
    assert_eq!(header.get_field("i"), Some(""));
    assert_eq!(header.get_field("o"), Some(""));
    assert_eq!(header.get_field("z"), Some(""));
    assert_eq!(header.get_field("j"), Some(""));
    assert_eq!(header.get_field("xi"), Some(""));
    assert_eq!(header.get_field("xm"), Some(""));
    assert_eq!(header.get_field("xh"), Some(""));
    assert_eq!(header.get_field("pi"), Some(""));
}

#[test]
fn roundtrip_repository_request_session_id() {
    let session = "test_session_42";
    let buf = build_repository_request("/CM/report.ozr", session).unwrap();
    assert_eq!(buf.len(), REQUEST_FRAME_SIZE);

    let mut reader = BufReader::new(&buf);
    let header = parse_header(&mut reader).unwrap();

    assert_eq!(header.class_name, class_names::REPOSITORY_ITEM);
    assert_eq!(header.session_id(), Some(session));
    assert_eq!(header.fields.len(), 16);
}

#[test]
fn roundtrip_data_module_request_class_name_and_session() {
    let params = vec![
        ("arg1".to_string(), "2026".to_string()),
        ("arg2".to_string(), "090".to_string()),
    ];
    let buf = build_data_module_request("report.odi", "/CM", &params, "sess99").unwrap();
    assert_eq!(buf.len(), REQUEST_FRAME_SIZE);

    let mut reader = BufReader::new(&buf);
    let header = parse_header(&mut reader).unwrap();

    assert_eq!(header.class_name, class_names::DATA_MODULE);
    assert_eq!(header.session_id(), Some("sess99"));
}

#[test]
fn roundtrip_login_then_parse_trailing_marker() {
    let buf = build_login_request("admin", "password123").unwrap();
    let mut reader = BufReader::new(&buf);
    let header = parse_header(&mut reader).unwrap();

    // 사용자명/비밀번호 검증
    assert_eq!(header.get_field("un"), Some("admin"));
    assert_eq!(header.get_field("p"), Some("password123"));

    // trailing marker (LOGIN_TRAILING_MARKER = 0xB0)
    let marker = reader.read_u32().unwrap();
    assert_eq!(marker, 0xB0);
}

#[test]
fn roundtrip_repository_payload_verification() {
    let path = "/forcs/강의계획서.ozr";
    let buf = build_repository_request(path, "sess_kr").unwrap();
    let mut reader = BufReader::new(&buf);
    let _header = parse_header(&mut reader).unwrap();

    // Repository payload: REPO_HEADER_MARKER + 0x00 + 0x0000 + path
    let marker = reader.read_u32().unwrap();
    assert_eq!(marker, 0x100);
    let zero32 = reader.read_u32().unwrap();
    assert_eq!(zero32, 0);
    let zero16 = reader.read_u16().unwrap();
    assert_eq!(zero16, 0);
    let parsed_path = reader.read_utf16be().unwrap();
    assert_eq!(parsed_path, path);
}

#[test]
fn roundtrip_data_module_payload_verification() {
    let params = vec![("key1".to_string(), "val1".to_string())];
    let buf = build_data_module_request("test.odi", "/Test", &params, "s1").unwrap();
    let mut reader = BufReader::new(&buf);
    let _header = parse_header(&mut reader).unwrap();

    // DataModule payload 순서 검증
    let type_marker = reader.read_u32().unwrap();
    assert_eq!(type_marker, 0x17C); // DATA_MODULE_TYPE_MARKER
    let odi = reader.read_utf16be().unwrap();
    assert_eq!(odi, "test.odi");
    let sub_magic = reader.read_u32().unwrap();
    assert_eq!(sub_magic, 0x2710); // SUB_MAGIC
    let category = reader.read_utf16be().unwrap();
    assert_eq!(category, "/Test");
    let b1 = reader.read_u8().unwrap();
    assert_eq!(b1, 0);
    let b2 = reader.read_u8().unwrap();
    assert_eq!(b2, 0);
    let empty = reader.read_utf16be().unwrap();
    assert_eq!(empty, "");
    let param_count = reader.read_u32().unwrap();
    assert_eq!(param_count, 1);
    let k = reader.read_utf16be().unwrap();
    assert_eq!(k, "key1");
    let v = reader.read_utf16be().unwrap();
    assert_eq!(v, "val1");
    // trailing constants
    assert_eq!(reader.read_u32().unwrap(), 2);
    assert_eq!(reader.read_u32().unwrap(), 0x20);
    assert_eq!(reader.read_u32().unwrap(), 0x11);
}

/// 수동 바이너리 생성 → codec 파서 → 필드값 검증
#[test]
fn data_module_single_group_varchar_integer() {
    let buf = build_test_dm_response_single_group();
    let response = parse_data_module(&buf).unwrap();

    // 헤더
    assert_eq!(response.header.magic, MAGIC);
    assert_eq!(response.header.session_id(), Some("session42"));

    // 메타데이터
    assert_eq!(response.meta.version, 17);
    assert_eq!(response.meta.data_version, 2040);
    assert_eq!(response.meta.group_count, 1);

    // 그룹
    assert_eq!(response.groups.len(), 1);
    assert_eq!(response.groups[0].name, "TestGroup");
    assert_eq!(response.groups[0].fields.len(), 2);
    assert_eq!(response.groups[0].fields[0].name, "NAME");
    assert_eq!(response.groups[0].fields[0].sql_type, SqlType::VarChar);
    assert_eq!(response.groups[0].fields[1].name, "AGE");
    assert_eq!(response.groups[0].fields[1].sql_type, SqlType::Integer);

    // 데이터셋
    assert_eq!(response.datasets.len(), 1);
    let (group_name, rows) = &response.datasets[0];
    assert_eq!(group_name, "TestGroup");
    assert_eq!(rows.len(), 2);

    // 행 1
    assert_eq!(
        rows[0][0],
        ("NAME".to_string(), FieldValue::String("Alice".to_string()))
    );
    assert_eq!(rows[0][1], ("AGE".to_string(), FieldValue::Int(30)));

    // 행 2
    assert_eq!(
        rows[1][0],
        ("NAME".to_string(), FieldValue::String("Bob".to_string()))
    );
    assert_eq!(rows[1][1], ("AGE".to_string(), FieldValue::Int(25)));
}

/// 여러 그룹, 혼합 SQL 타입 테스트
#[test]
fn data_module_multiple_groups_mixed_types() {
    let buf = build_test_dm_response_multi_group();
    let response = parse_data_module(&buf).unwrap();

    assert_eq!(response.meta.group_count, 2);
    assert_eq!(response.groups.len(), 2);
    assert_eq!(response.datasets.len(), 2);

    // 그룹 1: G1 with SmallInt
    let (name1, rows1) = &response.datasets[0];
    assert_eq!(name1, "G1");
    assert_eq!(rows1.len(), 2);
    assert_eq!(rows1[0][0], ("ID".to_string(), FieldValue::Int(100)));
    assert_eq!(rows1[1][0], ("ID".to_string(), FieldValue::Int(200)));

    // 그룹 2: G2 with VarChar + Bit
    let (name2, rows2) = &response.datasets[1];
    assert_eq!(name2, "G2");
    assert_eq!(rows2.len(), 1);
    assert_eq!(
        rows2[0][0],
        (
            "FLAG_NAME".to_string(),
            FieldValue::String("active".to_string())
        )
    );
    assert_eq!(
        rows2[0][1],
        ("FLAG_VAL".to_string(), FieldValue::Bool(true))
    );
}

/// NULL 값이 포함된 DataModule 테스트
#[test]
fn data_module_with_null_values() {
    let buf = build_test_dm_response_with_nulls();
    let response = parse_data_module(&buf).unwrap();

    let (_, rows) = &response.datasets[0];
    assert_eq!(rows.len(), 3);

    // 행 1: VARCHAR = NULL, INTEGER = 42
    assert_eq!(rows[0][0].1, FieldValue::Null);
    assert_eq!(rows[0][1].1, FieldValue::Int(42));

    // 행 2: VARCHAR = "hello", INTEGER = NULL
    assert_eq!(rows[1][0].1, FieldValue::String("hello".to_string()));
    assert_eq!(rows[1][1].1, FieldValue::Null);

    // 행 3: VARCHAR = NULL, INTEGER = NULL
    assert_eq!(rows[2][0].1, FieldValue::Null);
    assert_eq!(rows[2][1].1, FieldValue::Null);
}

/// Numeric (bool prefix 없음) + Timestamp + Binary 혼합 테스트
#[test]
fn data_module_with_numeric_timestamp_binary() {
    let buf = build_test_dm_response_numeric_timestamp_binary();
    let response = parse_data_module(&buf).unwrap();

    let (_, rows) = &response.datasets[0];
    assert_eq!(rows.len(), 1);

    // NUMERIC: "123.456"
    assert_eq!(
        rows[0][0],
        (
            "PRICE".to_string(),
            FieldValue::String("123.456".to_string())
        )
    );
    // TIMESTAMP: epoch ms
    assert_eq!(
        rows[0][1],
        (
            "CREATED".to_string(),
            FieldValue::DateTime(1_700_000_000_000)
        )
    );
    // BINARY: [0xDE, 0xAD]
    assert_eq!(
        rows[0][2],
        ("DATA".to_string(), FieldValue::Binary(vec![0xDE, 0xAD]))
    );
}

/// 보조 필드(secondary fields)가 있는 그룹 테스트 (IMetaSet 이중 필드 목록)
#[test]
fn data_module_with_secondary_fields() {
    let buf = build_test_dm_response_with_secondary_fields();
    let response = parse_data_module(&buf).unwrap();

    // 보조 필드가 있어도 주 필드만 데이터 파싱에 사용됨
    assert_eq!(response.groups[0].fields.len(), 1);
    assert_eq!(response.groups[0].secondary_fields.len(), 1);
    assert_eq!(response.groups[0].secondary_fields[0].name, "SEC_FIELD");

    let (_, rows) = &response.datasets[0];
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0][0], ("MAIN_FIELD".to_string(), FieldValue::Int(999)));
}

#[test]
fn field_values_consecutive_read_offset_accuracy() {
    // 여러 타입의 필드를 연속으로 작성하고 읽어 오프셋 정확성 검증
    let fields = vec![
        BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::SmallInt,
            name: "A".into(),
            nullable: false,
            parsing_code: None,
        },
        BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::Integer,
            name: "B".into(),
            nullable: true,
            parsing_code: None,
        },
        BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::VarChar,
            name: "C".into(),
            nullable: true,
            parsing_code: None,
        },
        BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::Numeric,
            name: "D".into(),
            nullable: true,
            parsing_code: None,
        },
        BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::Bit,
            name: "E".into(),
            nullable: false,
            parsing_code: None,
        },
        BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::Timestamp,
            name: "F".into(),
            nullable: true,
            parsing_code: None,
        },
    ];

    let mut w = BufWriter::new();
    // SmallInt = 7 (4B)
    w.write_i32(7).unwrap();
    // Integer = NULL (1B)
    w.write_bool(true).unwrap();
    // VarChar = "test" (1B + 2B + 4B = 7B)
    w.write_bool(false).unwrap();
    w.write_utf("test").unwrap();
    // Numeric = "99.9" (2B + 4B = 6B, no bool!)
    w.write_utf("99.9").unwrap();
    // Bit = true (1B)
    w.write_u8(1).unwrap();
    // Timestamp = 1700000000000 (8B)
    w.write_i64(1_700_000_000_000).unwrap();

    let data: Vec<u8> = w.as_bytes()[..w.offset()].to_vec();

    // 예상 총 바이트: 4 + 1 + 7 + 6 + 1 + 8 = 27
    assert_eq!(data.len(), 27);

    let mut r = BufReader::new(&data);
    let row = read_row(&mut r, &fields).unwrap();

    assert_eq!(row.len(), 6);
    assert_eq!(row[0], ("A".into(), FieldValue::Int(7)));
    assert_eq!(row[1], ("B".into(), FieldValue::Null));
    assert_eq!(row[2], ("C".into(), FieldValue::String("test".into())));
    assert_eq!(row[3], ("D".into(), FieldValue::String("99.9".into())));
    assert_eq!(row[4], ("E".into(), FieldValue::Bool(true)));
    assert_eq!(
        row[5],
        ("F".into(), FieldValue::DateTime(1_700_000_000_000))
    );

    // 모든 데이터가 정확히 소비됐는지
    assert_eq!(r.offset(), data.len());
    assert_eq!(r.remaining(), 0);
}

#[test]
fn error_invalid_magic_number() {
    let mut buf = vec![0x00, 0x00, 0x00, 0x01]; // wrong magic (1, not 0x2711)
    buf.extend_from_slice(&0u32.to_be_bytes()); // empty class name
    buf.extend_from_slice(&0u32.to_be_bytes()); // 0 fields

    let mut reader = BufReader::new(&buf);
    let err = parse_header(&mut reader).unwrap_err();

    match err {
        OzError::InvalidMagic { expected, actual } => {
            assert_eq!(expected, MAGIC);
            assert_eq!(actual, 1);
        }
        other => panic!("expected InvalidMagic, got: {:?}", other),
    }
}

#[test]
fn error_invalid_prefix() {
    let buf = build_dm_with_wrong_prefix("WRONG_PREFIX");
    let err = parse_data_module(&buf).unwrap_err();

    match err {
        OzError::InvalidPrefix { expected, actual } => {
            assert_eq!(expected, DATA_MODULE_PREFIX);
            assert_eq!(actual, "WRONG_PREFIX");
        }
        other => panic!("expected InvalidPrefix, got: {:?}", other),
    }
}

#[test]
fn error_unexpected_eof_on_empty_buffer() {
    let buf: &[u8] = &[];
    let mut reader = BufReader::new(buf);
    let err = parse_header(&mut reader).unwrap_err();

    match err {
        OzError::UnexpectedEof {
            offset,
            needed,
            available,
        } => {
            assert_eq!(offset, 0);
            assert_eq!(needed, 4); // magic u32
            assert_eq!(available, 0);
        }
        other => panic!("expected UnexpectedEof, got: {:?}", other),
    }
}

#[test]
fn error_unexpected_eof_truncated_header() {
    // 매직만 있고 나머지 없음
    let buf = MAGIC.to_be_bytes();
    let mut reader = BufReader::new(&buf);
    let err = parse_header(&mut reader).unwrap_err();

    assert!(matches!(err, OzError::UnexpectedEof { .. }));
}

#[test]
fn error_check_error_detects_exception_message() {
    let error_buf = build_error_response_raw(-42, "permission denied");
    let result = check_error(&error_buf);
    assert!(result.is_some());
    let msg = result.unwrap();
    assert!(msg.contains("-42"));
    assert!(msg.contains("permission denied"));
}

#[test]
fn error_check_error_result_returns_protocol_error() {
    let error_buf = build_error_response_raw(-99, "server error");
    let err = check_error_result(&error_buf).unwrap_err();

    match err {
        OzError::ProtocolError { code, message } => {
            assert_eq!(code, -99);
            assert!(message.contains("server error"));
        }
        other => panic!("expected ProtocolError, got: {:?}", other),
    }
}

#[test]
fn error_check_error_ok_on_normal_response() {
    let buf = build_login_request("guest", "guest").unwrap();
    assert!(check_error_result(&buf).is_ok());
}

#[test]
fn error_field_read_on_insufficient_buffer() {
    // INTEGER 읽기: bool(1B) 필요한데 빈 버퍼
    let data: &[u8] = &[];
    let mut r = BufReader::new(data);
    let err = read_field_value(&mut r, SqlType::Integer).unwrap_err();
    assert!(matches!(err, OzError::UnexpectedEof { .. }));
}

#[test]
fn error_field_read_partial_integer() {
    // INTEGER: bool(false, 1B) + i32(4B 필요) but only 3B 제공
    let data: &[u8] = &[0x00, 0x00, 0x00, 0x01]; // bool=false + 3B (insufficient for i32)
    let mut r = BufReader::new(data);
    let err = read_field_value(&mut r, SqlType::Integer).unwrap_err();
    assert!(matches!(err, OzError::UnexpectedEof { .. }));
}

#[cfg(feature = "client")]
#[test]
fn feature_client_module_exists() {
    // client 모듈이 존재하고 OzClient 구조체가 접근 가능한지 확인
    use ozra::client::OzClient;

    let client = OzClient::new("https://example.com/oz70", "guest", "guest").unwrap();
    assert_eq!(client.session_id(), INITIAL_SESSION_ID);
    assert!(!client.is_authenticated());
}

#[cfg(feature = "client")]
#[tokio::test]
#[ignore = "requires network access to SSU OZ server"]
async fn live_fetch_syllabus() {
    use ozra::client::OzClient;

    let base_url = "https://office.ssu.ac.kr/oz70";
    let mut client = OzClient::new(base_url, "guest", "guest").unwrap();

    // Step 0: 세션 초기화
    client.init_session().await.expect("init_session failed");

    // Step 1: 로그인
    let login_header = client.login().await.expect("login failed");
    assert!(
        client.is_authenticated(),
        "should be authenticated after login"
    );
    println!("Session ID: {:?}", login_header.session_id());

    // Step 2: .ozr 다운로드
    let ozr_data = client
        .fetch_repository("/CM/zcm_get_abeek_plan_2018_new.ozr")
        .await
        .expect("fetch .ozr failed");
    assert!(!ozr_data.is_empty(), ".ozr data should not be empty");
    println!(".ozr size: {} bytes", ozr_data.len());

    // Step 3: .odi 다운로드
    let odi_data = client
        .fetch_repository("/CM/zcm_get_abeek_plan_2018_new.odi")
        .await
        .expect("fetch .odi failed");
    assert!(!odi_data.is_empty(), ".odi data should not be empty");
    println!(".odi size: {} bytes", odi_data.len());

    // Step 4: DataModule 조회 (강의계획서)
    let params = vec![
        ("arg1".to_string(), "2026".to_string()),
        ("arg2".to_string(), "090".to_string()),
        ("arg3".to_string(), "50345792".to_string()),
        ("UNAME".to_string(), "OZASPN".to_string()),
        ("P_RANDOM".to_string(), "*01882".to_string()),
    ];
    let response = client
        .fetch_data_module("zcm_get_abeek_plan_2018_new.odi", "/CM", &params)
        .await
        .expect("fetch_data_module failed");

    // 응답 검증
    assert!(
        !response.datasets.is_empty(),
        "should have at least one dataset"
    );
    println!("Groups: {}", response.groups.len());
    for group in &response.groups {
        println!("  Group: {} (fields: {})", group.name, group.fields.len());
    }
    for (name, rows) in &response.datasets {
        println!("  Dataset '{}': {} rows", name, rows.len());
    }

    // ET_DEPLAN 데이터셋이 존재하는지 확인
    let has_deplan = response
        .datasets
        .iter()
        .any(|(name, _)| name == "ET_DEPLAN");
    assert!(has_deplan, "response should contain ET_DEPLAN dataset");
}

#[cfg(not(feature = "client"))]
#[test]
fn feature_client_module_disabled() {
    // client feature가 비활성화되면 client 모듈 없음을 컴파일 타임에 확인
    // 이 테스트는 `--no-default-features`로 실행 시에만 활성화됨
    // core 모듈은 feature 없이도 정상 동작해야 함
    let buf = build_login_request("guest", "guest").unwrap();
    assert_eq!(buf.len(), REQUEST_FRAME_SIZE);
}

#[test]
fn wire_roundtrip_complex_message() {
    let mut w = BufWriter::new();
    // 헤더 구조 모방: magic + class_name + field_count + fields
    w.write_u32(MAGIC).unwrap();
    w.write_utf16be("test.ClassName").unwrap();
    w.write_u32(3).unwrap();
    w.write_utf16be("key1").unwrap();
    w.write_utf16be("val1").unwrap();
    w.write_utf16be("한글키").unwrap();
    w.write_utf16be("한글값").unwrap();
    w.write_utf16be("empty").unwrap();
    w.write_utf16be("").unwrap();
    // 추가 데이터
    w.write_i32(-42).unwrap();
    w.write_bool(true).unwrap();
    w.write_utf("Modified UTF-8 string").unwrap();

    let data = w.as_bytes()[..w.offset()].to_vec();
    let mut r = BufReader::new(&data);

    assert_eq!(r.read_u32().unwrap(), MAGIC);
    assert_eq!(r.read_utf16be().unwrap(), "test.ClassName");
    assert_eq!(r.read_u32().unwrap(), 3);
    assert_eq!(r.read_utf16be().unwrap(), "key1");
    assert_eq!(r.read_utf16be().unwrap(), "val1");
    assert_eq!(r.read_utf16be().unwrap(), "한글키");
    assert_eq!(r.read_utf16be().unwrap(), "한글값");
    assert_eq!(r.read_utf16be().unwrap(), "empty");
    assert_eq!(r.read_utf16be().unwrap(), "");
    assert_eq!(r.read_i32().unwrap(), -42);
    assert!(r.read_bool().unwrap());
    assert_eq!(r.read_utf().unwrap(), "Modified UTF-8 string");
}

#[test]
fn all_sql_types_field_read_roundtrip() {
    // 모든 SQL 타입의 필드 값을 작성하고 읽어 검증
    let test_cases: Vec<(SqlType, Vec<u8>, FieldValue)> = vec![
        // SmallInt normal
        (
            SqlType::SmallInt,
            42i32.to_be_bytes().to_vec(),
            FieldValue::Int(42),
        ),
        // SmallInt null
        (
            SqlType::SmallInt,
            i32::MIN.to_be_bytes().to_vec(),
            FieldValue::Null,
        ),
        // TinyInt
        (
            SqlType::TinyInt,
            7i32.to_be_bytes().to_vec(),
            FieldValue::Int(7),
        ),
        // Bit
        (SqlType::Bit, vec![0x01], FieldValue::Bool(true)),
        (SqlType::Bit, vec![0x00], FieldValue::Bool(false)),
    ];

    for (sql_type, data, expected) in test_cases {
        let mut r = BufReader::new(&data);
        let value = read_field_value(&mut r, sql_type).unwrap();
        assert_eq!(value, expected, "Failed for {:?}", sql_type);
    }

    // Integer with bool prefix
    {
        let mut data = vec![0x00]; // not null
        data.extend_from_slice(&100i32.to_be_bytes());
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Integer).unwrap(),
            FieldValue::Int(100)
        );
    }

    // Integer null
    {
        let data = vec![0x01]; // null
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Integer).unwrap(),
            FieldValue::Null
        );
    }

    // BigInt
    {
        let mut data = vec![0x00];
        data.extend_from_slice(&999_999_999_999i64.to_be_bytes());
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::BigInt).unwrap(),
            FieldValue::Long(999_999_999_999)
        );
    }

    // VarChar
    {
        let mut data = vec![0x00]; // not null
        let s = "hello";
        data.extend_from_slice(&(s.len() as u16).to_be_bytes());
        data.extend_from_slice(s.as_bytes());
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::VarChar).unwrap(),
            FieldValue::String("hello".into())
        );
    }

    // VarChar null
    {
        let data = vec![0x01]; // null
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::VarChar).unwrap(),
            FieldValue::Null
        );
    }

    // Numeric (no bool prefix!)
    {
        let s = "456.78";
        let mut data = (s.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(s.as_bytes());
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Numeric).unwrap(),
            FieldValue::String("456.78".into())
        );
    }

    // Numeric null (empty string)
    {
        let data = 0u16.to_be_bytes().to_vec(); // len = 0
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Numeric).unwrap(),
            FieldValue::Null
        );
    }

    // Date normal
    {
        let data = 1_609_459_200_000i64.to_be_bytes().to_vec();
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Date).unwrap(),
            FieldValue::DateTime(1_609_459_200_000)
        );
    }

    // Date null
    {
        let null_ms = ((i32::MIN as i64) << 32).to_be_bytes().to_vec();
        let mut r = BufReader::new(&null_ms);
        assert_eq!(
            read_field_value(&mut r, SqlType::Date).unwrap(),
            FieldValue::Null
        );
    }

    // Binary
    {
        let payload = vec![0x01, 0x02, 0x03];
        let mut data = (payload.len() as i32).to_be_bytes().to_vec();
        data.extend_from_slice(&payload);
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Binary).unwrap(),
            FieldValue::Binary(vec![0x01, 0x02, 0x03])
        );
    }

    // Binary null
    {
        let data = 0i32.to_be_bytes().to_vec(); // len = 0
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Binary).unwrap(),
            FieldValue::Null
        );
    }

    // Float (same encoding as Double: bool prefix + f64)
    {
        let mut data = vec![0x00]; // not null
        data.extend_from_slice(&std::f64::consts::E.to_be_bytes());
        let mut r = BufReader::new(&data);
        match read_field_value(&mut r, SqlType::Float).unwrap() {
            FieldValue::Double(v) => assert!((v - std::f64::consts::E).abs() < 1e-10),
            other => panic!("expected Double for Float, got: {:?}", other),
        }
    }

    // Float null
    {
        let data = vec![0x01]; // null
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Float).unwrap(),
            FieldValue::Null
        );
    }

    // Real (bool prefix + f32)
    {
        let mut data = vec![0x00];
        data.extend_from_slice(&2.5f32.to_be_bytes());
        let mut r = BufReader::new(&data);
        match read_field_value(&mut r, SqlType::Real).unwrap() {
            FieldValue::Float(v) => assert!((v - 2.5).abs() < 1e-6),
            other => panic!("expected Float for Real, got: {:?}", other),
        }
    }

    // Double
    {
        let mut data = vec![0x00];
        data.extend_from_slice(&std::f64::consts::PI.to_be_bytes());
        let mut r = BufReader::new(&data);
        match read_field_value(&mut r, SqlType::Double).unwrap() {
            FieldValue::Double(v) => assert!((v - std::f64::consts::PI).abs() < 1e-10),
            other => panic!("expected Double, got: {:?}", other),
        }
    }

    // Char (same encoding as VarChar)
    {
        let mut data = vec![0x00];
        let s = "char_val";
        data.extend_from_slice(&(s.len() as u16).to_be_bytes());
        data.extend_from_slice(s.as_bytes());
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Char).unwrap(),
            FieldValue::String("char_val".into())
        );
    }

    // LongVarChar
    {
        let mut data = vec![0x00];
        let s = "long_text";
        data.extend_from_slice(&(s.len() as u16).to_be_bytes());
        data.extend_from_slice(s.as_bytes());
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::LongVarChar).unwrap(),
            FieldValue::String("long_text".into())
        );
    }

    // Decimal (same encoding as Numeric: no bool prefix)
    {
        let s = "789.01";
        let mut data = (s.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(s.as_bytes());
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Decimal).unwrap(),
            FieldValue::String("789.01".into())
        );
    }

    // Time (same as Date: i64 epoch ms)
    {
        let data = 43200000i64.to_be_bytes().to_vec(); // 12:00:00.000
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Time).unwrap(),
            FieldValue::DateTime(43200000)
        );
    }

    // VarBinary
    {
        let payload = vec![0xAA, 0xBB];
        let mut data = (payload.len() as i32).to_be_bytes().to_vec();
        data.extend_from_slice(&payload);
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::VarBinary).unwrap(),
            FieldValue::Binary(vec![0xAA, 0xBB])
        );
    }

    // LongVarBinary
    {
        let payload = vec![0xCC];
        let mut data = (payload.len() as i32).to_be_bytes().to_vec();
        data.extend_from_slice(&payload);
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::LongVarBinary).unwrap(),
            FieldValue::Binary(vec![0xCC])
        );
    }

    // Blob
    {
        let payload = vec![0xFF, 0xFE];
        let mut data = (payload.len() as i32).to_be_bytes().to_vec();
        data.extend_from_slice(&payload);
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Blob).unwrap(),
            FieldValue::Binary(vec![0xFF, 0xFE])
        );
    }

    // Clob (string class, same as VarChar)
    {
        let mut data = vec![0x00];
        let s = "clob_data";
        data.extend_from_slice(&(s.len() as u16).to_be_bytes());
        data.extend_from_slice(s.as_bytes());
        let mut r = BufReader::new(&data);
        assert_eq!(
            read_field_value(&mut r, SqlType::Clob).unwrap(),
            FieldValue::String("clob_data".into())
        );
    }
}

#[test]
fn all_request_types_exactly_9545_bytes() {
    let login = build_login_request("guest", "guest").unwrap();
    assert_eq!(login.len(), 9545, "login request size mismatch");

    let repo = build_repository_request("/a/b/c.ozr", "s1").unwrap();
    assert_eq!(repo.len(), 9545, "repository request size mismatch");

    let params = vec![
        ("a".to_string(), "1".to_string()),
        ("b".to_string(), "2".to_string()),
        ("c".to_string(), "3".to_string()),
    ];
    let dm = build_data_module_request("x.odi", "/Y", &params, "s2").unwrap();
    assert_eq!(dm.len(), 9545, "data module request size mismatch");
}

#[test]
fn request_with_empty_params() {
    let params: Vec<(String, String)> = vec![];
    let buf = build_data_module_request("empty.odi", "/", &params, "s0").unwrap();
    assert_eq!(buf.len(), 9545);

    let mut reader = BufReader::new(&buf);
    let header = parse_header(&mut reader).unwrap();
    assert_eq!(header.class_name, class_names::DATA_MODULE);
}

/// UTF-16BE 문자열을 raw Vec에 작성
fn write_utf16be_raw(buf: &mut Vec<u8>, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
    for u in &units {
        buf.extend_from_slice(&u.to_be_bytes());
    }
}

/// Java Modified UTF-8 문자열을 raw Vec에 작성
fn write_utf_raw(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// BasicField를 raw Vec에 작성
fn write_basic_field_raw(buf: &mut Vec<u8>, kind: i32, sql_type: i32, name: &str, nullable: bool) {
    buf.extend_from_slice(&kind.to_be_bytes());
    buf.extend_from_slice(&sql_type.to_be_bytes());
    write_utf_raw(buf, name);
    buf.push(if nullable { 0x01 } else { 0x00 });
}

/// DataModule 응답의 공통 프리앰블 작성 (헤더 + 페이로드 헤더 + TTk)
fn write_dm_preamble(buf: &mut Vec<u8>, class_name: &str, session_id: &str, group_count: i16) {
    // 헤더
    buf.extend_from_slice(&MAGIC.to_be_bytes());
    write_utf16be_raw(buf, class_name);
    buf.extend_from_slice(&1u32.to_be_bytes()); // 1 field
    write_utf16be_raw(buf, "s");
    write_utf16be_raw(buf, session_id);

    // 페이로드 헤더
    buf.extend_from_slice(&380i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.push(0x01);

    // TTk 헤더
    buf.extend_from_slice(&17i32.to_be_bytes());
    write_utf_raw(buf, DATA_MODULE_PREFIX);
    buf.extend_from_slice(&2040i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());

    // 그룹 수
    buf.extend_from_slice(&group_count.to_be_bytes());
}

/// 단일 그룹 DataModule 응답 (NAME:VarChar, AGE:Integer, 2행)
fn build_test_dm_response_single_group() -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);
    write_dm_preamble(&mut buf, "TestDM", "session42", 1);

    // 그룹: TestGroup
    write_utf_raw(&mut buf, "TestGroup");
    write_utf_raw(&mut buf, "ByteArraySet");
    write_utf_raw(&mut buf, "");

    // 2 fields
    buf.extend_from_slice(&2i32.to_be_bytes());
    write_basic_field_raw(&mut buf, 1, 12, "NAME", true); // VarChar
    write_basic_field_raw(&mut buf, 1, 4, "AGE", true); // Integer

    // 0 secondary
    buf.extend_from_slice(&0i32.to_be_bytes());

    // 1 dataset, 2 rows
    buf.extend_from_slice(&1i32.to_be_bytes());
    buf.extend_from_slice(&100i32.to_be_bytes()); // byte_size
    buf.extend_from_slice(&2i32.to_be_bytes()); // row_count
    write_utf_raw(&mut buf, "ds0");

    // 행 데이터
    let row1 = build_varchar_int_row("Alice", false, 30, false);
    let row2 = build_varchar_int_row("Bob", false, 25, false);

    let total_size = row1.len() + row2.len();
    buf.extend_from_slice(&(total_size as i32).to_be_bytes());

    // RecordInfo
    buf.extend_from_slice(&(row1.len() as i32).to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&(row2.len() as i32).to_be_bytes());
    buf.extend_from_slice(&(row1.len() as i32).to_be_bytes());

    // data blob
    buf.extend_from_slice(&row1);
    buf.extend_from_slice(&row2);

    buf
}

fn build_varchar_int_row(text: &str, text_null: bool, int_val: i32, int_null: bool) -> Vec<u8> {
    let mut row = Vec::new();
    // VarChar
    if text_null {
        row.push(0x01);
    } else {
        row.push(0x00);
        let bytes = text.as_bytes();
        row.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        row.extend_from_slice(bytes);
    }
    // Integer
    if int_null {
        row.push(0x01);
    } else {
        row.push(0x00);
        row.extend_from_slice(&int_val.to_be_bytes());
    }
    row
}

/// 복수 그룹 DataModule 응답
fn build_test_dm_response_multi_group() -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);
    write_dm_preamble(&mut buf, "MultiDM", "sess_multi", 2);

    // --- 그룹 1: G1 with SmallInt ---
    write_utf_raw(&mut buf, "G1");
    write_utf_raw(&mut buf, "ByteArraySet");
    write_utf_raw(&mut buf, "");
    buf.extend_from_slice(&1i32.to_be_bytes()); // 1 field
    write_basic_field_raw(&mut buf, 1, 5, "ID", false); // SmallInt
    buf.extend_from_slice(&0i32.to_be_bytes()); // 0 secondary
    buf.extend_from_slice(&1i32.to_be_bytes()); // 1 dataset
    buf.extend_from_slice(&8i32.to_be_bytes());
    buf.extend_from_slice(&2i32.to_be_bytes()); // 2 rows
    write_utf_raw(&mut buf, "d0");

    // --- 그룹 2: G2 with VarChar + Bit ---
    write_utf_raw(&mut buf, "G2");
    write_utf_raw(&mut buf, "ByteArraySet");
    write_utf_raw(&mut buf, "");
    buf.extend_from_slice(&2i32.to_be_bytes()); // 2 fields
    write_basic_field_raw(&mut buf, 1, 12, "FLAG_NAME", true); // VarChar
    write_basic_field_raw(&mut buf, 1, -7, "FLAG_VAL", false); // Bit
    buf.extend_from_slice(&0i32.to_be_bytes()); // 0 secondary
    buf.extend_from_slice(&1i32.to_be_bytes()); // 1 dataset
    buf.extend_from_slice(&20i32.to_be_bytes());
    buf.extend_from_slice(&1i32.to_be_bytes()); // 1 row
    write_utf_raw(&mut buf, "d1");

    // 행 데이터
    let g1_row1 = 100i32.to_be_bytes().to_vec(); // SmallInt
    let g1_row2 = 200i32.to_be_bytes().to_vec();

    let mut g2_row = Vec::new();
    g2_row.push(0x00); // VarChar not null
    let s = "active";
    g2_row.extend_from_slice(&(s.len() as u16).to_be_bytes());
    g2_row.extend_from_slice(s.as_bytes());
    g2_row.push(0x01); // Bit = true

    let total = g1_row1.len() + g1_row2.len() + g2_row.len();
    buf.extend_from_slice(&(total as i32).to_be_bytes());

    // RecordInfo: G1 ds0 (2 rows)
    let mut off = 0i32;
    buf.extend_from_slice(&(g1_row1.len() as i32).to_be_bytes());
    buf.extend_from_slice(&off.to_be_bytes());
    off += g1_row1.len() as i32;
    buf.extend_from_slice(&(g1_row2.len() as i32).to_be_bytes());
    buf.extend_from_slice(&off.to_be_bytes());
    off += g1_row2.len() as i32;

    // RecordInfo: G2 ds0 (1 row)
    buf.extend_from_slice(&(g2_row.len() as i32).to_be_bytes());
    buf.extend_from_slice(&off.to_be_bytes());

    // data blob
    buf.extend_from_slice(&g1_row1);
    buf.extend_from_slice(&g1_row2);
    buf.extend_from_slice(&g2_row);

    buf
}

/// NULL 값이 포함된 DataModule 응답
fn build_test_dm_response_with_nulls() -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);
    write_dm_preamble(&mut buf, "NullDM", "sess_null", 1);

    write_utf_raw(&mut buf, "NullGrp");
    write_utf_raw(&mut buf, "ByteArraySet");
    write_utf_raw(&mut buf, "");
    buf.extend_from_slice(&2i32.to_be_bytes());
    write_basic_field_raw(&mut buf, 1, 12, "TEXT", true); // VarChar
    write_basic_field_raw(&mut buf, 1, 4, "NUM", true); // Integer
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&1i32.to_be_bytes());
    buf.extend_from_slice(&50i32.to_be_bytes());
    buf.extend_from_slice(&3i32.to_be_bytes()); // 3 rows
    write_utf_raw(&mut buf, "d0");

    // row1: TEXT=NULL, NUM=42
    let row1 = build_varchar_int_row("", true, 42, false);
    // row2: TEXT="hello", NUM=NULL
    let row2 = build_varchar_int_row("hello", false, 0, true);
    // row3: TEXT=NULL, NUM=NULL
    let row3 = build_varchar_int_row("", true, 0, true);

    let total = row1.len() + row2.len() + row3.len();
    buf.extend_from_slice(&(total as i32).to_be_bytes());

    let mut off = 0i32;
    buf.extend_from_slice(&(row1.len() as i32).to_be_bytes());
    buf.extend_from_slice(&off.to_be_bytes());
    off += row1.len() as i32;
    buf.extend_from_slice(&(row2.len() as i32).to_be_bytes());
    buf.extend_from_slice(&off.to_be_bytes());
    off += row2.len() as i32;
    buf.extend_from_slice(&(row3.len() as i32).to_be_bytes());
    buf.extend_from_slice(&off.to_be_bytes());

    buf.extend_from_slice(&row1);
    buf.extend_from_slice(&row2);
    buf.extend_from_slice(&row3);

    buf
}

/// Numeric + Timestamp + Binary DataModule 응답
fn build_test_dm_response_numeric_timestamp_binary() -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);
    write_dm_preamble(&mut buf, "MixedDM", "sess_mixed", 1);

    write_utf_raw(&mut buf, "MixedGrp");
    write_utf_raw(&mut buf, "ByteArraySet");
    write_utf_raw(&mut buf, "");
    buf.extend_from_slice(&3i32.to_be_bytes()); // 3 fields
    write_basic_field_raw(&mut buf, 1, 2, "PRICE", true); // Numeric
    write_basic_field_raw(&mut buf, 1, 93, "CREATED", true); // Timestamp
    write_basic_field_raw(&mut buf, 1, -2, "DATA", true); // Binary
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&1i32.to_be_bytes());
    buf.extend_from_slice(&50i32.to_be_bytes());
    buf.extend_from_slice(&1i32.to_be_bytes()); // 1 row
    write_utf_raw(&mut buf, "d0");

    // 행 데이터
    let mut row = Vec::new();
    // Numeric: "123.456" (no bool prefix!)
    let price = "123.456";
    row.extend_from_slice(&(price.len() as u16).to_be_bytes());
    row.extend_from_slice(price.as_bytes());
    // Timestamp: epoch ms
    row.extend_from_slice(&1_700_000_000_000i64.to_be_bytes());
    // Binary: [0xDE, 0xAD]
    row.extend_from_slice(&2i32.to_be_bytes());
    row.extend_from_slice(&[0xDE, 0xAD]);

    buf.extend_from_slice(&(row.len() as i32).to_be_bytes());

    buf.extend_from_slice(&(row.len() as i32).to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());

    buf.extend_from_slice(&row);

    buf
}

/// 보조 필드가 있는 DataModule 응답
fn build_test_dm_response_with_secondary_fields() -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);
    write_dm_preamble(&mut buf, "SecDM", "sess_sec", 1);

    write_utf_raw(&mut buf, "SecGrp");
    write_utf_raw(&mut buf, "ByteArraySet");
    write_utf_raw(&mut buf, "");

    // 1 primary field: SmallInt "MAIN_FIELD"
    buf.extend_from_slice(&1i32.to_be_bytes());
    write_basic_field_raw(&mut buf, 1, 5, "MAIN_FIELD", false); // SmallInt

    // 1 secondary field: VarChar "SEC_FIELD" (반드시 읽어서 오프셋 전진, 데이터 파싱엔 미사용)
    buf.extend_from_slice(&1i32.to_be_bytes());
    write_basic_field_raw(&mut buf, 1, 12, "SEC_FIELD", true); // VarChar

    buf.extend_from_slice(&1i32.to_be_bytes()); // 1 dataset
    buf.extend_from_slice(&4i32.to_be_bytes());
    buf.extend_from_slice(&1i32.to_be_bytes()); // 1 row
    write_utf_raw(&mut buf, "d0");

    // 행 데이터: SmallInt = 999
    let row = 999i32.to_be_bytes().to_vec();

    buf.extend_from_slice(&(row.len() as i32).to_be_bytes());
    buf.extend_from_slice(&(row.len() as i32).to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());

    buf.extend_from_slice(&row);

    buf
}

/// 잘못된 prefix의 DataModule 응답
fn build_dm_with_wrong_prefix(prefix: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // 헤더
    buf.extend_from_slice(&MAGIC.to_be_bytes());
    write_utf16be_raw(&mut buf, "Test");
    buf.extend_from_slice(&0u32.to_be_bytes());

    // 페이로드 헤더
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.push(0x01);

    // TTk 헤더 with wrong prefix
    buf.extend_from_slice(&17i32.to_be_bytes());
    write_utf_raw(&mut buf, prefix);

    buf
}

/// 에러 응답 바이너리 생성
fn build_error_response_raw(error_code: i32, message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(&MAGIC.to_be_bytes());

    // 클래스명에 "ExceptionMessage" 포함
    let class_name = "oz.framework.OZCPExceptionMessage";
    let units: Vec<u16> = class_name.encode_utf16().collect();
    buf.extend_from_slice(&(units.len() as u32).to_be_bytes());
    for u in &units {
        buf.extend_from_slice(&u.to_be_bytes());
    }

    // error code
    buf.extend_from_slice(&error_code.to_be_bytes());

    // message (UTF-16BE)
    let msg_units: Vec<u16> = message.encode_utf16().collect();
    buf.extend_from_slice(&(msg_units.len() as u32).to_be_bytes());
    for u in &msg_units {
        buf.extend_from_slice(&u.to_be_bytes());
    }

    buf
}
