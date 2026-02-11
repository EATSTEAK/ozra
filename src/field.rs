//! SQL 타입별 필드 값 디코딩 모듈
//!
//! OZ 프로토콜의 DataModule 응답에서 각 SQL 타입에 따라
//! 바이너리 데이터를 [`FieldValue`]로 변환합니다.
//!
//! ## 핵심 함수
//!
//! - [`read_field_value`] — SQL 타입별 단일 필드 값 디코딩
//! - [`read_row`] — 필드 목록 기반 한 행 전체 디코딩
//!
//! ## SQL 타입별 인코딩 규칙
//!
//! | 필드 클래스 | SQL 타입 | 바이너리 형식 | Null 판별 |
//! |---|---|---|---|
//! | BasicSmallField | TINYINT, SMALLINT | `i32(4B)` | `== i32::MIN` |
//! | BasicIntField | INTEGER | `bool(1B) + i32(4B)` | `bool == true` |
//! | BasicLongField | BIGINT | `bool(1B) + i64(8B)` | `bool == true` |
//! | BasicFloatField | REAL | `bool(1B) + f32(4B)` | `bool == true` |
//! | BasicDoubleField | FLOAT, DOUBLE | `bool(1B) + f64(8B)` | `bool == true` |
//! | BasicBooleanField | BIT | `u8(1B)` | null 없음 |
//! | BasicStringField | CHAR, VARCHAR, LONGVARCHAR, CLOB | `bool(1B) + UTF(2+NB)` | `bool == true` |
//! | BasicStringField2 | NUMERIC, DECIMAL | `UTF(2+NB)` (bool 없음!) | 빈 문자열 |
//! | BasicDateField | DATE, TIME, TIMESTAMP | `i64(8B)` | `hi == i32::MIN && lo == 0` |
//! | BasicBinaryField | BINARY, VARBINARY, LONGVARBINARY, BLOB | `i32(4B) len + bytes` | `len <= 0` |

use crate::constants::MAX_BINARY_LENGTH;
use crate::error::{OzError, Result};
use crate::types::{BasicField, FieldValue, Row, SqlType};
use crate::wire::BufReader;

/// SQL 타입에 따라 바이너리 데이터에서 필드 값을 디코딩합니다.
///
/// 알 수 없는 SQL 타입은 [`BasicStringField`](SqlType::Char) 동일 방식으로 처리합니다.
///
/// # 인자
///
/// - `reader` — 현재 위치에서 읽을 [`BufReader`]
/// - `sql_type` — 필드의 SQL 타입 코드
///
/// # 반환
///
/// 디코딩된 [`FieldValue`]. SQL NULL이면 [`FieldValue::Null`]을 반환합니다.
///
/// # 에러
///
/// 바이너리 데이터가 부족하면 [`OzError::UnexpectedEof`](crate::error::OzError::UnexpectedEof)를 반환합니다.
pub fn read_field_value(reader: &mut BufReader, sql_type: SqlType) -> Result<FieldValue> {
    match sql_type {
        // BasicSmallField: TINYINT(-6), SMALLINT(5)
        // 4B i32, null sentinel = i32::MIN (0x80000000)
        SqlType::TinyInt | SqlType::SmallInt => {
            let raw = reader.read_i32()?;
            if raw == i32::MIN {
                Ok(FieldValue::Null)
            } else {
                Ok(FieldValue::Int(raw))
            }
        }

        // BasicIntField: INTEGER(4)
        // bool(1B) + i32(4B), null이면 bool == true
        SqlType::Integer => {
            let is_null = reader.read_bool()?;
            if is_null {
                Ok(FieldValue::Null)
            } else {
                Ok(FieldValue::Int(reader.read_i32()?))
            }
        }

        // BasicLongField: BIGINT(-5)
        // bool(1B) + i64(8B), null이면 bool == true
        SqlType::BigInt => {
            let is_null = reader.read_bool()?;
            if is_null {
                Ok(FieldValue::Null)
            } else {
                Ok(FieldValue::Long(reader.read_i64()?))
            }
        }

        // BasicFloatField: REAL(7)
        // bool(1B) + f32(4B), null이면 bool == true
        SqlType::Real => {
            let is_null = reader.read_bool()?;
            if is_null {
                Ok(FieldValue::Null)
            } else {
                Ok(FieldValue::Float(reader.read_f32()?))
            }
        }

        // BasicDoubleField: FLOAT(6), DOUBLE(8)
        // bool(1B) + f64(8B), null이면 bool == true
        SqlType::Float | SqlType::Double => {
            let is_null = reader.read_bool()?;
            if is_null {
                Ok(FieldValue::Null)
            } else {
                Ok(FieldValue::Double(reader.read_f64()?))
            }
        }

        // BasicBooleanField: BIT(-7)
        // u8(1B), null 없음
        SqlType::Bit => Ok(FieldValue::Bool(reader.read_u8()? != 0)),

        // BasicStringField: CHAR(1), VARCHAR(12), LONGVARCHAR(-1), CLOB(2005)
        // bool(1B) + readUTF(2+NB), null이면 bool == true
        SqlType::Char | SqlType::VarChar | SqlType::LongVarChar | SqlType::Clob => {
            let is_null = reader.read_bool()?;
            if is_null {
                Ok(FieldValue::Null)
            } else {
                Ok(FieldValue::String(reader.read_utf()?))
            }
        }

        // BasicStringField2: NUMERIC(2), DECIMAL(3) — ⚠️ boolean prefix 없음!
        // readUTF(2+NB) 직접, null이면 빈 문자열
        SqlType::Numeric | SqlType::Decimal => {
            let s = reader.read_utf()?;
            if s.is_empty() {
                Ok(FieldValue::Null)
            } else {
                Ok(FieldValue::String(s))
            }
        }

        // BasicDateField: DATE(91), TIME(92), TIMESTAMP(93)
        // i64(8B) = epoch milliseconds
        // null 체크: hi == i32::MIN (0x80000000) && lo == 0
        SqlType::Date | SqlType::Time | SqlType::Timestamp => {
            let millis = reader.read_i64()?;
            let hi = (millis >> 32) as i32;
            let lo = millis as u32;
            if hi == i32::MIN && lo == 0 {
                Ok(FieldValue::Null)
            } else {
                Ok(FieldValue::DateTime(millis))
            }
        }

        // BasicBinaryField: BINARY(-2), VARBINARY(-3), LONGVARBINARY(-4), BLOB(2004)
        // i32(4B) = length, 그 다음 raw bytes
        SqlType::Binary | SqlType::VarBinary | SqlType::LongVarBinary | SqlType::Blob => {
            let length = reader.read_i32()?;
            if length <= 0 {
                Ok(FieldValue::Null)
            } else {
                let len = length as usize;
                // DoS 방어: 바이너리 크기가 너무 크면 거부
                if len > MAX_BINARY_LENGTH {
                    return Err(OzError::BinaryTooLarge {
                        length: len,
                        max: MAX_BINARY_LENGTH,
                    });
                }
                Ok(FieldValue::Binary(reader.read_bytes(len)?.to_vec()))
            }
        }
    }
}

/// 알 수 없는 SQL 타입 코드에 대해 필드 값을 읽습니다.
///
/// [`BasicStringField`](SqlType::Char) 동일 방식으로 처리합니다:
/// `bool(1B) + readUTF(2+NB)`, null이면 `bool == true`.
///
/// 이 함수는 [`SqlType`]으로 변환할 수 없는 원시 SQL 코드를 처리할 때 사용합니다.
pub fn read_field_value_default(reader: &mut BufReader) -> Result<FieldValue> {
    let is_null = reader.read_bool()?;
    if is_null {
        Ok(FieldValue::Null)
    } else {
        Ok(FieldValue::String(reader.read_utf()?))
    }
}

/// 필드 목록을 기반으로 한 행(row)의 전체 필드 값을 디코딩합니다.
///
/// # 인자
///
/// - `reader` — 현재 위치에서 읽을 [`BufReader`]
/// - `fields` — 행의 필드 정의 목록 ([`BasicField`])
///
/// # 반환
///
/// `(필드명, 필드값)` 쌍의 벡터. 필드 순서는 입력 `fields` 순서와 동일합니다.
pub fn read_row(reader: &mut BufReader, fields: &[BasicField]) -> Result<Row> {
    fields
        .iter()
        .map(|field| {
            let value = read_field_value(reader, field.sql_type)?;
            Ok((field.name.clone(), value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FieldKind;
    use crate::wire::BufWriter;

    /// BufWriter로 작성한 데이터를 Vec<u8>로 변환하는 헬퍼
    fn writer_to_vec(w: &BufWriter) -> Vec<u8> {
        w.as_bytes()[..w.offset()].to_vec()
    }

    #[test]
    fn test_tinyint_normal_value() {
        let mut w = BufWriter::new();
        w.write_i32(42).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::TinyInt).unwrap();
        assert_eq!(v, FieldValue::Int(42));
    }

    #[test]
    fn test_tinyint_null_sentinel() {
        let mut w = BufWriter::new();
        w.write_i32(i32::MIN).unwrap(); // 0x80000000
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::TinyInt).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_smallint_normal_value() {
        let mut w = BufWriter::new();
        w.write_i32(256).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::SmallInt).unwrap();
        assert_eq!(v, FieldValue::Int(256));
    }

    #[test]
    fn test_smallint_null_sentinel() {
        let mut w = BufWriter::new();
        w.write_i32(i32::MIN).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::SmallInt).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_smallint_zero() {
        let mut w = BufWriter::new();
        w.write_i32(0).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::SmallInt).unwrap();
        assert_eq!(v, FieldValue::Int(0));
    }

    #[test]
    fn test_smallint_negative() {
        let mut w = BufWriter::new();
        w.write_i32(-100).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::SmallInt).unwrap();
        assert_eq!(v, FieldValue::Int(-100));
    }

    #[test]
    fn test_integer_normal_value() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap(); // not null
        w.write_i32(12345).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Integer).unwrap();
        assert_eq!(v, FieldValue::Int(12345));
    }

    #[test]
    fn test_integer_null() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap(); // null
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Integer).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_integer_zero() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_i32(0).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Integer).unwrap();
        assert_eq!(v, FieldValue::Int(0));
    }

    #[test]
    fn test_bigint_normal_value() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_i64(9876543210).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::BigInt).unwrap();
        assert_eq!(v, FieldValue::Long(9876543210));
    }

    #[test]
    fn test_bigint_null() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::BigInt).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_real_normal_value() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_f32(1.5_f32).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Real).unwrap();
        match v {
            FieldValue::Float(f) => assert!((f - 1.5_f32).abs() < 0.001),
            other => panic!("expected Float, got {:?}", other),
        }
    }

    #[test]
    fn test_real_null() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Real).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_float_double_normal_value() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_f64(std::f64::consts::PI).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Float).unwrap();
        match v {
            FieldValue::Double(d) => assert!((d - std::f64::consts::PI).abs() < f64::EPSILON),
            other => panic!("expected Double, got {:?}", other),
        }
    }

    #[test]
    fn test_double_normal_value() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_f64(1.23456).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Double).unwrap();
        match v {
            FieldValue::Double(d) => assert!((d - 1.23456).abs() < 0.0001),
            other => panic!("expected Double, got {:?}", other),
        }
    }

    #[test]
    fn test_float_null() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Float).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_double_null() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Double).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_bit_true() {
        let mut w = BufWriter::new();
        w.write_u8(1).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Bit).unwrap();
        assert_eq!(v, FieldValue::Bool(true));
    }

    #[test]
    fn test_bit_false() {
        let mut w = BufWriter::new();
        w.write_u8(0).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Bit).unwrap();
        assert_eq!(v, FieldValue::Bool(false));
    }

    #[test]
    fn test_bit_nonzero_is_true() {
        let mut w = BufWriter::new();
        w.write_u8(0xFF).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Bit).unwrap();
        assert_eq!(v, FieldValue::Bool(true));
    }

    #[test]
    fn test_varchar_normal_value() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_utf("hello world").unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::VarChar).unwrap();
        assert_eq!(v, FieldValue::String("hello world".to_string()));
    }

    #[test]
    fn test_varchar_null() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::VarChar).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_char_normal_value() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_utf("A").unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Char).unwrap();
        assert_eq!(v, FieldValue::String("A".to_string()));
    }

    #[test]
    fn test_longvarchar_normal_value() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_utf("장문 텍스트").unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::LongVarChar).unwrap();
        assert_eq!(v, FieldValue::String("장문 텍스트".to_string()));
    }

    #[test]
    fn test_clob_null() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Clob).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_numeric_normal_value() {
        let mut w = BufWriter::new();
        w.write_utf("123.456").unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Numeric).unwrap();
        assert_eq!(v, FieldValue::String("123.456".to_string()));
    }

    #[test]
    fn test_numeric_null_empty_string() {
        let mut w = BufWriter::new();
        w.write_utf("").unwrap(); // 빈 문자열 → Null
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Numeric).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_decimal_normal_value() {
        let mut w = BufWriter::new();
        w.write_utf("99999.99").unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Decimal).unwrap();
        assert_eq!(v, FieldValue::String("99999.99".to_string()));
    }

    #[test]
    fn test_decimal_null_empty_string() {
        let mut w = BufWriter::new();
        w.write_utf("").unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Decimal).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_numeric_no_boolean_prefix() {
        // NUMERIC/DECIMAL은 boolean prefix가 없으므로,
        // 만약 boolean prefix가 있다고 가정하면 offset이 달라질 것임
        let mut w = BufWriter::new();
        w.write_utf("42").unwrap();
        let data = writer_to_vec(&w);
        // 데이터: [0x00, 0x02, 0x34, 0x32] (2B len + "42")
        assert_eq!(data.len(), 4); // bool(1B)이 없으므로 총 4바이트
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Numeric).unwrap();
        assert_eq!(v, FieldValue::String("42".to_string()));
        assert_eq!(r.offset(), 4); // 정확히 4바이트 소비
    }

    #[test]
    fn test_date_normal_value() {
        let epoch_ms: i64 = 1_700_000_000_000; // 2023-11-14T22:13:20Z
        let mut w = BufWriter::new();
        w.write_i64(epoch_ms).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Date).unwrap();
        assert_eq!(v, FieldValue::DateTime(1_700_000_000_000));
    }

    #[test]
    fn test_date_null_sentinel() {
        // null: hi == i32::MIN (0x80000000), lo == 0
        // i64 = (i32::MIN as i64) << 32 = 0x80000000_00000000
        let null_millis: i64 = (i32::MIN as i64) << 32;
        let mut w = BufWriter::new();
        w.write_i64(null_millis).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Date).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_time_normal_value() {
        let epoch_ms: i64 = 43_200_000; // 12:00:00.000
        let mut w = BufWriter::new();
        w.write_i64(epoch_ms).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Time).unwrap();
        assert_eq!(v, FieldValue::DateTime(43_200_000));
    }

    #[test]
    fn test_time_null_sentinel() {
        let null_millis: i64 = (i32::MIN as i64) << 32;
        let mut w = BufWriter::new();
        w.write_i64(null_millis).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Time).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_timestamp_normal_value() {
        let epoch_ms: i64 = 1_609_459_200_000; // 2021-01-01T00:00:00Z
        let mut w = BufWriter::new();
        w.write_i64(epoch_ms).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Timestamp).unwrap();
        assert_eq!(v, FieldValue::DateTime(1_609_459_200_000));
    }

    #[test]
    fn test_timestamp_null_sentinel() {
        let null_millis: i64 = (i32::MIN as i64) << 32;
        let mut w = BufWriter::new();
        w.write_i64(null_millis).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Timestamp).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_date_null_verify_hi_lo_split() {
        // null sentinel의 실제 바이트 확인: 0x80 00 00 00 00 00 00 00
        let null_bytes: [u8; 8] = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut r = BufReader::new(&null_bytes);
        let v = read_field_value(&mut r, SqlType::Date).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_date_epoch_zero_not_null() {
        // epoch 0 (1970-01-01T00:00:00Z) — hi=0, lo=0 → null이 아님
        let mut w = BufWriter::new();
        w.write_i64(0).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Date).unwrap();
        assert_eq!(v, FieldValue::DateTime(0));
    }

    #[test]
    fn test_binary_normal_value() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut w = BufWriter::new();
        w.write_i32(payload.len() as i32).unwrap();
        w.write_bytes(&payload).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Binary).unwrap();
        assert_eq!(v, FieldValue::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn test_binary_null_zero_length() {
        let mut w = BufWriter::new();
        w.write_i32(0).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Binary).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_binary_null_negative_length() {
        let mut w = BufWriter::new();
        w.write_i32(-1).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Binary).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_varbinary_normal_value() {
        let payload = vec![0x01, 0x02, 0x03];
        let mut w = BufWriter::new();
        w.write_i32(3).unwrap();
        w.write_bytes(&payload).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::VarBinary).unwrap();
        assert_eq!(v, FieldValue::Binary(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_longvarbinary_null() {
        let mut w = BufWriter::new();
        w.write_i32(0).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::LongVarBinary).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_blob_normal_value() {
        let payload = vec![0xFF; 10];
        let mut w = BufWriter::new();
        w.write_i32(10).unwrap();
        w.write_bytes(&payload).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Blob).unwrap();
        assert_eq!(v, FieldValue::Binary(vec![0xFF; 10]));
    }

    #[test]
    fn test_default_normal_value() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_utf("unknown type value").unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value_default(&mut r).unwrap();
        assert_eq!(v, FieldValue::String("unknown type value".to_string()));
    }

    #[test]
    fn test_default_null() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value_default(&mut r).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_read_row_mixed_fields() {
        let fields = vec![
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::VarChar,
                name: "NAME".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Integer,
                name: "AGE".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Numeric,
                name: "SALARY".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Bit,
                name: "ACTIVE".to_string(),
                nullable: false,
                parsing_code: None,
            },
        ];

        let mut w = BufWriter::new();
        // VARCHAR "NAME" = "홍길동"
        w.write_bool(false).unwrap();
        w.write_utf("홍길동").unwrap();
        // INTEGER "AGE" = 30
        w.write_bool(false).unwrap();
        w.write_i32(30).unwrap();
        // NUMERIC "SALARY" = "50000.00"
        w.write_utf("50000.00").unwrap();
        // BIT "ACTIVE" = true
        w.write_u8(1).unwrap();

        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let row = read_row(&mut r, &fields).unwrap();

        assert_eq!(row.len(), 4);
        assert_eq!(
            row[0],
            ("NAME".to_string(), FieldValue::String("홍길동".to_string()))
        );
        assert_eq!(row[1], ("AGE".to_string(), FieldValue::Int(30)));
        assert_eq!(
            row[2],
            (
                "SALARY".to_string(),
                FieldValue::String("50000.00".to_string())
            )
        );
        assert_eq!(row[3], ("ACTIVE".to_string(), FieldValue::Bool(true)));
    }

    #[test]
    fn test_read_row_with_nulls() {
        let fields = vec![
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::VarChar,
                name: "DESCRIPTION".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Integer,
                name: "COUNT".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Date,
                name: "CREATED".to_string(),
                nullable: true,
                parsing_code: None,
            },
        ];

        let mut w = BufWriter::new();
        // VARCHAR "DESCRIPTION" = null
        w.write_bool(true).unwrap();
        // INTEGER "COUNT" = null
        w.write_bool(true).unwrap();
        // DATE "CREATED" = null
        let null_millis: i64 = (i32::MIN as i64) << 32;
        w.write_i64(null_millis).unwrap();

        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let row = read_row(&mut r, &fields).unwrap();

        assert_eq!(row.len(), 3);
        assert_eq!(row[0].1, FieldValue::Null);
        assert_eq!(row[1].1, FieldValue::Null);
        assert_eq!(row[2].1, FieldValue::Null);
    }

    #[test]
    fn test_read_row_empty_fields() {
        let fields: Vec<BasicField> = vec![];
        let data: Vec<u8> = vec![];
        let mut r = BufReader::new(&data);
        let row = read_row(&mut r, &fields).unwrap();
        assert!(row.is_empty());
    }

    #[test]
    fn test_read_row_single_field() {
        let fields = vec![BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::SmallInt,
            name: "ID".to_string(),
            nullable: false,
            parsing_code: None,
        }];

        let mut w = BufWriter::new();
        w.write_i32(999).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let row = read_row(&mut r, &fields).unwrap();

        assert_eq!(row.len(), 1);
        assert_eq!(row[0], ("ID".to_string(), FieldValue::Int(999)));
    }

    #[test]
    fn test_read_row_all_types() {
        let fields = vec![
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::TinyInt,
                name: "F_TINYINT".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Integer,
                name: "F_INT".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::BigInt,
                name: "F_BIGINT".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Real,
                name: "F_REAL".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Double,
                name: "F_DOUBLE".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Bit,
                name: "F_BIT".to_string(),
                nullable: false,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::VarChar,
                name: "F_VARCHAR".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Numeric,
                name: "F_NUMERIC".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Timestamp,
                name: "F_TIMESTAMP".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Binary,
                name: "F_BINARY".to_string(),
                nullable: true,
                parsing_code: None,
            },
        ];

        let mut w = BufWriter::new();
        // TINYINT = 7
        w.write_i32(7).unwrap();
        // INTEGER = 42
        w.write_bool(false).unwrap();
        w.write_i32(42).unwrap();
        // BIGINT = 1234567890123
        w.write_bool(false).unwrap();
        w.write_i64(1_234_567_890_123).unwrap();
        // REAL = 1.5
        w.write_bool(false).unwrap();
        w.write_f32(1.5_f32).unwrap();
        // DOUBLE = 9.876
        w.write_bool(false).unwrap();
        w.write_f64(9.876).unwrap();
        // BIT = true
        w.write_u8(1).unwrap();
        // VARCHAR = "test"
        w.write_bool(false).unwrap();
        w.write_utf("test").unwrap();
        // NUMERIC = "123.45"
        w.write_utf("123.45").unwrap();
        // TIMESTAMP = 1700000000000
        w.write_i64(1_700_000_000_000).unwrap();
        // BINARY = [0x01, 0x02]
        w.write_i32(2).unwrap();
        w.write_bytes(&[0x01, 0x02]).unwrap();

        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let row = read_row(&mut r, &fields).unwrap();

        assert_eq!(row.len(), 10);
        assert_eq!(row[0].1, FieldValue::Int(7));
        assert_eq!(row[1].1, FieldValue::Int(42));
        assert_eq!(row[2].1, FieldValue::Long(1_234_567_890_123));
        assert!(matches!(row[3].1, FieldValue::Float(f) if (f - 1.5).abs() < 0.001));
        assert!(matches!(row[4].1, FieldValue::Double(d) if (d - 9.876).abs() < 0.001));
        assert_eq!(row[5].1, FieldValue::Bool(true));
        assert_eq!(row[6].1, FieldValue::String("test".to_string()));
        assert_eq!(row[7].1, FieldValue::String("123.45".to_string()));
        assert_eq!(row[8].1, FieldValue::DateTime(1_700_000_000_000));
        assert_eq!(row[9].1, FieldValue::Binary(vec![0x01, 0x02]));
    }

    #[test]
    fn test_read_field_value_eof_error() {
        let data: [u8; 0] = [];
        let mut r = BufReader::new(&data);
        let err = read_field_value(&mut r, SqlType::Integer);
        assert!(err.is_err());
    }

    #[test]
    fn test_read_row_eof_error_midway() {
        let fields = vec![
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::SmallInt,
                name: "A".to_string(),
                nullable: false,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Integer,
                name: "B".to_string(),
                nullable: false,
                parsing_code: None,
            },
        ];

        // SmallInt 하나만 쓰고 Integer는 쓰지 않음
        let mut w = BufWriter::new();
        w.write_i32(10).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let err = read_row(&mut r, &fields);
        assert!(err.is_err());
    }
}
