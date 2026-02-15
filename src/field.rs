//! SQL 타입별 필드 값 인코딩/디코딩 모듈
//!
//! OZ 프로토콜의 DataModule 응답에서 각 SQL 타입에 따라
//! 바이너리 데이터를 [`FieldValue`]로 변환하거나, 그 역방향으로 직렬화합니다.
//!
//! ## 핵심 함수
//!
//! - [`read_field_value`] — SQL 타입별 단일 필드 값 디코딩
//! - [`write_field_value`] — SQL 타입별 단일 필드 값 인코딩 (`read_field_value`의 역함수)
//! - [`read_row`] — 필드 목록 기반 한 행 전체 디코딩
//! - [`write_row`] — 필드 목록 기반 한 행 전체 인코딩
//!
//! ## SQL 타입별 인코딩 규칙
//!
//! | 필드 클래스 | SQL 타입 | 바이너리 형식 | Null 판별 |
//! |---|---|---|---|
//! | BasicIntField | INTEGER, TINYINT | `i32(4B)` | `== i32::MIN` |
//! | BasicSmallField | SMALLINT | `bool(1B) + i32(4B)` | `bool == true` |
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
use crate::wire::{BufReader, BufWriter};

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
/// 바이너리 데이터가 부족하면 [`OzError::UnexpectedEof`]를 반환합니다.
pub fn read_field_value(reader: &mut BufReader, sql_type: SqlType) -> Result<FieldValue> {
    match sql_type {
        // BasicIntField: INTEGER(4), TINYINT(-6)
        // 4B i32, null sentinel = i32::MIN (0x80000000)
        SqlType::Integer | SqlType::TinyInt => {
            let raw = reader.read_i32()?;
            if raw == i32::MIN {
                Ok(FieldValue::Null)
            } else {
                Ok(FieldValue::Int(raw))
            }
        }

        // BasicSmallField: SMALLINT(5)
        // bool(1B) + i32(4B), null이면 bool == true
        SqlType::SmallInt => {
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

/// [`FieldValue`] 변형의 이름을 반환하는 헬퍼 함수 (에러 메시지용)
fn field_value_name(value: &FieldValue) -> &'static str {
    match value {
        FieldValue::Null => "Null",
        FieldValue::String(_) => "String",
        FieldValue::Int(_) => "Int",
        FieldValue::Long(_) => "Long",
        FieldValue::Float(_) => "Float",
        FieldValue::Double(_) => "Double",
        FieldValue::Bool(_) => "Bool",
        FieldValue::DateTime(_) => "DateTime",
        FieldValue::Binary(_) => "Binary",
    }
}

/// 타입 불일치 에러를 생성하는 헬퍼 함수
fn type_mismatch(sql_type: SqlType, expected: &str, actual: &FieldValue) -> OzError {
    OzError::TypeMismatch {
        sql_type: format!("{:?}", sql_type),
        expected: expected.to_string(),
        actual: field_value_name(actual).to_string(),
    }
}

/// SQL 타입에 따라 [`FieldValue`]를 바이너리 형식으로 직렬화합니다.
///
/// [`read_field_value()`]의 역함수입니다. 각 `SqlType`에 대해
/// `read_field_value()`가 읽는 것과 동일한 와이어 포맷으로 씁니다.
///
/// # 인자
///
/// - `writer` — 현재 위치에서 쓸 [`BufWriter`]
/// - `sql_type` — 필드의 SQL 타입 코드
/// - `value` — 직렬화할 [`FieldValue`]
///
/// # 에러
///
/// - `sql_type`과 `value` 변형이 일치하지 않으면 [`OzError::TypeMismatch`]를 반환합니다.
///   (예: `SqlType::Integer`인데 `FieldValue::String`이 들어온 경우)
/// - 버퍼 공간이 부족하면 [`OzError::BufferOverflow`]를 반환합니다.
///
/// # SQL 타입별 직렬화 규칙
///
/// | SQL 타입 | Null 표현 | 값 표현 |
/// |---|---|---|
/// | `Integer`, `TinyInt` | `i32::MIN` | `i32` |
/// | `SmallInt` | `bool(true)` | `bool(false) + i32` |
/// | `BigInt` | `bool(true)` | `bool(false) + i64` |
/// | `Real` | `bool(true)` | `bool(false) + f32` |
/// | `Float`, `Double` | `bool(true)` | `bool(false) + f64` |
/// | `Bit` | (null 없음) | `u8` |
/// | `Char`, `VarChar`, `LongVarChar`, `Clob` | `bool(true)` | `bool(false) + UTF` |
/// | `Numeric`, `Decimal` | 빈 문자열 UTF | `UTF` |
/// | `Date`, `Time`, `Timestamp` | `(i32::MIN << 32)` | `i64` |
/// | `Binary`, `VarBinary`, `LongVarBinary`, `Blob` | `i32(0)` | `i32(len) + bytes` |
pub fn write_field_value(
    writer: &mut BufWriter,
    sql_type: SqlType,
    value: &FieldValue,
) -> Result<()> {
    match sql_type {
        // BasicIntField: INTEGER(4), TINYINT(-6)
        // 4B i32, null sentinel = i32::MIN (0x80000000)
        SqlType::Integer | SqlType::TinyInt => match value {
            FieldValue::Null => writer.write_i32(i32::MIN),
            FieldValue::Int(v) => writer.write_i32(*v),
            _ => Err(type_mismatch(sql_type, "Int", value)),
        },

        // BasicSmallField: SMALLINT(5)
        // bool(1B) + i32(4B), null이면 bool == true
        SqlType::SmallInt => match value {
            FieldValue::Null => writer.write_bool(true),
            FieldValue::Int(v) => {
                writer.write_bool(false)?;
                writer.write_i32(*v)
            }
            _ => Err(type_mismatch(sql_type, "Int", value)),
        },

        // BasicLongField: BIGINT(-5)
        // bool(1B) + i64(8B), null이면 bool == true
        SqlType::BigInt => match value {
            FieldValue::Null => writer.write_bool(true),
            FieldValue::Long(v) => {
                writer.write_bool(false)?;
                writer.write_i64(*v)
            }
            _ => Err(type_mismatch(sql_type, "Long", value)),
        },

        // BasicFloatField: REAL(7)
        // bool(1B) + f32(4B), null이면 bool == true
        SqlType::Real => match value {
            FieldValue::Null => writer.write_bool(true),
            FieldValue::Float(v) => {
                writer.write_bool(false)?;
                writer.write_f32(*v)
            }
            _ => Err(type_mismatch(sql_type, "Float", value)),
        },

        // BasicDoubleField: FLOAT(6), DOUBLE(8)
        // bool(1B) + f64(8B), null이면 bool == true
        SqlType::Float | SqlType::Double => match value {
            FieldValue::Null => writer.write_bool(true),
            FieldValue::Double(v) => {
                writer.write_bool(false)?;
                writer.write_f64(*v)
            }
            _ => Err(type_mismatch(sql_type, "Double", value)),
        },

        // BasicBooleanField: BIT(-7)
        // u8(1B), null 없음
        SqlType::Bit => match value {
            FieldValue::Bool(v) => writer.write_u8(if *v { 1 } else { 0 }),
            _ => Err(type_mismatch(sql_type, "Bool", value)),
        },

        // BasicStringField: CHAR(1), VARCHAR(12), LONGVARCHAR(-1), CLOB(2005)
        // bool(1B) + writeUTF(2+NB), null이면 bool == true
        SqlType::Char | SqlType::VarChar | SqlType::LongVarChar | SqlType::Clob => match value {
            FieldValue::Null => writer.write_bool(true),
            FieldValue::String(s) => {
                writer.write_bool(false)?;
                writer.write_utf(s)
            }
            _ => Err(type_mismatch(sql_type, "String", value)),
        },

        // BasicStringField2: NUMERIC(2), DECIMAL(3) — ⚠️ boolean prefix 없음!
        // writeUTF(2+NB) 직접, null이면 빈 문자열
        SqlType::Numeric | SqlType::Decimal => match value {
            FieldValue::Null => writer.write_utf(""),
            FieldValue::String(s) => writer.write_utf(s),
            _ => Err(type_mismatch(sql_type, "String", value)),
        },

        // BasicDateField: DATE(91), TIME(92), TIMESTAMP(93)
        // i64(8B) = epoch milliseconds
        // null: hi == i32::MIN (0x80000000) && lo == 0
        SqlType::Date | SqlType::Time | SqlType::Timestamp => match value {
            FieldValue::Null => {
                let null_millis: i64 = (i32::MIN as i64) << 32;
                writer.write_i64(null_millis)
            }
            FieldValue::DateTime(millis) => writer.write_i64(*millis),
            _ => Err(type_mismatch(sql_type, "DateTime", value)),
        },

        // BasicBinaryField: BINARY(-2), VARBINARY(-3), LONGVARBINARY(-4), BLOB(2004)
        // i32(4B) = length, 그 다음 raw bytes
        SqlType::Binary | SqlType::VarBinary | SqlType::LongVarBinary | SqlType::Blob => {
            match value {
                FieldValue::Null => writer.write_i32(0),
                FieldValue::Binary(data) => {
                    if data.len() > MAX_BINARY_LENGTH {
                        return Err(OzError::BinaryTooLarge {
                            length: data.len(),
                            max: MAX_BINARY_LENGTH,
                        });
                    }
                    writer.write_i32(data.len() as i32)?;
                    writer.write_bytes(data)
                }
                _ => Err(type_mismatch(sql_type, "Binary", value)),
            }
        }
    }
}

/// 알 수 없는 SQL 타입 코드에 대해 필드 값을 씁니다.
///
/// [`BasicStringField`](SqlType::Char) 동일 방식으로 처리합니다:
/// `bool(1B) + writeUTF(2+NB)`, null이면 `bool == true`.
///
/// 이 함수는 [`SqlType`]으로 변환할 수 없는 원시 SQL 코드를 처리할 때 사용합니다.
pub fn write_field_value_default(writer: &mut BufWriter, value: &FieldValue) -> Result<()> {
    match value {
        FieldValue::Null => writer.write_bool(true),
        FieldValue::String(s) => {
            writer.write_bool(false)?;
            writer.write_utf(s)
        }
        _ => Err(OzError::TypeMismatch {
            sql_type: "Unknown".to_string(),
            expected: "String".to_string(),
            actual: field_value_name(value).to_string(),
        }),
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

/// 필드 목록을 기반으로 한 행(row)의 전체 필드 값을 직렬화합니다.
///
/// [`read_row()`]의 역함수입니다.
///
/// # 인자
///
/// - `writer` — 현재 위치에서 쓸 [`BufWriter`]
/// - `fields` — 행의 필드 정의 목록 ([`BasicField`])
/// - `row` — 직렬화할 `(필드명, 필드값)` 쌍의 벡터
///
/// # 에러
///
/// 필드 수와 행 값의 수가 다르거나, 타입 불일치 시 에러를 반환합니다.
pub fn write_row(writer: &mut BufWriter, fields: &[BasicField], row: &Row) -> Result<()> {
    if fields.len() != row.len() {
        return Err(OzError::ProtocolError {
            code: 0,
            message: format!(
                "field count mismatch: {} fields vs {} values",
                fields.len(),
                row.len()
            ),
        });
    }
    for (field, (_name, value)) in fields.iter().zip(row.iter()) {
        write_field_value(writer, field.sql_type, value)?;
    }
    Ok(())
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
        w.write_bool(false).unwrap(); // not null
        w.write_i32(256).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::SmallInt).unwrap();
        assert_eq!(v, FieldValue::Int(256));
    }

    #[test]
    fn test_smallint_null_sentinel() {
        let mut w = BufWriter::new();
        w.write_bool(true).unwrap(); // null
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::SmallInt).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_smallint_zero() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_i32(0).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::SmallInt).unwrap();
        assert_eq!(v, FieldValue::Int(0));
    }

    #[test]
    fn test_smallint_negative() {
        let mut w = BufWriter::new();
        w.write_bool(false).unwrap();
        w.write_i32(-100).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::SmallInt).unwrap();
        assert_eq!(v, FieldValue::Int(-100));
    }

    #[test]
    fn test_integer_normal_value() {
        let mut w = BufWriter::new();
        w.write_i32(12345).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Integer).unwrap();
        assert_eq!(v, FieldValue::Int(12345));
    }

    #[test]
    fn test_integer_null() {
        let mut w = BufWriter::new();
        w.write_i32(i32::MIN).unwrap(); // 0x80000000
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Integer).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    #[test]
    fn test_integer_zero() {
        let mut w = BufWriter::new();
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
        // INTEGER "AGE" = 30 (sentinel i32, no bool prefix)
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
        // INTEGER "COUNT" = null (sentinel i32::MIN)
        w.write_i32(i32::MIN).unwrap();
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
        w.write_bool(false).unwrap(); // not null
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
        // TINYINT = 7 (sentinel i32)
        w.write_i32(7).unwrap();
        // INTEGER = 42 (sentinel i32, no bool prefix)
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
        w.write_bool(false).unwrap(); // SmallInt not null
        w.write_i32(10).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let err = read_row(&mut r, &fields);
        assert!(err.is_err());
    }

    // ══════════════════════════════════════════════════════════════
    // write_field_value() roundtrip 테스트
    // ══════════════════════════════════════════════════════════════

    /// write → read roundtrip 헬퍼: write_field_value로 쓰고 read_field_value로 읽어서 비교
    fn assert_roundtrip(sql_type: SqlType, value: &FieldValue) {
        let mut w = BufWriter::new();
        write_field_value(&mut w, sql_type, value).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let read_back = read_field_value(&mut r, sql_type).unwrap();
        assert_eq!(&read_back, value, "roundtrip failed for {:?}", sql_type);
        assert_eq!(
            r.offset(),
            data.len(),
            "not all bytes consumed for {:?}",
            sql_type
        );
    }

    // -- TinyInt roundtrip --

    #[test]
    fn test_write_tinyint_normal() {
        assert_roundtrip(SqlType::TinyInt, &FieldValue::Int(42));
    }

    #[test]
    fn test_write_tinyint_null() {
        assert_roundtrip(SqlType::TinyInt, &FieldValue::Null);
    }

    #[test]
    fn test_write_tinyint_zero() {
        assert_roundtrip(SqlType::TinyInt, &FieldValue::Int(0));
    }

    #[test]
    fn test_write_tinyint_negative() {
        assert_roundtrip(SqlType::TinyInt, &FieldValue::Int(-100));
    }

    // -- SmallInt roundtrip --

    #[test]
    fn test_write_smallint_normal() {
        assert_roundtrip(SqlType::SmallInt, &FieldValue::Int(256));
    }

    #[test]
    fn test_write_smallint_null() {
        assert_roundtrip(SqlType::SmallInt, &FieldValue::Null);
    }

    #[test]
    fn test_write_smallint_zero() {
        assert_roundtrip(SqlType::SmallInt, &FieldValue::Int(0));
    }

    #[test]
    fn test_write_smallint_negative() {
        assert_roundtrip(SqlType::SmallInt, &FieldValue::Int(-100));
    }

    // -- Integer roundtrip --

    #[test]
    fn test_write_integer_normal() {
        assert_roundtrip(SqlType::Integer, &FieldValue::Int(12345));
    }

    #[test]
    fn test_write_integer_null() {
        assert_roundtrip(SqlType::Integer, &FieldValue::Null);
    }

    #[test]
    fn test_write_integer_zero() {
        assert_roundtrip(SqlType::Integer, &FieldValue::Int(0));
    }

    #[test]
    fn test_write_integer_negative() {
        assert_roundtrip(SqlType::Integer, &FieldValue::Int(-999));
    }

    // -- BigInt roundtrip --

    #[test]
    fn test_write_bigint_normal() {
        assert_roundtrip(SqlType::BigInt, &FieldValue::Long(9876543210));
    }

    #[test]
    fn test_write_bigint_null() {
        assert_roundtrip(SqlType::BigInt, &FieldValue::Null);
    }

    #[test]
    fn test_write_bigint_zero() {
        assert_roundtrip(SqlType::BigInt, &FieldValue::Long(0));
    }

    #[test]
    fn test_write_bigint_negative() {
        assert_roundtrip(SqlType::BigInt, &FieldValue::Long(-1234567890123));
    }

    // -- Real roundtrip --

    #[test]
    fn test_write_real_normal() {
        let mut w = BufWriter::new();
        write_field_value(&mut w, SqlType::Real, &FieldValue::Float(1.5_f32)).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Real).unwrap();
        match v {
            FieldValue::Float(f) => assert!((f - 1.5_f32).abs() < 0.001),
            other => panic!("expected Float, got {:?}", other),
        }
    }

    #[test]
    fn test_write_real_null() {
        assert_roundtrip(SqlType::Real, &FieldValue::Null);
    }

    // -- Float/Double roundtrip --

    #[test]
    fn test_write_float_normal() {
        let mut w = BufWriter::new();
        write_field_value(
            &mut w,
            SqlType::Float,
            &FieldValue::Double(std::f64::consts::PI),
        )
        .unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Float).unwrap();
        match v {
            FieldValue::Double(d) => {
                assert!((d - std::f64::consts::PI).abs() < f64::EPSILON)
            }
            other => panic!("expected Double, got {:?}", other),
        }
    }

    #[test]
    fn test_write_float_null() {
        assert_roundtrip(SqlType::Float, &FieldValue::Null);
    }

    #[test]
    fn test_write_double_normal() {
        let mut w = BufWriter::new();
        write_field_value(&mut w, SqlType::Double, &FieldValue::Double(1.23456)).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value(&mut r, SqlType::Double).unwrap();
        match v {
            FieldValue::Double(d) => assert!((d - 1.23456).abs() < 0.0001),
            other => panic!("expected Double, got {:?}", other),
        }
    }

    #[test]
    fn test_write_double_null() {
        assert_roundtrip(SqlType::Double, &FieldValue::Null);
    }

    // -- Bit roundtrip --

    #[test]
    fn test_write_bit_true() {
        assert_roundtrip(SqlType::Bit, &FieldValue::Bool(true));
    }

    #[test]
    fn test_write_bit_false() {
        assert_roundtrip(SqlType::Bit, &FieldValue::Bool(false));
    }

    // -- String field roundtrip (Char, VarChar, LongVarChar, Clob) --

    #[test]
    fn test_write_varchar_normal() {
        assert_roundtrip(
            SqlType::VarChar,
            &FieldValue::String("hello world".to_string()),
        );
    }

    #[test]
    fn test_write_varchar_null() {
        assert_roundtrip(SqlType::VarChar, &FieldValue::Null);
    }

    #[test]
    fn test_write_char_normal() {
        assert_roundtrip(SqlType::Char, &FieldValue::String("A".to_string()));
    }

    #[test]
    fn test_write_longvarchar_normal() {
        assert_roundtrip(
            SqlType::LongVarChar,
            &FieldValue::String("장문 텍스트".to_string()),
        );
    }

    #[test]
    fn test_write_clob_null() {
        assert_roundtrip(SqlType::Clob, &FieldValue::Null);
    }

    #[test]
    fn test_write_clob_normal() {
        assert_roundtrip(
            SqlType::Clob,
            &FieldValue::String("CLOB 데이터".to_string()),
        );
    }

    // -- Numeric/Decimal roundtrip --

    #[test]
    fn test_write_numeric_normal() {
        assert_roundtrip(SqlType::Numeric, &FieldValue::String("123.456".to_string()));
    }

    #[test]
    fn test_write_numeric_null() {
        assert_roundtrip(SqlType::Numeric, &FieldValue::Null);
    }

    #[test]
    fn test_write_decimal_normal() {
        assert_roundtrip(
            SqlType::Decimal,
            &FieldValue::String("99999.99".to_string()),
        );
    }

    #[test]
    fn test_write_decimal_null() {
        assert_roundtrip(SqlType::Decimal, &FieldValue::Null);
    }

    // -- Date/Time/Timestamp roundtrip --

    #[test]
    fn test_write_date_normal() {
        assert_roundtrip(SqlType::Date, &FieldValue::DateTime(1_700_000_000_000));
    }

    #[test]
    fn test_write_date_null() {
        assert_roundtrip(SqlType::Date, &FieldValue::Null);
    }

    #[test]
    fn test_write_date_epoch_zero() {
        assert_roundtrip(SqlType::Date, &FieldValue::DateTime(0));
    }

    #[test]
    fn test_write_time_normal() {
        assert_roundtrip(SqlType::Time, &FieldValue::DateTime(43_200_000));
    }

    #[test]
    fn test_write_time_null() {
        assert_roundtrip(SqlType::Time, &FieldValue::Null);
    }

    #[test]
    fn test_write_timestamp_normal() {
        assert_roundtrip(SqlType::Timestamp, &FieldValue::DateTime(1_609_459_200_000));
    }

    #[test]
    fn test_write_timestamp_null() {
        assert_roundtrip(SqlType::Timestamp, &FieldValue::Null);
    }

    // -- Binary/VarBinary/LongVarBinary/Blob roundtrip --

    #[test]
    fn test_write_binary_normal() {
        assert_roundtrip(
            SqlType::Binary,
            &FieldValue::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        );
    }

    #[test]
    fn test_write_binary_null() {
        assert_roundtrip(SqlType::Binary, &FieldValue::Null);
    }

    #[test]
    fn test_write_varbinary_normal() {
        assert_roundtrip(
            SqlType::VarBinary,
            &FieldValue::Binary(vec![0x01, 0x02, 0x03]),
        );
    }

    #[test]
    fn test_write_longvarbinary_null() {
        assert_roundtrip(SqlType::LongVarBinary, &FieldValue::Null);
    }

    #[test]
    fn test_write_blob_normal() {
        assert_roundtrip(SqlType::Blob, &FieldValue::Binary(vec![0xFF; 10]));
    }

    // -- write_field_value_default roundtrip --

    #[test]
    fn test_write_default_normal() {
        let mut w = BufWriter::new();
        write_field_value_default(
            &mut w,
            &FieldValue::String("unknown type value".to_string()),
        )
        .unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value_default(&mut r).unwrap();
        assert_eq!(v, FieldValue::String("unknown type value".to_string()));
    }

    #[test]
    fn test_write_default_null() {
        let mut w = BufWriter::new();
        write_field_value_default(&mut w, &FieldValue::Null).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let v = read_field_value_default(&mut r).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    // ══════════════════════════════════════════════════════════════
    // 타입 불일치 에러 테스트
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_write_integer_type_mismatch_string() {
        let mut w = BufWriter::new();
        let err = write_field_value(
            &mut w,
            SqlType::Integer,
            &FieldValue::String("oops".to_string()),
        );
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_integer_type_mismatch_bool() {
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::Integer, &FieldValue::Bool(true));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_varchar_type_mismatch_int() {
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::VarChar, &FieldValue::Int(42));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_bit_type_mismatch_int() {
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::Bit, &FieldValue::Int(1));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_bit_type_mismatch_null() {
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::Bit, &FieldValue::Null);
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_bigint_type_mismatch_int() {
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::BigInt, &FieldValue::Int(42));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_real_type_mismatch_double() {
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::Real, &FieldValue::Double(1.5));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_double_type_mismatch_float() {
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::Double, &FieldValue::Float(1.5_f32));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_date_type_mismatch_long() {
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::Date, &FieldValue::Long(123));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_binary_type_mismatch_string() {
        let mut w = BufWriter::new();
        let err = write_field_value(
            &mut w,
            SqlType::Binary,
            &FieldValue::String("bytes".to_string()),
        );
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_numeric_type_mismatch_int() {
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::Numeric, &FieldValue::Int(42));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    #[test]
    fn test_write_default_type_mismatch_int() {
        let mut w = BufWriter::new();
        let err = write_field_value_default(&mut w, &FieldValue::Int(42));
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), OzError::TypeMismatch { .. }));
    }

    // ══════════════════════════════════════════════════════════════
    // write_row roundtrip 테스트
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_write_row_mixed_roundtrip() {
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

        let original_row: Row = vec![
            ("NAME".to_string(), FieldValue::String("홍길동".to_string())),
            ("AGE".to_string(), FieldValue::Int(30)),
            (
                "SALARY".to_string(),
                FieldValue::String("50000.00".to_string()),
            ),
            ("ACTIVE".to_string(), FieldValue::Bool(true)),
        ];

        let mut w = BufWriter::new();
        write_row(&mut w, &fields, &original_row).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let read_back = read_row(&mut r, &fields).unwrap();

        assert_eq!(read_back.len(), 4);
        assert_eq!(read_back[0], original_row[0]);
        assert_eq!(read_back[1], original_row[1]);
        assert_eq!(read_back[2], original_row[2]);
        assert_eq!(read_back[3], original_row[3]);
    }

    #[test]
    fn test_write_row_all_nulls_roundtrip() {
        let fields = vec![
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::VarChar,
                name: "A".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Integer,
                name: "B".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Date,
                name: "C".to_string(),
                nullable: true,
                parsing_code: None,
            },
        ];

        let original_row: Row = vec![
            ("A".to_string(), FieldValue::Null),
            ("B".to_string(), FieldValue::Null),
            ("C".to_string(), FieldValue::Null),
        ];

        let mut w = BufWriter::new();
        write_row(&mut w, &fields, &original_row).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let read_back = read_row(&mut r, &fields).unwrap();

        assert_eq!(read_back.len(), 3);
        assert_eq!(read_back[0].1, FieldValue::Null);
        assert_eq!(read_back[1].1, FieldValue::Null);
        assert_eq!(read_back[2].1, FieldValue::Null);
    }

    #[test]
    fn test_write_row_empty_fields() {
        let fields: Vec<BasicField> = vec![];
        let row: Row = vec![];
        let mut w = BufWriter::new();
        write_row(&mut w, &fields, &row).unwrap();
        assert_eq!(w.offset(), 0);
    }

    #[test]
    fn test_write_row_all_types_roundtrip() {
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

        let original_row: Row = vec![
            ("F_TINYINT".to_string(), FieldValue::Int(7)),
            ("F_INT".to_string(), FieldValue::Int(42)),
            ("F_BIGINT".to_string(), FieldValue::Long(1_234_567_890_123)),
            ("F_REAL".to_string(), FieldValue::Float(1.5_f32)),
            ("F_DOUBLE".to_string(), FieldValue::Double(9.876)),
            ("F_BIT".to_string(), FieldValue::Bool(true)),
            (
                "F_VARCHAR".to_string(),
                FieldValue::String("test".to_string()),
            ),
            (
                "F_NUMERIC".to_string(),
                FieldValue::String("123.45".to_string()),
            ),
            (
                "F_TIMESTAMP".to_string(),
                FieldValue::DateTime(1_700_000_000_000),
            ),
            ("F_BINARY".to_string(), FieldValue::Binary(vec![0x01, 0x02])),
        ];

        let mut w = BufWriter::new();
        write_row(&mut w, &fields, &original_row).unwrap();
        let data = writer_to_vec(&w);
        let mut r = BufReader::new(&data);
        let read_back = read_row(&mut r, &fields).unwrap();

        assert_eq!(read_back.len(), 10);
        assert_eq!(read_back[0].1, FieldValue::Int(7));
        assert_eq!(read_back[1].1, FieldValue::Int(42));
        assert_eq!(read_back[2].1, FieldValue::Long(1_234_567_890_123));
        assert!(matches!(read_back[3].1, FieldValue::Float(f) if (f - 1.5).abs() < 0.001));
        assert!(matches!(read_back[4].1, FieldValue::Double(d) if (d - 9.876).abs() < 0.001));
        assert_eq!(read_back[5].1, FieldValue::Bool(true));
        assert_eq!(read_back[6].1, FieldValue::String("test".to_string()));
        assert_eq!(read_back[7].1, FieldValue::String("123.45".to_string()));
        assert_eq!(read_back[8].1, FieldValue::DateTime(1_700_000_000_000));
        assert_eq!(read_back[9].1, FieldValue::Binary(vec![0x01, 0x02]));
    }
    // ══════════════════════════════════════════════════════════════
    // 빈 바이너리 lossy 변환 문서화 테스트
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn write_read_binary_empty_is_lossy_null() {
        // 빈 바이너리(len=0)는 write 시 i32(0)으로 직렬화되고,
        // read 시 length <= 0 조건에 의해 Null로 해석됩니다.
        // 이는 프로토콜 제약으로 인한 sentinel 값(0) 충돌 때문이며,
        // Binary(vec![]) → write → read = Null 이 되는 lossy 변환입니다.
        let value = FieldValue::Binary(vec![]);

        let mut w = BufWriter::new();
        write_field_value(&mut w, SqlType::Binary, &value).unwrap();
        let data = writer_to_vec(&w);

        // write 결과: i32(0) = 4바이트 (len=0)
        assert_eq!(data.len(), 4);

        let mut r = BufReader::new(&data);
        let read_back = read_field_value(&mut r, SqlType::Binary).unwrap();

        // 빈 바이너리가 Null로 변환됨 (lossy)
        assert_eq!(read_back, FieldValue::Null);
        assert_ne!(
            read_back, value,
            "empty binary is lossy: Binary(vec![]) becomes Null after roundtrip"
        );
    }

    // ══════════════════════════════════════════════════════════════
    // write_row 길이 불일치 에러 테스트
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_write_row_field_count_mismatch_more_fields() {
        let fields = vec![
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Integer,
                name: "A".to_string(),
                nullable: true,
                parsing_code: None,
            },
            BasicField {
                kind: FieldKind::Normal,
                sql_type: SqlType::Integer,
                name: "B".to_string(),
                nullable: true,
                parsing_code: None,
            },
        ];

        // fields=2, row=1 → 에러
        let row: Row = vec![("A".to_string(), FieldValue::Int(1))];
        let mut w = BufWriter::new();
        let err = write_row(&mut w, &fields, &row);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("field count mismatch"));
    }

    #[test]
    fn test_write_row_field_count_mismatch_more_values() {
        let fields = vec![BasicField {
            kind: FieldKind::Normal,
            sql_type: SqlType::Integer,
            name: "A".to_string(),
            nullable: true,
            parsing_code: None,
        }];

        // fields=1, row=2 → 에러
        let row: Row = vec![
            ("A".to_string(), FieldValue::Int(1)),
            ("B".to_string(), FieldValue::Int(2)),
        ];
        let mut w = BufWriter::new();
        let err = write_row(&mut w, &fields, &row);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("field count mismatch"));
    }

    // ── §5 경계값 테스트 ─────────────────────────────────

    /// Integer i32::MAX — null sentinel(i32::MIN)과 가장 먼 경계
    #[test]
    fn test_integer_boundary_i32_max() {
        assert_roundtrip(SqlType::Integer, &FieldValue::Int(i32::MAX));
    }

    /// Integer i32::MIN + 1 — null sentinel 바로 옆 경계값
    #[test]
    fn test_integer_boundary_i32_min_plus_one() {
        assert_roundtrip(SqlType::Integer, &FieldValue::Int(i32::MIN + 1));
    }

    /// Integer i32::MAX - 1 — 최대값 근처
    #[test]
    fn test_integer_boundary_i32_max_minus_one() {
        assert_roundtrip(SqlType::Integer, &FieldValue::Int(i32::MAX - 1));
    }

    /// Integer -1 — 음수 일반값
    #[test]
    fn test_integer_negative_one() {
        assert_roundtrip(SqlType::Integer, &FieldValue::Int(-1));
    }

    /// VarChar 빈 문자열 — null이 아닌 빈 문자열 라운드트립
    #[test]
    fn test_varchar_empty_string_roundtrip() {
        assert_roundtrip(SqlType::VarChar, &FieldValue::String("".to_string()));
    }

    /// BigInt i64::MAX 경계값
    #[test]
    fn test_bigint_boundary_i64_max() {
        assert_roundtrip(SqlType::BigInt, &FieldValue::Long(i64::MAX));
    }

    /// BigInt i64::MIN + 1 — 최소값 근처 (i64::MIN은 일반값으로 사용 가능)
    #[test]
    fn test_bigint_boundary_i64_min_plus_one() {
        assert_roundtrip(SqlType::BigInt, &FieldValue::Long(i64::MIN + 1));
    }

    /// DateTime 경계 — null sentinel 바로 옆 값 (hi=i32::MIN, lo=1)
    #[test]
    fn test_datetime_boundary_near_null_sentinel() {
        // null sentinel: hi == i32::MIN && lo == 0
        // hi=i32::MIN, lo=1 → null이 아님
        let millis: i64 = ((i32::MIN as i64) << 32) | 1;
        assert_roundtrip(SqlType::Date, &FieldValue::DateTime(millis));
    }

    /// DateTime 0 (epoch) — null이 아닌 정상값
    #[test]
    fn test_datetime_epoch_zero_roundtrip() {
        assert_roundtrip(SqlType::Timestamp, &FieldValue::DateTime(0));
    }

    /// Binary read에서 MAX_BINARY_LENGTH 초과 시 BinaryTooLarge 에러
    #[test]
    fn test_read_binary_too_large() {
        let mut w = BufWriter::new();
        // MAX_BINARY_LENGTH + 1 크기의 length prefix를 기록
        let too_large = (MAX_BINARY_LENGTH + 1) as i32;
        w.write_i32(too_large).unwrap();
        let buf = w.into_bytes();
        let mut reader = BufReader::new(&buf);
        let err = read_field_value(&mut reader, SqlType::Binary).unwrap_err();
        match err {
            OzError::BinaryTooLarge { length, max } => {
                assert_eq!(length, MAX_BINARY_LENGTH + 1);
                assert_eq!(max, MAX_BINARY_LENGTH);
            }
            other => panic!("expected BinaryTooLarge, got: {other:?}"),
        }
    }

    /// Binary write에서 MAX_BINARY_LENGTH 초과 시 BinaryTooLarge 에러
    #[test]
    fn test_write_binary_too_large() {
        // 실제로 100MB 할당하지 않고, BufWriter의 한계를 우회하여 검증
        // write_field_value는 data.len()을 검사하므로 큰 Vec을 만들어야 함
        // → 대신 길이만 검증하는 방식으로 테스트
        let huge = vec![0u8; MAX_BINARY_LENGTH + 1];
        let mut w = BufWriter::new();
        let err = write_field_value(&mut w, SqlType::VarBinary, &FieldValue::Binary(huge));
        assert!(err.is_err());
        match err.unwrap_err() {
            OzError::BinaryTooLarge { length, max } => {
                assert_eq!(length, MAX_BINARY_LENGTH + 1);
                assert_eq!(max, MAX_BINARY_LENGTH);
            }
            other => panic!("expected BinaryTooLarge, got: {other:?}"),
        }
    }

    /// Binary 정확히 MAX_BINARY_LENGTH — 경계 허용
    #[test]
    fn test_binary_exactly_max_length_read() {
        // read 쪽: length prefix가 정확히 MAX_BINARY_LENGTH → BinaryTooLarge가 아님
        // (실제 데이터가 부족하면 EOF가 발생하지만, 길이 검증 자체는 통과해야 함)
        let mut w = BufWriter::new();
        w.write_i32(MAX_BINARY_LENGTH as i32).unwrap();
        let buf = w.into_bytes();
        let mut reader = BufReader::new(&buf);
        let err = read_field_value(&mut reader, SqlType::Binary);
        // 데이터 부족으로 EOF 에러가 나지만, BinaryTooLarge는 아니어야 함
        match err {
            Err(OzError::BinaryTooLarge { .. }) => {
                panic!("should not be BinaryTooLarge for exactly max length")
            }
            Err(OzError::UnexpectedEof { .. }) => {} // 예상대로 EOF
            other => panic!("unexpected result: {other:?}"),
        }
    }

    /// Numeric/Decimal 빈 문자열 → Null 라운드트립
    #[test]
    fn test_numeric_empty_string_is_null_roundtrip() {
        // write Null → empty UTF → read → Null
        let mut w = BufWriter::new();
        write_field_value(&mut w, SqlType::Numeric, &FieldValue::Null).unwrap();
        let buf = w.into_bytes();
        let mut reader = BufReader::new(&buf);
        let v = read_field_value(&mut reader, SqlType::Numeric).unwrap();
        assert_eq!(v, FieldValue::Null);
    }

    /// 모든 SQL 타입의 Null 라운드트립 (Bit 제외 — Bit은 null 없음)
    #[test]
    fn test_all_nullable_types_null_roundtrip() {
        let nullable_types = [
            SqlType::Integer,
            SqlType::TinyInt,
            SqlType::SmallInt,
            SqlType::BigInt,
            SqlType::Real,
            SqlType::Float,
            SqlType::Double,
            SqlType::Char,
            SqlType::VarChar,
            SqlType::LongVarChar,
            SqlType::Clob,
            SqlType::Numeric,
            SqlType::Decimal,
            SqlType::Date,
            SqlType::Time,
            SqlType::Timestamp,
            SqlType::Binary,
            SqlType::VarBinary,
            SqlType::LongVarBinary,
            SqlType::Blob,
        ];
        for sql_type in nullable_types {
            assert_roundtrip(sql_type, &FieldValue::Null);
        }
    }
}
