//! GZIP 블록 압축/해제 모듈
//!
//! OZ 프로토콜의 블록 단위 GZIP 압축 형식을 처리합니다.
//! 표준 GZIP과 달리, 데이터를 고정 크기 블록으로 나누어 각각 독립적으로 압축합니다.
//!
//! # 블록 형식
//!
//! ```text
//! [4B 블록 크기 (Big-Endian i32)] [GZIP 압축 데이터]
//! [4B 블록 크기 (Big-Endian i32)] [GZIP 압축 데이터]
//! ...
//! [4B: 0 또는 음수] ← 종료 마커
//! ```
//!
//! # 예시
//!
//! ```
//! use ozra::gzip::{decode_gzip_blocked, encode_gzip_blocked};
//!
//! let original = b"Hello, OZ Protocol! This is a test of GZIP blocked compression.";
//! let encoded = encode_gzip_blocked(original, 32).unwrap();
//! let decoded = decode_gzip_blocked(&encoded).unwrap();
//! assert_eq!(decoded, original);
//! ```

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

use crate::error::{OzError, Result};

/// 기본 블록 크기 (바이트)
///
/// 프로토콜 문서에 따른 기본값은 4,096바이트입니다.
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// 해제 후 최대 허용 크기 (ZIP 폭탄 방어)
///
/// 해제된 전체 데이터 크기가 이 상한을 초과하면 에러를 반환합니다.
const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024; // 256MB

/// GZIP 블록 스트림을 해제합니다.
///
/// 각 블록은 `[4B 크기 헤더 (Big-Endian i32)]` + `[GZIP 압축 데이터]`로 구성됩니다.
/// 크기가 0 이하이면 스트림 종료로 간주합니다.
///
/// # 인수
///
/// * `data` — GZIP 블록 스트림 바이트 슬라이스
///
/// # 반환
///
/// 모든 블록을 해제한 후 연결한 바이트 벡터를 반환합니다.
///
/// # 에러
///
/// - 블록 크기 헤더를 읽기에 충분한 데이터가 없을 때
/// - GZIP 해제에 실패할 때
/// - 해제된 전체 크기가 [`MAX_DECOMPRESSED_SIZE`] (256MB)를 초과할 때
///
/// # 예시
///
/// ```
/// use ozra::gzip::{decode_gzip_blocked, encode_gzip_blocked};
///
/// let data = b"test data for decoding";
/// let encoded = encode_gzip_blocked(data, 1024).unwrap();
/// let decoded = decode_gzip_blocked(&encoded).unwrap();
/// assert_eq!(decoded, data);
/// ```
pub fn decode_gzip_blocked(data: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut offset = 0;

    loop {
        // 4바이트 크기 헤더를 읽을 수 있는지 확인
        if offset + 4 > data.len() {
            // 남은 바이트가 4바이트 미만이면 스트림 종료로 간주
            break;
        }

        // Big-Endian i32로 블록 크기 읽기
        let block_size = i32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        // 종료 조건: 크기가 0 이하
        if block_size <= 0 {
            break;
        }

        let block_size = block_size as usize;

        // 블록 데이터가 충분한지 확인
        if offset + block_size > data.len() {
            return Err(OzError::DecompressionError {
                detail: format!(
                    "GZIP block truncated: expected {} bytes at offset {}, but only {} remaining",
                    block_size,
                    offset,
                    data.len() - offset
                ),
            });
        }

        // GZIP 해제
        let compressed_block = &data[offset..offset + block_size];
        let mut decoder = GzDecoder::new(compressed_block);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| OzError::DecompressionError {
                detail: format!("GZIP decompression failed at offset {offset}: {e}"),
            })?;

        // ZIP 폭탄 방어: 해제 총 크기 상한 검사
        if result.len() + decompressed.len() > MAX_DECOMPRESSED_SIZE {
            return Err(OzError::DecompressionError {
                detail: format!(
                    "decompressed size exceeds limit: {} + {} > {} bytes",
                    result.len(),
                    decompressed.len(),
                    MAX_DECOMPRESSED_SIZE
                ),
            });
        }

        result.extend_from_slice(&decompressed);
        offset += block_size;
    }

    Ok(result)
}

/// 데이터를 GZIP 블록 스트림으로 압축합니다.
///
/// 지정된 블록 크기로 원본 데이터를 분할하여 각 블록을 개별 GZIP 압축합니다.
/// 마지막에 4바이트 종료 마커(`0x00000000`)를 추가합니다.
///
/// # 인수
///
/// * `data` — 압축할 원본 데이터
/// * `block_size` — 블록당 원본 데이터 크기 (바이트). 0이면 [`DEFAULT_BLOCK_SIZE`] 사용.
///
/// # 반환
///
/// GZIP 블록 스트림 형식의 바이트 벡터를 반환합니다.
///
/// # 예시
///
/// ```
/// use ozra::gzip::{encode_gzip_blocked, decode_gzip_blocked, DEFAULT_BLOCK_SIZE};
///
/// let data = vec![0x42u8; 10000];
/// let encoded = encode_gzip_blocked(&data, DEFAULT_BLOCK_SIZE).unwrap();
/// let decoded = decode_gzip_blocked(&encoded).unwrap();
/// assert_eq!(decoded, data);
/// ```
pub fn encode_gzip_blocked(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    let block_size = if block_size == 0 {
        DEFAULT_BLOCK_SIZE
    } else {
        block_size
    };

    let mut result = Vec::with_capacity(data.len());

    // 빈 데이터: 종료 마커만 기록
    if data.is_empty() {
        result.extend_from_slice(&0i32.to_be_bytes());
        return Ok(result);
    }

    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + block_size, data.len());
        let chunk = &data[offset..end];

        // GZIP 압축
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(chunk)
            .map_err(|e| OzError::CompressionError {
                detail: format!("GZIP compression failed: {e}"),
            })?;
        let compressed = encoder.finish().map_err(|e| OzError::CompressionError {
            detail: format!("GZIP compression finalize failed: {e}"),
        })?;

        // 압축된 블록 크기가 i32 범위를 초과하는지 검사
        let block_len = i32::try_from(compressed.len()).map_err(|_| OzError::CompressionError {
            detail: format!("compressed block too large: {} bytes", compressed.len()),
        })?;

        // 4바이트 Big-Endian 크기 헤더 + 압축 데이터
        result.extend_from_slice(&block_len.to_be_bytes());
        result.extend_from_slice(&compressed);

        offset = end;
    }

    // 종료 마커: 0x00000000
    result.extend_from_slice(&0i32.to_be_bytes());

    Ok(result)
}

/// 데이터가 GZIP 블록 스트림인지 확인합니다.
///
/// GZIP 블록 스트림은 4바이트 크기 헤더로 시작하고, 그 뒤에 GZIP 매직 바이트(`0x1f 0x8b`)가
/// 위치합니다. 이 함수는 첫 번째 블록의 구조를 검사하여 판별합니다.
///
/// # 한계
///
/// 첫 6바이트 휴리스틱 기반 판별이므로, 비압축 바이너리가 동일 패턴
/// (양수 Big-Endian i32 + `0x1f 0x8b`)을 만족할 경우 false-positive가 발생할 수 있습니다.
///
/// # 참고
///
/// 단일 GZIP 스트림(`0x1f 0x8b`로 시작)과는 다릅니다.
/// GZIP 블록 스트림은 반드시 4바이트 크기 헤더가 먼저 위치합니다.
///
/// # 예시
///
/// ```
/// use ozra::gzip::{is_gzip_blocked, encode_gzip_blocked};
///
/// let encoded = encode_gzip_blocked(b"test", 1024).unwrap();
/// assert!(is_gzip_blocked(&encoded));
///
/// // 일반 GZIP은 false
/// assert!(!is_gzip_blocked(&[0x1f, 0x8b, 0x08]));
///
/// // 빈 데이터는 false
/// assert!(!is_gzip_blocked(&[]));
/// ```
pub fn is_gzip_blocked(data: &[u8]) -> bool {
    // 최소 크기: 4B 헤더 + 2B GZIP 매직
    if data.len() < 6 {
        return false;
    }

    // 첫 번째 블록의 크기 헤더 읽기
    let block_size = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    // 블록 크기가 양수이고, 그 뒤에 GZIP 매직 바이트가 있는지 확인
    block_size > 0 && data[4] == 0x1f && data[5] == 0x8b
}

/// 바이트 슬라이스를 GZIP 해제합니다.
///
/// 데이터의 구조를 자동 감지하여 적절한 해제 방식을 선택합니다:
/// - GZIP 블록 스트림이면 블록 단위로 해제
/// - 단일 GZIP 스트림(`0x1f 0x8b`)이면 일반 GZIP 해제
/// - 압축되지 않은 데이터이면 그대로 복사하여 반환
///
/// # 에러
///
/// GZIP 해제에 실패하면 [`OzError::DecompressionError`]를 반환합니다.
pub fn decompress_bytes(content: &[u8]) -> Result<Vec<u8>> {
    if content.is_empty() {
        return Ok(Vec::new());
    }

    // GZIP 블록 스트림 감지 (4B 크기 헤더 + GZIP 매직)
    if is_gzip_blocked(content) {
        return decode_gzip_blocked(content);
    }

    // 단일 GZIP 스트림 감지 (매직 바이트 0x1f 0x8b)
    if content.len() >= 2 && content[0] == 0x1f && content[1] == 0x8b {
        let mut decoder = GzDecoder::new(content);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| OzError::DecompressionError {
                detail: format!("GZIP decompression failed: {e}"),
            })?;
        return Ok(decompressed);
    }

    // 압축되지 않은 데이터 — 그대로 반환
    Ok(content.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- roundtrip 테스트 --

    #[test]
    fn test_roundtrip_single_block() {
        let original = b"Hello, OZ Protocol!";
        let encoded = encode_gzip_blocked(original, 1024).unwrap();
        let decoded = decode_gzip_blocked(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_multiple_blocks() {
        let original: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let encoded = encode_gzip_blocked(&original, 100).unwrap();
        let decoded = decode_gzip_blocked(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_empty_data() {
        let original: &[u8] = &[];
        let encoded = encode_gzip_blocked(original, 1024).unwrap();
        let decoded = decode_gzip_blocked(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_exact_block_size() {
        // 데이터가 블록 크기와 정확히 일치하는 경우
        let original = vec![0xABu8; 256];
        let encoded = encode_gzip_blocked(&original, 256).unwrap();
        let decoded = decode_gzip_blocked(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_block_size_boundary() {
        // 블록 크기보다 1바이트 크거나 작은 경우
        for size in [255, 256, 257] {
            let original: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let encoded = encode_gzip_blocked(&original, 256).unwrap();
            let decoded = decode_gzip_blocked(&encoded).unwrap();
            assert_eq!(decoded, original, "roundtrip failed for size {size}");
        }
    }

    #[test]
    fn test_roundtrip_default_block_size() {
        // block_size=0이면 DEFAULT_BLOCK_SIZE 사용
        let original: Vec<u8> = vec![0x42; 10000];
        let encoded = encode_gzip_blocked(&original, 0).unwrap();
        let decoded = decode_gzip_blocked(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_large_data() {
        let original: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        let encoded = encode_gzip_blocked(&original, DEFAULT_BLOCK_SIZE).unwrap();
        let decoded = decode_gzip_blocked(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_single_byte() {
        let original = &[0x42u8];
        let encoded = encode_gzip_blocked(original, 1024).unwrap();
        let decoded = decode_gzip_blocked(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_block_size_one() {
        // 극단적: 블록 크기 1바이트
        let original = b"ABCD";
        let encoded = encode_gzip_blocked(original, 1).unwrap();
        let decoded = decode_gzip_blocked(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    // -- encode 구조 검증 --

    #[test]
    fn test_encode_structure() {
        let data = b"test";
        let encoded = encode_gzip_blocked(data, 1024).unwrap();

        // 첫 4바이트: 압축 크기 (양수여야 함)
        let block_size = i32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert!(block_size > 0);

        // 블록 뒤에 GZIP 매직 바이트 (0x1f 0x8b)
        assert_eq!(encoded[4], 0x1f);
        assert_eq!(encoded[5], 0x8b);

        // 마지막 4바이트: 종료 마커 (0x00000000)
        let terminator_offset = 4 + block_size as usize;
        let terminator = i32::from_be_bytes([
            encoded[terminator_offset],
            encoded[terminator_offset + 1],
            encoded[terminator_offset + 2],
            encoded[terminator_offset + 3],
        ]);
        assert_eq!(terminator, 0);
    }

    #[test]
    fn test_encode_empty_has_terminator() {
        let encoded = encode_gzip_blocked(&[], 1024).unwrap();
        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded, [0, 0, 0, 0]);
    }

    #[test]
    fn test_encode_multiple_blocks_count() {
        let data = vec![0x42u8; 300];
        let encoded = encode_gzip_blocked(&data, 100).unwrap();

        // 3개 블록 + 종료 마커
        let mut offset = 0;
        let mut block_count = 0;
        loop {
            if offset + 4 > encoded.len() {
                break;
            }
            let size = i32::from_be_bytes([
                encoded[offset],
                encoded[offset + 1],
                encoded[offset + 2],
                encoded[offset + 3],
            ]);
            offset += 4;
            if size <= 0 {
                break;
            }
            block_count += 1;
            offset += size as usize;
        }
        assert_eq!(block_count, 3);
    }

    // -- decode 에러 처리 --

    #[test]
    fn test_decode_corrupted_gzip_data() {
        // 유효한 크기 헤더 + 손상된 GZIP 데이터
        let mut data = Vec::new();
        data.extend_from_slice(&10i32.to_be_bytes()); // 블록 크기 10
        data.extend_from_slice(&[0x1f, 0x8b, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // 손상된 데이터

        let result = decode_gzip_blocked(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_truncated_block() {
        // 크기 헤더는 100바이트를 가리키지만 데이터가 5바이트뿐
        let mut data = Vec::new();
        data.extend_from_slice(&100i32.to_be_bytes());
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);

        let result = decode_gzip_blocked(&data);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("truncated"));
    }

    #[test]
    fn test_decode_empty_input() {
        let decoded = decode_gzip_blocked(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_only_terminator() {
        let decoded = decode_gzip_blocked(&[0, 0, 0, 0]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_insufficient_header_bytes() {
        // 3바이트만 있으면 크기 헤더를 읽을 수 없음 → 스트림 종료로 간주
        let decoded = decode_gzip_blocked(&[0x00, 0x01, 0x02]).unwrap();
        assert!(decoded.is_empty());
    }

    // -- is_gzip_blocked 테스트 --

    #[test]
    fn test_is_gzip_blocked_valid() {
        let encoded = encode_gzip_blocked(b"test data", 1024).unwrap();
        assert!(is_gzip_blocked(&encoded));
    }

    #[test]
    fn test_is_gzip_blocked_empty() {
        assert!(!is_gzip_blocked(&[]));
    }

    #[test]
    fn test_is_gzip_blocked_plain_gzip() {
        // 일반 GZIP (블록이 아닌)은 false
        assert!(!is_gzip_blocked(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_is_gzip_blocked_too_short() {
        assert!(!is_gzip_blocked(&[0x00, 0x00, 0x00, 0x0a, 0x1f])); // 5바이트
    }

    #[test]
    fn test_is_gzip_blocked_zero_size() {
        // 크기가 0인 종료 마커만 있는 경우
        assert!(!is_gzip_blocked(&[0x00, 0x00, 0x00, 0x00, 0x1f, 0x8b]));
    }

    #[test]
    fn test_is_gzip_blocked_negative_size() {
        // 음수 크기
        assert!(!is_gzip_blocked(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1f, 0x8b]));
    }

    // -- decompress_bytes 테스트 --

    #[test]
    fn test_decompress_bytes_empty() {
        let result = decompress_bytes(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_decompress_bytes_uncompressed() {
        let data = b"hello world";
        let result = decompress_bytes(data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decompress_bytes_gzip_blocked() {
        let original = b"test data for decompress_bytes";
        let encoded = encode_gzip_blocked(original, 16).unwrap();
        let result = decompress_bytes(&encoded).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decompress_bytes_single_gzip() {
        use flate2::write::GzEncoder;
        let original = b"single gzip stream";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_bytes(&compressed).unwrap();
        assert_eq!(result, original);
    }
}
