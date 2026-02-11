//! ABEEK 계획 데이터를 가져오는 CLI 예제
//!
//! 사용법:
//! ```bash
//! cargo run --example fetch_abeek -- <arg1> <arg2> <arg3>
//! ```
//!
//! 예시:
//! ```bash
//! cargo run --example fetch_abeek -- 2026 090 50124399
//! ```

use ozra::FieldValue;
use ozra::client::OzClient;
use serde::Serialize;
use std::collections::HashMap;
use std::env;

/// JSON 출력용 데이터 구조
#[derive(Debug, Serialize)]
struct OutputData {
    /// 성공 여부
    success: bool,
    /// 메시지 (에러 시 에러 메시지)
    message: String,
    /// 데이터셋 목록 (그룹명 -> 행 목록)
    datasets: HashMap<String, Vec<HashMap<String, serde_json::Value>>>,
}

/// FieldValue를 serde_json::Value로 변환
fn field_value_to_json(value: &FieldValue) -> serde_json::Value {
    match value {
        FieldValue::Null => serde_json::Value::Null,
        FieldValue::String(s) => serde_json::Value::String(s.clone()),
        FieldValue::Int(v) => serde_json::json!(*v),
        FieldValue::Long(v) => serde_json::json!(*v),
        FieldValue::Float(v) => serde_json::json!(*v),
        FieldValue::Double(v) => serde_json::json!(*v),
        FieldValue::Bool(v) => serde_json::json!(*v),
        FieldValue::DateTime(ms) => serde_json::json!(*ms),
        FieldValue::Binary(b) => serde_json::json!({
            "type": "binary",
            "length": b.len()
        }),
    }
}

fn print_usage() {
    eprintln!("ABEEK 계획 데이터 조회 CLI");
    eprintln!();
    eprintln!("사용법:");
    eprintln!("  cargo run --example fetch_abeek -- <arg1> <arg2> <arg3>");
    eprintln!();
    eprintln!("인자:");
    eprintln!("  arg1 - 연도 (예: 2026)");
    eprintln!("  arg2 - 학과 코드 (예: 090)");
    eprintln!("  arg3 - 학번 (예: 50124399)");
    eprintln!();
    eprintln!("예시:");
    eprintln!("  cargo run --example fetch_abeek -- 2026 090 50124399");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        print_usage();
        std::process::exit(1);
    }

    let arg1 = &args[1];
    let arg2 = &args[2];
    let arg3 = &args[3];

    let result = fetch_abeek_data(arg1, arg2, arg3).await;

    // JSON 출력
    match serde_json::to_string_pretty(&result) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("JSON 직렬화 실패: {}", e);
            std::process::exit(1);
        }
    }

    if !result.success {
        std::process::exit(1);
    }
}

async fn fetch_abeek_data(arg1: &str, arg2: &str, arg3: &str) -> OutputData {
    // OZ 서버 설정
    const BASE_URL: &str = "https://office.ssu.ac.kr/oz70";
    const OZRNAME: &str = "zcm_get_abeek_plan_2018_new";
    const CATEGORY: &str = "CM";
    const ODI_NAME: &str = "zcm_get_abeek_plan_2018_new.odi";

    // 파라미터 구성
    // arg4와 UNAME은 서버에서 요구하는 필수 파라미터
    let params = vec![
        ("arg1".to_string(), arg1.to_string()),
        ("arg2".to_string(), arg2.to_string()),
        ("arg3".to_string(), arg3.to_string()),
        ("arg4".to_string(), "OZASPN".to_string()),
        ("UNAME".to_string(), "OZASPN".to_string()),
    ];

    // 클라이언트 생성
    let mut client = match OzClient::new(BASE_URL, "guest", "guest") {
        Ok(c) => c,
        Err(e) => {
            return OutputData {
                success: false,
                message: format!("클라이언트 생성 실패: {}", e),
                datasets: HashMap::new(),
            };
        }
    };

    // 1. 세션 초기화 (파라미터 포함)
    if let Err(e) = client
        .init_session_with_params(OZRNAME, CATEGORY, &params)
        .await
    {
        return OutputData {
            success: false,
            message: format!("세션 초기화 실패: {}", e),
            datasets: HashMap::new(),
        };
    }

    // 2. 로그인
    if let Err(e) = client.login().await {
        return OutputData {
            success: false,
            message: format!("로그인 실패: {}", e),
            datasets: HashMap::new(),
        };
    }

    // 3. DataModule 조회
    let response = match client
        .fetch_data_module(ODI_NAME, &format!("/{}", CATEGORY), &params)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return OutputData {
                success: false,
                message: format!("데이터 조회 실패: {}", e),
                datasets: HashMap::new(),
            };
        }
    };

    // 4. 결과 변환
    let mut datasets: HashMap<String, Vec<HashMap<String, serde_json::Value>>> = HashMap::new();

    for (group_name, rows) in &response.datasets {
        let mut json_rows: Vec<HashMap<String, serde_json::Value>> = Vec::new();

        for row in rows {
            let mut json_row: HashMap<String, serde_json::Value> = HashMap::new();
            for (field_name, value) in row {
                json_row.insert(field_name.clone(), field_value_to_json(value));
            }
            json_rows.push(json_row);
        }

        datasets.insert(group_name.clone(), json_rows);
    }

    OutputData {
        success: true,
        message: format!(
            "조회 성공: {} 그룹, 총 {} 행",
            response.datasets.len(),
            response
                .datasets
                .iter()
                .map(|(_, rows)| rows.len())
                .sum::<usize>()
        ),
        datasets,
    }
}
