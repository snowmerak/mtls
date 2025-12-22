# mTLS 인증서 관리 도구

mTLS (상호 TLS) 인증서를 생성하고 관리하기 위한 강력하고 사용자 친화적인 CLI 도구입니다. 자체 서명된 Root CA와 서버 인증서를 쉽게 만들 수 있습니다.

## 주요 기능

- 🔐 **자체 서명 Root CA 생성** - 자신만의 인증 기관 생성
- ⛓️ **중간 인증 기관(Intermediate CA) 생성** - 다계층 신뢰 체인을 위한 중간 CA 생성
- 📜 **서버 인증서 생성** - CA로 서명된 서버 인증서 생성
- 👤 **클라이언트 인증서 생성** - mTLS 인증을 위한 클라이언트 인증서 생성
- ✍️ **CSR 서명** - 외부 소스의 인증서 서명 요청(CSR) 서명
- 🚫 **인증서 폐기** - 인증서 폐기 및 CRL 생성
- 🔍 **검사 및 검증** - 인증서 세부 정보 검사 및 체인 검증
- 🌳 **계층 구조 시각화** - 인증서 체인 계층 구조 및 상태 트리 조회
- 🔑 **다양한 키 타입 지원** - RSA (2048/4096), ECDSA (P-256/P-384/P-521), Ed25519 지원
- 🎨 **대화형 CLI** - 합리적인 기본값을 가진 사용자 친화적 프롬프트
- 📊 **인증서 레지스트리** - SQLite 백엔드로 모든 인증서를 한 곳에서 체계적으로 관리
- 🎯 **유연한 Subject 설정** - 모든 인증서 필드 커스터마이징 가능 (간소화된 DN 지원)
- 🌐 **SAN 지원** - 서버 및 클라이언트 인증서 모두에 DNS 이름과 IP 주소 추가 가능
- 📦 **풀체인 지원** - 기본적으로 풀체인(Full Chain) 인증서 자동 생성

## 설치

```bash
# 저장소 클론
git clone https://github.com/snowmerak/mtls.git
cd mtls

# 바이너리 빌드
go build

# 선택사항: 전역 설치
go install
```

## Taskfile 사용법

이 프로젝트는 빌드 및 테스트 작업을 관리하기 위해 [Taskfile](https://taskfile.dev/)을 사용합니다.

```bash
# 웹 애플리케이션 빌드
task build:web

# Go 애플리케이션 빌드
task build:app

# 웹 및 Go 애플리케이션 모두 빌드
task build

# 테스트 실행
task test

# 도구 전역 설치 (웹 앱 빌드 포함)
task install
```

## 예제

다양한 언어로 구현된 실제 예제는 [examples](./examples) 디렉토리를 참조하세요:

- **Go**: [서버](./examples/go-server/) | [클라이언트](./examples/go-client/) - 표준 라이브러리, 의존성 없음
- **Node.js**: [서버](./examples/node-server/) | [클라이언트](./examples/node-client/) - 내장 HTTPS 모듈 사용
- **Python**: [서버](./examples/python-server/) | [클라이언트](./examples/python-client/) - 표준 라이브러리 ssl 모듈
- **PHP**: [서버](./examples/php-server/) | [클라이언트](./examples/php-client/) - OpenSSL을 사용하는 스트림 컨텍스트
- **Rust**: [서버](./examples/rust-server/) | [클라이언트](./examples/rust-client/) - 고성능 Axum + Rustls
- **Caddy**: [설정](./examples/caddy/) - mTLS를 지원하는 프로덕션 리버스 프록시

빠른 테스트:
```bash
cd examples
./test.sh
```

## 빠른 시작

### 1. Root CA 생성 (대화형 모드)

```bash
./mtls ca create
```

다음 항목들을 입력하게 됩니다:
- CA 타입 (Root CA 또는 Intermediate CA)
- Common Name (예: "우리 회사 Root CA")
- 조직명 (선택 사항)
- 국가 코드 (선택 사항)
- 유효 기간 (년)
- 키 타입 (RSA 2048/4096, ECDSA P-256/P-384/P-521, Ed25519)
- 출력 디렉토리

> **참고**: 조직명과 국가 코드는 선택 사항입니다. 생략할 경우 DN에는 Common Name만 포함됩니다.
> **참고**: 생성된 `ca-cert.pem` 파일은 중간 CA인 경우 풀체인을 포함합니다. 단일 인증서는 `ca-cert-leaf.pem`으로 별도 생성됩니다.

### 2. 중간 인증 기관(Intermediate CA) 생성 (대화형 모드)

```bash
./mtls ca create
```

CA 타입에서 "Intermediate CA"를 선택하세요. 그 후 레지스트리에 등록된 부모 CA를 선택하라는 메시지가 표시됩니다.

### 3. 서버 인증서 생성 (대화형 모드)

```bash
./mtls cert create
```

다음 항목들을 입력하게 됩니다:
- 기존 CA 선택 또는 찾아보기
- Common Name (예: "api.example.com")
- DNS 이름들 (쉼표로 구분)
- IP 주소들 (쉼표로 구분)
- 조직명 (선택 사항)
- 유효 기간
- 키 타입

> **참고**: 생성된 `server-cert.pem` 파일은 풀체인 인증서를 포함합니다. Leaf 인증서만 필요한 경우 `server-cert-leaf.pem`을 사용하세요.

### 4. 클라이언트 인증서 생성 (대화형 모드)

```bash
./mtls cert create-client
```

다음 항목들을 입력하게 됩니다:
- 기존 CA 선택
- Common Name (예: "client-1")
- DNS 이름들 (쉼표로 구분, 선택 사항)
- IP 주소들 (쉼표로 구분, 선택 사항)
- 조직명 (선택 사항)
- 유효 기간
- 키 타입

> **참고**: 생성된 `client-cert.pem` 파일은 풀체인 인증서를 포함합니다. Leaf 인증서만 필요한 경우 `client-cert-leaf.pem`을 사용하세요.

### 5. 인증서 트리 조회

인증서 계층 구조와 상태를 시각적으로 확인합니다:

```bash
./mtls tree
```

모든 인증서의 유효성 상태, 만료일, 상속 관계를 트리 형태로 보여줍니다.

```text
Certificate Registry Tree
=========================
Legend: ✓ Valid  ! Expired  ✗ Revoked

├── ✓ My Root CA (root_ca) [Expires: 2035-12-22 (3650 days left)]
│   ├── ✓ Intermediate CA (intermediate_ca) [Expires: 2030-12-22 (1825 days left)]
│   │   ├── ✓ api.server.com (server) [Expires: 2026-12-22 (365 days left)]
│   │   └── ! expired-client (client) [Expired: 2024-01-01 (-356 days left)]
```
- 유효 기간
- 키 타입

### 5. 기타 작업

```bash
# 모든 CA 목록 (Root 및 Intermediate)
./mtls ca list

# 모든 서버 인증서 목록
./mtls cert list

# 모든 클라이언트 인증서 목록
./mtls cert list-client

# CSR 서명
./mtls ca sign

# 인증서 폐기
./mtls ca revoke

# CRL 생성
./mtls ca crl

# 인증서 검사
./mtls cert inspect --cert ./path/to/cert.pem

# 인증서 체인 검증
./mtls cert verify --cert ./path/to/cert.pem --root ./path/to/root.pem --intermediate ./path/to/inter.pem
```

## 배치 모드 (비대화형)

### Root CA 생성

```bash
./mtls ca create --batch \
  --type root \
  --cn "우리 회사 Root CA" \
  --org "우리 조직" \
  --country "KR" \
  --years 10 \
  --key-type rsa4096 \
  --output ./certs/ca
```

### 중간 인증 기관(Intermediate CA) 생성

```bash
./mtls ca create --batch \
  --type intermediate \
  --parent "우리 회사 Root CA" \
  --cn "우리 회사 Intermediate CA" \
  --org "우리 조직" \
  --country "KR" \
  --years 5 \
  --key-type rsa4096 \
  --output ./certs/intermediate

```bash
./mtls ca create --batch \
  --cn "우리 회사 Root CA" \
  --org "우리 조직" \
  --country "KR" \
  --years 10 \
  --key-type rsa4096 \
  --output ./certs/ca
```

### 서버 인증서 생성

```bash
./mtls cert create --batch \
  --ca ./certs/ca \
  --cn "api.example.com" \
  --org "우리 API 서버" \
  --dns "api.example.com,*.api.example.com,localhost" \
  --ip "127.0.0.1,192.168.1.100" \
  --years 5 \
  --key-type rsa2048 \
  --output ./certs/servers/api.example.com
```

## 키 타입

| 키 타입 | 보안성 | 속도 | 용도 |
|---------|--------|------|------|
| `rsa2048` | 양호 | 빠름 | 일반 서버 인증서 |
| `rsa4096` | 우수 | 느림 | Root CA, 고보안 환경 |
| `ecp256` | 양호 | 매우 빠름 | 최신 시스템, IoT |
| `ecp384` | 우수 | 빠름 | 고보안 최신 시스템 |
| `ecp521` | 최고 | 보통 | 최대 보안 요구사항 |

## 디렉토리 구조

인증서 생성 후 다음과 같은 구조가 만들어집니다:

```
certs/
├── .registry.json                    # 인증서 레지스트리
├── ca/
│   ├── ca-cert.pem                  # CA 인증서
│   ├── ca-key.pem                   # CA 개인키 (0600)
│   └── .metadata.json               # CA 메타데이터
└── servers/
    └── api.example.com/
        ├── server-cert.pem          # 서버 인증서
        ├── server-key.pem           # 서버 개인키 (0600)
        ├── ca-cert.pem              # CA 인증서 (복사본)
        └── .metadata.json           # 인증서 메타데이터
```

## Go 코드에서 사용하기

### 서버 측 (mTLS 서버)

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "log"
    "net/http"
    "os"
)

func main() {
    // 서버 인증서 로드
    cert, err := tls.LoadX509KeyPair(
        "certs/servers/api.example.com/server-cert.pem",
        "certs/servers/api.example.com/server-key.pem",
    )
    if err != nil {
        log.Fatal(err)
    }

    // 클라이언트 검증을 위한 CA 인증서 로드
    caCert, err := os.ReadFile("certs/ca/ca-cert.pem")
    if err != nil {
        log.Fatal(err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    // TLS 설정
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientCAs:    caCertPool,
        ClientAuth:   tls.RequireAndVerifyClientCert,
    }

    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
    }

    log.Println("서버 시작: https://localhost:8443")
    log.Fatal(server.ListenAndServeTLS("", ""))
}
```

### 클라이언트 측 (mTLS 클라이언트)

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "io"
    "log"
    "net/http"
    "os"
)

func main() {
    // 클라이언트 인증서 로드
    cert, err := tls.LoadX509KeyPair(
        "certs/servers/client.example.com/server-cert.pem",
        "certs/servers/client.example.com/server-key.pem",
    )
    if err != nil {
        log.Fatal(err)
    }

    // CA 인증서 로드
    caCert, err := os.ReadFile("certs/ca/ca-cert.pem")
    if err != nil {
        log.Fatal(err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    // TLS 클라이언트 설정
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
    }

    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }

    resp, err := client.Get("https://api.example.com:8443")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    log.Println(string(body))
}
```

## IP 전용 인증서

DNS 이름 없이 IP 주소만으로 인증서를 생성할 수 있습니다:

```bash
./mtls cert create --batch \
  --ca ./certs/ca \
  --cn "192.168.1.100" \
  --ip "192.168.1.100,10.0.0.5" \
  --key-type ecp256
```

다음과 같은 경우에 유용합니다:
- 내부 네트워크 서비스
- IP 기반 통신을 하는 Kubernetes 파드
- 고정 IP를 가진 IoT 디바이스

## 명령어 참조

```bash
# Root CA 관리
mtls ca create              # 새 Root CA 생성 (대화형)
mtls ca create --batch      # 새 Root CA 생성 (비대화형)
mtls ca list                # 모든 Root CA 목록

# 서버 인증서 관리
mtls cert create            # 서버 인증서 생성 (대화형)
mtls cert create --batch    # 서버 인증서 생성 (비대화형)
mtls cert list              # 모든 서버 인증서 목록

# 유틸리티
mtls version                # 버전 표시
mtls help                   # 도움말 표시
mtls [명령어] --help        # 특정 명령어 도움말
```

## 고급 옵션

### 커스텀 Subject 필드

배치 모드에서 더 많은 필드를 커스터마이징할 수 있습니다:

```bash
./mtls ca create --batch \
  --cn "우리 Root CA" \
  --org "우리 조직" \
  --country "KR" \
  --key-type rsa4096
```

### 혼합 키 타입

CA와 서버 인증서에 서로 다른 키 타입을 사용할 수 있습니다:

```bash
# ECDSA CA (빠름)
./mtls ca create --batch --cn "빠른 CA" --key-type ecp256

# ECDSA CA로 서명된 RSA 서버 인증서
./mtls cert create --batch --ca ./certs/ca --cn "server.com" --key-type rsa2048
```

## 보안 모범 사례

1. **개인키 보호**: 개인키는 자동으로 0600 권한으로 설정됩니다
2. **키 타입**: CA에는 RSA 4096 또는 ECDSA P-384 이상 사용
3. **유효 기간**: 
   - CA: 10-20년
   - 서버 인증서: 1-5년
4. **인증서 교체**: 정기적으로 서버 인증서 교체
5. **저장소**: CA 개인키는 안전하고 암호화된 저장소에 보관

## 개발

### 테스트 실행

```bash
go test -v
go test -cover
go test -bench=.
```

### 빌드

```bash
go build
```

## 라이선스

이 프로젝트는 오픈 소스입니다. 자세한 내용은 LICENSE 파일을 참조하세요.

## 기여

기여를 환영합니다! Pull Request를 자유롭게 제출해주세요.

## 기술 스택

- **언어**: Go 1.25.4
- **CLI 프레임워크**: [cobra](https://github.com/spf13/cobra)
- **대화형 프롬프트**: [survey](https://github.com/AlecAivazis/survey)
- **색상 출력**: [color](https://github.com/fatih/color)
- **로딩 스피너**: [spinner](https://github.com/briandowns/spinner)

## 특징

### 사용자 친화적
- 🎨 색상이 있는 출력 (성공/오류/정보)
- ⏳ 작업 진행 시 로딩 스피너
- 💬 명확한 프롬프트와 도움말
- ✅ 합리적인 기본값 제공

### 유연함
- 🔧 모든 Subject 필드 커스터마이징
- 🔑 RSA와 ECDSA 키 타입 지원
- 🌐 DNS 이름과 IP 주소 SAN 지원
- 🤖 자동화를 위한 배치 모드

### 안전함
- 🔒 자동 개인키 권한 설정 (0600)
- 📋 인증서 메타데이터 추적
- 🔍 SHA256 fingerprint 계산
- ✨ 인증서 체인 검증

## FAQ

### Q: IP 주소만으로 인증서를 만들 수 있나요?
A: 네! DNS 이름 없이 IP 주소만으로 인증서를 생성할 수 있습니다. `--ip` 플래그만 사용하면 됩니다.

### Q: CA와 서버에 다른 키 타입을 사용할 수 있나요?
A: 네! 예를 들어 ECDSA CA로 RSA 서버 인증서를 서명하거나 그 반대도 가능합니다.

### Q: 생성된 인증서는 어디에 저장되나요?
A: 기본적으로 `./certs/` 디렉토리에 저장됩니다. `--output` 플래그로 변경할 수 있습니다.

### Q: 기존 CA를 사용해서 새 서버 인증서를 만들 수 있나요?
A: 네! `mtls cert create`를 실행하면 기존 CA 목록에서 선택하거나 CA 경로를 직접 지정할 수 있습니다.

### Q: 프로덕션 환경에서 사용할 수 있나요?
A: 이 도구는 내부 네트워크나 개발/테스트 환경에 적합합니다. 공개 인터넷에서 사용할 인증서는 신뢰할 수 있는 CA (Let's Encrypt 등)를 사용하세요.
