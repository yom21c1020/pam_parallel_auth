# pam_parallel_auth

fprintd(지문)와 패스워드 인증을 **병렬로** 처리하는 PAM 모듈.
먼저 성공하는 쪽이 인증을 완료하고, 나머지는 자동으로 취소된다.

macOS / GDM에서 지문과 패스워드를 동시에 받는 것과 동일한 동작.

## 빌드

```bash
# 의존성
sudo dnf install pam-devel  # Fedora

# 빌드
cargo build --release
```

## 설치 (Fedora + authselect)

```bash
sudo ./install.sh
```

이 스크립트는 다음을 수행한다:
1. `.so`를 `/usr/lib64/security/pam_parallel_auth.so`에 설치
2. `custom-parallel-auth` authselect 프로필 설치
3. `with-parallel-auth` feature를 활성화한 상태로 프로필 선택

### 수동 설치

```bash
# .so 설치
sudo install -m 755 target/release/libpam_parallel_auth.so /usr/lib64/security/pam_parallel_auth.so

# authselect 프로필 설치
sudo cp -a authselect/custom-parallel-auth /etc/authselect/custom/

# 프로필 활성화
sudo authselect select custom/custom-parallel-auth with-parallel-auth --force
```

### 원래 프로필로 복원

```bash
sudo authselect select local  # 또는 이전 프로필
```

## 동작 방식

1. `pam_sm_authenticate()` 진입 시 설정된 백엔드를 병렬 실행
2. **지문 성공** → `PAM_SUCCESS` 즉시 반환, `pam_unix` 건너뜀
3. **패스워드 입력** → `PAM_AUTHTOK`에 저장 후 `PAM_IGNORE` 반환,
   뒤의 `pam_unix.so use_first_pass`가 실제 검증
4. **fprintd 없음 / 지문 미등록** → 패스워드 단독 모드로 자동 fallback

### PAM 스택 흐름

```
# with-parallel-auth 활성화 시 system-auth의 auth 섹션:

auth  [success=2 default=ignore]  pam_parallel_auth.so modules=fprint,pass
auth  sufficient                  pam_unix.so use_first_pass nullok
auth  required                    pam_deny.so
```

- 지문 성공 → `PAM_SUCCESS` → `success=2`로 pam_unix + pam_deny 건너뜀 → 인증 완료
- 패스워드 입력 → `PAM_IGNORE` → `default=ignore` → pam_unix로 진행 → 패스워드 검증
- 전부 실패 → `PAM_AUTH_ERR` → `default=ignore` → pam_unix로 진행 → pam_unix도 실패 → 인증 실패

## 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `modules=fprint,pass` | `fprint,pass` | 활성화할 백엔드 목록 |
| `debug` | off | syslog에 디버그 로그 출력 |
| `enable_closed_lid` | off | 설정 시 덮개 닫힌 상태에서도 지문 인식 시도 |
| `timeout=60` | `60` | 전체 인증 타임아웃 (초) |

## 새 백엔드 추가

`AuthBackend` trait을 구현하면 새로운 인증 백엔드를 추가할 수 있다:

```rust
// src/backend/yubikey.rs
use super::{AuthBackend, AuthOutcome};

pub struct YubikeyBackend { /* ... */ }

impl AuthBackend for YubikeyBackend {
    fn name(&self) -> &str { "yubikey" }

    fn authenticate<'a>(
        &'a self,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = AuthOutcome> + Send + 'a>> {
        Box::pin(async move { /* ... */ })
    }

    fn cancel<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async { /* ... */ })
    }
}
```

그 후 `orchestrator.rs`의 `run_auth()`에서 새 백엔드를 등록하면 된다.

## 타겟 환경

- Fedora 43, KDE Plasma, Wayland
- fprintd (D-Bus API v1)
- sudo, polkit

## 라이선스

GPL-3.0 (pamsm crate 라이선스를 따름)
