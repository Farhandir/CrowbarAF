# CI ve Branch Protection

## 1. CI (GitHub Actions)

Workflow: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)

Her `master` push’unda ve PR’da:

1. Python 3.12
2. `pip install -r requirements.txt`
3. `pytest -q`

Unit testler fake/mock kullanır; Ghidra/capa/FLOSS/gerçek malware entegrasyonu
GitHub runner’da **çalışmaz**. Onlar offline VM smoke testinde kalır.

İlk push’tan sonra GitHub’da **Actions** sekmesinde `CI / tests` çalışması
görünür. Yeşil değilse branch protection merge’e izin vermez.

## 2. Branch protection (GitHub arayüzü)

Repo → **Settings** → **Branches** → **Add branch protection rule**:

- Branch name pattern: `master`
- ✅ **Require a pull request before merging**
  - Required approvals: `1`
  - Dismiss stale approvals: açık
- ✅ **Require status checks to pass before merging**
  - Required check: **`tests`**
  - Require branches to be up to date: açık
- ✅ **Do not allow bypassing the above settings** (enforce admins)
- ✅ **Restrict who can push** (istersen sadece sen/arkadaş)
- ❌ Allow force pushes
- ❌ Allow deletions

Kaydet. Artık `master`’a doğrudan push yerine PR açılır; CI yeşil + review
olmadan merge edilemez.

> Not: Private repo planına göre bazı branch-protection seçenekleri kilitli
> olabilir. Public repo’da klasik branch protection ücretsizdir. Kilitliyse
> public’e geçince aynı adımları uygula; o zamana kadar PR disiplini kullan.

### Alternatif: Rulesets

**Settings → Rules → New ruleset → New branch ruleset**:

- Target: `master`
- Require a pull request
- Require status checks: `tests`
- Block force pushes
- Block deletions

## 3. İlk PR akışı

```text
branch → commit → push → PR
                         ↓
                    CI / tests
                         ↓
                  review (1 approval)
                         ↓
                    master merge
```

## 4. Doğrulama

- Actions sekmesinde `CI` yeşil mi?
- Settings → Branches’ta `master` kuralı görünüyor mu?
- `master`’a doğrudan push denemesi reddediliyor mu? (Kendi hesabında test etme;
  yeni bir branch + PR kullan.)
