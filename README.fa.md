# agentfence (ایجنت‌فنس)

> **فایروال قابلیت‌ها، شبیه‌ساز Blast Radius و دفتر کل ممیزی مقاوم در برابر دستکاری برای ایجنت‌های هوش مصنوعی**

[English](README.md) · [شبیه‌ساز تعاملی و مستندات](https://mrzroot.github.io/agentfence/)

پیش از آنکه ایجنت یک دستور Shell، کوئری SQL یا عملیات Git را اجرا کند، `agentfence` آن را با سیاست محلی (`fence.toml`) می‌سنجد، دامنه اثر (Blast Radius) روی فایل‌ها را بدون تغییر دیسک شبیه‌سازی می‌کند و هر تصمیم را در یک دفتر زنجیره‌ای SHA-256 ثبت می‌کند.

```bash
agentfence check "git push --force origin main" --json
agentfence run --ledger .agentfence/audit.jsonl -- pytest -q
agentfence verify-ledger .agentfence/audit.jsonl
```

## مجوز

[MIT](LICENSE)
