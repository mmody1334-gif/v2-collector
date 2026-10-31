# 🛰️ V2 Collector

بيجمع سيرفرات V2Ray المجانية من مصادر عامة كل 3 ساعات، يقيس البينج، يشيل السيرفرات الواقعة، يقسم الباقي حسب **الدولة** و**البروتوكول**، ويطلع روابط اشتراك جاهزة لـ **V2Box** وأي عميل V2Ray تاني.

## الصفحة
`https://mmody1334-gif.github.io/v2-collector/` — منها تختار الدول أو الأسرع أو الكل وتستورد في V2Box.

## روابط الاشتراك المباشرة
| | الرابط |
|---|---|
| ⚡ الأسرع | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/fast.txt` |
| 🌍 الكل | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/all.txt` |
| 🇩🇪 دولة | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/country/DE.txt` |
| 🔐 بروتوكول | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/protocol/vless.txt` |

## الملفات
- `sources.txt`: المصادر، ضيف أو شيل براحتك.
- `scripts/collect.py`: السكربت اللي بيجمع ويختبر ويقسم (Python بس، من غير مكتبات خارجية).
- `.github/workflows/update.yml`: التشغيل التلقائي، والنتيجة بتتنشر على فرع `subs`.
- `docs/`: الصفحة.

> البينج مقاس بـ TCP من سيرفرات GitHub، فهو مؤشر تقريبي. بعد الاستيراد اعمل Ping All في V2Box.
> السيرفرات المجانية بيشغّلها ناس مش معروفين، فمتستخدمهاش في أي حاجة حساسة.
