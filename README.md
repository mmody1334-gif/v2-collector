# 🛰️ V2 Collector

بيجمع سيرفرات V2Ray المجانية من مصادر عامة كل 3 ساعات، يقيس البينج، يشيل السيرفرات الواقعة، يقسم الباقي حسب **الدولة** و**البروتوكول**، ويطلع روابط اشتراك جاهزة لـ **V2Box** وأي عميل V2Ray تاني. وفيه كمان تاب **🧼 آي بي نظيف** بيجمع آي بيهات كلاودفلير اللي المواقع مش بتكشفها كـ VPN/بروكسي.

## الصفحة
`https://mmody1334-gif.github.io/v2-collector/` — منها تختار الدول أو الأسرع أو الكل وتستورد في V2Box، وتلاقي قايمة الآي بيهات النظيفة.

## روابط الاشتراك المباشرة
| | الرابط |
|---|---|
| ⚡ الأسرع | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/fast.txt` |
| 🌍 الكل | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/all.txt` |
| 🇩🇪 دولة | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/country/DE.txt` |
| 🔐 بروتوكول | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/protocol/vless.txt` |
| 📡 تليجرام | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/telegram.txt` |
| 🧼 WARP نظيف | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/warp.txt` |
| 🧼 آي بي نظيف | `https://raw.githubusercontent.com/mmody1334-gif/v2-collector/subs/cleanip.txt` |

## الآي بي النظيف (Clean IP)
آي بيهات كلاودفلير متجربة (TLS على 443) ومش متعلمة كـ بروكسي/VPN عند ip-api. استخدمها كعنوان سيرفر (Address) في أي كونفيج شغال على كلاودفلير مع سيب الـ SNI/Host زي ما هو، أو كـ Endpoint في WARP — كده الموقع بيشوف آي بي كلاودفلير العادي ومش بيكشف إنك على VPN.
- `cleanip-manual.txt`: آي بيهاتك اللي جربتها بنفسك — بتتثبت أول القايمة.
- `cleanip-sources.txt`: قوايم عامة بتتسحب كل تشغيلة.
- اشتراك **🧼 WARP نظيف** (`warp.txt`): كونفيجات WireGuard/WARP جاهزة بأنضف آي بيهات WARP، بتتسجّل تلقائي كل تشغيلة — استيرادها في v2rayNG أو التطبيق وشغّل على طول، والمواقع بتشوف آي بي كلاودفلير العادي.

## الملفات
- `sources.txt`: المصادر، ضيف أو شيل براحتك.
- `scripts/collect.py`: السكربت اللي بيجمع ويختبر ويقسم (Python بس، من غير مكتبات خارجية).
- `scripts/cleanip.py`: بيجمع ويختبر الآي بيهات النظيفة.
- `.github/workflows/update.yml`: التشغيل التلقائي، والنتيجة بتتنشر على فرع `subs`.
- `docs/`: الصفحة.

> كل سيرفر بيتجرب فعلاً من خلال Xray-core: بنقيس Real Delay لـ generate_204، ونحدد دولة الخروج من الـ IP الحقيقي. القياس من سيرفرات GitHub في أمريكا، فبعد الاستيراد اعمل Ping All في V2Box.
> السيرفرات المجانية بيشغّلها ناس مش معروفين، فمتستخدمهاش في أي حاجة حساسة.
