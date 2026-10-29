# Diamond Sword — run-book (جهاز نزار)

> الأداة تشتغل بالكامل بالـ stdlib. الالتقاط الحيّ (متصفّح/بروكسي) + CLIs الأداتين = خطوات جهازك (L2).
> **تحقّق من نطاق البرنامج الرسمي قبل أي تشغيل حيّ** — النطاقات تتغيّر؛ البروفايلات هنا نقطة بداية.

## 0) تثبيت (مرّة وحدة)
```
python3 -m venv .venv && source .venv/bin/activate
pip install playwright mitmproxy        # الالتقاط فقط؛ باقي الأداة stdlib
playwright install chromium
```
IOLITE و ONYX: نصّبهم من مجلداتهم (CLIs: `iolite`, وONYX عبر `onyx_link`).

## 1) جهّز الـ engagement
```
python3 -m diamond_sword init fixtures/engagements/crapi.local.json
```
ابدأ دائماً بـ crAPI محلي (صفر مخاطرة قانونية). بعده هدف حقيقي مُصرّح بيه.

## 2) زحف قراءة-فقط (scope مفروض + سجل مُوقّع)
```
python3 -m diamond_sword crawl fixtures/engagements/crapi.local.json \
  --start http://localhost:8888/ --audit runs/crapi.audit.jsonl --rps 1.0
python3 -m diamond_sword verify runs/crapi.audit.jsonl     # لازم ok=True
```

## 3) التقاط متعدّد المبادئ (الموصى: mitmproxy)
انت تسجّل الدخول يدوي لكل حساب، والأداة تلتقط:
```
# لكل مبدأ (A ثم B ثم anon)، شغّل المتصفّح عبر البروكسي وسجّل دخولك، ثم:
DS_PRINCIPAL=A  DS_HAR=runs/A.har    mitmdump -s diamond_sword/capture/backend_mitmproxy.py
DS_PRINCIPAL=B  DS_HAR=runs/B.har    mitmdump -s diamond_sword/capture/backend_mitmproxy.py
DS_PRINCIPAL=anon DS_HAR=runs/anon.har mitmdump -s diamond_sword/capture/backend_mitmproxy.py
```
بديل: Playwright عبر `capture/backend_playwright.py` (يدير المتصفّح حتمياً ويكتب HAR).

## 4) السلسلة الكاملة: HAR → IOLITE → ONYX → تقرير
```
# conductor يربط الكل؛ وفّر runners لـ IOLITE/ONYX (يستدعون CLIs عندك) ثم:
python3 -m diamond_sword pipe fixtures/engagements/crapi.local.json \
  --start http://localhost:8888/ --har runs/A.har,runs/B.har,runs/anon.har
```
(أو برمجياً: Conductor(program, PrincipalManager, IoliteBridge(runner), OnyxBridge(runner), scope_prove, ledger).)

## 5) scorecard T1 صادق
- عدد القوالب المُغطّاة / النسخ (نسبة الطيّ).
- عدد الفخاخ المكتشفة (صفر انفجار).
- findings مؤكّدة من ONYX فقط (Δstate) — صفر FP.
- سجل التدقيق `verify` = ok=True (قانونية مُبرهَنة).
- التدخّل البشري = دخول + لصقة أجوبة العرّاف (ينقص كل تشغيل).

## الخطوط الحمر وقت التشغيل
صفر AI بالزحف/الحكم · scope fail-closed على كل طلب · قراءة-فقط (أي إنشاء = consent + dry-run) · كل قرار مُسجّل بسلسلة hash.

---

## 7) التشغيل الكامل end-to-end (v1.1) — `pipe`
زحف متعدّد المبادئ → HAR مطابق لكل مبدأ → IOLITE → ONYX → تقرير، بخطوة وحدة. البوابات القانونية (ScopeGuard + AuditLedger) مربوطة، وعقد ONYX فاشل-بصوت (أي خلل بالعقد يوقف فوراً ويسمّي الحقل).

```
# 1) لكل مبدأ: سجّل دخول يدوي واحفظ الهيدرز/الكوكيز بملف json (مثال principal_A.json: {"Cookie":"..."} )
# 2) للـ SPA الكبيرة استعمل Playwright/mitmproxy للالتقاط (أدق سطح)؛ الـ urllib المدمج يكفي للصفحات المُخدَّمة + API مباشر.
python3 -m diamond_sword pipe fixtures/engagements/devhub.json \
  --start https://gitlab.example/ \
  --principal A=principal_A.json --principal B=principal_B.json --principal anon \
  --audit audit.jsonl --coverage coverage.jsonl --har-dir ./har \
  --onyx-link /path/to/iolite/onyx_link.py --iolite-module iolite \
  --out report.md
```
- بلا `--onyx-link`: يزحف ويكتب الـ HAR بس (ما يحكم) — مفيد لو تريد تشغّل IOLITE/ONYX يدوي.
- العقد: لو ONYX طلّع مفاتيح مختلفة، راح يطلع `FindingSchemaError` يسمّي الحقل → صحّح الربط بمكان واحد (`pipeline/finding.py::_ALIASES`).

## 8) استئناف بعد انقطاع — `resume`
```
python3 -m diamond_sword resume --coverage coverage.jsonl           # يعرض الحالة + المتبقّي
python3 -m diamond_sword resume --coverage coverage.jsonl \
  --engagement fixtures/engagements/devhub.json --principal anon    # يكمل من المتبقّي
```
