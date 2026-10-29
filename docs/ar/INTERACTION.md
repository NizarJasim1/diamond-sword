# Diamond Sword — طبقة التفاعل (Interaction Engine)

هاي الطبقة تحوّل Diamond Sword من زاحف روابط (GET بس) إلى زاحف **أفعال**: يفتح الموقع وانت مسجّل
دخول، يشغّل كل كائن تفاعلي (أزرار، forms، toggles، قوائم، links)، ويخلّي الـ driver يلتقط كل
الترافيك الناتج (navigations + XHR/fetch/GraphQL) كـ HAR متعدّد المبادئ — بصفر AI وقت التشغيل،
وكل فعل مُسيّج بـ ROE + consent.

> الكود كله `interact/` (المحرك الحتمي، مُبرهَن بالـ tests) + `capture/driver_playwright.py`
> (اليد الحيّة على جهازك). ONYX وحده يحكم؛ هاي الطبقة بس تغذّيه.

---

## 1. شلون يشتغل (باختصار)

1. يشغّل **flows** اللي تكتبها انت (تسجيل دخول، "أنشئ مشروع"، "افتح الإعدادات") حتى يوصل لحالات عميقة
   ما يوصلها الزحف الأعمى.
2. لكل **seed URL** (وكل حالة وصّلتها الـ flows) يمشي على الـ state machine:
   snapshot ← يبصم الـ state ← يعدّد الكائنات ← يرتّبهم (أولويّتك، بعدين triage التفويض) ←
   لكل كائن ما تعامل وياه، داخل الـ scope، مو ممنوع: locate ← gate (ROE+consent) ←
   ينفّذ (إلا إذا مرفوض/dry-run) ← يتعافى من المودال/انتهاء الجلسة/الـ WAF ← يسجّل ← إذا وصل
   لحالة جديدة يضيفها للقائمة.

**ليش العملاق ينكمش:** `/orders/1` و`/orders/2` نفس القالب → حالة وحدة؛ وزر "Delete" بصف طويل من
الطلبات توقيعه واحد → كائن واحد مو ألف. فالتغطية محدودة وقابلة للإنجاز.

**السلامة كلها** من الحقنتين المحقونتين: `ScopeGuard` (وين) و`ConsentGate` فوق `RoePolicy` (شنو):
الأفعال المدمّرة (delete/pay/transfer…) **مرفوضة وما تنفّذ أبداً**، وباقي الـ mutations تحتاج موافقة
(fail-closed) وتمشي dry أول. هذا مُبرهَن بـ test: حتى مع "وافق على كل شي"، الـ Delete ما ينفّذ.

---

## 2. التنصيب (مرّة وحدة على جهازك)

```bash
pip install playwright
python -m playwright install chromium
```

كلشي باقي stdlib. ما تحتاج شي ثاني.

---

## 3. تسجيل الدخول مرّة (storage_state) لكل principal

انت تسجّل الدخول بيدك، وDiamond Sword يعيد استعمال الجلسة المحفوظة. أسهل طريقة:

```bash
# سجّل دخول "الحساب A" بيدك، وبعد ما تخلّص اقفل المتصفح؛ Playwright يحفظ الجلسة
python -m playwright codegen --save-storage=A.storage.json https://TARGET/login
# نفس الشي لمبدأ ثاني (B) ولو تريد anon خلّيه بدون storage
python -m playwright codegen --save-storage=B.storage.json https://TARGET/login
```

المبادئ المتعدّدة (A/B/anon) ضروريّة لصيد BOLA: ONYX يقارن نفس السطح بين هويّتين.

---

## 4. الـ playbook: التوجيه (offline)

التوجيه كله بملف JSON يكتبه المشغّل، يدوياً أو بمساعدة LLM، **قبل** التشغيل (حتى يبقى صفر AI وقت التشغيل). شوف
`fixtures/playbooks/crapi.local.playbook.json` كنموذج. البلوك المهم هو `interaction`:

```jsonc
{
  "target": "my-target",
  "interaction": {
    "seeds":    ["https://app/dashboard", "https://app/settings"],   // من وين يبدأ
    "priority": ["admin", "billing", "order", "profile"],            // صيد هذي الأول
    "avoid":    ["logout", "delete account", "invite"],              // لا تضغطها نهائياً
    "flows": [                                                        // مسارات مقصودة
      { "id": "login-A", "steps": [
        {"action": "navigate", "value": "https://app/login"},
        {"action": "fill", "test_id": "email",    "value": "a@b.c"},
        {"action": "fill", "test_id": "password", "value": "***"},
        {"action": "click", "text": "Sign in", "expect_url": "/dashboard"}
      ]},
      { "id": "create-project", "steps": [
        {"action": "click", "text": "Create"},
        {"action": "fill",  "test_id": "proj-name", "value": "ds-probe"},
        {"action": "click", "text": "Save", "expect_text": "created"}
      ]}
    ]
  }
}
```

خطوة الـ flow تحدّد الكائن بأي من: `role`, `test_id`, `label`, `text`, `css`, `near` (نفس ترتيب
الـ locator cascade). و`expect_url`/`expect_text`/`expect_gone` تتحوّل لـ postcondition (شلون يعرف
إنها نجحت). `avoid`/`priority` تطابق نصّي (substring) على نص الزر أو الـ href.

> ملاحظة سلامة: الـ flows تمرّ من نفس الـ gate. تسجيل الدخول/التعبئة مسموحة (قراءة)، بس أي خطوة
> تغيّر الحالة (مثل "Save" لإنشاء مشروع) تحتاج موافقة — شغّلها بـ `--yes` أو خلّي approver يوافق.

---

## 5. التشغيل

```bash
# التقاط بس (بدون حكم): يشغّل الموقع ويطلّع HAR لكل principal
python -m diamond_sword explore engagement.json \
  --playbook playbook.json \
  --principal A=A.storage.json --principal B=B.storage.json --principal anon \
  --start https://TARGET/ \
  --audit audit.jsonl --ledger-dir ./ledgers --har-dir ./har

# بعدها شغّل الحكم (أو مرّة وحدة بـ --onyx-link حتى يكمّل IOLITE→ONYX→تقرير)
python -m diamond_sword explore engagement.json --playbook playbook.json \
  --principal A=A.storage.json --start https://TARGET/ \
  --onyx-link ../onyx/onyx_link.py --out report.md
```

خيارات مهمّة:
- `--yes` : يوافق تلقائياً على mutations الـ CONSENT (المدمّر يبقى مرفوض). بدونها، أي mutation
  تنرفض (fail-closed) — مناسب للـ run غير المراقَب.
- `--headless` : بدون نافذة متصفح.
- `--ledger-dir` : يخزّن تقدّم التفاعل حتى تكدر تكمّل بعد انقطاع بدون ما يعيد فعل سواه.
- `--audit` : السجل المُوقّع (hash-chain) — دليلك القانوني إنك بقيت داخل النطاق.

الـ ROE knobs (بملف الـ engagement، تحت `roe`): `read_only`, `allow_mutations`, `extra_destructive`,
`auto_allow_whitelisted`, `dry_run_default`, `time_window`, `max_rps`. (شوف `legal/roe.py`.)

---

## 6. سلّم التحقّق (لا تقفز للعملاق)

1. **crAPI محلي** (`fixtures/engagements/crapi.local.json` + `fixtures/playbooks/crapi.local.playbook.json`):
   ثبّت إن الـ explore يمشي، يملأ forms، يفتح طلبات، ويطلّع HAR فيه XHR.
2. **هدف صغير حقيقي داخل scope**: ثبّت إن الـ capture يمسك كل الـ API traffic فعلاً، وإن الـ scope
   guard يرفض أي شي خارج النطاق، وإن المدمّر ما ينضغط.
3. **الهدف الكبير**: شغّل بالمبادئ المتعدّدة، وراقب الـ `questions` (كائنات ما قدر الـ
   cascade يحلّها) — جاوبها بـ playbook محدّث.

> لو شفت `stopped=PAUSE_FOR_HUMAN`: انتهت الجلسة. سجّل دخول من جديد واحفظ storage_state وكمّل بنفس
> الـ ledger-dir.

---

## 7. حدوده (بصراحة)

- الـ driver الحي (`driver_playwright.py`) هو الجزء الوحيد اللي ما ينختبر هنا (يحتاج متصفح حقيقي)؛
  منطقه رقيق عمداً، كل القرارات بالنواة الحتمية المُبرهَنة. ثبّته انت على crAPI أول.
- `mine_js` (باكتشاف السطح) regex — على SPA مضغوط ممكن يفوت endpoints تتبنى وقت التشغيل؛ هنا الـ
  capture الحي هو اللي يغطّيها (لذلك التفاعل مهم).
- للـ fidelity الكامل (بودي الطلب/الرد، وترافيك غير المتصفح) شغّل mitmdump بالتوازي مع
  `capture/backend_mitmproxy.py:DiamondSwordAddon` كـ upstream proxy وادمج الـ HAR‑ين.
