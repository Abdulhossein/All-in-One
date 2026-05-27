# All-in-One V2Ray Config Automation

این ریپو برای **جمع‌آوری، پالایش، تست و انتشار** کانفیگ‌های V2Ray/VLESS/Trojan/SS/SOCKS طراحی شده است و دو اکشن مستقل دارد که یکی فایل `v2rays` را می‌سازد و دیگری نسخه‌ی live-tested را در `data/live_v2ray` نگه می‌دارد.[cite:1]

## ساختار کلی

این پروژه به‌صورت عملی دو pipeline مجزا دارد: یکی برای **به‌روزرسانی و ساخت لیست اصلی** از روی `DEFAULT_LINKS` و `subscriptions.txt`، و دیگری برای **تست live تدریجی** روی خروجی اصلی و ساخت یک فایل مصرفی زنده‌تر.[cite:1]

### فایل‌های مهم

| مسیر | کاربرد |
|---|---|
| `.github/workflows/update_configs.yml` | ورک‌فلو ساخت و به‌روزرسانی فایل `v2rays` از روی subscription sources.[cite:1] |
| `.github/workflows/update_live_batch.yml` | ورک‌فلو تست live تدریجی و ساخت `data/live_v2ray`.[cite:1] |
| `tools/config-update/config_updater.py` | اسکریپت batch-based برای جمع‌آوری و merge کانفیگ‌ها.[cite:1] |
| `tools/live-check/live_batch_updater.py` | اسکریپت batch-based برای تست live با Xray و ساخت خروجی live.[cite:1] |
| `subscriptions.txt` | لیست لینک‌های subscription ورودی که در کنار `DEFAULT_LINKS` استفاده می‌شود.[cite:1] |
| `v2rays` | خروجی اصلی شامل header ثابت و کانفیگ‌های deduplicated.[cite:1] |
| `data/live_v2ray` | خروجی نهایی live-tested که به‌صورت تدریجی ساخته و جایگزین می‌شود.[cite:1] |

## Workflow اول: ساخت `v2rays`

این workflow با نام `Update Configs` کار می‌کند و هدف آن ساخت یا به‌روزرسانی فایل `v2rays` از روی لینک‌های پیش‌فرض و لینک‌های موجود در `subscriptions.txt` است.[cite:1] این workflow هدر اختصاصی فایل را حفظ می‌کند، خطوط هدر/کامنت ورودی از subscriptionها را حذف می‌کند، و فقط URIهای معتبر proxy را نگه می‌دارد.[cite:1]

### منطق اجرا

اسکریپت `config_updater.py` subscriptionها را به‌صورت batchی بررسی می‌کند تا در هر ران، حداقل تعداد مشخصی config تست شود و execution بی‌دلیل طولانی نشود.[cite:1] اگر بعضی subscriptionها خالی باشند یا داده‌ی کمی داشته باشند، اسکریپت از آن‌ها عبور می‌کند و تا رسیدن به آستانه‌ی تعریف‌شده یا سقف لینک‌های همان اجرا ادامه می‌دهد.[cite:1]

### رفتارهای مهم

- هدر خروجی همیشه از `HEADER_LINES` ساخته می‌شود و از ورودی‌ها وارد فایل نهایی نمی‌شود.[cite:1]
- decode base64 معمولی و urlsafe base64 با padding correction انجام می‌شود.[cite:1]
- configهای زنده با TCP liveness check شناسایی می‌شوند، نه live test کامل با Xray.[cite:1]
- پیشرفت cycle در فایل state ذخیره می‌شود تا اجرای بعدی از همان نقطه ادامه پیدا کند.[cite:1]
- اگر همه‌ی subscriptionها تمام شوند یا مدت reset اجباری برسد، cycle از نو شروع می‌شود.[cite:1]

### زمان‌بندی

این workflow با cron در GitHub Actions اجرا می‌شود، ولی cadence واقعی می‌تواند در خود اسکریپت enforce شود تا محدودیت‌های cron ساده‌تر مدیریت شوند.[cite:2][cite:3] برای intervalهای غیردقیق مثل 8.5 ساعت، اجرای پرتکرارتر همراه با کنترل `last_run_at` در state معمولاً از cron خالص قابل‌اعتمادتر است.[cite:2][cite:3]

## Workflow دوم: ساخت `data/live_v2ray`

این workflow برای تست **واقعی‌تر** configها طراحی شده و از Xray-core برای راه‌اندازی local SOCKS proxy و سنجش دسترسی واقعی به URLهای تست استفاده می‌کند.[cite:1] خروجی نهایی در `data/live_v2ray` ذخیره می‌شود و تا زمانی که staged output جدید آماده نشده، فایل نهایی قبلی حفظ می‌شود.[cite:1]

### منطق اجرا

این workflow به‌جای تست کل فایل `v2rays` در هر ران، batchهای محدود را بررسی می‌کند تا زمان اجرا قابل‌کنترل بماند.[cite:1] هر config ابتدا می‌تواند یک precheck سریع داشته باشد و سپس در صورت عبور، با Xray-core به‌صورت واقعی تست شود؛ configهایی که از timeout تعریف‌شده عبور کنند skip می‌شوند تا job روی موارد بدقلق گیر نکند.[cite:1]

### رفتارهای مهم

- فایل final در `data/live_v2ray` نگه داشته می‌شود و فایل staged در runtime ساخته می‌شود.[cite:1]
- اگر job وسط کار fail شود، progress تا همان‌جا حفظ و commit می‌شود.[cite:1]
- جایگزینی فایل نهایی با الگوی write-then-replace انجام می‌شود تا فایل مصرفی ناگهان خالی نشود.[cite:4][cite:5]
- هر هفته یا در پایان یک cycle کامل، بازسازی staged جدید آغاز می‌شود و پس از آماده‌شدن promote می‌شود.[cite:1]

## ورودی‌ها

### `subscriptions.txt`

این فایل شامل لینک‌های subscription سفارشی است و در کنار `DEFAULT_LINKS` استفاده می‌شود.[cite:1] هر خط باید یک لینک معتبر باشد و خطوط خالی یا commentها با `#` نادیده گرفته می‌شوند.[cite:1]

نمونه:

```txt
https://example.com/sub1.txt
https://example.com/sub2.txt
# comment
https://example.com/provider.yaml
```

### اجرای دستی با ورودی جدید

در workflow اول می‌توان به‌صورت دستی `new_subs` را از طریق `workflow_dispatch` ارسال کرد تا لینک‌های جدید به `subscriptions.txt` اضافه شوند.[cite:1] ورودی comma-separated است و در workflow به خطوط جداگانه تبدیل می‌شود.[cite:1]

## خروجی‌ها

### `v2rays`

این فایل خروجی اصلی پروژه است و شامل header ثابت و مجموعه‌ای deduplicated از configهای استخراج‌شده و alive است.[cite:1] این فایل منبع downstream برای live-check نیز هست.[cite:1]

### `data/live_v2ray`

این فایل نسخه‌ی live-tested و مصرفی‌تر از configهاست که با رویکرد batchی و staged update ساخته می‌شود.[cite:1] این فایل طوری مدیریت می‌شود که حتی هنگام reset هفتگی یا پایان cycle نیز تا آماده‌شدن نسخه‌ی جدید، خالی نشود.[cite:1]

## ساختار پوشه‌ها

برای جلوگیری از شلوغی روت، فایل‌های موقت و runtime هر workflow داخل پوشه‌های اختصاصی خودشان نگه داشته می‌شوند.[cite:1]

```text
.github/
  workflows/
    update_configs.yml
    update_live_batch.yml

tools/
  config-update/
    config_updater.py
    README.md
    runtime/
      update_state.json
      v2rays.next

  live-check/
    live_batch_updater.py
    README.md
    bin/
      xray
    runtime/
      live_state.json
      live_v2ray.next
      tmp/

data/
  live_v2ray

subscriptions.txt
v2rays
```

## محدودیت‌ها و ملاحظات

GitHub Actions برای jobهای روی GitHub-hosted runner محدودیت زمانی دارد و jobهای سنگین ممکن است در صورت full-scan شدن بیش از حد طول بکشند؛ به همین دلیل این ریپو از batching، state persistence و staged promotion استفاده می‌کند.[cite:6][cite:7] workflowهای زمان‌بندی‌شده هم ممکن است دقیقاً سر زمان مقرر اجرا نشوند یا delay داشته باشند، بنابراین منطق داخلی اسکریپت نباید صرفاً به precision cron متکی باشد.[cite:2][cite:3]

## توصیه‌های نگه‌داری

- `subscriptions.txt` را تمیز و deduplicated نگه دارید تا چرخه‌ها سریع‌تر شوند.[cite:1]
- اگر runtime هنوز زیاد است، batch size یا timeouts را کاهش دهید.[cite:1]
- اگر خروجی live ضعیف شد، شرط promote staged file را سخت‌گیرانه‌تر کنید تا فایل نهایی فقط وقتی جایگزین شود که کیفیت کافی دارد.[cite:1]
- اگر به latency واقعی دقیق‌تر نیاز است، URLهای تست و timeoutها را با توجه به رفتار runner تنظیم کنید.[cite:1]

## خلاصه عملی

این ریپو یک سیستم دو مرحله‌ای دارد: workflow اول `v2rays` را از subscription sources می‌سازد و workflow دوم نسخه‌ی live-tested آن را در `data/live_v2ray` تولید می‌کند.[cite:1] هر دو workflow برای مقیاس‌پذیری و جلوگیری از runtimeهای طولانی، به‌جای full rebuild از stateful batching، append-progress و resetهای دوره‌ای استفاده می‌کنند.[cite:1]
