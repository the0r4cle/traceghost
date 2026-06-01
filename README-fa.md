# traceghost

> ردپای پکت‌های **شبح‌وار**ت رو پیدا کن.
>
> دو ابزار کوچک لینوکسی برای پیدا کردن این که کدوم **سورس‌آی‌پی‌های اسپوف‌شده** واقعاً از فیلتر egress شبکه‌ت و فیلتر ingress مقصد رد می‌شن — و تشخیص این که DPI یا فایروال state‌دار وسط راه کانکشن رو وسط می‌بنده یا نه.

[English](README.md) &nbsp;|&nbsp; 🌐 **فارسی**

---

## معرفی

`traceghost` از دو ابزار CLI تشکیل شده که با هم کار می‌کنن:

| باینری       | نقش                                                                                |
| ------------ | ---------------------------------------------------------------------------------- |
| `tg-scan`    | **فرستنده** — پکت IPv4 خام با source address اسپوف‌شده می‌فرسته به یه target مشخص   |
| `tg-listen`  | **گیرنده** — پکتایی که می‌رسن رو می‌گیره و per `(پروتکل, سورس‌آی‌پی)` شمارش می‌کنه |

هر کدوم دو ساب‌کامند داره که با هم جفت می‌شن:

| Mode           | رفتار فرستنده                                                       | گزارش گیرنده                                                                       |
| -------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **discover**   | یک پکت به ازای هر سورس‌آی‌پی، در هر پروتکل                          | لیست سورس‌آی‌پی‌هایی که رسیدن، per پروتکل                                          |
| **throughput** | `N` پکت با سایز `S` بایت از هر سورس، روی یک پروتکل، با rate limit | شمارنده‌ی پکت و بایت per IP، مرتب — نشون می‌ده کی داده انتقال داد و کی drop شد |

روش کار دومرحله‌ای:

۱. **`discover`** پیدا می‌کنه کدوم سورس‌های اسپوف‌شده از فیلتر egress فرستنده عبور می‌کنن و فیلتر ingress گیرنده پذیرفته‌شون.
۲. **`throughput`** ترافیک پایدار از همون بازماندگان می‌فرسته تا ببینه DPI / فایروال state‌دار وسط راه بعد از چند پکت اول کدوم‌ها رو block می‌کنه.

## چرا؟

- پیدا کردن سورس‌هایی که برای پروژه‌های تونل با IP اسپوف کار می‌کنن.
- تست فیلتر egress شبکه‌ی خودت (BCP 38 / uRPF) و reverse-path filter سرورت.
- درک **رفتار DPI**: یه سورسی که تو `discover` (یک پکت) موفقه ولی تو `throughput` (پانصد پکت) شکست می‌خوره → یعنی شبکه‌ی وسط stateful tracking داره.
- تحقیق ضد سانسور روی **زیرساخت خودت**.

## امکانات

- 🚀 **سریع** — مسیر فرستادن خام با `AF_INET / IPPROTO_RAW`، بافر روی stack، و استراتژی `IP_HDRINCL` که کرنل رو از مسیر بیرون می‌اندازه.
- 🎛 **سه پروتکل** — دیتاگرام UDP، probe برای TCP-SYN، و ICMP Echo Request.
- 📏 **سایز پکت قابل تنظیم** برای throughput (۰ تا ۱۴۰۰ بایت برای فرار از فرگمنت IP).
- ⏱ **rate limiter** با `nanosleep` و scheduling بدون drift (`--rate` بر حسب pps، صفر = نامحدود).
- 🎯 **فیلتر پروتکل تو listener** — فقط پروتکل‌هایی که می‌خوای رو شمارش کن، TCP/ICMP رندوم وسط wire رو نادیده بگیر.
- 🔇 **defaults سکوت** — اگه فایل کانفیگ پیش‌فرض موجود نباشه، سکوت می‌کنه. فقط وقتی `-c <file>` صریح بدی و فایل نباشه، اخطار می‌ده.
- 📊 **per-IP counter** تو listener، با گزارش top-N مرتب و خروجی فایل نهایی.
- 🧹 **CLI تمیز** با subcommand، فلگ‌های long و short، و فایل کانفیگ INI برای مقادیری که نمی‌خوای هر بار تکرارشون کنی.
- 🛡 **capture بدون آلودگی** — listener پکتای outgoing رو با `PACKET_IGNORE_OUTGOING` (کرنل ≥ ۴٫۲۰) drop می‌کنه، با fallback سطح userspace. حتی اگه هر دو طرف رو روی همون ماشین برای تست بزنی، شمارش درست در میاد.
- ✨ **کوچیک** — حدود ۱۲۰۰ خط C بدون dependency، با `make` تو چند ثانیه بیلد می‌شه.

## بیلد

```bash
make
```

دو باینری تو پوشه می‌سازه: `tg-scan` و `tg-listen`.

اگه نمی‌خوای هر بار `sudo` بزنی، capability `CAP_NET_RAW` رو روی باینری‌ها بذار:

```bash
make setcap     # یک بار با sudo capability نصب می‌کنه
./tg-listen discover    # بعدش دیگه بدون sudo
```

## شروع سریع

### مرحله ۱ — discover

روی ماشین **target** (که قراره probeها رو دریافت کنه):

```bash
sudo ./tg-listen discover
```

روی ماشین **فرستنده**:

```bash
sudo ./tg-scan discover \
     --target 1.2.3.4 \
     --range 5.0.0.0/24 \
     --range 8.8.8.0/24 \
     --rate 5000
```

وقتی listener رو `Ctrl+C` کنی، گزارش مرتب رو تو `scan_report.txt` می‌نویسه. IPهایی که رسیدن رو بکش بیرون و تو `open_ips.txt` ذخیره کن (هر IP در یک خط).

### مرحله ۲ — throughput

```bash
# سمت target
sudo ./tg-listen throughput --proto udp --top 20

# سمت فرستنده
sudo ./tg-scan throughput \
     --target 1.2.3.4 \
     --ips-file open_ips.txt \
     --proto udp \
     --size 1200 --count 500 --rate 3000
```

جدول نهایی per-IP می‌گه برای هر سورس کشف‌شده، چند تا از اون ۵۰۰ پکت واقعاً رد شدن. سورسی که تو discover حدود ۱۰۰٪ موفق بوده ولی اینجا زیر ۱۰٪ → نشانه‌ی قوی DPI.

> ℹ️ دو طرف رو با همون `--proto` بزن — وگرنه listener پکت‌های TCP-SYN و ping رندومی که اتفاقی به ماشین می‌رسن رو هم اشتباهی شمارش می‌کنه.

## فایل‌های کانفیگ

هر ابزار فایل INI خودش رو از working directory می‌خونه:

| باینری       | فایل پیش‌فرض      | روی ماشین        |
| ------------ | ----------------- | ---------------- |
| `tg-scan`    | `tg-scan.conf`    | فرستنده          |
| `tg-listen`  | `tg-listen.conf`  | target           |

سه کلید توی هر دو فایل میان چون **باید بین دو طرف match باشن**:

```ini
udp_port = 54321
tcp_port = 54322
icmp_id  = 0x1234     # تو listener، صفر یعنی "any ID"
```

کلیدهای نشناخته بی‌سروصدا نادیده گرفته می‌شن — می‌تونی یه فایل ترکیبی نگه داری و با `-c` به هر دو ابزار بدی. هر فلگ CLI روی مقدار فایل override می‌کنه.

فایل‌های نمونه‌ی کامنت‌دار: [`tg-scan.conf`](tg-scan.conf) و [`tg-listen.conf`](tg-listen.conf).

## مرجع CLI

### `tg-scan`

```
Usage:
  tg-scan <discover|throughput> [options]

گزینه‌های مشترک:
  -c, --config <file>     فایل کانفیگ INI                          (پیش‌فرض: tg-scan.conf)
  -t, --target <ip>       IP مقصد (override کانفیگ)
  -r, --range <cidr>      CIDR سورس (تکرارشدنی، override کانفیگ)
  -p, --proto <list>      udp,tcp,icmp  یا  udp / tcp / icmp / all
      --udp-port <p>      پورت UDP مقصد                            (پیش‌فرض: 54321)
      --tcp-port <p>      پورت TCP مقصد                            (پیش‌فرض: 54322)
      --icmp-id <n>       شناسه‌ی ICMP echo                        (پیش‌فرض: 0x1234)
      --rate <pps>        محدودیت پکت در ثانیه، صفر = نامحدود
      --report <secs>     بازه‌ی نمایش پیشرفت                       (پیش‌فرض: 2.0)

فقط throughput:
      --size <bytes>      بایت payload در هر پکت (0..1400)          (پیش‌فرض: 1024)
      --count <N>         پکت در ازای هر سورس‌آی‌پی                  (پیش‌فرض: 100)
      --ips-file <file>   یک IP در هر خط، جایگزین --range
```

### `tg-listen`

```
Usage:
  tg-listen <discover|throughput> [options]

Options:
  -c, --config <file>     فایل کانفیگ INI                          (پیش‌فرض: tg-listen.conf)
  -p, --proto <list>      پروتکل‌های شمارش‌شدنی: udp,tcp,icmp / all  (پیش‌فرض: all)
      --udp-port <p>      فیلتر روی این پورت UDP                   (پیش‌فرض: 54321)
      --tcp-port <p>      فیلتر روی این پورت TCP (فقط SYN)         (پیش‌فرض: 54322)
      --icmp-id <n>       فیلتر روی این ICMP echo id، صفر = any    (پیش‌فرض: 0x1234)
      --report <secs>     بازه‌ی نمایش live                         (پیش‌فرض: 2.0)
      --top <N>           ردیف نمایش throughput live، صفر = همه    (پیش‌فرض: 10)
      --rcvbuf <bytes>    SO_RCVBUF                                 (پیش‌فرض: 16 MiB)
  -o, --output <file>     مسیر گزارش نهایی                          (پیش‌فرض: scan_report.txt)
```

## نحوه‌ی کار

**`tg-scan`** یه سوکت `AF_INET / SOCK_RAW / IPPROTO_RAW` باز می‌کنه، `IP_HDRINCL` رو فعال می‌کنه، و هر پکت رو از صفر می‌سازه — هدر IPv4 کامل با source address انتخاب‌شده، به اضافه‌ی segment پروتکل UDP / TCP-SYN / ICMP با checksum صحیح RFC-1071 (شامل pseudo-header برای TCP و UDP). کرنل فقط checksum خود IP رو می‌نویسه.

**`tg-listen`** سوکت `AF_PACKET / SOCK_RAW` باز می‌کنه و هر فریم اترنتی که کرنل تحویل می‌ده رو parse می‌کنه. فریم‌ها این فیلترها رو رد می‌کنن:

- IPv4 + پروتکل UDP / TCP / ICMP (محدود به bitmask فلگ `--proto`)
- TCP: فلگ SYN فعال، destination port با `tcp_port` match
- UDP: destination port با `udp_port` match
- ICMP: type 8 (Echo Request); شناسه با `icmp_id` match (یا هر شناسه‌ای وقتی `icmp_id == 0`)
- جهت: گزینه‌ی سوکت `PACKET_IGNORE_OUTGOING` (کرنل ≥ ۴٫۲۰)، با چک `sll_pkttype == PACKET_OUTGOING` تو userspace به‌عنوان fallback

فریم‌های باقی‌مونده تو یه hash map open-addressed با linear probing per-IP (تقریباً ۲۶ MiB per پروتکل) ثبت می‌شن. موقع گزارش، listener از map snapshot می‌گیره و بر اساس تعداد پکت مرتب می‌کنه.

## پیش‌نیازهای شبکه

پکت‌های اسپوف‌شده فقط وقتی به جایی می‌رسن که شبکه‌ی بین فرستنده و گیرنده فیلترشون نکنه. دو مانع رایج:

```bash
# اکثر distroها rp_filter=1 پیش‌فرض دارن — پکت اسپوف‌شده ورودی رو می‌کشه.
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0
sudo sysctl -w net.ipv4.conf.<interface-name>.rp_filter=0

# کرنل ممکنه به ICMP Echo Requestهای آدرس‌شده به IP اسپوف‌شده، خودش جواب اتومات بده.
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

اگه یه مسیر UDP / TCP رو تست می‌کنی و کرنل سمت گیرنده ICMP-unreachable یا TCP-RST به سورس اسپوف‌شده می‌فرسته، drop‌های عجیب تو شبکه‌ی فرستنده هم می‌بینی. اینا رو خفه کن:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
```

## نکات

- **`--proto` رو دو طرف یکی بزن.** اگه `tg-scan` فقط UDP می‌فرسته، `tg-listen ... -p udp` بزن — وگرنه listener ترافیک TCP-SYN و ICMP رندوم وسط wire رو هم اشتباهی قاطی می‌کنه.
- **`icmp_id` رو با دقت انتخاب کن** — مقدار `0x0001` همون چیزی که `/bin/ping` معمولی استفاده می‌کنه، با ping‌های عادی روی همون wire قاطی می‌شه. هر چی غیر از این (مثل `0x4321`، `0x7E5F`) اوکیه. پیش‌فرض `0x1234` برای اکثر setupها به اندازه‌ی کافی منحصربه‌فرده.
- **همیشه `--rate` رو ست کن** برای ران‌های جدی. حالت نامحدود همه‌ی queueهای بین تو و target رو پر می‌کنه و drop‌های ساختگی ایجاد می‌کنه که شبیه DPI به نظر می‌رسن ولی DPI نیستن.
- **`--size` رو زیر ۱۴۰۰ بایت نگه دار** تا فرگمنت IP رو مسیر MTU-1500 ایجاد نشه — فرگمنت رو DPI به‌صورت ناسازگار هندل می‌کنه.
- **throughput با TCP فقط SYN می‌فرسته**. نمی‌شه با سورس اسپوف‌شده یه کانکشن TCP واقعی برقرار کرد (SYN-ACK می‌ره به یکی دیگه)، پس شمارش throughput سمت TCP می‌گه چندتا SYN زنده موند — مفید برای رفتار stateful firewall، نه برای «throughput» به معنای واقعی.

## مسئولیت

این ابزار برای تحقیق و عملیات روی **زیرساختی که خودت مالکشی یا اجازه‌ی صریح برای تستش گرفتی** ساخته شده. فرستادن پکت با سورس اسپوف به سیستم‌هایی که کنترلشون نداری در بهترین حالت ناخوشاینده و توی خیلی از حوزه‌های قضایی غیرقانونیه. نکن.

## مجوز

MIT.
