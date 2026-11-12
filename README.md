<div dir="rtl">

# مختبر صيد التهديدات SOC

مختبر عملي لمحللي مراكز العمليات الأمنية (SOC): تحقيق في سجلات هجمات حقيقية من أنظمة ويندوز وحركة الشبكة، باستخدام أدوات الصيد والكشف المستخدمة في الميدان.

يعمل بالكامل من المتصفح عبر **GitHub Codespaces**، بدون تثبيت أي برنامج.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/cybers-sa/soc-hunting-lab?hide_repo_select=true&ref=main&geo=EuropeWest&machine=basicLinux32gb)

## التشغيل

1. اضغط زر **Open in GitHub Codespaces**.
2. تأكد من الإعدادات: **Region: Europe West** و **Machine type: 2-core**، ثم اضغط **Create codespace**.
3. انتظر حتى تظهر في الطرفية رسالة **SOC Hunting Lab is ready** (من 3 إلى 8 دقائق في المرة الأولى).
4. افتح رابط **SOC Dashboard** الظاهر في الطرفية، أو من تبويب **Ports** افتح المنفذ **8000**.
   إذا ظهر الخطأ **HTTP ERROR 401**: من تبويب **Ports** اضغط بالزر الأيمن على المنفذ 8000، ثم **Port Visibility** ← **Public**.
5. اختر القضية واضغط **Analyze Evidence**.

## لوحة التحكم

كل العمل يتم من لوحة التحكم، بدون أوامر:

| التبويب | الاستخدام |
| --- | --- |
| **Overview** | توزيع التنبيهات حسب الخطورة، الخط الزمني للهجوم، أكثر القواعد تنبيهًا، الأجهزة وأرقام الأحداث |
| **Hayabusa Alerts** | جدول التنبيهات مع التصفية حسب الخطورة والبحث وتفاصيل كل حدث |
| **Sigma Detections** | الأحداث المطابقة لقواعد Sigma |
| **Raw Events** | كل أحداث السجل مع البحث والتصفية حسب رقم الحدث |
| **DNS / Connections / Zeek Logs** | سجلات Zeek لقضايا الشبكة |
| **Investigation** | السيناريو، والإجابة عن الأسئلة، وكتابة تقرير الحادثة وتحميله |

الإجابات والتقرير تُحفظ تلقائيًا.

### تحليل ملفاتك

اضغط **+ New Case**، واكتب عنوان القضية، وارفع ملفات `.evtx` أو `.pcap` أو `.pcapng`، ثم **Create and Analyze**. تظهر القضية تحت **My Cases**.

استخدم بيانات المختبرات وتحديات CTF فقط، ولا ترفع سجلات من بيئة عمل حقيقية.

## الأدوات

| الأداة | الاستخدام |
| --- | --- |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | بناء خط زمني للتنبيهات من سجلات ويندوز |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | الصيد بقواعد Sigma، والبحث في السجلات وعرضها |
| [Sigma](https://github.com/SigmaHQ/sigma) | قواعد الكشف المفتوحة |
| [Zeek](https://zeek.org) | تحليل حركة الشبكة من ملفات PCAP |

## الأوامر (اختياري)

| الأمر | الوظيفة |
| --- | --- |
| `dashboard` | تشغيل لوحة التحكم على المنفذ 8000 |
| `hunt cases/case-01` | تشغيل Hayabusa و Chainsaw على أدلة القضية، والنتائج في مجلد `results` |
| `chainsaw dump <file.evtx> -q \| less` | عرض أحداث السجل كاملة |
| `chainsaw search "<كلمة>" <folder> -q` | البحث عن كلمة داخل السجلات |
| `zeek-run <file.pcap>` | تحليل ملف PCAP وإخراج سجلات Zeek |
| `cat dns.log \| zeek-cut <columns>` | استخراج أعمدة محددة من سجلات Zeek |

## القضايا

| القضية | الموضوع | المستوى | الأدلة |
| --- | --- | --- | --- |
| [01](cases/case-01/README.md) | مسح الأثر | مبتدئ | Security |
| [02](cases/case-02/README.md) | تخمين كلمات المرور | مبتدئ | Security (DC) |
| [03](cases/case-03/README.md) | تنفيذ عن بُعد | متوسط | Sysmon |
| [04](cases/case-04/README.md) | باب خلفي في شاشة الدخول | متوسط | Sysmon |
| [05](cases/case-05/README.md) | تفريغ ذاكرة عملية | متوسط | Sysmon |
| [06](cases/case-06/README.md) | سرقة بيانات الدومين | متقدم | Security (DC) |
| [07](cases/case-07/README.md) | قناة تحكم مخفية | متقدم | PCAP |

## مخرجات كل قضية

لكل قضية، اكتب تقرير حادثة مختصر يتضمن:

- ملخص ما حدث
- الجهاز والحساب المتأثر
- الخط الزمني (بتوقيت UTC)
- تقنيات MITRE ATT&CK
- مؤشرات الاختراق (IOCs)
- التوصيات

## الإيقاف

من [github.com/codespaces](https://github.com/codespaces) أوقف الـ Codespace بعد كل جلسة.

## مصادر البيانات

- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK)

</div>
