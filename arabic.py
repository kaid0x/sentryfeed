"""Arabic presentation for /ar/learn. URLs, matching rules and counts remain shared.

Every catalogue topic must have a translation; translations are plain, escaped text.
Do not translate source records or imply that the linked English courses are Arabic.
"""
TOPICS = {
    'sql-injection': ('حقن SQL', 'تغيّر المدخلات أمر قاعدة البيانات بدلاً من التعامل معها كبيانات.'),
    'os-command-injection': ('حقن أوامر نظام التشغيل', 'تغيّر المدخلات أمراً ينفّذه الخادم عبر نظام التشغيل.'),
    'cross-site-scripting': ('البرمجة النصية عبر المواقع', 'يتحوّل محتوى غير موثوق إلى شيفرة تعمل في متصفح زائر آخر.'),
    'cross-site-request-forgery': ('تزوير الطلبات عبر المواقع', 'يخدع موقعٌ متصفحَ مستخدم مسجّل الدخول ليرسل طلباً غير مرغوب فيه إلى موقع آخر.'),
    'path-traversal': ('اجتياز المسارات', 'يتجاوز مسار ملف يقدّمه المستخدم حدود المجلد الذي يفترض أن يسمح التطبيق بالوصول إليه.'),
    'server-side-request-forgery': ('تزوير الطلبات من جهة الخادم', 'تدفع المدخلات الخادم إلى إرسال طلب إلى وجهة غير مقصودة.'),
    'xml-external-entities': ('الكيانات الخارجية في XML', 'يتبع محلّل XML مراجع إلى ملفات أو خدمات خارجية وردت في مستند غير موثوق.'),
    'unsafe-file-uploads': ('رفع ملفات غير آمنة', 'يقبل التطبيق نوعاً خطراً من الملفات قد يُنفّذ لاحقاً أو يُقدَّم للمستخدمين بطريقة غير آمنة.'),
    'insecure-deserialization': ('إلغاء التسلسل غير الآمن', 'قد تؤدي إعادة بناء الكائنات من بيانات محفوظة غير موثوقة إلى سلوك غير مقصود.'),
    'template-injection': ('حقن القوالب', 'تصبح المدخلات جزءاً من تعليمات قالب يُعالَج على الخادم.'),
    'authentication-weaknesses': ('ضعف التحقق من الهوية', 'لا يتحقق التطبيق بصورة موثوقة من أن المستخدم هو الشخص الذي يدّعي أنه هو.'),
    'authorization-weaknesses': ('ضعف التحقق من الصلاحيات', 'لا يتحقق التطبيق مما إذا كان يُسمح للمستخدم بالوصول إلى مورد أو تنفيذ إجراء.'),
    'missing-authentication': ('غياب التحقق من الهوية', 'يمكن الوصول إلى وظيفة حساسة دون إثبات هوية المستخدم.'),
    'http-request-smuggling': ('تهريب طلبات HTTP', 'تختلف الخوادم في تحديد نهاية الطلب، مما يسمح بتفسيره بطريقة غير متوقعة.'),
    'stack-buffer-overflow': ('تجاوز سعة المخزن المؤقت في المكدّس', 'تتجاوز عملية كتابة حدود مخزن مؤقت في المكدّس، وقد تستبدل بيانات مجاورة يستخدمها البرنامج.'),
    'heap-buffer-overflow': ('تجاوز سعة المخزن المؤقت في الكومة', 'تتجاوز عملية كتابة حدود مساحة محجوزة في ذاكرة الكومة، وقد تتلف البيانات المجاورة.'),
    'out-of-bounds-write': ('الكتابة خارج الحدود', 'يكتب البرنامج خارج منطقة الذاكرة المسموح له باستخدامها.'),
    'integer-overflow-or-underflow': ('تجاوز نطاق الأعداد الصحيحة', 'تتجاوز نتيجة عملية حسابية نطاق نوع العدد، مما قد ينتج عنه حساب أحجام أو إجراء تحققات بصورة خاطئة.'),
    'integer-conversion-errors': ('أخطاء تحويل الأعداد الصحيحة', 'يغيّر تحويل حجم العدد أو طريقة تمثيل إشارته معناه في عملية حسابية تؤثر في الأمان.'),
    'type-confusion': ('الخلط بين الأنواع', 'يتعامل البرنامج مع كائن على أنه من نوع آخر، فيستخدم محتوياته بصورة خاطئة.'),
    'uninitialized-data': ('بيانات غير مهيّأة', 'يستخدم البرنامج الذاكرة قبل تعيين القيمة المطلوبة فيها.'),
    'race-conditions': ('حالات التسابق', 'تغيّر عملية أخرى حالة مشتركة بين التحقق منها وتنفيذ الإجراء الذي يعتمد عليها.'),
    'use-after-free': ('الاستخدام بعد التحرير', 'يستخدم البرنامج الذاكرة بعد تحريرها، حين قد تكون محتوياتها قد خُصّصت لغرض آخر.'),
    'uncontrolled-format-strings': ('سلاسل تنسيق غير منضبطة', 'تتحوّل مدخلات غير موثوقة إلى تعليمات تنسيق قد تقرأ ذاكرة البرنامج أو تغيّرها.'),
}
KINDS = {'Reading and practice labs': 'قراءة ومختبرات تدريبية',
         'Video course': 'دورة فيديو', 'Practice labs': 'مختبرات تدريبية'}
PREPARATION = {
    'Free account for labs. Basic HTTP knowledge; some labs use Burp Suite.':
        'تحتاج المختبرات إلى حساب مجاني ومعرفة أساسية ببروتوكول HTTP. يستخدم بعضها أداة Burp Suite.',
    'Free course. C programming and memory concepts are useful; covers several weakness types.':
        'دورة مجانية تغطي عدة أنواع من نقاط الضعف. تفيدك معرفة البرمجة بلغة C ومفاهيم الذاكرة.',
    'Free account. Requires C, pointers and basic binary exploitation; begin with Freebie (Easy).':
        'تحتاج إلى حساب مجاني ومعرفة بلغة C والمؤشرات وأساسيات استغلال البرامج الثنائية. ابدأ بتمرين Freebie (Easy).',
    'Free account. Advanced: C, assembly and binary exploitation experience are useful.':
        'تحتاج إلى حساب مجاني. المستوى متقدم؛ تفيدك الخبرة بلغة C ولغة التجميع واستغلال البرامج الثنائية.',
}
GROUPS = {'Intel': 'الأخبار والتحليل', 'Tools': 'الأدوات', 'Community': 'المجتمع'}
PAGES = {'feed': 'الأخبار', 'map': 'الخريطة', 'stocks': 'الأسهم', 'stack': 'تقنياتي',
         'vulns': 'الثغرات', 'patch': 'أولوية التحديثات', 'vendors': 'سجل المورّدين',
         'ransomware': 'إحصاءات برمجيات الفدية', 'digest': 'الملخص الأسبوعي',
         'gulf': 'نبض الأمن السيبراني في الخليج', 'password': 'فحص كلمة المرور',
         'scan': 'فحص الملفات والروابط', 'headers': 'تحليل ترويسات البريد',
         'domain': 'فحص النطاق', 'learn': 'تعلّم من الأخبار', 'events': 'الفعاليات',
         'submit': 'إضافة فعالية'}
FOOTER = {'How it works': 'كيف يعمل الموقع', 'Sources': 'المصادر', 'Code': 'الشيفرة',
          'RSS feeds': 'خلاصات RSS', 'Built by Haseeb': 'من تطوير حسيب'}
MONTHS = ('يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو', 'يوليو', 'أغسطس', 'سبتمبر', 'أكتوبر', 'نوفمبر', 'ديسمبر')
DAYS = ('الاثنين', 'الثلاثاء', 'الأربعاء', 'الخميس', 'الجمعة', 'السبت', 'الأحد')


def date_label(value):
    return f'{DAYS[value.weekday()]} {value.day} {MONTHS[value.month - 1]} {value.year}'


def navigation(nav):
    return [(GROUPS[group], [(PAGES[key] + ('' if key == 'learn' else ' (بالإنجليزية)'),
                              '/ar/learn' if key == 'learn' else href, key)
                             for _, href, key in links]) for group, links in nav]


def learning(data):
    # Copy rather than mutate data shared with English rendering or cached stories.
    result = dict(data)
    result['topics'] = [dict(topic, title=TOPICS[topic['slug']][0]) for topic in data['topics']]
    result['catalogue'] = [dict(topic, title=TOPICS[topic['slug']][0],
                               explanation=TOPICS[topic['slug']][1], kind=KINDS[topic['kind']],
                               preparation=PREPARATION[topic['preparation']],
                               video=topic['kind'] == 'Video course') for topic in data['catalogue']]
    return result
