"""Work out which countries a story is about, for the map.

Each story gets two lists of ISO country codes:

- where: where it happened, i.e. the country of the victims or targets.
- blamed: who the story blames. A country counts as blamed when it's attached to
  attacker wording ("Chinese hackers", "Russia-linked group", "backed by Iran") or
  when the story names a group publicly tied to it (Lazarus -> North Korea).
  This is what the reporting claims, not proven attribution.

Every other country mentioned counts as where it happened. Only the title and the
first two sentences of the summary are read, because later sentences tend to
mention countries in passing (where a researcher is based, past incidents).

Run `python geo.py` to print what it finds in your database.
"""
import re

# (code, name shown on the map, names and other ways of referring to the country,
#  adjectives). Matching is case-sensitive, since country names are always
# capitalised: "US" isn't "us", "Polish" isn't "polish", "China" isn't "china".
# Names that are usually something else in tech news (Georgia the US state,
# Jordan, Chad) are left out on purpose.
COUNTRIES = [
    ("US", "United States", ["United States", "USA", "US", "U.S.", "U.S.A.", "America", "Washington"], ["American"]),
    ("GB", "United Kingdom", ["United Kingdom", "UK", "U.K.", "Britain", "Great Britain", "England", "Scotland", "Wales", "London"], ["British", "English", "Scottish", "Welsh"]),
    ("CN", "China", ["China", "PRC", "People's Republic of China", "Beijing", "Shanghai"], ["Chinese"]),
    ("RU", "Russia", ["Russia", "Russian Federation", "Moscow", "Kremlin"], ["Russian"]),
    ("KP", "North Korea", ["North Korea", "DPRK", "Pyongyang"], ["North Korean"]),
    ("KR", "South Korea", ["South Korea", "Korea", "ROK", "Seoul"], ["South Korean", "Korean"]),
    ("IR", "Iran", ["Iran", "Tehran"], ["Iranian"]),
    ("IL", "Israel", ["Israel", "Tel Aviv"], ["Israeli"]),
    ("PS", "Palestine", ["Palestine", "Gaza", "West Bank"], ["Palestinian"]),
    ("UA", "Ukraine", ["Ukraine", "Kyiv", "Kiev"], ["Ukrainian"]),
    ("BY", "Belarus", ["Belarus", "Minsk"], ["Belarusian"]),
    ("AE", "United Arab Emirates", ["United Arab Emirates", "UAE", "U.A.E.", "Emirates", "Dubai", "Abu Dhabi"], ["Emirati"]),
    ("SA", "Saudi Arabia", ["Saudi Arabia", "Riyadh", "KSA"], ["Saudi"]),
    ("QA", "Qatar", ["Qatar", "Doha"], ["Qatari"]),
    ("KW", "Kuwait", ["Kuwait"], ["Kuwaiti"]),
    ("BH", "Bahrain", ["Bahrain"], ["Bahraini"]),
    ("OM", "Oman", ["Oman"], ["Omani"]),
    ("YE", "Yemen", ["Yemen"], ["Yemeni"]),
    ("IQ", "Iraq", ["Iraq", "Baghdad"], ["Iraqi"]),
    ("SY", "Syria", ["Syria", "Damascus"], ["Syrian"]),
    ("LB", "Lebanon", ["Lebanon", "Beirut"], ["Lebanese"]),
    ("TR", "Turkey", ["Turkey", "Türkiye", "Turkiye", "Ankara", "Istanbul"], ["Turkish"]),
    ("EG", "Egypt", ["Egypt", "Cairo"], ["Egyptian"]),
    ("PK", "Pakistan", ["Pakistan", "Islamabad"], ["Pakistani"]),
    ("IN", "India", ["India", "New Delhi", "Mumbai", "Bengaluru", "Bangalore"], ["Indian"]),
    ("BD", "Bangladesh", ["Bangladesh", "Dhaka"], ["Bangladeshi"]),
    ("LK", "Sri Lanka", ["Sri Lanka"], ["Sri Lankan"]),
    ("NP", "Nepal", ["Nepal"], ["Nepalese", "Nepali"]),
    ("AF", "Afghanistan", ["Afghanistan", "Kabul"], ["Afghan"]),
    ("KZ", "Kazakhstan", ["Kazakhstan"], ["Kazakh"]),
    ("UZ", "Uzbekistan", ["Uzbekistan"], ["Uzbek"]),
    ("JP", "Japan", ["Japan", "Tokyo"], ["Japanese"]),
    ("TW", "Taiwan", ["Taiwan", "Taipei"], ["Taiwanese"]),
    ("HK", "Hong Kong", ["Hong Kong"], []),
    ("MO", "Macau", ["Macau", "Macao"], []),
    ("MN", "Mongolia", ["Mongolia"], ["Mongolian"]),
    ("VN", "Vietnam", ["Vietnam", "Viet Nam", "Hanoi"], ["Vietnamese"]),
    ("TH", "Thailand", ["Thailand", "Bangkok"], ["Thai"]),
    ("KH", "Cambodia", ["Cambodia", "Phnom Penh"], ["Cambodian"]),
    ("LA", "Laos", ["Laos"], ["Laotian"]),
    ("MM", "Myanmar", ["Myanmar", "Burma"], ["Burmese"]),
    ("MY", "Malaysia", ["Malaysia", "Kuala Lumpur"], ["Malaysian"]),
    ("SG", "Singapore", ["Singapore"], ["Singaporean"]),
    ("ID", "Indonesia", ["Indonesia", "Jakarta"], ["Indonesian"]),
    ("PH", "Philippines", ["Philippines", "Manila"], ["Philippine", "Filipino"]),
    ("AU", "Australia", ["Australia", "Sydney", "Melbourne", "Canberra"], ["Australian"]),
    ("NZ", "New Zealand", ["New Zealand"], []),
    ("CA", "Canada", ["Canada", "Ottawa", "Toronto"], ["Canadian"]),
    ("MX", "Mexico", ["Mexico"], ["Mexican"]),
    ("BR", "Brazil", ["Brazil"], ["Brazilian"]),
    ("AR", "Argentina", ["Argentina"], ["Argentine", "Argentinian"]),
    ("CL", "Chile", ["Chile"], ["Chilean"]),
    ("CO", "Colombia", ["Colombia"], ["Colombian"]),
    ("PE", "Peru", ["Peru"], ["Peruvian"]),
    ("VE", "Venezuela", ["Venezuela"], ["Venezuelan"]),
    ("CU", "Cuba", ["Cuba"], ["Cuban"]),
    ("EC", "Ecuador", ["Ecuador"], ["Ecuadorian"]),
    ("CR", "Costa Rica", ["Costa Rica"], ["Costa Rican"]),
    ("PA", "Panama", ["Panama"], ["Panamanian"]),
    ("FR", "France", ["France", "Paris"], ["French"]),
    ("DE", "Germany", ["Germany", "Berlin"], ["German"]),
    ("IT", "Italy", ["Italy", "Rome"], ["Italian"]),
    ("ES", "Spain", ["Spain", "Madrid"], ["Spanish"]),
    ("PT", "Portugal", ["Portugal", "Lisbon"], ["Portuguese"]),
    ("NL", "Netherlands", ["Netherlands", "Holland", "Amsterdam"], ["Dutch"]),
    ("BE", "Belgium", ["Belgium", "Brussels"], ["Belgian"]),
    ("LU", "Luxembourg", ["Luxembourg"], []),
    ("CH", "Switzerland", ["Switzerland", "Geneva", "Zurich"], ["Swiss"]),
    ("AT", "Austria", ["Austria", "Vienna"], ["Austrian"]),
    ("IE", "Ireland", ["Ireland", "Dublin"], ["Irish"]),
    ("DK", "Denmark", ["Denmark", "Copenhagen"], ["Danish"]),
    ("NO", "Norway", ["Norway", "Oslo"], ["Norwegian"]),
    ("SE", "Sweden", ["Sweden", "Stockholm"], ["Swedish"]),
    ("FI", "Finland", ["Finland", "Helsinki"], ["Finnish"]),
    ("IS", "Iceland", ["Iceland"], ["Icelandic"]),
    ("EE", "Estonia", ["Estonia"], ["Estonian"]),
    ("LV", "Latvia", ["Latvia"], ["Latvian"]),
    ("LT", "Lithuania", ["Lithuania"], ["Lithuanian"]),
    ("PL", "Poland", ["Poland", "Warsaw"], ["Polish"]),
    ("CZ", "Czechia", ["Czechia", "Czech Republic", "Prague"], ["Czech"]),
    ("SK", "Slovakia", ["Slovakia"], ["Slovak"]),
    ("HU", "Hungary", ["Hungary", "Budapest"], ["Hungarian"]),
    ("RO", "Romania", ["Romania", "Bucharest"], ["Romanian"]),
    ("BG", "Bulgaria", ["Bulgaria"], ["Bulgarian"]),
    ("GR", "Greece", ["Greece", "Athens"], ["Greek"]),
    ("CY", "Cyprus", ["Cyprus"], ["Cypriot"]),
    ("MT", "Malta", ["Malta"], ["Maltese"]),
    ("RS", "Serbia", ["Serbia", "Belgrade"], ["Serbian"]),
    ("HR", "Croatia", ["Croatia"], ["Croatian"]),
    ("SI", "Slovenia", ["Slovenia"], ["Slovenian"]),
    ("BA", "Bosnia and Herzegovina", ["Bosnia"], ["Bosnian"]),
    ("AL", "Albania", ["Albania"], ["Albanian"]),
    ("MK", "North Macedonia", ["North Macedonia"], []),
    ("MD", "Moldova", ["Moldova"], ["Moldovan"]),
    ("AM", "Armenia", ["Armenia"], ["Armenian"]),
    ("AZ", "Azerbaijan", ["Azerbaijan"], ["Azerbaijani"]),
    ("ZA", "South Africa", ["South Africa"], ["South African"]),
    ("NG", "Nigeria", ["Nigeria", "Lagos"], ["Nigerian"]),
    ("KE", "Kenya", ["Kenya", "Nairobi"], ["Kenyan"]),
    ("ET", "Ethiopia", ["Ethiopia"], ["Ethiopian"]),
    ("GH", "Ghana", ["Ghana"], ["Ghanaian"]),
    ("MA", "Morocco", ["Morocco"], ["Moroccan"]),
    ("DZ", "Algeria", ["Algeria"], ["Algerian"]),
    ("TN", "Tunisia", ["Tunisia"], ["Tunisian"]),
    ("LY", "Libya", ["Libya"], ["Libyan"]),
    ("SD", "Sudan", ["Sudan"], ["Sudanese"]),
    ("UG", "Uganda", ["Uganda"], ["Ugandan"]),
    ("TZ", "Tanzania", ["Tanzania"], ["Tanzanian"]),
    ("RW", "Rwanda", ["Rwanda"], ["Rwandan"]),
    ("SN", "Senegal", ["Senegal"], ["Senegalese"]),
    ("CI", "Ivory Coast", ["Ivory Coast", "Côte d'Ivoire", "Cote d'Ivoire"], ["Ivorian"]),
    ("CM", "Cameroon", ["Cameroon"], ["Cameroonian"]),
    ("ZW", "Zimbabwe", ["Zimbabwe"], ["Zimbabwean"]),
    ("ZM", "Zambia", ["Zambia"], ["Zambian"]),
    ("AO", "Angola", ["Angola"], ["Angolan"]),
    ("MZ", "Mozambique", ["Mozambique"], []),
]

NAMES = {code: name for code, name, _, _ in COUNTRIES}

# Groups that governments or major security firms publicly tie to a country.
# Microsoft names state groups by weather, one word per country, so any
# "<Word> Typhoon" is China, "<Word> Blizzard" Russia and so on.
GROUP_COUNTRY = [
    (r"[A-Z][a-z]+ Typhoon|APT ?(?:1|3|10|15|17|27|31|40|41)|Hafnium|Mustang Panda|"
     r"UNC3886|UNC5221|Storm-0558|Winnti|BlackTech", "CN"),
    (r"[A-Z][a-z]+ Blizzard|APT ?(?:28|29|44)|Fancy Bear|Cozy Bear|Sandworm|Turla|Gamaredon|"
     r"Nobelium|Callisto|Cold River|Ember Bear|Primitive Bear|Berserk Bear", "RU"),
    (r"[A-Z][a-z]+ Sleet|Lazarus(?: Group)?|Kimsuky|Andariel|BlueNoroff|ScarCruft|"
     r"APT ?(?:37|38|43|45)|Famous Chollima|TraderTraitor|Konni", "KP"),
    (r"[A-Z][a-z]+ Sandstorm|APT ?(?:33|34|35|39|42)|Charming Kitten|MuddyWater|OilRig|"
     r"Imperial Kitten|CyberAv3ngers|Agrius|Pioneer Kitten|Fox Kitten", "IR"),
    (r"APT ?36|Transparent Tribe|SideCopy", "PK"),
    (r"Patchwork (?:APT|group|hackers)|SideWinder|Bitter APT", "IN"),
    (r"APT ?32|OceanLotus", "VN"),
    (r"Ghostwriter|UNC1151", "BY"),
]

GROUPS = "|".join(pattern for pattern, _ in GROUP_COUNTRY)
# Intelligence and military agencies: "Russia's GRU", "China's MSS".
AGENCIES = r"GRU|FSB|SVR|MSS|IRGC|MOIS|RGB|PLA|Unit \d{4,5}"
# Tracking codes that sit between a country and an attacker word:
# "Chinese APT41 hackers", "China-aligned TA419", "Russia-linked UAC-0099".
CODES = r"[A-Z][A-Za-z]*-?\d+|[A-Z]{2,}[A-Z0-9]*"
# At most one name or code may sit in between. It has to look like one, so a
# headline's ordinary capitalised words don't count: "Denmark Says Attackers..."
BETWEEN = rf"(?:(?:{GROUPS}|{AGENCIES}|{CODES})\s+)?"

# Words that make a country the one being blamed when they follow it:
# "Chinese hackers", "Russian state-sponsored threat actors", "North Korean IT workers".
ACTOR = (
    r"(?:(?:state|government|military|nation)(?:[- ](?:sponsored|backed|linked|aligned))? |"
    r"(?:military|intelligence|cyber|cyberespionage|espionage|ransomware|cybercrime|hacking|scam) )?"
    r"(?:hackers?|hacktivists?|hacking (?:group|crew|team|unit)s?|apts?|threat (?:actors?|groups?|clusters?)|"
    r"(?:cyber ?)?(?:spies|criminals|crooks)|cybercriminals?|spy (?:agency|agencies)|operatives|"
    r"(?:it|tech) workers|attackers|cyber ?(?:army|units?|actors?)|gangs?|crews?|cybercrime forums?)"
)
# Weaker words that only count after an adjective ("Russian cyberattacks"), since
# after a noun they usually describe the victim ("US hospital attacks").
ACTOR_AFTER_ADJECTIVE = (
    r"(?:cyber ?attacks?|attacks?|malware|espionage|intrusions?|disinformation|"
    r"(?:espionage|phishing|hacking|influence|malware|disinformation|cyber|ransomware) (?:campaigns?|operations?))"
)
# Joined to a country these tie it to an attack ("China-linked", "Iran-backed"), but
# only when attacker wording follows: "U.K.-linked academics" are not attackers.
LINKED = r"(?:linked|backed|aligned|nexus|sponsored|affiliated|speaking|based)"
AFTER_LINKED = (
    rf"(?:{GROUPS}|{AGENCIES}|{CODES}|"
    rf"(?:[\w-]+\s+){{0,2}}?(?i:{ACTOR}|{ACTOR_AFTER_ADJECTIVE}|groups?|clusters?|actors?|"
    r"campaigns?|operations?|activity|intrusion sets?|threats?))"
)
# Phrases that name a country without it being where anything happened, blanked
# out first: CISA is a US agency, but a CISA warning isn't a US incident.
NOT_A_PLACE = re.compile(
    r"(?:the )?U\.?S\.? (?:Cybersecurity and Infrastructure Security Agency|CISA)|"
    r"U\.?S\.? [Ff]ederal (?:[Cc]ivilian )?agencies|Federal Civilian Executive Branch|"
    r"Pwn2Own \w+"
)


def _alternation(words):
    """Longest first, so "North Korean" wins over "Korean"."""
    return "|".join(re.escape(w) for w in sorted(set(words), key=len, reverse=True))


# The people of a country also count: "Americans", "Israelis".
for _, _, nouns, adjectives in COUNTRIES:
    nouns += [a + "s" for a in adjectives if a.endswith(("an", "i"))]

_LOOKUP = {}          # lowercased mention -> country code
for code, _, nouns, adjectives in COUNTRIES:
    for w in nouns + adjectives:
        _LOOKUP[w.lower()] = code

_ANY = _alternation(w for _, _, nouns, adjectives in COUNTRIES for w in nouns + adjectives)
_ADJ = _alternation(a for _, _, _, adjectives in COUNTRIES for a in adjectives)
# "Latin America", "North America", "South America", "Bank of America" are not the US.
_NOT_US = r"(?<!Latin )(?<!North )(?<!South )(?<!Central )(?<!Bank of )"

# Word boundaries that also work next to "U.S." and "U.K.", where \b doesn't.
_B, _E = r"(?<![\w.])", r"(?![\w])"

MENTION_RE = re.compile(rf"{_B}{_NOT_US}(?P<c>{_ANY}){_E}")
_POSSESSIVE = r"(?:['’]s)?"
BLAMED_RES = [
    # "Chinese hackers", "North Korea's IT workers", "Russian GRU hackers"
    re.compile(rf"{_B}{_NOT_US}(?P<c>{_ANY}){_POSSESSIVE}\s+{BETWEEN}(?i:{ACTOR}){_E}"),
    # "Russian cyberattacks", "Iranian espionage campaign"
    re.compile(rf"{_B}(?P<c>{_ADJ})\s+{BETWEEN}(?i:{ACTOR_AFTER_ADJECTIVE}){_E}"),
    # "China-linked TA419", "Iran-backed hackers", "China-nexus espionage campaign"
    re.compile(rf"{_B}{_NOT_US}(?P<c>{_ANY})[- ](?i:{LINKED})\s+{AFTER_LINKED}{_E}"),
    # "Russia's Star Blizzard", "China's MSS", "Kremlin-backed Sandworm"
    re.compile(rf"{_B}{_NOT_US}(?P<c>{_ANY}){_POSSESSIVE}(?:[- ](?i:{LINKED}))?\s+(?:{GROUPS}|{AGENCIES})\b"),
    # "linked to China", "attributed to Russian state hackers", "backed by Iran"
    re.compile(rf"(?i:\b(?:linked to|attributed to|traced (?:back )?to|blamed on|backed by|sponsored by|"
               rf"working for|on behalf of)\s+(?:the\s+)?){_NOT_US}(?P<c>{_ANY}){_E}"),
]
GROUP_RES = [(re.compile(rf"\b(?:{pattern})\b"), code) for pattern, code in GROUP_COUNTRY]

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'])")


def _code(mention):
    return _LOOKUP.get(mention.lower())


def text_for(item):
    """The title plus the first two sentences of the summary."""
    sentences = _SENTENCE_END.split((item.get("summary") or "").strip())
    return f"{item['title']}. {' '.join(sentences[:2])}"


def explain(item):
    """Returns (where, blamed, reasons): sorted country codes, plus the words that
    made each blamed country blamed, for checking the rules."""
    text = NOT_A_PLACE.sub(lambda m: " " * len(m.group(0)), text_for(item))
    reasons, spans = {}, []
    for regex in BLAMED_RES:
        for m in regex.finditer(text):
            code = _code(m.group("c"))
            if code:
                reasons.setdefault(code, m.group(0))
                spans.append(m.span())
    for regex, code in GROUP_RES:
        m = regex.search(text)
        if m:
            reasons.setdefault(code, m.group(0))

    # Blank out the blaming phrases, then every country still mentioned is where
    # it happened. A country can be both: "Russian hackers hit Russian banks".
    chars = list(text)
    for start, end in spans:
        chars[start:end] = " " * (end - start)
    where = {_code(m.group("c")) for m in MENTION_RE.finditer("".join(chars))} - {None}
    return sorted(where), sorted(reasons), reasons


def locate(item):
    """Returns (where, blamed): sorted lists of country codes."""
    where, blamed, _ = explain(item)
    return where, blamed


def main():
    """Print what the map would show for the last 14 days."""
    from app import load_items_ungrouped

    items = [i for i in load_items_ungrouped(14) if i["severity"] in ("red", "orange", "yellow")]
    placed = 0
    for item in items:
        where, blamed, reasons = explain(item)
        if not (where or blamed):
            continue
        placed += 1
        print(f"[{item['source']}] {item['title']}")
        print(f"    where: {', '.join(NAMES[c] for c in where) or '-'}")
        for code in blamed:
            print(f"    blamed: {NAMES[code]}  (\"{' '.join(reasons[code].split())}\")")
    print(f"\n{placed} of {len(items)} security stories name a country.")


if __name__ == "__main__":
    main()
