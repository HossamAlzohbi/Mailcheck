"""PDF report generation for scan results.

The report is written in Norwegian because it is meant for the
business owner, not for a technical audience. Fix instructions
include the actual DNS values so the report stands on its own.
"""

from datetime import date

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)

# Colour coding for the three-level verdict shown to the customer.
VERDICT_COLOURS = {
    "ok": colors.HexColor("#1a7f37"),
    "warn": colors.HexColor("#bf8700"),
    "bad": colors.HexColor("#c62828"),
}

VERDICT_LABELS = {
    "ok": "I ORDEN",
    "warn": "BØR UTBEDRES",
    "bad": "KRITISK",
}

# Maps internal status values to a customer-facing verdict level.
SPF_VERDICT = {
    "enforcing": "ok",
    "weak": "warn",
    "broken": "bad",
    "missing": "bad",
    "error": "warn",
}

DMARC_VERDICT = {
    "enforcing": "ok",
    "partial": "warn",
    "weak": "bad",
    "broken": "bad",
    "missing": "bad",
    "error": "warn",
}

DKIM_VERDICT = {
    "found": "ok",
    "not_found": "warn",
}

# Plain-Norwegian explanations. Keyed by status so the report never
# shows raw jargon to a non-technical reader.
SPF_TEXT = {
    "enforcing": (
        "Dere har en liste over hvem som har lov til å sende e-post i "
        "deres navn, og den avviser alle andre. Dette er riktig satt opp."
    ),
    "weak": (
        "Dere har en liste over godkjente avsendere, men den sier at "
        "e-post fra andre skal leveres likevel. I praksis stopper den "
        "ingenting."
    ),
    "broken": (
        "Oppsettet finnes, men er ufullstendig og har ingen praktisk "
        "virkning."
    ),
    "missing": (
        "Det finnes ingen liste over hvem som har lov til å sende "
        "e-post i deres navn. Hvem som helst kan sende e-post som ser "
        "ut som den kommer fra dere."
    ),
    "error": (
        "Vi klarte ikke å hente dette oppsettet. Det kan skyldes en "
        "midlertidig feil, og bør sjekkes på nytt."
    ),
}

DMARC_TEXT = {
    "enforcing": (
        "Dere har bestemt at forfalsket e-post i deres navn skal "
        "avvises. Dette er riktig satt opp."
    ),
    "partial": (
        "Dere har en regel på plass, men den stopper ikke forfalsket "
        "e-post helt. Den kan fortsatt nå frem til mottakeren."
    ),
    "weak": (
        "Dere har en regel, men den sier bare at forfalskninger skal "
        "registreres, ikke stoppes. E-post som utgir seg for å komme "
        "fra dere leveres som normalt."
    ),
    "broken": (
        "Regelen finnes, men mangler innhold og har ingen virkning."
    ),
    "missing": (
        "Dere har ingen regel for hva som skal skje med forfalsket "
        "e-post. Det betyr at svindel-e-post i deres navn leveres "
        "til kunder og leverandører uten hindring."
    ),
    "error": (
        "Vi klarte ikke å hente dette oppsettet. Det bør sjekkes "
        "på nytt."
    ),
}

DKIM_TEXT = {
    "found": (
        "E-posten deres signeres digitalt, slik at mottakeren kan "
        "bekrefte at den er ekte og ikke endret underveis."
    ),
    "not_found": (
        "Vi fant ingen digital signatur på e-posten deres blant de "
        "vanligste oppsettene. Merk at dette ikke er et endelig bevis "
        "på at signering mangler, men det bør bekreftes."
    ),
}


def dmarc_description(row):
    """
    Pick the right explanation for a partial DMARC policy.

    "partial" covers three different problems, and telling a customer
    the wrong one is worse than saying nothing.
    """
    status = row["dmarc_status"]

    if status != "partial":
        return DMARC_TEXT.get(status, "")

    if row.get("dmarc_subdomain") == "none":
        return (
            "Domenet deres er beskyttet, men underdomener er unntatt. "
            "En angriper kan forfalske e-post fra et underdomene i "
            "stedet, og oppnå det samme."
        )

    pct = row.get("dmarc_pct")
    if pct and pct < 100:
        return (
            f"Regelen gjelder bare {pct} prosent av e-posten deres. "
            "Resten behandles som om dere ikke hadde noen regel."
        )

    return (
        "Forfalsket e-post i deres navn sendes til søppelpost, men "
        "avvises ikke. Mottakeren kan fortsatt finne den og åpne den "
        "i god tro."
    )


def dmarc_steps(row, domain):
    """
    Concrete DMARC remediation, staged.

    Going straight to p=reject on a domain that has never been
    monitored can block the company's own mail, so the advice is
    always to measure first and tighten afterwards.
    """
    rua_domain = row.get("dmarc_rua_domain", "")
    has_rua = row.get("dmarc_reporting") == "yes"

    # Reports may go to a third party: a DMARC vendor the company pays
    # for, or the hosting provider that set the record up. We cannot
    # tell which from DNS, so we flag it rather than assume.
    external_rua = bool(rua_domain) and not rua_domain.endswith(domain)

    if external_rua:
        rua_step = (
            "Rapportene sendes i dag til en ekstern part "
            f"(<b>{rua_domain}</b>), ikke til dere. Bekreft at dere "
            "har tilgang til dem, eller legg til deres egen adresse:",
            f"rua=mailto:dmarc@{rua_domain}, mailto:dmarc@{domain}",
            "Uten tilgang til rapportene har dere ingen oversikt over "
            "forsøk på misbruk, og ingen måte å vite om egne systemer "
            "blir stoppet når regelen strammes inn.",
        )
    else:
        rua_step = (
            "Legg inn en rapportadresse i samme oppføring, slik at dere "
            "faktisk ser hvem som sender e-post i deres navn:",
            f"rua=mailto:dmarc@{domain}",
            "Uten denne har dere ingen oversikt over forsøk på misbruk, "
            "og heller ingen måte å vite om egne systemer blir stoppet.",
        )

    # Only reports the company itself receives count as real oversight.
    own_rua = has_rua and not external_rua

    if row["dmarc_status"] == "missing":
        return [
            (
                "Opprett en DMARC-regel. Legg til en ny TXT-oppføring på "
                f"navnet <b>_dmarc.{domain}</b> med denne verdien:",
                f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}",
                "Denne første versjonen blokkerer ingenting. Den samler "
                "kun inn rapporter, slik at dere ser hvem som sender "
                "e-post i deres navn før dere strammer inn. La den stå "
                "i fire til seks uker.",
            ),
            (
                "Stram deretter inn i to trinn, når rapportene viser at "
                "all legitim e-post er dekket:",
                f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}\n"
                f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
                "Først quarantine i noen uker, deretter reject. Da er "
                "domenet fullt beskyttet.",
            ),
        ]

    if row["dmarc_status"] == "weak":
        steps = [
            (
                "Regelen står på ren overvåking og stopper ingenting. "
                f"Endre TXT-oppføringen på <b>_dmarc.{domain}</b> til:",
                f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}",
                "Rapportene bør gjennomgås først, for å bekrefte at "
                "all legitim e-post er dekket."
                if own_rua
                else None,
            ),
            (
                "Når det har stått i noen uker uten at legitim e-post "
                "blir stoppet, sett den til full beskyttelse:",
                f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
                None,
            ),
        ]
        if not own_rua:
            steps.insert(0, rua_step)
        return steps

    if row["dmarc_status"] == "partial":
        # Subdomain gap is a different problem from a soft policy.
        if row.get("dmarc_subdomain") == "none":
            return [
                (
                    "Hoveddomenet er beskyttet, men underdomener er "
                    "unntatt. Fjern <b>sp=none</b> fra TXT-oppføringen "
                    f"på <b>_dmarc.{domain}</b>, eller sett den til:",
                    "sp=reject",
                    "Uten dette kan en angriper forfalske e-post fra "
                    f"for eksempel faktura.{domain}.",
                )
            ]

        pct = row.get("dmarc_pct")
        if pct and pct < 100:
            return [
                (
                    "Regelen gjelder bare deler av e-posten deres. "
                    f"Fjern <b>pct={pct}</b> fra TXT-oppføringen på "
                    f"<b>_dmarc.{domain}</b> slik at den gjelder alt.",
                    None,
                    None,
                )
            ]

        steps = [
            (
                "Regelen sender forfalsket e-post til søppelpost, men "
                "avviser den ikke. Mottakeren kan fortsatt finne og "
                "åpne den. Endre TXT-oppføringen på "
                f"<b>_dmarc.{domain}</b> til:",
                f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
                "Gjør dette når rapportene bekrefter at ingen legitim "
                "e-post havner i søppelpost i dag."
                if own_rua
                else None,
            )
        ]
        if not own_rua:
            steps.insert(0, rua_step)
        return steps

    if row["dmarc_status"] == "broken":
        return [
            (
                "Regelen mangler gyldig innhold. Erstatt "
                f"TXT-oppføringen på <b>_dmarc.{domain}</b> med:",
                f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}",
                "Stram inn til quarantine og deretter reject når "
                "rapportene ser riktige ut.",
            )
        ]

    return []


def spf_steps(row, domain):
    """Concrete SPF remediation."""
    if row["spf_status"] == "missing":
        return [
            (
                "Opprett en SPF-oppføring. Legg til en TXT-oppføring på "
                f"<b>{domain}</b> som lister e-postleverandøren deres. "
                "Eksempel for Microsoft 365:",
                "v=spf1 include:spf.protection.outlook.com -all",
                "For Google Workspace brukes "
                "include:_spf.google.com i stedet. Alle systemer som "
                "sender e-post i deres navn, som nyhetsbrev eller "
                "fakturasystem, må også med i listen.",
            )
        ]

    if row["spf_status"] == "weak":
        return [
            (
                "Listen finnes, men avviser ikke ukjente avsendere. "
                f"Bytt <b>~all</b> til <b>-all</b> på slutten av "
                f"TXT-oppføringen på <b>{domain}</b>:",
                "... -all",
                "Gjør dette først når DMARC-rapportene bekrefter at "
                "alle legitime avsendere står i listen. Ellers kan "
                "e-post fra egne systemer bli avvist.",
            )
        ]

    if row["spf_status"] == "broken":
        return [
            (
                "Oppføringen mangler avslutning og har ingen virkning. "
                f"Legg til <b>-all</b> på slutten av TXT-oppføringen "
                f"på <b>{domain}</b>.",
                None,
                None,
            )
        ]

    return []


def dkim_steps(row):
    """Concrete DKIM remediation."""
    if row["dkim_status"] == "not_found":
        return [
            (
                "Slå på digital signering hos e-postleverandøren deres. "
                "I Microsoft 365 ligger dette under Defender, i Google "
                "Workspace under Apps og Gmail. Leverandøren oppgir en "
                "verdi som skal legges inn som TXT-oppføring.",
                None,
                "Merk at vi kun har sjekket de vanligste oppsettene. "
                "Det er mulig signering allerede er aktiv med et "
                "navn vi ikke har testet.",
            )
        ]

    return []


def build_styles():
    """Paragraph styles used throughout the report."""
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            spaceAfter=4,
            alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#666666"),
            spaceAfter=20,
        ),
        "lead": ParagraphStyle(
            "lead",
            parent=base["Normal"],
            fontSize=11,
            leading=16,
            spaceAfter=16,
        ),
        "tag": ParagraphStyle(
            "tag",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            spaceBefore=18,
            spaceAfter=1,
        ),
        "heading": ParagraphStyle(
            "heading",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            spaceBefore=2,
            spaceAfter=7,
        ),
        "section": ParagraphStyle(
            "section",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            spaceBefore=20,
            spaceAfter=8,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["Normal"],
            fontSize=10.5,
            leading=15,
            spaceAfter=8,
        ),
        "note": ParagraphStyle(
            "note",
            parent=base["Normal"],
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#555555"),
            spaceAfter=12,
        ),
        "mono": ParagraphStyle(
            "mono",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=8,
            leading=12,
            textColor=colors.HexColor("#222222"),
            backColor=colors.HexColor("#f4f4f4"),
            borderPadding=7,
            spaceBefore=2,
            spaceAfter=10,
        ),
    }


def soft_wrap(text):
    """
    Let DNS records wrap naturally at spaces, but add break points
    inside very long single tokens so they do not overflow the page.
    """
    parts = []
    for token in text.split():
        if len(token) > 34:
            token = token.replace(":", ":<br/>")
        parts.append(token)
    return " ".join(parts)


def overall_verdict(row):
    """
    Decide the headline verdict for the whole domain.

    DMARC carries the most weight because it is the mechanism that
    actually decides what happens to forged mail.
    """
    dmarc = DMARC_VERDICT.get(row["dmarc_status"], "warn")
    spf = SPF_VERDICT.get(row["spf_status"], "warn")

    if dmarc == "bad" or spf == "bad":
        return (
            "bad",
            "Domenet er ikke beskyttet mot forfalskning",
            "Slik det står i dag kan utenforstående sende e-post som "
            "ser ut som den kommer fra dere. Mottakeren har ingen måte "
            "å se at den er falsk på.",
        )

    if dmarc == "warn" or spf == "warn":
        return (
            "warn",
            "Delvis beskyttet",
            "Dere har gjort deler av jobben, men oppsettet stopper "
            "ikke forfalsket e-post i praksis. Det gjenstår lite for "
            "å lukke hullet.",
        )

    return (
        "ok",
        "Domenet er riktig beskyttet",
        "Oppsettet deres stopper forfalsket e-post slik det skal.",
    )


def add_check(story, styles, heading, verdict, text, evidence=None):
    """Add one check section, with the verdict tag above the heading."""
    colour = VERDICT_COLOURS[verdict]

    story.append(
        Paragraph(
            f'<font color="{colour.hexval()}">'
            f"{VERDICT_LABELS[verdict]}</font>",
            styles["tag"],
        )
    )
    story.append(Paragraph(heading, styles["heading"]))
    story.append(Paragraph(text, styles["body"]))

    if evidence:
        story.append(Paragraph(soft_wrap(evidence), styles["mono"]))


def add_steps(story, styles, steps):
    """Render the remediation steps, numbered, with DNS values."""
    for i, (instruction, value, note) in enumerate(steps, 1):
        story.append(Paragraph(f"{i}. {instruction}", styles["body"]))

        if value:
            # Each line of the value is shown as its own code block line.
            lines = "<br/>".join(value.split("\n"))
            story.append(Paragraph(lines, styles["mono"]))

        if note:
            story.append(Paragraph(note, styles["note"]))


def build_report(row, path, company=None):
    """
    Write a PDF report for one scanned domain.

    row     - a result dict from scan()
    path    - output file path
    company - optional company name for the header
    """
    styles = build_styles()
    domain = row["domain"]

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=22 * mm,
        rightMargin=22 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=f"E-postsikkerhet - {domain}",
    )

    story = []

    story.append(Paragraph("Rapport: e-postsikkerhet", styles["title"]))
    story.append(
        Paragraph(
            f"{company or domain} &nbsp;&middot;&nbsp; "
            f"{date.today().strftime('%d.%m.%Y')}",
            styles["subtitle"],
        )
    )

    verdict, headline, summary = overall_verdict(row)
    colour = VERDICT_COLOURS[verdict]

    story.append(
        Paragraph(
            f'<font color="{colour.hexval()}"><b>{headline}</b></font>',
            styles["heading"],
        )
    )
    story.append(Paragraph(summary, styles["lead"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#dddddd")))

    add_check(
        story,
        styles,
        "Godkjente avsendere (SPF)",
        SPF_VERDICT.get(row["spf_status"], "warn"),
        SPF_TEXT.get(row["spf_status"], ""),
        row.get("spf_record"),
    )

    add_check(
        story,
        styles,
        "Regel for forfalsket e-post (DMARC)",
        DMARC_VERDICT.get(row["dmarc_status"], "warn"),
        dmarc_description(row),
        row.get("dmarc_record"),
    )

    add_check(
        story,
        styles,
        "Digital signatur (DKIM)",
        DKIM_VERDICT.get(row["dkim_status"], "warn"),
        DKIM_TEXT.get(row["dkim_status"], ""),
    )

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#dddddd")))
    story.append(Paragraph("Hva som bør gjøres", styles["section"]))

    # DMARC first: it is the change with the largest effect.
    steps = (
        dmarc_steps(row, domain)
        + spf_steps(row, domain)
        + dkim_steps(row)
    )

    if steps:
        add_steps(story, styles, steps)
        story.append(
            Paragraph(
                "Endringene gjøres i domeneoppsettet (DNS) hos den som "
                "administrerer domenet deres. De påvirker ikke "
                "e-posten deres i det daglige.",
                styles["note"],
            )
        )
    else:
        story.append(
            Paragraph(
                "Ingen tiltak nødvendig. Oppsettet er i orden.",
                styles["body"],
            )
        )

    story.append(HRFlowable(width="100%", color=colors.HexColor("#dddddd")))
    story.append(
        Paragraph(
            "Rapporten bygger utelukkende på offentlig tilgjengelige "
            f"DNS-oppslag for {domain}. Ingen systemer hos "
            f"{company or domain} er berørt.",
            styles["note"],
        )
    )

    doc.build(story)
    return path