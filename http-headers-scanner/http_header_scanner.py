import argparse
import re
import sys
from dataclasses import dataclass
from typing import Literal
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

"""
This script scans HTTP headers of a given URL and displays them in a formatted table."""

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]

@dataclass(frozen=True, slots=True)
class HeaderRule:
    """Represents a rule for checking an HTTP header.
    Frozen: makes the instance immutable after creation. Slots: optimizes memory usage by preventing the creation of a __dict__ for each instance.

    Fields: 
    header: the name of the HTTP header to check. (case-insensitive)
    severity: the severity level of the rule (high, medium, low).
    description: a brief description of the rule.
    recommendation: a recommendation for addressing if the header is missing.
    must_match: an optional string that specifies a required value for the header. If provided, the header's value must match this string to be considered valid.
    """
    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None  # Optional field to specify a required value for the header. If provided, the header's value must match this string to be considered valid.



    #Rules: The single source.

RULES: list[HeaderRule] = [
    HeaderRule(
        header = "Strict-Transport-Security",
        severity = "high",
        description = (
            "Tells the browser to ONLY connect over HTTPS for the "
            "next N seconds, defeating SSL-stripping attacks"
        ),
        recommendation = (
            "Add: Strict-Transport-Security: "
            "max-age=31536000; includeSubDomains"
        ),
        # Require max-age to be a positive integer — `max-age=0`
        # actively disables HSTS, so we must reject it. The regex
        # accepts whitespace around `=` to tolerate `max-age = 60`.
        must_match = r"max-age\s*=\s*[1-9]",
    ),
    HeaderRule(
        header = "Content-Security-Policy",
        severity = "high",
        description = (
            "Controls which scripts, styles, frames, and connections "
            "the browser may load — the strongest XSS defense"
        ),
        recommendation = (
            "Add a Content-Security-Policy that disallows "
            "'unsafe-inline' and limits sources to trusted origins"
        ),
    ),
    HeaderRule(
        header = "X-Content-Type-Options",
        severity = "medium",
        description = (
            "Stops browsers from second-guessing the Content-Type "
            "and treating a .txt file as HTML — defeats MIME-sniffing"
        ),
        recommendation = "Add: X-Content-Type-Options: nosniff",
        # Value must literally be `nosniff`; anything else is broken.
        # `re.search("nosniff", ...)` is a substring match here — no
        # special regex characters in the pattern.
        must_match = "nosniff",
    ),
    HeaderRule(
        header = "X-Frame-Options",
        severity = "medium",
        description = (
            "Prevents another site from embedding this page in an "
            "iframe, defeating clickjacking attacks"
        ),
        recommendation = (
            "Add: X-Frame-Options: DENY (or use "
            "Content-Security-Policy: frame-ancestors 'none')"
        ),
    ),
    HeaderRule(
        header = "Referrer-Policy",
        severity = "low",
        description = (
            "Limits how much of the current URL leaks to other sites "
            "when the user clicks an outbound link"
        ),
        recommendation = (
            "Add: Referrer-Policy: strict-origin-when-cross-origin"
        ),
    ),
    HeaderRule(
        header = "Permissions-Policy",
        severity = "low",
        description = (
            "Disables browser features the page does not use "
            "(camera, microphone, geolocation, payments, etc.)"
        ),
        recommendation = (
            "Add: Permissions-Policy: "
            "camera=(), microphone=(), geolocation=()"
        ),
    ),
]

SEVERITY_POINTS: dict[Severity, int] = {
    "high": 30,
    "medium": 15,
    "low": 5,
}


@dataclass(frozen=True, slots=True)
class HeaderFinding:
    """Represents the result of checking an HTTP header against a rule.

    Fields:
    header: the name of the HTTP header that was checked.
    severity: the severity level of the rule (high, medium, low).
    description: a brief description of the rule.
    recommendation: a recommendation for addressing if the header is missing.
    """
    rule: HeaderRule
    status: Status
    actual_value: str | None = None  # The actual value of the header if it was found; None if the header was missing.
    note: str | None = None  # Optional note providing additional context about the finding. For example, if the header was found but its value did not match the expected value, this field can explain why it was considered weak.


@dataclass(frozen = True, slots = True)
class ScanReport:
    """
    A full scan result for one URL

    The `score` and `grade` properties are computed on demand from
    the findings, so they always reflect whatever the rules table
    looked like at scan time
    """
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]

    @property
    def score(self) -> int:
        """
        Return a 0–100 score reflecting the weighted findings

        Formula
        -------
            earned = full points for every "ok"
                   + half points for every "weak"
                   + zero  for every "missing"
            score  = round(earned / total * 100)
        """
        total = sum(SEVERITY_POINTS[r.severity] for r in RULES)
        # Guard against an empty rules table — would only matter if
        # someone deletes RULES while testing. Keeps the code total
        if total == 0:
            return 0

        earned = 0.0
        for finding in self.findings:
            full = SEVERITY_POINTS[finding.rule.severity]
            if finding.status == "ok":
                earned += full
            elif finding.status == "weak":
                earned += full / 2
            # "missing" earns 0 — no else branch needed

        # Round-half-up via int(x + 0.5) avoids Python's banker's
        # rounding, which would map round(0.5) -> 0 and round(2.5) -> 2
        # — surprising for a score that should always round up at the
        # .5 boundary
        return int((earned / total) * 100 + 0.5)

    @property
    def grade(self) -> str:
        """
        Map the score to a letter grade A–F
        """
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

def evaluate_header(
    rule: HeaderRule,
    response_headers: dict[str,
                           str],
) -> HeaderFinding:
    """
    Apply a single HeaderRule to a set of response headers

    HTTP header names are case-insensitive per RFC 7230 — `HSTS` and
    `hsts` and `Hsts` are the same header. We normalize both sides
    to lowercase before comparing
    """
    target = rule.header.lower()

    # Walk the response headers manually instead of building a
    # case-insensitive dict. The input is always a plain dict here —
    # scan() converts httpx's Headers object before calling us, so
    # tests can pass any dict[str, str] without ceremony
    actual_value: str | None = None
    for name, value in response_headers.items():
        if name.lower() == target:
            actual_value = value
            break

    if actual_value is None:
        return HeaderFinding(
            rule = rule,
            status = "missing",
            actual_value = None,
            note = f"Header `{rule.header}` is not set",
        )

    # If the rule has no must_match check, presence is enough
    if rule.must_match is None:
        return HeaderFinding(
            rule = rule,
            status = "ok",
            actual_value = actual_value,
            note = "Present",
        )

    # Otherwise verify the value matches the required pattern.
    # re.search finds the pattern anywhere in the string — for a plain
    # word like `nosniff` that behaves as a substring check; for a
    # real regex like `max-age\s*=\s*[1-9]` it enforces a richer
    # condition (positive integer after `max-age=`)
    if re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule = rule,
            status = "ok",
            actual_value = actual_value,
            note = f"Present and matches `{rule.must_match}`",
        )

    return HeaderFinding(
        rule = rule,
        status = "weak",
        actual_value = actual_value,
        note = (
            f"Present but does not match `{rule.must_match}` "
            f"(got `{actual_value}`)"
        ),
    )


# =============================================================================
# scan() — fetch the URL and apply every rule
# =============================================================================


# A polite, identifiable User-Agent. Some servers block requests with
# the default httpx UA or no UA at all
DEFAULT_USER_AGENT: str = (
    "http-headers-scanner/1.0 "
    "(+https://github.com/tomisin-akingba/security-projects)"
)


def scan(
    url: str,
    *,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ScanReport:
    """
    Fetch `url` once and grade its response headers

    Parameters
    ----------
    url
        Full URL including the scheme. Bare hostnames like
        "example.com" are NOT supported because we cannot guess
        whether the user wanted http or https
    timeout
        Seconds before we give up on a slow server. Default 10
    user_agent
        Sent as the User-Agent header. Some sites serve different
        responses to bots; the default identifies us honestly

    Returns
    -------
    ScanReport
        Containing the findings, status code, and final URL after
        any redirects

    Raises
    ------
    httpx.RequestError
        On DNS failure, connection refusal, timeout, etc. The CLI
        catches these to print a clean error message
    """
    # follow_redirects=True means http://example.com → https://example.com
    # is followed automatically. We grade the FINAL URL, not the first
    # one, because that is the one users actually see
    response = httpx.get(
        url,
        timeout = timeout,
        follow_redirects = True,
        headers = {"User-Agent": user_agent},
    )

    # httpx Headers object behaves like a dict for our purposes.
    # dict(response.headers) gives us a regular dict[str, str]
    response_headers = dict(response.headers)

    # Run every rule against the response. List comprehension is
    # cleaner than a for-loop with .append() here
    findings = [evaluate_header(rule, response_headers) for rule in RULES]

    return ScanReport(
        url = url,
        final_url = str(response.url),
        status_code = response.status_code,
        findings = findings,
    )


# =============================================================================
# CLI rendering — keeps display logic out of the data layer
# =============================================================================


# How each status / severity should be colored in the terminal
STATUS_COLORS: dict[Status,
                    str] = {
                        "ok": "green",
                        "weak": "yellow",
                        "missing": "red",
                    }

GRADE_COLORS: dict[str,
                   str] = {
                       "A": "bright_green",
                       "B": "green",
                       "C": "yellow",
                       "D": "red",
                       "F": "bright_red",
                   }


def _render_report(report: ScanReport, console: Console) -> None:
    """
    Print the scan report as a rich table plus a grade panel
    """
    # The header table — one row per rule
    table = Table(
        title = (
            f"Headers for {report.final_url} "
            f"(HTTP {report.status_code})"
        ),
        title_style = "bold cyan",
        show_lines = False,
    )
    table.add_column("header", style = "bold white", no_wrap = True)
    table.add_column("status", no_wrap = True)
    table.add_column("severity", no_wrap = True)
    table.add_column("note", style = "dim")

    for finding in report.findings:
        status_color = STATUS_COLORS[finding.status]
        table.add_row(
            finding.rule.header,
            f"[{status_color}]{finding.status}[/{status_color}]",
            finding.rule.severity,
            finding.note,
        )
    console.print(table)

    # Browsers IGNORE HSTS received over plain HTTP per RFC 6797 §8.1
    # — if the final response was served over http://, any HSTS grade
    # above is misleading. Warn so the user does not walk away with a
    # false sense of security
    if report.final_url.startswith("http://"):
        console.print(
            "[yellow]Note:[/yellow] this response was served over plain "
            "HTTP. Browsers IGNORE HSTS over HTTP, so any HSTS grade "
            "above is misleading until the site enforces HTTPS"
        )

    # The grade panel — big, color-coded, eye-catching
    grade_color = GRADE_COLORS[report.grade]
    panel = Panel(
        f"[bold {grade_color}]Grade: {report.grade}[/bold {grade_color}]\n"
        f"Score: {report.score} / 100",
        title = "Result",
        border_style = grade_color,
    )
    console.print(panel)

    # Print recommendations for any non-ok findings, so the user has
    # an action list — what to add or fix
    actionable = [f for f in report.findings if f.status != "ok"]
    if actionable:
        console.print("\n[bold]Recommendations:[/bold]")
        for finding in actionable:
            console.print(
                f"  • [yellow]{finding.rule.header}[/yellow] "
                f"— {finding.rule.recommendation}"
            )


# =============================================================================
# argparse plumbing — broken out so tests can call it directly
# =============================================================================


def _build_argument_parser() -> argparse.ArgumentParser:
    """
    Construct the argparse parser used by main()
    """
    parser = argparse.ArgumentParser(
        prog = "headers",
        description = (
            "Scan a URL for HTTP security headers and grade the result A–F."
        ),
    )
    parser.add_argument(
        "url",
        help = "Full URL to scan (must include http:// or https://).",
    )
    parser.add_argument(
        "--timeout",
        type = float,
        default = 10.0,
        help =
        "Seconds to wait before giving up on the request (default: 10).",
    )
    return parser


# =============================================================================
# main() — exit codes mean something
# =============================================================================
# 0 → grade A or B (green light for CI)
# 1 → grade C or D (warn but do not fail by default)
# 2 → grade F or network error (fail loudly)


def main() -> int:
    """
    CLI entry point — return an exit code reflecting the scan result
    """
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    # Catch network errors here so the user sees a clean message
    # instead of a raw traceback. We let httpx's own message bubble
    # through after our prefix — the underlying error usually has
    # useful detail (DNS failure, connection refused, etc.)
    try:
        report = scan(args.url, timeout = args.timeout)
    except httpx.RequestError as exc:
        console.print(
            f"[red]Request failed:[/red] {type(exc).__name__}: {exc}"
        )
        return 2

    _render_report(report, console)

    if report.grade in ("A", "B"):
        return 0
    if report.grade in ("C", "D"):
        return 1
    return 2


# Standard "if invoked directly as a script" guard — lets the file be
# imported by tests without firing main()
if __name__ == "__main__":
    sys.exit(main())
