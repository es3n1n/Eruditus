import io
import json
import logging
import os
import re
import urllib.parse
import warnings
from datetime import datetime, timezone
from hashlib import md5
from string import ascii_lowercase, digits
from typing import Any, Optional, Type, TypeVar

import discord
import matplotlib.pyplot as plt
from aiohttp import ClientResponse
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from markdownify import markdownify as html2md
from pydantic import TypeAdapter, ValidationError
from tldextract.tldextract import ExtractResult, TLDExtract

from config import (
    CHALLENGE_COLLECTION,
    CTF_COLLECTION,
    DBNAME,
    MONGO,
    WORKON_COLLECTION,
)
from lib.platforms.abc import ChallengeFile, TeamScoreHistory

T = TypeVar("T")
_log = logging.getLogger("discord.eruditus.util")
tld_extract = TLDExtract()

# "The input looks more like a filename than a markup" warnings
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


def country_name(country_code: str) -> Optional[str]:
    """Get the full country name for a given 2 letter country code."""
    # todo es3n1n: perhaps move this big dictionary to a .json file or something
    return {
        "AF": "Afghanistan",
        "AX": "Åland Islands",
        "AL": "Albania",
        "DZ": "Algeria",
        "AS": "American Samoa",
        "AD": "Andorra",
        "AO": "Angola",
        "AI": "Anguilla",
        "AQ": "Antarctica",
        "AG": "Antigua and Barbuda",
        "AR": "Argentina",
        "AM": "Armenia",
        "AW": "Aruba",
        "AU": "Australia",
        "AT": "Austria",
        "AZ": "Azerbaijan",
        "BS": "Bahamas",
        "BH": "Bahrain",
        "BD": "Bangladesh",
        "BB": "Barbados",
        "BY": "Belarus",
        "BE": "Belgium",
        "BZ": "Belize",
        "BJ": "Benin",
        "BM": "Bermuda",
        "BT": "Bhutan",
        "BO": "Plurinational State of Bolivia",
        "BQ": "Bonaire, Sint Eustatius and Saba",
        "BA": "Bosnia and Herzegovina",
        "BW": "Botswana",
        "BV": "Bouvet Island",
        "BR": "Brazil",
        "IO": "British Indian Ocean Territory",
        "BN": "Brunei Darussalam",
        "BG": "Bulgaria",
        "BF": "Burkina Faso",
        "BI": "Burundi",
        "KH": "Cambodia",
        "CM": "Cameroon",
        "CA": "Canada",
        "CV": "Cape Verde",
        "KY": "Cayman Islands",
        "CF": "Central African Republic",
        "TD": "Chad",
        "CL": "Chile",
        "CN": "China",
        "CX": "Christmas Island",
        "CC": "Cocos (Keeling) Islands",
        "CO": "Colombia",
        "KM": "Comoros",
        "CG": "Congo",
        "CK": "Cook Islands",
        "CR": "Costa Rica",
        "CI": "Côte D'ivoire",
        "HR": "Croatia",
        "CU": "Cuba",
        "CW": "Curaçao",
        "CY": "Cyprus",
        "CZ": "Czech Republic",
        "DK": "Denmark",
        "DJ": "Djibouti",
        "DM": "Dominica",
        "DO": "Dominican Republic",
        "EC": "Ecuador",
        "EG": "Egypt",
        "SV": "El Salvador",
        "GQ": "Equatorial Guinea",
        "EE": "Estonia",
        "ET": "Ethiopia",
        "FK": "Falkland Islands (Malvinas)",
        "FO": "Faroe Islands",
        "FJ": "Fiji",
        "FI": "Finland",
        "FR": "France",
        "GF": "French Guiana",
        "PF": "French Polynesia",
        "TF": "French Southern Territories",
        "GA": "Gabon",
        "GM": "Gambia",
        "GE": "Georgia",
        "DE": "Germany",
        "GH": "Ghana",
        "GI": "Gibraltar",
        "GR": "Greece",
        "GL": "Greenland",
        "GD": "Grenada",
        "GP": "Guadeloupe",
        "GU": "Guam",
        "GT": "Guatemala",
        "GG": "Guernsey",
        "GN": "Guinea",
        "GY": "Guyana",
        "HT": "Haiti",
        "HM": "Heard Island and McDonald Islands",
        "VA": "Holy See (Vatican City State)",
        "HN": "Honduras",
        "HK": "Hong Kong",
        "HU": "Hungary",
        "IS": "Iceland",
        "IN": "India",
        "ID": "Indonesia",
        "IR": "Islamic Republic of Iran",
        "IQ": "Iraq",
        "IE": "Ireland",
        "IM": "Isle of Man",
        "IT": "Italy",
        "JM": "Jamaica",
        "JP": "Japan",
        "JO": "Jordan",
        "KZ": "Kazakhstan",
        "KE": "Kenya",
        "KI": "Kiribati",
        "KP": "Democratic People's Republic of Korea",
        "KR": "Republic of Korea",
        "KW": "Kuwait",
        "KG": "Kyrgyzstan",
        "LA": "Lao People's Democratic Republic",
        "LV": "Latvia",
        "LB": "Lebanon",
        "LS": "Lesotho",
        "LR": "Liberia",
        "LY": "Libya",
        "LI": "Liechtenstein",
        "LT": "Lithuania",
        "LU": "Luxembourg",
        "MO": "Macao",
        "MK": "The Former Yugoslav Republic of Macedonia",
        "MG": "Madagascar",
        "MY": "Malaysia",
        "MV": "Maldives",
        "ML": "Mali",
        "MT": "Malta",
        "MH": "Marshall Islands",
        "MQ": "Martinique",
        "MR": "Mauritania",
        "MU": "Mauritius",
        "YT": "Mayotte",
        "MX": "Mexico",
        "FM": "Federated States of Micronesia",
        "MD": "Republic of Moldova",
        "MC": "Monaco",
        "MN": "Mongolia",
        "MS": "Montserrat",
        "MA": "Morocco",
        "MZ": "Mozambique",
        "MM": "Myanmar",
        "NA": "Namibia",
        "NR": "Nauru",
        "NP": "Nepal",
        "NL": "Netherlands",
        "NC": "New Caledonia",
        "NZ": "New Zealand",
        "NI": "Nicaragua",
        "NE": "Niger",
        "NG": "Nigeria",
        "NU": "Niue",
        "NF": "Norfolk Island",
        "MP": "Northern Mariana Islands",
        "NO": "Norway",
        "OM": "Oman",
        "PK": "Pakistan",
        "PW": "Palau",
        "PS": "Palestine",
        "PA": "Panama",
        "PG": "Papua New Guinea",
        "PY": "Paraguay",
        "PE": "Peru",
        "PH": "Philippines",
        "PN": "Pitcairn",
        "PL": "Poland",
        "PT": "Portugal",
        "PR": "Puerto Rico",
        "QA": "Qatar",
        "RE": "Réunion",
        "RO": "Romania",
        "RU": "Russian Federation",
        "RW": "Rwanda",
        "BL": "Saint Barthélemy",
        "KN": "Saint Kitts and Nevis",
        "LC": "Saint Lucia",
        "MF": "Saint Martin (French Part)",
        "SA": "Saudi Arabia",
        "SN": "Senegal",
        "RS": "Serbia",
        "SC": "Seychelles",
        "SL": "Sierra Leone",
        "SG": "Singapore",
        "SK": "Slovakia",
        "SI": "Slovenia",
        "SB": "Solomon Islands",
        "SO": "Somalia",
        "ZA": "South Africa",
        "GS": "South Georgia and the South Sandwich Islands",
        "SS": "South Sudan",
        "ES": "Spain",
        "LK": "Sri Lanka",
        "SD": "Sudan",
        "SJ": "Svalbard and Jan Mayen",
        "SZ": "Swaziland",
        "SE": "Sweden",
        "CH": "Switzerland",
        "SY": "Syrian Arab Republic",
        "TW": "Taiwan, Republic of China",
        "TJ": "Tajikistan",
        "TZ": "United Republic of Tanzania",
        "TH": "Thailand",
        "TL": "Timor-leste",
        "TG": "Togo",
        "TT": "Trinidad and Tobago",
        "TN": "Tunisia",
        "TR": "Turkey",
        "TM": "Turkmenistan",
        "TV": "Tuvalu",
        "UG": "Uganda",
        "UA": "Ukraine",
        "AE": "United Arab Emirates",
        "GB": "United Kingdom",
        "US": "United States",
        "UM": "United States Minor Outlying Islands",
        "UY": "Uruguay",
        "UZ": "Uzbekistan",
        "VU": "Vanuatu",
        "VE": "Bolivarian Republic of Venezuela",
        "VN": "Viet Nam",
        "VG": "Virgin Islands, British",
        "VI": "Virgin Islands, U.S.",
        "WF": "Wallis and Futuna",
        "EH": "Western Sahara",
        "YE": "Yemen",
        "ZM": "Zambia",
        "ZW": "Zimbabwe",
    }.get(country_code.upper())


def get_local_time() -> datetime:
    """Return offset aware local time.

    Returns:
        Offset aware datetime object.
    """
    local_timezone = datetime.now(timezone.utc).astimezone().tzinfo
    return datetime.now(local_timezone)


def truncate(text: str, max_len: int = 1024) -> str:
    """Truncate a paragraph to a specific length.

    Args:
        text: The paragraph to truncate.
        max_len: The maximum length of the paragraph.

    Returns:
        The truncated paragraph.
    """
    etc = "\n[…]"
    return (
        f"{text[:max_len - len(etc)]}{etc}" if len(text) > max_len - len(etc) else text
    )


def sanitize_category_name(name: str) -> str:
    # Avoid having duplicate categories when people mix up upper/lower case
    # or add unnecessary spaces at the beginning or the end.
    return name.title().strip()


def sanitize_channel_name(name: str) -> str:
    """Filter out characters that aren't allowed by Discord for guild channels.

    Args:
        name: Channel name.

    Returns:
        Sanitized channel name.
    """
    whitelist = ascii_lowercase + digits + "-_"
    name = name.lower().replace(" ", "-")

    for char in name:
        if char not in whitelist:
            name = name.replace(char, "")

    while "--" in name:
        name = name.replace("--", "-")

    return name


def derive_colour(role_name: str) -> int:
    """Derive a color for the CTF role by taking its MD5 hash and using the first three
    bytes as the color.

    Args:
        role_name: Name of the role we wish to set a color for.

    Returns:
        An integer representing an RGB color.
    """
    return int(md5(role_name.encode()).hexdigest()[:6], 16)


def in_range(value: int, minimal: int, maximum: int) -> bool:
    """Check whether number is in desired range.

    Args:
        value: The value that is going to be checked.
        minimal: Min value.
        maximum: Max value.

    Returns:
        True or false.
    """
    return minimal <= value <= maximum


def is_empty_string(value: Optional[str]) -> bool:
    """Check whether a string is empty.

    Args:
        value: The string that is going to be checked.

    Returns:
        True if the string is empty or None, False otherwise.

    Raises:
        TypeError: if `value` is of type other than `None` or `str`.
    """
    if value is not None and not isinstance(value, str):
        raise TypeError("Value must be either None or a string")
    return value is None or value.strip() == ""


def extract_filename_from_url(url: str) -> str:
    """Extract a filename from a URL.

    Args:
        The URL to extract the filename from.

    Returns:
        The filename.
    """
    return os.path.basename(urllib.parse.urlparse(url).path)


def html_to_markdown(description: Optional[str]) -> Optional[str]:
    """Convert HTML content to Markdown.

    Args:
        The HTML content.

    Returns:
        Converted result.
    """
    if description is None:
        return None

    # Convert to markdown.
    md = html2md(
        description,
        heading_style="atx",
        escape_asterisks=False,
        escape_underscores=False,
    )

    # Remove all images.
    md = re.sub(r'[^\S\r\n]*!\[[^\]]*\]\((.*?)\s*("(?:.*[^"])")?\s*\)\s*', "", md)

    # Remove multilines.
    md = re.sub(r"\n+", "\n", md)

    return md


def convert_attachment_url(url: str, base_url: Optional[str]) -> str:
    """Convert attachment URL to an absolute URL.

    Args:
        url: The attachment url.
        base_url: Domain base url.

    Returns:
        Absolute url.
    """
    if not url.startswith("http") and base_url:
        url = f'{base_url.rstrip("/")}/{url.lstrip("/")}'

    return url


def parse_attachment(url: str, base_url: Optional[str]) -> ChallengeFile:
    """Convert attachment URL to a ChallengeFile item.

    Args:
        url: The attachment url.
        base_url: Domain base url.

    Returns:
        Converted file.
    """
    return ChallengeFile(
        url=convert_attachment_url(url, base_url),
        name=extract_filename_from_url(url),
    )


def extract_images_from_html(
    description: Optional[str], base_url: Optional[str] = None
) -> Optional[list[ChallengeFile]]:
    """Extract `img` tags from the HTML description.

    Args:
        description: The HTMl content.
        base_url: Domain base url.

    TODO:
        Add markdown support.

    Returns:
        Converted files.
    """
    if not description:
        return None

    result = []

    for img in BeautifulSoup(description, "html.parser").findAll("img"):
        src: Optional[str] = img.get("src")
        if not src:
            continue

        result.append(parse_attachment(src, base_url))

    return result


def strip_url_components(url: str) -> str:
    """Strip the path, query parameters and fragments from a URL.

    Args:
        The URL to parse.

    Returns:
        The base URL.
    """
    parsed_url = urllib.parse.urlparse(url)
    return f"{parsed_url.scheme}://{parsed_url.netloc}"


def extract_rctf_team_token(invite_url: str) -> Optional[str]:
    """Extract the rCTF team token from an invitation URL.

    Args:
        The rCTF invite URL (e.g., https://rctf.example.com/login?token=<token>).

    Returns:
        The team token.
    """
    parsed_url = urllib.parse.urlparse(invite_url)
    params = urllib.parse.parse_qs(parsed_url.query)
    if not (team_token := params.get("token")):
        return None

    return team_token[0]


def re_ignorecase(s: str) -> Any:
    """Convert the immediate value to the regex ignore case expression.

    Args:
        The string to be converted.

    Returns:
        Converted expression.
    """
    return re.compile(f"^{re.escape(s.strip())}$", re.IGNORECASE)


def _build_query(**search_fields: Any) -> dict:
    """Build a search query for the ctf/challenge search.

    Returns:
        The built search query.

    Notes:
        The name and category are case-insensitive.
    """
    query = {}
    for field, value in search_fields.items():
        if field in {"name", "category"}:
            query[field] = re_ignorecase(value)
            continue

        query[field] = value

    return query


def get_ctf_info(**search_fields: Any) -> Optional[dict]:
    """Retrieve information for a CTF.

    Returns:
        The CTF document, or None if no such CTF exists.

    Notes:
        The CTF name is case insensitive.
    """
    return MONGO[DBNAME][CTF_COLLECTION].find_one(_build_query(**search_fields))


def get_challenge_info(**search_fields: Any) -> Optional[dict]:
    """Retrieve a challenge from the database.

    Returns:
        The challenge document.

    Notes:
        The challenge name and category name are case-insensitive.
    """
    return MONGO[DBNAME][CHALLENGE_COLLECTION].find_one(_build_query(**search_fields))


def get_all_challenges_info(**search_fields: Any) -> list[dict]:
    """Retrieve multiple challenges from the database.

    Returns:
        The challenges documents.

    Notes:
        The challenge name and category name are case-insensitive.
    """
    return list(MONGO[DBNAME][CHALLENGE_COLLECTION].find(_build_query(**search_fields)))


def get_workon_info(ctf_id: Any, user_id: int, category_name: str) -> Optional[dict]:
    """Retrieve a workon info from the database.

    Returns:
        The optional document.

    Notes:
        The category name is case-insensitive.
    """
    return MONGO[DBNAME][WORKON_COLLECTION].find_one(
        {"ctf_id": ctf_id, "category": re_ignorecase(category_name), "user_id": user_id}
    )


def get_all_workon_info(ctf_id: Any, category_name: str) -> list[dict]:
    """Retrieve all workon info for a category

    Returns:
        List of documents.

    Notes:
        The category name is case-insensitive.
    """
    return list(
        MONGO[DBNAME][WORKON_COLLECTION].find(
            {"ctf_id": ctf_id, "category": re_ignorecase(category_name)}
        )
    )


def make_form_field_config(name: str, config: dict) -> dict:
    """Generate configuration for a form field.

    Args:
        name: The field name (e.g., username, password, etc.).
        config: The form configuration (label, placeholder, etc.), for a full list, see
            the arguments of `discord.ui.TextInput`.

    Returns:
        A dictionary containing the field configuration.
    """
    max_length = 128
    match name:
        case "email":
            label, placeholder = "Email", "Enter your email..."
        case "username":
            label, placeholder = "Username", "Enter your username..."
        case "password":
            label, placeholder = "Password", "Enter your password..."
        case "invite":
            label, placeholder, max_length = (
                "Invite link",
                "Enter your team invite URL...",
                512,
            )
        case "token":
            label, placeholder, max_length = (
                "Token",
                "Enter your team token...",
                256,
            )
        case _:
            label, placeholder, max_length = ("Unknown field", "Unknown field", 128)

    return {
        "label": config.get("label", label),
        "placeholder": config.get("placeholder", placeholder),
        "required": config.get("required", True),
        "max_length": config.get("max_length", max_length),
        "style": config.get("style", discord.TextStyle.short),
    }


async def deserialize_response(
    response: ClientResponse, model: Type[T], suppress_warnings: bool = False
) -> Optional[T]:
    """Validate response status code and JSON content.

    Args:
        response: The HTTP response.
        model: The pydantic model used to validate the JSON response.
        suppress_warnings: No warnings would be printed if set to true.

    Returns:
        A deserialized response if the response is valid, None otherwise.
    """
    response_ranges: list[list[int]] = [
        [200, 299],  # ok
        [400, 499],  # client-side errors
    ]

    valid_status_code: bool = False
    for response_range in response_ranges:
        valid_status_code |= in_range(response.status, *response_range)

    if not valid_status_code:
        return None

    response_json: dict[str, Any] = await response.json()

    try:
        return TypeAdapter(model).validate_python(response_json)
    except ValidationError as e:
        if not suppress_warnings:
            _log.warning(
                "Could not validate response data using the %s model:\n%s\nErrors - %s",
                model.__name__,
                json.dumps(response_json, indent=2),
                str(e),
            )
        return None


def plot_scoreboard(
    data: list[TeamScoreHistory], fig_size: tuple = (15, 6)
) -> io.BytesIO:
    """Plot scoreboard.

    Args:
        data: A list where each element is a struct containing:
            - The team name (used as the label in the graph).
            - The timestamps of each solve (as `datetime` objects, these will fill the
                x-axis).
            - The number of points at each instant (these will fill the y-axis).
        fig_size: The figure size.

    Returns:
        A BytesIO buffer containing the saved figure data in bytes.
    """

    # We're using an actual color instead of a transparent background in order for the
    # text to be visible in light theme as well.
    background_color: str = "#313338"

    # Create a new figure.
    fig: plt.Figure = plt.figure(
        figsize=fig_size, facecolor=background_color, layout="tight"
    )

    # Apply background color to the axes.
    axes = fig.subplots()
    for axe in [axes] if not isinstance(axes, list) else axes:
        axe.set_facecolor(background_color)

    # Obtain current axes and set the figure title.
    gca: plt.Subplot = fig.gca()
    gca.set_title(
        label=f"Top {len(data)} Teams", fontdict={"weight": "bold", "color": "white"}
    )

    for team in data:
        kw = {}
        if team.is_me:
            kw["zorder"] = len(data) + 1  # Bring our team to the front

        # Create a new plot item with the X axis set to time and the Y axis set to
        # score.
        gca.plot(
            [x.time for x in team.history],
            [x.score for x in team.history],
            label=team.name,
            **kw,
        )

    # Apply grid and legend style.
    gca.grid(color="gray", linestyle="dashed", alpha=0.5)
    gca.legend(loc="best")

    # Apply x tick labels styles.
    for label in gca.get_xticklabels(minor=False):
        label.set(rotation=45, color="white")

    # Apply y tick labels style.
    for label in gca.get_yticklabels(minor=False):
        label.set(color="white")

    # Apply spine colors.
    for highlighted_spine in ["bottom", "left"]:
        gca.spines[highlighted_spine].set_color("white")

    # Make the top/right spines invisible.
    for invisible_spine in ["top", "right"]:
        gca.spines[invisible_spine].set_visible(False)

    # Save the result and close the figure object.
    result = io.BytesIO()
    fig.savefig(result, bbox_inches="tight")
    plt.close(fig)

    # Reset buffer position and return it.
    result.seek(0)
    return result


def substitute_base_url(base_url: str) -> list[str]:
    """Substitute the base url to try to discover the API subdomain for a platform.

    Args:
        base_url: Subdomain base url provided by the user

    Returns:
        A list of urls that the platform matcher should check.
    """
    url: urllib.parse.ParseResult = urllib.parse.urlparse(base_url)
    domains: list[str] = [url.netloc]

    # First pass, collecting base domain if the provided url is a subdomain
    extracted: ExtractResult = tld_extract.extract_urllib(url)
    if extracted.subdomain != "":
        domains.append(f"{extracted.domain}.{extracted.suffix}")

    # Second pass, trying common api subdomains
    subdomains = []
    for subdomain in ["api"]:
        for domain in domains:
            subdomains.append(f"{subdomain}.{domain}")

    # Converting domains back to the URLs and returning
    return [f"{url.scheme}://{domain}/" for domain in [*domains, *subdomains]]
