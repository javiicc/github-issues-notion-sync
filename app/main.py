import datetime
import logging
import re
import sys
from typing import Annotated, Any, Literal

from github import Github
from github.Issue import Issue, PaginatedList
from github.Auth import Token
from pydantic import (
    BaseModel,
    BeforeValidator,
    Field,
    HttpUrl as _HttpUrlBase,
    SecretStr,
    TypeAdapter,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings
import requests


NOTION_BASE_URL = "https://api.notion.com"


NotionColor = Literal[
    "default",
    "gray",
    "brown",
    "orange",
    "yellow",
    "green",
    "blue",
    "purple",
    "pink",
    "red",
]


# https://github.com/pydantic/pydantic/issues/7071
_HttpUrlAdapter = TypeAdapter(_HttpUrlBase)
HttpUrl = Annotated[
    str, BeforeValidator(lambda v: str(_HttpUrlAdapter.validate_python(v)))
]


class ClosedStateMap(BaseModel):
    completed: str = "completed"
    not_planed: str = "not-planned"


class InputConfig(BaseModel):
    notion_new_issue: str = "new-issue"
    notion_open_status: list[str] = ["frozen", "backlog", "working-on", "review-qa"]
    closed_state_map: ClosedStateMap = ClosedStateMap()
    notion_page_size: int = 10

    @model_validator(mode="before")
    @staticmethod
    def validate_closed_state_map(data: Any) -> Any:
        if isinstance(data, dict) and "closed_state_map" in data:
            expected_keys = set(ClosedStateMap.model_fields.keys())
            provided_keys = set(data["closed_state_map"].keys())
            if expected_keys != provided_keys:
                missing_keys = expected_keys - provided_keys
                extra_keys = provided_keys - expected_keys
                error_message = (
                    f"Invalid keys in 'closed_state_map'. "
                    f"Missing: {missing_keys}, Extra: {extra_keys}"
                )
                raise ValueError(error_message)
        return data

    def get_status_names(self) -> set[str]:
        status = set()
        status.add(self.notion_new_issue)
        status.update(self.notion_open_status)
        status.update(self.closed_state_map.model_dump().values())
        return status

    def validate_config_against_db_status_prop(self, db_status_prop: set[str]) -> None:
        """Validate the input configuration against the Notion DB status property names. This
        method is to be used as deferred validation because it needs the Notion DB schema
        to be fetched first.

        Validations:
        1. Check if there are any missing or extra status values in the input configuration.
        2. Ensure 'notion_new_issue' is not used in 'notion_open_status' or 'closed_state_map'.
        3. Ensure 'closed_state_map' values are not used in 'notion_open_status'.
        """
        # 1. Validate input status names match DB status names
        status_names = self.get_status_names()
        if db_status_prop != status_names:
            missing_keys = db_status_prop - status_names
            extra_keys = status_names - db_status_prop

            raise ValueError(
                f"Mismatch between input config status values {status_names} and DB status property {db_status_prop}. "
                f"Missing: {missing_keys}, Extra: {extra_keys}"
            )

        def validate_unique_status(
            value: str, invalid_set: set[str], context: str
        ) -> None:
            if value in invalid_set:
                raise ValueError(
                    f"Status '{value}' ({context}) cannot overlap with {invalid_set}."
                )

        # 2. Ensure 'notion_new_issue' is not used in 'notion_open_status' or 'closed_state_map'
        open_and_closed = set(self.notion_open_status) | set(
            self.closed_state_map.model_dump().values()
        )
        logging.info(open_and_closed)
        validate_unique_status(
            self.notion_new_issue, open_and_closed, "notion_new_issue"
        )

        # 3. Ensure 'closed_state_map' values are not used in 'notion_open_status'
        for name in self.closed_state_map.model_dump().values():
            validate_unique_status(
                name, set(self.notion_open_status), "closed_state_map"
            )


class Settings(BaseSettings):
    input_config: InputConfig
    github_repository: str
    github_repository_owner: str
    input_github_token: SecretStr
    input_notion_api_key: SecretStr
    input_notion_db_id_issues: SecretStr
    default_notion_version: str = "2022-06-28"
    notion_api_version: str = "v1"

    @field_validator("input_config", mode="before")
    def discard_schema(cls, v):
        if "$schema" in v:
            del v["$schema"]
        return v


class MultiSelect(BaseModel):
    name: str
    color: NotionColor


class MultiSelectProp(BaseModel):
    type: Literal["multi_select"]
    multi_select: list[MultiSelect]


class DateRange(BaseModel):
    start: datetime.date | None
    end: datetime.date | None
    time_zone: str | None


class DueProp(BaseModel):
    type: Literal["date"]
    date: DateRange | None


class NumberProp(BaseModel):
    type: Literal["number"]
    number: Annotated[int, Field(gt=0)]


class Select(BaseModel):
    name: str
    color: NotionColor | None = None


class PriorityProp(BaseModel):
    type: Literal["select"]
    select: Select | None


class StatusProp(BaseModel):
    type: Literal["status"]
    status: Select


class TitleContent(BaseModel):
    content: str


class Title(BaseModel):
    type: Literal["text"]
    text: TitleContent
    href: str | None = None


class TitleProp(BaseModel):
    type: Literal["title"]
    title: list[Title]


class UrlProp(BaseModel):
    type: Literal["url"]
    url: HttpUrl

    @field_validator("url")
    def validate_github_issue_url(cls, v: HttpUrl) -> HttpUrl:
        github_issue_api_pattern = re.compile(
            r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/\d+$"
        )
        if not github_issue_api_pattern.match(v):
            raise ValueError("Invalid GitHub issue API URL format")
        return v


class IssuePageProps(BaseModel):
    assignees: MultiSelectProp
    due: DueProp | None = None
    labels: MultiSelectProp
    number: NumberProp
    priority: PriorityProp | None = None
    status: StatusProp
    title: TitleProp
    url: UrlProp


class UpdateIssueProps(BaseModel):
    assignees: MultiSelectProp | None = None
    labels: MultiSelectProp | None = None
    number: NumberProp | None = None
    status: StatusProp | None = None
    title: TitleProp | None = None
    url: UrlProp | None = None


class RNIParent(BaseModel):
    type: Literal["database_id"]
    database_id: str

    @field_validator("database_id")
    def validate_notion_database_id(cls, v: str) -> str:
        uuid_pattern = re.compile(
            r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
        )
        if not uuid_pattern.match(v):
            raise ValueError("Invalid Notion database ID format")
        return v


class IssuePage(BaseModel):
    object: Literal["page"]
    id: str
    properties: IssuePageProps
    parent: RNIParent
    url: HttpUrl

    @field_validator("url")
    def validate_notion_page_url(cls, v: HttpUrl) -> HttpUrl:
        notion_page_pattern = re.compile(r"^https://www\.notion\.so/.*[a-f0-9]{32}$")
        if not notion_page_pattern.match(v):
            raise ValueError("Invalid Notion page URL format")
        return v


class ResponseNotionIssues(BaseModel):
    object: Literal["list"]
    results: list[IssuePage]
    next_cursor: str | None
    has_more: bool


def fetch_notion_db_status_names(settings: Settings) -> set[str]:
    url = f"{NOTION_BASE_URL}/{settings.notion_api_version}/databases/{settings.input_notion_db_id_issues.get_secret_value()}"

    headers = {
        "Authorization": f"Bearer {settings.input_notion_api_key.get_secret_value()}",
        "Notion-Version": settings.default_notion_version,
    }

    response = requests.get(url, headers=headers)

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        logging.error(
            f"Failed to fetch Notion DB schema for ID {settings.input_notion_db_id_issues.get_secret_value()}. "
            f"HTTP {response.status_code}: {response.json().get("message", "Unknown error")}"
        )
        raise

    status_options = (
        response.json().get("properties").get("status").get("status").get("options")
    )
    names = {option.get("name") for option in status_options}

    if len(names) < 4:
        raise ValueError("DB status property needs at least 4 options")

    return names


def get_notion_issues(settings: Settings) -> dict[int, IssuePage]:
    """Returns a map of {issue-number: notion-IssuePage-object}"""
    url = f"{NOTION_BASE_URL}/{settings.notion_api_version}/databases/{settings.input_notion_db_id_issues.get_secret_value()}/query"

    headers = {
        "Authorization": f"Bearer {settings.input_notion_api_key.get_secret_value()}",
        "Content-Type": "application/json",
        "Notion-Version": settings.default_notion_version,
    }

    payload = {"page_size": settings.input_config.notion_page_size}

    has_more = True
    next_cursor = None
    all_issues: dict[int, IssuePage] = {}

    logging.info("Fetching issues from Notion DB...")
    while has_more:
        if next_cursor:
            payload["start_cursor"] = next_cursor

        response = requests.post(url, json=payload, headers=headers)

        if response.status_code != 200:
            logging.error(f"Error: {response.json()}")
            break

        result = ResponseNotionIssues.model_validate(response.json())
        for issue in result.results:
            # Modify any open state to new-issue because all those open
            # issue pages are represented as new-issue when getting the
            # properties from the GitHub issue. The GitHub action does not
            # manage intermediate states between new-issue and completed
            # or not-planned.
            if (
                issue.properties.status.status.name
                in settings.input_config.notion_open_status
            ):
                issue.properties.status.status.name = (
                    settings.input_config.notion_new_issue
                )

            all_issues[issue.properties.number.number] = issue

        has_more = result.has_more
        next_cursor = result.next_cursor

        logging.info(
            f"Fetched {len(result.results)} issues -> Next cursor: {next_cursor}"
        )

    logging.info(f"Total issues fetched: {len(all_issues)}")

    return all_issues


def get_status_from_github_issue(issue: Issue, settings: Settings) -> str:
    closed_states = {
        "completed": settings.input_config.closed_state_map.completed,
        "not_planned": settings.input_config.closed_state_map.not_planed,
    }

    return (
        closed_states[issue.state_reason]
        if issue.state == "closed"
        else settings.input_config.notion_new_issue
    )


def get_properties_from_issue(issue: Issue, settings: Settings) -> IssuePageProps:
    all_properties = {
        "assignees": {
            "type": "multi_select",
            "multi_select": [
                {"name": assignee.login, "color": "default"}
                for assignee in issue.assignees
            ],
        },
        "labels": {
            "type": "multi_select",
            "multi_select": [
                {"name": label.name, "color": "gray"} for label in issue.labels
            ],
        },
        "number": {
            "type": "number",
            "number": issue.number,
        },
        "status": {
            "type": "status",
            "status": {"name": get_status_from_github_issue(issue, settings)},
        },
        "title": {
            "type": "title",
            "title": [
                {
                    "type": "text",
                    "text": {"content": issue.title},
                }
            ],
        },
        "url": {
            "type": "url",
            "url": issue.url.replace("api.", "").replace("/repos", ""),
        },
    }

    return IssuePageProps.model_validate(all_properties)


def get_properties_to_update(
    page_props: IssuePageProps, issue_props: IssuePageProps
) -> UpdateIssueProps | None:

    issue_props_dict = issue_props.model_dump(exclude={"due", "priority"})
    page_props_dict = page_props.model_dump(exclude={"due", "priority"})

    del issue_props_dict["status"]["status"]["color"]
    del page_props_dict["status"]["status"]["color"]

    update_props = {}

    for key, value in issue_props_dict.items():
        if value != page_props_dict.get(key):
            update_props[key] = value

    return UpdateIssueProps.model_validate(update_props)


def create_issue_page(properties: IssuePageProps, settings: Settings) -> None:
    url = f"{NOTION_BASE_URL}/{settings.notion_api_version}/pages"

    headers = {
        "Authorization": f"Bearer {settings.input_notion_api_key.get_secret_value()}",
        "Content-Type": "application/json",
        "Notion-Version": settings.default_notion_version,
    }

    payload = {
        "parent": {
            "database_id": settings.input_notion_db_id_issues.get_secret_value(),
        },
        "properties": properties.model_dump(exclude_none=True),
    }

    response = requests.post(url, json=payload, headers=headers)

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        logging.error(
            f"Failed to update issue {properties.number.number}. "
            f"HTTP {response.status_code}: {response.json().get("message", "Unknown error")}"
        )
        raise

    logging.info(
        f"Page for issue #{properties.number.number} successfully created in Notion DB"
    )


def update_issue_page(
    page: IssuePage,
    properties: UpdateIssueProps,
    settings: Settings,
):
    url = f"{NOTION_BASE_URL}/{settings.notion_api_version}/pages/{page.id.replace("-", "")}"

    headers = {
        "Authorization": f"Bearer {settings.input_notion_api_key.get_secret_value()}",
        "Content-Type": "application/json",
        "Notion-Version": settings.default_notion_version,
    }

    payload = {
        "parent": {
            "database_id": settings.input_notion_db_id_issues.get_secret_value(),
        },
        "properties": properties.model_dump(exclude_none=True),
    }

    response = requests.patch(url, json=payload, headers=headers)

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        logging.error(
            f"Failed to update issue {page.properties.number.number}. "
            f"HTTP {response.status_code}: {response.json().get("message", "Unknown error")}"
        )
        raise

    logging.info(
        f"Issue #{page.properties.number.number} {properties.model_dump(
            exclude_none=True
        ).keys()} properties successfully updated in Notion"
    )


def sync_issues(
    *, pages: dict[int, IssuePage], issues: PaginatedList[Issue], settings: Settings
) -> None:
    """Syncs GitHub issues and a Notion DB. Only synchronizes changes from GitHub, i.e., changing
    an issue from an open state to a closed state won't close the issue on GitHub, the issue
    will be assigned 'notion_new_issue' status.
    """
    logging.info("Synchronizing GitHub issues and Notion BD...")
    for issue in issues.reversed:
        logging.info(f"Checking issue #{issue.number}...")

        page = pages.get(issue.number, None)
        properties = get_properties_from_issue(issue, settings)

        if not page:
            logging.info(
                f"No page found for issue #{issue.number}, creating a new page..."
            )
            create_issue_page(properties, settings)
            continue

        update_props = get_properties_to_update(page.properties, properties)

        if not any(update_props.model_dump().values()):
            logging.info(f"Issue #{issue.number} already up to date in Notion DB")
            continue

        update_issue_page(page, update_props, settings)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    settings = Settings()
    logging.info(f"Config: {settings.model_dump_json()}")

    token = settings.input_github_token.get_secret_value()
    if not token:
        logging.error(
            "GitHub token is missing. Make sure GITHUB_TOKEN is set as an environment variable or passed as a secret"
        )
        sys.exit(1)

    g = Github(auth=Token(token))
    repo = g.get_repo(settings.github_repository)

    db_status_prop = fetch_notion_db_status_names(settings)
    settings.input_config.validate_config_against_db_status_prop(db_status_prop)

    notion_issues = get_notion_issues(settings=settings)

    # TODO: Implement since date
    logging.info("Fetching issues from GitHub...")
    github_issues = repo.get_issues(state="all")
    logging.info(f"Total issues fetched from GitHub: {github_issues.totalCount}")

    sync_issues(pages=notion_issues, issues=github_issues, settings=settings)

    g.close()
    logging.info("All done, bye!")
