#!/usr/bin/env python3

import requests
import trio
import sqlite3
import httpx
import re
import json
import browser_cookie3
import datetime
import argparse
import os
from urllib.parse import urlencode, urlparse
from dataclasses import dataclass
from collections.abc import AsyncGenerator
from bs4 import BeautifulSoup
from x_client_transaction.utils import handle_x_migration, get_ondemand_file_url
from x_client_transaction import ClientTransaction

DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15"

MAX_BLOCK_QUEUE_SIZE = 10

GQL_API_URL = 'https://twitter.com/i/api/graphql'
V1_API_URL = 'https://api.twitter.com/1.1'
V2_API_URL = 'https://twitter.com/i/api/2'

LOCAL_COOKIES = {
    'ct0': '',
    'auth_token': ''
}

FETCH_COOKIES_FROM_BROWSER = True
PREFFERED_BROWSER = 'safari'

THROTTLE_TIMEOUT = 15 * 60

DEFAULT_FEATURES = {
    'c9s_tweet_anatomy_moderator_badge_enabled': True,
    'responsive_web_home_pinned_timelines_enabled': True,
    'blue_business_profile_image_shape_enabled': True,
    'creator_subscriptions_tweet_preview_api_enabled': True,
    'freedom_of_speech_not_reach_fetch_enabled': True,
    'graphql_is_translatable_rweb_tweet_is_translatable_enabled': True,
    'graphql_timeline_v2_bookmark_timeline': True,
    'hidden_profile_likes_enabled': True,
    'highlights_tweets_tab_ui_enabled': True,
    'interactive_text_enabled': True,
    'longform_notetweets_consumption_enabled': True,
    'longform_notetweets_inline_media_enabled': True,
    'longform_notetweets_rich_text_read_enabled': True,
    'longform_notetweets_richtext_consumption_enabled': True,
    'profile_foundations_tweet_stats_enabled': True,
    'profile_foundations_tweet_stats_tweet_frequency': True,
    'responsive_web_birdwatch_note_limit_enabled': True,
    'responsive_web_edit_tweet_api_enabled': True,
    'responsive_web_enhance_cards_enabled': False,
    'responsive_web_graphql_exclude_directive_enabled': True,
    'responsive_web_graphql_skip_user_profile_image_extensions_enabled': False,
    'responsive_web_graphql_timeline_navigation_enabled': True,
    'responsive_web_media_download_video_enabled': False,
    'responsive_web_text_conversations_enabled': False,
    'responsive_web_twitter_article_data_v2_enabled': True,
    'responsive_web_twitter_article_tweet_consumption_enabled': False,
    'responsive_web_twitter_blue_verified_badge_is_enabled': True,
    'rweb_lists_timeline_redesign_enabled': True,
    'spaces_2022_h2_clipping': True,
    'spaces_2022_h2_spaces_communities': True,
    'standardized_nudges_misinfo': True,
    'subscriptions_verification_info_verified_since_enabled': True,
    'tweet_awards_web_tipping_enabled': False,
    'tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled': True,
    'tweetypie_unmention_optimization_enabled': True,
    'verified_phone_label_enabled': False,
    'vibe_api_enabled': True,
    'view_counts_everywhere_api_enabled': True
}

DEFAULT_VARIABLES = {
    'count': 5,
    'withSafetyModeUserFields': True,
    'includePromotedContent': True,
    'withQuickPromoteEligibilityTweetFields': True,
    'withVoice': True,
    'withV2Timeline': True,
    'withDownvotePerspective': False,
    'withBirdwatchNotes': True,
    'withCommunity': True,
    'withSuperFollowsUserFields': True,
    'withReactionsMetadata': False,
    'withReactionsPerspective': False,
    'withSuperFollowsTweetFields': True,
    'isMetatagsQuery': False,
    'withReplays': True,
    'withClientEventToken': False,
    'withAttachments': True,
    'withConversationQueryHighlights': True,
    'withMessageQueryHighlights': True,
    'withMessages': True,
}

def find_key(obj: any, key: str, ignore: list[str] | None = None) -> list:
    """
    Find all values of a given key within a nested dict or list of dicts

    Most data of interest is nested, and sometimes defined by different schemas.
    It is not worth our time to enumerate all absolute paths to a given key, then update
    the paths in our parsing functions every time Twitter changes their API.
    Instead, we recursively search for the key here, then run post-processing functions on the results.

    @param obj: dictionary or list of dictionaries
    @param key: key to search for
    @return: list of values
    """

    def helper(obj: any, key: str, L: list) -> list:
        if not obj:
            return L

        if isinstance(obj, list):
            for e in obj:
                L.extend(helper(e, key, []))
            return L

        if isinstance(obj, dict) and obj.get(key):
            L.append(obj[key])

        if isinstance(obj, dict) and obj:
            for k in obj:
                if ignore is None or k not in ignore:
                    L.extend(helper(obj[k], key, []))
        return L

    return helper(obj, key, [])

def find_single_key_opt(obj: any, key: str, ignore: list[str] | None = None) -> dict | None:
    results = find_key(obj, key, ignore)
    if len(results) == 1:
        return results[0]
    elif len(results) == 0:
        return None
    else:
        raise ValueError(f"Expected a single value for key '{key}', but found {len(results)} values")
    
def find_single_key(obj: any, key: str, ignore: list[str] | None = None) -> dict | None:
    results = find_key(obj, key, ignore)
    if len(results) == 1:
        return results[0]
    else:
        raise ValueError(f"Expected a single value for key '{key}', but found {len(results)} values")

class TransactionIdGenerator:
    def __init__(self, user_agent):
        headers = {"Authority": "x.com",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Referer": "https://x.com",
            "User-Agent": user_agent,
            "X-Twitter-Active-User": "yes",
            "X-Twitter-Client-Language": "en"}
            
        session = requests.Session()
        session.headers = headers
        response_twit = handle_x_migration(session)

        home_page = session.get(url="https://x.com")
        home_page_response = BeautifulSoup(home_page.content, 'html.parser')
        ondemand_file_url = get_ondemand_file_url(response=home_page_response)
        ondemand_file = session.get(url=ondemand_file_url)
        ondemand_file_response = BeautifulSoup(ondemand_file.content, 'html.parser')

        self.inner = ClientTransaction(response_twit, ondemand_file_response)

    def generate_tid(self, url: str, method: str = 'GET') -> str:
        return self.inner.generate_transaction_id(method, urlparse(url).path)

@dataclass
class BlockReason:
    MATCH_KEYWORD = 'kw'
    SUBSCRIBED_TO = 'fw'

@dataclass
class MiscKeys:
    CURRENT_OP = 'rop'

@dataclass
class TwtCookies:
    ct0: str
    auth_token: str

    def to_dict(self) -> dict:
        return {
            'ct0': self.ct0,
            'auth_token': self.auth_token
        }
    
    def is_empty(self) -> bool:
        return not self.ct0 or not self.auth_token

@dataclass
class User:
    id: str
    username: str
    handle: str
    description: str
    verified: bool
    created_at: datetime.datetime
    activity_count: int
    followers_count: int
    already_blocked: bool

    def __eq__(self, other):
        if isinstance(other, User):
            return self.id == other.id
        return False
    
    def __hash__(self):
        return hash(self.id)

@dataclass
class Tweet:
    id: int
    author: User
    contents: str
    views: int
    created_at: datetime.datetime

    def __eq__(self, other):
        if isinstance(other, Tweet):
            return self.id == other.id
        return False
    
    def __hash__(self):
        return hash(self.id)

class TwtClient:
    def __init__(self, cookies: TwtCookies, user_agent: str = DEFAULT_USER_AGENT):
        self.tid_generator = TransactionIdGenerator(user_agent)
        self.user_agent = user_agent
        self.cookies = cookies
        self.http = httpx.AsyncClient(cookies=cookies.to_dict(), follow_redirects=True)

    def build_headers(self, url: str, content_type: str = 'application/json', method: str = 'GET') -> dict:
        return {
            'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
            'content-type': content_type,
            'cookie': f"ct0={self.cookies.ct0};auth_token={self.cookies.auth_token}",
            'referer': 'https://x.com/',
            'user-agent': self.user_agent,
            'x-csrf-token': self.cookies.ct0,
            'x-twitter-auth-type': 'OAuth2Session',
            'x-guest-token': '',
            'x-twitter-active-user': 'yes',
            'x-twitter-client-language': 'en',
            'x-client-transaction-id': self.tid_generator.generate_tid(url, method),
        }
    
    async def v1(self, path: str, params: dict) -> tuple[int, dict]:
        url = f'{V1_API_URL}/{path}'
        headers = self.build_headers(url, content_type='application/x-www-form-urlencoded', method='POST')

        r = await self.http.post(url, headers=headers, params=urlencode(params))

        try:
            content = r.json()
        except:
            content = { }

        return (r.status_code, content)

    async def block(self, user: User) -> tuple[int, dict]:
        return await self.v1('blocks/create.json', { 'user_id': user.id })

    @staticmethod
    def parse_user(raw: dict) -> User:
        return User(
            id=int(raw['rest_id']),
            username=raw['legacy']['name'],
            handle=raw['legacy']['screen_name'],
            description=raw['legacy']['description'],
            verified=raw['legacy']['verified'],
            created_at=datetime.datetime.strptime(
                raw['legacy']['created_at'],
                '%a %b %d %H:%M:%S +0000 %Y'
            ),
            activity_count=int(raw['legacy']['statuses_count']),
            followers_count=int(raw['legacy']['followers_count']),
            already_blocked=raw['legacy']['blocking'] == True if 'blocking' in raw['legacy'] else False
        )
            
    @staticmethod
    def parse_tweets(entries: list[dict]) -> list[Tweet]:
        tweets = []
        for entry in entries:
            try:
                tweet_info = find_single_key_opt(entry, 'tweet_results')['result']

                if not tweet_info:
                    continue
                elif tweet_info['__typename'] == 'TweetWithVisibilityResults':
                    tweet_info = tweet_info['tweet']

                user_info = find_single_key_opt(tweet_info, 'user_results', ignore=['quoted_status_result', 'additional_media_info'])['result']

                if not user_info:
                    continue

                tweets.append(Tweet(
                    id=int(tweet_info['rest_id']),
                    author=TwtClient.parse_user(user_info),
                    contents=tweet_info['legacy']['full_text'],
                    views=int(tweet_info['views']['count']) if 'views' in tweet_info and 'count' in tweet_info['views'] else 0,
                    created_at=datetime.datetime.strptime(
                        tweet_info['legacy']['created_at'],
                        '%a %b %d %H:%M:%S +0000 %Y'
                    )
                ))
            except Exception as e:
                print(f"Error parsing tweet entry: {e}, entry: {entry}")
                exit(1)
        
        return tweets
    
    async def await_cookies_update(self):
        while True:
            nc = get_cookies(allows_none=True)

            if nc.is_empty() or nc == self.cookies:
                await trio.sleep(1)
            else:
                self.cookies = nc
                trio.sleep(0)
                break

    async def search(self, query: str, category: str) -> AsyncGenerator[tuple[int, list[Tweet]], None]:
        endpoint_url = f'{GQL_API_URL}/nK1dw4oV3k4w5TdtcAdSww/SearchTimeline'
        params = {
            'variables': {
                'count': 4,
                'querySource': 'typed_query',
                'rawQuery': query,
                'product': category
            },
            'features': DEFAULT_FEATURES,
            'fieldToggles': { 'withArticleRichContentState': False },
        }

        cursor = None

        while True:
            if cursor:
                params['variables']['cursor'] = cursor

            headers = self.build_headers(endpoint_url)
            r = await self.http.get(endpoint_url, headers=headers, params={k: json.dumps(v) for k, v in params.items()})

            if r.status_code >= 400:
                yield (r.status_code, [ ])
                continue

            data = r.json()
            raw_entries = find_single_key(data, 'entries')
            entries = [e for e in raw_entries if e['entryId'].startswith('tweet-')]
            cursor = next((e['content']['value'] for e in raw_entries if e['entryId'].startswith('cursor-bottom-')), None)

            if len(entries) == 0 or cursor is None:
                yield (r.status_code, [ ])
                break
            else:
                tweets = self.parse_tweets(entries)
                yield (r.status_code, tweets)

    async def get_user_by_handle(self, handle: str) -> tuple[int, User | None]:
        endpoint_url = f'{GQL_API_URL}/sLVLhk0bGj3MVFEKTdax1w/UserByScreenName'
        headers = self.build_headers(endpoint_url)

        params = {
            'variables': {
                'screen_name': handle,
            },
            'features': DEFAULT_FEATURES,
        }

        r = await self.http.get(endpoint_url, headers=headers, params={k: json.dumps(v) for k, v in params.items()})

        if r.status_code == 200:
            data = r.json()['data']
            if 'user' not in data:
                return (200, None)
            else:
                return (r.status_code, TwtClient.parse_user(data['user']['result']))
        else:
            return (r.status_code, None)
        
    async def get_user_by_id(self, id: int) -> tuple[int, User | None]:
        endpoint_url = f'{GQL_API_URL}/GazOglcBvgLigl3ywt6b3Q/UserByRestId'
        headers = self.build_headers(endpoint_url)

        params = {
            'variables': {
                'userId': id,
            },
            'features': DEFAULT_FEATURES,
        }

        r = await self.http.get(endpoint_url, headers=headers, params={k: json.dumps(v) for k, v in params.items()})

        if r.status_code == 200:
            data = r.json()['data']
            if 'user' not in data:
                return (200, None)
            else:
                return (r.status_code, TwtClient.parse_user(data['user']['result']))
        else:
            return (r.status_code, None)

    async def fetch_followers(self, user: User, initial_cursor: str | None = None) -> AsyncGenerator[tuple[int, list[User], str | None], None]:
        endpoint_url = f'{GQL_API_URL}/pd8Tt1qUz1YWrICegqZ8cw/Followers'

        params = {
            'variables': DEFAULT_VARIABLES | {
                'userId': user.id,
                'count': 100,
            },
            'features': DEFAULT_FEATURES,
        }

        cursor = initial_cursor

        while True:
            if cursor:
                params['variables']['cursor'] = cursor

            headers = self.build_headers(endpoint_url)
            r = await self.http.get(endpoint_url, headers=headers, params={k: json.dumps(v) for k, v in params.items()})

            if r.status_code >= 400:
                yield (r.status_code, [ ], None)
                continue

            data = r.json()
            raw_entries = find_single_key(data, 'entries')
            entries = [e for e in raw_entries if e['entryId'].startswith('user-')]
            cursor = next((e['content']['value'] for e in raw_entries if e['entryId'].startswith('cursor-bottom-')), None)

            if len(entries) == 0 or cursor is None:
                yield (r.status_code, [ ], None)
                break
            else:
                def get_udata(e: dict) -> dict:
                    try:
                        return e['content']['itemContent']['user_results']['result']
                    except KeyError as err:
                        None

                yield (r.status_code, [ self.parse_user(get_udata(e)) for e in entries if get_udata(e) is not None ], cursor)


def get_cookies(allows_none: bool = False) -> TwtCookies:
    if FETCH_COOKIES_FROM_BROWSER:
        browsers = {
            'safari': browser_cookie3.safari,
            'chrome': browser_cookie3.chrome,
            'edge': browser_cookie3.edge,
            'firefox': browser_cookie3.firefox,
        }
        
        try:
            if PREFFERED_BROWSER in browsers:
                auth_token = None
                ct0 = None

                for entry in browsers[PREFFERED_BROWSER](domain_name='x.com'):
                    if entry.name == 'auth_token':
                        auth_token = entry.value
                    elif entry.name == 'ct0':
                        ct0 = entry.value

                if auth_token and ct0:
                    return TwtCookies(ct0, auth_token)
                elif allows_none:
                    return TwtCookies(ct0='', auth_token='')
                else:
                    print(f"Cookies 'ct0' and 'auth_token' not found in {PREFFERED_BROWSER}.")
                    exit(1)
            else:
                print(f"Unsupported browser: {PREFFERED_BROWSER}")
                exit(1)
        except Exception as e:
            print(f"Error retrieving cookies from {PREFFERED_BROWSER}: {e}")
            exit(1)
    else:
        if LOCAL_COOKIES['ct0'] and LOCAL_COOKIES['auth_token']:
            return TwtCookies(
                ct0=LOCAL_COOKIES['ct0'],
                auth_token=LOCAL_COOKIES['auth_token']
            )
        else:
            print("Local cookies are not set. Please set 'ct0' and 'auth_token' in LOCAL_COOKIES or enable FETCH_COOKIES_FROM_BROWSER.")
            exit(1)

def init_db():
    db_path = 'storage.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            reason TEXT NOT NULL,
            match TEXT NOT NULL,
            date TEXT NOT NULL,
            blocked INTEGER NOT NULL DEFAULT 0,
            premium INT DEFAULT NULL,
            creation_date TEXT DEFAULT NULL,
            posts INT DEFAULT NULL,
            followers INT DEFAULT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS misc (
            key TEXT NOT NULL PRIMARY KEY,
            tag TEXT NOT NULL,
            value TEXT,
            ext TEXT
        )
    ''')

    cursor.close()
    return conn

local_db = init_db()

def save_block(user: User, reason: str, match: str):
    cursor =  local_db.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO users (id, name, reason, match, premium, creation_date, posts, followers, date, blocked)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, date('now'), 1)
    ''', (user.id, user.handle, reason, match, user.verified, f"{user.created_at:%d/%m/%Y}", user.activity_count, user.followers_count))
    cursor.close()
    local_db.commit()

def save_non_blocked_users(users: list[User], reason: str, match: str):
    cursor = local_db.cursor()
    for user in users:
        cursor.execute('''
            INSERT OR IGNORE INTO users (id, name, reason, match, date, blocked)
            VALUES (?, ?, ?, ?, date('now'), 0)
        ''', (user.id, user.handle, reason, match))
    cursor.close()
    local_db.commit()

def get_blocked_count_by(reason: str, match: str) -> int:
    cursor = local_db.cursor()
    cursor.execute('''
        SELECT COUNT(*) FROM users WHERE reason = ? AND match = ?
    ''', (reason, match))
    count = cursor.fetchone()[0]
    cursor.close()
    return count

@dataclass
class RunningOp:
    username: str
    user_id: int
    cursor: str | None

class OpManager:
    @staticmethod
    def open(user: User, cursor: str | None = None):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            INSERT OR REPLACE INTO misc (key, tag, value)
            VALUES (?, ?, ?)
        ''', (MiscKeys.CURRENT_OP, f'{user.handle}/{user.id}', cursor))
        db_cursor.close()
        local_db.commit()

    @staticmethod
    def close():
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            DELETE FROM misc WHERE key = ?
        ''', (MiscKeys.CURRENT_OP,))
        db_cursor.close()
        local_db.commit()

    @staticmethod
    def update_cursor(cursor: str):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            UPDATE misc SET value = ? WHERE key = ?
        ''', (cursor, MiscKeys.CURRENT_OP))
        db_cursor.close()
        local_db.commit()

    @staticmethod
    def get_current() -> RunningOp | None:
        db_cursor = local_db.cursor()
        db_cursor.execute('SELECT tag, value FROM misc WHERE key = ?', (MiscKeys.CURRENT_OP,))
        row = db_cursor.fetchone()
        db_cursor.close()

        if row:
            tag, value = row
            parts = tag.split('/')
            if len(parts) == 2:
                username = parts[0]
                user_id = int(parts[1])
                return RunningOp(username, user_id, cursor=value)
            else:
                print(f"Invalid tag format: {tag}")
                return None
        else:
            return None

def handle_error_code_internal(status_code: int, error: str):
    if status_code == 401:
        print(f"--- Unauthorized access, please re-authenticate: https://x.com/logout")
    elif status_code == 403:
        print(f"--- Forbidden access, please re-authenticate (captcha ?): https://x.com/logout")
    elif status_code == 404:
        print(f"Resource not found: {error}")
    elif status_code == 500:
        print(f"Internal server error: {error}")
    else:
        print(f"Unexpected error (status code {status_code}): {error}")

async def handle_error_code(client: TwtClient, status_code: int, error: str) -> bool:
    if status_code == 429:
        print("--- Rate limit exceeded, waiting a bit...") 
        await trio.sleep(THROTTLE_TIMEOUT)
        return True
    elif (status_code == 401 or status_code == 403):
        print("--- Unauthorized access, please re-authenticate: https://x.com/logout")
        await client.await_cookies_update()
        return True
    elif status_code >= 400:
        handle_error_code_internal(status_code, error)
        exit(1)
    else:
        await trio.sleep(0)
        return False

async def handle_error_stack(client: TwtClient, error_stack: dict[int, str]):
    should_wait = False
    should_refresh_cookies = False

    for status_code, error in error_stack.items():
        if status_code == 429:
            should_wait = True
        elif status_code == 666:
            print(f"Error while blocking a user: {error}")
            exit(1)
        elif status_code == 401 or status_code == 403:
            should_refresh_cookies = True
        else:
            handle_error_code_internal(status_code, error)
            exit(1)

    if should_refresh_cookies:
        print(f"--- Unauthorized access, please re-authenticate: https://x.com/logout")
        await client.await_cookies_update()
    elif should_wait:
        print("--- Rate limit exceeded, waiting a bit...") 
        await trio.sleep(THROTTLE_TIMEOUT)

async def block_task(client: TwtClient, queue: trio.Semaphore, user: User, results: dict, reason: str, match: str):
    async with queue:
        try:
            status_code, res = await client.block(user)

            if status_code == 200:
                save_block(user, reason, match)

            results[user.id] = [status_code, res]
        except Exception as e:
            results[user.id] = [400, str(e)]

def print_stats():
    cursor = local_db.cursor()

    cursor.execute('SELECT COUNT(*) FROM users WHERE date = date("now")')
    daily_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM users')
    total_count = cursor.fetchone()[0]

    cursor.close()

    print(f"{daily_count} users blocked today (out of {total_count} total)")

parser = argparse.ArgumentParser(description="Block users on Twitter based on search keywords.")
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output.')

cmd = parser.add_subparsers(dest='command', required=True)

cmd_kw = cmd.add_parser('kw', help='Block users based on a keyword search.')
cmd_kw.add_argument('query', type=str, help='The keyword to search for users to block.')

cmd_fw = cmd.add_parser('fw', help='Block followers of a given user.')
fw_params = cmd_fw.add_mutually_exclusive_group(required=True)
fw_params.add_argument('-n', '--name', type=str, help='The target user handle')
fw_params.add_argument('-i', '--id', type=str, help='The target user ID')
fw_params.add_argument('-c', '--continue', dest='continue_', action='store_true', help='Continue the previous search/block operation if possible.')

args = parser.parse_args()

async def cmd_kw(client: TwtClient, queue: trio.Semaphore):
    total_blocked = 0
    total_search = 0

    for category in ['Latest', 'Top']:
        print(f"Querying: {args.query}/{category}...")
        async for status_code, tweets in client.search(args.query, category):
            if await handle_error_code(client, status_code, "Failed to fetch tweets"):
                continue

            total_search += 1
            authors = { tweet.author.id: tweet.author for tweet in tweets if tweet.author.already_blocked is False }

            if len(authors) == 0:
                continue

            if args.verbose:
                print(f"[kw/{category}] Fetched {len(authors)} new tweet authors")

            while len(authors):
                results = { }

                async with trio.open_nursery() as nursery:
                    for author in authors.values():
                        nursery.start_soon(block_task, client, queue, author, results, BlockReason.MATCH_KEYWORD, args.query)

                error_stack = { }

                for author_id, author in list(authors.items()):
                    if author_id in results:
                        status_code, res = results[author_id]
                        if status_code == 200:
                            total_blocked += 1
                            print(f"  * blocked {author.id:>19} @{author.handle:<16} (created on {author.created_at:%d/%m/%Y} - {author.activity_count:>6} posts)")
                            authors.pop(author_id)
                        else:
                            error_stack[status_code] = res
                    else:
                        print(f"Error: No task result for user {author.handle} (ID: {author_id})")
                        exit(1)
                
                await handle_error_stack(client, error_stack)
    
    if total_blocked > 0:
        print(f"\nBlocked {total_blocked} users using {total_search} search call.")

async def cmd_fw(client: TwtClient, queue: trio.Semaphore):
    initial_cursor = None
    current_op = OpManager.get_current()
    target_user = None

    while True:
        if args.continue_:
            if current_op is None:
                print("No previous operation found. Please specify a new user.")
                exit(1)
            else:
                res_code, target_user = await client.get_user_by_id(int(current_op.user_id))
        elif args.name:
            res_code, target_user = await client.get_user_by_handle(args.name.strip('@'))
        else:
            res_code, target_user = await client.get_user_by_id(int(args.id))

        if await handle_error_code(client, res_code, 'Failed to fetch user information'):
            continue

        if target_user is None:
            print(f"User not found: {args.name or args.id}")
            exit(1)
        else:
            break

    if current_op is not None and target_user.id == current_op.user_id:
        initial_cursor = current_op.cursor

    if initial_cursor is None:
        print(f"Fetching followers of @{target_user.handle} ({target_user.id})...")
        OpManager.open(target_user)
    else:
        current_count = get_blocked_count_by(BlockReason.SUBSCRIBED_TO, target_user.handle)
        print(f"Continuing previous blocking operation for @{target_user.handle} ({target_user.id})...")
        print(f"  * Already blocked {current_count} followers out of {target_user.followers_count} ({current_count / target_user.followers_count * 100:.2f}%)")

    total_blocked = 0

    async for status_code, raw_followers, current_cursor in client.fetch_followers(target_user, initial_cursor):
        if await handle_error_code(client, status_code, "Failed to fetch followers"):
            continue

        if len(raw_followers) == 0:
            OpManager.close()
            block_count = get_blocked_count_by(BlockReason.SUBSCRIBED_TO, target_user.handle)
            print(f"End of the follower list reached, blocked {block_count} users.")
            break

        followers = { follower.id: follower for follower in raw_followers if follower.already_blocked is False }
        if len(followers) == 0:
            continue

        if args.verbose:
            print(f"[fw/{target_user.handle}] Fetched {len(followers)} new followers (cursor: {current_cursor})")

        while len(followers):
            results = { }

            async with trio.open_nursery() as nursery:
                for follower in followers.values():
                    nursery.start_soon(block_task, client, queue, follower, results, BlockReason.SUBSCRIBED_TO, target_user.handle)
            
            error_stack = { }

            for uid, follower in list(followers.items()):
                if uid in results:
                    status_code, res = results[uid]
                    if status_code == 200:
                        total_blocked += 1
                        print(f"  * blocked {follower.id:>19} @{follower.handle:<16} (created on {follower.created_at:%d/%m/%Y} - {follower.activity_count:>6} posts)")
                        followers.pop(uid)
                    else:
                        error_stack[status_code] = res
                else:
                    print(f"Error: No task result for user {follower.handle} (ID: {uid})")
                    exit(1)
            
            await handle_error_stack(client, error_stack)

        OpManager.update_cursor(current_cursor)

async def main():
    print_stats()
    client = TwtClient(get_cookies())
    block_sem = trio.Semaphore(MAX_BLOCK_QUEUE_SIZE)

    if args.command == 'kw':
        await cmd_kw(client, block_sem)
    elif args.command == 'fw':
        await cmd_fw(client, block_sem)

if __name__ == "__main__":
    trio.run(main)
