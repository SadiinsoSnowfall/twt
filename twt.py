#!/usr/bin/env python3

import requests
import trio
import sqlite3
import httpx
import json
import browser_cookie3
import datetime
import argparse
from urllib.parse import urlencode, urlparse
from dataclasses import dataclass
from collections.abc import AsyncGenerator
from bs4 import BeautifulSoup
from x_client_transaction.utils import handle_x_migration, get_ondemand_file_url
from x_client_transaction import ClientTransaction

DEFAULT_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15"

MAX_BLOCK_QUEUE_SIZE = 100

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
    "articles_preview_enabled": True,
    "blue_business_profile_image_shape_enabled": True,
    "c9s_tweet_anatomy_moderator_badge_enabled": True,
    "communities_web_enable_tweet_community_results_fetch": True,
    "creator_subscriptions_quote_tweet_preview_enabled": False,
    "creator_subscriptions_tweet_preview_api_enabled": True,
    "freedom_of_speech_not_reach_fetch_enabled": True,
    "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
    "graphql_timeline_v2_bookmark_timeline": True,
    "hidden_profile_likes_enabled": True,
    "highlights_tweets_tab_ui_enabled": True,
    "interactive_text_enabled": True,
    "longform_notetweets_consumption_enabled": True,
    "longform_notetweets_inline_media_enabled": True,
    "longform_notetweets_rich_text_read_enabled": True,
    "longform_notetweets_richtext_consumption_enabled": True,
    "payments_enabled": False,
    "premium_content_api_read_enabled": False,
    "profile_foundations_tweet_stats_enabled": True,
    "profile_foundations_tweet_stats_tweet_frequency": True,
    "profile_label_improvements_pcf_label_in_post_enabled": True,
    "responsive_web_birdwatch_note_limit_enabled": True,
    "responsive_web_edit_tweet_api_enabled": True,
    "responsive_web_enhance_cards_enabled": False,
    "responsive_web_graphql_exclude_directive_enabled": True,
    "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
    "responsive_web_graphql_timeline_navigation_enabled": True,
    "responsive_web_grok_analysis_button_from_backend": False,
    "responsive_web_grok_analyze_button_fetch_trends_enabled": False,
    "responsive_web_grok_analyze_post_followups_enabled": True,
    "responsive_web_grok_image_annotation_enabled": True,
    "responsive_web_grok_share_attachment_enabled": True,
    "responsive_web_grok_show_grok_translated_post": False,
    "responsive_web_home_pinned_timelines_enabled": True,
    "responsive_web_jetfuel_frame": False,
    "responsive_web_media_download_video_enabled": False,
    "responsive_web_text_conversations_enabled": False,
    "responsive_web_twitter_article_data_v2_enabled": True,
    "responsive_web_twitter_article_tweet_consumption_enabled": False,
    "responsive_web_twitter_blue_verified_badge_is_enabled": True,
    "rweb_lists_timeline_redesign_enabled": True,
    "rweb_tipjar_consumption_enabled": True,
    "rweb_video_screen_enabled": False,
    "spaces_2022_h2_clipping": True,
    "spaces_2022_h2_spaces_communities": True,
    "standardized_nudges_misinfo": True,
    "subscriptions_verification_info_verified_since_enabled": True,
    "tweet_awards_web_tipping_enabled": False,
    "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": True,
    "tweetypie_unmention_optimization_enabled": True,
    "verified_phone_label_enabled": False,
    "vibe_api_enabled": True,
    "view_counts_everywhere_api_enabled": True,
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

def elapsed_ms(r: httpx.Response) -> str:
    elapsed = r.elapsed.total_seconds() * 1000
    return f"{elapsed:.0f}ms"

def get_safe(raw: dict, path: list[str]) -> any:
    for key in path:
        if key in raw:
            raw = raw[key]
        else:
            return None
        
    return raw

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
    BLOCK_LIST = 'bl'

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
    
    async def v1(self, path: str, params: dict) -> tuple[int, dict, httpx.Response]:
        url = f'{V1_API_URL}/{path}'
        headers = self.build_headers(url, content_type='application/x-www-form-urlencoded', method='POST')

        r = await self.http.post(url, headers=headers, params=urlencode(params))

        try:
            content = r.json()
        except:
            content = { }

        return (r.status_code, content, r)

    async def block(self, user: User) -> tuple[int, dict, httpx.Response]:
        return await self.v1('blocks/create.json', { 'user_id': user.id })

    @staticmethod
    def parse_user(raw: dict) -> User:
        try:
            username = get_safe(raw, ['legacy', 'name']) or get_safe(raw, ['core', 'name'])
            handle = get_safe(raw, ['legacy', 'screen_name']) or get_safe(raw, ['core', 'screen_name'])
            description = get_safe(raw, ['legacy', 'description']) or ''
            created_at = get_safe(raw, ['legacy', 'created_at']) or get_safe(raw, ['core', 'created_at'])

            if not handle:
                raise ValueError(f"Handle is missing in {raw}")
            
            if not created_at:
                raise ValueError(f"Created at date is missing in {raw}")

            if 'relationship_perspectives' in raw:
                tmp = raw['relationship_perspectives']
                already_blocked = tmp['blocking'] if 'blocking' in tmp else False
            else:
                already_blocked = raw['legacy']['blocking'] if 'legacy' in raw and 'blocking' in raw['legacy'] else False

            return User(
                id=int(raw['rest_id']),
                username=username,
                handle=handle,
                description=description,
                verified=raw['is_blue_verified'],
                created_at=datetime.datetime.strptime(
                    created_at,
                    '%a %b %d %H:%M:%S +0000 %Y'
                ),
                activity_count=int(raw['legacy']['statuses_count']),
                followers_count=int(raw['legacy']['followers_count']),
                already_blocked=already_blocked
            )
        except KeyError as e:
            print(f"Error parsing user data: {e}, raw data: {raw}") 
            raise e
            
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
        if args.ring:
            for  _ in range(3):
                print('\a', end='', flush=True)
                await trio.sleep(0.1)

        while True:
            nc = get_cookies(allows_none=True)

            if nc.is_empty() or nc == self.cookies:
                await trio.sleep(0.5)
            else:
                self.cookies = nc
                await trio.sleep(0)
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
        
    async def get_users_by_ids(self, ids: list[int]) -> AsyncGenerator[tuple[int, list[User]]]:
        endpoint_url = f'{GQL_API_URL}/OJBgJQIrij6e3cjqQ3Zu1Q/UsersByRestIds'
        max_batch_size = 200

        for i in range(0, len(ids), max_batch_size):
            headers = self.build_headers(endpoint_url)
            params = {
                'variables': {
                    'userIds': ids[i:i + max_batch_size],
                },
                'features': DEFAULT_FEATURES,
            }

            r = await self.http.get(endpoint_url, headers=headers, params={k: json.dumps(v) for k, v in params.items()})

            if r.status_code == 200:
                data = r.json()['data']['users']
                users = [ self.parse_user(raw['result']) for raw in data if 'result' in raw and raw['result']['__typename'] == 'User' ]
                yield (r.status_code, users)
            else:
                yield (r.status_code, [ ])
        
    async def _fetch_followers_inner(self, user: User, endpoint: str, initial_cursor: str | None = None) -> AsyncGenerator[tuple[int, list[User], str | None], None]:
        endpoint_url = f'{GQL_API_URL}/{endpoint}'

        params = {
            'variables': DEFAULT_VARIABLES | {
                'userId': user.id,
                'count': 200,
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

            if cursor.endswith('|0'):
                yield (r.status_code, [ ], None)
                break
            else:
                def get_udata(e: dict) -> dict:
                    try:
                        raw = e['content']['itemContent']['user_results']['result']
                        if raw['__typename'] == 'UserUnavailable':
                            return None
                        else:
                            return self.parse_user(raw)
                    except KeyError as err:
                        None

                entries = [ get_udata(e) for e in entries ]
                yield (r.status_code, [ u for u in entries if u is not None ], cursor)

    def fetch_verified_followers(self, user: User, initial_cursor: str | None = None) -> AsyncGenerator[tuple[int, list[User], str | None], None]:
        return self._fetch_followers_inner(user, 'qKjNcwA6qZssapgGkylGdA/BlueVerifiedFollowers', initial_cursor)
    
    def fetch_followers(self, user: User, initial_cursor: str | None = None) -> AsyncGenerator[tuple[int, list[User], str | None], None]:
        return self._fetch_followers_inner(user, 'pd8Tt1qUz1YWrICegqZ8cw/Followers', initial_cursor)
    
    async def fetch_own_block_list(self, initial_cursor: str | None = None) -> AsyncGenerator[tuple[int, list[User], str | None], None]:
        endpoint_url = f'{GQL_API_URL}/wKSrEpYdqj2-VMkH9zPMBg/BlockedAccountsAll'

        params = {
            'variables': DEFAULT_VARIABLES | {
                'count': 1000,
                "includePromotedContent": False
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

            if cursor.endswith('|0'):
                yield (r.status_code, [ ], None)
                break
            else:
                def get_udata(e: dict) -> dict:
                    try:
                        raw = e['content']['itemContent']['user_results']['result']
                        if raw['__typename'] == 'UserUnavailable':
                            return None
                        else:
                            return self.parse_user(raw)
                    except KeyError as err:
                        None
                
                entries = [ get_udata(e) for e in entries ]
                yield (r.status_code, [ u for u in entries if u is not None ], cursor)

    
    async def fetch_mixed_followers(self, user: User, initial_cursor: str | None = None, force_skip_verified: bool = False) -> AsyncGenerator[tuple[int, list[User], str | None], None]:
        vtag = 'verified+'
        had_verified = False
        
        if initial_cursor is None:
            had_verified = True
        elif initial_cursor.startswith(vtag):
            had_verified = True
            initial_cursor = initial_cursor[len(vtag):]
        
        if had_verified and not force_skip_verified:
            async for status_code, raw_followers, cursor in self.fetch_verified_followers(user, initial_cursor):
                if status_code == 200 and len(raw_followers) == 0:
                    break
                elif cursor is None:
                    yield (status_code, raw_followers, None)
                else:
                    yield (status_code, raw_followers, vtag + cursor)

        async for status_code, raw_followers, cursor in self.fetch_followers(user, initial_cursor):
             yield (status_code, raw_followers, cursor)

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
            premium INT NOT NULL,
            creation_date TEXT NOT NULL,
            posts INT NOT NULL,
            followers INT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS running_ops (
            id int not null primary key,
            name text not null,
            cursor text null,
            count int not null default 0,
            done int not null default 0
        )
    ''')

    cursor.close()
    return conn

local_db = init_db()

def save_block(user: User, reason: str, match: str):
    cursor =  local_db.cursor()
    cursor.execute('''
        INSERT INTO users (id, name, reason, match, premium, creation_date, posts, followers, date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, date('now'))
    ''', (user.id, user.handle, reason, match, user.verified, f"{user.created_at:%Y-%m-%d}", user.activity_count, user.followers_count))
    cursor.close()
    local_db.commit()

def save_blocks(user: list[User], reason: str, match: str):
    cursor =  local_db.cursor()
    cursor.executemany('''
        INSERT INTO users (id, name, reason, match, premium, creation_date, posts, followers, date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, date('now'))
    ''', [(u.id, u.handle, reason, match, u.verified, f"{u.created_at:%Y-%m-%d}", u.activity_count, u.followers_count) for u in user])
    cursor.close()

def get_blocked_count_by_ex(reason: str, match: str) -> int:
    cursor = local_db.cursor()
    cursor.execute('''
        SELECT COUNT(*) FROM users WHERE reason = ? AND match = ?
    ''', (reason, match))
    count = cursor.fetchone()[0]
    cursor.close()
    return count

def get_blocked_count_by(reason: str) -> int:
    cursor = local_db.cursor()
    cursor.execute('''
        SELECT COUNT(*) FROM users WHERE reason = ?
    ''', (reason,))
    count = cursor.fetchone()[0]
    cursor.close()
    return count

@dataclass
class RunningOp:
    username: str
    user_id: int
    cursor: str | None
    count: int
    done: bool

class OpManager:
    @staticmethod
    def create_special(name: str, cursor: str | None = None):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            INSERT INTO running_ops (id, name, cursor)
            VALUES (?, ?, ?)
        ''', (0, name, cursor))
        db_cursor.close()
        local_db.commit()

        return RunningOp(username=name, user_id=0, cursor=cursor, count=0, done=False)
    
    @staticmethod
    def get_special(name: str) -> RunningOp | None:
        db_cursor = local_db.cursor()
        db_cursor.execute('SELECT cursor, count, done FROM running_ops WHERE id = 0 AND name = ?', (name,))
        row = db_cursor.fetchone()
        db_cursor.close()
        if row:
            cursor, count, done = row
            return RunningOp(username=name, user_id=0, cursor=cursor, count=count, done=done)
        else:
            return None

    @staticmethod
    def get_or_create_special(name: str) -> RunningOp:
        op = OpManager.get_special(name)
        if op is None:
            op = OpManager.create_special(name)

        return op
    
    @staticmethod
    def close_special(name: str):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            UPDATE running_ops SET done = 1 WHERE id = 0 AND name = ?
        ''', (name,))
        db_cursor.close()
        local_db.commit()

    @staticmethod
    def update_special_cursor_and_count(name: str, cursor: str, count: int):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            UPDATE running_ops SET cursor = ?, count = count + ? WHERE id = 0 AND name = ?
        ''', (cursor, count, name))
        db_cursor.close()
        local_db.commit()

    @staticmethod
    def create(user: User, cursor: str | None = None):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            INSERT OR REPLACE INTO running_ops (id, name, cursor)
            VALUES (?, ?, ?)
        ''', (user.id, user.handle, cursor))
        db_cursor.close()
        local_db.commit()

        return RunningOp(username=user.handle, user_id=user.id, cursor=cursor, count=0, done=False)

    @staticmethod
    def set_done(user: User):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            UPDATE running_ops SET done = 1 WHERE id = ?
        ''', (user.id,))
        db_cursor.close()
        local_db.commit()

    @staticmethod
    def update_cursor(user: User, cursor: str):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            UPDATE running_ops SET cursor = ? WHERE id = ?
        ''', (cursor, user.id))
        db_cursor.close()
        local_db.commit()

    @staticmethod
    def increment_count(user: User, count: int):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            UPDATE running_ops SET count = count + ? WHERE id = ?
        ''', (count, user.id))
        db_cursor.close()
        local_db.commit()

    @staticmethod
    def update_cursor_and_count(user: User, cursor: str, count: int):
        db_cursor = local_db.cursor()
        db_cursor.execute('''
            UPDATE running_ops SET cursor = ?, count = count + ? WHERE id = ?
        ''', (cursor, count, user.id))
        db_cursor.close()
        local_db.commit()

    @staticmethod
    def get_with(user: User) -> RunningOp | None:
        db_cursor = local_db.cursor()
        db_cursor.execute('SELECT cursor, count, done FROM running_ops WHERE id = ?', (user.id,))
        row = db_cursor.fetchone()
        db_cursor.close()

        if row:
            cursor, count, done = row
            return RunningOp(username=user.handle, user_id=user.id, cursor=cursor, count=count, done=done)
        else:
            return None
        
    @staticmethod
    def get_or_create_with(user: User) -> RunningOp:
        op = OpManager.get_with(user)
        if op is None:
            op = OpManager.create(user)

        return op

    @staticmethod
    def get_last() -> RunningOp | None:
        db_cursor = local_db.cursor()
        db_cursor.execute('SELECT id, name, cursor, count, done FROM running_ops WHERE done = 0 and id <> 0 ORDER BY id DESC LIMIT 1')
        row = db_cursor.fetchone()
        db_cursor.close()

        if row:
            user_id, username, cursor, count, done = row
            return RunningOp(username=username, user_id=int(user_id), cursor=cursor, count=int(count), done=int(done) > 0)
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
        print("--- Unauthorized access, please re-authenticate: https://x.com/logout [waiting for cookies update]")
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
        print(f"--- Unauthorized access, please re-authenticate: https://x.com/logout [waiting for cookies update]")
        await client.await_cookies_update()
    elif should_wait:
        print("--- Rate limit exceeded, waiting a bit...") 
        await trio.sleep(THROTTLE_TIMEOUT)

async def block_task(client: TwtClient, queue: trio.Semaphore, user: User, results: dict, reason: str, match: str):
    async with queue:
        try:
            status_code, res, raw = await client.block(user)

            if status_code == 200:
                save_block(user, reason, match)

            results[user.id] = [status_code, res, raw]
        except Exception as e:
            results[user.id] = [400, str(e), None]

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
parser.add_argument('-r', '--ring', action='store_true', help='Ring when user action is required.')

cmd = parser.add_subparsers(dest='command', required=True)

cmd_kw = cmd.add_parser('kw', help='Block users based on a keyword search.')
cmd_kw.add_argument('query', type=str, help='The keyword to search for users to block.')

cmd_fw = cmd.add_parser('fw', help='Block followers of a given user.')
cmd_fw.add_argument('--skip-premium', action='store_true', help='Skip blocking verified users (premium accounts).')
fw_params = cmd_fw.add_mutually_exclusive_group(required=True)
fw_params.add_argument('-n', '--name', type=str, help='The target user handle')
fw_params.add_argument('-i', '--id', type=str, help='The target user ID')
fw_params.add_argument('-c', '--continue', dest='continue_', action='store_true', help='Continue the previous search/block operation if possible.')

cmd_fetch = cmd.add_parser('fetch', help='Fetch the current block list.')

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
    target_user: User | None = None
    current_op: RunningOp | None = None

    while True:
        if args.continue_:
            current_op = OpManager.get_last()
            if current_op is None:
                print("No previous running operation found. Please specify a new user.")
                exit(1)
            else:
                res_code, target_user = await client.get_user_by_id(current_op.user_id)
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

    if current_op is None:
        current_op = OpManager.get_or_create_with(target_user)
    
    if current_op.done:
        print(f"Operation for @{target_user.handle} ({target_user.id}) is already done.")
        exit(0)

    if current_op.cursor is None:
        print(f"Fetching followers of @{target_user.handle} ({target_user.id})...")
    else:
        specific_blocked_count = get_blocked_count_by_ex(BlockReason.SUBSCRIBED_TO, target_user.handle)
        print(f"Continuing previous blocking operation for @{target_user.handle} ({target_user.id})...")
        print(f"  * Already blocked {specific_blocked_count} followers out of {target_user.followers_count} ({specific_blocked_count / target_user.followers_count * 100:.2f}%)")
        print(f"  * Already processed {current_op.count} followers ({current_op.count / target_user.followers_count * 100:.2f}%)")

    async for status_code, raw_followers, current_cursor in client.fetch_mixed_followers(target_user, initial_cursor=current_op.cursor, force_skip_verified=args.skip_premium):
        if await handle_error_code(client, status_code, "Failed to fetch followers"):
            continue

        if len(raw_followers) == 0:
            continue

        followers = { follower.id: follower for follower in raw_followers if follower.already_blocked is False }

        if args.verbose:
            print(f"[fw/{target_user.handle}] Fetched {len(followers)} new followers (cursor: {current_cursor}) ({current_op.count / target_user.followers_count * 100:.2f}%)")

        if len(followers) == 0:
            OpManager.update_cursor(target_user, current_cursor)
            continue

        while len(followers):
            results = { }

            async with trio.open_nursery() as nursery:
                for follower in followers.values():
                    nursery.start_soon(block_task, client, queue, follower, results, BlockReason.SUBSCRIBED_TO, target_user.handle)
            
            error_stack = { }

            for uid, follower in list(followers.items()):
                if uid in results:
                    status_code, res, _ = results[uid]
                    if status_code == 200:
                        print(f"  * blocked {follower.id:>19} @{follower.handle:<16} (created on {follower.created_at:%d/%m/%Y} - {follower.activity_count:>6} posts) {'[paid]' if follower.verified else ''}")
                        followers.pop(uid)
                    else:
                        error_stack[status_code] = res
                else:
                    print(f"Error: No task result for user {follower.handle} (ID: {uid})")
                    exit(1)
            
            await handle_error_stack(client, error_stack)

        current_op.count += len(raw_followers)
        OpManager.update_cursor_and_count(target_user, current_cursor, len(raw_followers))

    OpManager.set_done(target_user)
    block_count = get_blocked_count_by_ex(BlockReason.SUBSCRIBED_TO, target_user.handle)
    print(f"End of the follower list reached, blocked {block_count} new users.")

async def cmd_fetch(client: TwtClient):
    key = 'fetch_blocked_users'
    op = OpManager.get_or_create_special(key)

    async for status_code, raw_users, current_cursor in client.fetch_own_block_list(initial_cursor=op.cursor):
        if await handle_error_code(client, status_code, "Failed to fetch followers"):
            continue

        cursor = local_db.cursor()
        cursor.execute('SELECT id from users where id in ({})'.format(','.join(str(u.id) for u in raw_users)))
        existing_ids = { row[0] for row in cursor.fetchall() }
        cursor.close()

        new_users = [ u for u in raw_users if u.id not in existing_ids ]

        if args.verbose:
            print(f"[block_list] Fetched {len(new_users)}/{len(raw_users)} new blocked users (cursor: {current_cursor})")

        OpManager.update_special_cursor_and_count(key, current_cursor, len(raw_users))

        if len(new_users) != 0:
            save_blocks(new_users, BlockReason.BLOCK_LIST, '')

    OpManager.close_special(key)
    block_count = get_blocked_count_by(BlockReason.BLOCK_LIST)
    print(f"End of the block list reached, imported {block_count} new users.")

async def main():
    print_stats()
    client = TwtClient(get_cookies())
    block_sem = trio.Semaphore(MAX_BLOCK_QUEUE_SIZE)

    if args.command == 'kw':
        await cmd_kw(client, block_sem)
    elif args.command == 'fw':
        await cmd_fw(client, block_sem)
    elif args.command == 'fetch':
        await cmd_fetch(client)

if __name__ == "__main__":
    trio.run(main)
