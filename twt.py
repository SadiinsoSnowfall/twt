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

@dataclass
class TwtCookies:
    ct0: str
    auth_token: str

    def to_dict(self) -> dict:
        return {
            'ct0': self.ct0,
            'auth_token': self.auth_token
        }

@dataclass
class TweetAuthor:
    id: str
    username: str
    handle: str
    description: str
    verified: bool
    created_at: datetime.datetime
    activity_count: int

    def __eq__(self, other):
        if isinstance(other, TweetAuthor):
            return self.id == other.id
        return False
    
    def __hash__(self):
        return hash(self.id)

@dataclass
class Tweet:
    id: int
    author: TweetAuthor
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

    async def block(self, user: TweetAuthor) -> tuple[int, dict]:
        return await self.v1('blocks/create.json', { 'user_id': user.id })

    @staticmethod
    def res_get_cursor(data: list[dict]):
        for e in find_key(data, 'content'):
            if e.get('cursorType') == 'Bottom':
                return e['value']
            
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

                user_info = find_single_key_opt(tweet_info, 'user_results', ignore=['quoted_status_result'])['result']

                if not user_info:
                    continue

                author = TweetAuthor(
                    id=int(user_info['rest_id']),
                    username=user_info['legacy']['name'],
                    handle=user_info['legacy']['screen_name'],
                    description=user_info['legacy']['description'],
                    verified=user_info['legacy']['verified'],
                    created_at= datetime.datetime.strptime(
                        user_info['legacy']['created_at'],
                        '%a %b %d %H:%M:%S +0000 %Y'
                    ),
                    activity_count=int(user_info['legacy']['statuses_count'])
                )

                tweets.append(Tweet(
                    id=int(tweet_info['rest_id']),
                    author=author,
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

    async def search(self, query: str, category: str) -> AsyncGenerator[tuple[int, list[Tweet]], None]:
        endpoint_url = f'{GQL_API_URL}/nK1dw4oV3k4w5TdtcAdSww/SearchTimeline'
        params = {
            'variables': {
                'count': 60,
                'querySource': 'typed_query',
                'rawQuery': query,
                'product': category
            },
            'features': DEFAULT_FEATURES,
            'fieldToggles': { 'withArticleRichContentState': False },
        }

        cursor = ''

        while True:
            if cursor:
                params['variables']['cursor'] = cursor

            headers = self.build_headers(endpoint_url)
            r = await self.http.get(endpoint_url, headers=headers, params={k: json.dumps(v) for k, v in params.items()})

            if r.status_code >= 400:
                yield (r.status_code, [ ])
                break

            data = r.json()
            cursor = self.res_get_cursor(data)
            entries = [y for x in find_key(data, 'entries') for y in x if re.search(r'^(tweet|user)-', y['entryId'])]

            if len(entries) <= 2: # just cursors
                yield (r.status_code, [ ])
                break
            else:
                tweets = self.parse_tweets(entries)
                yield (r.status_code, tweets)
            
    
def get_cookies():
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
            blocked INTEGER NOT NULL DEFAULT 0
        )
    ''')

    cursor.close()
    return conn

local_db = init_db()

def save_block(id, name, reason, match):
    cursor =  local_db.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO users (id, name, reason, match, date, blocked)
        VALUES (?, ?, ?, ?, date('now'), 1)
    ''', (id, name, reason, match))
    cursor.close()
    local_db.commit()

def handle_error_code(status_code: int, error: str):
    if status_code == 429:
        print(f"Rate limit exceeded, please wait for ~15 minutes...")
    elif status_code == 401:
        print(f"--- Unauthorized access, please re-authenticate")
    elif status_code == 403:
        print(f"--- Forbidden access, please re-authenticate (captcha ?)")
    elif status_code == 404:
        print(f"Resource not found: {error}")
    elif status_code == 500:
        print(f"Internal server error: {error}")
    else:
        print(f"Unexpected error (status code {status_code}): {error}")

def print_stats():
    cursor = local_db.cursor()

    cursor.execute('SELECT COUNT(*) FROM users WHERE date = date("now")')
    daily_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM users')
    total_count = cursor.fetchone()[0]

    cursor.close()

    print(f"{daily_count} users blocked today (out of {total_count} total)")

# arg parser
parser = argparse.ArgumentParser(description="Block users on Twitter based on search keywords.")
parser.add_argument('query', type=str, help='The search query to find users to block.')

args = parser.parse_args()

async def main():
    print_stats()
    client = TwtClient(get_cookies())
    block_sem = trio.Semaphore(MAX_BLOCK_QUEUE_SIZE)

    total_blocked = 0
    total_search = 0

    async def block_task(user: TweetAuthor, results: dict, reason: str, match: str):
        async with block_sem:
            try:
                status_code, res = await client.block(user)

                if status_code == 200:
                    save_block(user.id, user.handle, reason, match)

                results[user.id] = [status_code, res]
            except Exception as e:
                results[user.id] = [400, str(e)]

    for category in ['Latest', 'Top']:
        print(f"Querying: {args.query}/{category}...")
        async for status_code, tweets in client.search(args.query, category):
            total_search += 1

            if status_code == 429:
                print("Rate limit exceeded. Waiting for 15 minutes before retrying...")
                await trio.sleep(15 * 60)
                continue
            elif status_code >= 400:
                handle_error_code(status_code, "Failed to fetch tweets")
                exit(1)

            results = { }
            authors = { tweet.author.id: tweet.author for tweet in tweets }

            if len(authors) == 0:
                continue

            async with trio.open_nursery() as nursery:
                for author in authors.values():
                    nursery.start_soon(block_task, author, results, BlockReason.MATCH_KEYWORD, args.query)

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
            
            should_wait = False

            for status_code, error in error_stack.items():
                if status_code == 429:
                    should_wait = True
                elif status_code == 666:
                    print(f"Error while blocking a user: {error}")
                    exit(1)
                else:
                    handle_error_code(status_code, error)
                    exit(1)

            if should_wait:
                print("Rate limit exceeded. Waiting for 15 minutes before retrying...")
                await trio.sleep(15 * 60)
    
    if total_blocked > 0:
        print(f"\nBlocked {total_blocked} users using {total_search} search call.")

if __name__ == "__main__":
    trio.run(main)
