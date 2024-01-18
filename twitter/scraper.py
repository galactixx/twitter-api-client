import asyncio
import logging.config
import math

from httpx import AsyncClient, Limits
from tqdm.asyncio import tqdm_asyncio

from .constants import *
from .login import login
from .util import *

class Scraper:
    def __init__(self, proxies: dict = {}):
        self.proxies = proxies
        self.save = False
        self.debug = 0
        self.pbar = True
        self.out = Path('data')
        self.guest = False
        self.logger: Logger = None
        self.session: AsyncClient = None
        
    async def init_session(
        self,
        email: str = None,
        username: str = None, 
        password: str = None,
        session: Client = None,
        **kwargs
    ):
        self.logger = self._init_logger(**kwargs)
        self.session = await self._validate_session(
            email, 
            username, 
            password,
            session,
            **kwargs
        )

    async def list_members(self, list_ids: list[int], **kwargs) -> list[dict]:
        """
        Get members by a list id.

        Metadata for members in a given list.

        @param list_ids: list of list ids
        @param kwargs: optional keyword arguments
        @return: list of members as dicts
        """
        return await self._run(
            Operation.ListMembers,
            list_ids,
            **kwargs
        )

    async def list_latest_tweets(self, list_ids: list[int], **kwargs) -> list[dict]:
        """
        Get latest tweets by a list id.

        Metadata for list latest tweets in timeline.

        @param list_ids: list of list ids
        @param kwargs: optional keyword arguments
        @return: list of list latest tweet data as dicts
        """
        return await self._run(
            Operation.ListLatestTweetsTimeline,
            list_ids,
            **kwargs
        )

    async def users(self, screen_names: list[str], **kwargs) -> list[dict]:
        """
        Get user data by screen names.

        @param screen_names: list of screen names (usernames)
        @param kwargs: optional keyword arguments
        @return: list of user data as dicts
        """
        return await self._run(
            Operation.UserByScreenName,
            screen_names,
            **kwargs
        )

    async def tweets_by_id(self, tweet_ids: list[int | str], **kwargs) -> list[dict]:
        """
        Get tweet metadata by tweet ids.

        @param tweet_ids: list of tweet ids
        @param kwargs: optional keyword arguments
        @return: list of tweet data as dicts
        """
        return await self._run(
            Operation.TweetResultByRestId,
            tweet_ids,
            **kwargs
        )

    async def tweets_by_ids(self, tweet_ids: list[int | str], **kwargs) -> list[dict]:
        """
        Get tweet metadata by tweet ids.

        Special batch query for tweet data. Most efficient way to get tweets.

        @param tweet_ids: list of tweet ids
        @param kwargs: optional keyword arguments
        @return: list of tweet data as dicts
        """
        return await self._run(
            Operation.TweetResultsByRestIds,
            batch_ids(tweet_ids),
            **kwargs
        )

    async def tweets_details(self, tweet_ids: list[int], **kwargs) -> list[dict]:
        """
        Get tweet data by tweet ids.

        Includes tweet metadata as well as comments, replies, etc.

        @param tweet_ids: list of tweet ids
        @param kwargs: optional keyword arguments
        @return: list of tweet data as dicts
        """
        return await self._run(Operation.TweetDetail, tweet_ids, **kwargs)

    async def tweets(self, user_ids: list[int], **kwargs) -> list[dict]:
        """
        Get tweets by user ids.

        Metadata for users tweets.

        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of tweet data as dicts
        """
        return await self._run(Operation.UserTweets, user_ids, **kwargs)

    async def tweets_and_replies(self, user_ids: list[int], **kwargs) -> list[dict]:
        """
        Get tweets and replies by user ids.

        Tweet metadata, including replies.

        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of tweet data as dicts
        """
        return await self._run(
            Operation.UserTweetsAndReplies,
            user_ids,
            **kwargs
        )

    async def media(self, user_ids: list[int], **kwargs) -> list[dict]:
        """
        Get media by user ids.

        Tweet metadata, filtered for tweets containing media.

        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of tweet data as dicts
        """
        return await self._run(Operation.UserMedia, user_ids, **kwargs)

    async def likes(self, user_ids: list[int], **kwargs) -> list[dict]:
        """
        Get likes by user ids.

        Tweet metadata for tweets liked by users.

        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of tweet data as dicts
        """
        return await self._run(Operation.Likes, user_ids, **kwargs)

    async def followers(self, user_ids: list[int], **kwargs) -> list[dict]:
        """
        Get followers by user ids.

        User data for users followers list.

        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of user data as dicts
        """
        return await self._run(Operation.Followers, user_ids, **kwargs)

    async def following(self, user_ids: list[int], **kwargs) -> list[dict]:
        """
        Get following by user ids.

        User metadata for users following list.

        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of user data as dicts
        """
        return await self._run(Operation.Following, user_ids, **kwargs)

    async def favoriters(self, tweet_ids: list[int], **kwargs) -> list[dict]:
        """
        Get favoriters by tweet ids.

        User data for users who liked these tweets.

        @param tweet_ids: list of tweet ids
        @param kwargs: optional keyword arguments
        @return: list of user data as dicts
        """
        return await self._run(Operation.Favoriters, tweet_ids, **kwargs)

    async def retweeters(self, tweet_ids: list[int], **kwargs) -> list[dict]:
        """
        Get retweeters by tweet ids.

        User data for users who retweeted these tweets.

        @param tweet_ids: list of tweet ids
        @param kwargs: optional keyword arguments
        @return: list of user data as dicts
        """
        return await self._run(Operation.Retweeters, tweet_ids, **kwargs)

    async def tweet_stats(self, user_ids: list[int], **kwargs) -> list[dict]:
        """
        Get tweet statistics by user ids.

        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of tweet statistics as dicts
        """
        return await self._run(Operation.TweetStats, user_ids, **kwargs)

    async def users_by_ids(self, user_ids: list[int], **kwargs) -> list[dict]:
        """
        Get user data by user ids.

        Special batch query for user data. Most efficient way to get user data.

        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of user data as dicts
        """
        return await self._run(
            Operation.UsersByRestIds, 
            batch_ids(user_ids),
            **kwargs
        )

    async def recommended_users(self, user_ids: list[int] = None, **kwargs) -> list[dict]:
        """
        Get recommended users by user ids, or general recommendations if no user ids are provided.

        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of recommended users data as dicts
        """
        if user_ids:
            contexts = [
                {"context": orjson.dumps({"contextualUserId": x}).decode()}
                for x in user_ids
            ]
        else:
            contexts = [{'context': None}]
        return await self._run(Operation.ConnectTabTimeline, contexts, **kwargs)

    async def profile_spotlights(self, screen_names: list[str], **kwargs) -> list[dict]:
        """
        Get user data by screen names.

        This endpoint is included for completeness only.
        Use the batched query `users_by_ids` instead if you wish to pull user profile data.

        @param screen_names: list of user screen names (usernames)
        @param kwargs: optional keyword arguments
        @return: list of user data as dicts
        """
        return await self._run(Operation.ProfileSpotlightsQuery, screen_names, **kwargs)

    async def users_by_id(self, user_ids: list[int], **kwargs) -> list[dict]:
        """
        Get user data by user ids.

        This endpoint is included for completeness only.
        Use the batched query `users_by_ids` instead if you wish to pull user profile data.


        @param user_ids: list of user ids
        @param kwargs: optional keyword arguments
        @return: list of user data as dicts
        """
        return await self._run(Operation.UserByRestId, user_ids, **kwargs)

    async def _run(
        self,
        operation: tuple[dict, str, str],
        queries: set | list[int | str | list | dict],
        **kwargs
    ):
        keys, _, _ = operation

        # stay within rate-limits
        if (l := len(queries)) > MAX_ENDPOINT_LIMIT:
            if self.debug:
                self.logger.warning(f'Got {l} queries, truncating to first 500.')
            queries = list(queries)[:MAX_ENDPOINT_LIMIT]

        if all(isinstance(q, dict) for q in queries):
            data = await self._process(operation, list(queries), **kwargs)
            return get_json(data, **kwargs)

        # queries are of type set | list[int|str], need to convert to list[dict]
        _queries = [{k: q} for q in queries for k, v in keys.items()]
        res = await self._process(operation, _queries, **kwargs)
        data = get_json(res, **kwargs)
        return data.pop() if kwargs.get('cursor') else flatten(data)

    async def _query(self, client: AsyncClient, operation: tuple, **kwargs) -> Response:
        keys, qid, name = operation
        params = {
            'variables': Operation.default_variables | keys | kwargs,
            'features': Operation.default_features,
        }
        r = await client.get(
            f'https://twitter.com/i/api/graphql/{qid}/{name}',
            params=build_params(params)
        )

        if self.debug:
            log(self.logger, self.debug, r)
        if self.save:
            await save_json(r, self.out, name, **kwargs)
        return r

    async def _process(self, operation: tuple, queries: list[dict], **kwargs):
        headers = self.session.headers if self.guest else get_headers(self.session)
        cookies = self.session.cookies
        
        async with AsyncClient(
            limits=Limits(max_connections=MAX_ENDPOINT_LIMIT),
            headers=headers,
            cookies=cookies,
            timeout=20,
            proxies=self.proxies
        ) as c:
            tasks = (self._paginate(c, operation, **q, **kwargs) for q in queries)
            if self.pbar:
                return await tqdm_asyncio.gather(*tasks, desc=operation[-1])
            return await asyncio.gather(*tasks)

    async def _paginate(self, client: AsyncClient, operation: tuple, **kwargs):
        limit = kwargs.pop('limit', math.inf)
        cursor = kwargs.pop('cursor', None)
        is_resuming = False
        dups = 0
        DUP_LIMIT = 3
        if cursor:
            is_resuming = True
            res = []
            ids = set()
        else:
            try:
                r = await self._query(client, operation, **kwargs)
                initial_data = r.json()
                res = [r]
                ids = {x for x in find_key(initial_data, 'rest_id') if x[0].isnumeric()}

                cursor = get_cursor(initial_data)
            except Exception as e:
                if self.debug:
                    self.logger.error('Failed to get initial pagination data', e)
                return
        while (dups < DUP_LIMIT) and cursor:
            prev_len = len(ids)
            if prev_len >= limit:
                break
            try:
                r = await self._query(client, operation, cursor=cursor, **kwargs)
                data = r.json()
            except Exception as e:
                if self.debug:
                    self.logger.error(f'Failed to get pagination data\n{e}')
                return
            cursor = get_cursor(data)
            ids |= {x for x in find_key(data, 'rest_id') if x[0].isnumeric()}

            if self.debug:
                self.logger.debug(f'Unique results: {len(ids)}\tcursor: {cursor}')
            if prev_len == len(ids):
                dups += 1
            res.append(r)
        if is_resuming:
            return res, cursor
        return res

    def _init_logger(self, **kwargs) -> Logger:
        if kwargs.get('debug'):
            cfg = kwargs.get('log_config')
            logging.config.dictConfig(cfg or LOG_CONFIG)

            # only support one logger
            logger_name = list(LOG_CONFIG['loggers'].keys())[0]

            # set level of all other loggers to ERROR
            for name in logging.root.manager.loggerDict:
                if name != logger_name:
                    logging.getLogger(name).setLevel(logging.ERROR)

            return logging.getLogger(logger_name)

    async def _validate_session(self, *args, **kwargs):
        email, username, password, session = args

        # validate credentials
        if all((email, username, password)):
            return await login(
                email=email,
                username=username,
                password=password,
                proxies=self.proxies,
                **kwargs
            )

        # invalid credentials, try validating session
        if session and all(session.cookies.get(c) for c in {'ct0', 'auth_token'}):
            return session

        # invalid credentials and session
        cookies = kwargs.get('cookies')

        # try validating cookies dict
        if isinstance(cookies, dict) and all(cookies.get(c) for c in {'ct0', 'auth_token'}):
            _session = AsyncClient(cookies=cookies, follow_redirects=True)
            _session.headers.update(get_headers(_session))
            return _session

        # try validating cookies from file
        if isinstance(cookies, str):
            _session = AsyncClient(
                cookies=orjson.loads(Path(cookies).read_bytes()),
                follow_redirects=True
            )
            _session.headers.update(get_headers(_session))
            return _session

        # no session, credentials, or cookies provided. use guest session.
        if self.debug:
            self.logger.warning(
                f'{RED}This is a guest session, some endpoints cannot be accessed.{RESET}\n'
            )
        self.guest = True
        return session

    @property
    def id(self) -> int:
        """ Get User ID """
        return int(re.findall('"u=(\d+)"', self.session.cookies.get('twid'))[0])

    def save_cookies(self, fname: str = None):
        """ Save cookies to file """
        cookies = self.session.cookies
        Path(f'{fname or cookies.get("username")}.cookies').write_bytes(orjson.dumps(dict(cookies)))
