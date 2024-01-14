import logging.config
import math
from copy import deepcopy

from httpx import AsyncClient

from .constants import *
from .login import login
from .util import *

class Account:

    def __init__(
        self,
        email: str = None,
        username: str = None, 
        password: str = None,
        session: Client = None,
        **kwargs
    ):
        self.save = kwargs.get('save', True)
        self.debug = kwargs.get('debug', 0)
        self.proxies = kwargs.get('proxies', {})
        self.gql_api = 'https://twitter.com/i/api/graphql'
        self.v1_api = 'https://api.twitter.com/1.1'
        self.v2_api = 'https://twitter.com/i/api/2'
        self.logger = self._init_logger(**kwargs)
        self.session = self._validate_session(
            email, 
            username, 
            password, 
            session, 
            **kwargs
        )

    async def gql(
        self,
        method: str,
        operation: tuple,
        variables: dict,
        features: dict = Operation.default_features
    ) -> dict:
        qid, op = operation
        params = {
            'queryId': qid,
            'features': features,
            'variables': Operation.default_variables | variables
        }
        if method == 'POST':
            data = {'json': params}
        else:
            data = {'params': {k: orjson.dumps(v).decode() for k, v in params.items()}}
            
        r = await self.session.request(
            method=method,
            url=f'{self.gql_api}/{qid}/{op}',
            headers=get_headers(self.session),
            **data
        )
        if self.debug:
            log(self.logger, self.debug, r)
        return r.json()

    async def v1(self, path: str, params: dict) -> dict:
        headers = get_headers(self.session)
        headers['content-type'] = 'application/x-www-form-urlencoded'
        r = await self.session.post(
            f'{self.v1_api}/{path}',
            headers=headers, 
            data=urlencode(params)
        )
        if self.debug:
            log(self.logger, self.debug, r)
        return r.json()

    async def retweet(self, tweet_id: int) -> dict:
        variables = {"tweet_id": tweet_id, "dark_request": False}
        return await self.gql('POST', Operation.CreateRetweet, variables)

    async def unretweet(self, tweet_id: int) -> dict:
        variables = {"source_tweet_id": tweet_id, "dark_request": False}
        return await self.gql('POST', Operation.DeleteRetweet, variables)

    async def untweet(self, tweet_id: int) -> dict:
        variables = {'tweet_id': tweet_id, 'dark_request': False}
        return await self.gql('POST', Operation.DeleteTweet, variables)

    async def like(self, tweet_id: int) -> dict:
        variables = {'tweet_id': tweet_id}
        return await self.gql('POST', Operation.FavoriteTweet, variables)

    async def unlike(self, tweet_id: int) -> dict:
        variables = {'tweet_id': tweet_id}
        return await self.gql('POST', Operation.UnfavoriteTweet, variables)

    async def bookmark(self, tweet_id: int) -> dict:
        variables = {'tweet_id': tweet_id}
        return await self.gql('POST', Operation.CreateBookmark, variables)

    async def unbookmark(self, tweet_id: int) -> dict:
        variables = {'tweet_id': tweet_id}
        return await self.gql('POST', Operation.DeleteBookmark, variables)

    async def create_list(self, name: str, description: str, private: bool) -> dict:
        variables = {
            "isPrivate": private,
            "name": name,
            "description": description,
        }
        return await self.gql('POST', Operation.CreateList, variables)

    async def update_list(
        self,
        list_id: int,
        name: str,
        description: str,
        private: bool
    ) -> dict:
        variables = {
            "listId": list_id,
            "isPrivate": private,
            "name": name,
            "description": description,
        }
        return await self.gql('POST', Operation.UpdateList, variables)

    async def update_pinned_lists(self, list_ids: list[int]) -> dict:
        """
        Update pinned lists.
        Reset all pinned lists and pin all specified lists in the order they are provided.

        @param list_ids: list of list ids to pin
        @return: response
        """
        return await self.gql('POST', Operation.ListsPinMany, {'listIds': list_ids})

    async def pin_list(self, list_id: int) -> dict:
        return await self.gql('POST', Operation.ListPinOne, {'listId': list_id})

    async def unpin_list(self, list_id: int) -> dict:
        return await self.gql('POST', Operation.ListUnpinOne, {'listId': list_id})

    async def add_list_member(self, list_id: int, user_id: int) -> dict:
        return await self.gql(
            'POST',
            Operation.ListAddMember,
            {'listId': list_id, "userId": user_id}
        )

    async def remove_list_member(self, list_id: int, user_id: int) -> dict:
        return await self.gql(
            'POST',
            Operation.ListRemoveMember,
            {'listId': list_id, "userId": user_id}
        )

    async def delete_list(self, list_id: int) -> dict:
        return await self.gql('POST', Operation.DeleteList, {'listId': list_id})

    async def update_list_banner(self, list_id: int, media: str) -> dict:
        media_id = self._upload_media(media)
        variables = {'listId': list_id, 'mediaId': media_id}
        return await self.gql('POST', Operation.EditListBanner, variables)

    async def delete_list_banner(self, list_id: int) -> dict:
        return await self.gql('POST', Operation.DeleteListBanner, {'listId': list_id})

    async def follow_topic(self, topic_id: int) -> dict:
        return await self.gql('POST', Operation.TopicFollow, {'topicId': str(topic_id)})

    async def unfollow_topic(self, topic_id: int) -> dict:
        return await self.gql('POST', Operation.TopicUnfollow, {'topicId': str(topic_id)})

    async def pin(self, tweet_id: int) -> dict:
        return await self.v1(
            'account/pin_tweet.json',
            {'tweet_mode': 'extended', 'id': tweet_id}
        )

    async def unpin(self, tweet_id: int) -> dict:
        return await self.v1(
            'account/unpin_tweet.json',
            {'tweet_mode': 'extended', 'id': tweet_id}
        )

    async def follow(self, user_id: int) -> dict:
        settings = deepcopy(follow_settings)
        settings |= {"user_id": user_id}
        return await self.v1('friendships/create.json', settings)

    async def unfollow(self, user_id: int) -> dict:
        settings = deepcopy(follow_settings)
        settings |= {"user_id": user_id}
        return await self.v1('friendships/destroy.json', settings)

    async def mute(self, user_id: int) -> dict:
        return await self.v1('mutes/users/create.json', {'user_id': user_id})

    async def unmute(self, user_id: int) -> dict:
        return await self.v1('mutes/users/destroy.json', {'user_id': user_id})

    async def enable_follower_notifications(self, user_id: int) -> dict:
        settings = deepcopy(follower_notification_settings)
        settings |= {'id': user_id, 'device': 'true'}
        return await self.v1('friendships/update.json', settings)

    async def disable_follower_notifications(self, user_id: int) -> dict:
        settings = deepcopy(follower_notification_settings)
        settings |= {'id': user_id, 'device': 'false'}
        return await self.v1('friendships/update.json', settings)

    async def block(self, user_id: int) -> dict:
        return await self.v1('blocks/create.json', {'user_id': user_id})

    async def unblock(self, user_id: int) -> dict:
        return await self.v1('blocks/destroy.json', {'user_id': user_id})

    async def update_profile_info(self, **kwargs) -> Response:
        url = f'{self.v1_api}/account/update_profile.json'
        headers = get_headers(self.session)
        r = await self.session.post(url, headers=headers, params=kwargs)
        return r

    async def update_search_settings(self, settings: dict) -> Response:
        twid = int(self.session.cookies.get('twid').split('=')[-1].strip('"'))
        headers = get_headers(self.session)
        r = await self.session.post(
            url=f'{self.v1_api}/strato/column/User/{twid}/search/searchSafety',
            headers=headers,
            json=settings,
        )
        return r

    async def update_settings(self, settings: dict) -> dict:
        return await self.v1('account/settings.json', settings)

    async def change_password(self, old: str, new: str) -> dict:
        params = {
            'current_password': old,
            'password': new,
            'password_confirmation': new
        }
        headers = get_headers(self.session)
        headers['content-type'] = 'application/x-www-form-urlencoded'
        url = 'https://twitter.com/i/api/i/account/change_password.json'
        r = await self.session.post(url, headers=headers, data=urlencode(params))
        return r.json()

    async def home_timeline(self, limit=math.inf) -> list[dict]:
        return await self._paginate(
            'POST',
            Operation.HomeTimeline,
            Operation.default_variables,
            limit
        )

    async def home_latest_timeline(self, limit=math.inf) -> list[dict]:
        return await self._paginate(
            'POST',
            Operation.HomeLatestTimeline,
            Operation.default_variables,
            limit
        )

    async def bookmarks(self, limit=math.inf) -> list[dict]:
        return await self._paginate('GET', Operation.Bookmarks, {}, limit)
    
    async def tweet(self, text: str) -> dict:
        variables = {
            'tweet_text': text,
            'dark_request': False,
            'media': {
                'media_entities': [],
                'possibly_sensitive': False,
            },
            'semantic_annotation_ids': [],
        }

        return await self.gql('POST', Operation.CreateTweet, variables)

    async def _paginate(
        self, 
        method: str, 
        operation: tuple,
        variables: dict,
        limit: int
    ) -> list[dict]:
        initial_data = await self.gql(method, operation, variables)
        res = [initial_data]
        ids = set(find_key(initial_data, 'rest_id'))
        dups = 0
        DUP_LIMIT = 3

        cursor = get_cursor(initial_data)
        while (dups < DUP_LIMIT) and cursor:
            prev_len = len(ids)
            if prev_len >= limit:
                return res

            variables['cursor'] = cursor
            data = await self.gql(method, operation, variables)

            cursor = get_cursor(data)
            ids |= set(find_key(data, 'rest_id'))

            if self.debug:
                self.logger.debug(f'cursor: {cursor}\tunique results: {len(ids)}')

            if prev_len == len(ids):
                dups += 1

            res.append(data)
        return res

    async def _add_alt_text(self, media_id: int, text: str) -> Response:
        params = {"media_id": media_id, "alt_text": {"text": text}}
        url = f'{self.v1_api}/media/metadata/create.json'
        r = await self.session.post(url, headers=get_headers(self.session), json=params)
        return r

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

    def _validate_session(self, *args, **kwargs):
        email, username, password, session = args

        # validate credentials
        if all((email, username, password)):
            session = login(email, username, password, **kwargs)
            session._init_with_cookies = False
            return session

        # invalid credentials, try validating session
        if session and all(session.cookies.get(c) for c in {'ct0', 'auth_token'}):
            session._init_with_cookies = True
            return session

        # invalid credentials and session
        cookies = kwargs.get('cookies')

        # try validating cookies dict
        if isinstance(cookies, dict) and all(cookies.get(c) for c in {'ct0', 'auth_token'}):
            _session = AsyncClient(
                cookies=cookies,
                follow_redirects=True,
                proxies=self.proxies
            )
            _session._init_with_cookies = True
            _session.headers.update(get_headers(_session))
            return _session

        # try validating cookies from file
        if isinstance(cookies, str):
            _session = AsyncClient(
                cookies=orjson.loads(Path(cookies).read_bytes()),
                follow_redirects=True,
                proxies=self.proxies
            )
            _session._init_with_cookies = True
            _session.headers.update(get_headers(_session))
            return _session

        raise Exception(
            'Session not authenticated. '
            'Please use an authenticated session or remove the `session` argument and try again.'
        )
    
    @property
    def id(self) -> int:
        """ Get User ID """
        return int(re.findall('"u=(\d+)"', self.session.cookies.get('twid'))[0])

    def save_cookies(self, fname: str = None):
        """ Save cookies to file """
        cookies = self.session.cookies
        Path(f'{fname or cookies.get("username")}.cookies').write_bytes(
            orjson.dumps(dict(cookies))
        )
