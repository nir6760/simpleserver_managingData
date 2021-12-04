import json
from exception_types import PostBodyException, DeleteException, DBException, DPException
from aiohttp import web, BasicAuth
import os
# from hw2 import mimeDict
import time
from db_utilis import UserType, UserDB
from urllib import parse
import aiofiles
import config
import re


class StatusType:
    OK200 = (200, 'OK')
    BAD_REQ400 = (400, 'Bad request')
    UNAUTHORIZED401 = (401, 'Unauthorized')
    FORBIDDEN403 = (403, 'Forbidden')
    NOTFOUND404 = (404, 'Not Found')
    CONFLICT409 = (409, 'Conflict')
    INTERNAL500 = (500, 'Internal Server Error')
    NOT_IMP501 = (501, 'Not Implemented')


async def check_auth(authorization):
    req_username = None
    auth = BasicAuth.decode(authorization)
    username = auth.login
    password = auth.password
    if username == config.admin.get('username') and password == config.admin.get('password'):
        print('This is an admin')
        req_username = 'admin'
        return req_username, UserType.ADMIN
    else:
        with UserDB() as u:
            is_a_user, user_password = u.select(username)
            if is_a_user:
                if password == user_password:  # authenticated user
                    req_username = username
                    return req_username, UserType.AUTHENTICATED_USER
                else:  # user but not authenticated
                    req_username = username
                    return req_username, UserType.NOT_AUTHENTICATED_USER

    return req_username, UserType.NOT_A_USER


class HTTPHandler:

    def __init__(self, request):
        self.request = request
        self.rel_url_str = request.path
        self.auth = UserType.NOT_A_USER
        self.user_name = None
        self.user_dict = {'authenticated': False, 'username': None}

    # check auth of the user
    async def auth_user(self):
        authorization = self.request.headers.get('Authorization')
        if authorization is not None and "Basic" in authorization:
            try:
                self.user_name, self.auth = await check_auth(authorization)
                if self.auth == UserType.ADMIN or self.auth == UserType.AUTHENTICATED_USER:
                    self.user_dict['authenticated'] = True
                    self.user_dict['username'] = self.user_name
                elif self.auth == UserType.NOT_AUTHENTICATED_USER:
                    self.user_dict['authenticated'] = False
                    self.user_dict['username'] = self.user_name
                else:
                    self.user_dict['authenticated'] = False
                    self.user_dict['username'] = None
            except Exception as e:
                print("auth is not basic error")

    # handle dynamic pages
    def handle_dynamic_page(self, rend_content_bytes):
        user = self.user_dict
        params = self.request.query
        context_variables = {'user': user, 'params': params}
        rend_content = rend_content_bytes.decode('utf-8')
        pat = '{%(.*?)%}'

        while re.search(pat, rend_content, flags=re.DOTALL):
            match = re.search(pat, rend_content, flags=re.DOTALL)
            match_indexes = match.span()
            sub_str = match.group(1).replace('\n', '')
            try:
                eval_sub_str = eval(sub_str, context_variables)
            except Exception as e:
                raise DPException('error while rendering')
            rend_content = rend_content[:match_indexes[0]] + eval_sub_str + rend_content[match_indexes[1]:]
        enc_rend_content = rend_content.encode('utf-8')
        return web.Response(body=enc_rend_content, status=200, reason="OK",
                            headers={"Date": make_http_time_string(time.localtime())
                                , "Content-Length": str(len(enc_rend_content))
                                , "Connection": "close"
                                , "Content-Type": 'text/html'})

    # the default web response
    @staticmethod
    def default_web_response(status_type):
        enc_content = HTTPHandler.create_status_html_page(status_type)
        return web.Response(body=enc_content, status=status_type[0],
                            reason=status_type[1],
                            headers={"Date": make_http_time_string(time.localtime())
                                , "Content-Length": str(len(enc_content))
                                , "charset": "utf-8"
                                , "Connection": "close"
                                , "Content-Type": 'text/html'})

    # unauthorized response
    @staticmethod
    def unauthorized_web_response(realam):
        enc_content = HTTPHandler.create_status_html_page(StatusType.UNAUTHORIZED401)
        return web.Response(body=enc_content, status=StatusType.UNAUTHORIZED401[0],
                            reason=StatusType.UNAUTHORIZED401[1],
                            headers={"Date": make_http_time_string(time.localtime())
                                , "Content-Length": str(len(enc_content))
                                , "WWW-Authenticate": f"Basic realm={realam}"
                                , "charset": "utf-8"
                                , "Connection": "close"
                                , "Content-Type": 'text/html'})

    # GET method handler
    async def get(self):
        exist, file_path = check_if_file_exist(self.rel_url_str)
        if self.rel_url_str.endswith('.dp') and self.auth == UserType.NOT_A_USER:
            # dp and not a user
            return self.unauthorized_web_response('Users')
        if exist:
            if not os.access(file_path, os.R_OK) or \
                    self.rel_url_str == '/config.py' or self.rel_url_str == '/users.db':  # no permission to read file
                return self.default_web_response(StatusType.FORBIDDEN403)
            try:
                # Read file contents
                async with aiofiles.open(file_path, mode='rb') as f:
                    content = await f.read()
            except Exception as e:
                return self.default_web_response(StatusType.INTERNAL500)

            if self.rel_url_str.endswith('.dp'):
                try:
                    return self.handle_dynamic_page(content)
                except DPException as e:
                    return self.default_web_response(StatusType.INTERNAL500)
                except Exception as e:
                    print(e)
                    return self.default_web_response(StatusType.INTERNAL500)

            else:
                # regular get
                content_type = await get_content_type(self.rel_url_str)
                if content_type is not None:
                    return web.Response(body=content, status=200, reason="OK",
                                        headers={"Date": make_http_time_string(time.localtime())
                                            , "Content-Length": str(len(content))
                                            , "Connection": "close"
                                            , "Content-Type": content_type})
                else:  # only exist but content type is None
                    return web.Response(body=content, status=200, reason="OK",
                                        headers={"Date": make_http_time_string(time.localtime())
                                            , "Content-Length": str(len(content))
                                            , "Connection": "close"
                                            , "Content-Type": 'text/plain'})  # default is text/plain
        else:  # not exist
            content = self.create_not_found_page()
            enc_content = content.encode('utf-8')
            return web.Response(body=enc_content, status=404, reason="Not Found",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Content-Length": str(len(enc_content))
                                    , "charset": "utf-8"
                                    , "Connection": "close"
                                    , "Content-Type": "text/html"})

    # POST method handler
    async def post(self):
        if self.auth != UserType.ADMIN:
            return self.unauthorized_web_response('Admin')

        content_type = self.request.headers.get('Content-Type')
        add_to = self.rel_url_str.strip('/').split('/')
        if len(add_to) == 1 and add_to[0] == 'users' and content_type is not None and \
                content_type == 'application/x-www-form-urlencoded' and self.request.body_exists \
                and self.request.can_read_body:
            try:
                new_user_name, new_password = await self.read_post_content()
                if new_user_name == config.admin['username']:
                    return self.default_web_response(StatusType.CONFLICT409)
            except PostBodyException as e:
                return self.default_web_response(StatusType.BAD_REQ400)
            try:
                with UserDB() as u:
                    u.insert_user(new_user_name, new_password)
            except DBException as e:
                return self.default_web_response(StatusType.CONFLICT409)
            enc_content = self.create_status_html_page(StatusType.OK200)
            return web.Response(body=enc_content, status=200, reason="OK",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Content-Length": str(len(enc_content))
                                    , "charset": "utf-8"
                                    , "Connection": "close"
                                    , "Content-Type": "text/html"})
        else:
            return self.default_web_response(StatusType.BAD_REQ400)

    # delet method handler
    async def delete(self):
        if self.auth != UserType.ADMIN:
            return self.unauthorized_web_response('Admin')
        try:
            user_to_delete = self.parse_user_to_delete()
        except DeleteException as e:
            return self.default_web_response(StatusType.BAD_REQ400)
        try:
            with UserDB() as u:
                count_rows = u.delete_user(user_to_delete)
        except DBException as e:
            return self.default_web_response(StatusType.CONFLICT409)
        enc_content = self.create_status_html_page(StatusType.OK200)
        return web.Response(body=enc_content, status=200, reason="OK",
                            headers={"Date": make_http_time_string(time.localtime())
                                , "Content-Length": str(len(enc_content))
                                , "charset": "utf-8"
                                , "Connection": "close"
                                , "Content-Type": "text/html"})

    # parse the username from delete request
    def parse_user_to_delete(self):
        username = self.request.path[len('/users/'):]
        return username
        # components = self.rel_url_str[1:].split('/')
        # if len(components) != 2 and components[0] != 'users':
        #     raise DeleteException('format is not valid')
        # return components[1]

    # coroutine read post content and return username and password
    async def read_post_content(self):
        try:
            content = await self.request.content.readline()
            content = content.decode('latin-1')
            username_password = dict(parse.parse_qs(content))
            username, password = username_password['username'], username_password['password']
            if len(username) > 1 or len(password) > 1:
                raise PostBodyException("username and or password not valid")
        except Exception as e:
            raise PostBodyException("Post content invalid")
        # check if username is the user
        return username[0], password[0]

    # create not-found page
    def create_not_found_page(self):
        not_found_page_html = f"HTTP/1.1 404 ERROR\n\n"
        not_found_page_html += f"<!DOCTYPE html>\n"
        not_found_page_html = "<html>\n\
                    <head>\n\
                        <title>404 Not Found</title>\n\
                    </head>\n\
                    <body>\n\
                    <h1>Not Found</h1>\n\
                     <p>The Requested URL " + self.rel_url_str + " was not found on this server</p>\n\
                    <hr/>\n\
                    </body>\n\
                    </html>"
        return not_found_page_html

    # create error html page
    @staticmethod
    def create_status_html_page(st):
        not_found_page_html = f"HTTP/1.1 {st[0]} ERROR\n\n"
        not_found_page_html += f"<!DOCTYPE html>\n"
        not_found_page_html += f"<html>\n\
                    <head>\n\
                        <title>{st[0]} - {st[1]}</title>\n\
                    </head>\n\
                    <body>\n\
                    <h1>{st[0]} - {st[1]}</h1>\n\
                    <hr/>\n\
                    </body>\n\
                    </html>"
        return not_found_page_html.encode('utf-8')


# create time header
def make_http_time_string(time_struct):
    '''Input struct_time and output HTTP header-type time string'''
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT',
                         time_struct)


# check if the relative path from url is valid file
def check_if_file_exist(rel_url):
    current_dir = os.getcwd()
    components = rel_url[1:].split('/')
    rel_path = os.path.join(*components)
    file_path = os.path.join(current_dir, rel_path)
    return os.path.isfile(file_path), file_path


# singeltone class for mimtype reading
class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


# Python3
class MimeTypeClass(metaclass=Singleton):
    @staticmethod
    async def load_json_mime():
        current_dir = os.getcwd()
        json_path = os.path.join(current_dir, 'mime.json')
        async with aiofiles.open(json_path) as json_file:
            contents_json = await json_file.read()
        dict = json.loads(contents_json)
        return dict

    def __init__(self):
        self.mimeDict = None

    async def get_mime_type(self):
        self.mimeDict = await self.load_json_mime()
        return self.mimeDict


# get the content-type of the file, or none if it'sn
async def get_content_type(rel_url):
    ext = os.path.splitext(rel_url)[1]
    ext = ext[1:]
    content_type = None
    mimeDict = await MimeTypeClass().get_mime_type()  # singleton
    for element in mimeDict['mime-mapping']:
        if element['extension'] == ext:
            content_type = element['mime-type']
            break
    return content_type


async def handler(request):
    http_handler = HTTPHandler(request)
    method = request.method
    # check authentication
    try:
        if method == 'GET':
            await http_handler.auth_user()
            return await http_handler.get()
        elif method == 'POST':
            await http_handler.auth_user()
            return await http_handler.post()
        elif method == 'DELETE':
            await http_handler.auth_user()
            return await http_handler.delete()
        else:
            return HTTPHandler.default_web_response(StatusType.NOT_IMP501)
    except Exception as e:
        return HTTPHandler.default_web_response(StatusType.INTERNAL500)
