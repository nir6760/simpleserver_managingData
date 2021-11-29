from urllib.parse import unquote
from aiohttp import web
import os
from hw2 import mimeDict
import time
from db_utilis import UserType, UserDB
from urllib import parse
import aiofiles
import base64
import config
import re


async def check_auth(authorization):
    req_username = None
    base64_message = str(authorization).split()[1]  # remove Basic
    base64_bytes = base64_message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    username_password = message_bytes.decode('utf-8')
    username_password_lst = username_password.split(':')
    username = username_password_lst[0]
    password = username_password_lst[1]
    if username == config.admin.get('username') and password == config.admin.get('password'):
        print('This is an admin')
        req_username = 'admin'
        return req_username, UserType.ADMIN
    else:
        with UserDB() as u:
            if u.is_a_user(username, password):
                req_username = username
                return req_username, UserType.USER
    return req_username, UserType.NOT_A_USER



class HTTPHandler:

    def __init__(self, request):
        self.request = request
        self.rel_url_str = str(request._rel_url)
        self.auth = UserType.NOT_A_USER
        self.user_name = None

    # check auth of the user
    async def auth_user(self):
        authorization = self.request.headers.get('Authorization')
        if authorization is not None and "Basic" in authorization:
            self.user_name, self.auth = await check_auth(authorization)

    # GET method handler
    async def get(self):
        exist, file_path = check_if_file_exist(self.rel_url_str)
        content_type = get_content_type(self.rel_url_str)
        if exist:
            async with aiofiles.open(file_path, mode='rb') as f:
                content = await f.read()
            # Read file contents
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
                                        , "Connection": "close"})
        else:
            content = self.create_not_found_page()
            enc_content = content.encode('utf-8')
            return web.Response(body=enc_content, status=404, reason="Not Found",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Content-Length": str(len(enc_content))
                                    , "Connection": "close"
                                    , "Content-Type": "text/html"})

    # POST method handler
    async def post(self):
        if self.auth != UserType.ADMIN:
            return web.Response(status=401, reason="Unauthorized",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Connection": "close"})

        content_type = self.request.headers.get('Content-Type')
        if self.rel_url_str == '/users' and content_type is not None and \
                content_type == 'application/x-www-form-urlencoded' and self.request.body_exists \
                and self.request.can_read_body:
            try:
                new_user_name, new_password = await self.read_post_content()
            except PostBodyException as e:
                return web.Response(status=400, reason="BadRequest",
                                    headers={"Date": make_http_time_string(time.localtime())
                                        , "Connection": "close"})
            try:
                with UserDB() as u:
                    u.insert_user(new_user_name, new_password)
            except DBException as e:
                    return web.Response(status=409, reason="Conflict",
                                        headers={"Date": make_http_time_string(time.localtime())
                                            , "WWW-Authenticate": "Basic realm=user"
                                            , "Connection": "close"})

            return web.Response(status=200, reason="OK",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Connection": "close"})
        else:
            return web.Response(status=400, reason="BadRequest",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Connection": "close"})

    # delet method handler
    async def delete(self):
        if self.auth != UserType.ADMIN:
            return web.Response(status=401, reason="Unauthorized",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Connection": "close"})
        try:
            user_to_delete = self.parse_user_to_delete()
        except DeleteException as e:
            return web.Response(status=400, reason="BadRequest",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Connection": "close"})
        try:
            with UserDB() as u:
                count_rows = u.delete_user(user_to_delete)
        except DBException as e:
            return web.Response(status=409, reason="Conflict",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "WWW-Authenticate": "Basic realm=user"
                                    , "Connection": "close"})
        return web.Response(status=200, reason="OK",
                            headers={"Date": make_http_time_string(time.localtime())
                                , "Connection": "close"})

    # parse the username from delete request
    def parse_user_to_delete(self):
        components = self.rel_url_str[1:].split('/')
        if len(components) != 2 and components[0] != 'users':
            raise DeleteException('format is not valid')
        return components[1]

    # coroutine read post content and return username and password
    async def read_post_content(self):
        try:
            content = await self.request.content.readline()
            content = content.decode('latin-1')
            username_password = dict(parse.parse_qs(content))
            username, password = username_password['username'], username_password['password']
            if len(username) > 1 or len(password) > 1:
                raise PostBodyException("username and or password not valid")
        except:
            raise PostBodyException("Post content invalid")
        # check if username is the user
        return username[0], password[0]

    # create not-found page
    def create_not_found_page(self):
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

    def get(self):
        exist, file_path = check_if_file_exist(self.rel_url_str)
        content_type = get_content_type(self.rel_url_str)
        if not exist or content_type is None:
            content = self.create_not_found_page()
            enc_content = content.encode('utf-8')
            return web.Response(body=enc_content, status=404, reason="Not Found",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Content-Length": str(len(enc_content))
                                    , "Connection": "close"
                                    , "Content-Type": "text/html"})
            # Dynamic Pages
            elif self.rel_url_str.endswith('.dp'):
            with open(file_path, 'rb') as f:
                content = f.read()
                rend_content = content

            user = {‘authenticated’: ??, ‘username’: ??}
            params = ???
            context_variables = {'user': user, 'params': params}}

            pat = '{%(.*?)%}'
            while re.search(pat, rend_content, flags=re.DOTALL):
                match = re.search(pat, rend_content, flags=re.DOTALL)
                match_indexes = match.regs[0]
                sub_str = match.group(1).replace('\n', '')
                try:
                    eval_sub_str = eval(sub_str, context_variables)
                except Exception as e:
                    raise ???
                    rend_content = rend_content[:match_indexes[0]] + eval_sub_str + rend_content[match_indexes[1]:]

                return web.Response(body=content_rend, status=200, reason="OK",
                                    headers={"Date": make_http_time_string(time.localtime())
                                        , "Content-Length": str(len(content_rend))
                                        , "Connection": "close"
                                        , "Content-Type": content_type})

            else:
                with open(file_path, 'rb') as f:
                    content = f.read()

                # Read file contents
                return web.Response(body=content, status=200, reason="OK",
                                    headers={"Date": make_http_time_string(time.localtime())
                                        , "Content-Length": str(len(content))
                                        , "Connection": "close"
                                        , "Content-Type": content_type})
        else:
            with open(file_path, 'rb') as f:
                content = f.read()

            # Read file contents
            return web.Response(body=content, status=200, reason="OK",
                                headers={"Date": make_http_time_string(time.localtime())
                                    , "Content-Length": str(len(content))
                                    , "Connection": "close"
                                    , "Content-Type": content_type})


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


# get the content-type of the file, or none if it'sn
def get_content_type(rel_url):
    ext = os.path.splitext(rel_url)[1]
    ext = ext[1:]
    content_type = None
    for element in mimeDict['mime-mapping']:
        if element['extension'] == ext:
            content_type = element['mime-type']
            break
    return content_type


async def handler(request):
    http_handler = HTTPHandler(request)
    method = request.method
    # check authentication
    if method == 'GET':
        await http_handler.auth_user()
        return await http_handler.get()
    if method == 'POST':
        await http_handler.auth_user()
        return await http_handler.post()
    if method == 'DELETE':
        await http_handler.auth_user()
        return await http_handler.delete()

    text = '''
            <!DOCTYPE html>
        <html>
            <head>
                <title> Document Title </title>
            </head>

            <body> 
                <h1> An header </h1>
                <p> The paragraph goes here </p>
                <ul>
                    <li> First item in a list </li>
                    <li> Another item </li>
                </ul>
            </body>
        </html>
    '''
    return web.Response(body=text.encode('utf-8'), status=500,
                        headers={"Content-Type": "text/html", "charset": "utf-8"})
