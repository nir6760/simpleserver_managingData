from urllib.parse import unquote
from aiohttp import web
import os
from hw2 import mimeDict
import time
import re

class HTTPHandler:

    def __init__(self, request):
        self.request = request
        self.rel_url_str = str(request._rel_url)

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
        return http_handler.get()

    print(request._rel_url)
    print(request.method)
    print(check_if_file_exist(str(request._rel_url)))
    print(get_content_type(str(request._rel_url)))

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
