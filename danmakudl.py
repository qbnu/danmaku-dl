#!/usr/bin/env python

import re
import json
import urllib.request
import zlib
import os
import argparse
import sys
import time
import gzip
import html
import datetime
import nndcomment_pb2
import signal
import functools
import random
import shutil

# Nicovideo doesn't return brotli anyway
try:
    import brotli
except ModuleNotFoundError:
    pass

print = functools.partial(print, flush=True)


class DelayedKeyboardInterrupt:
    def __enter__(self):
        self.signal_received = False
        self.old_handler = signal.signal(signal.SIGINT, self.handler)

    def handler(self, sig, frame):
        self.signal_received = (sig, frame)

    def __exit__(self, type, value, traceback):
        signal.signal(signal.SIGINT, self.old_handler)
        if self.signal_received:
            self.old_handler(*self.signal_received)


# https://github.com/yt-dlp/yt-dlp/blob/master/yt_dlp/utils/_utils.py#L69-L111
def random_user_agent():
    _USER_AGENT_TPL = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36'
    _CHROME_VERSIONS = (
        '90.0.4430.212',
        '90.0.4430.24',
        '90.0.4430.70',
        '90.0.4430.72',
        '90.0.4430.85',
        '90.0.4430.93',
        '91.0.4472.101',
        '91.0.4472.106',
        '91.0.4472.114',
        '91.0.4472.124',
        '91.0.4472.164',
        '91.0.4472.19',
        '91.0.4472.77',
        '92.0.4515.107',
        '92.0.4515.115',
        '92.0.4515.131',
        '92.0.4515.159',
        '92.0.4515.43',
        '93.0.4556.0',
        '93.0.4577.15',
        '93.0.4577.63',
        '93.0.4577.82',
        '94.0.4606.41',
        '94.0.4606.54',
        '94.0.4606.61',
        '94.0.4606.71',
        '94.0.4606.81',
        '94.0.4606.85',
        '95.0.4638.17',
        '95.0.4638.50',
        '95.0.4638.54',
        '95.0.4638.69',
        '95.0.4638.74',
        '96.0.4664.18',
        '96.0.4664.45',
        '96.0.4664.55',
        '96.0.4664.93',
        '97.0.4692.20',
    )
    return _USER_AGENT_TPL % random.choice(_CHROME_VERSIONS)


USER_AGENT = random_user_agent()


def get_cookies(cookiefile):
    cookie_names = ('nicosid', 'user_session', 'user_session_secure')
    d = dict()
    try:
        with open(cookiefile) as f:
            for line in f:
                line = line.strip()
                if not line or line[0] == '#':
                    continue
                for cookie in cookie_names:
                    m = re.match(f'{cookie}=(?P<{cookie}>' + r'[^ ",;\\]+)', line)
                    if m:
                        d[cookie] = m.group(cookie)
    except OSError:
        pass
    try:
        assert all(cookie in d for cookie in cookie_names)
    except AssertionError as e:
        print('Could not read session cookies')
        raise e
    return d


def parse_headers(s):
    pattern = r'\s*(?P<key>[a-zA-Z0-9\-]+):\s*(?P<value>.+)'
    p = re.compile(pattern)
    d = dict()
    for i in s.split('\n'):
        m = p.match(i)
        if m and m.group('key').lower() != 'host':
            d[m.group('key')] = m.group('value')
    if not d.get('User-Agent'):
        d['User-Agent'] = USER_AGENT
    return d


def parse_cookies(cookies):
    return '; '.join([f'{k}={cookies[k]}' for k in cookies])


NICOVIDEO_PATTERN = re.compile(
    r'(?:(?:https?://)?(?:(?:www\.|secure\.|sp\.)?nicovideo\.jp/watch|nico\.ms)/)?(?P<id>(?:[a-z]{2})?[0-9]+)', flags=re.IGNORECASE)

LANGUAGES = {
    'ja-jp': 'Japanese',
    'zh-tw': 'Chinese (Traditional)',
    'en-us': 'English',
}

HEADERS_DEFAULT = parse_headers(
    '''
    GET /watch/sm9 HTTP/1.1
    Host: www.nicovideo.jp
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Connection: keep-alive
    Cookie: will-be-replaced
    Upgrade-Insecure-Requests: 1
    Sec-Fetch-Dest: document
    Sec-Fetch-Mode: navigate
    Sec-Fetch-Site: none
    Sec-Fetch-User: ?1
    '''
)

HEADERS_WATCH = parse_headers(
    '''
    GET /api/watch/v3/sm9?_frontendId=6&_frontendVersion=0&actionTrackId=0_0&i18nLanguage=ja-jp HTTP/1.1
    Host: www.nicovideo.jp
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Referer: https://www.nicovideo.jp/
    Connection: keep-alive
    Cookie: will-be-replaced
    Sec-Fetch-Dest: empty
    Sec-Fetch-Mode: cors
    Sec-Fetch-Site: same-origin
    Pragma: no-cache
    Cache-Control: no-cache
    '''
)

HEADERS_THREAD_KEY = parse_headers(
    '''
    GET /v1/comment/keys/thread?videoId=sm9 HTTP/1.1
    Host: nvapi.nicovideo.jp
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Referer: https://www.nicovideo.jp/
    X-Frontend-Id: 6
    X-Frontend-Version: 0
    X-Niconico-Language: ja-jp
    Origin: https://www.nicovideo.jp
    Connection: keep-alive
    Cookie: will-be-replaced
    Sec-Fetch-Dest: empty
    Sec-Fetch-Mode: cors
    Sec-Fetch-Site: same-site
    '''
)

HEADERS_PAST_LOG_OPTIONS = parse_headers(
    '''
    OPTIONS /v1/threads HTTP/1.1
    Host: nvcomment.nicovideo.jp
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Referer: https://www.nicovideo.jp/
    Access-Control-Request-Method: POST
    Access-Control-Request-Headers: x-client-os-type,x-frontend-id,x-frontend-version
    Origin: https://www.nicovideo.jp
    Connection: keep-alive
    Sec-Fetch-Dest: empty
    Sec-Fetch-Mode: no-cors
    Sec-Fetch-Site: same-site
    Pragma: no-cache
    Cache-Control: no-cache
    '''
)

HEADERS_PAST_LOG = parse_headers(
    '''
    POST /v1/threads HTTP/1.1
    Host: nvcomment.nicovideo.jp
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Referer: https://www.nicovideo.jp/
    x-client-os-type: others
    x-frontend-id: 6
    x-frontend-version: 0
    Content-Type: text/plain;charset=UTF-8
    Origin: https://www.nicovideo.jp
    Connection: keep-alive
    Sec-Fetch-Dest: empty
    Sec-Fetch-Mode: cors
    Sec-Fetch-Site: same-site
    Pragma: no-cache
    Cache-Control: no-cache
    '''
)
# Content-Length will be added automatically


def download_file_simple(url: str, data: bytes = None, headers: dict = {},
                         method: str | None = None, decompress: bool = True) -> bytes:
    assert (headers.get('Cookie') != 'will-be-replaced')
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req) as resp:
        response_data = resp.read()
        encoding = resp.headers.get('Content-Encoding')
        if not encoding or not decompress:
            data = response_data
        elif encoding == 'gzip':
            data = gzip.decompress(response_data)
        elif encoding == 'deflate':
            try:
                data = zlib.decompress(response_data)
            except zlib.error:
                # Non-standard raw deflate supported by web browsers
                data = zlib.decompress(response_data, wbits=-15)
        elif encoding == 'br':
            data = brotli.decompress(response_data)
        else:
            raise ValueError('Unsupported Content-Encoding: ' + encoding)

    return data


def get_video_timestamp(video_id: str, cookies: dict, language: str) -> str:
    cookies = cookies.copy()
    cookies['lang'] = language
    try:
        url = f'https://www.nicovideo.jp/api/watch/v3/{video_id}?_frontendId=6&_frontendVersion=0&actionTrackId=0_0&i18nLanguage={language}'
        headers = HEADERS_WATCH.copy()
        headers['Cookie'] = parse_cookies(cookies)
        resp = download_file_simple(url, headers=headers, method='GET')
        j = json.loads(resp)
        j = j['data']
    except (urllib.request.HTTPError, KeyError):
        url = 'https://www.nicovideo.jp/watch/' + video_id
        headers = HEADERS_DEFAULT
        headers['Cookie'] = parse_cookies(cookies)
        resp = download_file_simple(url, headers=headers, method='GET')
        find_string = b'<div id="js-initial-watch-data" data-api-data="'
        start_index = resp.find(find_string) + len(find_string)
        end_index = resp.find(b'"', start_index)
        j = resp[start_index:end_index]
        j = j.decode(encoding='utf-8')
        j = html.unescape(j)
        j = json.loads(j)
    video_timestamp = j['comment']['layers'][0]['threadIds'][0]['id']
    thread_key = j['comment']['nvComment']['threadKey']
    assert (isinstance(video_timestamp, int) and video_timestamp > 0)
    video_timestamp = str(video_timestamp)
    return video_timestamp, thread_key


def get_thread_key(video_id: str, cookies: dict, language: str) -> str:
    cookies = cookies.copy()
    cookies['lang'] = language
    headers = HEADERS_THREAD_KEY.copy()
    headers['X-Niconico-Language'] = language
    headers['Cookie'] = parse_cookies(cookies)
    url = 'https://nvapi.nicovideo.jp/v1/comment/keys/thread?videoId=' + video_id
    resp = download_file_simple(url, headers=headers, method='GET')
    j = json.loads(resp)
    thread_key = j['data']['threadKey']
    return thread_key


def get_past_log(video_id: str, thread_key: str, video_timestamp: str, log_timestamp: int, language: str) -> bytes:
    url = 'https://nvcomment.nicovideo.jp/v1/threads'
    d = dict()
    d['params'] = dict()
    targets = ['owner', 'main']
    if language == 'ja-jp':
        targets.append('easy')
    d['params']['targets'] = [{'id': video_timestamp, 'fork': i} for i in targets]
    d['params']['language'] = language
    d['threadKey'] = thread_key
    d['additionals'] = dict()
    d['additionals']['when'] = int(log_timestamp)
    data = json.dumps(d, indent=None, separators=(',', ':'))
    data = data.encode('utf-8')
    download_file_simple(url, headers=HEADERS_PAST_LOG_OPTIONS, method='OPTIONS')
    resp = download_file_simple(url, data=data, headers=HEADERS_PAST_LOG, method='POST')
    return resp


def convert_past_log_to_old_style(j, forks=None):
    comments = []
    for f in j['data']['threads']:
        if forks is not None and f['fork'] not in forks:
            continue
        for c in f['comments']:
            comment = c.copy()
            comment['content'] = c['body']
            comment['mail'] = ' '.join(c['commands'])
            comment['vpos'] = c['vposMs'] // 10
            comment['date'] = int(datetime.datetime.fromisoformat(c['postedAt']).timestamp())
            comments.append(comment)
    comments.sort(key=lambda x: x['date'])
    return comments


def get_nextpage(j, forks=('main', 'easy')):
    mindates = []
    for f in j['data']['threads']:
        if forks is not None and f['fork'] not in forks:
            continue
        if f['comments']:
            mindate = datetime.datetime.fromisoformat(f['comments'][0]['postedAt'])
            mindates.append(int(mindate.timestamp()))
    if mindates:
        return max(mindates) + 1  # adding 1 prevents comments posted at the same time from being missed
    return None


# Merge older comments into newer log
def merge_past_log(log_newer, log_older, forks=None):
    for i in range(len(log_newer['data']['threads'])):
        if forks is not None and log_newer['data']['threads'][i]['fork'] not in forks:
            continue
        old_comments = log_older['data']['threads'][i]['comments']
        if not old_comments:
            continue
        new_comments = log_newer['data']['threads'][i]['comments']
        last_older = old_comments[-1]['no']
        new_start = 0
        while new_start < len(new_comments):
            if new_comments[new_start]['no'] > last_older:
                break
            new_start += 1
        log_newer['data']['threads'][i]['comments'] = new_comments[new_start:]


def clip_log(log, min_log_timestamp, forks=None):
    for i in range(len(log['data']['threads'])):
        if forks is not None and log['data']['threads'][i]['fork'] not in forks:
            continue
        comments = log['data']['threads'][i]['comments']
        if not comments:
            continue
        start = 0
        while start < len(comments):
            if int(datetime.datetime.fromisoformat(comments[start]['postedAt']).timestamp()) >= min_log_timestamp:
                break
            start += 1
        log['data']['threads'][i]['comments'] = comments[start:]


def serialize_protobuf(log, video_timestamp, forks=('main', 'easy')):
    j = log
    comments = []
    for f in j['data']['threads']:
        if forks is not None and f['fork'] not in forks:
            continue
        for c in f['comments']:
            comment = nndcomment_pb2.NNDComment()
            comment.thread = int(video_timestamp)
            comment.no = c['no']
            comment.vpos = c['vposMs'] // 10
            comment.date = int(datetime.datetime.fromisoformat(c['postedAt']).timestamp())
            comment.date_usec = 0
            comment.anonymity = '184' in c['commands']
            comment.user_id = c['userId']
            comment.mail = ' '.join(c['commands'])
            # comment.leaf = ?
            comment.premium = c['isPremium']
            comment.score = c['score']
            comment.content = c['body']
            # 13
            # 14
            comment.fork = f['fork']
            comments.append(comment)
    comments.sort(key=lambda x: -x.date)
    comments_serialized = []
    for c in comments:
        serialized = c.SerializeToString()
        comment_len = len(serialized)
        comments_serialized.extend([comment_len.to_bytes(4), serialized])
    return b''.join(comments_serialized)


# TODO: first page gets owner
def download_past_logs(output_file, video_id, log_timestamp, cookies, language,
                       min_log_timestamp=0, max_pages=1, compress=True, append_new=False):
    orig_filename = output_file
    if compress:
        output_file += ".gz"
    if (os.path.exists(output_file)):
        if not append_new:  # and input("File " + output_file + " already exists. Overwrite? [y/N] ").strip().lower() != "y":
            print("File exists, not overwriting.")
            return False
    else:
        append_new = False
    if compress:
        open_func = gzip.open
    else:
        open_func = open

    if append_new:
        with open_func(output_file, mode="rb") as find_fp:
            temp = find_fp.read(4)
            if temp:
                size = int.from_bytes(temp)
            else:
                return False
            comment_serialized = find_fp.read(size)
            comment = nndcomment_pb2.NNDComment()
            comment.ParseFromString(comment_serialized)
            min_log_timestamp = comment.date + 1

    if (os.path.exists(output_file + ".part")):
        if os.path.getsize(output_file + ".part") <= 100:  # empty files, or only gzip header
            os.remove(output_file + ".part")
        else:
            with open_func(output_file + ".part", mode="rb") as find_fp:
                while True:
                    temp = find_fp.read(4)
                    if temp:
                        size = int.from_bytes(temp)
                    else:
                        break
                    find_fp.seek(size, 1)
                find_fp.seek(-size, 1)
                comment_serialized = find_fp.read(size)
                comment = nndcomment_pb2.NNDComment()
                comment.ParseFromString(comment_serialized)
                log_timestamp = comment.date - 1  # TODO: this could skip comments posted 1 sec apart
                # print(str(comment).encode())
    elif compress:
        # Put the original filename in the gzip header
        letters = 'abcdefghijklmnopqrstuvwxyz0123456789'
        random_filename = ''.join(random.choice(letters) for i in range(len(orig_filename.encode())))
        if os.path.exists(random_filename):
            return False
        with open_func(random_filename, mode="wb") as out_fp:
            pass
        os.rename(random_filename, output_file + ".part")
        with open(output_file + ".part", mode="r+b") as out_fp:
            header = out_fp.read(50)
            index = header.find(random_filename.encode())
            if index != -1:
                out_fp.seek(index)
                out_fp.write(orig_filename.encode())

    try:
        with open_func(output_file + ".part", mode="ab") as out_fp:
            video_timestamp, thread_key = get_video_timestamp(video_id, cookies, language)
            final_log = None
            nextpage = log_timestamp
            num_errors = 0

            i = 0
            while i != max_pages:
                try:
                    if num_errors > 0:
                        thread_key = get_thread_key(video_id, cookies, language)
                    past_log = get_past_log(video_id, thread_key, video_timestamp, nextpage, language)
                except urllib.error.HTTPError as e:
                    num_errors += 1
                    if num_errors > 5:
                        print('Download incomplete')
                        break
                    print('Got HTTP Error code: ' + str(e.code) +
                          '. Retrying(' + str(num_errors) + ') with new thread key...')
                    continue
                num_errors = 0
                past_log = json.loads(past_log)

                print('Iteration: ' + str(i), 'Before: ' + str(nextpage),
                      'Comments left: ' + str(past_log['data']['globalComments'][0]['count']))

                if final_log is None:
                    pass
                else:
                    merge_past_log(final_log, past_log, forks=('main', 'easy'))
                    with DelayedKeyboardInterrupt():
                        out_fp.write(serialize_protobuf(final_log, video_timestamp, forks=('main', 'easy')))
                final_log = past_log
                prevpage = nextpage
                nextpage = get_nextpage(past_log)
                if nextpage is None:
                    break
                if nextpage is not None and prevpage is not None:
                    if prevpage <= nextpage:  # prevent potential infinite loop
                        nextpage = prevpage - 1
                if nextpage <= min_log_timestamp:
                    clip_log(final_log, min_log_timestamp)
                    with DelayedKeyboardInterrupt():
                        out_fp.write(serialize_protobuf(final_log, video_timestamp, forks=('main', 'easy')))
                    break
                i += 1

            with DelayedKeyboardInterrupt():
                out_fp.write(serialize_protobuf(final_log, video_timestamp, forks=('owner')))
        if append_new:
            os.rename(output_file, output_file)
            os.rename(output_file + ".part", output_file + ".part")
            with open(output_file + ".part", mode="ab") as new_fp:
                with open(output_file, mode="rb") as old_fp:
                    shutil.copyfileobj(old_fp, new_fp)
            os.remove(output_file)
        os.rename(output_file + ".part", output_file)
        return
    except KeyboardInterrupt:
        print('Exiting clean.')

# TODO: binary search on error
# conversion, save in parts


def nicovideo_url(url):
    m = NICOVIDEO_PATTERN.match(url)
    if not m:
        raise ValueError("Invalid video ID/URL: " + url)
    return m.group('id').lower()


def main():
    if len(sys.argv) == 1:
        sys.argv.append('--help')

    parser = argparse.ArgumentParser()

    parser.add_argument('-d', '--date', metavar=('DATE'), type=int, default=int(time.time()),
                        help=('Unix timestamp to start downloading from, defaults to current time'))
    parser.add_argument('-l', '--language', metavar=('LANGUAGE'), type=str.lower, default='ja-jp', choices=LANGUAGES,
                        help=('Comment language'))
    parser.add_argument('-c', '--compress', action='store_true',
                        help=('Compress output with gzip'))
    parser.add_argument('-a', '--append_new', action='store_true',
                        help=('Append new comments if file is already downloaded'))
    parser.add_argument('video_id', metavar=('VIDEO_ID'), type=nicovideo_url, nargs='+',
                        help=('Video ID or URL to download comments from'))
    args = parser.parse_args()

    for vid in args.video_id:
        output_file = vid + '.' + args.language + '.bin'
        download_past_logs(output_file, vid, args.date, get_cookies('cookies.txt'), args.language, min_log_timestamp=0,
                           max_pages=-1, compress=args.compress, append_new=args.append_new)


if __name__ == '__main__':
    main()
