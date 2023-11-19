# danmaku-dl
Python script to download all danmaku comments from Nico Nico Douga videos.

## Requirements

- A [nicovideo.jp](https://www.nicovideo.jp/) account that is currently logged in
- Python 3.7+

## Setup

```bash
git clone https://github.com/qbnu/danmaku-dl/
cd danmaku-dl
pip install -r requirements.txt
```
Copy the `cookies.template.txt` file to `cookies.txt` and fill in your NND session cookies.
If your session expires you will have to fill them in again.

## Example usage

```bash
./danmakudl.py sm38213757
```
This will download all the Japanese comments for https://www.nicovideo.jp/watch/sm38213757 to a file called "sm38213757.ja-jp.bin".

```bash
./danmakudl.py --compress --append_new --language en-us sm9
```
This will download all the English comments for https://www.nicovideo.jp/watch/sm9 to a gzip-compressed file called "sm9.en-us.bin.gz".
If the file already exists, any new comments not already downloaded will be appended.

## Converting comments to subtitles

Install/upgrade [danmakuC](https://github.com/HFrost0/danmakuC)
```bash
pip install --upgrade danmakuC
```

Then convert the comments to ASS subtitles
```bash
danmakuC sm38213757.ja-jp.bin -o sm38213757.jpn.ass
```
