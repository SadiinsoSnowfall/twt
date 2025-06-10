# TWT

Initially based on code from https://github.com/trevorhobenshield/twitter-api-client.

Using https://github.com/iSarabjitDhiman/XClientTransaction.


### Usage :
Either set your twitter cookies in the `LOCAL_COOKIES` variable and update the `FETCH_COOKIES_FROM_BROWSER` variable accordingly, or set the `PREFFERED_BROWSER` and let the script fetch your cookies automatically.

After that:
```
python twt.py <keyword>
```


### Misc:

- Blocked users infos are stored in the `storage.db` sqlite3 database.
- May need root/admin privileges to run when fetching cookies from your browser.
