# TWT

Initially based on code from https://github.com/trevorhobenshield/twitter-api-client.

Using https://github.com/iSarabjitDhiman/XClientTransaction.


### Usage :
Either set your twitter cookies in the `LOCAL_COOKIES` variable and update the `FETCH_COOKIES_FROM_BROWSER` variable accordingly, or set the `PREFFERED_BROWSER` and let the script fetch your cookies automatically.

After that:

Blocking every used that has tweeted a specific keyword, hashtag, code ticker, etc...
```
twt.py kw <keyword>
```

Blocking every followers of a specific user:
```
twt.py fw -n/--name <@handle>
twt.py fw -i/--id <user_id>
```

For the later, in case of API ratelimit, forced-disconnection, etc... You can resume the operation by running the following command:
```
twt.py fw --continue
```

Information about the last follower-based blocking operation is stored in the local database.

### Misc:

- Blocked users infos are stored in the `storage.db` sqlite3 database.
- May need root/admin privileges to run when fetching cookies from your browser.
