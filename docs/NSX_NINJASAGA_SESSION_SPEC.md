# NS XPanel 1.4.2 — Ninja Saga session / transport specification

Status: static frontend reversing, with native Ghidra verification pending for the WebView login handler.

## Scope

This specification covers only the Ninja Saga client/session path needed by a clean replacement panel.

Explicitly excluded from the replacement design:

- Discord authentication
- NS XPanel licensing
- HWID checks
- `64.235.45.180:3090`
- `/auth/*`, `/access/*`, `/menu/*`
- private NS XPanel tokens

## Critical transport finding

The frontend request router normally selects `game_browser_request_cmd` for Ninja Saga URLs when `useGameBrowser` is enabled.

However, the AMF call helper explicitly invokes the request layer with `useGameBrowser: false` for:

`https://amf.ninjasaga.cc/`

Therefore AMF traffic is sent through the native generic `http_request` command rather than through the authenticated WebView bridge.

Consequences:

1. WebView/cookie state is needed for the initial website login/capture path, not for the ongoing AMF engine.
2. Once the Ninja Saga login payload has been captured and `snsLogin` has yielded the AMF session token, the replacement panel can close/hide the login WebView.
3. The mission/training/hunting engine can use a standalone HTTP client for AMF requests.
4. The original cached-session path further supports this: it validates an existing AMF token with `SystemService.checkAmf` and reloads the character list without reopening the website login.

## Website login boundary

Frontend invokes:

- `start_game_login_cmd({ username, password })`
- `stop_game_login_cmd`

Frontend listens for:

- `game-login-success`
- `game-login-error`

The successful native login event supplies the values needed for the AMF bootstrap:

- `player_id`
- `access_token`
- `signature`
- `hash_time`
- username/session-associated data

Ghidra verification is still pending for the exact native WebView implementation: navigation, form injection, `/login` response interception, event emission, and cleanup.

## AMF bootstrap

Provider constants recovered from the frontend:

- provider: `facebook`
- client/version string: `latest`
- fixed login magic component: `85224034668`

Sequence:

1. `SystemService.requireLogin([time, hash_time, player_id])`
2. Convert returned result to `r`.
3. Generate the login proof from `r + player_id + "facebooklatest85224034668"` using the panel's recovered SHA helper.
4. `SystemService.snsLogin([player_id, "facebook", "latest", r, proof, signature, access_token, language])`
5. Read AMF session token from the returned result.
6. Validate it with `SystemService.checkAmf(...)`.
7. Load `CharacterDAO.getCharactersList([token])`.

## Character selection bootstrap

For the selected character:

1. `CharacterDAO.getCharacterById([token, Number(characterId)])`
2. Extract the selection key (`gk`) from the response.
3. Build the extra-data request with the AMF token, character XP proof, `access_token`, and selection key.
4. `CharacterDAO.getExtraData(...)`
5. Cache the per-character protocol state returned by the service.

The original panel consumes fields including:

- `csv`
- `cfn`
- `ivg`
- `ivn`
- `egv`
- `dvx`
- `slv`
- `sln`
- `gameKeys`
- mission data
- essence/hunting data
- pet data
- hunting passport state

## Direct AMF transport

Endpoint:

`https://amf.ninjasaga.cc/`

Recovered request headers include:

- `Accept: */*`
- `Accept-Language: en-US,en;q=0.9`
- `Content-Type: application/x-amf`
- `Origin: https://ninjasaga.cc`
- `Referer: https://ninjasaga.cc/`
- `Sec-Fetch-Dest: empty`
- `Sec-Fetch-Mode: cors`
- `Sec-Fetch-Site: same-site`
- browser-like `User-Agent`

The frontend AMF helper:

1. encodes the service name and parameter array into AMF;
2. base64-encodes the binary request for the Tauri IPC boundary;
3. calls the generic native `http_request`, explicitly disabling the game-browser route;
4. receives response bytes/base64;
5. decodes the AMF response.

A clean replacement does not need Tauri IPC for this layer; it can send the AMF bytes directly from its own HTTP client.

## Replacement session model

Recommended runtime state:

```text
NinjaSagaSession
  player_id
  access_token
  signature
  hash_time
  amf_token
  selected_character_id
  selected_character_data
  csv / cfn / ivg / ivn / egv / dvx / slv / sln
  gameKeys
  mission/progression metadata
```

The password should only exist for the website login phase and should be discarded after successful session bootstrap. Unlike NS XPanel, the replacement should not persist the password in localStorage/plain JSON.

## Resulting architecture

```text
Username + Password
       |
       v
Temporary ninjasaga.cc WebView
       |
       | capture successful /login payload
       v
player_id + access_token + signature + hash_time
       |
       v
AMF requireLogin / snsLogin
       |
       v
AMF session token
       |
       +--> close/hide login WebView
       |
       v
Standalone HTTPS AMF client
       |
       +--> character selection / extra data
       +--> Leveling
       +--> Exams
       +--> Daily / Special missions
       +--> TP Training
       +--> SS Training
       +--> S-Grade
       +--> Hunting House
```

## Remaining native reversing target

Ghidra is now only essential for fully reconstructing the initial browser-login handler, primarily:

- `start_game_login_cmd`
- `stop_game_login_cmd`
- login WebView construction
- navigation to `ninjasaga.cc`
- username/password injection
- interception of `/login`
- extraction/deserialization of login response
- emission of `game-login-success`
- WebView destruction/session cleanup

`game_browser_request_cmd` is no longer a blocker for the AMF automation engine because the recovered AMF helper deliberately bypasses it.
