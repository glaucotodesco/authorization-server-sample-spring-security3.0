# Auth EndPoints and Info
    http://localhost:9000/.well-known/oauth-authorization-server

# Get Auth Code
    https://oauthdebugger.com/
        - Authorize URI (required): http://localhost:9000/oauth/authorize
        - Redirect URI (required): https://oauthdebugger.com/debug
        - Client ID (required): client
        - Scope (required): openid
        - Response type (required): 
            - code: checked
            - Use PKCE: SHA-256
                - Token URI (required for PKCE): http://localhost:9000/oauth2/token
        - Response mode (required): form_post

# Get Token
    - POST: http://localhost:9000/oauth2/token
    - Authorization
        Username: client
        Password: secret
    - Body: x-www-form-urlencoded
        - grant_type: authorization_code
        - client_id: client
        - redirect_uri: https://oauthdebugger.com/debug
        - code_verifier: (Get from oauthdebugger.com) like: R1oASTP4h8e3NS0St5MdvTNSIyvBG7cK8OEdyGHUEo     
        - code: (Get from oauthdebugger.com after login) like this: q8XK0RtlnxYOpK7zMcGHvXxvWt5wva0P51hrqYQLw5FBDfpphNQzTj5AiOpDg9U2Ju8DiSfJdzPNx37kily4i0TbSoknQAqsqjhwtLqa8GvJbr75dbkVpZNrYKSXciUy

# Debug Token
    https://jwt.io/

# Login
    http://localhost:9000/login

    user
    123456

    adm
    123456

# Logout
    http://localhost:9000/logout









