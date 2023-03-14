# node-cloudflare-access-jwt

This sets up an server for BOTH http and https. In production you would probably only want https.

Main point of this code is the middleware that checkes the JWT from CloudFlare Access.

You will need an Cloudflare account with your own Domain name. Setup a tunnel (cloudflare zero trust) with some other means (docker, or other). Point the http or https tunnel with the port to what you have in this code.

Other tip: replace console.log in the middleware with some type of logger function
