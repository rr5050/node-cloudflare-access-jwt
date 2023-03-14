import * as dotenv from 'dotenv'
import jwt from 'jsonwebtoken'
import jwksClient from 'jwks-rsa'

dotenv.config()

const AUTH_CERTS_URL = process.env.AUTH_CERTS_URL
const AUTH_AUDIENCE_TAG = process.env.AUTH_AUDIENCE_TAG
const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME
const AUTH_FAILED_URL = process.env.AUTH_FAILED_URL

const client = jwksClient({
	// Signing keys cache
	cache: true, // Default Value
	cacheMaxEntries: 5, // Default value
	cacheMaxAge: 600000, // Defaults to 10m

	// rate limiting to prevent attackers sending many random KIDs
	rateLimit: true,
	jwksRequestsPerMinute: 10, // Default value

	// URL to Cloudflares public keys
	jwksUri: AUTH_CERTS_URL,
})

const handleFailedValidation = (res, message) => {
	console.log(message)
	res.redirect(AUTH_FAILED_URL)
}

function validateCloudflareAccess(req, res, next) {
	// extract the JWT token from cookies
	const token = req.cookies[AUTH_COOKIE_NAME]
	if (token) {
		const decodedToken = jwt.decode(token, { complete: true })
		const KIDclaim = decodedToken.header.kid
		const email = decodedToken.payload.email

		// look for the KID claim in Cloudflares public signing keys
		client.getSigningKey(KIDclaim, (err, key) => {
			if (!err) {
				try {
					const signingKey = key.getPublicKey()

					// verify the signature of the token
					jwt.verify(token, signingKey, { audience: AUTH_AUDIENCE_TAG })

					req.auth = { email: email } // set variable so that it can be accessed in the next middleware
					console.log(`Auth: Status 200: User allowed: ${email}`)
					next()
				} catch (e) {
					handleFailedValidation(
						res,
						`Auth: Status 403: malformed token. User NOT allowed: ${email}`
					)
				}
			} else {
				handleFailedValidation(
					res,
					`Auth: Status 403: error while fetching key. User NOT allowed: ${email}`
				)
			}
		})
	} else {
		handleFailedValidation(res, 'Auth: Status 403: no token. User NOT allowed')
	}
}

export default validateCloudflareAccess
