import express from 'express'
import fs from 'fs'
import http from 'http'
import https from 'https'
import cookieParser from 'cookie-parser'
import validateCloudflareAccess from './middleware/validatecloudflareaccess.middleware.js'

const app = express()

app.use(cookieParser())

app.use(validateCloudflareAccess)

app.get('/', (req, res) => {
	res.header('Content-type', 'text/html')
	return res.end('<h1>Hello, Secure World!</h1>')
})

const serverOptions = {
	// Certificate(s) & Key(s) - generate them yourself or get them from somewhere
	cert: fs.readFileSync('certificates/cert.pem', 'utf8'),
	key: fs.readFileSync('certificates/key.pem', 'utf8'),

	// TLS Versions
	maxVersion: 'TLSv1.3',
	minVersion: 'TLSv1.3',

	// Hardened configuration
	ciphers: 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256',
	ecdhCurve: 'P-521:P-384',
	sigalgs: 'rsa_pss_rsae_sha384',

	// // Attempt to use server cipher suite preference instead of clients
	honorCipherOrder: true,
}

var httpServer = http.createServer(app)
var httpsServer = https.createServer(serverOptions, app)

// For http
httpServer.listen(8080, () => {
	console.log(`[-] Server Listening on Port 8080 (http)`)
})

// For https
httpsServer.listen(3000, () => {
	console.log(`[-] Server Listening on Port 3000 (https)`)
})
