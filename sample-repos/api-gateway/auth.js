/**
 * JWT issuance and verification for the API gateway.
 *
 * Tokens are consumed by every downstream service; the public key is
 * distributed via the /.well-known/jwks.json endpoint in server.js.
 */

const fs = require('fs');
const jwt = require('jsonwebtoken');

const privateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH || './keys/gateway.pem');
const publicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH || './keys/gateway.pub');

const TOKEN_TTL_SECONDS = 15 * 60;

function issueToken(user) {
  const payload = {
    sub: user.id,
    email: user.email,
    scopes: user.scopes || [],
  };
  return jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    expiresIn: TOKEN_TTL_SECONDS,
    issuer: 'api-gateway',
  });
}

function verifyToken(token) {
  return jwt.verify(token, publicKey, {
    algorithms: ['RS256'],
    issuer: 'api-gateway',
  });
}

module.exports = { issueToken, verifyToken, TOKEN_TTL_SECONDS };
