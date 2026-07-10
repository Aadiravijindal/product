/** API gateway entrypoint — routes public traffic to internal services. */

const express = require('express');
const { issueToken, verifyToken } = require('./auth');

const app = express();
app.use(express.json());

app.post('/login', (req, res) => {
  // Demo stub: a real deployment validates credentials against the IdP.
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });
  const token = issueToken({ id: `u_${email}`, email, scopes: ['read'] });
  res.json({ token });
});

app.use('/api', (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer /, '');
  try {
    req.user = verifyToken(token);
    next();
  } catch (err) {
    res.status(401).json({ error: 'invalid token' });
  }
});

app.get('/api/me', (req, res) => res.json({ user: req.user }));

app.listen(process.env.PORT || 8080);
