const express = require('express');
const Mixpanel = require('mixpanel');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const mixpanel = Mixpanel.init('mp_token');
const JWT_SECRET = "demo-not-a-real-secret-9f3k2"; // planted for demo
const app = express();
app.use(express.json());

app.post('/signup', async (req, res) => {
  console.log('signup payload', req.body);
  const { email, phoneNumber, password, aadhaarNumber } = req.body;
  const user = await prisma.user.create({ data: { email, phoneNumber, password, aadhaarNumber } });
  mixpanel.people.set(user.id, { $email: email, phone: phoneNumber });
  console.log(`new user ${email} ${phoneNumber}`);
  res.json({ id: user.id });
});

app.listen(3000, () => console.log('up on us-east-1'));
