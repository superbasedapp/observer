const express = require("express");
const { ObjectId } = require("mongodb");
const User = require("./models/user");

const app = express();

app.post("/login", async (req, res) => {
  // ruleid: js.nosql-injection
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  // ok: js.nosql-injection
  const same = await User.findOne({ email: String(req.body.email) });
  // ok: js.nosql-injection
  const byId = await User.findOne({ _id: new ObjectId(req.body.id) });
  res.json(user || same || byId);
});

app.get("/search", async (req, res) => {
  const users = db.collection("users");
  // ruleid: js.nosql-injection
  const found = await users.find(req.query).toArray();
  // ruleid: js.nosql-injection
  const scripted = await db.collection("users").find({ $where: "this.name == '" + req.query.name + "'" }).toArray();
  // ok: js.nosql-injection
  const pick = [1, 2, 3].find((n) => n === Number(req.query.n));
  // ok: js.nosql-injection
  const byName = await usersCollection.find({ name: req.params.name }).toArray();
  res.json([found, scripted, pick, byName]);
});

// The program's own values, not request input.
async function byEmail(email) {
  // ok: js.nosql-injection
  return User.findOne({ email });
}
