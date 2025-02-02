// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require("express");
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require("./auth-middleware");
const { add } = require("../users/users-model");
const bcrypt = require("bcryptjs");
const router = express.Router();

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post("/register", checkUsernameFree(), checkPasswordLength(), async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 8);
    const user = { username, password: hash };
    const newUser = await add(user);

    res.status(200).json({ user_id: newUser.user_id, username: newUser.username });
  } catch (err) {
    next(err);
  }
});

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post("/login", checkUsernameExists(), (req, res, next) => {
  try {
    const { password } = req.body;
    const user = req.user;

    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.user = user;
      res.status(200).json({ message: `Welcome ${user.username}!` });
    } else {
      res.status(401).json({ message: "Invalid Credentials" });
    }
  } catch (err) {
    next(err);
  }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get("/logout", (req, res, next) => {
  if (req.session && req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        next(err);
      } else {
        res.status(200).json({ message: "logged out" });
      }
    });
  } else {
    res.status(200).json({ message: "no session" });
  }
});

// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router;
