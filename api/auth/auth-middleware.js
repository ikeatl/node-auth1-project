const { findBy } = require("../users/users-model");

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted() {
  return (req, res, next) => {
    if (req.session && req.session.user) {
      next();
    } else {
      res.status(401).json({ message: "You shall not pass!" });
    }
  };
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
function checkUsernameFree() {
  return async (req, res, next) => {
    const { username } = req.body;
    const user = await findBy({ username });

    if (user.length) {
      res.status(422).json({ message: "Username taken" });
    } else {
      next();
    }
  };
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
function checkUsernameExists() {
  return async (req, res, next) => {
    const { username } = req.body;
    const user = await findBy({ username }).first();

    if (user) {
      req.user = user;
      next();
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  };
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength() {
  return (req, res, next) => {
    const { password } = req.body;

    if (!password || password.length <= 3) {
      res.status(422).json({ message: "Password must be longer than 3 chars" });
    } else {
      next();
    }
  };
}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
};
