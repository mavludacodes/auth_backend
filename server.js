const express = require("express");
const { pool } = require("./config");
const bcrypt = require("bcrypt");
const app = express();
const port = process.env.PORT || 8000;
app.use(express.json());

app.use(function (req, res, next) {
  // Website you wish to allow to connect
  res.setHeader(
    "Access-Control-Allow-Origin",
    `${process.env.FRONTEND_ORIGIN}`
  );

  // Request methods you wish to allow
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS, PUT, PATCH, DELETE"
  );

  // Request headers you wish to allow
  res.setHeader(
    "Access-Control-Allow-Headers",
    "X-Requested-With,content-type"
  );

  // Set to true if you need the website to include cookies in the requests sent
  // to the API (e.g. in case you use sessions)
  res.setHeader("Access-Control-Allow-Credentials", true);

  // Pass to next layer of middleware
  next();
});

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// get users
app.get("/api/users", (req, res) => {
  pool.query(
    `SELECT id, name, email, status, created_at, last_login FROM users`,
    (err, result) => {
      if (err) {
        console.log(err);
      }
      // console.log(result.rows);
      res.send(result.rows);
    }
  );
});

// register user
app.post("/api/users", (req, res) => {
  let { name, email, password } = req.body;
  if (!name || !email || !password) {
    res.status(400).send("Error");
  } else {
    pool.query(
      `SELECT * FROM users
       WHERE email = $1`,
      [email],
      async (err, result) => {
        if (err) {
          console.log(err);
        }
        console.log(result.rows);
        if (result.rows.length > 0) {
          res.status(400).send("Email already taken");
        } else {
          let hashedPassword = await bcrypt.hash(password, 10);
          console.log(hashedPassword);
          pool.query(
            `INSERT INTO users (name, email, password) 
             VALUES ($1, $2, $3)
             RETURNING id, name, email`,
            [name, email, hashedPassword],
            (err, r) => {
              if (err) {
                console.log(err);
              }
              console.log(r.rows);
              res.status(200).send(r.rows[0]);
            }
          );
        }
      }
    );
  }
});

// login user
app.post("/api/auth/login", (req, res) => {
  let { email, password } = req.body;
  if (!email || !password) {
    res.status(400).send("Error");
  } else {
    pool.query(
      `SELECT * FROM users
       WHERE email = $1`,
      [email],
      (err, result) => {
        if (err) {
          console.log(err);
        }
        if (result.rows.length > 0) {
          console.log(result.rows);
          let { id, name, email, status } = result.rows[0];

          bcrypt.compare(password, result.rows[0].password, (err, isMatch) => {
            if (err) {
              console.log(err);
            }
            if (isMatch) {
              if (status) {
                const current_time = new Date();
                pool.query(
                  `UPDATE users
                  SET last_login = $1
                  WHERE id = $2
                  RETURNING id, last_login`,
                  [current_time, id],
                  (err, result) => {
                    if (err) {
                      console.log(err);
                    }
                    console.log(result.rows);
                    res.send({ id, name, email });
                  }
                );
              } else {
                res.status(403).send("User blocked");
              }
            } else {
              res.status(401).send("Unauthorized");
            }
          });

          // if (result.rows[0].password == password) {
          //   if (status) {
          //     const current_time = new Date();
          //     pool.query(
          //       `UPDATE users
          //       SET last_login = $1
          //       WHERE id = $2
          //       RETURNING id, last_login`,
          //       [current_time, id],
          //       (err, result) => {
          //         if (err) {
          //           console.log(err);
          //         }
          //         console.log(result.rows);
          //         res.send({ id, name, email });
          //       }
          //     );
          //   } else {
          //     res.status(403).send("User blocked");
          //   }
          // } else {
          //   res.status(401).send("Unauthorized");
          // }
        } else {
          res.status(401).send("Unauthorized");
        }
      }
    );
  }
});

// block user
app.post("/api/users/block", (req, res) => {
  let { id, status } = req.body;
  if (!id || !(typeof status === "boolean")) {
    res.status(400).send("Error");
  } else {
    pool.query(
      `UPDATE users
         SET status = $1
         WHERE id = $2
         RETURNING id, status;`,
      [status, id],
      (err, result) => {
        if (err) {
          console.log(err);
        }
        if (result.rows.length > 0) {
          res.send("Ok");
        } else {
          res.status(404).send("Not found");
        }
      }
    );
  }
});

// delete user
app.delete("/api/users/:id", (req, res) => {
  const id = req.params.id;
  pool.query(
    `DELETE
     FROM users
     WHERE id = $1
     RETURNING id, email;
    `,
    [id],
    (err, result) => {
      if (err) {
        console.log(err);
      }
      if (result.rows.length > 0) {
        console.log(result.rows);
        res.status(202).send("Ok");
      }
    }
  );
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
