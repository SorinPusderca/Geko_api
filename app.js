// nodemon

const express = require("express");
require("dotenv").config();
const app = express();
const mysql = require("mysql");
const port = process.env.PORT;
const DB_HOST = process.env.DB_HOST;
const DB_USER = process.env.DB_USER;
const DB_PASSWORD = process.env.DB_PASSWORD;
const DB_DATABASE = process.env.DB_DATABASE;
const DB_PORT = process.env.DB_PORT;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

app.use(cors());

console.log("DB_HOST" + DB_HOST);
const db = mysql.createPool({
  connectionLimit: 100,
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_DATABASE,
  port: DB_PORT,
});
db.getConnection((err, connection) => {
  if (err) throw err;
  console.log("DB connected successful: " + connection.threadId);
});
app.listen(port, () => console.log(`Server Started on port ${port}...`));

app.use(express.json());

//CREATE USER

app.post("/createUser", async (req, res) => {
  const user = req.body.name;

  console.log("createUser");
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  db.getConnection(async (err, connection) => {
    if (err) throw err;
    const sqlSearch = "SELECT * FROM user_table WHERE user = ?";
    const search_query = mysql.format(sqlSearch, [user]);
    await connection.query(search_query, async (err, result) => {
      if (err) throw err;
      console.log("------> Search Results");
      console.log(result.length);
      if (result.length != 0) {
        connection.release();
        console.log("------> User already exists");
        res.sendStatus(409);
      } else {
        const sqlInsert = "INSERT INTO user_table VALUES (0,?,?)";
        const insert_query = mysql.format(sqlInsert, [user, hashedPassword]);
        await connection.query(insert_query, (err, result) => {
          connection.release();
          if (err) throw err;
          console.log("--------> Created new User");
          console.log(result.insertId);
          res.sendStatus(201);
        });
      }
    });
  });
});

app.post("/login", async (req, res) => {
  console.log("login");
  const username = req.body.name;
  db.getConnection(async (err, connection) => {
    if (err) throw err;
    const sqlSearch = "SELECT * FROM user_table WHERE user = ?";
    const search_query = mysql.format(sqlSearch, [username]);
    await connection.query(search_query, async (err, result) => {
      if (err) throw err;
      console.log("------> Search Results");
      console.log(result.length);
      if (result.length != 0) {
        user = result[0];

        if (await bcrypt.compare(req.body.password, user.password)) {
          const accessToken = generateAccessToken({ user: req.body.name });
          const refreshToken = generateRefreshToken({ user: req.body.name });
          res.json({ accessToken: accessToken, refreshToken: refreshToken });
        } else {
          res.status(401).send("Password Incorrect!");
        }
        console.log(user);
        connection.release();
        console.log("------> User already exists");
      } else {
        res.status(404).send("User does not exist!");
      }
    });
  });
});

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
}

let refreshTokens = [];
function generateRefreshToken(user) {
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "20m",
  });
  refreshTokens.push(refreshToken);
  return refreshToken;
}

app.post("/refreshToken", (req, res) => {
  if (!refreshTokens.includes(req.body.token))
    res.status(400).send("Refresh Token Invalid");
  refreshTokens = refreshTokens.filter((c) => c != req.body.token);

  const accessToken = generateAccessToken({ user: req.body.name });
  const refreshToken = generateRefreshToken({ user: req.body.name });

  res.json({ accessToken: accessToken, refreshToken: refreshToken });
});

app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter((c) => c != req.body.token);
  res.status(204).send("Logged out!");
});
