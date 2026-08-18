/*
Author: Dalia Anaee
Date: November 2025
Description: ToDo List
*/

//add first!!! the required packages
import express from "express";
import { engine } from "express-handlebars";
import cookieParser from "cookie-parser";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";

const app = express();
const PORT = 3000;

//bcrypt salt rounds
const saltRounds = 10;

//middleware
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

//view engine
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set("views", "./views");

//database connection
const dbPromise = open({
  filename: "todolist.sqlite",
  driver: sqlite3.Database,
});

//initialize database tables
async function authMiddleware(req, res, next) {
  const db = await dbPromise;
  const token = req.cookies.authToken;

  if (!token) {
    return next(); // not logged in
  }

  const tokenRow = await db.get("SELECT * FROM authtokens WHERE token = ?", [
    token,
  ]);

  if (!tokenRow) {
    return next(); //invalid token
  }

  const user = await db.get(
    "SELECT user_id, username FROM users WHERE user_id = ?",
    [tokenRow.user_id]
  );

  req.user = user; //makes user available in req.user
  next();
}

//use the auth middleware
app.use(authMiddleware);

//The home page
app.get("/", async (req, res) => {
  if (!req.user) {
    return res.redirect("/login");
  }

  const db = await dbPromise;

  const tasks = await db.all("SELECT * FROM tasks WHERE user_id = ?", [
    req.user.user_id,
  ]);

  res.render("home", {
    username: req.user.username,
    tasks: tasks,
  });
});

//Login page
app.get("/login", (req, res) => {
  res.render("login");
});

//Register page
app.get("/register", (req, res) => {
  res.render("register");
});

//Logout
app.get("/logout", (req, res) => {
  res.clearCookie("authToken");
  return res.redirect("/login");
});

//Handle form submissions
app.post("/register", async (req, res) => {
  const db = await dbPromise;
  const { username, password, confirm } = req.body;

  if (!username || !password || !confirm) {
    return res.render("register", { error: "All fields required" });
  }

  if (password !== confirm) {
    return res.render("register", { error: "Passwords must match" });
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  try {
    await db.run("INSERT INTO users (username, password) VALUES (?, ?)", [
      username,
      hashedPassword,
    ]);

    const newUser = await db.get("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    const token = uuidv4();
    await db.run("INSERT INTO authtokens (token, user_id) VALUES (?, ?)", [
      token,
      newUser.user_id,
    ]);

    res.cookie("authToken", token);
    return res.redirect("/");
  } catch (err) {
    return res.render("register", { error: "Username already exists" });
  }
});

//Login handler
app.post("/login", async (req, res) => {
  const db = await dbPromise;
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render("login", { error: "All fields required" });
  }

  const user = await db.get("SELECT * FROM users WHERE username = ?", [
    username,
  ]);

  if (!user) {
    return res.render("login", {
      error: "Error: username or password incorrect",
    });
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.render("login", {
      error: "Error: username or password incorrect",
    });
  }

  const token = uuidv4();
  await db.run("INSERT INTO authtokens (token, user_id) VALUES (?, ?)", [
    token,
    user.user_id,
  ]);

  res.cookie("authToken", token);
  return res.redirect("/");
});

//Add task handler
app.post("/add-task", async (req, res) => {
  const db = await dbPromise;

  if (!req.user) {
    return res.redirect("/login");
  }

  const desc = req.body.task_desc;

  if (!desc) {
    return res.redirect("/");
  }

  await db.run(
    "INSERT INTO tasks (user_id, task_desc, is_complete) VALUES (?, ?, 0)",
    [req.user.user_id, desc]
  );

  return res.redirect("/");
});

//Mark task as complete handler
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
