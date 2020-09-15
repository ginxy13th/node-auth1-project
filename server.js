const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcryptjs = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const usersRouter = require("./users/users-router.js");
const authRouter = require("./auth/auth-router.js"); 
const connection = require("./connection.js");

const server = express();

const sessionConfig = {
    name: "monster",
    secret: process.env.SESSION_SECRET || "keep it secret, keep it safe!",
    resave: false,
    saveUninitialized: true, 
    cookie: {
        maxAge: 1000 * 60 * 60, 
        secure: process.env.USE_SECURE_COOKIES || false, 
        httpOnly: true, 
    },
    store: new KnexSessionStore({
        knex: connection, 
        tablename: "sessions",
        sidfieldname: "sid",
        createtable: true,
        clearInterval: 1000 * 60 * 60,
    }),
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig)); 

server.use("/api/users", protected, usersRouter);
server.use("/api/auth", authRouter); 

server.get("/", (req, res) => {
    const password = req.headers.password;
    const rounds = process.env.BCRYPT_ROUNDS || 4; 
    const hash = bcryptjs.hashSync(password, rounds);
    res.json({ api: "up", password, hash });
});

function protected(req, res, next) {
    if (req.session.username) {
        next();
    } else {
        res.status(401).json({ you: "cannot pass!" });
    }
}

module.exports = server;

