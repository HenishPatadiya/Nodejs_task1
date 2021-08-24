const fs = require("fs");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const express = require('express');
const app = express()
const port = 3000

app.use(express.json())

let signjwt = (username, jwt) => {
    return jwt.sign({
        username: username
    }, 'secret-key');
};

const verifyjwt = (req, res, next) => {
    let token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({
            error: 'token is required !'
        });
    }
    try {
        const tokendData = jwt.verify(token, 'secret-key');
        req.user = tokendData;
    } catch (err) {
        return res.status(401).json({
            error: 'Invalid Token'
        });
    }
    return next();
}
const data = JSON.parse(fs.readFileSync(`${__dirname}/Data/data.json`));
let flag = 0;

app.get('/users', (req, res) => res.status(200).json(data))

app.post('/signup', (req, res) => {
    // console.log(req.body);
    if (!req.body.username || !req.body.password) {
        return res.status(403).json({
            error: 'Please fill details'
        });
    }
    data.forEach((udata) => {
        if (udata.username == req.body.username) {
            flag = 1;
            return res.status(403).json({
                error: 'user already exist !'
            });
        }
    })

    if (flag == 0) {
        const token = signjwt(req.body.username, jwt)
        let newUser
        // console.log(req.body.password);
        bcrypt.hash(req.body.password, 10, (err, hash) => {
            // console.log(hash);
            newUser = {
                username: req.body.username,
                password: hash,
                todo: [],
            }
            data.push(newUser)
            fs.writeFile(`${__dirname}/Data/data.json`, JSON.stringify(data), (err => {
                res.status(201).json({
                    status: "success",
                    token,
                    data: newUser
                })
            }))
        })
    }
    flag = 0
})

app.post('/login', verifyjwt, (req, res) => {
    if (!req.body.username || !req.body.password) {
        return res.status(403).json({
            error: 'Please fill all details'
        });
    }

    data.forEach((udata) => {
        // console.log(u);

        if (udata.username == req.body.username && bcrypt.compare(req.body.password, udata.password)) {
            flag = 1;
            const token = signjwt(req.body.username, jwt)
            // res.send("Login successfully !");
            if (jwt.verify(token, 'secret-key')) {
                udata.token = token
                res.json(udata)
            } else {
                res.status(401).json({
                    error: "Invalid"
                })
            }            
        }
    })
    if (flag == 0) {
        return res.status(403).json({
            error: "Invalid details !"
        });
    }
    flag = 0;
})

app.post('/addTodo', verifyjwt, (req, res) => {
    if (req.body.newTodo == null && req.body.newTodo == '') {
        return res.status(403).json({
            error: "Please, write somthing !"
        });
    }
    data.forEach((udata) => {
        if (udata.username == req.body.username) {
            udata.todo.push(req.body.newTodo)
            const data = {
                username: req.body.username,
                todo: udata.todo
            };
            res.json(data);
        }
    })
    fs.writeFile(`${__dirname}/Data/data.json`, JSON.stringify(data), (err => {
        if (err) {
            return console.log(err);
        }
    }))
})

app.get('/getTodo', verifyjwt, (req, res) => {
    data.forEach((udata) => {
        if (req.user.username == udata.username) {
            res.json(udata.todo);
        }
    });
});

app.listen(port, () => console.log(`app listening on port ${port}!`))