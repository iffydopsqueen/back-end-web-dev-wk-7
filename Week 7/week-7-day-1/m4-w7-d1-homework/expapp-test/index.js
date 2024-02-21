const express = require("express");
const app = express();
const https = require("https");
const port = 3000;

function allTodos() {
    return [{
        id: 1,
        name: "Finished writing a blogpost"
    }, {
        id: 2,
        name: "Get pizza for dinner"
    }, {
        id: 3,
        name: "Wake up at 7:30am"
    }, ];
}

app.get("/", (req, res) => {
    res.send({
        date: new Date(),
        msg: "Greetings!"
    });
});

app.get("/todo", (req, res) => {
    res.send(allTodos());
});

app.get("/todo/:id", (req, res) => {
    const todoId = Math.abs(req.params.id);
    let todos = allTodos();
    let todo = todos.find(t => t.id === todoId);
    res.send(todo);
});