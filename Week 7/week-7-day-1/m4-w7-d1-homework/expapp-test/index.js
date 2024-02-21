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