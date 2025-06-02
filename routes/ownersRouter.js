const express = require("express");
const router = express.Router();
const ownerModel = require("../models/owner-model");

router.post("/create", async function (req, res) {
  let owners = await ownerModel.find();
  if (owners.length > 0) {
    return res.status(500).send("Can have only 1 owner");
  }
  let { fullname, email, password } = req.body;
  let createdOwner = await ownerModel.create({
    fullname,
    email,
    password,
  });
  res.status(201).send(createdOwner);
});

router.get("/", function (req, res) {
  res.send("hey its working");
});

router.get("/admin", function (req, res) {
  let success = req.flash("success");
  res.render("createproducts", { success });
});

module.exports = router;
