const responseModel = require("../modules/models/response.js");

const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const xss = require("xss");

module.exports.signIn = async (event, context, callback) => {
  let data = event.body;
  if (data.constructor.name === "String" || typeof data === "string") {
    data = JSON.parse(data);
  }

  const headers = {
    "Access-Control-Allow-Headers" : "Content-Type",
    "Access-Control-Allow-Methods": "POST",
    "Access-Control-Allow-Origin": event.headers.origin
  };

  let email;
  let password;

  if (typeof data.email === "string" && data.email.trim() !== "") {
    email = xss(data.email);
  }
  if (typeof data.password === "string" && data.password !== "") {
    password = xss(data.password);
  }

  if (typeof email === "undefined") {
    return callback(
      null,
      responseModel({ headers, message: "Please enter a valid email address." })
    );
  }
  if (typeof password === "undefined") {
    return callback(
      null,
      responseModel({ headers, message: "Please enter your password." })
    );
  }

  // prep connection
  let options = {};
  if (process.env.IS_OFFLINE) {
    options = {
      region: "localhost",
      endpoint: "http://localhost:8000"
    };
  }
  let docClient = new AWS.DynamoDB.DocumentClient(options);

  // get user
  let user = null;
  try {
    const res = await docClient
      .query({
        TableName: "users",
        IndexName: "usersByEmail",
        KeyConditionExpression: "email = :email",
        ExpressionAttributeValues: {
          ":email": email
        },
        ProjectionExpression: "userId, password"
      })
      .promise();

    if (res.Items.length > 0) {
      user = res.Items[0];
    }
  } catch (err) {
    user = null;
  }

  if (user === null) {
    return callback(
      null,
      responseModel({ headers, message: "Account does not exist!" })
    );
  }

  // compare password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return callback(
      null,
      responseModel({ headers, message: "Account does not exist!" })
    );
  }

  // generate jwt
  const token = jwt.sign({ id: user.userId }, process.env.JWT_SECRET, {
    expiresIn: 86400 // expires in 24 hours (not final)
  });

  callback(
    null,
    responseModel({
      headers,
      success: true,
      message: "Authenticated!",
      data: { token }
    })
  );
};
