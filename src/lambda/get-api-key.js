const responseModel = require("../modules/models/response.js");

const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const xss = require("xss");

module.exports.getApiKey = async (event, context, callback) => {
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

  if (typeof data.email === "string" && data.email !== "") {
    email = xss(data.email.trim());
  }
  if (typeof data.password === "string" && data.password !== "") {
    password = xss(data.password);
  }

  if (typeof email === "undefined") {
    return callback(null, responseModel({ headers, message: "Invalid email" }));
  }
  if (typeof password === "undefined") {
    return callback(
      null,
      responseModel({ headers, message: "Invalid password" })
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

  // prep data
  const params = {
    TableName: "users",
    IndexName: "usersByEmail",
    KeyConditionExpression: "email = :email",
    ExpressionAttributeValues: {
      ":email": email
    },
    ProjectionExpression: "apiKey, password"
  };

  // retrieve user
  let user;
  try {
    const res = await docClient.query(params).promise();
    user = {
      apiKey: res.Items[0].apiKey,
      password: res.Items[0].password
    };
  } catch (err) {
    return callback(
      null,
      responseModel({ headers, message: "Cannot find user!" })
    );
  }

  // compare password
  const isMatched = await bcrypt.compare(password, user.password);
  if (!isMatched) {
    return callback(
      null,
      responseModel({ headers, message: "Cannot find user!" })
    );
  }

  callback(
    null,
    responseModel({
      headers,
      success: true,
      message: "Successfully retrieved api key!",
      data: { apiKey: user.apiKey }
    })
  );
};
