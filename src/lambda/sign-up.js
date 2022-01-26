const responseModel = require("../modules/models/response.js");

const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const md5 = require("md5");
const xss = require("xss");
const { v4: uuidv4 } = require("uuid");

module.exports.signUp = async (event, context, callback) => {
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
  let firstname;
  let lastname;
  let password;
  let confirmPassword;

  // sanitize and set data
  if (typeof data.email === "string" && data.email.trim() !== "") {
    email = xss(data.email);
  }
  if (typeof data.firstname === "string" && data.firstname.trim() !== "") {
    firstname = xss(data.firstname);
  }
  if (typeof data.lastname === "string" && data.lastname.trim() !== "") {
    lastname = xss(data.lastname);
  }
  if (typeof data.password === "string" && data.password !== "") {
    password = xss(data.password);
  }
  if (typeof data.confirmPassword === "string" && data.confirmPassword !== "") {
    confirmPassword = xss(data.confirmPassword);
  }

  // validate data
  if (typeof email === "undefined") {
    return callback(
      null,
      responseModel({ headers, message: "Please enter a valid email address." })
    );
  }
  if (typeof firstname === "undefined") {
    return callback(
      null,
      responseModel({ headers, message: "Please enter your first name." })
    );
  }
  if (typeof lastname === "undefined") {
    return callback(
      null,
      responseModel({ headers, message: "Please enter your last name." })
    );
  }
  if (typeof password === "undefined") {
    return callback(
      null,
      responseModel({ headers, message: "Please enter your password." })
    );
  }
  if (typeof confirmPassword === "undefined") {
    return callback(
      null,
      responseModel({ headers, message: "Please re-type your password." })
    );
  }
  if (password !== confirmPassword) {
    return callback(
      null,
      responseModel({ headers, message: "Passwords don't match." })
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

  // check duplicate email
  let existingEmailCount = 0;
  try {
    const res = await docClient
      .query({
        TableName: "users",
        IndexName: "usersByEmail",
        KeyConditionExpression: "email = :email",
        ExpressionAttributeValues: {
          ":email": email
        },
        ProjectionExpression: "email"
      })
      .promise();

    existingEmailCount = res.Count;
  } catch (err) {
    existingEmailCount = 1;
  }

  if (existingEmailCount > 0) {
    return callback(
      null,
      responseModel({ headers, message: "Email address is already in use." })
    );
  }

  // hash password
  let hashedPassword = await bcrypt.hash(password, 10);
  if (!hashedPassword) {
    return callback(null, responseModel({ headers }));
  }

  // prep data
  const uuid = uuidv4();
  const params = {
    TableName: "users",
    Item: {
      userId: uuid,
      firstname,
      lastname,
      email,
      apiKey: `${uuid}-${md5(email)}`,
      password: hashedPassword
    }
  };

  // create user
  let isSuccess = true;
  docClient.put(params, function (err) {
    if (err) {
      isSuccess = false;
    }
  });

  if (!isSuccess) {
    return callback(
      null,
      responseModel({ headers, message: "Unable to register user!" })
    );
  }

  // generate jwt
  const token = jwt.sign({ id: params.Item.userId }, process.env.JWT_SECRET, {
    expiresIn: 86400 // expires in 24 hours (not final)
  });

  callback(
    null,
    responseModel({
      headers,
      success: true,
      message: "Successfully registered!",
      data: { token }
    })
  );
};
