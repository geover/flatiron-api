const responseModel = require("../modules/models/response.js");

const AWS = require("aws-sdk");
const jwt = require("jsonwebtoken");

module.exports.handler = async (event, context, callback) => {
  const authorizationHeader = event.headers.Authorization;
  const headers = {
    "Access-Control-Allow-Headers" : "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET",
    "Access-Control-Allow-Origin": event.headers.origin
  };

  // no bearer token
  if (typeof authorizationHeader === "undefined") {
    return callback(
      null,
      responseModel({
        headers,
        statusCode: 403
      })
    );
  }

  // parse token
  const bearerToken = authorizationHeader.split(" ")[1];

  // verify token
  let verifiedToken = null;
  try {
    verifiedToken = jwt.verify(bearerToken, process.env.JWT_SECRET, "complete");
  } catch (error) {
    verifiedToken = null;
  }

  // invalid token
  if (verifiedToken === null) {
    return callback(
      null,
      responseModel({
        headers,
        statusCode: 403
      })
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
      .get({
        TableName: "users",
        Key: {
          userId: verifiedToken.id
        },
        ProjectionExpression: "apiKey, email, firstname, lastname"
      })
      .promise();

    user = res.Item;
  } catch (err) {
    user = null;
  }

  // user does not exist
  if (user === null) {
    return callback(
      null,
      responseModel({
        headers,
        statusCode: 403
      })
    );
  }

  callback(
    null,
    responseModel({
      headers,
      message: "Successfully fetched user!",
      data: { user }
    })
  );
};
