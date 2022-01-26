const responseModel = require("../modules/models/response.js");

const AWS = require("aws-sdk");
const xss = require("xss");
const axios = require("axios");
const rdsDataService = new AWS.RDSDataService();

module.exports.check = async (event, context, callback) => {
  let data = event.body;
  if (data.constructor.name === "String" || typeof data === "string") {
    data = JSON.parse(data);
  }

  const headers = {
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST",
    "Access-Control-Allow-Origin": event.headers.origin,
  };

  let email;
  let password;

  if (typeof data.email === "string" && data.email !== "") {
    email = xss(data.email.trim());
  }
  if (
    typeof data.password === "object" &&
    typeof data.password.SHA1 !== "undefined" &&
    typeof data.password.SHA256 !== "undefined" &&
    typeof data.password.MD5 !== "undefined" &&
    data.password.SHA1 !== "" &&
    data.password.SHA256 !== "" &&
    data.password.MD5 !== ""
  ) {
    password = {
      SHA1: xss(data.password.SHA1.trim()),
      SHA256: xss(data.password.SHA256.trim()),
      MD5: xss(data.password.MD5.trim()),
    };
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

  // flags
  let isHibpEmailCompromised = false;
  let isHibpPasswordCompromised = false;
  let isCommonPassword = false;
  let isDarkWebPasswordCompromised = false;

  // prep dynamodb connection
  const options = {
    region: "us-east-1",
    accessKeyId: process.env.DYNAMODB_ACCESS_KEY_ID,
    secretAccessKey: process.env.DYNAMODB_SECRET_ACCESS_KEY,
  };
  let docClient = new AWS.DynamoDB.DocumentClient(options);

  // common password check
  try {
    const res = await docClient
      .query({
        TableName: "common_passwords",
        KeyConditionExpression: "sha1_password = :sha1Password",
        ExpressionAttributeValues: {
          ":sha1Password": password.SHA1,
        },
      })
      .promise();
    if (res.Count > 0) {
      isCommonPassword = true;
    }
  } catch (err) {
    isCommonPassword = false;
  }

  // darkweb password check
  try {
    const res = await docClient
      .query({
        TableName: "darkweb_passwords",
        KeyConditionExpression: "sha1_password = :sha1Password",
        ExpressionAttributeValues: {
          ":sha1Password": password.SHA1,
        },
      })
      .promise();
    if (res.Count > 0) {
      isDarkWebPasswordCompromised = true;
    }
  } catch (err) {
    isDarkWebPasswordCompromised = false;
  }

  // hibp request headers
  const requestHeaders = {
    "hibp-api-key": "4a76c0a3eea54890bb353db7d624b1f3",
    "user-agent": "Flatironcyber",
  };

  // hibp check (email)
  try {
    const response = await axios.get(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${email}`,
      {
        headers: requestHeaders,
      }
    );

    if (response.status === 200) {
      isHibpEmailCompromised = true;
    }
  } catch (error) {
    isHibpEmailCompromised = false;
  }

  // hibp check (password)
  try {
    const response = await axios.get(
      `https://api.pwnedpasswords.com/range/${password.SHA1.slice(0, 5)}`,
      {
        headers: requestHeaders,
      }
    );

    if (response.status === 200) {
      const pwnedPasswords = response.data
        .split("\r\n")
        .map((pwnedPassword) => {
          return pwnedPassword.split(":")[0];
        })
        .filter(
          (pwnedPassword) =>
            pwnedPassword.toLowerCase() === password.SHA1.slice(5)
        );

      if (pwnedPasswords.length > 0) {
        isHibpPasswordCompromised = true;
      }
    }
  } catch (error) {
    isHibpPasswordCompromised = false;
  }

  // confidence matrix
  const a = Number(isHibpEmailCompromised);
  const b = Number(isHibpPasswordCompromised);
  const c = Number(isDarkWebPasswordCompromised);
  const d = Number(isCommonPassword);
  const combination = Number(`1${a}${b}${c}${d}`);
  const matrix = {
    10000: 0,
    10001: 0,
    10010: 65,
    10011: 88,
    10100: 15,
    10101: 25,
    10110: 65,
    10111: 65,
    11000: 5,
    11001: 79,
    11010: 65,
    11011: 93,
    11100: 40,
    11101: 85,
    11110: 100,
    11111: 100,
  };
  const compromisedConfidenceScore = matrix[combination];

  // Log
  // prepare SQL command
  let sqlParams = {
    secretArn: process.env.RDS_SECRET_ARN,
    resourceArn: process.env.RDS_RESOURCE_ARN,
    database: "flatiron",
    sql: `INSERT INTO logs (hibp_email, hibp_password, darkweb_password, common_password, score, ip_address, timestamp) VALUES(${a}, ${b}, ${c}, ${d}, ${compromisedConfidenceScore}, '${
      event.requestContext.identity.sourceIp
    }', ${event.requestContext.requestTimeEpoch / 1000});`,
  };
  // run SQL command
  rdsDataService.executeStatement(sqlParams, function (err, data) {
    if (err) {
      console.log("Something went wrong: " + err);
    } else {
      console.log("Successfully inserted logs!");
    }
  });

  callback(
    null,
    responseModel({
      headers,
      success: true,
      message: "Done checking!",
      data: {
        isEmailCompromised: a,
        isPasswordCompromised: b || c || d,
        compromisedConfidenceScore,
      },
    })
  );
};
