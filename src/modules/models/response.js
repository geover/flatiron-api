module.exports = ({
  message = "Unknown error!",
  success = false,
  statusCode = 200,
  headers = {},
  data
} = {}) => {
  const payload = {
    message,
    success
  };
  if (typeof data !== "undefined") {
    payload.data = data;
  }

  return {
    statusCode,
    headers,
    body: JSON.stringify(payload)
  };
};
