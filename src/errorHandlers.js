export const unauthorizedErrorHandler = (err, req, res, next) => {
  if (err.httpStatusCode === 401) {
    res.status(401).send(err.message)
  } else {
    next(err)
  }
}

export const forbiddenErrorHandler = (err, req, res, next) => {
  if (err.httpStatusCode === 403) {
    res.status(403).send(err.message)
  } else {
    next(err)
  }
}

export const catchAllErrorHandler = (err, req, res, next) => {
  console.log(err)
  res.status(500).send("Generic Server Error")
}
