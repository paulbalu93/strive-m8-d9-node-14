import atob from "atob"

import UserModel from "../services/users/schema.js"
import { verifyJWT } from "./tools.js"

export const JWTAuthMiddleware = async (req, res, next) => {
  // if (!req.headers.authorization) {
  //   // if you don't provide credentials you are getting a 401
  //   const error = new Error("Please provide Bearer Token!")
  //   error.httpStatusCode = 401
  //   next(error)
  // } else {
  try {
    // console.log(req.headers.authorization)
    // const token = req.headers.authorization.replace("Bearer ", "")

    const token = req.cookies.accessToken

    const content = await verifyJWT(token) // verifies both the integrity and the expiration date of the token

    const user = await UserModel.findById(content._id)

    req.user = user
    next()
  } catch (error) {
    console.log(error)
    const err = new Error("Token not valid!")
    err.httpStatusCode = 401
    next(err)
  }
  // }
}

export const basicAuthMiddleware = async (req, res, next) => {
  if (!req.headers.authorization) {
    // if you don't provide credentials you are getting a 401
    const error = new Error("Please provide auth!")
    error.httpStatusCode = 401
    next(error)
  } else {
    const decoded = atob(req.headers.authorization.split(" ")[1])
    const [email, password] = decoded.split(":")

    // check the credentials

    const user = await UserModel.checkCredentials(email, password)
    if (user) {
      req.user = user
      next()
    } else {
      const error = new Error("Credentials are wrong")
      error.httpStatusCode = 401
      next(error)
    }

    // const user = await UserModel.findOne({ email })
    // if (user) {
    //   // compare plainPW with hashedPW
    //   const isMatch = await bcrypt.compare(password, user.password)
    //   if (isMatch) {
    //     next()
    //   } else {
    //     const error = new Error("Credentials are wrong!")
    //     error.httpStatusCode = 401
    //     next(error)
    //   }
    // } else {
    //   const error = new Error("Credentials are wrong!")
    //   error.httpStatusCode = 401
    //   next(error)
    // }
  }
}

export const adminOnly = (req, res, next) => {
  if (req.user.role === "Admin") {
    next()
  } else {
    const error = new Error("Admin Only")
    error.httpStatusCode = 403
    next(error)
  }
}
