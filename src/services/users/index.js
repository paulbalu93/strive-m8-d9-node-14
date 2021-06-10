import express from "express"
import passport from "passport"

import UserModel from "./schema.js"
import { basicAuthMiddleware, adminOnly, JWTAuthMiddleware } from "../../auth/index.js"
import { JWTAuthenticate, refreshTokens } from "../../auth/tools.js"

const usersRouter = express.Router()

usersRouter.post("/register", async (req, res, next) => {
  try {
    const newUser = new UserModel(req.body)
    const { _id } = await newUser.save()

    res.status(201).send(_id)
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/", JWTAuthMiddleware, async (req, res, next) => {
  try {
    const users = await UserModel.find()
    res.send(users)
  } catch (error) {
    next(error)
  }
})

usersRouter.get("/me", JWTAuthMiddleware, async (req, res, next) => {
  try {
    res.send(req.user)
  } catch (error) {
    next(error)
  }
})

usersRouter.delete("/me", basicAuthMiddleware, async (req, res, next) => {
  try {
    await req.user.deleteOne()
    res.status(204).send()
  } catch (error) {
    next(error)
  }
})

usersRouter.put("/me", basicAuthMiddleware, async (req, res, next) => {
  try {
    console.log(req.body)

    // req.user.name = req.body.name

    const updates = Object.keys(req.body)

    updates.forEach(u => (req.user[u] = req.body[u]))

    await req.user.save()

    res.status(204).send()
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body
    // 1. verify credentials

    const user = await UserModel.checkCredentials(email, password)
    // 2. generate access token

    const tokens = await JWTAuthenticate(user)

    res.cookie("accessToken", tokens.accessToken, { sameSite: "lax", httpOnly: true })

    // LOCAL ENVIRONMENT --> sameSite:"lax", PRODUCTION ENVIRONMENT (with 2 different domains) --> sameSite:"none", secure: true
    res.cookie("refreshToken", tokens.refreshToken, { sameSite: "lax", httpOnly: true })

    // 3. send token as a response
    res.send()
  } catch (error) {
    next(error)
  }
})

usersRouter.post("/refreshToken", async (req, res, next) => {
  try {
    const oldRefreshToken = req.cookies.refreshToken

    // 1. We need to check the validity and integrity of the old refresh token, if ok we are going to generate a new pair of access + refresh token
    const tokens = await refreshTokens(oldRefreshToken)
    // 2. Send back the new tokens
    res.cookie("accessToken", tokens.accessToken, { sameSite: "lax", httpOnly: true })

    // LOCAL ENVIRONMENT --> sameSite:"lax", httpOnly:true, PRODUCTION ENVIRONMENT (with 2 different domains) --> sameSite:"none", secure: true, httpOnly: true
    res.cookie("refreshToken", tokens.refreshToken, { sameSite: "lax", httpOnly: true })
    res.send()
    tokens
  } catch (error) {
    console.log(error)
    const err = new Error("Please login again!")

    err.httpStatusCode = 401
    next(err)
  }
})

usersRouter.post("/logout", JWTAuthMiddleware, async (req, res, next) => {
  try {
    req.user.refreshToken = null
    await req.user.save()
    res.clearCookie("accessToken")
    res.clearCookie("refreshToken")
    res.send("Logged out!")
  } catch (error) {
    next(error)
  }
})

// **************** GOOGLE OAUTH *******************************
usersRouter.get("/googleLogin", passport.authenticate("google", { scope: ["profile", "email"] }))

usersRouter.get("/googleRedirect", passport.authenticate("google"), async (req, res, next) => {
  try {
    // res.send(req.user.tokens)
    res.cookie("accessToken", req.user.tokens.accessToken, { sameSite: "lax", httpOnly: true })

    // LOCAL ENVIRONMENT --> sameSite:"lax", PRODUCTION ENVIRONMENT (with 2 different domains) --> sameSite:"none", secure: true
    res.cookie("refreshToken", req.user.tokens.refreshToken, { sameSite: "lax", httpOnly: true })
    res.status(200).redirect("http://localhost:3000")
  } catch (error) {
    next(error)
  }
})

export default usersRouter
