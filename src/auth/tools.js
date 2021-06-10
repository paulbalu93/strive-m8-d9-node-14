import jwt from "jsonwebtoken"
import UserModel from "../services/users/schema.js"

export const JWTAuthenticate = async user => {
  const accessToken = await generateJWT({ _id: user._id })
  const refreshToken = await generateRefreshJWT({ _id: user._id })

  user.refreshToken = refreshToken

  await user.save()

  return { accessToken, refreshToken }
}

const generateJWT = payload =>
  new Promise((res, rej) =>
    jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "10s" }, (err, token) => {
      if (err) rej(err)
      res(token)
    })
  )

export const verifyJWT = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.JWT_SECRET, (err, token) => {
      if (err) rej(err)
      res(token)
    })
  )

const generateRefreshJWT = payload =>
  new Promise((res, rej) =>
    jwt.sign(payload, process.env.REFRESH_JWT_SECRET, { expiresIn: "1 week" }, (err, token) => {
      if (err) rej(err)
      res(token)
    })
  )

export const verifyRefreshJWT = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.REFRESH_JWT_SECRET, (err, token) => {
      if (err) rej(err)
      res(token)
    })
  )

export const refreshTokens = async oldRefreshToken => {
  // 1. is the token expired or not valid?

  const content = await verifyRefreshJWT(oldRefreshToken)

  // 2. if the token is valid we can move on with the refresh token flow

  const user = await UserModel.findById(content._id)

  if (!user) throw new Error("Token not valid!")

  if (user.refreshToken !== oldRefreshToken) throw new Error("Token not valid!")

  // 3. if everything is fine we need to generate a new pair of tokens

  const newAccessToken = await generateJWT({ _id: user._id })
  const newRefreshToken = await generateRefreshJWT({ _id: user._id })

  // 4. save new refresh token in db

  user.refreshToken = newRefreshToken

  await user.save()

  return { newAccessToken, newRefreshToken }
}
