import express from "express"
import mongoose from "mongoose"
import listEndpoints from "express-list-endpoints"
import cors from "cors"
import passport from "passport"
import oauth from "./auth/oauth.js"
import cookieParser from "cookie-parser"

import usersRoutes from "./services/users/index.js"
import { unauthorizedErrorHandler, forbiddenErrorHandler, catchAllErrorHandler } from "./errorHandlers.js"

const server = express()

const port = process.env.PORT || 3001

// *************** MIDDLEWARES ****************

server.use(express.json())
server.use(cookieParser())
server.use(cors({ origin: "http://localhost:3000", credentials: true }))
server.use(passport.initialize())

// *************** ROUTES ***********************

server.use("/users", usersRoutes)

// *************** ERROR HANDLERS *****************

server.use(unauthorizedErrorHandler)
server.use(forbiddenErrorHandler)
server.use(catchAllErrorHandler)

console.table(listEndpoints(server))

mongoose.connect(process.env.MONGO_CONNECTION, { useNewUrlParser: true, useUnifiedTopology: true })

mongoose.connection.on("connected", () => {
  console.log("Successfully connected to Mongo!")
  server.listen(port, () => {
    console.log("Server is running on port: ", port)
  })
})

mongoose.connection.on("error", err => {
  console.log(err)
})
