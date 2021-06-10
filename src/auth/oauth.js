import passport from "passport"
import GoogleStrategy from "passport-google-oauth2"

import UserModel from "../services/users/schema.js"
import { JWTAuthenticate } from "./tools.js"

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_SECRET,
      callbackURL: "http://localhost:3001/users/googleRedirect",
    },
    async (request, accessToken, refreshToken, profile, next) => {
      // this function will be executed when we got a response back from Google
      // when we receive the profile we are going to save it in our db
      console.log(profile)
      try {
        const user = await UserModel.findOne({ googleId: profile.id })

        if (user) {
          // if user is already in db I'm creating tokens for him and save refresh in db
          const tokens = await JWTAuthenticate(user)
          next(null, { user, tokens })
        } else {
          // if user is not in db I'm saving him in db  then I'm creating tokens for him then

          const newUser = {
            name: profile.name.givenName,
            surname: profile.name.familyName,
            email: profile.email,
            role: "User",
            googleId: profile.id,
          }
          const createdUser = new UserModel(newUser)
          const u = await createdUser.save()

          const tokens = await JWTAuthenticate(u)

          next(null, { u, tokens })
        }
      } catch (error) {
        next(error)
      }
    }
  )
)

passport.serializeUser(function (user, next) {
  // this is for req.user
  next(null, user)
})

export default {}
