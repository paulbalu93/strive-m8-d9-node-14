import mongoose from "mongoose"
import bcrypt from "bcrypt"

const { Schema, model } = mongoose

const UserSchema = new Schema({
  name: { type: String, required: true },
  surname: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String },
  role: { type: String, required: true, enum: ["Admin", "User"] },
  refreshToken: { type: String },
  googleId: { type: String },
})

UserSchema.pre("save", async function (next) {
  const newUser = this

  const plainPW = newUser.password
  if (newUser.isModified("password")) {
    newUser.password = await bcrypt.hash(plainPW, 10)
  }
  next()
})

UserSchema.methods.toJSON = function () {
  const user = this

  const userObject = user.toObject()

  delete userObject.password
  delete userObject.__v
  delete userObject.refreshToken
  return userObject
}

UserSchema.statics.checkCredentials = async function (email, plainPW) {
  const user = await this.findOne({ email })
  console.log(user)

  if (user) {
    const isMatch = await bcrypt.compare(plainPW, user.password)
    if (isMatch) return user
    else return null
  } else return null
}

export default model("User", UserSchema)
